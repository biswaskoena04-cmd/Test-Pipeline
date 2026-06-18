import json
import os
import subprocess
import tempfile
import time

# Embedded, localized C/C++ security rules to bypass network rule-download limits
LOCAL_RULES_YAML = """
rules:
  - id: integer-overflow-alloc
    languages: [c, cpp]
    severity: WARNING
    message: Potential integer overflow leading to buffer overflow during allocation.
    pattern-either:
      - pattern: malloc($LEN * $SIZE)
      - pattern: calloc($NUM, $SIZE)
      - pattern: realloc($PTR, $LEN * $SIZE)

  - id: unsafe-string-copy
    languages: [c, cpp]
    severity: WARNING
    message: Unsafe string copy function detected. Use strncpy or bounds-checked alternatives.
    pattern-either:
      - pattern: strcpy(...)
      - pattern: strcat(...)
      - pattern: sprintf($BUF, "...", ...)

  - id: use-after-free
    languages: [c, cpp]
    severity: WARNING
    message: Potential use-after-free pattern detected.
    patterns:
      - pattern: free($PTR);
      - pattern-not: $PTR = NULL;
      - pattern-inside: |
          ...
          free($PTR);
          ...
          $PTR->...

  - id: generic-buffer-bounds
    languages: [c, cpp]
    severity: WARNING
    message: Potentially bounded function missing size control validation.
    pattern-either:
      - pattern: memcpy(...)
      - pattern: memmove(...)
      - pattern: gets(...)
"""

def run_semgrep_offline(src_dir: str):
    """Runs Semgrep locally using zero-network embedded rule validations."""
    findings_by_file = {}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(LOCAL_RULES_YAML)
        rule_file_path = f.name

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config", rule_file_path,
                "--json",
                "--quiet",
                src_dir
            ],
            capture_output=True,
            text=True
        )

        if result.stdout:
            try:
                output = json.loads(result.stdout)
                for r in output.get("results", []):
                    path = r.get("path", "")
                    filename = os.path.basename(path)
                    
                    rule_id = r.get("check_id")
                    message = r.get("extra", {}).get("message", "")
                    line = r.get("start", {}).get("line", 0)

                    if filename not in findings_by_file:
                        findings_by_file[filename] = []
                    
                    findings_by_file[filename].append({
                        "rule": rule_id,
                        "message": message,
                        "line": line
                    })
            except json.JSONDecodeError:
                pass
    finally:
        if os.path.exists(rule_file_path):
            os.remove(rule_file_path)

    return findings_by_file


def scan(json_path: str):
    print(f"\n[SCANNER] Reading dataset payload: {json_path}")
    start = time.time()

    if not os.path.exists(json_path):
        print(f"[ERROR] Input file {json_path} not found.")
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        valid_entries = {}

        for idx, entry in enumerate(data):
            vuln_code = entry.get("vulnerable_code", "").strip()
            if not vuln_code:
                continue

            # Ensure snippets look structurally valid to parser mechanics
            if "{" in vuln_code and not (vuln_code.startswith("void") or vuln_code.startswith("int") or vuln_code.startswith("static")):
                wrapped_code = f"void dataset_harness_{idx}() {{\n{vuln_code}\n}}"
            else:
                wrapped_code = vuln_code

            filename = f"entry_{idx}.c"
            code_path = os.path.join(tmpdir, filename)

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(wrapped_code)
            
            valid_entries[filename] = (idx, entry)

        print("[SCANNER] Running deterministic evaluation over workspace elements...")
        all_findings = run_semgrep_offline(tmpdir)

        for filename, (idx, original_entry) in valid_entries.items():
            findings = all_findings.get(filename, [])
            tag = "[FOUND]" if findings else "[WARN]"

            print(f"{tag} Entry {idx} | {len(findings)} issue(s) confirmed via custom mapping rules")

            results.append({
                "id": original_entry.get("id", idx if not isinstance(original_entry, dict) else original_entry.get("id", idx)),
                "cve_id": original_entry.get("cve_id", "N/A"),
                "cwe_id": original_entry.get("cwe_id", "N/A"),
                "vulnerable_code": original_entry.get("vulnerable_code", ""),
                "fixed_code": original_entry.get("fixed_code", ""),
                "semgrep_findings": findings,
            })

    print(f"[SCANNER] Completed execution loop in {time.time() - start:.2f}s")
    return results


if __name__ == "__main__":
    scan("test_input.json")
