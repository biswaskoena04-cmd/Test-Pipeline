import json
import os
import subprocess
import tempfile
import time


def run_semgrep(src_dir: str):
    """Runs Semgrep against the folder using the comprehensive C security pack."""
    findings_by_file = {}

    # Force download and usage of explicit C vulnerability rules
    result = subprocess.run(
        [
            "semgrep",
            "--config", "p/c",
            "--config", "p/security-audit",
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
                
                # Subtract 1 from the line number if you want to normalize 
                # the line numbers back to the original unwrapped code
                findings_by_file[filename].append({
                    "rule": rule_id,
                    "message": message,
                    "line": max(1, line - 1)  
                })

        except json.JSONDecodeError:
            pass

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

            # CRITICAL FIX: If the block doesn't start with a function definition,
            # wrap it in a dummy function so the static analyzer can parse its structures.
            if "{" in vuln_code and not vuln_code.startswith("void") and not vuln_code.startswith("int"):
                wrapped_code = f"void dataset_harness_{idx}() {{\n{vuln_code}\n}}"
            else:
                wrapped_code = vuln_code

            filename = f"entry_{idx}.c"
            code_path = os.path.join(tmpdir, filename)

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(wrapped_code)
            
            valid_entries[filename] = (idx, entry)

        print("[SCANNER] Running single batch pass across normalized snippets...")
        all_findings = run_semgrep(tmpdir)

        # Build downstream structures for the LLM pipeline
        for filename, (idx, original_entry) in valid_entries.items():
            findings = all_findings.get(filename, [])
            tag = "[FOUND]" if findings else "[WARN]"

            print(f"{tag} Entry {idx} | {len(findings)} issue(s) detected via Semgrep")

            results.append({
                "id": original_entry.get("id", idx if not isinstance(original_entry, dict) else original_entry.get("id", idx)),
                "cve_id": original_entry.get("cve_id", "N/A"),
                "cwe_id": original_entry.get("cwe_id", "N/A"),
                "vulnerable_code": original_entry.get("vulnerable_code", ""),
                "fixed_code": original_entry.get("fixed_code", ""),
                "semgrep_findings": findings,
            })

    elapsed = time.time() - start
    print(f"[SCANNER] Completed scanning execution in {elapsed:.2f}s")
    return results


if __name__ == "__main__":
    scan("test_input.json")
