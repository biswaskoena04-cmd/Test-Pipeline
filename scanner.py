import json
import os
import subprocess
import tempfile
import time
import re

def scan(json_path):
    print(f"\n[SCANNER] Reading: {json_path}")
    start = time.time()

    with open(json_path, 'r') as f:
        data = json.load(f)

    semgrep_rules = """
rules:
  - id: dangerous-strcpy
    patterns:
      - pattern: strcpy(...)
    message: "Dangerous strcpy usage - CWE-120 Buffer Copy Without Checking Size"
    languages: [c, cpp]
    severity: ERROR

  - id: dangerous-sprintf
    patterns:
      - pattern: sprintf(...)
    message: "Dangerous sprintf usage - CWE-120 Buffer Overflow risk"
    languages: [c, cpp]
    severity: ERROR

  - id: dangerous-strcat
    patterns:
      - pattern: strcat(...)
    message: "Dangerous strcat usage - CWE-120 Buffer Overflow risk"
    languages: [c, cpp]
    severity: ERROR

  - id: dangerous-gets
    patterns:
      - pattern: gets(...)
    message: "Dangerous gets usage - CWE-120 Buffer Overflow"
    languages: [c, cpp]
    severity: ERROR

  - id: use-after-free
    patterns:
      - pattern: |
          free($X);
          ...
          $X
    message: "Potential use-after-free - CWE-416"
    languages: [c, cpp]
    severity: ERROR
"""

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = os.path.join(tmpdir, "rules.yaml")
        with open(rules_path, 'w') as f:
            f.write(semgrep_rules)

        for entry in data:
            entry_id = entry["id"]
            cwe_id = entry.get("cwe_id", "UNKNOWN")
            cve_id = entry.get("cve_id", "UNKNOWN")

            prompt = entry.get("prompt", "")
            match = re.search(r'Vulnerable code:\n(.*?)(?:\[/INST\])', prompt, re.DOTALL)
            if not match:
                print(f"  [SKIP] ID {entry_id} — could not extract code")
                continue

            vuln_code = match.group(1).strip()

            code_path = os.path.join(tmpdir, f"entry_{entry_id}.c")
            with open(code_path, 'w') as f:
                f.write(vuln_code)

            result = subprocess.run(
                ["semgrep", "--config", rules_path, "--json", code_path],
                capture_output=True, text=True
            )

            findings = []
            if result.stdout:
                try:
                    semgrep_output = json.loads(result.stdout)
                    for r in semgrep_output.get("results", []):
                        findings.append({
                            "rule": r["check_id"],
                            "message": r["extra"]["message"],
                            "line": r["start"]["line"]
                        })
                except json.JSONDecodeError:
                    pass

            if findings:
                print(f"  [FOUND] ID {entry_id} | {cwe_id} | {cve_id} | {len(findings)} issue(s) detected by Semgrep")
            else:
                print(f"  [WARN]  ID {entry_id} | {cwe_id} | {cve_id} | No Semgrep rule matched (still passing through)")

            results.append({
                "id": entry_id,
                "cwe_id": cwe_id,
                "cve_id": cve_id,
                "vulnerable_code": vuln_code,
                "patch": entry.get("completion", "").strip(),
                "semgrep_findings": findings
            })

    elapsed = time.time() - start
    print(f"\n[SCANNER] Done. Processed {len(results)} entries in {elapsed:.3f} seconds.\n")
    return results


if __name__ == "__main__":
    scan("test_input.json")