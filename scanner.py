import json
import os
import subprocess
import tempfile
import time


def run_semgrep(code_path: str):
    result = subprocess.run(
        [
            "semgrep",
            "--config",
            "auto",
            "--json",
            "--quiet",
            code_path,
        ],
        capture_output=True,
        text=True,
    )

    findings = []

    if result.stdout:
        try:
            output = json.loads(result.stdout)

            for r in output.get("results", []):
                findings.append({
                    "rule": r["check_id"],
                    "message": r["extra"].get("message", ""),
                    "line": r["start"]["line"],
                })

        except json.JSONDecodeError:
            pass

    return findings


def scan(json_path: str):

    print(f"\n[SCANNER] Reading: {json_path}")

    start = time.time()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:

        for idx, entry in enumerate(data):

            vuln_code = entry.get("vulnerable_code", "").strip()

            if not vuln_code:
                print(f"[SKIP] Entry {idx} - missing vulnerable_code")
                continue

            code_path = os.path.join(
                tmpdir,
                f"entry_{idx}.c"
            )

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(vuln_code)

            findings = run_semgrep(code_path)

            tag = "[FOUND]" if findings else "[WARN]"

            print(
                f"{tag} Entry {idx} | "
                f"{len(findings)} issue(s)"
            )

            results.append({
                "entry_id": idx,
                "vulnerable_code": vuln_code,
                "semgrep_findings": findings,
            })

    elapsed = time.time() - start

    print(
        f"\n[SCANNER] Done. "
        f"Processed {len(results)} entries "
        f"in {elapsed:.2f}s"
    )

    return results


if __name__ == "__main__":
    scan("test_input.json")
