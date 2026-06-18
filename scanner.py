import json
import os
import subprocess
import tempfile
import time


def run_codeql(src_dir: str):
    """Creates a CodeQL database of the directory and analyzes it."""
    db_path = os.path.join(src_dir, "codeql_db")
    results_sarif = os.path.join(src_dir, "results.sarif")
    findings_by_file = {}

    # 1. Create a buildless CodeQL database
    subprocess.run(
        [
            "codeql", "database", "create", db_path,
            "--language=cpp",
            "--source-root", src_dir,
            "--build-mode=none",
            "--overwrite"
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True
    )

    # 2. Run standard C/C++ security queries (downloads packs automatically)
    subprocess.run(
        [
            "codeql", "database", "analyze", db_path,
            "codeql/cpp-queries",
            "--format=sarif-latest",
            "--output", results_sarif
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True
    )

    # 3. Parse the SARIF JSON output
    if os.path.exists(results_sarif):
        with open(results_sarif, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)

        # Loop through found runs/results
        for run in sarif_data.get("runs", []):
            for r in run.get("results", []):
                rule_id = r.get("ruleId")
                message = r.get("message", {}).get("text", "")
                
                for location in r.get("locations", []):
                    physical_loc = location.get("physicalLocation", {})
                    uri = physical_loc.get("artifactLocation", {}).get("uri", "")
                    filename = os.path.basename(uri)
                    line = physical_loc.get("region", {}).get("startLine", 0)

                    if filename not in findings_by_file:
                        findings_by_file[filename] = []
                    
                    findings_by_file[filename].append({
                        "rule": rule_id,
                        "message": message,
                        "line": line
                    })

    return findings_by_file


def scan(json_path: str):
    print(f"\n[SCANNER] Reading: {json_path}")
    start = time.time()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        valid_entries = {}

        # Write out all individual files first to scan them concurrently
        for idx, entry in enumerate(data):
            vuln_code = entry.get("vulnerable_code", "").strip()

            if not vuln_code:
                print(f"[SKIP] Entry {idx} - missing vulnerable_code")
                continue

            filename = f"entry_{idx}.c"
            code_path = os.path.join(tmpdir, filename)

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(vuln_code)
            
            valid_entries[filename] = (idx, vuln_code)

        # Run CodeQL once across the entire temporary folder
        print("[SCANNER] Initializing buildless CodeQL analysis pass...")
        all_findings = run_codeql(tmpdir)

        # Map CodeQL structural findings back to our processing dataset
        for filename, (idx, vuln_code) in valid_entries.items():
            findings = all_findings.get(filename, [])
            tag = "[FOUND]" if findings else "[WARN]"

            print(
                f"{tag} Entry {idx} | "
                f"{len(findings)} issue(s) detected via CodeQL"
            )

            results.append({
                "entry_id": idx,
                "vulnerable_code": vuln_code,
                "codeql_findings": findings,
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
