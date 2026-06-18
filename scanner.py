import json
import os
import subprocess
import tempfile
import time


def run_codeql(src_dir: str):
    """Creates a temporary CodeQL database of the isolated blocks and analyzes it."""
    db_path = os.path.join(src_dir, "codeql_db")
    results_sarif = os.path.join(src_dir, "results.sarif")
    findings_by_file = {}

    # 1. Create a buildless CodeQL database tracking C syntax structures
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

    # 2. Run standard C/C++ security queries
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

    # 3. Parse standard structural SARIF records for the LLM context mapping
    if os.path.exists(results_sarif):
        with open(results_sarif, "r", encoding="utf-8") as f:
            sarif_data = json.load(f)

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
    print(f"\n[SCANNER] Reading dataset payload: {json_path}")
    start = time.time()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:
        valid_entries = {}

        # Isolate code fragments into files to handle them in one batch run
        for idx, entry in enumerate(data):
            vuln_code = entry.get("vulnerable_code", "").strip()

            if not vuln_code:
                print(f"[SKIP] Entry {idx} - missing vulnerable_code")
                continue

            filename = f"entry_{idx}.c"
            code_path = os.path.join(tmpdir, filename)

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(vuln_code)
            
            valid_entries[filename] = (idx, entry)

        print("[SCANNER] Running single batch optimization pass using CodeQL...")
        all_findings = run_codeql(tmpdir)

        # Build clean downstream structures mapping data precisely to your schemas
        for filename, (idx, original_entry) in valid_entries.items():
            findings = all_findings.get(filename, [])
            tag = "[FOUND]" if findings else "[WARN]"

            print(f"{tag} Entry {idx} | {len(findings)} issue(s) detected via CodeQL")

            results.append({
                "id": original_entry.get("id", idx),
                "cve_id": original_entry.get("cve_id", "N/A"),
                "cwe_id": original_entry.get("cwe_id", "N/A"),
                "vulnerable_code": original_entry.get("vulnerable_code", ""),
                "fixed_code": original_entry.get("fixed_code", ""),
                "codeql_findings": findings,
            })

    elapsed = time.time() - start
    print(f"[SCANNER] Completed scanning execution in {elapsed:.2f}s")
    return results


if __name__ == "__main__":
    scan("test_input.json")
