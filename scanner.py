import json
import os
import re
import subprocess
import tempfile
import time


# --- Tool 1: Semgrep ---

def run_semgrep(file_path: str, config: str = "p/cpp") -> list[dict]:
    """Run Semgrep against a single C/C++ file and return raw JSON results."""
    try:
        result = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", file_path],
            capture_output=True, text=True, timeout=60
        )
        if not result.stdout.strip():
            return []
        return json.loads(result.stdout).get("results", [])
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[SEMGREP] error on {file_path}: {e}")
        return []


def parse_semgrep(raw_results: list[dict]) -> list[dict]:
    findings = []
    for r in raw_results:
        cwe_raw = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwe = cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else (cwe_raw or "N/A")
        findings.append({
            "tool": "semgrep",
            "rule_id": r.get("check_id", "unknown"),
            "message": r.get("extra", {}).get("message", "").strip(),
            "line_start": r.get("start", {}).get("line", -1),
            "line_end": r.get("end", {}).get("line", -1),
            "cwe": cwe,
            "severity": r.get("extra", {}).get("severity", "INFO"),
        })
    return findings


# --- Tool 2: cppcheck ---

def run_cppcheck(file_path: str) -> list[dict]:
    """Run cppcheck against a single C/C++ file and return parsed XML findings."""
    try:
        result = subprocess.run(
            ["cppcheck", "--enable=warning,portability", "--xml", "--xml-version=2", file_path],
            capture_output=True, text=True, timeout=60
        )
        return _parse_cppcheck_xml(result.stderr)  # cppcheck writes XML to stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[CPPCHECK] error on {file_path}: {e}")
        return []


def _parse_cppcheck_xml(xml_text: str) -> list[dict]:
    import xml.etree.ElementTree as ET
    findings = []
    try:
        root = ET.fromstring(xml_text)
        for error in root.findall(".//error"):
            location = error.find("location")
            line = int(location.get("line", -1)) if location is not None else -1
            findings.append({
                "tool": "cppcheck",
                "rule_id": error.get("id", "unknown"),
                "message": error.get("msg", ""),
                "line_start": line,
                "line_end": line,
                "cwe": error.get("cwe", "N/A"),
                "severity": error.get("severity", "info"),
            })
    except ET.ParseError:
        pass
    return findings


def parse_cppcheck(raw_results: list[dict]) -> list[dict]:
    # already parsed in run_cppcheck via _parse_cppcheck_xml
    return raw_results


# --- Tool 3: clang-tidy ---

def run_clang(file_path: str, checks: str = "clang-analyzer-*,security.*,cert-*") -> list[str]:
    """Run clang-tidy against a single C/C++ file and return raw stdout lines."""
    try:
        result = subprocess.run(
            ["clang-tidy", file_path, f"-checks={checks}", "--", "-std=c11"],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout.splitlines()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[CLANG-TIDY] error on {file_path}: {e}")
        return []


def parse_clang(raw_lines: list[str]) -> list[dict]:
    # clang-tidy line format: file:line:col: warning: message [check-name]
    pattern = re.compile(r"^(.+):(\d+):(\d+):\s+(warning|error):\s+(.+?)\s+\[([\w\-.,]+)\]$")
    findings = []
    for line in raw_lines:
        m = pattern.match(line.strip())
        if not m:
            continue
        _, lineno, _, severity, message, check_name = m.groups()
        findings.append({
            "tool": "clang-tidy",
            "rule_id": check_name,
            "message": message,
            "line_start": int(lineno),
            "line_end": int(lineno),
            "cwe": "N/A",  # clang-tidy doesn't natively tag CWE; map check_name -> CWE separately if needed
            "severity": severity,
        })
    return findings


# --- Dedup + merge ---

def deduplicate(findings: list[dict], line_window: int = 2) -> list[dict]:
    """Merge findings from different tools that point at the same/nearby lines."""
    merged = []
    used = [False] * len(findings)

    for i, f in enumerate(findings):
        if used[i]:
            continue
        group = [f]
        used[i] = True
        for j in range(i + 1, len(findings)):
            if used[j]:
                continue
            g = findings[j]
            if abs(g["line_start"] - f["line_start"]) <= line_window:
                group.append(g)
                used[j] = True

        merged.append({
            "line_start": min(x["line_start"] for x in group),
            "line_end": max(x["line_end"] for x in group),
            "tools": sorted(set(x["tool"] for x in group)),
            "cwe_candidates": sorted(set(x["cwe"] for x in group if x["cwe"] != "N/A")),
            "messages": [{"tool": x["tool"], "rule_id": x["rule_id"], "message": x["message"]} for x in group],
            "severity": max((x["severity"] for x in group), key=lambda s: _severity_rank(s)),
        })
    return merged


def _severity_rank(sev: str) -> int:
    order = {"error": 3, "warning": 2, "info": 1}
    return order.get(sev.lower(), 0)


# --- Vuln code extraction (from your old code) ---

def extract_vuln_code(entry: dict) -> str:
    vuln_code = entry.get("vulnerable_code", entry.get("prompt", "")).strip()
    if "[INST]" in vuln_code:
        try:
            vuln_code = vuln_code.split("Vulnerable code:\n")[-1].split("[/INST]")[0].strip()
        except IndexError:
            pass
    return vuln_code


# --- Main scan orchestration ---

def generate_unified_report(file_path: str) -> list[dict]:
    """Run all three scanners on one file, parse, and dedupe."""
    all_findings = []
    all_findings += parse_semgrep(run_semgrep(file_path))
    all_findings += parse_cppcheck(run_cppcheck(file_path))
    all_findings += parse_clang(run_clang(file_path))
    return deduplicate(all_findings)


def scan(json_path: str) -> list[dict]:
    print(f"\n[SCANNER] Ingesting dataset: {json_path}")
    start = time.time()

    if not os.path.exists(json_path):
        print(f"[ERROR] Input file {json_path} not found.")
        return []

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []
    total_findings = 0

    for idx, entry in enumerate(data):
        vuln_code = extract_vuln_code(entry)
        if not vuln_code:
            continue

        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False, encoding="utf-8") as tmp:
            tmp.write(vuln_code)
            tmp_path = tmp.name

        try:
            findings = generate_unified_report(tmp_path)
        finally:
            os.unlink(tmp_path)

        total_findings += len(findings)
        tag = "[FOUND]" if findings else "[CLEAN]"
        print(f"{tag} Entry {idx} | {len(findings)} finding(s)")

        results.append({
            "id": entry.get("id", idx),
            "vulnerable_code": vuln_code,
            "findings": findings,
        })

    elapsed = time.time() - start
    print(f"\n[SCANNER] Done in {elapsed:.2f}s | {total_findings} total findings across {len(results)} entries")
    return results


if __name__ == "__main__":
    output = scan("test_input.json")
    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
