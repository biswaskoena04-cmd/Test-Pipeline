import json
import os
import subprocess
import tempfile
import time
import re

# ── Language detection ────────────────────────────────────────────────────────

LANG_EXTENSION = {
    "c": ".c",
    "cpp": ".cpp",
    "python": ".py",
    "java": ".java",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "ruby": ".rb",
    "php": ".php",
    "rust": ".rs",
}

LANG_KEYWORDS = {
    "python": [r"\bdef\b", r"\bimport\b", r"\bprint\s*\("],
    "java": [r"\bpublic\s+class\b", r"\bSystem\.out\b", r"\bimport\s+java"],
    "javascript": [r"\bconst\b", r"\blet\b", r"require\(", r"=>"],
    "typescript": [r":\s*(string|number|boolean|void)\b", r"\binterface\b"],
    "go": [r"\bfunc\b", r"\bpackage\b", r":="],
    "ruby": [r"\bdef\b", r"\bend\b", r"\bputs\b"],
    "php": [r"<\?php", r"\$[a-zA-Z_]"],
    "rust": [r"\bfn\b", r"\blet\s+mut\b", r"\bimpl\b"],
    "cpp": [r"\bcout\b", r"\bstd::", r"#include\s*<", r"\bclass\b"],
    "c": [r"#include\s*<stdio", r"\bprintf\b", r"\bmalloc\b", r"\bfree\b"],
}


def detect_language(code: str, cwe_id: str = "") -> str:
    scores = {lang: 0 for lang in LANG_KEYWORDS}

    for lang, patterns in LANG_KEYWORDS.items():
        for pat in patterns:
            if re.search(pat, code):
                scores[lang] += 1

    best_lang = max(scores, key=scores.get)

    if scores[best_lang] > 0:
        return best_lang

    c_cwes = {
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-416",
        "CWE-415",
        "CWE-476",
    }

    if any(c in cwe_id for c in c_cwes):
        return "c"

    return "c"


# ── Semgrep registry rule packs ───────────────────────────────────────────────

CWE_TO_REGISTRY = {
    "CWE-22": ["p/owasp-top-ten", "p/security-audit"],
    "CWE-78": ["p/owasp-top-ten", "p/command-injection"],
    "CWE-79": ["p/owasp-top-ten", "p/xss"],
    "CWE-89": ["p/owasp-top-ten", "p/sql-injection"],
    "CWE-119": ["p/security-audit"],
    "CWE-120": ["p/security-audit"],
    "CWE-121": ["p/security-audit"],
    "CWE-122": ["p/security-audit"],
    "CWE-125": ["p/security-audit"],
    "CWE-134": ["p/security-audit"],
    "CWE-190": ["p/security-audit"],
    "CWE-200": ["p/owasp-top-ten", "p/security-audit"],
    "CWE-287": ["p/owasp-top-ten", "p/jwt"],
    "CWE-306": ["p/owasp-top-ten"],
    "CWE-327": ["p/owasp-top-ten", "p/secrets"],
    "CWE-330": ["p/owasp-top-ten", "p/secrets"],
    "CWE-352": ["p/owasp-top-ten"],
    "CWE-400": ["p/security-audit"],
    "CWE-415": ["p/security-audit"],
    "CWE-416": ["p/security-audit"],
    "CWE-476": ["p/security-audit"],
    "CWE-502": ["p/owasp-top-ten", "p/security-audit"],
    "CWE-601": ["p/owasp-top-ten"],
    "CWE-611": ["p/owasp-top-ten"],
    "CWE-798": ["p/secrets", "p/owasp-top-ten"],
    "CWE-918": ["p/owasp-top-ten"],
}

DEFAULT_PACKS = ["p/security-audit"]


def get_registry_packs(cwe_id: str) -> list[str]:
    for key, packs in CWE_TO_REGISTRY.items():
        if cwe_id.startswith(key):
            return list(dict.fromkeys(packs))
    return DEFAULT_PACKS


# ── Semgrep runner ────────────────────────────────────────────────────────────

def run_semgrep(config: str, code_path: str) -> list[dict]:
    result = subprocess.run(
        [
            "semgrep",
            "--config",
            config,
            "--json",
            "--quiet",
            code_path,
        ],
        capture_output=True,
        text=True,
    )

    if result.stderr:
        print(f"\n[SEMGREP STDERR] {config}")
        print(result.stderr[:1000])

    findings = []

    if result.stdout:
        try:
            output = json.loads(result.stdout)

            for r in output.get("results", []):
                findings.append({
                    "rule": r["check_id"],
                    "message": r["extra"].get("message", ""),
                    "line": r["start"]["line"],
                    "source": config,
                })

        except json.JSONDecodeError:
            print(f"\n[SEMGREP JSON ERROR] {config}")

    return findings


# ── Main scanner ──────────────────────────────────────────────────────────────

def scan(json_path: str) -> list[dict]:
    print(f"\n[SCANNER] Reading: {json_path}")
    start = time.time()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = []

    with tempfile.TemporaryDirectory() as tmpdir:

        for idx, entry in enumerate(data):

            cwe_id = entry.get("cwe_id", "UNKNOWN")
            cve_id = entry.get("cve_id", "UNKNOWN")
            entry_id = f"{cve_id}_{idx}"

            # ── Extract vulnerable code ──────────────────────────────────────

            vuln_code = entry.get("vulnerable_code", "").strip()

            if not vuln_code:
                print(f"  [SKIP] ID {entry_id} — missing vulnerable_code")
                continue

            # ── Language selection ───────────────────────────────────────────

            dataset_lang = entry.get("language", "").lower()

            lang_map = {
                "c": "c",
                "c++": "cpp",
                "cpp": "cpp",
                "python": "python",
                "java": "java",
                "javascript": "javascript",
                "typescript": "typescript",
                "go": "go",
                "ruby": "ruby",
                "php": "php",
                "rust": "rust",
            }

            detected_lang = lang_map.get(
                dataset_lang,
                detect_language(vuln_code, cwe_id)
            )

            ext = LANG_EXTENSION.get(detected_lang, ".c")

            code_path = os.path.join(
                tmpdir,
                f"entry_{entry_id}{ext}"
            )

            with open(code_path, "w", encoding="utf-8") as f:
                f.write(vuln_code)

            # ── Semgrep scan ────────────────────────────────────────────────

            packs = get_registry_packs(cwe_id)

            configs = list(dict.fromkeys(packs + ["auto"]))

            findings = []
            seen = set()

            for config in configs:

                for finding in run_semgrep(config, code_path):

                    key = (
                        finding["rule"],
                        finding["line"],
                    )

                    if key not in seen:
                        seen.add(key)
                        findings.append(finding)

            # ── Logging ─────────────────────────────────────────────────────

            tag = "[FOUND]" if findings else "[WARN] "

            print(
                f"  {tag} ID {entry_id} | "
                f"{cwe_id} | "
                f"{cve_id} | "
                f"lang={detected_lang} | "
                f"packs={configs} | "
                f"{len(findings)} issue(s)"
            )

            results.append({
                "id": entry_id,
                "cwe_id": cwe_id,
                "cve_id": cve_id,
                "detected_lang": detected_lang,
                "registry_packs": configs,
                "vulnerable_code": vuln_code,
                "patch": entry.get("fixed_code", "").strip(),
                "semgrep_findings": findings,
            })

    elapsed = time.time() - start

    print(
        f"\n[SCANNER] Done. "
        f"Processed {len(results)} entries "
        f"in {elapsed:.3f}s.\n"
    )

    return results


if __name__ == "__main__":
    scan("test_input.json")
