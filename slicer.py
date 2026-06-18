import time
from tree_sitter import Language, Parser
import tree_sitter_c as tsc
from scanner import scan

SEPARATOR = "-" * 60 

def extract_functions(code):
    """Isolates and extracts functional segments from blocks using Tree-Sitter."""
    if not code:
        return []
    C_LANGUAGE = Language(tsc.language())
    parser = Parser(C_LANGUAGE)

    code_bytes = code.encode("utf-8")
    tree = parser.parse(code_bytes)
    root = tree.root_node

    functions = []

    def walk(node):
        if node.type == "function_definition":
            func_code = code_bytes[node.start_byte:node.end_byte].decode("utf-8")
            functions.append({
                "name": get_function_name(node, code_bytes),
                "code": func_code,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1
            })
        for child in node.children:
            walk(child)

    walk(root)
    return functions


def get_function_name(node, code_bytes):
    for child in node.children:
        if child.type == "function_declarator":
            for subchild in child.children:
                if subchild.type == "identifier":
                    return code_bytes[subchild.start_byte:subchild.end_byte].decode("utf-8")
    return "unknown"


def slice_findings(findings):
    print(f"\n[SLICER] Refining entries via Tree-Sitter slicing...")
    start = time.time()

    sliced_llm_payload = []
    total_sliced_count = 0  # Track total sliced outputs

    for finding in findings:
        if not finding.get("semgrep_findings"):
            continue

        vuln_code = finding.get("vulnerable_code", "").strip()
        patch_code = finding.get("fixed_code", "").strip()

        vuln_functions = extract_functions(vuln_code)
        patch_functions = extract_functions(patch_code)

        print(SEPARATOR)
        print(f"ID    : {finding['id']}")
        print(f"CWE   : {finding['cwe_id']}")
        print(f"CVE   : {finding['cve_id']}")
        print(f"SEMGREP VULNERABILITY SIGNATURES DETECTED:")
        for sf in finding["semgrep_findings"]:
            print(f"  - {sf['rule']} (line {sf['line']}): {sf['message']}")

        if vuln_functions:
            print(f"\n[AST] EXTRACTED VULNERABLE FUNCTIONS ({len(vuln_functions)}):")
            for fn in vuln_functions:
                print(f"  > {fn['name']} (lines {fn['start_line']}-{fn['end_line']})")
        else:
            print(f"\n[RAW VULN CONTEXT] (Tree-Sitter found fragment loop blocks):")
            print(vuln_code[:150] + "...")

        print(SEPARATOR + "\n")

        sliced_llm_payload.append({
            "id": finding["id"],
            "CWE": finding["cwe_id"],
            "CVE": finding["cve_id"],
            "VULN_AST_FUNCTIONS": vuln_functions if vuln_functions else vuln_code,
            "PATCH_AST_FUNCTIONS": patch_functions if patch_functions else patch_code,
            "semgrep_findings": finding["semgrep_findings"]
        })
        total_sliced_count += 1  # Increment our slice counter

    elapsed = time.time() - start
    print(f"[SLICER] Completed processing inside {elapsed:.3f}s.")
    print(f"SUMMARY: {total_sliced_count} findings sliced\n")  # Y findings sliced
    return sliced_llm_payload


if __name__ == "__main__":
    findings = scan("test_input.json")
    llm_ready_data = slice_findings(findings)
