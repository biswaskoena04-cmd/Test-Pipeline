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
                "end_line": node.end_point[0] + 1,
                "findings": []  # populated later by line-overlap matching
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


def _ranges_overlap(a_start, a_end, b_start, b_end):
    return a_start <= b_end and b_start <= a_end


def attach_findings_to_functions(functions, findings):
    """Match each merged finding to the function(s) whose line range it falls in.

    A finding with no overlapping function is kept in 'unmatched' so nothing
    silently disappears (e.g. file-level issues, macro expansions, includes).
    """
    unmatched = []
    for finding in findings:
        f_start, f_end = finding["line_start"], finding["line_end"]
        matched = False
        for fn in functions:
            if _ranges_overlap(fn["start_line"], fn["end_line"], f_start, f_end):
                fn["findings"].append(finding)
                matched = True
        if not matched:
            unmatched.append(finding)
    return unmatched


def slice_findings(scan_results):
    print(f"\n[SLICER] Refining entries via Tree-Sitter slicing...")
    start = time.time()

    sliced_llm_payload = []
    total_sliced_count = 0

    for entry in scan_results:
        findings = entry.get("findings", [])
        if not findings:
            continue

        vuln_code = entry.get("vulnerable_code", "").strip()
        vuln_functions = extract_functions(vuln_code)

        unmatched = attach_findings_to_functions(vuln_functions, findings)

        # Only keep functions that actually have a finding attached — that's the
        # whole point of context-aware slicing: don't hand the LLM clean functions.
        flagged_functions = [fn for fn in vuln_functions if fn["findings"]]

        print(SEPARATOR)
        print(f"ID    : {entry['id']}")
        print(f"FINDINGS DETECTED: {len(findings)} (unmatched to any function: {len(unmatched)})")
        for fn in flagged_functions:
            print(f"\n  > {fn['name']} (lines {fn['start_line']}-{fn['end_line']})")
            for f in fn["findings"]:
                tools = ",".join(f["tools"])
                cwes = ",".join(f["cwe_candidates"]) if f["cwe_candidates"] else "N/A"
                print(f"      [{tools}] lines {f['line_start']}-{f['line_end']} | CWE: {cwes} | severity: {f['severity']}")

        if not flagged_functions:
            print(f"\n[RAW VULN CONTEXT] (no function boundary matched flagged lines):")
            print(vuln_code[:150] + "...")
        print(SEPARATOR + "\n")

        sliced_llm_payload.append({
            "id": entry["id"],
            "VULN_AST_FUNCTIONS": flagged_functions if flagged_functions else vuln_code,
            "UNMATCHED_FINDINGS": unmatched,  # file-level / non-function-scoped findings
        })
        total_sliced_count += 1

    elapsed = time.time() - start
    print(f"[SLICER] Completed processing in {elapsed:.3f}s.")
    print(f"SUMMARY: {total_sliced_count} entries sliced\n")
    return sliced_llm_payload


if __name__ == "__main__":
    scan_results = scan("test_input.json")
    llm_ready_data = slice_findings(scan_results)
