import time
from tree_sitter import Language, Parser
import tree_sitter_c as tsc
from scanner import scan

SEPARATOR = "-" * 60 

def extract_functions(code):
    """Use Tree-Sitter to extract functional nodes from raw code strings."""
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
    print(f"[SLICER] Processing {len(findings)} records using Tree-Sitter...\n")
    start = time.time()

    sliced_llm_payload = []

    for finding in findings:
        vuln_code = finding["vulnerable_code"]
        patch_code = finding["fixed_code"]  # Synchronized with 'fixed_code' key

        vuln_functions = extract_functions(vuln_code)
        patch_functions = extract_functions(patch_code)

        print(SEPARATOR)
        print(f"ID    : {finding['id']}")
        print(f"CWE   : {finding['cwe_id']}")
        print(f"CVE   : {finding['cve_id']}")

        # Evaluates and prints CodeQL rule flags natively 
        if finding["codeql_findings"]:
            print(f"CODEQL RULES HIT:")
            for cf in finding["codeql_findings"]:
                print(f"  - {cf['rule']} (line {cf['line']}): {cf['message']}")

        if vuln_functions:
            print(f"\nVULN FUNCTIONS EXTRACTED BY TREE-SITTER ({len(vuln_functions)} found):")
            for fn in vuln_functions:
                print(f"\n  Function: {fn['name']} (lines {fn['start_line']}-{fn['end_line']})")
                print(f"  Code:\n{fn['code']}")
        else:
            print(f"\nVULN (raw — Tree-Sitter found no complete function definitions):")
            print(vuln_code)

        if patch_functions:
            print(f"\nPATCH FUNCTIONS EXTRACTED BY TREE-SITTER ({len(patch_functions)} found):")
            for fn in patch_functions:
                print(f"\n  Function: {fn['name']} (lines {fn['start_line']}-{fn['end_line']})")
                print(f"  Code:\n{fn['code']}")
        else:
            print(f"\nPATCH (raw — Tree-Sitter found no complete function definitions):")
            print(patch_code)

        print(SEPARATOR + "\n")

        # Clean JSON payload structural dictionary meant for the downstream LLM 
        sliced_llm_payload.append({
            "id": finding["id"],
            "CWE": finding["cwe_id"],
            "CVE": finding["cve_id"],
            "VULN_AST_FUNCTIONS": vuln_functions if vuln_functions else vuln_code,
            "PATCH_AST_FUNCTIONS": patch_functions if patch_functions else patch_code,
            "codeql_findings": finding["codeql_findings"]
        })

    elapsed = time.time() - start
    print(f"[SLICER] Done. Sliced {len(sliced_llm_payload)} items for processing context in {elapsed:.3f}s.\n")
    return sliced_llm_payload


if __name__ == "__main__":
    findings = scan("test_input.json")
    llm_ready_data = slice_findings(findings)
    # The 'llm_ready_data' can now be passed safely to your prompt tokenizer.
