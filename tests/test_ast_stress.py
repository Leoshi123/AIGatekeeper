
import pytest
import os
from src.ast_parser.extractor import ASTExtractor
from src.detector.zombie_detector import LegacyShield, Severity

class PruningErrorDetector:
    """
    Validates that security-critical nodes are not pruned during AST extraction.
    """
    def __init__(self):
        self.shield = LegacyShield(languages=["python", "javascript", "typescript", "general"])
        self.extractor = ASTExtractor()

    def analyze_pruning_loss(self, file_path: str, task_description: str):
        """
        Compares vulnerabilities in original vs pruned code.
        """
        # 1. Find vulnerabilities in original
        original_results = self.shield.scan_file(file_path)
        critical_original = [r for r in original_results if r.pattern.severity == Severity.CRITICAL]

        # 2. Prune the code
        pruned_context = self.extractor.prune(file_path, task_description)

        # Reconstruct the pruned code to be analyzed by the shield
        # We combine imports, signatures, and bodies of relevant functions
        pruned_code = "\n".join(pruned_context.imports) + "\n"
        pruned_code += "\n".join(pruned_context.signatures) + "\n"
        for func in pruned_context.relevant_functions:
            pruned_code += f"{func.signature}\n{func.body}\n"

        # 3. Find vulnerabilities in pruned code
        pruned_results = self.shield.scan_code(pruned_code, file_path=file_path)
        critical_pruned = [r for r in pruned_results if r.pattern.severity == Severity.CRITICAL]

        # 4. Identify lost critical vulnerabilities
        # We check if any original critical pattern is missing in the pruned output
        lost_vulns = []
        for orig_vuln in critical_original:
            # A vulnerability is "lost" if its pattern no longer matches anything in the pruned code
            # (This is a simplification; in reality, we'd check line contents)
            found = any(orig_vuln.pattern.pattern == p.pattern.pattern for p in critical_pruned)
            if not found:
                lost_vulns.append(orig_vuln)

        return {
            "original_critical_count": len(critical_original),
            "pruned_critical_count": len(critical_pruned),
            "lost_vulns": lost_vulns,
            "pruned_code": pruned_code,
            "reduction_percent": self.extractor.get_stats(pruned_context)["reduction_percent"]
        }

def test_ast_stress_matrix():
    """
    Stress test against the complexity matrix.
    """
    detector = PruningErrorDetector()
    fixtures_dir = "test_fixtures/ast_stress"
    files = [f for f in os.listdir(fixtures_dir) if f.endswith(('.ts', '.js'))]

    security_holes = []

    for file_name in files:
        file_path = os.path.join(fixtures_dir, file_name)
        # We use a task description that might mislead the extractor into pruning "irrelevant" code
        # For example, "optimize the outer function" while the vuln is deep inside.
        task = "optimize the main entry point and structure"

        result = detector.analyze_pruning_loss(file_path, task)

        if result["lost_vulns"]:
            for vuln in result["lost_vulns"]:
                security_holes.append({
                    "file": file_name,
                    "pattern": vuln.pattern.description,
                    "line": vuln.line_number,
                    "content": vuln.line_content
                })

    if security_holes:
        print("\nSECURITY HOLES DETECTED")
        for hole in security_holes:
            print(f"File: {hole['file']} | Pattern: {hole['pattern']} | Line: {hole['line']}")
            print(f"Content: {hole['content']}\n")

        pytest.fail(f"Found {len(security_holes)} security holes where critical nodes were pruned.")

if __name__ == "__main__":
    # Allow running manually without pytest
    try:
        test_ast_stress_matrix()
        print("✅ AST Stress Test Passed: No critical nodes were pruned.")
    except Exception as e:
        print(e)
