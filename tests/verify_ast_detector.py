# AST vs Regex Test Suite
import os

# Test 1: False Positive (Comment)
code_comment = """
# This is a comment: eval("dangerous")
# we should not detect this
print("Hello")
"""

# Test 2: Obfuscation (Spaces)
code_obf = """
eval   (  "print(1)"  )
"""

# Test 3: Real Danger
code_danger = """
import os
os.system("ls")
"""

# Test 4: Regression (Mixed)
code_mixed = """
api_key = "sk-12345" # Should be regex
eval("1+1")          # Should be AST
"""

test_cases = [
    ("test_comment.py", code_comment, "should ignore eval in comment"),
    ("test_obf.py", code_obf, "should detect eval with spaces"),
    ("test_danger.py", code_danger, "should detect os.system"),
    ("test_mixed.py", code_mixed, "should detect both secret and eval"),
]

from src.detector.zombie_detector import LegacyShield

shield = LegacyShield()

print("=== AG-Wrapper Verification Suite ===\n")

for filename, code, goal in test_cases:
    print(f"Testing {filename} -> {goal}")
    results = shield.scan_code(code, file_path=filename)

    # Check for eval in comments (Test 1)
    if "test_comment" in filename:
        found_eval = any("eval" in r.line_content for r in results)
        print(f"  Result: {'FAILED' if found_eval else 'PASSED'} (Found eval in comment: {found_eval})")

    # Check for obfuscated eval (Test 2)
    elif "test_obf" in filename:
        found_eval = any("eval" in r.line_content for r in results)
        print(f"  Result: {'PASSED' if found_eval else 'FAILED'} (Found obfuscated eval: {found_eval})")

    # Check for os.system (Test 3)
    elif "test_danger" in filename:
        found_sys = any("os.system" in r.line_content for r in results)
        print(f"  Result: {'PASSED' if found_sys else 'FAILED'} (Found os.system: {found_sys})")

    # Check for mixed (Test 4)
    elif "test_mixed" in filename:
        found_key = any("api_key" in r.line_content for r in results)
        found_eval = any("eval" in r.line_content for r in results)
        print(f"  Result: {'PASSED' if (found_key and found_eval) else 'FAILED'} (Key: {found_key}, Eval: {found_eval})")

    print("-" * 40)
