import unicodedata
import re
import sys

task = "optimizar funcion process"  # sin tilde para probar
task_normalized = unicodedata.normalize("NFKD", task)
task_lower = task_normalized.lower()

keywords = [
    r"funcion(?:es)?\s+(\w+)",
    r"function\s+(\w+)",
    r"metodo\s+(\w+)",
    r"method\s+(\w+)",
    r"(\w+)\s+function",
    r"optimizar\s+(\w+)",
    r"refactor(?:izar)?\s+(\w+)",
    r"fix\s+(\w+)",
    r"update\s+(\w+)",
    r"change\s+(\w+)",
]

found = []
for kw in keywords:
    m = re.findall(kw, task_lower)
    if m:
        print(f"Pattern {kw}: {m}")
        found.extend(m)

print(f"Found: {found}")
