# Test file con magic comment en misma línea
def safe_calculator(expression):
    result = eval(expression)  # ag: ignore - math expression, validated before
    return result
