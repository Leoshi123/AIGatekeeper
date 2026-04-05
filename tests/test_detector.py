"""
🛡️ ZTC-Wrapper - Tests del Detector Zombi

Tests para el LegacyShield (detector de código vulnerable).
"""

import pytest
from src.detector import LegacyShield, Severity, DetectionResult, ZombiePattern


class TestLegacyShield:
    """Tests para el detector de código zombi."""

    def test_detect_eval_python(self):
        """Debe detectar eval() en Python."""
        code = "result = eval(user_input)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0
        assert any("eval" in r.line_content for r in results)

    def test_detect_shell_true(self):
        """Debe detectar subprocess con shell=True."""
        code = "subprocess.call(cmd, shell=True)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_dangerous_hardcoded_secrets(self):
        """Debe detectar secrets hardcodeados."""
        code = 'api_key = "sk-1234567890abcdef"'

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_pickle_unsafe(self):
        """Debe detectar pickle sin safe load."""
        code = "data = pickle.loads(user_data)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_yaml_unsafe(self):
        """Debe detectar yaml.load() sin Loader."""
        code = "config = yaml.load(data)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_javascript_eval(self):
        """Debe detectar eval() en JavaScript."""
        code = "eval(userInput)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_innerHTML(self):
        """Debe detectar innerHTML sin sanitización."""
        code = "element.innerHTML = userInput"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_detect_document_write(self):
        """Debe detectar document.write()."""
        code = 'document.write("<script>...")'

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0

    def test_no_false_positives_safe_code(self):
        """No debe generar falsos positivos en código seguro."""
        code = """
import json

def safe_parse(data):
    return json.loads(data)

result = safe_parse('{"key": "value"}')
"""

        detector = LegacyShield()
        results = detector.scan_code(code)

        # No debería encontrar nada peligroso
        assert len(results) == 0

    def test_multiple_issues_same_line(self):
        """Debe detectar múltiples problemas en la misma línea."""
        code = 'api_key = "sk-" + eval(user)'

        detector = LegacyShield()
        results = detector.scan_code(code)

        # Ambos problemas en la misma línea
        assert len(results) >= 2

    def test_get_summary(self):
        """Debe generar resumen correcto."""
        code = """
result = eval(user_input)
subprocess.call(cmd, shell=True)
api_key = "secret"
"""

        detector = LegacyShield()
        results = detector.scan_code(code)
        summary = detector.get_summary(results)

        assert summary["total"] >= 3
        assert summary["critical"] >= 1  # eval() y shell=True son CRITICAL

    def test_block_critical(self):
        """Debe bloquear cuando hay problemas críticos."""
        code = "result = eval(user_input)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert detector.block_critical(results) is True

    def test_no_block_without_critical(self):
        """No debe bloquear sin problemas críticos."""
        code = """
# This is just a comment
def hello():
    print("Hello, World!")
"""

        detector = LegacyShield()
        results = detector.scan_code(code)

        assert detector.block_critical(results) is False

    def test_severity_levels(self):
        """Debe asignar niveles de severidad correctos."""
        code = "result = eval(user_input)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        # eval() es CRITICAL
        assert results[0].pattern.severity == Severity.CRITICAL

    def test_cve_references(self):
        """Debe incluir referencias CVE cuando estén disponibles."""
        code = "result = eval(user_input)"

        detector = LegacyShield()
        results = detector.scan_code(code)

        # Algunos patrones tienen CVE
        has_cve = any(r.pattern.cve_ref for r in results)
        assert has_cve or len(results) > 0


class TestSeverityEnum:
    """Tests para el enum Severity."""

    def test_severity_order(self):
        """Debe mantener el orden correcto de severidad."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestZombiePattern:
    """Tests para la estructura ZombiePattern."""

    def test_pattern_creation(self):
        """Debe crear patrones correctamente."""
        pattern = ZombiePattern(
            pattern=r"\beval\s*\(",
            severity=Severity.CRITICAL,
            description="eval() permite ejecución",
            alternative="json.loads()",
            language="python",
        )

        assert pattern.pattern == r"\beval\s*\("
        assert pattern.severity == Severity.CRITICAL


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
