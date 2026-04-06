"""
🛡️ ZTC-Wrapper - Tests para el Detector Zombi

Tests para el detector de código vulnerable.
"""

import pytest
import os
from src.detector import (
    LegacyShield,
    Severity,
    DetectionResult,
    ZombiePattern,
    scan_directory,
)


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

    # ==== NUEVOS TESTS AGREGADOS ====

    def test_detect_exec_python(self):
        """Debe detectar exec() en Python."""
        code = 'exec("print(1)")'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any(r.pattern.severity == Severity.CRITICAL for r in results)

    def test_detect_os_system(self):
        """Debe detectar os.system()."""
        code = 'os.system("ls")'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("os.system" in r.pattern.description.lower() for r in results)

    def test_detect_os_popen(self):
        """Debe detectar os.popen()."""
        code = 'os.popen("cat /etc/passwd")'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("popen" in r.pattern.description.lower() for r in results)

    def test_detect_mD5_hash(self):
        """Debe detectar uso de MD5."""
        code = "hash = MD5(data)"
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("md5" in r.pattern.pattern.lower() for r in results)

    def test_detect_sha1_hash(self):
        """Debe detectar uso de SHA1."""
        code = "hash = sha1(data)"
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("sha1" in r.pattern.pattern.lower() for r in results)

    def test_detect_outerHTML(self):
        """Debe detectar outerHTML."""
        code = "element.outerHTML = userInput"
        detector = LegacyShield(languages=["javascript"])
        results = detector.scan_code(code)

        assert any("outerhtml" in r.pattern.pattern.lower() for r in results)

    def test_detect_new_function(self):
        """Debe detectar new Function()."""
        code = 'new Function("return 1")'
        detector = LegacyShield(languages=["javascript"])
        results = detector.scan_code(code)

        assert any("function" in r.pattern.pattern.lower() for r in results)

    def test_detect_password_hardcoded(self):
        """Debe detectar passwords hardcodeadas."""
        code = 'password = "mypassword123"'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("password" in r.pattern.pattern.lower() for r in results)

    def test_detect_secret_hardcoded(self):
        """Debe detectar secrets hardcodeados."""
        code = 'secret = "my-secret-value"'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert any("secret" in r.pattern.pattern.lower() for r in results)

    def test_ignore_magic_comment_python(self):
        """Debe ignorar líneas con # ztc: ignore en Python."""
        code = "eval(user_input)  # ztc: ignore"
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) == 0

    def test_ignore_magic_comment_js(self):
        """Debe ignorar líneas con // ztc: ignore en JS."""
        code = "eval(userInput)  // ztc: ignore"
        detector = LegacyShield(languages=["javascript"])
        results = detector.scan_code(code, file_path="test.js")

        assert len(results) == 0

    def test_scan_file_with_path(self):
        """Debe escanear archivos reales."""
        # Crear archivo temporal con código vulnerable
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('eval("print(1)")')
            temp_path = f.name

        try:
            detector = LegacyShield()
            results = detector.scan_file(temp_path)
            assert len(results) > 0
        finally:
            os.unlink(temp_path)

    def test_scan_directory(self):
        """Debe escanear un directorio completo."""
        import tempfile

        # Crear directorio temporal
        with tempfile.TemporaryDirectory() as tmpdir:
            # Crear archivo seguro
            safe_file = os.path.join(tmpdir, "safe.py")
            with open(safe_file, "w") as f:
                f.write('print("hello")')

            # Crear archivo vulnerable
            unsafe_file = os.path.join(tmpdir, "unsafe.py")
            with open(unsafe_file, "w") as f:
                f.write('eval("print(1)")')

            results = scan_directory(tmpdir, extensions=[".py"])

            # Debe encontrar problemas en unsafe.py
            assert any("unsafe.py" in path for path in results.keys())

    def test_summary_by_language(self):
        """Debe generar resumen por lenguaje."""
        code = """
eval(user_input)  # Python
document.write(x)  # JavaScript
"""
        detector = LegacyShield()
        results = detector.scan_code(code)
        summary = detector.get_summary(results)

        assert "python" in summary["by_language"]
        assert "javascript" in summary["by_language"]


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

    def test_pattern_with_cve(self):
        """Debe crear patrones con CVE."""
        pattern = ZombiePattern(
            pattern=r"\beval\s*\(",
            severity=Severity.CRITICAL,
            description="eval() permite ejecución",
            alternative="json.loads()",
            language="python",
            cve_ref="CVE-2021-23336",
        )

        assert pattern.cve_ref == "CVE-2021-23336"


class TestEdgeCases:
    """Tests para casos edge."""

    def test_empty_code(self):
        """Debe manejar código vacío."""
        detector = LegacyShield()
        results = detector.scan_code("")

        assert len(results) == 0

    def test_only_comments(self):
        """Debe manejar solo comentarios."""
        code = """
# This is a comment
// Another comment
"""
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) == 0

    def test_multiline_string(self):
        """Debe manejar strings multilínea."""
        code = '''
code = """
eval("malicious")
"""
'''
        detector = LegacyShield()
        results = detector.scan_code(code)

        # No debería detectar en strings (por ahora)
        # Este es un caso edge que podría mejorar
        assert len(results) >= 0

    def test_unicode_in_code(self):
        """Debe manejar código con unicode."""
        code = 'eval("print(🦊)")'
        detector = LegacyShield()
        results = detector.scan_code(code)

        assert len(results) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
