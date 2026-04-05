"""
🛡️ ZTC-Wrapper - Tests del Extractor AST

Tests para el podador de contexto.
"""

import pytest
import tempfile
import os
from src.ast_parser import ASTExtractor, prune_file


class TestASTExtractor:
    """Tests para el ASTExtractor."""

    @pytest.fixture
    def sample_python_file(self):
        """Crea un archivo Python de prueba temporal."""
        code = '''
import os
import json
from typing import List, Dict

def main():
    """Entry point"""
    config = load_config()
    return process(config)

def load_config() -> Dict:
    """Load configuration"""
    with open('config.json') as f:
        return json.load(f)

def process(data: Dict) -> List:
    """Process the data"""
    results = []
    for item in data.get('items', []):
        results.append(transform(item))
    return results

def transform(item: Dict) -> Dict:
    """Transform single item"""
    return {'processed': True, **item}

def helper_utility(x: int) -> int:
    """Not relevant for the task"""
    return x * 2
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            return f.name

    def test_detect_language_python(self):
        """Debe detectar lenguaje Python."""
        extractor = ASTExtractor()

        assert extractor.detect_language("test.py") == "python"
        assert extractor.detect_language("test.js") == "javascript"
        assert extractor.detect_language("test.ts") == "typescript"

    def test_prune_extracts_relevant_functions(self, sample_python_file):
        """Debe extraer solo funciones relevantes."""
        extractor = ASTExtractor()
        # Usar task en inglés para evitar problemas de unicode
        pruned = extractor.prune(sample_python_file, "optimize function process")

        func_names = [f.name for f in pruned.relevant_functions]

        # La función 'process' debe estar incluida
        assert "process" in func_names

        # Verificar que detecta dependencias (aunque no las incluya automáticamente)
        process_func = next(
            (f for f in pruned.relevant_functions if f.name == "process"), None
        )
        assert process_func is not None
        assert "transform" in process_func.dependencies

    def test_prune_reduces_lines(self, sample_python_file):
        """Debe reducir el número de líneas."""
        extractor = ASTExtractor()
        pruned = extractor.prune(sample_python_file, "optimize function process")
        stats = extractor.get_stats(pruned)

        assert stats["reduction_percent"] > 0
        assert stats["pruned_lines"] < stats["original_lines"]

    def test_prune_includes_imports(self, sample_python_file):
        """Debe incluir los imports."""
        extractor = ASTExtractor()
        pruned = extractor.prune(sample_python_file, "optimizar función process")

        assert len(pruned.imports) > 0
        assert any("json" in imp.lower() for imp in pruned.imports)

    def test_prune_omits_non_relevant(self, sample_python_file):
        """Debe omitir funciones no relevantes."""
        extractor = ASTExtractor()
        pruned = extractor.prune(sample_python_file, "optimizar función process")

        # helper_utility no debería estar en funciones relevantes
        func_names = [f.name for f in pruned.relevant_functions]
        assert "helper_utility" not in func_names

        # Pero sí en firmas omitidas
        omitted_sigs = " ".join(pruned.signatures)
        assert "helper_utility" in omitted_sigs

    def test_prune_detects_dependencies(self, sample_python_file):
        """Debe detectar dependencias entre funciones."""
        extractor = ASTExtractor()
        pruned = extractor.prune(sample_python_file, "optimize function process")

        # process llama a transform
        process_func = next(
            (f for f in pruned.relevant_functions if f.name == "process"), None
        )
        assert process_func is not None
        assert "transform" in process_func.dependencies

    def test_convenience_function(self):
        """Test de la función de conveniencia."""
        code = """
def main():
    return "hello"

def unused():
    return "bye"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            pruned = prune_file(temp_path, "main")
            assert len(pruned.relevant_functions) > 0
        finally:
            os.unlink(temp_path)

    def test_file_not_found(self):
        """Debe manejar archivo no encontrado."""
        extractor = ASTExtractor()

        with pytest.raises(FileNotFoundError):
            extractor.prune("/nonexistent/file.py", "task")


class TestPrunedContext:
    """Tests para la estructura PrunedContext."""

    def test_stats_calculation(self):
        """Debe calcular estadísticas correctamente."""
        extractor = ASTExtractor()
        code = """
import os

def main():
    return "hello"

def helper():
    return 1
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            pruned = extractor.prune(temp_path, "main")
            stats = extractor.get_stats(pruned)

            assert "original_lines" in stats
            assert "pruned_lines" in stats
            assert "reduction_percent" in stats
            assert stats["reduction_percent"] >= 0
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
