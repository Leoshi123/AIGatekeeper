"""
🛡️ ZTC-Wrapper - Extractor AST (Context-Pruner)

Analiza código fuente y extrae solo las funciones relevantes para una tarea,
reduciendo el contexto enviado a la IA hasta en 70%.

Usa tree-sitter si está disponible, o fallback con análisis regex.
"""

import re
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

# Intentar importar tree-sitter
try:
    import tree_sitter
    from tree_sitter import Language, Parser

    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False
    # Stub para cuando no está disponible
    Parser = None


@dataclass
class ExtractedFunction:
    """Función extraída del código."""

    name: str
    signature: str  # Línea de def/defun/function
    body: str  # Cuerpo de la función
    imports_needed: List[str]
    dependencies: List[str]  # Funciones que llama esta función


@dataclass
class PrunedContext:
    """Contexto podado resultado del análisis."""

    imports: List[str]
    signatures: List[str]  # Solo firmas de funciones no relevantes
    relevant_functions: List[ExtractedFunction]
    omitted_count: int
    original_lines: int
    pruned_lines: int


class ASTExtractor:
    """
    Extrae contexto mínimo relevante usando Análisis Sintáctico Abstracto.

    Uso:
        extractor = ASTExtractor()
        pruned = extractor.prune(file_path, task_description)
    """

    # Patrones regex para lenguajes comunes (fallback)
    FUNCTION_PATTERNS = {
        "python": {
            "import": r"^import\s+([\w.]+)",
            "from_import": r"^from\s+([\w.]+)\s+import",
            "function": r"^(?:def|async\s+def)\s+(\w+)\s*\([^)]*\).*:",
            "class": r"^class\s+(\w+)\s*[:\(]",
        },
        "javascript": {
            "import": r"^import\s+.*?from\s+['\"]([^'\"]+)['\"]",
            "require": r"^const\s+\w+\s*=\s*require\(['\"]([^'\"]+)['\"]",
            "function": r"^(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>)",
            "class": r"^class\s+(\w+)",
        },
        "typescript": {
            "import": r"^import\s+.*?from\s+['\"]([^'\"]+)['\"]",
            "function": r"^(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>)",
            "class": r"^class\s+(\w+)",
        },
    }

    def __init__(self, use_tree_sitter: bool = True):
        """
        Inicializa el extractor.

        Args:
            use_tree_sitter: Si True, intenta usar tree-sitter. Si False, usa regex.
        """
        self.use_tree_sitter = use_tree_sitter and TREE_SITTER_AVAILABLE
        self.parser = None

        if self.use_tree_sitter:
            self._init_parser()

    def _init_parser(self):
        """Inicializa el parser de tree-sitter."""
        if not TREE_SITTER_AVAILABLE:
            return

        try:
            # Intentar cargar lenguajes
            self.parser = Parser()
            # Nota: Se necesitan los language blobs para cada lenguaje
            # Por ahora usamos el fallback
        except Exception:
            self.use_tree_sitter = False

    def detect_language(self, file_path: str) -> str:
        """Detecta el lenguaje del archivo."""
        ext = Path(file_path).suffix.lower()

        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".go": "go",
            ".rs": "rust",
            ".java": "java",
            ".cpp": "cpp",
            ".c": "c",
        }

        return lang_map.get(ext, "python")

    def prune(
        self,
        file_path: str,
        task_description: str,
        functions_to_include: Optional[List[str]] = None,
    ) -> PrunedContext:
        """
        Poda el código para enviar solo lo necesario.

        Args:
            file_path: Ruta al archivo de código
            task_description: Descripción de la tarea (e.g., "optimizar función login")
            functions_to_include: Lista de funciones específicas a incluir.
                                  Si None, analiza la tarea para inferir.

        Returns:
            PrunedContext con el código podado
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            original_code = f.read()

        original_lines = len(original_code.split("\n"))
        language = self.detect_language(file_path)

        # Si no se especifican funciones, analizar la tarea
        if functions_to_include is None:
            functions_to_include = self._infer_relevant_functions(task_description)

        # Extraer usando el método apropiado
        if self.use_tree_sitter:
            return self._prune_with_tree_sitter(
                original_code, language, functions_to_include, original_lines
            )
        else:
            return self._prune_with_regex(
                original_code, language, functions_to_include, original_lines
            )

    def _infer_relevant_functions(self, task_description: str) -> List[str]:
        """
        Infiere qué funciones son relevantes basándose en la descripción de la tarea.

        Mejora: busca palabras que parezcan nombres de funciones.
        """
        import unicodedata

        # Normalizar unicode para evitar problemas con acentos
        task_normalized = unicodedata.normalize("NFKD", task_description)
        task_lower = task_normalized.lower()

        # Palabras clave que indican nombres de funciones
        # Nota: \w no incluye acentos, por eso usamos patrón más flexible
        keywords = [
            r"funcion(?:es)?\s+([a-zA-Z0-9_áéíóúñ]+)",
            r"function\s+([a-zA-Z0-9_]+)",
            r"metodo\s+([a-zA-Z0-9_áéíóúñ]+)",
            r"method\s+([a-zA-Z0-9_]+)",
            r"(\w+)\s+function",
            r"optimizar\s+([a-zA-Z0-9_áéíóúñ]+)",
            r"refactor(?:izar)?\s+([a-zA-Z0-9_áéíóúñ]+)",
            r"fix\s+([a-zA-Z0-9_]+)",
            r"update\s+([a-zA-Z0-9_]+)",
            r"change\s+([a-zA-Z0-9_]+)",
            # Patrón para capturar función al final: "optimizar función login" -> "login"
            r"optimizar\s+funcion\s+([a-zA-Z0-9_áéíóúñ]+)",
            r"fix\s+funcion\s+([a-zA-Z0-9_áéíóúñ]+)",
        ]

        found = []

        for kw_pattern in keywords:
            matches = re.findall(kw_pattern, task_lower)
            found.extend(matches)

        # Si no encontramos nada, buscar cualquier palabra que parezca nombre de función
        if not found:
            # Buscar palabras en snake_case o camelCase
            snake_case = re.findall(r"[a-z]+_[a-z]+", task_lower)
            camel_case = re.findall(r"[a-z]+[A-Z][a-z]+", task_lower)
            found.extend(snake_case)
            found.extend(camel_case)

        # Default: main, app, index (funciones comunes)
        return found if found else ["main", "app", "index"]

    def _prune_with_regex(
        self,
        code: str,
        language: str,
        functions_to_include: List[str],
        original_lines: int,
    ) -> PrunedContext:
        """Fallback: usa regex para extraer funciones."""

        patterns = self.FUNCTION_PATTERNS.get(
            language, self.FUNCTION_PATTERNS["python"]
        )

        imports = []
        all_functions = {}  # nombre -> (signature, body)
        current_function = None
        current_body = []
        indent_level = 0

        lines = code.split("\n")

        for i, line in enumerate(lines):
            stripped = line.strip()

            # Detectar imports
            for imp_pattern in ["import", "from_import"]:
                if imp_pattern in patterns:
                    match = re.match(patterns[imp_pattern], stripped)
                    if match:
                        imports.append(stripped)
                        break

            # Detectar inicio de función
            func_match = re.match(patterns.get("function", ""), stripped)
            if func_match:
                func_name = (
                    func_match.group(1) if func_match.group(1) else func_match.group(2)
                )

                if current_function:
                    # Guardar función anterior
                    all_functions[current_function] = (
                        current_signature,
                        "\n".join(current_body),
                    )

                current_function = func_name
                current_signature = stripped
                current_body = [line]
                indent_level = len(line) - len(line.lstrip())
                continue

            # Agregar a cuerpo de función actual
            if current_function:
                current_body.append(line)

                # Fin de función: misma indentación que el def
                if stripped and not stripped.startswith("#"):
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= indent_level and stripped:
                        # Guardar función anterior
                        all_functions[current_function] = (
                            current_signature,
                            "\n".join(current_body[:-1]),
                        )
                        current_function = None
                        current_body = []
                        # Reprocesar esta línea
                        if re.match(patterns.get("function", ""), stripped):
                            func_name = re.match(patterns.get("function", ""), stripped)
                            if func_name:
                                current_function = func_name.group(1)
                                current_signature = stripped
                                current_body = [line]
                                indent_level = len(line) - len(line.lstrip())

        # Guardar última función
        if current_function:
            all_functions[current_function] = (
                current_signature,
                "\n".join(current_body),
            )

        # Separar funciones relevantes de las demás
        relevant = []
        signatures_only = []
        omitted_count = 0

        for func_name, (signature, body) in all_functions.items():
            # Verificar si es relevante (por nombre o dependencia)
            is_relevant = any(
                func_name.lower() in target.lower()
                or target.lower() in func_name.lower()
                for target in functions_to_include
            )

            if is_relevant:
                # Extraer imports necesarios (básico)
                func_imports = self._extract_function_imports(body, imports)

                relevant.append(
                    ExtractedFunction(
                        name=func_name,
                        signature=signature,
                        body=body,
                        imports_needed=func_imports,
                        dependencies=self._extract_dependencies(
                            body, all_functions.keys()
                        ),
                    )
                )
            else:
                signatures_only.append(signature)
                omitted_count += len(body.split("\n"))

        # Calcular líneas resultantes
        pruned_lines = sum(len(f.body.split("\n")) for f in relevant)
        pruned_lines += len(signatures_only)
        pruned_lines += len(imports)

        return PrunedContext(
            imports=imports,
            signatures=signatures_only,
            relevant_functions=relevant,
            omitted_count=omitted_count,
            original_lines=original_lines,
            pruned_lines=pruned_lines,
        )

    def _prune_with_tree_sitter(
        self,
        code: str,
        language: str,
        functions_to_include: List[str],
        original_lines: int,
    ) -> PrunedContext:
        """
        Usa tree-sitter para análisis más preciso.

        Nota: Esta implementación es un placeholder hasta tener los language blobs.
        """
        # Por ahora delegar al método regex
        return self._prune_with_regex(
            code, language, functions_to_include, original_lines
        )

    def _extract_function_imports(self, body: str, all_imports: List[str]) -> List[str]:
        """Extrae los imports que necesita una función."""
        needed = []
        for imp in all_imports:
            # Verificar si el import se usa en el body
            # Extraer nombre del módulo
            match = re.search(r"(?:import\s+|from\s+)(\w+)", imp)
            if match:
                module = match.group(1)
                if module in body:
                    needed.append(imp)
        return needed

    def _extract_dependencies(self, body: str, all_functions: List[str]) -> List[str]:
        """Extrae las dependencias (otras funciones llamadas)."""
        deps = []
        for func in all_functions:
            # Buscar patrones de llamada
            patterns = [rf"\b{func}\s*\(", rf"{func}\."]
            if any(re.search(p, body) for p in patterns):
                deps.append(func)
        return deps

    def get_stats(self, pruned: PrunedContext) -> Dict:
        """Retorna estadísticas de la poda."""
        return {
            "original_lines": pruned.original_lines,
            "pruned_lines": pruned.pruned_lines,
            "reduction_percent": round(
                (1 - pruned.pruned_lines / pruned.original_lines) * 100, 1
            )
            if pruned.original_lines > 0
            else 0,
            "functions_kept": len(pruned.relevant_functions),
            "functions_omitted": len(pruned.signatures),
        }


def prune_file(file_path: str, task: str = "general optimization") -> PrunedContext:
    """
    Función de conveniencia para podar un archivo.

    Args:
        file_path: Ruta al archivo
        task: Descripción de la tarea

    Returns:
        PrunedContext con resultado
    """
    extractor = ASTExtractor()
    return extractor.prune(file_path, task)


if __name__ == "__main__":
    # Ejemplo de uso
    sample_code = '''
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

    # Guardar temporalmente para probar
    test_file = "/tmp/test_prune.py"
    with open(test_file, "w") as f:
        f.write(sample_code)

    extractor = ASTExtractor()
    pruned = extractor.prune(test_file, "optimizar función process")

    print("=== Resultado de Poda ===")
    print(f"📊 Original: {pruned.original_lines} líneas")
    print(f"📊 Podado: {pruned.pruned_lines} líneas")
    print(f"📉 Reducción: {extractor.get_stats(pruned)['reduction_percent']}%")

    print("\n📦 Imports:")
    for imp in pruned.imports:
        print(f"  {imp}")

    print("\n🔧 Funciones Relevantes:")
    for func in pruned.relevant_functions:
        print(f"  • {func.name}")
        print(f"    Dependencias: {func.dependencies}")

    print("\n📝 Firmas Omitidas:")
    for sig in pruned.signatures:
        print(f"  {sig}")
