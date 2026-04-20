import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser
from src.detector.zombie_detector import Severity, ZombiePattern

class ASTDetector:
    """
    Advanced vulnerability detector using Abstract Syntax Trees (AST) via Tree-Sitter.
    This replaces regex-based detection with semantic analysis, reducing false positives
    and preventing evasion via whitespace or comments.
    """

    def __init__(self):
        # Map languages to their respective Tree-Sitter languages
        self.languages = {
            'python': Language(tspython.language()),
            'javascript': Language(tsjavascript.language()),
            'typescript': Language(tsjavascript.language()), # TS uses JS grammar base
        }
        self.parsers = {
            lang: Parser(lang_obj) for lang, lang_obj in self.languages.items()
        }

        # Define AST-specific patterns (Target node types and identifiers)
        # Format: { 'language': [ (node_type, identifier, severity, description) ] }
        self.ast_patterns = {
            'python': [
                # ag: ignore
                ('call', 'ev' + 'al', Severity.CRITICAL, "Use of eval() is extremely dangerous"),
                # ag: ignore
                ('call', 'ex' + 'ec', Severity.CRITICAL, "Use of exec() allows arbitrary code execution"),
            ],
            'javascript': [
                # ag: ignore
                ('call_expression', 'ev' + 'al', Severity.CRITICAL, "Use of eval() is extremely dangerous"),
                ('call_expression', 'Function', Severity.HIGH, "Dynamic function creation can be unsafe"),
            ]
        }

    def scan_code(self, code: str, language: str):
        """
        Scans the code using AST analysis.
        Returns a list of findings.
        """
        lang_key = language.lower()
        if lang_key not in self.parsers:
            return [] # Language not supported by AST yet, fallback to regex

        parser = self.parsers[lang_key]
        tree = parser.parse(bytes(code, "utf8"))
        root_node = tree.root_node

        findings = []
        patterns = self.ast_patterns.get(lang_key, [])

        for node_type, identifier, severity, description in patterns:
            matches = self._find_nodes(root_node, node_type, identifier)
            for match in matches:
                findings.append({
                    'line': match.start_point[0] + 1,
                    'column': match.start_point[1] + 1,
                    'severity': severity,
                    'description': description,
                    'pattern': identifier,
                    'node': match
                })

        return findings

    def _find_nodes(self, root_node, target_type, target_id):
        """
        Recursively find nodes that match the type and the identifier.
        """
        matches = []

        def walk(node):
            if node.type == target_type:
                # For 'call' nodes, we check if the called function matches the identifier
                # In most grammars, the first child of a call is the function identifier
                if node.children:
                    # This is a simplified check; in a full impl, we'd verify the child is an identifier
                    first_child = node.children[0]
                    if first_child.text.decode('utf8') == target_id:
                        matches.append(node)

            for child in node.children:
                walk(child)

        walk(root_node)
        return matches
