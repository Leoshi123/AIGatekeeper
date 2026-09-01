# -*- coding: utf-8 -*-
"""
AG-Wrapper MCP Plugin — Core Module

Provides the AGWrapperPlugin class that can be registered with any FastMCP instance.
"""

import sys
import json
import logging
import tempfile
import os
from pathlib import Path
from typing import Optional
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from mcp.server.fastmcp import FastMCP, Context

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src import __version__
from src.sanitizer import MetadataSanitizer
from src.ast_parser import ASTExtractor
from src.detector import LegacyShield, scan_directory as scan_dir_fn
from src.version_check import check_for_updates


logger = logging.getLogger(__name__)


# =============================================================================
# RESILIENCE LAYER
# =============================================================================

def mcp_error_boundary(func):
    """Global boundary to prevent server crashes by capturing all exceptions."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            logger.error(f"MCP Tool Error in {func.__name__}:\n{error_trace}")

            return json.dumps({
                "error": "Internal Server Error",
                "message": str(e),
                "tool": func.__name__,
                "status": "failed"
            }, indent=2)
    return wrapper


def timeout_handler(seconds: int):
    """Decorator to enforce real tool execution timeouts using a ThreadPoolExecutor."""
    def decorator(func):
        executor = ThreadPoolExecutor(max_workers=1)

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                future = executor.submit(func, *args, **kwargs)
                return future.result(timeout=seconds)
            except FutureTimeoutError:
                return json.dumps({
                    "error": "TimeoutError",
                    "message": f"Tool execution timed out after {seconds}s",
                    "tool": func.__name__
                }, indent=2)
            except Exception as e:
                raise e
        return wrapper
    return decorator


# =============================================================================
# PLUGIN CLASS
# =============================================================================

class AGWrapperPlugin:
    """
    AG-Wrapper MCP Plugin.

    Registers security tools with an MCP server:
    - sanitize_code: Remove AI metadata, secrets, and paths
    - scan_code: Detect vulnerable patterns in code
    - scan_directory: Scan all files in a directory
    - prune_context: Extract minimal relevant context via AST
    - clean_code: Quick clean of code string

    Usage:
        from mcp.server.fastmcp import FastMCP
        from src.mcp_plugin import AGWrapperPlugin

        mcp = FastMCP(name="MyServer")
        plugin = AGWrapperPlugin()
        plugin.register(mcp)
    """

    def __init__(self, prefix: str = "ag"):
        """
        Initialize the plugin.

        Args:
            prefix: Prefix for tool names (default: "ag" → "ag_sanitize_code")
        """
        self.prefix = prefix
        self._tools_registered = []

    def register(self, mcp: FastMCP) -> None:
        """
        Register all plugin tools with an MCP server.

        Args:
            mcp: FastMCP instance to register tools with
        """
        self._register_tool(mcp, "sanitize_code", self._sanitize_code_impl, 30)
        self._register_tool(mcp, "scan_code", self._scan_code_impl, 60)
        self._register_tool(mcp, "scan_directory", self._scan_directory_impl, 120)
        self._register_tool(mcp, "prune_context", self._prune_context_impl, 30)
        self._register_tool(mcp, "clean_code", self._clean_code_impl, 10)
        self._register_tool(mcp, "update_check", self._update_check_impl, 15)

        self._register_resources(mcp)
        self._register_prompts(mcp)

        logger.info(f"AG-Wrapper plugin registered with prefix '{self.prefix}'")

    def _register_tool(self, mcp: FastMCP, name: str, func, timeout: int) -> None:
        """Register a single tool with timeout and error boundary."""
        tool_name = f"{self.prefix}_{name}" if self.prefix else name

        # Apply decorators
        decorated = mcp_error_boundary(timeout_handler(timeout)(func))

        # Register with MCP
        mcp.tool()(decorated)
        self._tools_registered.append(tool_name)
        logger.debug(f"Registered tool: {tool_name}")

    def _register_resources(self, mcp: FastMCP) -> None:
        """Register plugin resources."""
        resource_prefix = self.prefix if self.prefix else "ag"
        @mcp.resource(f"{resource_prefix}://version")
        def get_version() -> str:
            """Returns the AG-Wrapper version."""
            return f"AG-Wrapper v{__version__} — Zero-Trust AI Agent Security (Plugin)"

        @mcp.resource(f"{resource_prefix}://languages")
        def get_supported_languages() -> str:
            """Returns the list of supported programming languages and pattern counts."""
            languages = {
                "Python": 24,
                "JavaScript/Node.js": "20+",
                "TypeScript": "15+",
                "Go": 6,
                "Rust": 5,
                "Java": 4,
                "C/C++": 4,
                "PHP": "15+",
                "React 19": "10+",
            }
            return json.dumps(languages, indent=2)

        @mcp.resource(f"{resource_prefix}://severity-levels")
        def get_severity_levels() -> str:
            """Returns the severity levels used by the scanner."""
            levels = {
                "critical": "Immediate security risk — must fix (eval, exec, system calls)",
                "high": "Significant vulnerability — should fix (SQL injection, XSS)",
                "medium": "Potential issue — review recommended (deprecated libraries)",
                "low": "Minor concern — informational (type safety, style)",
                "info": "General information",
            }
            return json.dumps(levels, indent=2)

    def _register_prompts(self, mcp: FastMCP) -> None:
        """Register plugin prompts."""
        @mcp.prompt()
        def security_review(code: str, language: str = "python") -> str:
            """Generate a prompt for a thorough security review of code."""
            return (
                f"Review the following {language} code for security vulnerabilities, "
                f"best practices, and potential exploits. Provide specific recommendations.\n\n"
                f"```{language}\n{code}\n```\n\n"
                f"Focus on: injection attacks, hardcoded secrets, unsafe deserialization, "
                f"path traversal, and deprecated libraries."
            )

        @mcp.prompt()
        def prepare_for_ai(code: str, task: str = "refactor and improve") -> str:
            """Generate a prompt to prepare code for AI agent processing."""
            return (
                f"Your task: {task}\n\n"
                f"Here is the code to work with:\n\n"
                f"```python\n{code}\n```\n\n"
                f"Please provide clean, well-documented code following best practices. "
                f"Avoid introducing security vulnerabilities, hardcoded secrets, or "
                f"unsafe patterns."
            )

    # ==========================================================================
    # TOOL IMPLEMENTATIONS
    # ==========================================================================

    def _sanitize_code_impl(
        self,
        code: str,
        file_path: Optional[str] = None,
    ) -> str:
        """Remove AI-generated metadata, secrets, absolute paths, and model signatures from code.

        Use this to clean code produced by Claude, GPT, or other AI agents before
        committing or sharing it.

        Args:
            code: The source code to sanitize.
            file_path: Optional file path for language detection (e.g. "main.py").

        Returns:
            JSON string with 'cleaned_code' and 'removed_items' list.
        """
        sanitizer = MetadataSanitizer()
        result = sanitizer.sanitize(code)

        return json.dumps(
            {
                "cleaned_code": result.cleaned_code,
                "removed_items": [
                    {"type": t, "content": c} for t, c in result.removed_items
                ],
                "file": file_path or "unknown",
            },
            ensure_ascii=False,
            indent=2,
        )

    def _scan_code_impl(
        self,
        code: str,
        language: str = "python",
        file_path: Optional[str] = None,
        block_critical: bool = False,
    ) -> str:
        """Scan code for vulnerable patterns: eval(), exec(), SQL injection, XSS, hardcoded secrets, etc.

        Detects 60+ dangerous patterns across Python, JavaScript, TypeScript, Go,
        Rust, Java, C/C++, PHP, and React.

        Args:
            code: The source code to analyze.
            language: Language hint for pattern matching (python, javascript, typescript, go, rust, java, c, cpp, php).
            file_path: Optional file path for context.
            block_critical: If True, returns BLOCKED status when critical issues found.

        Returns:
            JSON string with findings list, severity summary, and blocked status.
        """
        detector = LegacyShield()
        results = detector.scan_code(code)

        if not results:
            return json.dumps(
                {
                    "status": "clean",
                    "message": "No vulnerabilities detected",
                    "file": file_path or "unknown",
                    "language": language,
                },
                indent=2,
            )

        summary = detector.get_summary(results)
        blocked = block_critical and detector.block_critical(results)

        findings = []
        for r in results:
            findings.append(
                {
                    "line": r.line_number,
                    "severity": r.pattern.severity.value,
                    "description": r.pattern.description,
                    "alternative": r.pattern.alternative,
                    "code": r.line_content[:120],
                }
            )

        return json.dumps(
            {
                "status": "blocked" if blocked else "vulnerabilities_found",
                "total": summary["total"],
                "critical": summary["critical"],
                "high": summary["high"],
                "medium": summary["medium"],
                "low": summary["low"],
                "findings": findings,
                "file": file_path or "unknown",
                "language": language,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _scan_directory_impl(
        self,
        directory: str,
        extensions: list[str] | None = None,
    ) -> str:
        """Scan all files in a directory for vulnerable patterns.

        Recursively scans source files and reports findings per file.

        Args:
            directory: Path to the directory to scan.
            extensions: File extensions to include (default: .py, .js, .ts, .jsx, .tsx, .go, .rs, .java, .c, .cpp, .php).

        Returns:
            JSON string with per-file findings and global summary.
        """
        if not os.path.isdir(directory):
            return json.dumps({"error": f"Directory not found: {directory}"}, indent=2)

        exts = extensions or [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".c", ".cpp", ".php",
        ]

        project_path = _find_project_root(directory)
        results = scan_dir_fn(directory, exts, project_path=project_path)

        if not results:
            return json.dumps(
                {
                    "status": "clean",
                    "message": "No vulnerabilities detected in directory",
                    "directory": directory,
                },
                indent=2,
            )

        all_results = []
        files_with_issues = {}
        for file_path, file_results in results.items():
            all_results.extend(file_results)
            files_with_issues[file_path] = len(file_results)

        detector = LegacyShield(project_path=project_path)
        summary = detector.get_summary(all_results)

        file_summaries = {}
        for file_path, file_results in results.items():
            file_summaries[file_path] = [
                {
                    "line": r.line_number,
                    "severity": r.pattern.severity.value,
                    "description": r.pattern.description,
                    "code": r.line_content[:100],
                }
                for r in file_results
            ]

        return json.dumps(
            {
                "status": "vulnerabilities_found",
                "files_scanned_with_issues": len(results),
                "total_issues": summary["total"],
                "critical": summary["critical"],
                "high": summary["high"],
                "medium": summary["medium"],
                "low": summary["low"],
                "files": file_summaries,
                "directory": directory,
            },
            ensure_ascii=False,
            indent=2,
        )

    def _prune_context_impl(
        self,
        code: str,
        task: str = "general optimization",
        file_path: Optional[str] = None,
        functions: list[str] | None = None,
    ) -> str:
        """Extract minimal relevant context from code using AST analysis.

        Reduces the amount of code sent to AI agents by keeping only imports,
        relevant functions, and signatures. Typically achieves 40-80% reduction.

        Args:
            code: The source code to prune.
            task: Description of the task to determine relevance.
            file_path: Optional file path (needed for file-based pruning).
            functions: Specific function names to include (optional).

        Returns:
            JSON string with pruned code, stats, and reduction percentage.
        """
        try:
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", encoding="utf-8", delete=False) as tf:
                tf.write(code)
                temp_path = tf.name

            extractor = ASTExtractor()
            func_list = functions or None
            pruned = extractor.prune(temp_path, task, func_list)
            stats = extractor.get_stats(pruned)

            output_code = _build_pruned_output(pruned)

            return json.dumps(
                {
                    "pruned_code": output_code,
                    "stats": {
                        "original_lines": stats["original_lines"],
                        "pruned_lines": stats["pruned_lines"],
                        "reduction_percent": stats["reduction_percent"],
                        "functions_kept": stats["functions_kept"],
                        "functions_omitted": stats["functions_omitted"],
                        "imports": len(pruned.imports),
                        "relevant_functions": [f.name for f in pruned.relevant_functions],
                    },
                    "file": file_path or "unknown",
                },
                ensure_ascii=False,
                indent=2,
            )
        finally:
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)

    def _clean_code_impl(self, code: str) -> str:
        """Quick clean of code string — removes AI metadata only (no vulnerability scan).

        Simpler version of sanitize_code that returns just the cleaned code.

        Args:
            code: The source code to clean.

        Returns:
            The cleaned code as plain text.
        """
        sanitizer = MetadataSanitizer()
        result = sanitizer.sanitize(code)
        return result.cleaned_code

    def _update_check_impl(self) -> str:
        """Check if the installed AG-Wrapper version is outdated vs latest GitHub release.

        Reads LOCAL version first (src.__version__), then queries GitHub Releases.
        Never blocks: if the network fails, returns local version as reference.
        """
        result = check_for_updates()
        return json.dumps(result, ensure_ascii=False, indent=2)


# =============================================================================
# HELPERS
# =============================================================================

def _build_pruned_output(pruned) -> str:
    """Build pruned code output."""
    lines = []
    lines.append("# ===== IMPORTS =====")
    lines.extend(pruned.imports)
    lines.append("")
    lines.append("# ===== SIGNATURES (OMITTED BODY) =====")
    lines.extend(pruned.signatures)
    lines.append("")
    lines.append("# ===== RELEVANT FUNCTIONS =====")
    for func in pruned.relevant_functions:
        lines.append(f"# --- {func.name} ---")
        lines.append(func.signature)
        lines.append(func.body)
        lines.append("")
    return "\n".join(lines)


def _find_project_root(start_path: str) -> str:
    """Find project root by looking for .agrc or .git."""
    current = Path(start_path)
    for _ in range(15):
        if (current / ".agrc").exists() or (current / ".git").exists():
            return str(current)
        parent = current.parent
        if parent == current:
            break
        current = parent
    return str(start_path)
