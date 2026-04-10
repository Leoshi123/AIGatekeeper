# -*- coding: utf-8 -*-
"""
🛡️ AG-Wrapper MCP Server
Model Context Protocol server for AI Agent security tools.

Exposes AG-Wrapper capabilities as MCP tools:
- sanitize_code: Remove AI metadata, secrets, and paths
- scan_code: Detect vulnerable patterns in a file
- scan_directory: Scan all files in a directory
- prune_context: Extract minimal relevant context via AST
- clean_code: Clean code string directly
"""

import sys
import os
import json
import time
import traceback
import logging
import tempfile
from pathlib import Path
from typing import Optional
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from mcp.server.fastmcp import FastMCP, Context

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.sanitizer import MetadataSanitizer
from src.ast_parser import ASTExtractor
from src.detector import LegacyShield, scan_directory as scan_dir_fn


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
            # Log the full traceback for the server operator
            error_trace = traceback.format_exc()
            logging.error(f"MCP Tool Error in {func.__name__}:\\n{error_trace}")

            # Return a clean JSON error to the client
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
        # We use a single-worker executor per tool to ensure the timeout is enforced
        # and we don't leak threads over time.
        executor = ThreadPoolExecutor(max_workers=1)

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Submit the tool function to the executor
                future = executor.submit(func, *args, **kwargs)
                # Block until the result is ready or the timeout expires
                return future.result(timeout=seconds)
            except FutureTimeoutError:
                return json.dumps({
                    "error": "TimeoutError",
                    "message": f"Tool execution timed out after {seconds}s",
                    "tool": func.__name__
                }, indent=2)
            except Exception as e:
                # Re-raise to be caught by @mcp_error_boundary
                raise e
        return wrapper
    return decorator

mcp = FastMCP(
    name="AG-Wrapper",
    host="127.0.0.1",
    port=8765,
    streamable_http_path="/mcp",
)


# =============================================================================
# TOOLS
# =============================================================================


@mcp.tool()
@mcp_error_boundary
@timeout_handler(30)
def sanitize_code(
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


@mcp.tool()
@mcp_error_boundary
@timeout_handler(60)
def scan_code(
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


@mcp.tool()
@mcp_error_boundary
@timeout_handler(120)
def scan_directory(
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
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".cpp",
        ".php",
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


@mcp.tool()
@mcp_error_boundary
@timeout_handler(30)
def prune_context(
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
    # Create a secure, unique temporary file for AST analysis
    # This prevents race conditions when multiple requests call prune_context simultaneously
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
        # Ensure the temporary file is deleted regardless of success or failure
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.remove(temp_path)


@mcp.tool()
@mcp_error_boundary
@timeout_handler(10)
def clean_code(code: str) -> str:
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


# =============================================================================
# RESOURCES
# =============================================================================


@mcp.resource("ag://version")
def get_version() -> str:
    """Returns the ZTC-Wrapper version."""
    return "AG-Wrapper v1.0.2 — Zero-Trust AI Agent Security"


@mcp.resource("ag://languages")
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


@mcp.resource("ag://severity-levels")
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


# =============================================================================
# PROMPTS
# =============================================================================


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
def prepare_for_ai(
    code: str,
    task: str = "refactor and improve",
) -> str:
    """Generate a prompt to prepare code for AI agent processing."""
    return (
        f"Your task: {task}\n\n"
        f"Here is the code to work with:\n\n"
        f"```python\n{code}\n```\n\n"
        f"Please provide clean, well-documented code following best practices. "
        f"Avoid introducing security vulnerabilities, hardcoded secrets, or "
        f"unsafe patterns."
    )


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


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Support both stdio (default) and streamable-http
    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    mcp.run(transport="stdio" if transport != "http" else "streamable-http")
