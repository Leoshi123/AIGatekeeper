# -*- coding: utf-8 -*-
"""
AG-Wrapper MCP Plugin — Tool Functions

Direct function exports for tools that can be used without registering the full plugin.
"""

import sys
import json
import tempfile
import os
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.sanitizer import MetadataSanitizer
from src.ast_parser import ASTExtractor
from src.detector import LegacyShield, scan_directory as scan_dir_fn


def sanitize_code(code: str, file_path: Optional[str] = None) -> str:
    """Remove AI-generated metadata, secrets, absolute paths, and model signatures from code.

    Args:
        code: The source code to sanitize.
        file_path: Optional file path for language detection.

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


def scan_code(
    code: str,
    language: str = "python",
    file_path: Optional[str] = None,
    block_critical: bool = False,
) -> str:
    """Scan code for vulnerable patterns: eval(), exec(), SQL injection, XSS, hardcoded secrets, etc.

    Args:
        code: The source code to analyze.
        language: Language hint for pattern matching.
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


def scan_directory(directory: str, extensions: list[str] | None = None) -> str:
    """Scan all files in a directory for vulnerable patterns.

    Args:
        directory: Path to the directory to scan.
        extensions: File extensions to include (default: common source files).

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
    for file_path, file_results in results.items():
        all_results.extend(file_results)

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


def prune_context(
    code: str,
    task: str = "general optimization",
    file_path: Optional[str] = None,
    functions: list[str] | None = None,
) -> str:
    """Extract minimal relevant context from code using AST analysis.

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
        pruned = extractor.prune(temp_path, task, functions or None)
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


def clean_code(code: str) -> str:
    """Quick clean of code string — removes AI metadata only.

    Args:
        code: The source code to clean.

    Returns:
        The cleaned code as plain text.
    """
    sanitizer = MetadataSanitizer()
    result = sanitizer.sanitize(code)
    return result.cleaned_code


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
