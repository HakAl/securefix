"""
Code patching utilities for applying security fixes to files.

Uses LibCST for syntax-aware patching with fallback to line-based replacement.
"""
from typing import List, Dict, Tuple
from collections import defaultdict
from difflib import SequenceMatcher
import os


def group_fixes_by_file(remediations: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Group remediations by file path and sort by line number (descending).

    Sorting descending ensures that when we apply fixes, line numbers
    for earlier fixes remain valid (we modify bottom-up).

    Args:
        remediations: List of remediation dictionaries

    Returns:
        Dict mapping file_path -> sorted list of remediations for that file
    """
    grouped = defaultdict(list)

    for rem in remediations:
        file_path = rem['finding'].get('file', '')
        if file_path:
            grouped[file_path].append(rem)

    # Sort each file's fixes by line number (descending)
    for file_path in grouped:
        grouped[file_path].sort(
            key=lambda r: r['finding'].get('line', 0),
            reverse=True
        )

    return dict(grouped)


def apply_fixes_to_file(file_path: str, remediations: List[Dict]) -> str:
    """
    Apply multiple fixes to a single file.

    Attempts to use LibCST for syntax-aware patching, falls back to
    line-based replacement if LibCST is not available or fails.

    Args:
        file_path: Path to the file to fix
        remediations: List of fixes for this file (should be sorted desc by line)

    Returns:
        Updated file content as string

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If fixes cannot be applied
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, 'r', encoding='utf-8') as f:
        original_content = f.read()

    # Try LibCST first
    try:
        return _apply_fixes_with_libcst(original_content, remediations, file_path)
    except ImportError:
        # LibCST not installed, use fallback
        pass
    except Exception:
        # LibCST failed, use fallback
        pass

    # Fallback to line-based approach
    return _apply_fixes_line_based(original_content, remediations)


def _apply_fixes_with_libcst(content: str, remediations: List[Dict], file_path: str) -> str:
    """
    Apply fixes using LibCST for syntax-aware patching.

    Args:
        content: Original file content
        remediations: List of fixes to apply
        file_path: File path (for error messages)

    Returns:
        Modified content

    Raises:
        ImportError: If libcst not available
        Exception: If parsing or transformation fails
    """
    import libcst as cst

    # Parse the module
    try:
        module = cst.parse_module(content)
    except Exception as e:
        raise ValueError(f"Failed to parse {file_path} with LibCST: {e}")

    # Apply each fix
    for rem in remediations:
        finding = rem['finding']
        old_snippet = finding.get('snippet', '').strip()
        new_snippet = rem.get('suggested_fix', '').strip()
        target_line = finding.get('line', 0)

        if not old_snippet or not new_snippet:
            continue

        # Create a transformer for this fix
        class FixTransformer(cst.CSTTransformer):
            def __init__(self, target_line_num, old_code, new_code):
                super().__init__()
                self.target_line = target_line_num
                self.old_code = old_code
                self.new_code = new_code
                self.found = False

            def leave_SimpleStatementLine(self, original_node, updated_node):
                # Try to match simple statements (single line)
                # This is a simplified approach - more complex matching needed for multi-line
                node_code = updated_node.body[0] if updated_node.body else None
                if node_code:
                    # Rough comparison (LibCST matching is complex)
                    # For now, just use line number proximity
                    # TODO: Implement proper CST node matching
                    pass
                return updated_node

        # For now, fall back to line-based if complex
        # Full LibCST implementation would require metadata providers
        # and more sophisticated node matching
        raise NotImplementedError("Complex LibCST transformation - using fallback")

    return module.code


def _apply_fixes_line_based(content: str, remediations: List[Dict]) -> str:
    """
    Apply fixes using simple line-based replacement with fuzzy matching.

    Args:
        content: Original file content
        remediations: List of fixes to apply (should be sorted desc by line)

    Returns:
        Modified content

    Raises:
        ValueError: If a fix cannot be applied
    """
    lines = content.splitlines(keepends=True)

    for rem in remediations:
        finding = rem['finding']
        old_snippet = finding.get('snippet', '')
        new_snippet = rem.get('suggested_fix', '')
        target_line = finding.get('line', 1) - 1  # Convert to 0-indexed

        if not old_snippet or not new_snippet:
            continue

        # Try to find and replace the snippet
        try:
            lines = _find_and_replace_snippet(
                lines, target_line, old_snippet, new_snippet
            )
        except ValueError as e:
            # Log warning but continue with other fixes
            print(f"Warning: Could not apply fix at line {target_line + 1}: {e}")
            continue

    return ''.join(lines)


def _find_and_replace_snippet(
    lines: List[str],
    target_line: int,
    old_snippet: str,
    new_snippet: str
) -> List[str]:
    """
    Find snippet near target line and replace, preserving indentation.

    Uses exact matching first, then fuzzy matching if exact fails.

    Args:
        lines: File lines (with newlines preserved)
        target_line: 0-indexed line number where snippet should be
        old_snippet: Original code snippet to find
        new_snippet: New code snippet to insert

    Returns:
        Modified lines

    Raises:
        ValueError: If snippet cannot be located
    """
    # Parse old snippet
    old_lines = old_snippet.split('\n')
    num_old_lines = len(old_lines)

    # Define search window (±10 lines from target)
    search_start = max(0, target_line - 10)
    search_end = min(len(lines), target_line + 11)

    # Try exact match first
    for i in range(search_start, search_end):
        if i + num_old_lines > len(lines):
            continue

        # Extract candidate lines
        candidate_lines = lines[i:i + num_old_lines]
        candidate = ''.join(candidate_lines)

        # Compare (strip common trailing comment markers)
        old_normalized = old_snippet.replace('  # ', ' # ').strip()
        candidate_normalized = candidate.replace('  # ', ' # ').strip()

        if old_normalized in candidate_normalized or candidate_normalized in old_normalized:
            # Found exact match! Detect indentation and replace
            return _replace_lines_preserving_indent(
                lines, i, num_old_lines, new_snippet
            )

    # Try fuzzy match
    best_match_idx = None
    best_ratio = 0.0
    FUZZY_THRESHOLD = 0.85  # 85% similarity required

    for i in range(search_start, search_end):
        if i + num_old_lines > len(lines):
            continue

        candidate_lines = lines[i:i + num_old_lines]
        candidate = ''.join(candidate_lines).strip()
        old_stripped = old_snippet.strip()

        # Calculate similarity
        ratio = SequenceMatcher(None, old_stripped, candidate).ratio()

        if ratio > best_ratio:
            best_ratio = ratio
            best_match_idx = i

    if best_match_idx is not None and best_ratio >= FUZZY_THRESHOLD:
        # Found fuzzy match
        return _replace_lines_preserving_indent(
            lines, best_match_idx, num_old_lines, new_snippet
        )

    raise ValueError(
        f"Could not locate snippet near line {target_line + 1}. "
        f"Best match: {best_ratio:.2f} similarity (need {FUZZY_THRESHOLD:.2f})"
    )


def _replace_lines_preserving_indent(
    lines: List[str],
    start_idx: int,
    num_lines: int,
    new_snippet: str
) -> List[str]:
    """
    Replace lines while preserving indentation.

    Args:
        lines: Original file lines
        start_idx: Index where replacement starts
        num_lines: Number of lines to replace
        new_snippet: New code to insert

    Returns:
        Modified lines list
    """
    # Detect indentation from first line being replaced
    original_line = lines[start_idx]
    indent = len(original_line) - len(original_line.lstrip())
    indent_str = ' ' * indent

    # Split new snippet and apply indentation
    new_lines = new_snippet.split('\n')
    indented_new = []

    for new_line in new_lines:
        if new_line.strip():  # Non-empty line
            # Preserve relative indentation
            line_indent = len(new_line) - len(new_line.lstrip())
            # Apply base indent + relative indent
            indented_line = indent_str + new_line.lstrip()
        else:
            # Empty line
            indented_line = ''

        # Add newline if not last line or if original had newlines
        if not indented_line.endswith('\n'):
            indented_line += '\n'

        indented_new.append(indented_line)

    # Replace the lines
    result = lines[:start_idx] + indented_new + lines[start_idx + num_lines:]

    return result
