"""
Code patching utilities for applying security fixes to files.

Uses LibCST for syntax-aware patching with fallback to line-based replacement.
"""
from typing import List, Dict, Tuple, Set
from collections import defaultdict
from difflib import SequenceMatcher
import os
import re


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


def _extract_imports(code: str) -> Tuple[Set[str], str]:
    """
    Extract import statements from code snippet.

    Args:
        code: Code snippet that may contain imports

    Returns:
        Tuple of (set of import lines, code without imports)
    """
    lines = code.split('\n')
    imports = set()
    non_import_lines = []

    for line in lines:
        stripped = line.strip()
        # Match import statements (import x, from x import y)
        if stripped.startswith('import ') or stripped.startswith('from '):
            imports.add(stripped)
        elif stripped or non_import_lines:  # Include line if non-empty or after content started
            non_import_lines.append(line)

    # Remove trailing empty lines
    while non_import_lines and not non_import_lines[-1].strip():
        non_import_lines.pop()

    cleaned_code = '\n'.join(non_import_lines)
    return imports, cleaned_code


def _get_existing_imports(file_content: str) -> Set[str]:
    """
    Extract existing import statements from file.

    Args:
        file_content: Full file content

    Returns:
        Set of normalized import statements
    """
    imports = set()
    lines = file_content.split('\n')

    for line in lines:
        stripped = line.strip()
        if stripped.startswith('import ') or stripped.startswith('from '):
            imports.add(stripped)

    return imports


def _add_missing_imports(file_content: str, new_imports: Set[str]) -> str:
    """
    Add missing imports to the file after existing imports.

    Args:
        file_content: Original file content
        new_imports: Set of import statements to add

    Returns:
        File content with new imports added
    """
    if not new_imports:
        return file_content

    existing = _get_existing_imports(file_content)
    imports_to_add = new_imports - existing

    if not imports_to_add:
        return file_content

    # Find where to insert imports (after last import in top import block)
    lines = file_content.split('\n')
    last_import_idx = -1
    found_import_block = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Skip shebang, encoding, docstrings, and initial comments
        if not found_import_block and (stripped.startswith('#') or
                                        stripped.startswith('"""') or
                                        stripped.startswith("'''") or
                                        not stripped):
            continue

        # Found an import
        if stripped.startswith('import ') or stripped.startswith('from '):
            last_import_idx = i
            found_import_block = True
        # Hit actual code (not import, not comment, not blank) - stop looking
        elif found_import_block and stripped and not stripped.startswith('#'):
            break

    # Insert new imports
    if last_import_idx >= 0:
        # Insert after last import
        insert_idx = last_import_idx + 1
        lines[insert_idx:insert_idx] = sorted(imports_to_add)
    else:
        # No existing imports, insert at top after docstrings/comments
        insert_idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip shebang, encoding, docstrings, and comments
            if (stripped.startswith('#') or
                stripped.startswith('"""') or
                stripped.startswith("'''") or
                not stripped):
                continue
            insert_idx = i
            break

        lines[insert_idx:insert_idx] = sorted(imports_to_add)

    return '\n'.join(lines)


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
    all_imports = set()

    # First pass: extract imports and clean suggested fixes
    cleaned_remediations = []
    for rem in remediations:
        finding = rem['finding']
        old_snippet = finding.get('snippet', '')
        new_snippet = rem.get('suggested_fix', '')
        target_line = finding.get('line', 1) - 1  # Convert to 0-indexed

        if not old_snippet or not new_snippet:
            continue

        # Extract imports from suggested fix
        imports, cleaned_fix = _extract_imports(new_snippet)
        all_imports.update(imports)

        # Create cleaned remediation
        cleaned_rem = rem.copy()
        cleaned_rem['suggested_fix'] = cleaned_fix
        cleaned_remediations.append(cleaned_rem)

    # Second pass: apply fixes with cleaned snippets
    for rem in cleaned_remediations:
        finding = rem['finding']
        old_snippet = finding.get('snippet', '')
        new_snippet = rem.get('suggested_fix', '')
        target_line = finding.get('line', 1) - 1  # Convert to 0-indexed

        # Try to find and replace the snippet
        try:
            lines = _find_and_replace_snippet(
                lines, target_line, old_snippet, new_snippet
            )
        except ValueError as e:
            # Log warning but continue with other fixes
            print(f"Warning: Could not apply fix at line {target_line + 1}: {e}")
            continue

    # Third pass: add missing imports
    content_with_fixes = ''.join(lines)
    content_with_imports = _add_missing_imports(content_with_fixes, all_imports)

    return content_with_imports


def _extend_to_complete_function(lines: List[str], start_idx: int, initial_lines: int, debug: bool = False) -> int:
    """
    Extend line range to include complete function/block.

    Args:
        lines: File lines
        start_idx: Starting line index
        initial_lines: Initial number of lines detected
        debug: Enable debug output

    Returns:
        Extended number of lines to include entire function
    """
    # Check if this is a function definition
    if start_idx >= len(lines):
        if debug:
            print(f'  [EXTEND] start_idx >= len(lines), returning {initial_lines}')
        return initial_lines

    # Check if ANY line in the matched range is a function/class definition
    # This handles cases where matching starts at a blank line before the function
    func_line_idx = None
    for i in range(start_idx, min(start_idx + initial_lines, len(lines))):
        stripped = lines[i].strip()
        if stripped.startswith('def ') or stripped.startswith('class '):
            func_line_idx = i
            break

    if func_line_idx is None:
        if debug:
            print(f'  [EXTEND] No def/class found in lines {start_idx}-{start_idx+initial_lines}, returning {initial_lines}')
        return initial_lines

    # Find base indentation of the function
    base_indent = len(lines[func_line_idx]) - len(lines[func_line_idx].lstrip())

    # Scan forward from the function line to find all lines that belong to it
    current_idx = func_line_idx + 1
    while current_idx < len(lines):
        line = lines[current_idx]
        stripped = line.strip()
        line_indent = len(line) - len(line.lstrip())

        # Check indentation first - if at or less than base, we've exited the function
        # This stops at module-level code (blank lines, comments, or next function)
        if stripped and line_indent <= base_indent:
            break

        # Empty lines or comments within function (indented)
        # Only skip if indented, otherwise we've hit the end
        if not stripped:
            # Blank line - could be end of function or within it
            # Check next non-blank line to decide
            next_idx = current_idx + 1
            while next_idx < len(lines) and not lines[next_idx].strip():
                next_idx += 1

            if next_idx >= len(lines):
                # End of file
                break

            next_indent = len(lines[next_idx]) - len(lines[next_idx].lstrip())
            if next_indent <= base_indent:
                # Next non-blank line is at module level, so stop here
                break

            # Next line is still indented, so this blank is within function
            current_idx += 1
            continue

        # Non-empty line that's indented - part of function
        current_idx += 1

    # Return total lines from start to end of function
    return current_idx - start_idx


def _find_and_replace_snippet(
    lines: List[str],
    target_line: int,
    old_snippet: str,
    new_snippet: str,
    debug: bool = False
) -> List[str]:
    """
    Find snippet near target line and replace, preserving indentation.

    Uses exact matching first, then fuzzy matching if exact fails.
    If replacing a function, automatically extends to include the entire function.

    Args:
        lines: File lines (with newlines preserved)
        target_line: 0-indexed line number where snippet should be
        old_snippet: Original code snippet to find
        new_snippet: New code snippet to insert
        debug: Enable debug output

    Returns:
        Modified lines

    Raises:
        ValueError: If snippet cannot be located
    """
    # Parse old snippet
    old_lines = old_snippet.split('\n')
    num_old_lines = len(old_lines)

    if debug:
        print(f'\n[DEBUG _find_and_replace_snippet]')
        print(f'  target_line: {target_line}')
        print(f'  num_old_lines: {num_old_lines}')
        print(f'  old_snippet: {repr(old_snippet[:50])}...')

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

        # Compare (strip common trailing comment markers and internal newlines for comparison)
        old_normalized = old_snippet.replace('  # ', ' # ').replace('\n', ' ').strip()
        candidate_normalized = candidate.replace('  # ', ' # ').replace('\n', ' ').strip()

        # Skip if either is empty (blank lines would match everything)
        if not old_normalized or not candidate_normalized:
            continue

        # Require high similarity (not just substring match)
        # This prevents partial matches like matching just the first line of a 2-line snippet
        if old_normalized == candidate_normalized:
            # Found exact match! Extend to full function if needed
            if debug:
                print(f'  [MATCH] Found at line {i}')
                print(f'    Matched {num_old_lines} lines')
                for j in range(i, i + num_old_lines):
                    print(f'      [{j}]: {repr(lines[j][:50])}...')
            extended_lines = _extend_to_complete_function(lines, i, num_old_lines)
            if debug:
                print(f'    Extended to {extended_lines} lines')
            # Use the matched line's indentation, not target_line
            return _replace_lines_preserving_indent(
                lines, i, extended_lines, new_snippet
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
        # Found fuzzy match! Extend to full function if needed
        extended_lines = _extend_to_complete_function(lines, best_match_idx, num_old_lines)
        return _replace_lines_preserving_indent(
            lines, best_match_idx, extended_lines, new_snippet
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
    # Detect indentation from first non-blank line being replaced
    # Skip blank lines to avoid incorrect indentation
    base_indent = 0
    for i in range(start_idx, min(start_idx + num_lines, len(lines))):
        if lines[i].strip():  # Non-blank line
            original_line = lines[i]
            base_indent = len(original_line) - len(original_line.lstrip())
            break

    # Split new snippet and apply indentation
    new_lines = new_snippet.split('\n')

    # Detect minimum indentation in new snippet (excluding empty lines)
    # This represents the "base" indentation level of the fix
    min_indent = float('inf')
    for line in new_lines:
        if line.strip():  # Non-empty line
            line_indent = len(line) - len(line.lstrip())
            min_indent = min(min_indent, line_indent)

    if min_indent == float('inf'):
        min_indent = 0

    # Apply indentation while preserving relative indentation
    indented_new = []
    for new_line in new_lines:
        if new_line.strip():  # Non-empty line
            # Calculate relative indentation from the minimum
            line_indent = len(new_line) - len(new_line.lstrip())
            relative_indent = line_indent - min_indent

            # Apply base indent + relative indent
            indented_line = ' ' * (base_indent + relative_indent) + new_line.lstrip()
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
