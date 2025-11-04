"""
Repository and file path utilities for MCP integration.

Functions for detecting git repositories and converting between absolute
and relative paths.
"""
import os
from pathlib import Path
from typing import List, Callable, Optional


def detect_repo_root(
    file_paths: List[str],
    output: Optional[Callable[[str], None]] = None
) -> str:
    """
    Detect git repository root from a list of file paths.

    Args:
        file_paths: List of absolute file paths
        output: Optional callback for user messages (e.g., click.echo)

    Returns:
        Repository root path, or common directory if no .git found

    Raises:
        ValueError: If no common directory found
    """
    output = output or (lambda x: None)

    if not file_paths:
        raise ValueError("No file paths provided")

    # Convert to absolute paths
    abs_paths = [os.path.abspath(p) for p in file_paths]

    # Find common directory
    common = os.path.commonpath(abs_paths)

    # Walk up to find .git directory
    current = Path(common)
    while current != current.parent:
        if (current / '.git').exists():
            return str(current)
        current = current.parent

    # If no .git found, use common directory
    # (user might not have initialized git yet)
    output(f"⚠ Warning: No .git directory found. Using common directory: {common}")
    return common


def make_relative_path(absolute_path: str, repo_root: str) -> str:
    """
    Convert absolute file path to relative path from repository root.

    Args:
        absolute_path: Absolute file path
        repo_root: Repository root directory

    Returns:
        Relative path with forward slashes (for GitHub)

    Raises:
        ValueError: If path is not within repository root
    """
    abs_path = Path(absolute_path).resolve()
    root = Path(repo_root).resolve()

    try:
        rel_path = abs_path.relative_to(root)
        # Convert to forward slashes for GitHub
        return str(rel_path).replace('\\', '/')
    except ValueError:
        # Path is not relative to root
        raise ValueError(
            f"File {absolute_path} is not within repository root {repo_root}"
        )


def convert_files_to_relative(
    changed_files: dict[str, str],
    repo_root: str,
    output: Optional[Callable[[str], None]] = None
) -> dict[str, str]:
    """
    Convert all absolute file paths to relative paths.

    Args:
        changed_files: Dict mapping absolute paths to file contents
        repo_root: Repository root directory
        output: Optional callback for progress messages

    Returns:
        Dict mapping relative paths to file contents

    Raises:
        ValueError: If any path cannot be converted
    """
    output = output or (lambda x: None)

    output(f"📁 Repository root: {repo_root}")
    relative_files = {}

    for abs_path, content in changed_files.items():
        rel_path = make_relative_path(abs_path, repo_root)
        relative_files[rel_path] = content
        output(f"  → {rel_path}")

    return relative_files
