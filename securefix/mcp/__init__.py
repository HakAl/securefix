"""
MCP (Model Context Protocol) integration for GitHub PR automation.

This module provides functionality to automatically create GitHub Pull Requests
with security fixes via the github-mcp-server.
"""

from .pr_content import (
    generate_commit_message,
    generate_pr_title,
    generate_pr_body,
)
from .code_patcher import (
    group_fixes_by_file,
    apply_fixes_to_file,
)

__all__ = [
    'generate_commit_message',
    'generate_pr_title',
    'generate_pr_body',
    'group_fixes_by_file',
    'apply_fixes_to_file',
]
