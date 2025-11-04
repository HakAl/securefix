"""
MCP (Model Context Protocol) integration for GitHub PR automation.

This module provides functionality to automatically create GitHub Pull Requests
with security fixes via the github-mcp-server.

All functions are framework-agnostic and use callback patterns for output,
making them reusable from CLI, API, web interfaces, etc.
"""

# PR content generation
from .pr_content import (
    generate_commit_message,
    generate_pr_title,
    generate_pr_body,
)

# Code patching
from .code_patcher import (
    group_fixes_by_file,
    apply_fixes_to_file,
)

# Repository utilities
from .repo_utils import (
    detect_repo_root,
    make_relative_path,
    convert_files_to_relative,
)

# PR business logic
from .pr_logic import (
    should_create_pr,
    generate_branch_name,
    prepare_pr_data,
)

# MCP client
from .mcp_client import (
    create_pr_via_mcp,
)

__all__ = [
    # PR content
    'generate_commit_message',
    'generate_pr_title',
    'generate_pr_body',
    # Code patching
    'group_fixes_by_file',
    'apply_fixes_to_file',
    # Repository utilities
    'detect_repo_root',
    'make_relative_path',
    'convert_files_to_relative',
    # PR logic
    'should_create_pr',
    'generate_branch_name',
    'prepare_pr_data',
    # MCP client
    'create_pr_via_mcp',
]
