"""
Business logic for pull request creation decisions.

Functions to determine if PR should be created, generate branch names,
and prepare PR data structures.
"""
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from securefix.mcp.pr_content import (
    generate_commit_message,
    generate_pr_title,
    generate_pr_body,
)
from securefix.mcp.code_patcher import (
    group_fixes_by_file,
    apply_fixes_to_file,
)
from securefix.mcp.repo_utils import convert_files_to_relative


def should_create_pr(remediations: List[Dict]) -> Tuple[bool, List[Dict]]:
    """
    Determine if we should prompt for PR creation.

    Filters for high/critical severity AND high confidence fixes.

    Args:
        remediations: List of remediation dictionaries

    Returns:
        (should_prompt, pr_worthy_fixes): Tuple of bool and list of fixes
    """
    if not remediations:
        return False, []

    # Filter for high/critical severity AND high confidence fixes
    pr_worthy = []
    for remediation in remediations:
        severity = remediation['finding'].get('severity', '').lower()
        confidence = remediation.get('confidence', '').lower()

        # Only include high/critical severity with high confidence
        if severity in ['high', 'critical'] and confidence == 'high':
            pr_worthy.append(remediation)

    return len(pr_worthy) > 0, pr_worthy


def generate_branch_name(remediations: List[Dict]) -> str:
    """
    Generate a default branch name based on fixes.

    Args:
        remediations: List of remediation dictionaries

    Returns:
        Branch name string (e.g., "securefix-critical-fixes-20250104-143022")
    """
    # Count severity types
    severities = [r['finding'].get('severity', '').lower() for r in remediations]
    critical_count = severities.count('critical')
    high_count = severities.count('high')

    # Build branch name
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')

    if critical_count > 0:
        return f"securefix-critical-fixes-{timestamp}"
    elif high_count > 0:
        return f"securefix-high-severity-{timestamp}"
    else:
        return f"securefix-automated-fixes-{timestamp}"


def prepare_pr_data(
    remediations: List[Dict],
    report_path: str,
    branch_name: Optional[str] = None,
    output=None
) -> Dict:
    """
    Prepare all data needed for PR creation (without actually creating it).

    This function performs all PR preparation steps in memory:
    1. Loads repository root from scan report
    2. Generates commit message, PR title, and PR body
    3. Groups fixes by file
    4. Applies fixes to files in memory
    5. Converts paths to relative

    Args:
        remediations: List of remediation dictionaries with fixes
        report_path: Path to the original scan report
        branch_name: Optional custom branch name. If None, will be auto-generated.
        output: Optional callback for user messages

    Returns:
        Dict with prepared PR data:
        {
            'success': bool,
            'error': str (if not successful),
            'branch_name': str,
            'commit_message': str,
            'pr_title': str,
            'pr_body': str,
            'changed_files': dict[str, str],  # relative paths -> content
            'repo_root': str,
            'failed_files': List[Tuple[str, str]]  # (path, error)
        }
    """
    output = output or (lambda x: None)

    # Read repository root from scan report
    repo_root = None
    try:
        with open(report_path, 'r') as f:
            scan_data = json.load(f)
            repo_root = scan_data.get('repository_root')
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        pass

    if not repo_root:
        return {
            'success': False,
            'error': 'No repository root found in scan report. Re-scan with latest version of securefix.'
        }

    # Generate branch name if not provided
    if not branch_name:
        branch_name = generate_branch_name(remediations)

    # Step 1: Generate PR content
    commit_message = generate_commit_message(remediations)
    pr_title = generate_pr_title(remediations)
    pr_body = generate_pr_body(remediations)

    output("\n" + "=" * 70)
    output("PULL REQUEST PREVIEW")
    output("=" * 70)
    output(f"\nTitle: {pr_title}")
    output(f"Branch: {branch_name}")
    output(f"Commit: {commit_message}")

    # Step 2: Group fixes by file and apply in memory
    grouped_fixes = group_fixes_by_file(remediations)
    changed_files_abs = {}
    failed_files = []

    output(f"\nFiles to modify: {len(grouped_fixes)}")
    for file_path in grouped_fixes.keys():
        output(f"  - {file_path}")

    output("\n" + "-" * 70)
    output("Applying fixes (in memory)...")
    output("-" * 70 + "\n")

    for file_path, file_fixes in grouped_fixes.items():
        try:
            output(f"Processing {file_path} ({len(file_fixes)} fix(es))...")
            updated_content = apply_fixes_to_file(file_path, file_fixes)
            changed_files_abs[file_path] = updated_content
            output("  ✓")
        except FileNotFoundError:
            output(f"  ✗ (file not found)")
            failed_files.append((file_path, "File not found"))
        except Exception as e:
            output(f"  ✗ ({str(e)})")
            failed_files.append((file_path, str(e)))

    if not changed_files_abs:
        return {
            'success': False,
            'error': 'Could not apply any fixes to files. Check file paths and permissions.'
        }

    if failed_files:
        output(f"\n⚠ Warning: {len(failed_files)} file(s) could not be fixed:")
        for file_path, error in failed_files:
            output(f"  - {file_path}: {error}")

    # Step 3: Convert to relative paths
    try:
        changed_files = convert_files_to_relative(changed_files_abs, repo_root, output)
    except ValueError as e:
        return {
            'success': False,
            'error': f'Path conversion error: {str(e)}'
        }

    return {
        'success': True,
        'branch_name': branch_name,
        'commit_message': commit_message,
        'pr_title': pr_title,
        'pr_body': pr_body,
        'changed_files': changed_files,
        'repo_root': repo_root,
        'failed_files': failed_files
    }
