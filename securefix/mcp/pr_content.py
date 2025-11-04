"""
Content generation for GitHub Pull Requests.

Functions to generate commit messages, PR titles, and PR descriptions
from security fix remediations.
"""
from typing import List, Dict


def generate_commit_message(remediations: List[Dict]) -> str:
    """
    Generate a concise commit message from remediations.

    Args:
        remediations: List of remediation dictionaries with 'finding' and fix details

    Returns:
        Commit message string (single line, ~50-72 chars preferred)

    Example:
        "Fix 3 critical vulnerabilities (SQL injection, XSS, CSRF)"
    """
    if not remediations:
        return "Fix security vulnerabilities"

    # Count severities and collect vulnerability types
    severity_counts = {}
    vuln_types = set()

    for rem in remediations:
        severity = rem['finding'].get('severity', 'medium').lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        vuln_types.add(rem['finding'].get('type', 'Unknown'))

    total = len(remediations)

    # Use highest severity present
    severity_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    highest_severity = max(
        severity_counts.keys(),
        key=lambda s: severity_priority.get(s, 0)
    )

    # Limit vulnerability types to 3 for brevity
    types_list = sorted(vuln_types)[:3]
    types_str = ', '.join(types_list)

    # Add "..." if there are more types
    if len(vuln_types) > 3:
        types_str += ', ...'

    return f"Fix {total} {highest_severity} vulnerabilities ({types_str})"


def generate_pr_title(remediations: List[Dict]) -> str:
    """
    Generate a clear, actionable PR title.

    Args:
        remediations: List of remediation dictionaries

    Returns:
        PR title string with emoji and severity indicator

    Example:
        "🔒 [SecureFix] Fix 3 critical security vulnerabilities"
    """
    if not remediations:
        return "🛡️ [SecureFix] Fix security vulnerabilities"

    total = len(remediations)

    # Determine highest severity
    severity_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    severities = [rem['finding'].get('severity', 'medium').lower() for rem in remediations]
    highest_severity = max(severities, key=lambda s: severity_priority.get(s, 0))

    # Choose emoji based on severity
    emoji = '🔒' if highest_severity in ['high', 'critical'] else '🛡️'

    return f"{emoji} [SecureFix] Fix {total} {highest_severity} security vulnerabilities"


def generate_pr_body(remediations: List[Dict]) -> str:
    """
    Generate detailed PR description in GitHub markdown format.

    Args:
        remediations: List of remediation dictionaries

    Returns:
        Multi-line markdown string with:
        - Summary
        - Vulnerabilities table
        - Detailed fixes with before/after code
        - Testing checklist
        - Footer
    """
    if not remediations:
        return "This PR fixes security vulnerabilities detected by SecureFix."

    body = []

    # Header
    body.append("## 🔒 Security Fixes")
    body.append("")
    body.append(f"This PR addresses **{len(remediations)} security vulnerabilities** ")
    body.append("detected and fixed by SecureFix.")
    body.append("")

    # Summary table
    body.append("### Vulnerabilities Fixed")
    body.append("")
    body.append("| Type | File | Line | Severity | Confidence | CWE |")
    body.append("|------|------|------|----------|------------|-----|")

    for rem in remediations:
        finding = rem['finding']
        file_name = finding.get('file', 'Unknown')
        line_num = finding.get('line', 'N/A')
        vuln_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        confidence = rem.get('confidence', 'Unknown')
        cwe_id = rem.get('cwe_id', 'N/A')

        body.append(
            f"| {vuln_type} | `{file_name}` | {line_num} | "
            f"**{severity}** | {confidence} | {cwe_id} |"
        )

    body.append("")

    # Detailed fixes
    body.append("### 📋 Detailed Changes")
    body.append("")

    for i, rem in enumerate(remediations, 1):
        finding = rem['finding']
        file_name = finding.get('file', 'Unknown')
        line_num = finding.get('line', 'N/A')
        vuln_type = finding.get('type', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        confidence = rem.get('confidence', 'Unknown')
        explanation = rem.get('explanation', 'No explanation provided.')

        # Fix header
        body.append(f"#### {i}. {vuln_type} in `{file_name}:{line_num}`")
        body.append("")
        body.append(f"**Severity**: {severity} | **Confidence**: {confidence}")
        body.append("")
        body.append(explanation)
        body.append("")

        # Before/After code
        body.append("<details>")
        body.append("<summary>📝 Show code change</summary>")
        body.append("")

        # Before
        body.append("**Before:**")
        body.append("```python")
        body.append(finding.get('snippet', '# Code snippet not available'))
        body.append("```")
        body.append("")

        # After
        body.append("**After:**")
        body.append("```python")
        body.append(rem.get('suggested_fix', '# Fix not available'))
        body.append("```")

        body.append("</details>")
        body.append("")

    # Testing checklist
    body.append("### ✅ Testing Checklist")
    body.append("")
    body.append("- [ ] Code review completed")
    body.append("- [ ] All tests pass")
    body.append("- [ ] Manual testing performed")
    body.append("- [ ] No regressions introduced")
    body.append("- [ ] Security scan confirms fixes")
    body.append("")

    # Source documents (if available)
    has_sources = any('source_documents' in rem for rem in remediations)
    if has_sources:
        body.append("<details>")
        body.append("<summary>📚 Source Documentation</summary>")
        body.append("")

        for i, rem in enumerate(remediations, 1):
            if 'source_documents' in rem and rem['source_documents']:
                body.append(f"**Fix {i}:**")
                for doc in rem['source_documents']:
                    source = doc.get('source', 'Unknown')
                    doc_type = doc.get('doc_type', 'Unknown')
                    body.append(f"- {source} ({doc_type})")
                body.append("")

        body.append("</details>")
        body.append("")

    # Footer
    body.append("---")
    body.append("")
    body.append("🤖 **Generated by [SecureFix](https://github.com/HakAl/securefix)**")
    body.append("")
    body.append("_This PR was automatically created by SecureFix's AI-powered ")
    body.append("security remediation engine. Please review all changes carefully ")
    body.append("before merging._")

    return '\n'.join(body)

