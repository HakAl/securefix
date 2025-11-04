"""
Tests for MCP PR content generation.

Tests for commit messages, PR titles, and PR body generation.
"""
import pytest
from securefix.mcp.pr_content import (
    generate_commit_message,
    generate_pr_title,
    generate_pr_body,
)


class TestGenerateCommitMessage:
    """Tests for commit message generation."""

    def test_single_critical_vulnerability(self):
        """Should generate message for single critical vuln."""
        remediations = [
            {
                'finding': {
                    'type': 'SQL Injection',
                    'severity': 'Critical'
                },
                'confidence': 'High'
            }
        ]

        message = generate_commit_message(remediations)

        assert 'Fix 1 critical' in message
        assert 'SQL Injection' in message

    def test_multiple_vulnerabilities(self):
        """Should generate message for multiple vulns."""
        remediations = [
            {
                'finding': {'type': 'SQL Injection', 'severity': 'High'},
                'confidence': 'High'
            },
            {
                'finding': {'type': 'XSS', 'severity': 'High'},
                'confidence': 'High'
            },
            {
                'finding': {'type': 'CSRF', 'severity': 'Medium'},
                'confidence': 'High'
            },
        ]

        message = generate_commit_message(remediations)

        assert 'Fix 3' in message
        assert 'high' in message.lower()
        # Should contain vulnerability types (up to 3)
        assert 'SQL Injection' in message or 'XSS' in message or 'CSRF' in message

    def test_prioritizes_highest_severity(self):
        """Should use highest severity in message."""
        remediations = [
            {
                'finding': {'type': 'Issue 1', 'severity': 'Low'},
                'confidence': 'High'
            },
            {
                'finding': {'type': 'Issue 2', 'severity': 'Critical'},
                'confidence': 'High'
            },
            {
                'finding': {'type': 'Issue 3', 'severity': 'Medium'},
                'confidence': 'High'
            },
        ]

        message = generate_commit_message(remediations)

        assert 'critical' in message.lower()

    def test_truncates_many_vulnerability_types(self):
        """Should truncate when >3 vulnerability types."""
        remediations = [
            {
                'finding': {'type': f'Type{i}', 'severity': 'High'},
                'confidence': 'High'
            }
            for i in range(5)
        ]

        message = generate_commit_message(remediations)

        assert '...' in message  # Should indicate more types

    def test_empty_remediations(self):
        """Should handle empty list gracefully."""
        message = generate_commit_message([])

        assert 'Fix security vulnerabilities' in message


class TestGeneratePRTitle:
    """Tests for PR title generation."""

    def test_critical_severity_gets_lock_emoji(self):
        """Should use 🔒 emoji for critical severity."""
        remediations = [
            {
                'finding': {'type': 'SQL Injection', 'severity': 'Critical'},
                'confidence': 'High'
            }
        ]

        title = generate_pr_title(remediations)

        assert '🔒' in title
        assert '[SecureFix]' in title
        assert 'critical' in title.lower()

    def test_high_severity_gets_lock_emoji(self):
        """Should use 🔒 emoji for high severity."""
        remediations = [
            {
                'finding': {'type': 'XSS', 'severity': 'High'},
                'confidence': 'High'
            }
        ]

        title = generate_pr_title(remediations)

        assert '🔒' in title
        assert 'high' in title.lower()

    def test_medium_severity_gets_shield_emoji(self):
        """Should use 🛡️ emoji for medium severity."""
        remediations = [
            {
                'finding': {'type': 'Issue', 'severity': 'Medium'},
                'confidence': 'High'
            }
        ]

        title = generate_pr_title(remediations)

        assert '🛡️' in title
        assert 'medium' in title.lower()

    def test_includes_count(self):
        """Should include number of vulnerabilities."""
        remediations = [
            {'finding': {'severity': 'High'}, 'confidence': 'High'}
            for _ in range(3)
        ]

        title = generate_pr_title(remediations)

        assert 'Fix 3' in title

    def test_empty_remediations(self):
        """Should handle empty list gracefully."""
        title = generate_pr_title([])

        assert '🛡️' in title
        assert '[SecureFix]' in title


class TestGeneratePRBody:
    """Tests for PR body generation."""

    def test_includes_summary_table(self):
        """Should include markdown table with vulnerability summary."""
        remediations = [
            {
                'finding': {
                    'type': 'SQL Injection',
                    'file': 'app.py',
                    'line': 42,
                    'severity': 'Critical'
                },
                'confidence': 'High',
                'cwe_id': 'CWE-89'
            }
        ]

        body = generate_pr_body(remediations)

        assert '## 🔒 Security Fixes' in body
        assert '### Vulnerabilities Fixed' in body
        assert '| Type | File | Line | Severity | Confidence | CWE |' in body
        assert 'SQL Injection' in body
        assert '`app.py`' in body
        assert '42' in body
        assert 'CWE-89' in body

    def test_includes_detailed_changes(self):
        """Should include detailed changes section."""
        remediations = [
            {
                'finding': {
                    'type': 'XSS',
                    'file': 'views.py',
                    'line': 10,
                    'severity': 'High',
                    'snippet': 'return render_template("page.html", data=user_input)'
                },
                'confidence': 'High',
                'suggested_fix': 'return render_template("page.html", data=escape(user_input))',
                'explanation': 'User input should be escaped to prevent XSS attacks.'
            }
        ]

        body = generate_pr_body(remediations)

        assert '### 📋 Detailed Changes' in body
        assert '#### 1. XSS in `views.py:10`' in body
        assert 'User input should be escaped' in body
        assert '<details>' in body
        assert '**Before:**' in body
        assert '**After:**' in body
        assert '```python' in body

    def test_includes_testing_checklist(self):
        """Should include testing checklist."""
        remediations = [
            {
                'finding': {'type': 'Issue', 'severity': 'High'},
                'confidence': 'High'
            }
        ]

        body = generate_pr_body(remediations)

        assert '### ✅ Testing Checklist' in body
        assert '- [ ] Code review completed' in body
        assert '- [ ] All tests pass' in body
        assert '- [ ] Manual testing performed' in body

    def test_includes_source_documents(self):
        """Should include source documentation when available."""
        remediations = [
            {
                'finding': {'type': 'Issue', 'severity': 'High'},
                'confidence': 'High',
                'source_documents': [
                    {
                        'source': 'OWASP_Guide.md',
                        'doc_type': 'owasp_cheatsheet'
                    }
                ]
            }
        ]

        body = generate_pr_body(remediations)

        assert '📚 Source Documentation' in body
        assert 'OWASP_Guide.md' in body
        assert 'owasp_cheatsheet' in body

    def test_includes_footer(self):
        """Should include SecureFix footer."""
        remediations = [
            {
                'finding': {'type': 'Issue', 'severity': 'High'},
                'confidence': 'High'
            }
        ]

        body = generate_pr_body(remediations)

        assert '🤖 **Generated by [SecureFix]' in body
        assert 'https://github.com/HakAl/securefix' in body

    def test_empty_remediations(self):
        """Should handle empty list gracefully."""
        body = generate_pr_body([])

        assert 'security vulnerabilities' in body.lower()

    def test_multiple_fixes_same_file(self):
        """Should handle multiple fixes in same file."""
        remediations = [
            {
                'finding': {
                    'type': 'SQL Injection',
                    'file': 'app.py',
                    'line': 10,
                    'severity': 'High',
                    'snippet': 'query = f"SELECT * FROM users WHERE id={uid}"'
                },
                'confidence': 'High',
                'suggested_fix': 'query = "SELECT * FROM users WHERE id=?"',
                'explanation': 'Use parameterized queries.'
            },
            {
                'finding': {
                    'type': 'XSS',
                    'file': 'app.py',
                    'line': 50,
                    'severity': 'High',
                    'snippet': 'return data'
                },
                'confidence': 'High',
                'suggested_fix': 'return escape(data)',
                'explanation': 'Escape user input.'
            }
        ]

        body = generate_pr_body(remediations)

        # Should have 2 detailed change sections
        assert '#### 1.' in body
        assert '#### 2.' in body
        assert 'SQL Injection' in body
        assert 'XSS' in body


if __name__ == '__main__':
    pytest.main([__file__, "-v"])
