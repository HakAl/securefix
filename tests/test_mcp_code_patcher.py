"""
Tests for MCP code patcher.

Tests for grouping fixes, applying patches, and preserving indentation.
"""
import pytest
import os
import tempfile
from securefix.mcp.code_patcher import (
    group_fixes_by_file,
    apply_fixes_to_file,
    _apply_fixes_line_based,
    _find_and_replace_snippet,
    _replace_lines_preserving_indent,
)


class TestGroupFixesByFile:
    """Tests for grouping and sorting fixes by file."""

    def test_groups_by_file_path(self):
        """Should group remediations by file path."""
        remediations = [
            {'finding': {'file': 'app.py', 'line': 10}},
            {'finding': {'file': 'views.py', 'line': 20}},
            {'finding': {'file': 'app.py', 'line': 5}},
        ]

        grouped = group_fixes_by_file(remediations)

        assert len(grouped) == 2
        assert 'app.py' in grouped
        assert 'views.py' in grouped
        assert len(grouped['app.py']) == 2
        assert len(grouped['views.py']) == 1

    def test_sorts_descending_by_line_number(self):
        """Should sort fixes in descending order by line number."""
        remediations = [
            {'finding': {'file': 'app.py', 'line': 5}},
            {'finding': {'file': 'app.py', 'line': 20}},
            {'finding': {'file': 'app.py', 'line': 10}},
        ]

        grouped = group_fixes_by_file(remediations)

        lines = [fix['finding']['line'] for fix in grouped['app.py']]
        assert lines == [20, 10, 5]

    def test_handles_missing_file_field(self):
        """Should skip remediations without file field."""
        remediations = [
            {'finding': {'file': 'app.py', 'line': 10}},
            {'finding': {'line': 20}},  # Missing file
            {'finding': {}},  # Missing both
        ]

        grouped = group_fixes_by_file(remediations)

        assert len(grouped) == 1
        assert 'app.py' in grouped

    def test_handles_missing_line_number(self):
        """Should handle missing line numbers (use 0 as default)."""
        remediations = [
            {'finding': {'file': 'app.py', 'line': 10}},
            {'finding': {'file': 'app.py'}},  # Missing line
        ]

        grouped = group_fixes_by_file(remediations)

        assert len(grouped['app.py']) == 2
        # Should sort by line, missing treated as 0 (goes last)
        assert grouped['app.py'][0]['finding'].get('line', 0) == 10

    def test_empty_list(self):
        """Should handle empty remediation list."""
        grouped = group_fixes_by_file([])
        assert grouped == {}


class TestApplyFixesToFile:
    """Tests for applying fixes to actual files."""

    def test_applies_single_fix(self, tmp_path):
        """Should apply a single fix to a file."""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "def vulnerable():\n"
            "    query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
            "    return query\n"
        )

        remediations = [
            {
                'finding': {
                    'file': str(test_file),
                    'line': 2,
                    'snippet': 'query = f"SELECT * FROM users WHERE id={user_id}"'
                },
                'suggested_fix': 'query = "SELECT * FROM users WHERE id=?"',
                'confidence': 'High'
            }
        ]

        result = apply_fixes_to_file(str(test_file), remediations)

        assert 'query = "SELECT * FROM users WHERE id=?"' in result
        assert 'f"SELECT * FROM users WHERE id={user_id}"' not in result

    def test_applies_multiple_fixes_same_file(self, tmp_path):
        """Should apply multiple fixes to same file."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "def app():\n"
            "    query = f\"SELECT * FROM users WHERE id={uid}\"\n"
            "    result = db.execute(query)\n"
            "    return render_template('page.html', data=result)\n"
        )

        remediations = [
            {
                'finding': {
                    'line': 4,
                    'snippet': "return render_template('page.html', data=result)"
                },
                'suggested_fix': "return render_template('page.html', data=escape(result))"
            },
            {
                'finding': {
                    'line': 2,
                    'snippet': 'query = f"SELECT * FROM users WHERE id={uid}"'
                },
                'suggested_fix': 'query = "SELECT * FROM users WHERE id=?"'
            }
        ]

        result = apply_fixes_to_file(str(test_file), remediations)

        # Both fixes should be applied
        assert 'query = "SELECT * FROM users WHERE id=?"' in result
        assert 'escape(result)' in result

    def test_preserves_indentation(self, tmp_path):
        """Should preserve indentation when applying fixes."""
        test_file = tmp_path / "test.py"
        test_file.write_text(
            "class App:\n"
            "    def method(self):\n"
            "        query = f\"SELECT * FROM users\"\n"
            "        return query\n"
        )

        remediations = [
            {
                'finding': {
                    'line': 3,
                    'snippet': 'query = f"SELECT * FROM users"'
                },
                'suggested_fix': 'query = "SELECT * FROM users"'
            }
        ]

        result = apply_fixes_to_file(str(test_file), remediations)

        # Should preserve 8-space indentation
        assert '        query = "SELECT * FROM users"' in result

    def test_file_not_found_raises_error(self):
        """Should raise FileNotFoundError for non-existent file."""
        with pytest.raises(FileNotFoundError):
            apply_fixes_to_file('/nonexistent/file.py', [])

    def test_skips_fixes_without_snippet(self, tmp_path):
        """Should skip fixes that don't have snippet or suggested_fix."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def app():\n    pass\n")

        remediations = [
            {'finding': {'line': 2}, 'suggested_fix': 'return None'},  # Missing snippet
            {'finding': {'line': 2, 'snippet': 'pass'}},  # Missing suggested_fix
        ]

        result = apply_fixes_to_file(str(test_file), remediations)

        # Original content preserved
        assert 'pass' in result


class TestApplyFixesLineBased:
    """Tests for line-based fix application."""

    def test_exact_match_replacement(self):
        """Should replace exact match."""
        content = "line1\nold_code\nline3\n"
        remediations = [
            {
                'finding': {'line': 2, 'snippet': 'old_code'},
                'suggested_fix': 'new_code'
            }
        ]

        result = _apply_fixes_line_based(content, remediations)

        assert 'new_code' in result
        assert 'old_code' not in result

    def test_fuzzy_match_replacement(self):
        """Should use fuzzy matching when exact match fails."""
        content = "line1\nold_code_with_extra_spaces  \nline3\n"
        remediations = [
            {
                'finding': {'line': 2, 'snippet': 'old_code_with_extra_spaces'},
                'suggested_fix': 'new_code'
            }
        ]

        result = _apply_fixes_line_based(content, remediations)

        assert 'new_code' in result

    def test_continues_on_failed_match(self, capsys):
        """Should continue with other fixes if one fails."""
        content = "line1\nline2\nline3\n"
        remediations = [
            {
                'finding': {'line': 2, 'snippet': 'nonexistent_code'},
                'suggested_fix': 'new_code'
            },
            {
                'finding': {'line': 2, 'snippet': 'line2'},
                'suggested_fix': 'replaced_line2'
            }
        ]

        result = _apply_fixes_line_based(content, remediations)

        # Second fix should succeed
        assert 'replaced_line2' in result
        # Warning printed for first fix
        captured = capsys.readouterr()
        assert 'Warning' in captured.out


class TestFindAndReplaceSnippet:
    """Tests for snippet finding and replacement."""

    def test_exact_match_at_target_line(self):
        """Should find exact match at target line."""
        lines = ["line1\n", "target_code\n", "line3\n"]
        old_snippet = "target_code"
        new_snippet = "new_code"

        result = _find_and_replace_snippet(lines, 1, old_snippet, new_snippet)

        assert result[1] == "new_code\n"

    def test_exact_match_near_target_line(self):
        """Should find exact match within search window."""
        lines = ["line1\n", "line2\n", "target_code\n", "line4\n"]
        old_snippet = "target_code"
        new_snippet = "new_code"

        # Target line is 1, but actual code is at line 2
        result = _find_and_replace_snippet(lines, 1, old_snippet, new_snippet)

        assert result[2] == "new_code\n"

    def test_multiline_snippet_replacement(self):
        """Should handle multi-line snippets."""
        lines = [
            "line1\n",
            "def old():\n",
            "    return None\n",
            "line4\n"
        ]
        old_snippet = "def old():\n    return None"
        new_snippet = "def new():\n    return True"

        result = _find_and_replace_snippet(lines, 1, old_snippet, new_snippet)

        assert "def new():\n" in result
        assert "    return True\n" in result  # With correct indentation

    def test_fuzzy_match_threshold(self):
        """Should use fuzzy match above 85% threshold."""
        lines = ["line1\n", "target_code_with_minor_diff\n", "line3\n"]
        old_snippet = "target_code_with_minor_difference"
        new_snippet = "new_code"

        # Should match due to high similarity (>85%)
        result = _find_and_replace_snippet(lines, 1, old_snippet, new_snippet)

        assert "new_code" in ''.join(result)

    def test_raises_error_when_not_found(self):
        """Should raise ValueError when snippet not found."""
        lines = ["line1\n", "line2\n", "line3\n"]
        old_snippet = "completely_different_code"
        new_snippet = "new_code"

        with pytest.raises(ValueError, match="Could not locate snippet"):
            _find_and_replace_snippet(lines, 1, old_snippet, new_snippet)

    def test_search_window_limits(self):
        """Should search within ±10 lines of target."""
        # Create 30 lines
        lines = [f"line{i}\n" for i in range(30)]
        lines[25] = "target_code\n"  # Far from target

        old_snippet = "target_code"
        new_snippet = "new_code"

        # Target at line 5, snippet at line 25 (20 lines away)
        with pytest.raises(ValueError):
            _find_and_replace_snippet(lines, 5, old_snippet, new_snippet)


class TestReplacePreservingIndent:
    """Tests for indentation preservation."""

    def test_preserves_indentation(self):
        """Should preserve indentation of original line."""
        lines = [
            "line1\n",
            "    old_code\n",
            "line3\n"
        ]
        new_snippet = "new_code"

        result = _replace_lines_preserving_indent(lines, 1, 1, new_snippet)

        # Should preserve 4-space indent
        assert result[1] == "    new_code\n"

    def test_handles_multiline_replacement(self):
        """Should apply indentation to all new lines."""
        lines = [
            "line1\n",
            "    old_code\n",
            "line3\n"
        ]
        new_snippet = "new_line1\nnew_line2"

        result = _replace_lines_preserving_indent(lines, 1, 1, new_snippet)

        # Both lines should have indent
        assert result[1] == "    new_line1\n"
        assert result[2] == "    new_line2\n"

    def test_handles_no_indentation(self):
        """Should handle lines with no indentation."""
        lines = [
            "line1\n",
            "old_code\n",
            "line3\n"
        ]
        new_snippet = "new_code"

        result = _replace_lines_preserving_indent(lines, 1, 1, new_snippet)

        assert result[1] == "new_code\n"

    def test_handles_empty_lines_in_snippet(self):
        """Should handle empty lines in new snippet."""
        lines = [
            "line1\n",
            "    old_code\n",
            "line3\n"
        ]
        new_snippet = "new_line1\n\nnew_line3"

        result = _replace_lines_preserving_indent(lines, 1, 1, new_snippet)

        # Empty line should remain empty
        assert result[1] == "    new_line1\n"
        assert result[2] == "\n"
        assert result[3] == "    new_line3\n"

    def test_replaces_correct_number_of_lines(self):
        """Should replace exact number of lines specified."""
        lines = [
            "line1\n",
            "old1\n",
            "old2\n",
            "old3\n",
            "line5\n"
        ]
        new_snippet = "new_code"

        # Replace 3 lines with 1
        result = _replace_lines_preserving_indent(lines, 1, 3, new_snippet)

        assert len(result) == 3  # 5 original - 3 removed + 1 added
        assert result[1] == "new_code\n"
        assert result[2] == "line5\n"


if __name__ == '__main__':
    pytest.main([__file__, "-v"])
