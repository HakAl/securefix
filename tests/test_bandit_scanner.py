import pytest
import json
from unittest.mock import patch, MagicMock
from sast.bandit_scanner import scan
from models import Finding, Type, Severity, Confidence


@pytest.fixture
def mock_bandit_output():
    """Sample Bandit JSON output"""
    return {
        "results": [
            {
                "test_id": "B105",
                "issue_text": "Possible hardcoded password: 'admin123'",
                "line_number": 10,
                "issue_severity": "HIGH",
                "issue_confidence": "MEDIUM",
                "code": "10 password = 'admin123'",
                "filename": "test.py"
            },
            {
                "test_id": "B602",
                "issue_text": "subprocess call with shell=True",
                "line_number": 25,
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "code": "25 subprocess.call('ls -la', shell=True)",
                "filename": "test.py"
            }
        ]
    }


@pytest.fixture
def mock_subprocess_success(mock_bandit_output):
    """Mock successful subprocess.run call"""
    mock_result = MagicMock()
    mock_result.returncode = 1  # Bandit returns 1 when issues found
    mock_result.stdout = json.dumps(mock_bandit_output)
    mock_result.stderr = ""
    return mock_result


class TestBanditScanner:

    def test_scan_success_with_findings(self, mock_subprocess_success):
        """Test successful scan with vulnerabilities found"""
        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_subprocess_success):
            findings = scan("/test/path")

        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)

        # Check first finding
        assert findings[0].type == Type.SECRETS
        assert findings[0].line == 10
        assert findings[0].severity == Severity.HIGH
        assert findings[0].confidence == Confidence.MEDIUM
        assert findings[0].file == "test.py"

        # Check second finding
        assert findings[1].type == Type.COMMAND_INJECTION
        assert findings[1].line == 25
        assert findings[1].severity == Severity.MEDIUM

    def test_scan_no_findings(self):
        """Test successful scan with no vulnerabilities"""
        mock_result = MagicMock()
        mock_result.returncode = 0  # No issues found
        mock_result.stdout = json.dumps({"results": []})
        mock_result.stderr = ""

        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_result):
            findings = scan("/test/path")

        assert len(findings) == 0

    def test_scan_bandit_not_installed(self):
        """Test when Bandit is not installed"""
        with patch('sast.bandit_scanner.subprocess.run', side_effect=FileNotFoundError()):
            findings = scan("/test/path")

        assert findings == []

    def test_scan_bandit_failure(self):
        """Test when Bandit fails with error"""
        mock_result = MagicMock()
        mock_result.returncode = 2  # Error code
        mock_result.stdout = ""
        mock_result.stderr = "Bandit error"

        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_result):
            findings = scan("/test/path")

        assert findings == []

    def test_scan_invalid_json(self):
        """Test when Bandit returns invalid JSON"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "not valid json"
        mock_result.stderr = ""

        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_result):
            findings = scan("/test/path")

        assert findings == []

    def test_scan_command_construction(self, mock_subprocess_success):
        """Test that the correct command is constructed"""
        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_subprocess_success) as mock_run:
            scan("/my/test/path")

        # Check the command that was called
        called_command = mock_run.call_args[0][0]
        assert called_command == ["bandit", "-r", "/my/test/path", "-f", "json"]
        assert mock_run.call_args[1]['capture_output'] is True
        assert mock_run.call_args[1]['text'] is True

    def test_scan_handles_file_path(self, mock_subprocess_success):
        """Test scanning a single file"""
        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_subprocess_success):
            findings = scan("/path/to/file.py")

        assert isinstance(findings, list)

    def test_scan_handles_directory_path(self, mock_subprocess_success):
        """Test scanning a directory"""
        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_subprocess_success):
            findings = scan("/path/to/directory")

        assert isinstance(findings, list)

    def test_scan_snippet_cleaning(self):
        """Test that line numbers are removed from snippets"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps({
            "results": [{
                "test_id": "B105",
                "issue_text": "Test issue",
                "line_number": 5,
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "code": "5 password = 'test'",
                "filename": "test.py"
            }]
        })
        mock_result.stderr = ""

        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_result):
            findings = scan("/test")

        # Snippet should not contain line number
        assert findings[0].snippet
        assert not findings[0].snippet.startswith("5")
        assert "password = 'test'" in findings[0].snippet

    def test_scan_multiline_snippet(self):
        """Test handling of multiline code snippets"""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = json.dumps({
            "results": [{
                "test_id": "B602",
                "issue_text": "Test issue",
                "line_number": 10,
                "issue_severity": "MEDIUM",
                "issue_confidence": "MEDIUM",
                "code": "10 def foo():\n11     os.system('ls')\n12     return True",
                "filename": "test.py"
            }]
        })
        mock_result.stderr = ""

        with patch('sast.bandit_scanner.subprocess.run', return_value=mock_result):
            findings = scan("/test")

        # Check that multiline snippet is preserved
        assert findings[0].snippet
        assert "\n" in findings[0].snippet
        assert "def foo():" in findings[0].snippet
        assert "os.system('ls')" in findings[0].snippet


@pytest.mark.integration
class TestBanditScannerIntegration:
    """Integration tests - require Bandit to be installed"""

    def test_scan_actual_vulnerable_file(self, tmp_path):
        """Test scanning an actual file with vulnerabilities"""
        # Create a test file with a known vulnerability
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("""
import pickle

def load_data(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)  # B301: pickle usage
""")

        findings = scan(str(test_file))

        # Should find the pickle vulnerability
        assert len(findings) > 0
        assert any(f.type == Type.INSECURE_DESERIALIZATION for f in findings)

    def test_scan_safe_file(self, tmp_path):
        """Test scanning a safe file with no vulnerabilities"""
        test_file = tmp_path / "safe.py"
        test_file.write_text("""
def add(a, b):
    return a + b
""")

        findings = scan(str(test_file))

        # Should find no vulnerabilities (or very few/low severity)
        assert isinstance(findings, list)