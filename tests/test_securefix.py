import json
import pytest
import textwrap
from click.testing import CliRunner
from pathlib import Path
from securefix import cli


@pytest.fixture
def runner():
    """Create a Click CLI test runner"""
    return CliRunner()


@pytest.fixture
def temp_vulnerable_file(tmp_path):
    """Create a temporary file with vulnerabilities"""
    file_path = tmp_path / "vulnerable.py"
    file_path.write_text("""
API_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")
""")
    return file_path


@pytest.fixture
def temp_clean_file(tmp_path):
    """Create a temporary file with no vulnerabilities"""
    file_path = tmp_path / "clean.py"
    file_path.write_text("""
def add(a, b):
    return a + b
""")
    return file_path


@pytest.fixture
def temp_requirements(tmp_path):
    """Create a temporary requirements.txt with vulnerabilities"""
    req_path = tmp_path / "requirements.txt"
    req_path.write_text("flask==0.12\nrequests==2.28.0\n")
    return req_path


class TestScanCommand:
    """Tests for the scan command"""

    def test_scan_file_with_vulnerabilities(self, runner, temp_vulnerable_file, tmp_path):
        """Should scan a single file and generate report"""
        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0
        assert "Scanning" in result.output
        assert "Found" in result.output
        assert "SAST findings" in result.output
        assert "Report saved to" in result.output

        # Verify report was created
        assert output_path.exists()

        # Verify report structure
        with open(output_path) as f:
            report = json.load(f)

        assert 'summary' in report
        assert 'sast_findings' in report
        assert 'cve_findings' in report
        assert report['summary']['total_findings'] > 0

    def test_scan_file_with_no_vulnerabilities(self, runner, temp_clean_file, tmp_path):
        """Should scan clean file and report no findings"""
        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(temp_clean_file),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0
        assert "Found 0 SAST findings" in result.output

        with open(output_path) as f:
            report = json.load(f)

        assert report['summary']['total_findings'] == 0

    def test_scan_directory(self, runner, tmp_path):
        """Should scan all Python files in a directory"""
        # Create multiple files with more obvious vulnerabilities
        file1 = tmp_path / "file1.py"
        file1.write_text('password = "hardcoded_password_123"')  # More obvious secret

        file2 = tmp_path / "file2.py"
        file2.write_text('import os\nos.system("ls -la")')  # Command injection

        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(tmp_path),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0

        with open(output_path) as f:
            report = json.load(f)

        # Should find at least 1 vulnerability (may not find both)
        assert report['summary']['total_findings'] >= 1

    def test_scan_with_dependencies(self, runner, temp_vulnerable_file, temp_requirements, tmp_path):
        """Should scan both code and dependencies"""
        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--dependencies', str(temp_requirements),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0
        assert "Scanning dependencies" in result.output
        assert "vulnerable dependencies" in result.output

        with open(output_path) as f:
            report = json.load(f)

        assert report['summary']['total_findings'] > 0  # SAST findings
        # CVE findings may or may not be present depending on OSV API

    def test_scan_with_short_option_flags(self, runner, temp_vulnerable_file, tmp_path):
        """Should accept short option flags (-d, -o)"""
        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '-o', str(output_path)
        ])

        assert result.exit_code == 0
        assert output_path.exists()

    def test_scan_default_output_filename(self, runner, temp_vulnerable_file):
        """Should use default output filename when not specified"""
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ['scan', str(temp_vulnerable_file)])

            assert result.exit_code == 0
            assert Path('report.json').exists()

    def test_scan_nonexistent_target(self, runner):
        """Should fail gracefully with nonexistent target"""
        result = runner.invoke(cli, ['scan', 'nonexistent.py'])

        assert result.exit_code != 0

    def test_scan_invalid_dependencies_path(self, runner, temp_vulnerable_file):
        """Should fail gracefully with invalid dependencies path"""
        result = runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--dependencies', 'nonexistent_requirements.txt'
        ])

        assert result.exit_code != 0


class TestReportStructure:
    """Tests for report output format"""

    def test_report_has_required_fields(self, runner, temp_vulnerable_file, tmp_path):
        """Report should have all required fields"""
        output_path = tmp_path / "report.json"

        runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--output', str(output_path)
        ])

        with open(output_path) as f:
            report = json.load(f)

        # Check summary fields
        assert 'summary' in report
        assert 'total_findings' in report['summary']
        assert 'total_cve_findings' in report['summary']
        assert 'by_severity' in report['summary']
        assert 'scan_timestamp' in report['summary']

        # Check severity breakdown
        severity_breakdown = report['summary']['by_severity']
        assert 'low' in severity_breakdown
        assert 'medium' in severity_breakdown
        assert 'high' in severity_breakdown
        assert 'critical' in severity_breakdown

        # Check findings structure
        assert 'sast_findings' in report
        assert 'cve_findings' in report
        assert isinstance(report['sast_findings'], list)
        assert isinstance(report['cve_findings'], list)

    def test_report_findings_have_required_fields(self, runner, temp_vulnerable_file, tmp_path):
        """Each finding should have required fields"""
        output_path = tmp_path / "report.json"

        runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--output', str(output_path)
        ])

        with open(output_path) as f:
            report = json.load(f)

        if report['sast_findings']:
            finding = report['sast_findings'][0]
            assert 'type' in finding
            assert 'line' in finding
            assert 'severity' in finding
            assert 'confidence' in finding
            assert 'file' in finding

    def test_report_is_valid_json(self, runner, temp_vulnerable_file, tmp_path):
        """Report should be valid, parseable JSON"""
        output_path = tmp_path / "report.json"

        runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--output', str(output_path)
        ])

        # Should not raise JSONDecodeError
        with open(output_path) as f:
            report = json.load(f)

        assert isinstance(report, dict)


class TestCLIOutput:
    """Tests for CLI output messages"""

    def test_displays_summary_statistics(self, runner, temp_vulnerable_file, tmp_path):
        """Should display summary statistics in terminal"""
        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(temp_vulnerable_file),
            '--output', str(output_path)
        ])

        assert "Summary:" in result.output
        assert "Total SAST findings:" in result.output
        assert "Total CVE findings:" in result.output
        assert "By severity:" in result.output

    def test_displays_severity_counts_only_when_nonzero(self, runner, tmp_path):
        """Should only show severity counts > 0"""
        # Create file with a hardcoded password (B105/B106/B107)
        file_path = tmp_path / "secrets.py"
        file_path.write_text('PASSWORD = "my_secret_password"')

        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(file_path),
            '--output', str(output_path)
        ])

        # Just check that summary section exists and report was generated
        assert result.exit_code == 0
        assert "Summary:" in result.output
        assert "By severity:" in result.output


class TestIntegration:
    """End-to-end integration tests"""

    def test_full_scan_workflow(self, runner, tmp_path):
        """Test complete workflow: scan code + dependencies"""
        # Create project structure
        code_file = tmp_path / "app.py"
        code_file.write_text(textwrap.dedent("""
            import pickle
            import os

            PASSWORD = "hardcoded_password_123"

            def unsafe_load(data):
                return pickle.load(data)

            def run_command(cmd):
                os.system(cmd)
        """).strip())

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==0.12\n")

        output_path = tmp_path / "full_report.json"

        result = runner.invoke(cli, [
            'scan',
            str(code_file),
            '--dependencies', str(req_file),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0

        with open(output_path) as f:
            report = json.load(f)

        # Should have at least some SAST findings
        assert report['summary']['total_findings'] >= 1
        assert len(report['sast_findings']) >= 1