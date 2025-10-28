from sast.scanner import scan_file, scan_directory
from models import Type, Severity


class TestScanFile:
    """Tests for scanning individual files"""

    def test_scan_file_with_sql_injection(self, tmp_path):
        """Should detect SQL injection in a file"""
        test_file = tmp_path / "vulnerable.py"
        test_file.write_text("""
def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")
""")

        findings = scan_file(str(test_file))

        assert len(findings) >= 1
        sql_findings = [f for f in findings if f.type == Type.SQL_INJECTION]
        assert len(sql_findings) == 1
        assert sql_findings[0].severity == Severity.HIGH
        assert sql_findings[0].file == str(test_file)

    def test_scan_file_with_hardcoded_secret(self, tmp_path):
        """Should detect hardcoded secrets in a file"""
        test_file = tmp_path / "secrets.py"
        test_file.write_text("""
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SECRET = "some_other_code"
""")

        findings = scan_file(str(test_file))

        assert len(findings) >= 1
        secret_findings = [f for f in findings if f.type == Type.SECRETS]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == Severity.CRITICAL
        assert secret_findings[0].file == str(test_file)

    def test_scan_file_with_multiple_vulnerabilities(self, tmp_path):
        """Should detect multiple vulnerability types in one file"""
        test_file = tmp_path / "multiple.py"
        test_file.write_text("""
API_KEY = "AKIAIOSFODNN7EXAMPLE"

def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")
""")

        findings = scan_file(str(test_file))

        assert len(findings) >= 2
        types = [f.type for f in findings]
        assert Type.SQL_INJECTION in types
        assert Type.SECRETS in types

    def test_scan_file_with_no_vulnerabilities(self, tmp_path):
        """Should return empty list for clean code"""
        test_file = tmp_path / "clean.py"
        test_file.write_text("""
def get_user(uid):
    cursor.execute("SELECT * FROM users WHERE id=%s", (uid,))
    return cursor.fetchone()
""")

        findings = scan_file(str(test_file))

        assert len(findings) == 0

    def test_scan_file_handles_syntax_errors(self, tmp_path):
        """Should gracefully handle files with syntax errors"""
        test_file = tmp_path / "invalid.py"
        test_file.write_text("""
def broken syntax here:
    this is not valid python
""")

        # Should not raise exception
        findings = scan_file(str(test_file))

        # May have regex-based findings but AST-based should be skipped
        assert isinstance(findings, list)

    def test_scan_file_adds_filepath_to_findings(self, tmp_path):
        """Should add filepath to all findings"""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
API_KEY = "AKIAIOSFODNN7EXAMPLE"
""")

        findings = scan_file(str(test_file))

        assert len(findings) >= 1
        for finding in findings:
            assert finding.file == str(test_file)


class TestScanDirectory:
    """Tests for scanning directories"""

    def test_scan_directory_with_multiple_files(self, tmp_path):
        """Should scan all Python files in a directory"""
        # Create multiple files with vulnerabilities
        file1 = tmp_path / "file1.py"
        file1.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')

        file2 = tmp_path / "file2.py"
        file2.write_text('cursor.execute(f"SELECT * FROM users WHERE id={uid}")')

        findings = scan_directory(str(tmp_path))

        assert len(findings) >= 2
        files_with_findings = {f.file for f in findings}
        assert str(file1) in files_with_findings
        assert str(file2) in files_with_findings

    def test_scan_directory_with_nested_structure(self, tmp_path):
        """Should recursively scan nested directories"""
        # Create nested directory structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        file1 = tmp_path / "top.py"
        file1.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')

        file2 = subdir / "nested.py"
        file2.write_text('cursor.execute(f"SELECT * FROM users WHERE id={uid}")')

        findings = scan_directory(str(tmp_path))

        assert len(findings) >= 2
        files_with_findings = {f.file for f in findings}
        assert str(file1) in files_with_findings
        assert str(file2) in files_with_findings

    def test_scan_directory_ignores_non_python_files(self, tmp_path):
        """Should only scan .py files"""
        py_file = tmp_path / "code.py"
        py_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')

        txt_file = tmp_path / "readme.txt"
        txt_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')

        js_file = tmp_path / "script.js"
        js_file.write_text('const key = "AKIAIOSFODNN7EXAMPLE";')

        findings = scan_directory(str(tmp_path))

        # Should only find vulnerability in .py file
        assert all(f.file.endswith('.py') for f in findings)

    def test_scan_directory_with_no_python_files(self, tmp_path):
        """Should return empty list if no Python files"""
        txt_file = tmp_path / "readme.txt"
        txt_file.write_text("Some text")

        findings = scan_directory(str(tmp_path))

        assert len(findings) == 0

    def test_scan_directory_with_clean_code(self, tmp_path):
        """Should return empty list if all files are clean"""
        file1 = tmp_path / "clean1.py"
        file1.write_text('def add(a, b):\n    return a + b')

        file2 = tmp_path / "clean2.py"
        file2.write_text('x = 5\ny = 10\nprint(x + y)')

        findings = scan_directory(str(tmp_path))

        assert len(findings) == 0

    def test_scan_empty_directory(self, tmp_path):
        """Should handle empty directories gracefully"""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        findings = scan_directory(str(empty_dir))

        assert len(findings) == 0


class TestIntegration:
    """Integration tests for realistic scenarios"""

    def test_realistic_flask_app_scan(self, tmp_path):
        """Should detect vulnerabilities in realistic Flask app"""
        app_file = tmp_path / "app.py"
        app_file.write_text("""
from flask import Flask, request
import sqlite3

app = Flask(__name__)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.route('/search')
def search():
    query = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    results = cursor.execute(f"SELECT * FROM items WHERE name='{query}'")
    return results.fetchall()
""")

        findings = scan_file(str(app_file))

        # Should find both secret and SQLi
        assert len(findings) >= 2
        types = [f.type for f in findings]
        assert Type.SECRETS in types
        assert Type.SQL_INJECTION in types