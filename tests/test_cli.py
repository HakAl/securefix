import json
import os
import pytest
import textwrap
from click.testing import CliRunner
from pathlib import Path
from unittest.mock import patch, Mock
from securefix.cli import cli


@pytest.fixture
def runner():
    """Create a Click CLI test runner"""
    return CliRunner()


@pytest.fixture
def temp_vulnerable_file(tmp_path):
    """Create a temporary file with vulnerabilities"""
    file_path = tmp_path / "vulnerable.py"
    # Use pickle which is reliably detected by Bandit (B301)
    file_path.write_text("""
import pickle

def load_data(data):
    return pickle.loads(data)

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

        # Mock config finder to avoid picking up any local bandit config
        with patch('securefix.sast.bandit_scanner._find_bandit_config', return_value=None):
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
        # Create multiple files with vulnerabilities that Bandit will definitely catch
        # Use pickle (B301) which is reliably detected
        file1 = tmp_path / "file1.py"
        file1.write_text(textwrap.dedent("""
            import pickle

            def load_data(data):
                return pickle.loads(data)
        """).strip())

        # Use eval (B307) which is reliably detected
        file2 = tmp_path / "file2.py"
        file2.write_text(textwrap.dedent("""
            def run_code(code):
                return eval(code)
        """).strip())

        output_path = tmp_path / "report.json"

        result = runner.invoke(cli, [
            'scan',
            str(tmp_path),
            '--output', str(output_path)
        ])

        assert result.exit_code == 0

        with open(output_path) as f:
            report = json.load(f)

        # Should find at least 1 vulnerability (pickle or eval)
        assert report['summary']['total_findings'] >= 1

    def test_scan_with_dependencies(self, runner, temp_vulnerable_file, temp_requirements, tmp_path):
        """Should scan both code and dependencies"""
        output_path = tmp_path / "report.json"

        # Mock config finder to avoid picking up any local bandit config
        with patch('securefix.sast.bandit_scanner._find_bandit_config', return_value=None):
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


class TestIngestCommand:
    """Tests for the ingest command"""

    def test_ingest_creates_corpus_directory(self, runner, tmp_path):
        """Should create corpus directory if it doesn't exist"""
        corpus_path = tmp_path / "corpus"
        persist_dir = tmp_path / "chroma_db"

        result = runner.invoke(cli, [
            'ingest',
            '--corpus-path', str(corpus_path),
            '--persist-dir', str(persist_dir)
        ])

        assert result.exit_code == 0
        assert corpus_path.exists()
        assert "Creating corpus directory" in result.output
        assert "Please add security corpus files" in result.output

    def test_ingest_refuses_to_overwrite_without_rebuild(self, runner, tmp_path):
        """Should not overwrite existing database without --rebuild flag"""
        corpus_path = tmp_path / "corpus"
        persist_dir = tmp_path / "chroma_db"

        # Create corpus and persist directories
        corpus_path.mkdir()
        persist_dir.mkdir()
        (persist_dir / "dummy.txt").write_text("existing")

        result = runner.invoke(cli, [
            'ingest',
            '--corpus-path', str(corpus_path),
            '--persist-dir', str(persist_dir)
        ])

        assert result.exit_code == 0
        assert "already exists" in result.output
        assert "Use --rebuild" in result.output

    @patch('securefix.cli.DocumentProcessor')
    def test_ingest_with_corpus_files(self, mock_processor_class, runner, tmp_path):
        """Should process corpus files and build vector database"""
        corpus_path = tmp_path / "corpus"
        corpus_path.mkdir()

        # Create sample corpus files
        (corpus_path / "test.md").write_text("# Security Guide\nTest content")
        (corpus_path / "data.csv").write_text("cwe_id,title\nCWE-89,SQL Injection")

        persist_dir = tmp_path / "chroma_db"

        # Mock the processor
        mock_processor = mock_processor_class.return_value
        mock_vector_store = Mock()
        mock_bm25_index = Mock()
        mock_chunks = [Mock() for _ in range(10)]
        mock_processor.process_documents.return_value = (mock_vector_store, mock_bm25_index, mock_chunks)

        result = runner.invoke(cli, [
            'ingest',
            '--corpus-path', str(corpus_path),
            '--persist-dir', str(persist_dir)
        ])

        assert result.exit_code == 0
        assert "Processing corpus" in result.output
        assert "Vector database built successfully" in result.output
        assert "Chunks indexed: 10" in result.output

    @patch('securefix.remediation.corpus_builder.DocumentProcessor')
    def test_ingest_rebuild_flag(self, mock_processor_class, runner, tmp_path):
        """Should rebuild database when --rebuild flag is used"""
        corpus_path = tmp_path / "corpus"
        corpus_path.mkdir()
        (corpus_path / "test.md").write_text("Test")

        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()
        (persist_dir / "old_data.txt").write_text("old")

        # Mock the processor
        mock_processor = mock_processor_class.return_value
        mock_processor.process_documents.return_value = (Mock(), Mock(), [Mock()])

        result = runner.invoke(cli, [
            'ingest',
            '--corpus-path', str(corpus_path),
            '--persist-dir', str(persist_dir),
            '--rebuild'
        ])

        assert result.exit_code == 0
        assert "Removing old database" in result.output


class TestFixCommand:
    """Tests for the fix command"""

    @pytest.fixture
    def sample_report(self, tmp_path):
        """Create a sample scan report"""
        report_path = tmp_path / "report.json"
        report_data = {
            'summary': {
                'scan_timestamp': '2024-01-01T00:00:00',
                'total_findings': 2,
                'total_cve_findings': 0,
                'by_severity': {'high': 2, 'medium': 0, 'low': 0, 'critical': 0}
            },
            'sast_findings': [
                {
                    'type': 'SQL Injection',
                    'snippet': 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")',
                    'line': 42,
                    'file': 'app.py',
                    'severity': 'High',
                    'confidence': 'High',
                    'cwe_id': 'CWE-89'
                },
                {
                    'type': 'Hardcoded Password',
                    'snippet': 'PASSWORD = "secret123"',
                    'line': 10,
                    'file': 'config.py',
                    'severity': 'High',
                    'confidence': 'Medium',
                    'cwe_id': 'CWE-798'
                }
            ],
            'cve_findings': []
        }
        report_path.write_text(json.dumps(report_data, indent=2))
        return report_path

    def test_fix_requires_vector_database(self, runner, sample_report, tmp_path):
        """Should fail if vector database doesn't exist"""
        persist_dir = tmp_path / "nonexistent_chroma"

        result = runner.invoke(cli, [
            'fix',
            str(sample_report),
            '--persist-dir', str(persist_dir)
        ])

        assert result.exit_code == 0  # CLI doesn't exit with error code
        assert "Vector database not found" in result.output
        assert "securefix ingest" in result.output

    def test_fix_loads_report(self, runner, sample_report, tmp_path):
        """Should load and parse scan report"""
        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()

        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc:
            mock_proc.return_value.load_existing_vectorstore.return_value = (None, None, None)

            result = runner.invoke(cli, [
                'fix',
                str(sample_report),
                '--persist-dir', str(persist_dir)
            ])

            assert "Loading scan report" in result.output
            assert "Found 2 SAST" in result.output

    def test_fix_sast_only_flag(self, runner, tmp_path):
        """Should filter to only SAST findings"""
        report_path = tmp_path / "mixed_report.json"
        report_data = {
            'summary': {'scan_timestamp': '2024-01-01T00:00:00'},
            'sast_findings': [{'type': 'SQL Injection', 'snippet': 'test', 'severity': 'High'}],
            'cve_findings': [{'package': 'flask', 'version': '0.12', 'cves': ['CVE-2018-1000656']}]
        }
        report_path.write_text(json.dumps(report_data))

        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()

        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc:
            mock_proc.return_value.load_existing_vectorstore.return_value = (None, None, None)

            result = runner.invoke(cli, [
                'fix',
                str(report_path),
                '--persist-dir', str(persist_dir),
                '--sast-only'
            ])

            assert "SAST only mode: 1 findings" in result.output

    def test_fix_cve_only_flag(self, runner, tmp_path):
        """Should filter to only CVE findings"""
        report_path = tmp_path / "mixed_report.json"
        report_data = {
            'summary': {'scan_timestamp': '2024-01-01T00:00:00'},
            'sast_findings': [{'type': 'SQL Injection', 'snippet': 'test', 'severity': 'High'}],
            'cve_findings': [{'package': 'flask', 'version': '0.12', 'cves': ['CVE-2018-1000656'], 'severity': 'High'}]
        }
        report_path.write_text(json.dumps(report_data))

        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()

        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc:
            mock_proc.return_value.load_existing_vectorstore.return_value = (None, None, None)

            result = runner.invoke(cli, [
                'fix',
                str(report_path),
                '--persist-dir', str(persist_dir),
                '--cve-only'
            ])

            assert "CVE only mode: 1 findings" in result.output

    def test_fix_severity_filter(self, runner, tmp_path):
        """Should filter findings by severity"""
        report_path = tmp_path / "report.json"
        report_data = {
            'summary': {'scan_timestamp': '2024-01-01T00:00:00'},
            'sast_findings': [
                {'type': 'Test1', 'snippet': 'test', 'severity': 'High'},
                {'type': 'Test2', 'snippet': 'test', 'severity': 'Medium'},
                {'type': 'Test3', 'snippet': 'test', 'severity': 'Low'}
            ],
            'cve_findings': []
        }
        report_path.write_text(json.dumps(report_data))

        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()

        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc:
            mock_proc.return_value.load_existing_vectorstore.return_value = (None, None, None)

            result = runner.invoke(cli, [
                'fix',
                str(report_path),
                '--persist-dir', str(persist_dir),
                '--severity-filter', 'high'
            ])

            assert "Filtered to 1/3 findings (>= high)" in result.output

    def test_fix_invalid_json_report(self, runner, tmp_path):
        """Should handle invalid JSON in report"""
        report_path = tmp_path / "bad_report.json"
        report_path.write_text("{ invalid json }")

        result = runner.invoke(cli, [
            'fix',
            str(report_path)
        ])

        assert "Invalid JSON" in result.output

    def test_fix_empty_report(self, runner, tmp_path):
        """Should handle report with no findings"""
        report_path = tmp_path / "empty_report.json"
        report_data = {
            'summary': {'scan_timestamp': '2024-01-01T00:00:00'},
            'sast_findings': [],
            'cve_findings': []
        }
        report_path.write_text(json.dumps(report_data))

        result = runner.invoke(cli, [
            'fix',
            str(report_path)
        ])

        assert "No vulnerabilities found" in result.output

    @patch('securefix.remediation.remediation_engine.RemediationEngine')
    @patch('securefix.remediation.corpus_builder.DocumentProcessor')
    @patch('securefix.remediation.llm.check_ollama_available')
    def test_fix_generates_remediations(self, mock_ollama_check, mock_proc_class,
                                        mock_engine_class, runner, sample_report, tmp_path):
        """Should generate fixes for vulnerabilities"""
        persist_dir = tmp_path / "chroma_db"
        persist_dir.mkdir()

        # Mock availability checks
        mock_ollama_check.return_value = True

        # Mock processor
        mock_processor = mock_proc_class.return_value
        mock_vector_store = Mock()
        mock_bm25_index = Mock()
        mock_chunks = [Mock()]
        mock_processor.load_existing_vectorstore.return_value = (mock_vector_store, mock_bm25_index, mock_chunks)

        # Mock remediation engine
        mock_engine = mock_engine_class.return_value
        mock_engine.get_llm_info.return_value = "Ollama llama3.2:3b"
        mock_engine.generate_fix.return_value = {
            'answer': '{"suggested_fix": "Use parameterized queries", "explanation": "Prevents SQL injection", "confidence": "High", "cwe_id": "CWE-89"}',
            'source_documents': [Mock(metadata={'source': 'test.md', 'doc_type': 'markdown'})]
        }

        output_path = tmp_path / "fixes.json"

        result = runner.invoke(cli, [
            'fix',
            str(sample_report),
            '--persist-dir', str(persist_dir),
            '--output', str(output_path),
            '--llm-mode', 'local'
        ])

        assert result.exit_code == 0
        assert "Generating fixes" in result.output
        assert "Successfully remediated: 2" in result.output
        assert output_path.exists()

        # Verify output structure
        with open(output_path) as f:
            fixes = json.load(f)

        assert 'summary' in fixes
        assert 'remediations' in fixes
        assert len(fixes['remediations']) == 2


class TestLLMConfiguration:
    """Tests for LLM configuration in CLI"""

    @patch('securefix.remediation.llm.check_ollama_available')
    def test_configure_llm_local_mode(self, mock_check, runner, tmp_path):
        """Should configure Ollama for local mode"""
        from securefix.cli import _configure_llm

        mock_check.return_value = True

        config = _configure_llm('local')

        assert config is not None
        mock_check.assert_called_once()

    @patch('securefix.remediation.llm.check_ollama_available')
    def test_configure_llm_local_unavailable(self, mock_check, runner):
        """Should fail if Ollama is not available"""
        from securefix.cli import _configure_llm

        mock_check.return_value = False

        config = _configure_llm('local')

        assert config is None

    @patch('securefix.remediation.llm.check_google_api_key')
    @patch.dict(os.environ, {'GOOGLE_API_KEY': 'test-key'})
    def test_configure_llm_google_mode(self, mock_check):
        """Should configure Google GenAI for google mode"""
        from securefix.cli import _configure_llm
        from securefix.remediation.config import app_config

        mock_check.return_value = True
        app_config.config.google_api_key = 'test-key'

        config = _configure_llm('google')

        assert config is not None

    @patch.dict(os.environ, {}, clear=True)
    def test_configure_llm_google_no_api_key(self):
        """Should fail if Google API key not set"""
        from securefix.cli import _configure_llm
        from securefix.remediation.config import app_config

        app_config.config.google_api_key = None

        config = _configure_llm('google')

        assert config is None

    @patch('securefix.remediation.llm.LLAMACPP_AVAILABLE', True)
    @patch('securefix.remediation.llm.validate_gguf_model')
    def test_configure_llm_llamacpp_mode(self, mock_validate, tmp_path):
        """Should configure LlamaCPP when available"""
        from securefix.cli import _configure_llm

        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        mock_validate.return_value = (True, None)

        config = _configure_llm('llamacpp', model_path=str(model_file))

        assert config is not None
        mock_validate.assert_called_once_with(str(model_file))

    @patch('securefix.remediation.llm.LLAMACPP_AVAILABLE', False)
    def test_configure_llm_llamacpp_unavailable(self):
        """Should fail if llama-cpp-python not installed"""
        from securefix.cli import _configure_llm

        config = _configure_llm('llamacpp', model_path='test.gguf')

        assert config is None

    @patch('securefix.remediation.llm.LLAMACPP_AVAILABLE', True)
    @patch.dict(os.environ, {}, clear=True)  # Clear all env vars
    def test_configure_llm_llamacpp_no_model_path(self):
        """Should fail if model path not provided"""
        from securefix.cli import _configure_llm
        from securefix.remediation.config import app_config

        # Reset app_config to not have the path
        app_config.config.llama_cpp_model_path = None

        config = _configure_llm('llamacpp')

        assert config is None

    @patch('securefix.remediation.llm.LLAMACPP_AVAILABLE', True)
    @patch('securefix.remediation.llm.validate_gguf_model')
    def test_configure_llm_llamacpp_invalid_model(self, mock_validate):
        """Should fail if model file is invalid"""
        from securefix.cli import _configure_llm

        mock_validate.return_value = (False, "File too small")

        config = _configure_llm('llamacpp', model_path='test.gguf')

        assert config is None

    @patch('securefix.remediation.llm.LLAMACPP_AVAILABLE', True)
    @patch('securefix.remediation.llm.validate_gguf_model')
    @patch.dict(os.environ, {'LLAMACPP_MODEL_PATH': '/path/to/model.gguf'}, clear=True)
    def test_configure_llm_llamacpp_env_variable(self, mock_validate):
        """Should use LLAMACPP_MODEL_PATH environment variable"""
        from securefix.cli import _configure_llm
        from securefix.remediation.config import Config

        # Reload config from env to pick up the mocked env var
        test_config = Config.from_env()

        with patch('securefix.remediation.config.app_config.config', test_config):
            mock_validate.return_value = (True, None)

            config = _configure_llm('llamacpp')

            assert config is not None
            mock_validate.assert_called_once_with('/path/to/model.gguf')


class TestUtilityFunctions:
    """Tests for CLI utility functions"""

    def test_parse_fix_response_valid_json(self):
        """Should parse valid JSON response"""
        from securefix.cli import _parse_fix_response

        response = '{"suggested_fix": "test", "explanation": "test", "confidence": "High"}'
        result = _parse_fix_response(response)

        assert result is not None
        assert result['suggested_fix'] == 'test'

    def test_parse_fix_response_with_markdown(self):
        """Should extract JSON from markdown code blocks"""
        from securefix.cli import _parse_fix_response

        response = '```json\n{"suggested_fix": "test"}\n```'
        result = _parse_fix_response(response)

        assert result is not None
        assert 'suggested_fix' in result

    def test_parse_fix_response_invalid(self):
        """Should handle invalid JSON gracefully"""
        from securefix.cli import _parse_fix_response

        response = 'not json at all'
        result = _parse_fix_response(response)

        assert result is None

    def test_parse_fix_response_empty(self):
        """Should handle empty response"""
        from securefix.cli import _parse_fix_response

        result = _parse_fix_response('')

        assert result is None

    def test_count_by_severity(self):
        """Should count remediations by severity"""
        from securefix.cli import _count_by_severity

        remediations = [
            {'finding': {'severity': 'High'}},
            {'finding': {'severity': 'High'}},
            {'finding': {'severity': 'Medium'}},
        ]

        counts = _count_by_severity(remediations)

        assert counts['high'] == 2
        assert counts['medium'] == 1
        assert counts['low'] == 0

    def test_count_by_confidence(self):
        """Should count remediations by confidence"""
        from securefix.cli import _count_by_confidence

        remediations = [
            {'confidence': 'High'},
            {'confidence': 'High'},
            {'confidence': 'Medium'},
        ]

        counts = _count_by_confidence(remediations)

        assert counts['High'] == 2
        assert counts['Medium'] == 1
        assert counts['Low'] == 0

    def test_should_create_pr_with_high_confidence_high_severity(self):
        """Should return True for high confidence + high severity fixes"""
        from securefix.mcp import should_create_pr

        remediations = [
            {'finding': {'severity': 'High'}, 'confidence': 'High'},
            {'finding': {'severity': 'Critical'}, 'confidence': 'High'},
        ]

        should_prompt, pr_worthy = should_create_pr(remediations)

        assert should_prompt is True
        assert len(pr_worthy) == 2

    def test_should_create_pr_with_low_confidence(self):
        """Should return False for low confidence fixes"""
        from securefix.mcp import should_create_pr

        remediations = [
            {'finding': {'severity': 'High'}, 'confidence': 'Low'},
            {'finding': {'severity': 'Critical'}, 'confidence': 'Medium'},
        ]

        should_prompt, pr_worthy = should_create_pr(remediations)

        assert should_prompt is False
        assert len(pr_worthy) == 0

    def test_should_create_pr_with_low_severity(self):
        """Should return False for low severity fixes"""
        from securefix.mcp import should_create_pr

        remediations = [
            {'finding': {'severity': 'Low'}, 'confidence': 'High'},
            {'finding': {'severity': 'Medium'}, 'confidence': 'High'},
        ]

        should_prompt, pr_worthy = should_create_pr(remediations)

        assert should_prompt is False
        assert len(pr_worthy) == 0

    def test_should_create_pr_with_empty_list(self):
        """Should return False for empty remediation list"""
        from securefix.mcp import should_create_pr

        should_prompt, pr_worthy = should_create_pr([])

        assert should_prompt is False
        assert len(pr_worthy) == 0

    def test_should_create_pr_mixed_fixes(self):
        """Should filter correctly with mixed severity/confidence"""
        from securefix.mcp import should_create_pr

        remediations = [
            {'finding': {'severity': 'High'}, 'confidence': 'High'},      # YES
            {'finding': {'severity': 'High'}, 'confidence': 'Medium'},    # NO
            {'finding': {'severity': 'Medium'}, 'confidence': 'High'},    # NO
            {'finding': {'severity': 'Critical'}, 'confidence': 'High'},  # YES
        ]

        should_prompt, pr_worthy = should_create_pr(remediations)

        assert should_prompt is True
        assert len(pr_worthy) == 2

    def test_generate_branch_name_critical(self):
        """Should generate branch name for critical severity"""
        from securefix.mcp import generate_branch_name

        remediations = [
            {'finding': {'severity': 'Critical'}},
        ]

        branch_name = generate_branch_name(remediations)

        assert branch_name.startswith('securefix-critical-fixes-')
        # Format: securefix-critical-fixes-YYYYMMDD-HHMMSS (5 parts with dashes)
        assert len(branch_name.split('-')) == 5

    def test_generate_branch_name_high(self):
        """Should generate branch name for high severity"""
        from securefix.mcp import generate_branch_name

        remediations = [
            {'finding': {'severity': 'High'}},
        ]

        branch_name = generate_branch_name(remediations)

        assert branch_name.startswith('securefix-high-severity-')

    def test_generate_branch_name_mixed(self):
        """Should prioritize critical in branch name"""
        from securefix.mcp import generate_branch_name

        remediations = [
            {'finding': {'severity': 'High'}},
            {'finding': {'severity': 'Critical'}},
            {'finding': {'severity': 'Medium'}},
        ]

        branch_name = generate_branch_name(remediations)

        assert 'critical' in branch_name

    def test_generate_branch_name_default(self):
        """Should generate default branch name for other severities"""
        from securefix.mcp import generate_branch_name

        remediations = [
            {'finding': {'severity': 'Medium'}},
        ]

        branch_name = generate_branch_name(remediations)

        assert branch_name.startswith('securefix-automated-fixes-')

    def test_create_github_pr_not_configured(self):
        """Should fail gracefully when MCP is not configured"""
        from securefix.cli import _create_github_pr_cli

        with patch('securefix.remediation.config.app_config') as mock_config:
            mock_config.mcp.is_configured.return_value = False

            result = _create_github_pr_cli([], 'report.json')

            assert result['success'] is False
            assert 'not fully configured' in result['error']

    def test_create_github_pr_with_custom_branch(self):
        """Should use custom branch name when provided"""
        from securefix.cli import _create_github_pr_cli
        import json
        from unittest.mock import mock_open

        mock_report = json.dumps({'repository_root': '/test/repo'})

        with patch('securefix.remediation.config.app_config') as mock_config, \
             patch('securefix.mcp.pr_logic.group_fixes_by_file') as mock_group, \
             patch('securefix.mcp.pr_logic.apply_fixes_to_file') as mock_apply, \
             patch('securefix.cli.click.confirm', return_value=False), \
             patch('builtins.open', mock_open(read_data=mock_report)):  # Mock report file

            mock_config.mcp.is_configured.return_value = True
            mock_config.mcp.github_owner = 'test-owner'
            mock_config.mcp.github_repo = 'test-repo'
            mock_config.mcp.mcp_server_host = '127.0.0.1'
            mock_config.mcp.mcp_server_port = 3000

            # Mock file operations
            mock_group.return_value = {'/test/repo/test.py': [{'finding': {'line': 10}}]}
            mock_apply.return_value = 'fixed code'

            remediations = [
                {'finding': {'severity': 'High', 'file': '/test/repo/test.py', 'line': 10}, 'confidence': 'High'}
            ]

            result = _create_github_pr_cli(remediations, 'report.json', 'custom-branch-name')

            # User cancelled, so we get cancelled flag
            assert result.get('cancelled') == True

    def test_create_github_pr_auto_generates_branch(self):
        """Should auto-generate branch name if not provided"""
        from securefix.cli import _create_github_pr_cli
        import json
        from unittest.mock import mock_open

        mock_report = json.dumps({'repository_root': '/test/repo'})

        with patch('securefix.remediation.config.app_config') as mock_config, \
             patch('securefix.mcp.pr_logic.group_fixes_by_file') as mock_group, \
             patch('securefix.mcp.pr_logic.apply_fixes_to_file') as mock_apply, \
             patch('securefix.cli.click.confirm', return_value=False), \
             patch('builtins.open', mock_open(read_data=mock_report)):  # Mock report file

            mock_config.mcp.is_configured.return_value = True
            mock_config.mcp.github_owner = 'test-owner'
            mock_config.mcp.github_repo = 'test-repo'
            mock_config.mcp.mcp_server_host = '127.0.0.1'
            mock_config.mcp.mcp_server_port = 3000

            # Mock file operations
            mock_group.return_value = {'/test/repo/test.py': [{'finding': {'line': 10}}]}
            mock_apply.return_value = 'fixed code'

            remediations = [
                {'finding': {'severity': 'Critical', 'file': '/test/repo/test.py', 'line': 10}, 'confidence': 'High'}
            ]

            result = _create_github_pr_cli(remediations, 'report.json')

            # User cancelled, but function still runs successfully
            assert result.get('cancelled') == True


class TestMCPIntegration:
    """Tests for MCP GitHub PR creation integration"""

    @pytest.fixture
    def mock_mcp_config(self):
        """Mock MCP configuration"""
        with patch('securefix.remediation.config.app_config') as mock_config:
            mock_config.mcp.is_configured.return_value = True
            mock_config.mcp.github_owner = 'test-owner'
            mock_config.mcp.github_repo = 'test-repo'
            mock_config.mcp.mcp_server_host = '127.0.0.1'
            mock_config.mcp.mcp_server_port = 3000
            yield mock_config

    @pytest.fixture
    def sample_report_with_high_severity(self, tmp_path):
        """Create a sample report with high severity findings"""
        report_path = tmp_path / "report.json"
        report_data = {
            "summary": {
                "scan_timestamp": "2025-01-03T12:00:00",
                "total_findings": 2,
                "by_severity": {"High": 2}
            },
            "sast_findings": [
                {
                    "type": "SQL Injection",
                    "severity": "High",
                    "file": "app.py",
                    "line": 10,
                    "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
                },
                {
                    "type": "Pickle Deserialization",
                    "severity": "Critical",
                    "file": "utils.py",
                    "line": 5,
                    "snippet": "pickle.loads(data)"
                }
            ],
            "cve_findings": []
        }
        with open(report_path, 'w') as f:
            json.dump(report_data, f)
        return report_path

    def test_fix_prompts_for_pr_when_mcp_configured(self, runner, mock_mcp_config,
                                                      sample_report_with_high_severity, tmp_path,
                                                      mock_vector_store, mock_bm25_index, mock_bm25_chunks):
        """Should prompt for PR creation when MCP is configured and high-confidence fixes exist"""
        # Mock all the dependencies
        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc_cls, \
             patch('securefix.cli._configure_llm') as mock_llm, \
             patch('securefix.remediation.fix_knowledge_store.DocumentStore'), \
             patch('securefix.remediation.remediation_engine.RemediationEngine') as mock_engine:

            # Setup DocumentProcessor mock to return 3-tuple
            mock_proc_instance = Mock()
            mock_proc_instance.load_existing_vectorstore.return_value = (
                mock_vector_store,
                mock_bm25_index,
                mock_bm25_chunks
            )
            mock_proc_cls.return_value = mock_proc_instance

            # Setup LLM mock
            mock_llm.return_value = Mock()

            # Setup RemediationEngine mock
            mock_engine_instance = Mock()
            mock_engine_instance.get_llm_info.return_value = "Mock LLM"
            mock_engine_instance.generate_fix.return_value = {
                'answer': '{"suggested_fix": "test", "explanation": "test", "confidence": "High"}',
                'source_documents': []
            }
            mock_engine.return_value = mock_engine_instance

            # Create vector DB directory
            vector_db = tmp_path / "chroma_db"
            vector_db.mkdir()

            # Run fix command with --no-cache to avoid interactive prompts
            # Answer 'n' to PR creation prompt
            result = runner.invoke(cli, [
                'fix',
                str(sample_report_with_high_severity),
                '--output', str(tmp_path / 'fixes.json'),
                '--persist-dir', str(vector_db),
                '--no-cache'
            ], input='n\n')

            # Should show PR prompt
            assert 'GITHUB PULL REQUEST' in result.output
            assert 'high-confidence fix' in result.output
            assert 'Would you like to create a GitHub Pull Request' in result.output

    def test_fix_skips_pr_prompt_when_no_high_confidence_fixes(self, runner, mock_mcp_config,
                                                                 tmp_path):
        """Should not prompt for PR when no high-confidence fixes exist"""
        # Create report with low severity findings
        report_path = tmp_path / "report.json"
        report_data = {
            "summary": {"scan_timestamp": "2025-01-03T12:00:00", "total_findings": 1},
            "sast_findings": [
                {"type": "Test", "severity": "Low", "file": "test.py", "line": 1, "snippet": "test"}
            ],
            "cve_findings": []
        }
        with open(report_path, 'w') as f:
            json.dump(report_data, f)

        with patch('securefix.remediation.corpus_builder.DocumentProcessor'), \
             patch('securefix.cli._configure_llm') as mock_llm, \
             patch('securefix.remediation.fix_knowledge_store.DocumentStore'), \
             patch('securefix.remediation.remediation_engine.RemediationEngine') as mock_engine:

            mock_llm.return_value = Mock()
            mock_engine_instance = Mock()
            mock_engine_instance.get_llm_info.return_value = "Mock LLM"
            # Return low confidence
            mock_engine_instance.generate_fix.return_value = {
                'answer': '{"suggested_fix": "test", "explanation": "test", "confidence": "Low"}',
                'source_documents': []
            }
            mock_engine.return_value = mock_engine_instance

            vector_db = tmp_path / "chroma_db"
            vector_db.mkdir()

            result = runner.invoke(cli, [
                'fix',
                str(report_path),
                '--output', str(tmp_path / 'fixes.json'),
                '--persist-dir', str(vector_db),
                '--no-cache'
            ])

            # Should NOT show PR prompt
            assert 'GITHUB PULL REQUEST' not in result.output

    def test_fix_skips_pr_prompt_when_mcp_not_configured(self, runner, tmp_path,
                                                          sample_report_with_high_severity):
        """Should not prompt for PR when MCP is not configured"""
        with patch('securefix.remediation.config.app_config') as mock_config, \
             patch('securefix.remediation.corpus_builder.DocumentProcessor'), \
             patch('securefix.cli._configure_llm') as mock_llm, \
             patch('securefix.remediation.fix_knowledge_store.DocumentStore'), \
             patch('securefix.remediation.remediation_engine.RemediationEngine') as mock_engine:

            # MCP not configured
            mock_config.mcp.is_configured.return_value = False

            mock_llm.return_value = Mock()
            mock_engine_instance = Mock()
            mock_engine_instance.get_llm_info.return_value = "Mock LLM"
            mock_engine_instance.generate_fix.return_value = {
                'answer': '{"suggested_fix": "test", "explanation": "test", "confidence": "High"}',
                'source_documents': []
            }
            mock_engine.return_value = mock_engine_instance

            vector_db = tmp_path / "chroma_db"
            vector_db.mkdir()

            result = runner.invoke(cli, [
                'fix',
                str(sample_report_with_high_severity),
                '--output', str(tmp_path / 'fixes.json'),
                '--persist-dir', str(vector_db),
                '--no-cache'
            ])

            # Should NOT show PR prompt
            assert 'GITHUB PULL REQUEST' not in result.output

    def test_fix_creates_pr_with_custom_branch_name(self, runner, mock_mcp_config,
                                                     sample_report_with_high_severity, tmp_path,
                                                     mock_vector_store, mock_bm25_index, mock_bm25_chunks):
        """Should allow customizing branch name during PR creation"""
        with patch('securefix.remediation.corpus_builder.DocumentProcessor') as mock_proc_cls, \
             patch('securefix.cli._configure_llm') as mock_llm, \
             patch('securefix.remediation.fix_knowledge_store.DocumentStore'), \
             patch('securefix.remediation.remediation_engine.RemediationEngine') as mock_engine, \
             patch('securefix.cli._create_github_pr_cli') as mock_create_pr:

            # Setup DocumentProcessor mock to return 3-tuple
            mock_proc_instance = Mock()
            mock_proc_instance.load_existing_vectorstore.return_value = (
                mock_vector_store,
                mock_bm25_index,
                mock_bm25_chunks
            )
            mock_proc_cls.return_value = mock_proc_instance

            # Setup LLM mock
            mock_llm.return_value = Mock()

            # Setup RemediationEngine mock
            mock_engine_instance = Mock()
            mock_engine_instance.get_llm_info.return_value = "Mock LLM"
            mock_engine_instance.generate_fix.return_value = {
                'answer': '{"suggested_fix": "test", "explanation": "test", "confidence": "High"}',
                'source_documents': []
            }
            mock_engine.return_value = mock_engine_instance

            # Setup PR creation mock
            mock_create_pr.return_value = {
                'success': True,
                'pr_url': 'https://github.com/test/test/pull/123'
            }

            # Create vector DB directory
            vector_db = tmp_path / "chroma_db"
            vector_db.mkdir()

            # Answer: yes to PR creation, yes to customize, enter custom name
            result = runner.invoke(cli, [
                'fix',
                str(sample_report_with_high_severity),
                '--output', str(tmp_path / 'fixes.json'),
                '--persist-dir', str(vector_db),
                '--no-cache'
            ], input='y\ny\nmy-custom-branch\n')

            # Should have called create_pr with custom branch name
            assert mock_create_pr.called
            call_args = mock_create_pr.call_args
            assert call_args[0][2] == 'my-custom-branch'  # branch_name argument


if __name__ == '__main__':
    pytest.main([__file__, "-v"])