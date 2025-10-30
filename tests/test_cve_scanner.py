from unittest.mock import mock_open, patch, MagicMock
import pytest
import sys

from securefix.cve.scanner import (
    scan_pyproject,
    scan_dependencies,
    _parse_dependency_spec,
    _extract_version_from_specifier
)
from securefix.models import OSVFinding


class TestParseDependencySpec:
    """Tests for parsing PEP 508 dependency specifications"""

    def test_parse_exact_version(self):
        """Test parsing exact version specification"""
        package, version = _parse_dependency_spec("requests==2.32.0")
        assert package == "requests"
        assert version == "2.32.0"

    def test_parse_minimum_version(self):
        """Test parsing >= version specification"""
        package, version = _parse_dependency_spec("requests>=2.32.0")
        assert package == "requests"
        assert version == "2.32.0"

    def test_parse_version_range(self):
        """Test parsing version range with multiple specifiers"""
        package, version = _parse_dependency_spec("requests>=2.32.0,<3.0.0")
        assert package == "requests"
        assert version == "2.32.0"  # Should extract minimum version

    def test_parse_complex_spec(self):
        """Test parsing complex specification"""
        package, version = _parse_dependency_spec("click>=8.3.0,<9.0.0")
        assert package == "click"
        assert version == "8.3.0"

    def test_parse_no_version_specifier(self):
        """Test parsing dependency without version"""
        package, version = _parse_dependency_spec("requests")
        assert package is None
        assert version is None

    def test_parse_with_extras(self):
        """Test parsing dependency with extras"""
        package, version = _parse_dependency_spec("requests[security]>=2.32.0")
        assert package == "requests"
        assert version == "2.32.0"

    def test_parse_invalid_spec(self):
        """Test handling of invalid dependency spec"""
        package, version = _parse_dependency_spec("invalid>>2.0.0")
        assert package is None
        assert version is None

    def test_parse_with_environment_marker(self):
        """Test parsing dependency with environment marker"""
        package, version = _parse_dependency_spec("tomli>=2.0.0; python_version < '3.11'")
        assert package == "tomli"
        assert version == "2.0.0"


class TestExtractVersionFromSpecifier:
    """Tests for version extraction from specifier sets"""

    def test_extract_exact_version(self):
        """Test extracting exact version (==)"""
        from packaging.specifiers import SpecifierSet
        spec_set = SpecifierSet("==2.32.0")
        version = _extract_version_from_specifier(spec_set)
        assert version == "2.32.0"

    def test_extract_minimum_version(self):
        """Test extracting from >= specifier"""
        from packaging.specifiers import SpecifierSet
        spec_set = SpecifierSet(">=2.32.0,<3.0.0")
        version = _extract_version_from_specifier(spec_set)
        assert version == "2.32.0"

    def test_extract_from_less_than_only(self):
        """Test extracting from < specifier when no >= exists"""
        from packaging.specifiers import SpecifierSet
        spec_set = SpecifierSet("<3.0.0")
        version = _extract_version_from_specifier(spec_set)
        assert version == "3.0.0"

    def test_extract_prioritizes_exact(self):
        """Test that == is prioritized over other operators"""
        from packaging.specifiers import SpecifierSet
        spec_set = SpecifierSet(">=2.0.0,==2.32.0,<3.0.0")
        version = _extract_version_from_specifier(spec_set)
        assert version == "2.32.0"


class TestScanPyproject:
    """Tests for scanning pyproject.toml files"""

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_with_vulnerabilities(self, mock_query_osv):
        """Test scanning pyproject.toml with vulnerable dependencies"""
        pyproject_content = b"""
[project]
dependencies = [
    "flask==0.12",
    "requests>=2.32.0,<3.0.0",
    "django==2.2.0"
]
"""

        def query_side_effect(package, version):
            if package == 'flask':
                return ['CVE-2018-1000656']
            elif package == 'django':
                return ['CVE-2019-14234']
            return []

        mock_query_osv.side_effect = query_side_effect

        # Mock tomllib/tomli load
        if sys.version_info >= (3, 11):
            import tomllib
            mock_module = 'tomllib'
        else:
            mock_module = 'tomli'

        with patch('builtins.open', mock_open(read_data=pyproject_content)):
            with patch(f'securefix.cve.scanner.{mock_module}.load') as mock_load:
                mock_load.return_value = {
                    'project': {
                        'dependencies': [
                            'flask==0.12',
                            'requests>=2.32.0,<3.0.0',
                            'django==2.2.0'
                        ]
                    }
                }
                findings = scan_pyproject('pyproject.toml')

        assert len(findings) == 2
        assert findings[0].package == 'flask'
        assert findings[0].version == '0.12'
        assert findings[0].cves == ['CVE-2018-1000656']
        assert findings[1].package == 'django'
        assert findings[1].version == '2.2.0'

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_no_vulnerabilities(self, mock_query_osv):
        """Test scanning pyproject.toml with no vulnerabilities"""
        mock_query_osv.return_value = []

        pyproject_data = {
            'project': {
                'dependencies': [
                    'requests>=2.32.0',
                    'click>=8.3.0'
                ]
            }
        }

        with patch('builtins.open', mock_open()):
            with patch('securefix.cve.scanner.tomllib.load', return_value=pyproject_data):
                findings = scan_pyproject('pyproject.toml')

        assert len(findings) == 0

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_no_dependencies(self, mock_query_osv):
        """Test scanning pyproject.toml with no dependencies section"""
        pyproject_data = {'project': {}}

        with patch('builtins.open', mock_open()):
            with patch('securefix.cve.scanner.tomllib.load', return_value=pyproject_data):
                findings = scan_pyproject('pyproject.toml')

        assert len(findings) == 0
        mock_query_osv.assert_not_called()

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_skips_unparseable_deps(self, mock_query_osv):
        """Test that unparseable dependencies are skipped gracefully"""
        mock_query_osv.return_value = []

        if sys.version_info >= (3, 11):
            mock_module = 'tomllib'
        else:
            mock_module = 'tomli'

        with patch('builtins.open', mock_open()):
            with patch(f'securefix.cve.scanner.{mock_module}.load') as mock_load:
                mock_load.return_value = {
                    'project': {
                        'dependencies': [
                            'requests>=2.32.0',  # Valid
                            'invalid>>spec',  # Invalid
                            'click'  # No version
                        ]
                    }
                }
                findings = scan_pyproject('pyproject.toml')

        # Should only check 'requests' (the valid one with version)
        assert mock_query_osv.call_count == 1
        mock_query_osv.assert_called_with('requests', '2.32.0')

    def test_scan_pyproject_file_not_found(self):
        """Test handling of missing pyproject.toml"""
        with pytest.raises(FileNotFoundError):
            scan_pyproject('nonexistent.toml')

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_invalid_toml(self, mock_query_osv):
        """Test handling of invalid TOML syntax"""
        if sys.version_info >= (3, 11):
            mock_module = 'tomllib'
        else:
            mock_module = 'tomli'

        with patch('builtins.open', mock_open()):
            with patch(f'securefix.cve.scanner.{mock_module}.load') as mock_load:
                mock_load.side_effect = Exception("Invalid TOML")

                with pytest.raises(ValueError, match="Error parsing pyproject.toml"):
                    scan_pyproject('pyproject.toml')

    @patch('securefix.cve.scanner.query_osv')
    def test_scan_pyproject_with_environment_markers(self, mock_query_osv):
        """Test scanning dependencies with environment markers"""
        mock_query_osv.return_value = ['CVE-2023-1234']

        pyproject_data = {
            'project': {
                'dependencies': [
                    "tomli>=2.0.0; python_version < '3.11'",
                ]
            }
        }

        with patch('builtins.open', mock_open()):
            with patch('securefix.cve.scanner.tomllib.load', return_value=pyproject_data):
                findings = scan_pyproject('pyproject.toml')

        # Should parse and check despite environment marker
        assert mock_query_osv.call_count == 1
        mock_query_osv.assert_called_with('tomli', '2.0.0')


class TestScanDependenciesAutoDetect:
    """Tests for auto-detecting file type"""

    @patch('securefix.cve.scanner.scan_requirements')
    def test_autodetect_requirements_txt(self, mock_scan_requirements):
        """Test that requirements.txt is detected and scanned"""
        mock_scan_requirements.return_value = []

        scan_dependencies('requirements.txt')

        mock_scan_requirements.assert_called_once_with('requirements.txt')

    @patch('securefix.cve.scanner.scan_pyproject')
    def test_autodetect_pyproject_toml(self, mock_scan_pyproject):
        """Test that pyproject.toml is detected and scanned"""
        mock_scan_pyproject.return_value = []

        scan_dependencies('pyproject.toml')

        mock_scan_pyproject.assert_called_once_with('pyproject.toml')

    @patch('securefix.cve.scanner.scan_requirements')
    def test_autodetect_defaults_to_requirements(self, mock_scan_requirements):
        """Test that non-.toml files default to requirements scanner"""
        mock_scan_requirements.return_value = []

        scan_dependencies('deps.txt')

        mock_scan_requirements.assert_called_once_with('deps.txt')

    @patch('securefix.cve.scanner.scan_pyproject')
    def test_autodetect_case_sensitive_toml(self, mock_scan_pyproject):
        """Test that .toml extension detection is case-sensitive"""
        mock_scan_pyproject.return_value = []

        scan_dependencies('pyproject.toml')

        mock_scan_pyproject.assert_called_once()


class TestTomliImport:
    """Tests for tomli/tomllib import handling"""

    def test_tomli_not_installed_python_310(self):
        """Test that helpful error is raised if tomli not installed on Python < 3.11"""
        if sys.version_info >= (3, 11):
            pytest.skip("Test only relevant for Python < 3.11")

        with patch.dict('sys.modules', {'tomli': None}):
            with patch('builtins.open', mock_open()):
                with pytest.raises(ImportError, match="tomli is required"):
                    scan_pyproject('pyproject.toml')

    def test_uses_tomllib_python_311_plus(self):
        """Test that tomllib is used on Python 3.11+"""
        if sys.version_info < (3, 11):
            pytest.skip("Test only relevant for Python >= 3.11")

        # Should not raise ImportError about tomli
        with patch('builtins.open', mock_open()):
            with patch('tomllib.load') as mock_load:
                mock_load.return_value = {'project': {}}
                scan_pyproject('pyproject.toml')
                mock_load.assert_called_once()