from unittest.mock import mock_open, patch, MagicMock
import requests

from cve.scanner import check_osv_api, scan_dependencies
from models import OSVFinding


class TestCheckOSVAPI:
    """Tests for the check_osv_api function"""

    @patch('cve.scanner.requests.post')
    def test_successful_vulnerability_found(self, mock_post):
        """Test when vulnerabilities are found"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'vulns': [
                {'id': 'CVE-2021-44228'},
                {'id': 'CVE-2021-45046'}
            ]
        }
        mock_post.return_value = mock_response

        result = check_osv_api('log4j', '2.14.1')

        assert result == ['CVE-2021-44228', 'CVE-2021-45046']
        mock_post.assert_called_once()

    @patch('cve.scanner.requests.post')
    def test_no_vulnerabilities_found(self, mock_post):
        """Test when no vulnerabilities are found"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'vulns': []}
        mock_post.return_value = mock_response

        result = check_osv_api('safe-package', '1.0.0')

        assert result == []

    @patch('cve.scanner.requests.post')
    def test_api_error_returns_empty_list(self, mock_post):
        """Test that API errors are handled gracefully"""
        mock_post.side_effect = requests.RequestException("API Error")

        result = check_osv_api('flask', '0.12')

        assert result == []

    @patch('cve.scanner.requests.post')
    def test_non_200_status_code(self, mock_post):
        """Test handling of non-200 status codes"""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        result = check_osv_api('unknown', '1.0.0')

        assert result == []

    @patch('cve.scanner.requests.post')
    def test_request_payload_format(self, mock_post):
        """Test that the API request payload is formatted correctly"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'vulns': []}
        mock_post.return_value = mock_response

        check_osv_api('requests', '2.28.0')

        expected_payload = {
            'package': {
                'name': 'requests',
                'ecosystem': 'PyPI'
            },
            'version': '2.28.0'
        }
        mock_post.assert_called_once_with(
            "https://api.osv.dev/v1/query",
            json=expected_payload,
            timeout=5
        )


class TestScanDependencies:
    """Tests for the scan_dependencies function"""

    @patch('cve.scanner.check_osv_api')
    def test_scan_with_vulnerabilities(self, mock_check_osv):
        """Test scanning a requirements file with vulnerabilities"""
        requirements_content = "flask==0.12\nrequests==2.28.0\ndjango==2.2.0\n"

        # Mock different responses for different packages
        def check_side_effect(package, version):
            if package == 'flask':
                return ['CVE-2018-1000656']
            elif package == 'django':
                return ['CVE-2019-14234']
            return []

        mock_check_osv.side_effect = check_side_effect

        with patch('builtins.open', mock_open(read_data=requirements_content)):
            findings = scan_dependencies('requirements.txt')

        assert len(findings) == 2
        assert findings[0].package == 'flask'
        assert findings[0].version == '0.12'
        assert findings[0].cves == ['CVE-2018-1000656']
        assert findings[1].package == 'django'
        assert findings[1].version == '2.2.0'
        assert findings[1].cves == ['CVE-2019-14234']

    @patch('cve.scanner.check_osv_api')
    def test_scan_with_no_vulnerabilities(self, mock_check_osv):
        """Test scanning when no vulnerabilities are found"""
        requirements_content = "requests==2.28.0\nnumpy==1.24.0\n"
        mock_check_osv.return_value = []

        with patch('builtins.open', mock_open(read_data=requirements_content)):
            findings = scan_dependencies('requirements.txt')

        assert len(findings) == 0

    @patch('cve.scanner.check_osv_api')
    def test_scan_skips_lines_without_version_pin(self, mock_check_osv):
        """Test that lines without == are skipped"""
        requirements_content = "flask==0.12\nrequests\n# comment\ndjango>=2.2.0\n"
        mock_check_osv.return_value = []

        with patch('builtins.open', mock_open(read_data=requirements_content)):
            findings = scan_dependencies('requirements.txt')

        # Should only check flask (the only one with ==)
        assert mock_check_osv.call_count == 1
        mock_check_osv.assert_called_with('flask', '0.12')

    @patch('cve.scanner.check_osv_api')
    def test_scan_empty_file(self, mock_check_osv):
        """Test scanning an empty requirements file"""
        with patch('builtins.open', mock_open(read_data="")):
            findings = scan_dependencies('requirements.txt')

        assert len(findings) == 0
        mock_check_osv.assert_not_called()

    @patch('cve.scanner.check_osv_api')
    def test_osv_finding_structure(self, mock_check_osv):
        """Test that OSVFinding objects are created correctly"""
        requirements_content = "flask==0.12\n"
        mock_check_osv.return_value = ['CVE-2018-1000656', 'CVE-2019-1010083']

        with patch('builtins.open', mock_open(read_data=requirements_content)):
            findings = scan_dependencies('requirements.txt')

        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, OSVFinding)
        assert finding.package == 'flask'
        assert finding.version == '0.12'
        assert finding.cves == ['CVE-2018-1000656', 'CVE-2019-1010083']

    @patch('cve.scanner.check_osv_api')
    def test_scan_with_whitespace(self, mock_check_osv):
        """Test that whitespace in requirements is handled"""
        requirements_content = "  flask==0.12  \n\ndjango==2.2.0\n"
        mock_check_osv.return_value = []

        with patch('builtins.open', mock_open(read_data=requirements_content)):
            findings = scan_dependencies('requirements.txt')

        # Verify both packages were checked despite whitespace
        assert mock_check_osv.call_count == 2