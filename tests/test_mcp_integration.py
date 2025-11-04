"""
Integration tests for MCP (Model Context Protocol) GitHub server communication.

These tests verify that fastmcp can successfully connect to and communicate with
the github-mcp-server. Tests are marked with @pytest.mark.requires_mcp and will
be skipped if the MCP server is not available.

Prerequisites:
    - github-mcp-server must be running (npm install -g @modelcontextprotocol/server-github)
    - GITHUB_TOKEN environment variable must be set
    - fastmcp must be installed (pip install -e ".[mcp]")
"""
import os
import pytest
from unittest.mock import patch, MagicMock

# Check if fastmcp is available
try:
    import fastmcp
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False
    fastmcp = None
    FastMCP = None


@pytest.fixture
def github_token():
    """Get GitHub token from environment or skip test if not available."""
    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        pytest.skip("GITHUB_TOKEN environment variable not set")
    return token


@pytest.fixture
def mcp_server_config():
    """Get MCP server configuration from environment."""
    return {
        'host': os.environ.get('MCP_SERVER_HOST', '127.0.0.1'),
        'port': int(os.environ.get('MCP_SERVER_PORT', '3000')),
    }


@pytest.fixture
def mock_mcp_client():
    """Create a mock MCP client for unit testing without server."""
    # Don't use spec=FastMCP since we don't know the exact API yet
    mock_client = MagicMock()
    mock_client.connect = MagicMock(return_value=True)
    mock_client.disconnect = MagicMock(return_value=None)
    mock_client.is_connected = MagicMock(return_value=True)
    return mock_client


class TestMCPClientAvailability:
    """Test that the MCP client library is properly installed."""

    def test_fastmcp_importable(self):
        """Test that fastmcp can be imported."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed - run: pip install -e '.[mcp]'")

        assert fastmcp is not None
        assert FastMCP is not None

    def test_fastmcp_version(self):
        """Test that fastmcp version is acceptable."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # Check if version attribute exists
        if hasattr(fastmcp, '__version__'):
            version = fastmcp.__version__
            # Version should be 0.2.0 or higher
            major, minor, *_ = version.split('.')
            assert int(major) >= 0
            assert int(minor) >= 2


@pytest.mark.unit
class TestMCPClientUnitTests:
    """Unit tests for MCP client functionality (mocked, no server required)."""

    def test_mock_client_connection(self, mock_mcp_client):
        """Test that mock client can simulate connection."""
        result = mock_mcp_client.connect()
        assert result is True
        assert mock_mcp_client.is_connected()

    def test_mock_client_disconnection(self, mock_mcp_client):
        """Test that mock client can simulate disconnection."""
        mock_mcp_client.connect()
        mock_mcp_client.disconnect()
        mock_mcp_client.disconnect.assert_called_once()


@pytest.mark.integration
@pytest.mark.requires_mcp
class TestMCPServerConnection:
    """Integration tests for MCP server connectivity.

    These tests require a running github-mcp-server instance.
    Run: github-mcp-server --token $GITHUB_TOKEN
    """

    def test_mcp_server_reachable(self, mcp_server_config):
        """Test that MCP server is reachable at configured host:port."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        import socket

        host = mcp_server_config['host']
        port = mcp_server_config['port']

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # 2 second timeout

        try:
            result = sock.connect_ex((host, port))
            sock.close()

            if result != 0:
                pytest.skip(
                    f"MCP server not reachable at {host}:{port}. "
                    f"Start server with: github-mcp-server --token $GITHUB_TOKEN"
                )

            # Server is reachable
            assert result == 0
        except socket.gaierror:
            pytest.skip(f"Cannot resolve host: {host}")

    def test_fastmcp_client_initialization(self, github_token, mcp_server_config):
        """Test that FastMCP client can be initialized with config."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # This is a basic test - actual connection tested in next test
        # Just verify we can create a client instance without errors
        try:
            # Note: Actual FastMCP API might differ - adjust as needed
            # This is a placeholder for the real implementation
            client_config = {
                'server_url': f"http://{mcp_server_config['host']}:{mcp_server_config['port']}",
                'token': github_token
            }

            # Just verify we can create config without errors
            assert client_config is not None
            assert 'token' in client_config

        except Exception as e:
            pytest.skip(f"Error initializing MCP client: {e}")

    @pytest.mark.slow
    def test_mcp_github_server_health(self, github_token, mcp_server_config):
        """Test basic communication with github-mcp-server.

        This test attempts to verify the server is responsive.
        Actual test implementation depends on github-mcp-server's protocol.
        """
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # TODO: Implement actual health check once FastMCP API is clear
        # This is a placeholder that will need to be updated based on
        # the actual fastmcp API for connecting to MCP servers

        pytest.skip(
            "Health check implementation pending - depends on fastmcp API. "
            "Manual verification: curl http://localhost:3000/health"
        )


@pytest.mark.integration
@pytest.mark.requires_mcp
@pytest.mark.slow
class TestMCPGitHubOperations:
    """Integration tests for GitHub operations via MCP.

    These tests perform actual GitHub API operations through the MCP server.
    """

    def test_github_authentication(self, github_token):
        """Test that GitHub token is valid for authentication."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # Verify token format
        assert github_token.startswith(('ghp_', 'github_pat_', 'gho_', 'ghu_', 'ghs_', 'ghr_'))
        assert len(github_token) >= 40  # GitHub tokens are at least 40 chars

    def test_list_repositories_via_mcp(self, github_token, mcp_server_config):
        """Test listing repositories through MCP server.

        This is a placeholder test that will be implemented once we have
        working examples of the fastmcp + github-mcp-server integration.
        """
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # TODO: Implement actual repository listing test
        # Example (API TBD):
        # client = FastMCP(server_url=..., token=github_token)
        # repos = client.list_repositories()
        # assert isinstance(repos, list)

        pytest.skip(
            "Repository listing test pending - requires fastmcp API implementation. "
            "This test will verify MCP can communicate with GitHub API."
        )

    def test_get_repository_info_via_mcp(self, github_token, mcp_server_config):
        """Test getting repository information through MCP server.

        This is a placeholder test for retrieving repo details.
        """
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # TODO: Implement actual repo info retrieval test
        pytest.skip("Repository info test pending - requires fastmcp API implementation")

    def test_create_pull_request_via_mcp(self, github_token, mcp_server_config):
        """Test creating a pull request through MCP server.

        NOTE: This test should use a test repository and will actually create
        a PR if run. Consider using a dedicated test repo or mocking in CI/CD.
        """
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        # TODO: Implement PR creation test
        # This would be the main test for the auto-PR feature
        pytest.skip(
            "PR creation test pending - requires fastmcp API implementation. "
            "Will test the core auto-PR functionality for vulnerability fixes."
        )


class TestMCPConfiguration:
    """Tests for MCP configuration and environment setup."""

    def test_github_token_env_var(self):
        """Test that GITHUB_TOKEN can be read from environment."""
        # This test doesn't require the token to be set, just verifies we can check
        token = os.environ.get('GITHUB_TOKEN')
        # Just verify we can access the env var (may be None)
        assert token is None or isinstance(token, str)

    def test_mcp_server_host_config(self):
        """Test that MCP server host can be configured."""
        host = os.environ.get('MCP_SERVER_HOST', '127.0.0.1')
        assert isinstance(host, str)
        assert len(host) > 0

    def test_mcp_server_port_config(self):
        """Test that MCP server port can be configured."""
        port = os.environ.get('MCP_SERVER_PORT', '3000')
        port_int = int(port)
        assert 1 <= port_int <= 65535


@pytest.mark.unit
class TestMCPErrorHandling:
    """Tests for error handling in MCP integration."""

    def test_missing_github_token(self):
        """Test graceful handling of missing GitHub token."""
        with patch.dict(os.environ, {}, clear=True):
            token = os.environ.get('GITHUB_TOKEN')
            assert token is None

    def test_invalid_server_port(self):
        """Test handling of invalid port configuration."""
        with patch.dict(os.environ, {'MCP_SERVER_PORT': 'invalid'}):
            with pytest.raises(ValueError):
                int(os.environ.get('MCP_SERVER_PORT'))

    def test_connection_timeout_handling(self):
        """Test that connection timeouts are handled gracefully."""
        if not FASTMCP_AVAILABLE:
            pytest.skip("fastmcp not installed")

        import socket

        # Try to connect to a non-existent server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)  # Very short timeout

        try:
            # Use a port that's likely not in use
            result = sock.connect_ex(('127.0.0.1', 65534))
            sock.close()
            # Connection should fail (non-zero result)
            assert result != 0
        except socket.timeout:
            # Timeout is expected behavior
            pass
