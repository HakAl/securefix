"""
Unit tests for securefix.mcp.mcp_client module.
Tests the create_pr_via_mcp function with mocked MCP sessions.
"""
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open, call
from securefix.mcp.mcp_client import create_pr_via_mcp


class MockToolResult:
    """Mock MCP tool result"""
    def __init__(self, is_error=False, text="Success"):
        self.isError = is_error
        self.content = [MagicMock(text=text)]


@pytest.mark.asyncio
async def test_import_error_when_mcp_not_installed():
    """Test handling when mcp library is not installed"""
    # Create a custom ImportError that will be raised when trying to import mcp
    def mock_import(name, *args, **kwargs):
        if name in ['mcp', 'mcp.client', 'mcp.client.stdio']:
            raise ImportError(f"No module named '{name}'")
        return __import__(name, *args, **kwargs)

    with patch('builtins.__import__', side_effect=mock_import):
        result = await create_pr_via_mcp(
            branch_name="test-branch",
            commit_message="Test commit",
            pr_title="Test PR",
            pr_body="Test body",
            changed_files={"test.py": "print('hello')"},
            repo_root="/tmp/test",
            github_owner="owner",
            github_repo="repo",
            github_token="token123"
        )

        assert result['success'] is False
        assert 'mcp library not installed' in result['error']
        assert 'pip install "securefix[mcp]"' in result['error']


@pytest.mark.asyncio
async def test_successful_pr_creation_docker():
    """Test successful PR creation using Docker transport"""
    # Mock the MCP sessions
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    # Mock git operations
    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False, text="Branch created"),  # create_branch
        MockToolResult(is_error=False, text="Checked out"),  # checkout
        MockToolResult(is_error=False, text="File staged"),  # add file
        MockToolResult(is_error=False, text="Committed"),  # commit
    ])

    # Mock GitHub operations
    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False, text="Branch created on GitHub"),  # create_branch
        MockToolResult(is_error=False, text="Files pushed"),  # push_files
        MockToolResult(is_error=False, text="Pull request created: https://github.com/owner/repo/pull/42 (#42)"),  # create_pull_request
    ])

    # Mock file writing
    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        # Setup context managers
        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="feature-test",
            commit_message="Add test feature",
            pr_title="Test PR Title",
            pr_body="Test PR Body",
            changed_files={"src/test.py": "print('test')"},
            repo_root="/tmp/repo",
            github_owner="testowner",
            github_repo="testrepo",
            github_token="ghp_testtoken123",
            github_server_transport="docker",
            base_branch="main"
        )

        # Verify success
        assert result['success'] is True
        assert result['pr_url'] == 'https://github.com/owner/repo/pull/42'
        assert result['pr_number'] == 42
        assert result['branch_name'] == 'feature-test'

        # Verify git operations were called
        assert mock_git_session.call_tool.call_count == 4

        # Verify GitHub operations were called
        assert mock_github_session.call_tool.call_count == 3


@pytest.mark.asyncio
async def test_successful_pr_creation_stdio():
    """Test successful PR creation using stdio transport"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=False),  # push_files
        MockToolResult(is_error=False, text="PR #99: https://github.com/owner/repo/pull/99"),  # create_pull_request
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test-stdio",
            commit_message="Stdio test",
            pr_title="Stdio PR",
            pr_body="Body",
            changed_files={"test.py": "code"},
            repo_root="/tmp/repo",
            github_owner="owner",
            github_repo="repo",
            github_token="token",
            github_server_transport="stdio",
            github_server_stdio_command="node github-server.js"
        )

        assert result['success'] is True
        assert result['pr_number'] == 99


@pytest.mark.asyncio
async def test_stdio_transport_without_command():
    """Test error when stdio transport is used without command"""
    # Mock git session since it runs first
    mock_git_session = AsyncMock()
    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.return_value = mock_git_session

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={},
            repo_root="/tmp",
            github_owner="owner",
            github_repo="repo",
            github_token="token",
            github_server_transport="stdio",
            github_server_stdio_command=None  # Missing command
        )

        assert result['success'] is False
        assert 'GitHub stdio command not configured' in result['error']


@pytest.mark.asyncio
async def test_invalid_transport():
    """Test error with invalid transport type"""
    # Mock git session since it runs first
    mock_git_session = AsyncMock()
    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.return_value = mock_git_session

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={},
            repo_root="/tmp",
            github_owner="owner",
            github_repo="repo",
            github_token="token",
            github_server_transport="invalid_transport"
        )

        assert result['success'] is False
        assert 'Invalid GitHub transport: invalid_transport' in result['error']


@pytest.mark.asyncio
async def test_branch_creation_failure_continues():
    """Test that branch creation failure doesn't stop execution"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=True, text="Branch already exists"),  # create_branch fails
        MockToolResult(is_error=False),  # checkout succeeds
        MockToolResult(is_error=False),  # add
        MockToolResult(is_error=False),  # commit
    ])

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #1: https://github.com/o/r/pull/1"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="existing-branch",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"file.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        # Should still succeed despite branch creation failure
        assert result['success'] is True


@pytest.mark.asyncio
async def test_checkout_failure():
    """Test that checkout failure raises exception"""
    mock_git_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=True, text="Checkout failed"),  # checkout fails
    ])

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class:

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.return_value = mock_git_session

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is False
        assert 'Checkout failed' in result['error']


@pytest.mark.asyncio
async def test_commit_failure():
    """Test that commit failure raises exception"""
    mock_git_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=False),  # checkout
        MockToolResult(is_error=False),  # add
        MockToolResult(is_error=True, text="Nothing to commit"),  # commit fails
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.return_value = mock_git_session

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"file.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is False
        assert 'Nothing to commit' in result['error']


@pytest.mark.asyncio
async def test_push_files_failure():
    """Test that push_files failure raises exception"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=True, text="Push rejected"),  # push_files fails
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"file.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is False
        assert 'Push rejected' in result['error']


@pytest.mark.asyncio
async def test_pr_creation_failure():
    """Test that PR creation failure raises exception"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=False),  # push_files
        MockToolResult(is_error=True, text="PR already exists"),  # create_pull_request fails
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"file.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is False
        assert 'PR already exists' in result['error']


@pytest.mark.asyncio
async def test_github_branch_creation_failure_continues():
    """Test that GitHub branch creation failure doesn't stop execution"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=True, text="Branch exists on GitHub"),  # create_branch fails
        MockToolResult(is_error=False),  # push_files succeeds
        MockToolResult(is_error=False, text="PR #5: https://github.com/o/r/pull/5"),  # PR creation succeeds
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"file.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        # Should succeed despite GitHub branch creation failure
        assert result['success'] is True
        assert result['pr_number'] == 5


@pytest.mark.asyncio
async def test_multiple_files_staging():
    """Test staging multiple files"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    # Mock responses for: create_branch, checkout, add file1, add file2, add file3, commit
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=False),  # checkout
        MockToolResult(is_error=False),  # add file1
        MockToolResult(is_error=False),  # add file2
        MockToolResult(is_error=False),  # add file3
        MockToolResult(is_error=False),  # commit
    ])

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #10: https://github.com/o/r/pull/10"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="multi-file",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={
                "src/file1.py": "code1",
                "src/file2.py": "code2",
                "tests/test_file.py": "test_code"
            },
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is True
        # Verify 3 add operations were called (one per file)
        add_calls = [c for c in mock_git_session.call_tool.call_args_list if c[0][0] == 'git_add']
        assert len(add_calls) == 3


@pytest.mark.asyncio
async def test_file_staging_with_error():
    """Test that file staging error is logged but doesn't stop execution"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),  # create_branch
        MockToolResult(is_error=False),  # checkout
        MockToolResult(is_error=True, text="File not found"),  # add file1 fails
        MockToolResult(is_error=False),  # add file2 succeeds
        MockToolResult(is_error=False),  # commit
    ])

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #7: https://github.com/o/r/pull/7"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={
                "bad_file.py": "code1",
                "good_file.py": "code2"
            },
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        # Should still succeed despite one file staging failure
        assert result['success'] is True


@pytest.mark.asyncio
async def test_windows_path_conversion():
    """Test that Windows paths are converted to forward slashes"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #1: https://github.com/o/r/pull/1"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"test.py": "code"},
            repo_root="C:\\Users\\test\\repo",  # Windows path
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is True

        # Verify the path was converted to forward slashes
        git_create_call = mock_git_session.call_tool.call_args_list[0]
        repo_path_arg = git_create_call[1]['arguments']['repo_path']
        assert '\\' not in repo_path_arg  # No backslashes
        assert repo_path_arg == "C:/Users/test/repo"


@pytest.mark.asyncio
async def test_custom_output_callback():
    """Test that custom output callback is used"""
    output_messages = []

    def custom_output(msg):
        output_messages.append(msg)

    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #1: https://github.com/o/r/pull/1"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"test.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token",
            output=custom_output
        )

        assert result['success'] is True
        # Verify output callback was called
        assert len(output_messages) > 0
        assert any("DUAL MCP SERVER" in msg for msg in output_messages)


@pytest.mark.asyncio
async def test_error_troubleshooting_messages():
    """Test that appropriate troubleshooting messages are added to errors"""
    test_cases = [
        ("ConnectionError", "Check git MCP server is installed"),
        ("authentication failed", "Check GITHUB_TOKEN has repo permissions"),
        ("branch error", "Branch may already exist"),
        ("permission denied", "Check repository permissions"),
        ("docker error", "Ensure Docker is running"),
    ]

    for error_type, expected_message in test_cases:
        mock_git_session = AsyncMock()
        mock_git_session.initialize = AsyncMock(side_effect=Exception(error_type))

        with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
             patch('mcp.ClientSession') as mock_session_class:

            mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
            mock_session_class.return_value.__aenter__.return_value = mock_git_session

            result = await create_pr_via_mcp(
                branch_name="test",
                commit_message="test",
                pr_title="test",
                pr_body="test",
                changed_files={},
                repo_root="/tmp/repo",
                github_owner="o",
                github_repo="r",
                github_token="token"
            )

            assert result['success'] is False
            assert expected_message.lower() in result['error'].lower()
            assert 'debug' in result  # Verify traceback is included


@pytest.mark.asyncio
async def test_pr_url_parsing_variations():
    """Test parsing PR URLs with # number format"""
    # Test with format that matches the regex: URL + #number
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    # PR response with both URL and #number format (which the regex expects)
    pr_text = "Pull request #456 created at https://github.com/o/r/pull/456"

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text=pr_text),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="test",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"test.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result['success'] is True
        assert result['pr_number'] == 456
        assert result['pr_url'] == "https://github.com/o/r/pull/456"

    # Test with URL but no #number - should still extract URL but number will be 0
    mock_git_session2 = AsyncMock()
    mock_github_session2 = AsyncMock()

    mock_git_session2.initialize = AsyncMock()
    mock_git_session2.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    pr_text2 = "Created PR at https://github.com/owner/repo/pull/999"

    mock_github_session2.initialize = AsyncMock()
    mock_github_session2.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text=pr_text2),
    ])

    with patch('mcp.client.stdio.stdio_client') as mock_stdio2, \
         patch('mcp.ClientSession') as mock_session_class2, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio2.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class2.return_value.__aenter__.side_effect = [mock_git_session2, mock_github_session2]

        result2 = await create_pr_via_mcp(
            branch_name="test2",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"test.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token"
        )

        assert result2['success'] is True
        assert result2['pr_url'] == "https://github.com/owner/repo/pull/999"
        # Without #number format, pr_number will be 0
        assert result2['pr_number'] == 0


@pytest.mark.asyncio
async def test_custom_base_branch():
    """Test using custom base branch instead of main"""
    mock_git_session = AsyncMock()
    mock_github_session = AsyncMock()

    mock_git_session.initialize = AsyncMock()
    mock_git_session.call_tool = AsyncMock(return_value=MockToolResult(is_error=False))

    mock_github_session.initialize = AsyncMock()
    mock_github_session.call_tool = AsyncMock(side_effect=[
        MockToolResult(is_error=False),
        MockToolResult(is_error=False),
        MockToolResult(is_error=False, text="PR #1: https://github.com/o/r/pull/1"),
    ])

    mock_file = mock_open()

    with patch('mcp.client.stdio.stdio_client') as mock_stdio, \
         patch('mcp.ClientSession') as mock_session_class, \
         patch('builtins.open', mock_file), \
         patch('os.makedirs'):

        mock_stdio.return_value.__aenter__.return_value = (MagicMock(), MagicMock())
        mock_session_class.return_value.__aenter__.side_effect = [mock_git_session, mock_github_session]

        result = await create_pr_via_mcp(
            branch_name="feature",
            commit_message="test",
            pr_title="test",
            pr_body="test",
            changed_files={"test.py": "code"},
            repo_root="/tmp/repo",
            github_owner="o",
            github_repo="r",
            github_token="token",
            base_branch="develop"  # Custom base branch
        )

        assert result['success'] is True

        # Verify base_branch was passed to git_create_branch
        git_create_call = mock_git_session.call_tool.call_args_list[0]
        assert git_create_call[1]['arguments']['base_branch'] == 'develop'

        # Verify base_branch was passed to create_pull_request
        pr_create_call = mock_github_session.call_tool.call_args_list[2]
        assert pr_create_call[1]['arguments']['base'] == 'develop'
