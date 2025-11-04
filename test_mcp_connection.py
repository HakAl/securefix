"""
Simple test script to verify MCP server connections work.
Tests git and GitHub MCP servers independently.
"""
import asyncio
import os


async def test_git_server():
    """Test connection to git MCP server"""
    print("\n" + "="*70)
    print("TEST 1: Git MCP Server Connection")
    print("="*70)

    try:
        from fastmcp import Client

        # Test with a real repo
        repo_path = "C:/Users/anyth/MINE/dev/securefix"
        print(f"Testing with repo: {repo_path}")

        # Try simple command string
        command = f"python -m mcp_server_git --repository {repo_path}"
        print(f"Command: {command}")

        print("Connecting...")
        async with Client(command) as client:
            print("OK Connected successfully!")

            # Try git status
            print("\nTrying git_status...")
            result = await client.call_tool("git_status", arguments={})
            print(f"OK git_status worked!")
            print(f"  Result: {str(result)[:200]}...")

            return True

    except Exception as e:
        print(f"X Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_github_server():
    """Test connection to GitHub MCP server (Docker)"""
    print("\n" + "="*70)
    print("TEST 2: GitHub MCP Server Connection (Docker)")
    print("="*70)

    # Check if token is set
    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("X GITHUB_TOKEN not set. Skipping GitHub server test.")
        print("  Set it with: export GITHUB_TOKEN=ghp_...")
        return False

    try:
        from fastmcp import Client

        print(f"Using token: {github_token[:10]}...")

        # Try simple command string for Docker
        command = f'docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN={github_token} ghcr.io/github/github-mcp-server:latest'
        print(f"Command: docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN=*** ghcr.io/github/github-mcp-server:latest")

        print("Starting Docker container...")
        async with Client(command) as client:
            print("OK Connected successfully!")

            # Just verify connection works
            print("\nConnection verified!")

            return True

    except Exception as e:
        print(f"X Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    print("MCP SERVER CONNECTION TESTS")
    print("="*70)

    # Test 1: Git server
    git_ok = await test_git_server()

    # Test 2: GitHub server
    github_ok = await test_github_server()

    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Git MCP Server:    {'OK PASS' if git_ok else 'X FAIL'}")
    print(f"GitHub MCP Server: {'OK PASS' if github_ok else 'X FAIL'}")
    print("="*70)

    if git_ok and github_ok:
        print("\nOK All tests passed! MCP integration should work.")
    else:
        print("\nX Some tests failed. Fix these before trying full PR creation.")


if __name__ == "__main__":
    asyncio.run(main())
