"""
Simple MCP client test using the mcp library directly.
"""
import asyncio
import os


async def test_git_server():
    """Test git MCP server connection"""
    print("\n" + "="*70)
    print("TEST 1: Git MCP Server")
    print("="*70)

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        repo_path = "C:/Users/anyth/MINE/dev/securefix"
        print(f"Repo: {repo_path}")

        server_params = StdioServerParameters(
            command="python",
            args=["-m", "mcp_server_git", "--repository", repo_path],
        )

        print("Connecting...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("OK Connected!")

                # List available tools
                tools = await session.list_tools()
                print(f"\nAvailable tools: {[t.name for t in tools.tools]}")

                # Try git_status
                print("\nCalling git_status...")
                result = await session.call_tool("git_status", arguments={})
                print(f"OK Result: {str(result)[:200]}...")

                return True

    except Exception as e:
        print(f"X Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_github_server():
    """Test GitHub MCP server (Docker)"""
    print("\n" + "="*70)
    print("TEST 2: GitHub MCP Server (Docker)")
    print("="*70)

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("X GITHUB_TOKEN not set")
        return False

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        print(f"Token: {github_token[:10]}...")

        server_params = StdioServerParameters(
            command="docker",
            args=[
                "run", "-i", "--rm",
                "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={github_token}",
                "ghcr.io/github/github-mcp-server:latest"
            ],
        )

        print("Starting Docker container...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("OK Connected!")

                # List available tools
                tools = await session.list_tools()
                print(f"\nAvailable tools: {[t.name for t in tools.tools]}")

                return True

    except Exception as e:
        print(f"X Failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    print("MCP CLIENT TESTS")

    git_ok = await test_git_server()
    github_ok = await test_github_server()

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Git MCP:    {'OK' if git_ok else 'FAIL'}")
    print(f"GitHub MCP: {'OK' if github_ok else 'FAIL'}")


if __name__ == "__main__":
    asyncio.run(main())
