"""
Test git MCP server operations in detail to see what's actually happening.
"""
import asyncio
import subprocess
import pytest


@pytest.mark.asyncio
async def test_git_operations():
    """Test actual git operations via MCP"""
    print("="*70)
    print("GIT MCP SERVER ISOLATED TEST")
    print("="*70)

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        repo_path = "C:/Users/anyth/MINE/dev/vulnerable"
        print(f"\nRepo: {repo_path}")

        # Check current git state
        print("\nCurrent branches (before):")
        result = subprocess.run(['git', 'branch', '-a'], cwd=repo_path, capture_output=True, text=True)
        print(result.stdout)

        server_params = StdioServerParameters(
            command="python",
            args=["-m", "mcp_server_git", "--repository", repo_path],
        )

        print("Connecting to git MCP server...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("OK Connected!\n")

                # List available tools
                tools = await session.list_tools()
                print(f"Available tools: {[t.name for t in tools.tools]}\n")

                # Test 1: Git status
                print("=" * 70)
                print("TEST 1: git_status")
                print("=" * 70)
                result = await session.call_tool("git_status", arguments={})
                print(f"Result: {result}")
                print()

                # Test 2: Create branch
                print("=" * 70)
                print("TEST 2: git_create_branch")
                print("=" * 70)
                branch_name = "test-mcp-branch-123"
                print(f"Creating branch: {branch_name}")
                result = await session.call_tool(
                    "git_create_branch",
                    arguments={
                        "branch_name": branch_name,
                        "base_branch": "main"
                    }
                )
                print(f"Result: {result}")
                print()

                # Test 3: List branches
                print("=" * 70)
                print("TEST 3: git_branch (list branches)")
                print("=" * 70)
                result = await session.call_tool("git_branch", arguments={})
                print(f"Result: {result}")
                print()

                # Test 4: Checkout branch
                print("=" * 70)
                print("TEST 4: git_checkout")
                print("=" * 70)
                print(f"Checking out: {branch_name}")
                result = await session.call_tool(
                    "git_checkout",
                    arguments={"branch": branch_name}
                )
                print(f"Result: {result}")
                print()

        # Check git state after operations
        print("\n" + "="*70)
        print("GIT STATE AFTER MCP OPERATIONS")
        print("="*70)
        result = subprocess.run(['git', 'branch', '-a'], cwd=repo_path, capture_output=True, text=True)
        print("Branches:")
        print(result.stdout)

        result = subprocess.run(['git', 'status', '--short'], cwd=repo_path, capture_output=True, text=True)
        print("Status:")
        print(result.stdout if result.stdout else "(clean)")

    except Exception as e:
        print(f"\nX Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_git_operations())
