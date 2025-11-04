"""
Test that git MCP operations now work correctly with repo_path argument.
"""
import asyncio
import subprocess


async def test_git_fixed():
    """Test git operations with proper repo_path"""
    print("="*70)
    print("TEST: Git MCP with repo_path argument")
    print("="*70)

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        repo_path = "C:/Users/anyth/MINE/dev/vulnerable"
        print(f"\nRepo: {repo_path}")

        # Check initial state
        print("\nBranches BEFORE:")
        result = subprocess.run(['git', 'branch'], cwd=repo_path, capture_output=True, text=True)
        print(result.stdout)

        server_params = StdioServerParameters(
            command="python",
            args=["-m", "mcp_server_git", "--repository", repo_path],
        )

        print("Connecting...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("OK Connected!\n")

                # Test: Create branch
                branch_name = "test-branch-with-repo-path"
                print(f"Creating branch: {branch_name}")
                result = await session.call_tool(
                    "git_create_branch",
                    arguments={
                        "repo_path": repo_path,
                        "branch_name": branch_name,
                        "base_branch": "main"
                    }
                )

                if result.isError:
                    print(f"X Error: {result.content[0].text}")
                else:
                    print(f"OK Success: {result.content[0].text if result.content else 'Branch created'}")

                # Test: Checkout branch
                print(f"\nChecking out: {branch_name}")
                result = await session.call_tool(
                    "git_checkout",
                    arguments={
                        "repo_path": repo_path,
                        "branch_name": branch_name
                    }
                )

                if result.isError:
                    print(f"X Error: {result.content[0].text}")
                else:
                    print(f"OK Success: {result.content[0].text if result.content else 'Checked out'}")

        # Check final state
        print("\nBranches AFTER:")
        result = subprocess.run(['git', 'branch'], cwd=repo_path, capture_output=True, text=True)
        print(result.stdout)

        # Check current branch
        result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], cwd=repo_path, capture_output=True, text=True)
        print(f"Current branch: {result.stdout.strip()}")

        # Clean up
        print(f"\nCleaning up - switching back to main...")
        subprocess.run(['git', 'checkout', 'main'], cwd=repo_path, capture_output=True)
        print(f"Deleting test branch...")
        subprocess.run(['git', 'branch', '-D', branch_name], cwd=repo_path, capture_output=True)

        print("\nOK Test complete!")

    except Exception as e:
        print(f"\nX Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_git_fixed())
