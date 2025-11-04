"""
Check GitHub MCP server tool schemas.
"""
import asyncio
import os
import pytest


@pytest.mark.asyncio
async def test_check_github_tools():
    """Check GitHub MCP tools and their schemas"""
    print("="*70)
    print("GITHUB MCP SERVER TOOLS")
    print("="*70)

    github_token = os.getenv("GITHUB_TOKEN")
    if not github_token:
        print("X GITHUB_TOKEN not set")
        return

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        server_params = StdioServerParameters(
            command="docker",
            args=[
                "run", "-i", "--rm",
                "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={github_token}",
                "ghcr.io/github/github-mcp-server:latest"
            ],
        )

        print("\nConnecting...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("Connected!\n")

                # List all tools
                tools_result = await session.list_tools()
                tool_names = [t.name for t in tools_result.tools]
                print(f"All tools ({len(tool_names)}):")
                for name in sorted(tool_names):
                    print(f"  - {name}")

                # Focus on push/branch/PR tools
                print("\n" + "="*70)
                print("RELEVANT TOOL SCHEMAS")
                print("="*70)

                for tool in tools_result.tools:
                    if tool.name in ['push_files', 'create_branch', 'create_or_update_file', 'create_pull_request']:
                        print(f"\n{'='*70}")
                        print(f"Tool: {tool.name}")
                        print(f"{'='*70}")
                        print(f"Description: {tool.description}")
                        print(f"\nInput Schema:")
                        import json
                        print(json.dumps(tool.inputSchema, indent=2))

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_check_github_tools())
