"""
Check the schema/input requirements for git MCP server tools.
"""
import asyncio


async def check_tool_schemas():
    """Check what arguments each tool expects"""
    print("="*70)
    print("GIT MCP SERVER TOOL SCHEMAS")
    print("="*70)

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        repo_path = "C:/Users/anyth/MINE/dev/vulnerable"

        server_params = StdioServerParameters(
            command="python",
            args=["-m", "mcp_server_git", "--repository", repo_path],
        )

        print("\nConnecting...")
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                print("Connected!\n")

                # List tools with their schemas
                tools_result = await session.list_tools()

                for tool in tools_result.tools:
                    print(f"\n{'='*70}")
                    print(f"Tool: {tool.name}")
                    print(f"{'='*70}")
                    print(f"Description: {tool.description}")
                    print(f"\nInput Schema:")
                    if hasattr(tool, 'inputSchema'):
                        import json
                        print(json.dumps(tool.inputSchema, indent=2))
                    else:
                        print("(no schema available)")

    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(check_tool_schemas())
