"""
MCP client for GitHub operations using dual-server architecture.

Orchestrates local git operations (via git MCP server) and GitHub API operations
(via GitHub MCP server) to create pull requests.
"""
import base64
import os
from typing import Dict, Optional, Callable


async def create_pr_via_mcp(
    branch_name: str,
    commit_message: str,
    pr_title: str,
    pr_body: str,
    changed_files: Dict[str, str],
    repo_root: str,
    github_owner: str,
    github_repo: str,
    github_token: str,
    git_server_command: str = "python -m mcp_server_git",
    github_server_transport: str = "docker",
    github_server_docker_image: str = "ghcr.io/github/github-mcp-server:latest",
    github_server_stdio_command: Optional[str] = None,
    base_branch: str = "main",
    output: Optional[Callable[[str], None]] = None
) -> dict:
    """
    Execute dual MCP server operations to create a GitHub PR.

    Uses two MCP servers:
    1. Git server (Python) - Local git operations (branch, commit)
    2. GitHub server (Docker/stdio) - GitHub API operations (push, PR)

    This function is framework-agnostic and uses callbacks for output.

    Args:
        branch_name: Name for the new branch
        commit_message: Commit message for changes
        pr_title: Pull request title
        pr_body: Pull request body/description
        changed_files: Dict mapping relative file paths to updated content
        repo_root: Repository root directory path
        github_owner: GitHub repository owner
        github_repo: GitHub repository name
        github_token: GitHub personal access token
        git_server_command: Command to start git MCP server
        github_server_transport: "docker" or "stdio"
        github_server_docker_image: Docker image for GitHub server
        github_server_stdio_command: Command for stdio GitHub server
        base_branch: Base branch to create PR against (default: "main")
        output: Optional callback for user messages

    Returns:
        dict with 'success', 'pr_url', 'pr_number', and optionally 'error'
    """
    output = output or (lambda x: None)

    try:
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
    except ImportError:
        return {
            'success': False,
            'error': 'mcp library not installed. Install with: pip install "securefix[mcp]"'
        }

    output("\n" + "=" * 70)
    output("DUAL MCP SERVER PR CREATION")
    output("=" * 70)

    try:
        # ============================================================
        # PHASE 1: Local Git Operations (via git MCP server)
        # ============================================================
        output(f"\n[1/2] LOCAL GIT OPERATIONS")
        output(f"  → Connecting to git MCP server...")

        # Convert Windows path to forward slashes for consistency
        repo_path = repo_root.replace('\\', '/')
        output(f"    Command: {git_server_command} --repository {repo_path}")

        # Parse git_server_command (e.g., "python -m mcp_server_git")
        git_cmd_parts = git_server_command.split()
        git_params = StdioServerParameters(
            command=git_cmd_parts[0],  # "python"
            args=git_cmd_parts[1:] + ["--repository", repo_path],  # ["-m", "mcp_server_git", "--repository", path]
        )

        async with stdio_client(git_params) as (read, write):
            async with ClientSession(read, write) as git_session:
                await git_session.initialize()
                output("  ✓ Connected to git server")

                # Step 1: Create branch from base
                output(f"\n  → Creating branch '{branch_name}' from '{base_branch}'...")
                try:
                    result = await git_session.call_tool(
                        "git_create_branch",
                        arguments={
                            "repo_path": repo_path,
                            "branch_name": branch_name,
                            "base_branch": base_branch
                        }
                    )
                    if result.isError:
                        output(f"  ! Branch creation failed: {result.content[0].text}")
                    else:
                        output(f"  ✓ Branch '{branch_name}' created")
                except Exception as e:
                    output(f"  ! Branch creation failed: {str(e)}")
                    # Branch might already exist, continue anyway

                # Step 2: Checkout the branch
                output(f"  → Checking out branch '{branch_name}'...")
                result = await git_session.call_tool(
                    "git_checkout",
                    arguments={
                        "repo_path": repo_path,
                        "branch_name": branch_name
                    }
                )
                if result.isError:
                    raise Exception(f"Checkout failed: {result.content[0].text}")
                output(f"  ✓ Checked out '{branch_name}'")

                # Step 3: Write files and stage them
                output(f"\n  → Staging {len(changed_files)} file(s)...")
                for i, (rel_path, content) in enumerate(changed_files.items(), 1):
                    output(f"    [{i}/{len(changed_files)}] {rel_path}...")

                    # Write file content
                    full_path = os.path.join(repo_root, rel_path)
                    os.makedirs(os.path.dirname(full_path), exist_ok=True)
                    with open(full_path, 'w', encoding='utf-8') as f:
                        f.write(content)

                    # Stage the file
                    result = await git_session.call_tool(
                        "git_add",
                        arguments={
                            "repo_path": repo_path,
                            "files": [rel_path]
                        }
                    )
                    if result.isError:
                        output(f" X Error: {result.content[0].text}")
                    else:
                        output(" ✓")

                output(f"  ✓ All files staged")

                # Step 4: Commit changes
                output(f"\n  → Committing changes...")
                result = await git_session.call_tool(
                    "git_commit",
                    arguments={
                        "repo_path": repo_path,
                        "message": commit_message
                    }
                )
                if result.isError:
                    raise Exception(f"Commit failed: {result.content[0].text}")
                output(f"  ✓ Committed: {commit_message}")

        output(f"\n  ✓ Local git operations complete")

        # ============================================================
        # PHASE 2: GitHub API Operations (via GitHub MCP server)
        # ============================================================
        output(f"\n[2/2] GITHUB API OPERATIONS")

        # Determine GitHub server connection
        if github_server_transport == "docker":
            output(f"  → Starting GitHub MCP server (Docker)...")
            output(f"    Image: {github_server_docker_image}")

            # Use Docker with environment variable for token
            github_params = StdioServerParameters(
                command="docker",
                args=[
                    "run", "-i", "--rm",
                    "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={github_token}",
                    github_server_docker_image
                ],
            )

        elif github_server_transport == "stdio":
            if not github_server_stdio_command:
                return {
                    'success': False,
                    'error': 'GitHub stdio command not configured'
                }
            output(f"  → Connecting to GitHub MCP server via stdio...")
            output(f"    Command: {github_server_stdio_command}")

            # Parse stdio command
            github_cmd_parts = github_server_stdio_command.split()
            github_params = StdioServerParameters(
                command=github_cmd_parts[0],
                args=github_cmd_parts[1:],
                env={"GITHUB_PERSONAL_ACCESS_TOKEN": github_token}
            )
        else:
            return {
                'success': False,
                'error': f'Invalid GitHub transport: {github_server_transport}'
            }

        async with stdio_client(github_params) as (read, write):
            async with ClientSession(read, write) as github_session:
                await github_session.initialize()
                output("  ✓ Connected to GitHub server")

                # Step 5: Create branch on GitHub
                output(f"\n  → Creating branch '{branch_name}' on GitHub...")
                result = await github_session.call_tool(
                    "create_branch",
                    arguments={
                        "owner": github_owner,
                        "repo": github_repo,
                        "branch": branch_name,
                        "from_branch": base_branch
                    }
                )
                if result.isError:
                    output(f"  ! Branch creation failed: {result.content[0].text}")
                    # Branch might already exist, continue anyway
                else:
                    output(f"  ✓ Branch created on GitHub")

                # Step 6: Push files to the branch
                output(f"\n  → Pushing {len(changed_files)} file(s) to GitHub...")
                # Convert changed_files dict to array format expected by push_files
                files_array = [
                    {"path": path, "content": content}
                    for path, content in changed_files.items()
                ]

                result = await github_session.call_tool(
                    "push_files",
                    arguments={
                        "owner": github_owner,
                        "repo": github_repo,
                        "branch": branch_name,
                        "files": files_array,
                        "message": commit_message
                    }
                )
                if result.isError:
                    raise Exception(f"Push files failed: {result.content[0].text}")
                output(f"  ✓ Files pushed to GitHub")

                # Step 7: Create pull request
                output(f"\n  → Creating pull request...")
                result = await github_session.call_tool(
                    "create_pull_request",
                    arguments={
                        "owner": github_owner,
                        "repo": github_repo,
                        "title": pr_title,
                        "body": pr_body,
                        "head": branch_name,
                        "base": base_branch
                    }
                )

                if result.isError:
                    raise Exception(f"PR creation failed: {result.content[0].text}")

                # Extract PR details from result content
                # The result should contain the PR URL and number
                pr_text = result.content[0].text if result.content else ""

                # Parse URL and number from response
                import re
                pr_url_match = re.search(r'https://github\.com/[^/]+/[^/]+/pull/\d+', pr_text)
                pr_number_match = re.search(r'#(\d+)', pr_text)

                pr_url = pr_url_match.group(0) if pr_url_match else ""
                pr_number = int(pr_number_match.group(1)) if pr_number_match else 0

                output(f"  ✓ Pull request created!")
                output(f"\n{'=' * 70}")
                output("✓ SUCCESS")
                output("=" * 70)
                output(f"PR #{pr_number}: {pr_url}")
                output("=" * 70)

                return {
                    'success': True,
                    'pr_url': pr_url,
                    'pr_number': pr_number,
                    'branch_name': branch_name
                }

    except Exception as e:
        import traceback
        error_details = f'Failed to create PR via dual MCP: {str(e)}'

        # Provide specific troubleshooting
        if 'ConnectionError' in str(type(e)) or 'connect' in str(e).lower():
            error_details += '\n  → Check git MCP server is installed: pip install mcp-server-git'
            error_details += '\n  → Check Docker is running: docker ps'
            error_details += f'\n  → Pull GitHub server: docker pull {github_server_docker_image}'
        elif 'authentication' in str(e).lower() or 'token' in str(e).lower():
            error_details += '\n  → Check GITHUB_TOKEN has repo permissions'
        elif 'branch' in str(e).lower():
            error_details += '\n  → Branch may already exist'
        elif 'permission' in str(e).lower() or 'forbidden' in str(e).lower():
            error_details += '\n  → Check repository permissions'
        elif 'docker' in str(e).lower():
            error_details += '\n  → Ensure Docker is running: docker ps'

        return {
            'success': False,
            'error': error_details,
            'debug': traceback.format_exc()
        }
