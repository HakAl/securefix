"""
MCP client for GitHub operations using dual-server architecture.

Orchestrates local git operations (via git MCP server) and GitHub API operations
(via GitHub MCP server) to create pull requests.
"""
import base64
import subprocess
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
        from fastmcp import Client
    except ImportError:
        return {
            'success': False,
            'error': 'fastmcp not installed. Install with: pip install "securefix[mcp]"'
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
        output(f"    Command: {git_server_command} --repository {repo_root}")

        git_command = f"{git_server_command} --repository {repo_root}"

        async with Client(git_command) as git_client:
            output("  ✓ Connected to git server")

            # Step 1: Create branch from base
            output(f"\n  → Creating branch '{branch_name}' from '{base_branch}'...")
            try:
                await git_client.call_tool(
                    "git_create_branch",
                    arguments={
                        "branch_name": branch_name,
                        "base_branch": base_branch
                    }
                )
                output(f"  ✓ Branch '{branch_name}' created")
            except Exception as e:
                output(f"  ! Branch creation failed: {str(e)}")
                # Branch might already exist, continue anyway

            # Step 2: Checkout the branch
            output(f"  → Checking out branch '{branch_name}'...")
            await git_client.call_tool(
                "git_checkout",
                arguments={"branch": branch_name}
            )
            output(f"  ✓ Checked out '{branch_name}'")

            # Step 3: Write files and stage them
            output(f"\n  → Staging {len(changed_files)} file(s)...")
            for i, (rel_path, content) in enumerate(changed_files.items(), 1):
                output(f"    [{i}/{len(changed_files)}] {rel_path}...")

                # Write file content (git server handles file I/O)
                import os
                full_path = os.path.join(repo_root, rel_path)
                os.makedirs(os.path.dirname(full_path), exist_ok=True)
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                # Stage the file
                await git_client.call_tool(
                    "git_add",
                    arguments={"files": [rel_path]}
                )
                output(" ✓")

            output(f"  ✓ All files staged")

            # Step 4: Commit changes
            output(f"\n  → Committing changes...")
            commit_result = await git_client.call_tool(
                "git_commit",
                arguments={"message": commit_message}
            )
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
            github_command = [
                "docker", "run", "-i", "--rm",
                "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={github_token}",
                github_server_docker_image
            ]
            # fastmcp expects command as string
            github_connection = " ".join(github_command)

        elif github_server_transport == "stdio":
            if not github_server_stdio_command:
                return {
                    'success': False,
                    'error': 'GitHub stdio command not configured'
                }
            output(f"  → Connecting to GitHub MCP server via stdio...")
            output(f"    Command: {github_server_stdio_command}")
            github_connection = github_server_stdio_command
        else:
            return {
                'success': False,
                'error': f'Invalid GitHub transport: {github_server_transport}'
            }

        async with Client(github_connection) as github_client:
            output("  ✓ Connected to GitHub server")

            # Step 5: Push branch to GitHub
            output(f"\n  → Pushing branch '{branch_name}' to GitHub...")
            try:
                await github_client.call_tool(
                    "push_branch",
                    arguments={
                        "owner": github_owner,
                        "repo": github_repo,
                        "branch": branch_name
                    }
                )
                output(f"  ✓ Branch pushed to remote")
            except Exception as e:
                # If push fails, try create_branch (GitHub server may handle differently)
                output(f"  ! Push failed, trying create_branch: {str(e)}")
                await github_client.call_tool(
                    "create_branch",
                    arguments={
                        "owner": github_owner,
                        "repo": github_repo,
                        "branch": branch_name,
                        "from_branch": base_branch
                    }
                )
                output(f"  ✓ Branch created on GitHub")

            # Step 6: Create pull request
            output(f"\n  → Creating pull request...")
            pr_result = await github_client.call_tool(
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

            # Extract PR details
            pr_url = pr_result.get('html_url', '')
            pr_number = pr_result.get('number', 0)

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

    except ConnectionError as e:
        error_msg = f'Could not connect to MCP servers: {str(e)}'
        todo_steps = [
            'Ensure git MCP server is installed: pip install mcp-server-git',
            'Check Docker is running: docker ps',
            f'Pull GitHub server: docker pull {github_server_docker_image}',
            'Verify GITHUB_TOKEN is set with repo permissions',
        ]
        return {
            'success': False,
            'error': error_msg,
            'todo': todo_steps
        }
    except Exception as e:
        import traceback
        error_details = f'Failed to create PR via dual MCP: {str(e)}'

        # Provide specific troubleshooting
        if 'authentication' in str(e).lower() or 'token' in str(e).lower():
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
