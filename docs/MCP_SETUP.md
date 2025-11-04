# MCP Setup Guide for SecureFix

## Architecture Overview

SecureFix uses a **dual MCP server architecture** for extensible platform integration.

See full documentation at: https://github.com/modelcontextprotocol/servers

## Quick Start

### 1. Git Server (Python)
```bash
cd /c/Users/anyth/MINE/dev/mcp-servers/src/git
pip install -e .
python -m mcp_server_git --repository /path/to/repo
```

### 2. GitHub Server (Docker)
```bash
docker pull ghcr.io/github/github-mcp-server
docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN=$GITHUB_TOKEN ghcr.io/github/github-mcp-server
```

### 3. Configure SecureFix
Add to `.env`:
```
GITHUB_TOKEN=ghp_your_token
GITHUB_OWNER=your_username
GITHUB_REPO=your_repo
```

## Status

- ✅ Git MCP server installed
- ✅ GitHub MCP server (Docker) ready
- ✅ SecureFix client integration complete
- ⏳ End-to-end testing

## Integration Details

### Dual-Server Orchestration

SecureFix now orchestrates both MCP servers automatically:

**Phase 1: Local Git Operations (git MCP server)**
1. Create branch from base branch
2. Checkout new branch
3. Write and stage fixed files
4. Commit changes locally

**Phase 2: GitHub API Operations (GitHub MCP server via Docker)**
5. Push branch to GitHub remote
6. Create pull request with fixes

### Configuration

All settings are in `securefix/remediation/config.py` via environment variables:

```bash
# Required
GITHUB_TOKEN=ghp_your_token          # GitHub PAT with repo permissions
GITHUB_OWNER=your_username           # Repository owner
GITHUB_REPO=your_repo                # Repository name

# Optional
GITHUB_BASE_BRANCH=main              # Default: "main"
GIT_MCP_SERVER_COMMAND="python -m mcp_server_git"  # Git server command
GITHUB_MCP_TRANSPORT=docker          # "docker" or "stdio"
GITHUB_MCP_DOCKER_IMAGE=ghcr.io/github/github-mcp-server:latest
```

### Usage

Once configured, PR creation is automatic:

```bash
securefix scan vulnerable/ -o report.json
securefix fix report.json --create-pr
```

The tool will:
- Auto-detect repository root
- Generate branch name and PR content
- Orchestrate both MCP servers
- Create PR on GitHub

## Testing

To test the integration:

```bash
# 1. Ensure both servers are available
python -m mcp_server_git --help
docker pull ghcr.io/github/github-mcp-server:latest

# 2. Configure environment
export GITHUB_TOKEN=ghp_...
export GITHUB_OWNER=your_username
export GITHUB_REPO=your_repo

# 3. Run SecureFix with PR creation
securefix scan test/ -o report.json
securefix fix report.json --create-pr
```

