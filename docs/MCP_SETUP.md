# MCP (Model Context Protocol) Setup Guide

This guide explains how to set up the MCP integration for automated GitHub Pull Request creation in SecureFix.

## Architecture Overview

SecureFix uses the Model Context Protocol (MCP) to integrate with GitHub:
- **fastmcp** - Python MCP client library (installed via pip)
- **github-mcp-server** - Node.js MCP server that handles GitHub API operations

## Prerequisites

### 1. Node.js and npm
The github-mcp-server requires Node.js 18+ and npm:

```bash
# Check if Node.js is installed
node --version  # Should be v18.0.0 or higher
npm --version
```

If not installed, download from [nodejs.org](https://nodejs.org/)

### 2. GitHub Personal Access Token
You'll need a GitHub token with appropriate permissions:

1. Go to GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Select scopes:
   - `repo` (Full control of private repositories)
   - `workflow` (Update GitHub Actions workflows - if needed)
4. Generate and copy the token
5. Store it securely (you won't be able to see it again)

## Installation

### Step 1: Install Python Dependencies

Install fastmcp along with other SecureFix dependencies:

```bash
# Install with MCP support
pip install -e ".[mcp]"

# Or install all optional dependencies
pip install -e ".[all]"
```

### Step 2: Install github-mcp-server

Install the github-mcp-server globally using npm:

```bash
npm install -g @modelcontextprotocol/server-github
```

Or install it locally in your project:

```bash
npm install @modelcontextprotocol/server-github
```

### Step 3: Configure Environment Variables

Create or update your `.env` file:

```bash
# GitHub Configuration
GITHUB_TOKEN=ghp_your_token_here
GITHUB_OWNER=your-username-or-org
GITHUB_REPO=your-repository-name

# MCP Server Configuration (optional)
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=3000
```

## Running the MCP Server

### Option 1: Start Manually

```bash
# If installed globally
github-mcp-server --token $GITHUB_TOKEN

# If installed locally
npx @modelcontextprotocol/server-github --token $GITHUB_TOKEN
```

### Option 2: Start as Background Process (Unix/Linux/Mac)

```bash
github-mcp-server --token $GITHUB_TOKEN &
```

### Option 3: Start as Background Process (Windows)

```powershell
Start-Process -NoNewWindow github-mcp-server -ArgumentList "--token $env:GITHUB_TOKEN"
```

## Verification

### Test MCP Connection

Run the integration test to verify the setup:

```bash
# Run MCP integration tests only
pytest -m requires_mcp

# Run with verbose output
pytest -m requires_mcp -v
```

### Manual Verification

Check if the server is running:

```bash
# Check if the process is running
ps aux | grep github-mcp-server  # Unix/Linux/Mac
tasklist | findstr github-mcp    # Windows

# Test server connectivity (if it exposes HTTP)
curl http://localhost:3000/health
```

## Usage in SecureFix

Once configured, SecureFix can automatically create PRs for high-confidence fixes:

```bash
# Scan for vulnerabilities and auto-create PRs
securefix scan ./my-project -o report.json
securefix fix report.json --auto-pr --severity high
```

## Troubleshooting

### Server Not Starting
- **Check Node.js version**: Ensure Node.js 18+ is installed
- **Check token validity**: Test your token with `gh auth status` (if GitHub CLI is installed)
- **Port conflicts**: Check if port 3000 is already in use

### Authentication Errors
- **Token permissions**: Ensure token has `repo` scope
- **Token expiration**: Personal access tokens can expire - check GitHub settings
- **Environment variables**: Verify `GITHUB_TOKEN` is properly set

### Connection Errors
- **Firewall**: Check if firewall is blocking localhost connections
- **Server not running**: Verify the github-mcp-server process is active
- **Wrong host/port**: Check `MCP_SERVER_HOST` and `MCP_SERVER_PORT` in `.env`

### Test Failures
```bash
# Skip MCP tests if server is not available
pytest -m "not requires_mcp"

# Run with verbose logging
pytest -m requires_mcp -vv --log-cli-level=DEBUG
```

## Security Considerations

1. **Never commit tokens**: Add `.env` to `.gitignore` (already done in SecureFix)
2. **Rotate tokens regularly**: GitHub recommends rotating PATs every 90 days
3. **Use fine-grained tokens**: Consider using GitHub's fine-grained personal access tokens for better security
4. **Minimal permissions**: Only grant the minimum required scopes

## References

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [fastmcp Python Client](https://github.com/jlowin/fastmcp)
- [GitHub MCP Server](https://github.com/modelcontextprotocol/servers)
- [GitHub Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token)
