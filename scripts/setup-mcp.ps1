# Setup MCP Server for Claude Code
# Run this in PowerShell from the plxvault directory

$claudeDir = "$env:USERPROFILE\.claude"
$settingsFile = "$claudeDir\mcp_settings.json"

# Create .claude directory if it doesn't exist
if (-not (Test-Path $claudeDir)) {
    New-Item -ItemType Directory -Path $claudeDir -Force
    Write-Host "Created $claudeDir"
}

# Get the current directory (should be plxvault)
$plxvaultPath = (Get-Location).Path -replace '\\', '\\\\'

# Create MCP settings
$settings = @{
    mcpServers = @{
        ejbca = @{
            command = "python"
            args = @("$plxvaultPath\\mcp-pki-server\\ejbca_server.py")
            env = @{
                EJBCA_URL = "https://localhost:8443/ejbca"
                EJBCA_CERT = ""
                EJBCA_KEY = ""
            }
        }
    }
} | ConvertTo-Json -Depth 4

# Write settings file
$settings | Out-File -FilePath $settingsFile -Encoding utf8
Write-Host "MCP settings written to: $settingsFile"
Write-Host ""
Write-Host "Restart Claude Code to load the EJBCA MCP server."
Write-Host ""
Write-Host "Test with: 'Check EJBCA health' or 'List all CAs'"
