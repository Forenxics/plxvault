# PlxVault Windows Build Script
# Run from repository root in PowerShell

$ErrorActionPreference = "Stop"

Write-Host "Building PlxVault for Windows..." -ForegroundColor Cyan

# Check prerequisites
if (-not (Get-Command rustc -ErrorAction SilentlyContinue)) {
    Write-Host "Rust not found. Install from https://rustup.rs" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "Python not found. Install Python 3.11+" -ForegroundColor Red
    exit 1
}

# Create virtual environment if needed
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv .venv
}

# Activate venv
. .venv\Scripts\Activate.ps1

# Install maturin
Write-Host "Installing maturin..." -ForegroundColor Yellow
pip install maturin

# Build wheel
Write-Host "Building wheel..." -ForegroundColor Yellow
maturin build --release -m crates/plxvault-python/Cargo.toml

# Install the wheel
Write-Host "Installing plxvault..." -ForegroundColor Yellow
$wheel = Get-ChildItem target\wheels\*.whl | Select-Object -First 1
pip install $wheel.FullName

# Install dependencies
pip install fastapi uvicorn httpx structlog aiosqlite pyjwt cryptography python-multipart

Write-Host ""
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "Wheel located at: target\wheels\" -ForegroundColor Cyan
Write-Host ""
Write-Host "To run the server:" -ForegroundColor Yellow
Write-Host "  plxvault-server"
Write-Host ""
Write-Host "To run the MCP server:" -ForegroundColor Yellow
Write-Host "  plxvault-mcp"
