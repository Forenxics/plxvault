@echo off
setlocal enabledelayedexpansion

echo.
echo PlxVault CA Installer for Windows
echo ==================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.11 or later.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Get Python version
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Found Python %PYVER%

:: Find wheel in current directory or wheels subdirectory
set WHEEL=
for %%f in (plxvault*.whl) do set WHEEL=%%f
if not defined WHEEL (
    for %%f in (wheels\plxvault*.whl) do set WHEEL=wheels\%%f
)

if not defined WHEEL (
    echo ERROR: No wheel file found.
    echo Please download the Windows wheel from the releases page.
    pause
    exit /b 1
)

echo Installing %WHEEL%...
echo.

:: Install the wheel and dependencies
pip install "%WHEEL%"
pip install fastapi uvicorn[standard] httpx structlog aiosqlite pyjwt cryptography python-multipart pydantic

if errorlevel 1 (
    echo.
    echo ERROR: Installation failed.
    pause
    exit /b 1
)

echo.
echo ========================================
echo PlxVault CA installed successfully!
echo ========================================
echo.
echo Commands available:
echo   plxvault        - CLI tool
echo   plxvault-mcp    - MCP server for AI integration
echo.
echo To start the API server:
echo   python -m uvicorn plxvault.api.app:app --host 0.0.0.0 --port 8000
echo.
echo API documentation at: http://localhost:8000/docs
echo.
pause
