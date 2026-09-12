# ==============================================================================
#  TORCRYPT — One-Liner Uninstaller for Windows (PowerShell)
#  Repository: https://github.com/Fireball122/Torcrypt
# ==============================================================================
$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║        🗑️   TORCRYPT — WINDOWS UNINSTALLER                    ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$InstallDir = "$env:LOCALAPPDATA\Programs\torcrypt"
$DataDir = "$env:LOCALAPPDATA\torcrypt"

# Terminate any running processes
Get-Process -Name "torcrypt", "torcrypt-tui", "dt" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300

# Remove User PATH
Write-Host "[*] Removing TORCRYPT from User PATH..." -ForegroundColor Cyan
$p = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($p) {
    $newP = ($p -split ';' | Where-Object { $_ -and $_ -notlike '*\Programs\torcrypt*' }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $newP, 'User')
}

# Remove program files, wordlists, and databases
Write-Host "[*] Removing program files, wordlists, and databases..." -ForegroundColor Cyan
if (Test-Path -Path $InstallDir) {
    Remove-Item -Recurse -Force -LiteralPath $InstallDir -ErrorAction SilentlyContinue
}
if (Test-Path -Path $DataDir) {
    Remove-Item -Recurse -Force -LiteralPath $DataDir -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  [+] TORCRYPT has been completely uninstalled from Windows." -ForegroundColor Green
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
