# ==============================================================================
#  TORCRYPT — One-Liner Universal Installer for Windows (PowerShell)
#  Repository: https://github.com/Fireball122/Torcrypt
# ==============================================================================
$ErrorActionPreference = "Stop"

$Repo = "Fireball122/Torcrypt"
$BinName = "torcrypt.exe"
$ShortAlias = "dt.exe"
$InstallDir = "$env:LOCALAPPDATA\Programs\torcrypt"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║        🔐  TORCRYPT — WINDOWS POWERSHELL INSTALLER            ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. Ensure Install Directory Exists
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$TargetPath = Join-Path $InstallDir $BinName
$AliasPath = Join-Path $InstallDir $ShortAlias
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/torcrypt-windows-x86_64.exe"

Write-Host "[*] Downloading TORCRYPT for Windows (x86_64)..." -ForegroundColor Cyan

$Downloaded = $false

# Method A: Use native curl.exe if present (Windows 10/11 built-in)
if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    try {
        & curl.exe -fSL -o "$TargetPath" "$DownloadUrl" --connect-timeout 10
        if (Test-Path $TargetPath -and (Get-Item $TargetPath).Length -gt 100000) {
            $Downloaded = $true
            Write-Host "[✔] Downloaded pre-compiled Windows executable via curl." -ForegroundColor Green
        }
    } catch {
        # Fall through to PowerShell methods
    }
}

# Method B: PowerShell WebClient / Invoke-WebRequest
if (-not $Downloaded) {
    try {
        # Enable TLS 1.2 safely without throwing on older .NET Framework
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object System.Net.WebClient).DownloadFile($DownloadUrl, $TargetPath)
        if (Test-Path $TargetPath -and (Get-Item $TargetPath).Length -gt 100000) {
            $Downloaded = $true
            Write-Host "[✔] Downloaded pre-compiled Windows executable via WebClient." -ForegroundColor Green
        }
    } catch {
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TargetPath -UseBasicParsing
            if (Test-Path $TargetPath -and (Get-Item $TargetPath).Length -gt 100000) {
                $Downloaded = $true
                Write-Host "[✔] Downloaded pre-compiled Windows executable via Invoke-WebRequest." -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Pre-compiled release download failed: $_" -ForegroundColor Yellow
        }
    }
}

# Method C: Fallback to local Cargo build
if (-not $Downloaded) {
    Write-Host "[!] Checking for local Cargo build..." -ForegroundColor Yellow
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        Write-Host "[*] Compiling with Cargo..." -ForegroundColor Cyan
        $TempDir = Join-Path $env:TEMP "torcrypt_build"
        git clone --depth 1 "https://github.com/$Repo.git" $TempDir
        Push-Location $TempDir
        cargo build --release
        Copy-Item "target\release\torcrypt-tui.exe" -Destination $TargetPath -Force
        Pop-Location
        Remove-Item -Recurse -Force $TempDir
        $Downloaded = $true
        Write-Host "[✔] Successfully compiled and installed via Cargo." -ForegroundColor Green
    } else {
        Write-Error "[-] Could not download release binary. Please check internet access or install Rust/Cargo."
        exit 1
    }
}

# 2. Create dt.exe copy alias
Copy-Item $TargetPath $AliasPath -Force
Write-Host "[✔] Created shortcut: $AliasPath" -ForegroundColor Green

# 3. Add to User PATH if not present
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -split ";" -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
    Write-Host "[*] Added $InstallDir to User PATH." -ForegroundColor Cyan
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✨ TORCRYPT installation complete!" -ForegroundColor Green
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Restart your PowerShell/Command Prompt or run:"
Write-Host "    torcrypt  (or shorthand: dt)" -ForegroundColor Yellow
Write-Host "  Optional External Acceleration Engines (GPU Acceleration):" -ForegroundColor Yellow
Write-Host "    winget install hashcat.hashcat" -ForegroundColor DarkGray
Write-Host "    choco install hashcat john" -ForegroundColor DarkGray
Write-Host ""
