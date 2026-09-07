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
        if ((Test-Path -Path $TargetPath) -and ((Get-Item -Path $TargetPath).Length -gt 100000)) {
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
        if ((Test-Path -Path $TargetPath) -and ((Get-Item -Path $TargetPath).Length -gt 100000)) {
            $Downloaded = $true
            Write-Host "[✔] Downloaded pre-compiled Windows executable via WebClient." -ForegroundColor Green
        }
    } catch {
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TargetPath -UseBasicParsing
            if ((Test-Path -Path $TargetPath) -and ((Get-Item -Path $TargetPath).Length -gt 100000)) {
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

# 4. Interactive Setup Helper
function Prompt-User {
    param(
        [string]$Message,
        [string]$Default = ""
    )
    try {
        $ans = Read-Host $Message
        if ([string]::IsNullOrWhiteSpace($ans)) {
            return $Default
        }
        return $ans.Trim()
    } catch {
        return $Default
    }
}

# 5. Interactive External Decryption Backends
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │ ⚡ STEP 1: EXTERNAL DECRYPTION GUI ENGINES (OPTIONAL)        │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "  TORCRYPT can operate as a terminal GUI frontend for:" -ForegroundColor Gray
Write-Host "    [1] Hashcat (GPU / OpenCL / CUDA Acceleration - Recommended)" -ForegroundColor White
Write-Host "    [2] John the Ripper (Multi-Core SIMD & Jumbo Container Formats)" -ForegroundColor White
Write-Host "    [3] Both Hashcat & John the Ripper" -ForegroundColor White
Write-Host "    [4] Skip (Use built-in pure-Rust AVX2 vector engine only)" -ForegroundColor DarkGray
Write-Host ""

$ToolChoice = Prompt-User -Message "  Select an option [1-4] (Default: 3)" -Default "3"

$HasWinget = [bool](Get-Command winget.exe -ErrorAction SilentlyContinue)
$HasChoco = [bool](Get-Command choco.exe -ErrorAction SilentlyContinue)
$HasScoop = [bool](Get-Command scoop.ps1, scoop -ErrorAction SilentlyContinue)

if ($ToolChoice -in @("1", "2", "3")) {
    if ($ToolChoice -eq "1" -or $ToolChoice -eq "3") {
        Write-Host "[*] Installing Hashcat (GPU Acceleration)..." -ForegroundColor Cyan
        if ($HasWinget) {
            try {
                & winget.exe install --id hashcat.hashcat -e --accept-package-agreements --accept-source-agreements --silent
                Write-Host "[✔] Hashcat installed successfully via winget." -ForegroundColor Green
            } catch {
                Write-Host "[!] winget install failed: $_" -ForegroundColor Yellow
            }
        } elseif ($HasChoco) {
            & choco.exe install -y hashcat
        } elseif ($HasScoop) {
            & scoop.ps1 install hashcat
        } else {
            Write-Host "[!] No package manager (winget/choco/scoop) found. Install manually via: winget install hashcat.hashcat" -ForegroundColor Yellow
        }
    }

    if ($ToolChoice -eq "2" -or $ToolChoice -eq "3") {
        Write-Host "[*] Installing John the Ripper (Multi-Core SIMD)..." -ForegroundColor Cyan
        if ($HasChoco) {
            & choco.exe install -y john
            Write-Host "[✔] John the Ripper installed via Chocolatey." -ForegroundColor Green
        } elseif ($HasScoop) {
            & scoop.ps1 install john
            Write-Host "[✔] John the Ripper installed via Scoop." -ForegroundColor Green
        } else {
            Write-Host "[!] John the Ripper can be installed via: choco install john (or scoop install john)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[*] Skipped external backends." -ForegroundColor Gray
}

# 6. Interactive Wordlists Download
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │ 📖 STEP 2: DICTIONARY WORDLISTS                             │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host "  TORCRYPT includes a 27K built-in corpus. Real-world wordlists" -ForegroundColor Gray
Write-Host "  enable recovery of complex, real-world passwords:" -ForegroundColor Gray
Write-Host "    [1] Download RockYou.txt (14.3M Passwords - ~134 MB, Industry Standard)" -ForegroundColor White
Write-Host "    [2] Download SecLists Top-100k (~1 MB - Lightweight Quick Starter)" -ForegroundColor White
Write-Host "    [3] Download Both RockYou & Top-100k" -ForegroundColor White
Write-Host "    [4] Skip wordlists (use built-in dictionary or custom wordlists)" -ForegroundColor DarkGray
Write-Host ""

$WlChoice = Prompt-User -Message "  Select an option [1-4] (Default: 1)" -Default "1"

$WordlistsDir = Join-Path $InstallDir "wordlists"
if (!(Test-Path -Path $WordlistsDir)) {
    New-Item -ItemType Directory -Path $WordlistsDir -Force | Out-Null
}

if ($WlChoice -in @("1", "2", "3")) {
    if ($WlChoice -eq "1" -or $WlChoice -eq "3") {
        $RockYouPath = Join-Path $WordlistsDir "rockyou.txt"
        $RockYouUrl = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        Write-Host "[*] Downloading RockYou.txt (14.3M passwords, ~134 MB)..." -ForegroundColor Cyan
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$RockYouPath" "$RockYouUrl" --progress-bar
            } else {
                Invoke-WebRequest -Uri $RockYouUrl -OutFile $RockYouPath -UseBasicParsing
            }
            if ((Test-Path -Path $RockYouPath) -and ((Get-Item -Path $RockYouPath).Length -gt 1000000)) {
                Write-Host "[✔] Saved RockYou wordlist to: $RockYouPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Could not download RockYou wordlist: $_" -ForegroundColor Yellow
        }
    }

    if ($WlChoice -eq "2" -or $WlChoice -eq "3") {
        $Top100kPath = Join-Path $WordlistsDir "top-100000.txt"
        $Top100kUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
        Write-Host "[*] Downloading SecLists Top-100k..." -ForegroundColor Cyan
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$Top100kPath" "$Top100kUrl" --silent
            } else {
                Invoke-WebRequest -Uri $Top100kUrl -OutFile $Top100kPath -UseBasicParsing
            }
            if ((Test-Path -Path $Top100kPath) -and ((Get-Item -Path $Top100kPath).Length -gt 10000)) {
                Write-Host "[✔] Saved Top-100k wordlist to: $Top100kPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Could not download Top-100k wordlist: $_" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "[*] Skipped wordlists." -ForegroundColor Gray
}

# 7. Final Summary Card
Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✨ TORCRYPT installation complete!" -ForegroundColor Green
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Executable : $TargetPath" -ForegroundColor White
Write-Host "  Shortcut   : dt (or torcrypt)" -ForegroundColor White
if ((Test-Path -Path $WordlistsDir) -and ((Get-ChildItem -Path $WordlistsDir).Count -gt 0)) {
    Write-Host "  Wordlists  : $WordlistsDir" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  Run: torcrypt  (or shorthand: dt)" -ForegroundColor Yellow
Write-Host "  In [1 Analyze], press [E] to cycle backends (Auto / Hashcat / John / Native)" -ForegroundColor Gray
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
