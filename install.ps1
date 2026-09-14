# ==============================================================================
#  TORCRYPT — One-Liner Universal Installer for Windows (PowerShell)
#  Repository: https://github.com/Fireball122/Torcrypt
# ==============================================================================
$ErrorActionPreference = "Stop"

$Repo = "Fireball122/Torcrypt"
$BinName = "torcrypt.exe"
$ShortAlias = "dt.exe"
$InstallDir = "$env:LOCALAPPDATA\Programs\torcrypt"
$BinDir = Join-Path $InstallDir "bin"
$WordlistsDir = Join-Path $InstallDir "wordlists"

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║        🔐  TORCRYPT — WINDOWS POWERSHELL INSTALLER            ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 0. Terminate any running Torcrypt processes so Windows does not lock the .exe
Get-Process -Name "torcrypt", "torcrypt-tui", "dt" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 200

# 1. Ensure Directories Exist
foreach ($dir in @($InstallDir, $BinDir, $WordlistsDir)) {
    if (!(Test-Path -Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

$TargetPath = Join-Path $InstallDir $BinName
$AliasPath = Join-Path $InstallDir $ShortAlias
$TempFile = Join-Path $env:TEMP ("torcrypt_dl_" + [System.Guid]::NewGuid().ToString("N") + ".exe")
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/torcrypt-windows-x86_64.exe"
$IsUpdate = (Test-Path -Path $TargetPath)

if ($IsUpdate) {
    Write-Host "[*] Updating TORCRYPT binary to latest release..." -ForegroundColor Cyan
} else {
    Write-Host "[*] Downloading TORCRYPT for Windows (x86_64)..." -ForegroundColor Cyan
}

$Downloaded = $false

# Method A: Use native curl.exe if present (Windows 10/11 built-in)
if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
    try {
        & curl.exe -fSL -o "$TempFile" "$DownloadUrl" --connect-timeout 10
        if ((Test-Path -Path $TempFile) -and ((Get-Item -Path $TempFile).Length -gt 1000000)) {
            Move-Item -Path "$TempFile" -Destination "$TargetPath" -Force
            $Downloaded = $true
            Write-Host "[+] Installed latest release binary via curl." -ForegroundColor Green
        }
    } catch {
        # Fall through to PowerShell methods
    }
}

# Method B: PowerShell WebClient / Invoke-WebRequest
if (-not $Downloaded) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        (New-Object System.Net.WebClient).DownloadFile($DownloadUrl, $TempFile)
        if ((Test-Path -Path $TempFile) -and ((Get-Item -Path $TempFile).Length -gt 1000000)) {
            Move-Item -Path "$TempFile" -Destination "$TargetPath" -Force
            $Downloaded = $true
            Write-Host "[+] Installed latest release binary via WebClient." -ForegroundColor Green
        }
    } catch {
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempFile -UseBasicParsing
            if ((Test-Path -Path $TempFile) -and ((Get-Item -Path $TempFile).Length -gt 1000000)) {
                Move-Item -Path "$TempFile" -Destination "$TargetPath" -Force
                $Downloaded = $true
                Write-Host "[+] Installed latest release binary via Invoke-WebRequest." -ForegroundColor Green
            }
        } catch {
            Write-Host "[!] Pre-compiled release download failed: $_" -ForegroundColor Yellow
        }
    }
}
Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue

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
        Write-Host "[+] Successfully compiled and installed via Cargo." -ForegroundColor Green
    } else {
        Write-Error "[-] Could not download release binary. Please check internet access or install Rust/Cargo."
        exit 1
    }
}

# 2. Create dt.exe copy alias
Copy-Item $TargetPath $AliasPath -Force
Write-Host "[+] Created shortcut: $AliasPath" -ForegroundColor Green

# 3. Add to User PATH if not present
function Add-ToUserPath {
    param([string]$DirToAdd)
    if (!(Test-Path -Path $DirToAdd)) { return }
    $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $Parts = $CurrentPath -split ";"
    if ($Parts -notcontains $DirToAdd) {
        [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$DirToAdd", "User")
        $env:Path += ";$DirToAdd"
        Write-Host "[*] Added $DirToAdd to User PATH." -ForegroundColor Cyan
    }
}

Add-ToUserPath -DirToAdd $InstallDir
Add-ToUserPath -DirToAdd $BinDir

# 4. Helper to find installed backend executables
function Find-BackendExecutable {
    param([string]$Name)

    # A. Check PATH
    $cmd = Get-Command "${Name}.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    # B. Check Torcrypt bin folder recursively (e.g. bin\hashcat\hashcat.exe)
    if (Test-Path -Path $BinDir) {
        $found = Get-ChildItem -Path $BinDir -Filter "${Name}.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { return $found.FullName }
    }

    # C. Check well-known package manager & system locations
    $candidates = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\${Name}.exe",
        "$env:LOCALAPPDATA\Programs\${Name}\${Name}.exe",
        "$env:USERPROFILE\scoop\shims\${Name}.exe",
        "$env:USERPROFILE\scoop\apps\${Name}\current\${Name}.exe",
        "$env:USERPROFILE\scoop\apps\${Name}\current\run\${Name}.exe",
        "C:\ProgramData\chocolatey\bin\${Name}.exe",
        "C:\tools\${Name}\${Name}.exe",
        "C:\tools\${Name}\run\${Name}.exe",
        "C:\${Name}\${Name}.exe",
        "C:\${Name}\run\${Name}.exe",
        "C:\Program Files\${Name}\${Name}.exe",
        "C:\Program Files\${Name}\run\${Name}.exe",
        "C:\Program Files (x86)\${Name}\${Name}.exe"
    )
    foreach ($cand in $candidates) {
        if (Test-Path -Path $cand) { return $cand }
    }
    return $null
}

# Helper for interactive or automated prompt
function Prompt-Choice {
    param(
        [string]$PromptMessage,
        [bool]$DefaultYes = $true
    )
    $hint = if ($DefaultYes) { "Y/n" } else { "y/N" }
    try {
        if ([Console]::IsInputRedirected) {
            Write-Host "  [?] $PromptMessage [$hint]: $(if ($DefaultYes) { 'Y (default)' } else { 'N (default)' })" -ForegroundColor Cyan
            return $DefaultYes
        }
        Write-Host ""
        $resp = Read-Host "  [?] $PromptMessage [$hint]"
        if ([string]::IsNullOrWhiteSpace($resp)) {
            return $DefaultYes
        }
        $resp = $resp.Trim().ToLower()
        if ($resp -eq "y" -or $resp -eq "yes") { return $true }
        if ($resp -eq "n" -or $resp -eq "no")  { return $false }
        return $DefaultYes
    } catch {
        Write-Host "  [?] $PromptMessage [$hint]: $(if ($DefaultYes) { 'Y' } else { 'N' })" -ForegroundColor Cyan
        return $DefaultYes
    }
}

# 5. External Decryption Backend Verification & Setup
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  STEP 1: EXTERNAL DECRYPTION ENGINES AUDIT & SETUP          │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

# --- HASHCAT SETUP ---
$HashcatExe = Find-BackendExecutable -Name "hashcat"
if ($HashcatExe) {
    Write-Host "  [+] Hashcat (GPU Acceleration)    : DETECTED" -ForegroundColor Green
    Write-Host "      Location: $HashcatExe" -ForegroundColor Gray
} else {
    Write-Host "  [-] Hashcat (GPU Acceleration)    : NOT DETECTED" -ForegroundColor Yellow
    $DoInstallHc = Prompt-Choice -PromptMessage "Download & install official portable Hashcat v7.1.2 (~19 MB)?" -DefaultYes $true
    if ($DoInstallHc) {
        Write-Host "  [*] Installing official portable Hashcat..." -ForegroundColor Cyan
        $HashcatTargetDir = Join-Path $BinDir "hashcat"
        if (!(Test-Path -Path $HashcatTargetDir)) {
            New-Item -ItemType Directory -Path $HashcatTargetDir -Force | Out-Null
        }

        $7zrPath = Join-Path $env:TEMP "7zr.exe"
        if (!(Test-Path -Path $7zrPath)) {
            Write-Host "      Fetching portable 7zr extractor (~580 KB)..." -ForegroundColor Gray
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$7zrPath" "https://www.7-zip.org/a/7zr.exe" --silent
            } else {
                Invoke-WebRequest -Uri "https://www.7-zip.org/a/7zr.exe" -OutFile "$7zrPath" -UseBasicParsing
            }
        }

        $HashcatArchive = Join-Path $env:TEMP "hashcat-7.1.2.7z"
        Write-Host "      Downloading official Hashcat v7.1.2 archive (~19 MB)..." -ForegroundColor Gray
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$HashcatArchive" "https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z" --progress-bar
            } else {
                Invoke-WebRequest -Uri "https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z" -OutFile "$HashcatArchive" -UseBasicParsing
            }

            if (Test-Path -Path $HashcatArchive) {
                Write-Host "      Extracting Hashcat to $HashcatTargetDir..." -ForegroundColor Gray
                & "$7zrPath" x "$HashcatArchive" "-o$HashcatTargetDir" -y | Out-Null
                Remove-Item -Path "$HashcatArchive" -Force -ErrorAction SilentlyContinue

                $HashcatExe = Find-BackendExecutable -Name "hashcat"
                if ($HashcatExe) {
                    Write-Host "  [+] Hashcat installed successfully!" -ForegroundColor Green
                    Write-Host "      Location: $HashcatExe" -ForegroundColor Gray
                    Add-ToUserPath -DirToAdd (Split-Path -Parent $HashcatExe)
                }
            }
        } catch {
            Write-Host "  [!] Could not download Hashcat: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [*] Skipped Hashcat installation." -ForegroundColor Gray
    }
}

# --- JOHN THE RIPPER SETUP ---
$JohnExe = Find-BackendExecutable -Name "john"
if ($JohnExe) {
    Write-Host "  [+] John the Ripper (SIMD Engine) : DETECTED" -ForegroundColor Green
    Write-Host "      Location: $JohnExe" -ForegroundColor Gray
} else {
    Write-Host "  [-] John the Ripper (SIMD Engine) : NOT DETECTED" -ForegroundColor Yellow
    $DoInstallJohn = Prompt-Choice -PromptMessage "Download & install official portable Win64 John the Ripper Jumbo (~62 MB)?" -DefaultYes $true
    if ($DoInstallJohn) {
        Write-Host "  [*] Installing official Win64 John the Ripper Jumbo..." -ForegroundColor Cyan
        $JohnTargetDir = Join-Path $BinDir "john"
        if (!(Test-Path -Path $JohnTargetDir)) {
            New-Item -ItemType Directory -Path $JohnTargetDir -Force | Out-Null
        }

        $JohnArchive = Join-Path $env:TEMP "john_win64.zip"
        Write-Host "      Downloading John the Ripper Jumbo v1.9.1 (~62 MB)..." -ForegroundColor Gray
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$JohnArchive" "https://github.com/openwall/john-packages/releases/download/v1.9.1-ce/winX64_1_JtR.zip" --progress-bar
            } else {
                Invoke-WebRequest -Uri "https://github.com/openwall/john-packages/releases/download/v1.9.1-ce/winX64_1_JtR.zip" -OutFile "$JohnArchive" -UseBasicParsing
            }

            if (Test-Path -Path $JohnArchive) {
                Write-Host "      Extracting John the Ripper to $JohnTargetDir..." -ForegroundColor Gray
                Expand-Archive -Path "$JohnArchive" -DestinationPath "$JohnTargetDir" -Force
                Remove-Item -Path "$JohnArchive" -Force -ErrorAction SilentlyContinue

                $JohnExe = Find-BackendExecutable -Name "john"
                if ($JohnExe) {
                    Write-Host "  [+] John the Ripper installed successfully!" -ForegroundColor Green
                    Write-Host "      Location: $JohnExe" -ForegroundColor Gray
                    Add-ToUserPath -DirToAdd (Split-Path -Parent $JohnExe)
                }
            }
        } catch {
            Write-Host "  [!] Could not download John the Ripper: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [*] Skipped John the Ripper installation." -ForegroundColor Gray
    }
}

# 6. Wordlists Setup
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │  STEP 2: DICTIONARY WORDLISTS VERIFICATION                  │" -ForegroundColor Cyan
Write-Host "  └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

$RockYouPath = Join-Path $WordlistsDir "rockyou.txt"
if ((Test-Path -Path $RockYouPath) -and ((Get-Item -Path $RockYouPath).Length -gt 1000000)) {
    Write-Host "  [+] RockYou Wordlist              : DETECTED ($([math]::Round((Get-Item -Path $RockYouPath).Length / 1MB)) MB)" -ForegroundColor Green
} else {
    Write-Host "  [-] RockYou Wordlist (14.3M Passwords) : NOT DETECTED" -ForegroundColor Yellow
    $DoDownloadRy = Prompt-Choice -PromptMessage "Download RockYou.txt dictionary (~134 MB)?" -DefaultYes $true
    if ($DoDownloadRy) {
        Write-Host "  [*] Downloading RockYou.txt (14.3M passwords, ~134 MB)..." -ForegroundColor Cyan
        $RockYouUrl = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$RockYouPath" "$RockYouUrl" --progress-bar
            } else {
                Invoke-WebRequest -Uri $RockYouUrl -OutFile $RockYouPath -UseBasicParsing
            }
            if ((Test-Path -Path $RockYouPath) -and ((Get-Item -Path $RockYouPath).Length -gt 1000000)) {
                Write-Host "  [+] Saved RockYou wordlist to: $RockYouPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Could not download RockYou wordlist: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [*] Skipped RockYou wordlist." -ForegroundColor Gray
    }
}

$Top100kPath = Join-Path $WordlistsDir "top-100000.txt"
if ((Test-Path -Path $Top100kPath) -and ((Get-Item -Path $Top100kPath).Length -gt 10000)) {
    Write-Host "  [+] SecLists Top-100k Wordlist    : DETECTED" -ForegroundColor Green
} else {
    Write-Host "  [-] SecLists Top-100k Wordlist    : NOT DETECTED" -ForegroundColor Yellow
    $DoDownload100k = Prompt-Choice -PromptMessage "Download SecLists Top-100k wordlist (~1 MB)?" -DefaultYes $true
    if ($DoDownload100k) {
        Write-Host "  [*] Downloading SecLists Top-100k..." -ForegroundColor Cyan
        $Top100kUrl = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt"
        try {
            if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
                & curl.exe -fSL -o "$Top100kPath" "$Top100kUrl" --silent
            } else {
                Invoke-WebRequest -Uri $Top100kUrl -OutFile $Top100kPath -UseBasicParsing
            }
            if ((Test-Path -Path $Top100kPath) -and ((Get-Item -Path $Top100kPath).Length -gt 10000)) {
                Write-Host "  [+] Saved Top-100k wordlist to: $Top100kPath" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Could not download Top-100k wordlist: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [*] Skipped Top-100k wordlist." -ForegroundColor Gray
    }
}

# 7. Final Summary Card
Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  [+] TORCRYPT setup & verification complete!" -ForegroundColor Green
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Executable : $TargetPath" -ForegroundColor White
Write-Host "  Shortcut   : dt (or torcrypt)" -ForegroundColor White
Write-Host "  Backends   : " -NoNewline -ForegroundColor White
if ($HashcatExe) { Write-Host "[Hashcat (GPU)] " -NoNewline -ForegroundColor Green }
if ($JohnExe)    { Write-Host "[John (SIMD)] " -NoNewline -ForegroundColor Green }
Write-Host "[Native (AVX2)]" -ForegroundColor Green
if (Test-Path -Path $WordlistsDir) {
    Write-Host "  Wordlists  : $WordlistsDir" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  To launch: type 'torcrypt' or 'dt' in any terminal." -ForegroundColor Yellow
Write-Host "  Click directly on [Hashcat], [John], or [Native] to select engine." -ForegroundColor Gray
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
