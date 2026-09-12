// src/cli.rs — TORCRYPT CLI Subcommand Dispatcher (update, uninstall, version, help)
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

pub fn handle_cli_args(args: &[String]) -> Option<io::Result<()>> {
    if args.len() <= 1 {
        return None; // Launch TUI
    }

    match args[1].as_str() {
        "update" | "--update" | "-u" => Some(cli_update()),
        "uninstall" | "--uninstall" => {
            let purge = args.iter().any(|a| a == "--all" || a == "-y" || a == "--purge");
            Some(cli_uninstall(purge))
        }
        "version" | "--version" | "-v" | "-V" => {
            println!("TORCRYPT v{}", env!("CARGO_PKG_VERSION"));
            Some(Ok(()))
        }
        "help" | "--help" | "-h" => {
            print_help();
            Some(Ok(()))
        }
        _ => None, // Let TUI handle paths or other flags
    }
}

pub fn print_help() {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════════╗");
    println!("  ║     🔐  TORCRYPT — CRYPTOGRAPHIC ANALYSIS & DECRYPTION TUI     ║");
    println!("  ╚═══════════════════════════════════════════════════════════════╝");
    println!();
    println!("USAGE:");
    println!("  torcrypt               Launch the Cyberpunk interactive TUI");
    println!("  torcrypt update        Check for updates and fast-upgrade the binary");
    println!("  torcrypt uninstall     Uninstall TORCRYPT, shortcuts, and data");
    println!("  torcrypt version       Display installed version");
    println!("  torcrypt help          Display this help reference");
    println!();
    println!("OPTIONS FOR UNINSTALL:");
    println!("  torcrypt uninstall -y       Skip confirmation prompts (automated purge)");
    println!("  torcrypt uninstall --purge  Purge all wordlists, session DBs, and potfiles");
    println!();
    println!("SHORTHAND ALIAS:");
    println!("  dt                     Direct shorthand command for torcrypt");
    println!();
}

pub fn cli_update() -> io::Result<()> {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════════╗");
    println!("  ║           🔐  TORCRYPT — SOFTWARE UPDATE CHECK               ║");
    println!("  ╚═══════════════════════════════════════════════════════════════╝");
    println!();
    let cur_ver = env!("CARGO_PKG_VERSION").trim();
    println!("[*] Installed version : v{}", cur_ver);
    println!("[*] Checking GitHub for latest release...");

    let api_url = "https://api.github.com/repos/Fireball122/Torcrypt/releases/latest";
    let latest_tag = fetch_latest_release_tag(api_url);

    match latest_tag {
        Some(tag) => {
            let tag_clean = tag.trim_start_matches('v').trim();
            println!("[*] Latest release    : v{}", tag_clean);

            if !is_newer_version(tag_clean, cur_ver) {
                println!();
                println!("  [+] TORCRYPT is already up to date! (v{})", cur_ver);
                println!();
                return Ok(());
            }

            println!();
            println!("[*] Upgrade available: v{} -> v{}", cur_ver, tag_clean);
            println!("[*] Downloading and installing updated release binary...");
            println!();

            #[cfg(target_os = "windows")]
            {
                let cmd_str = "irm https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.ps1 | iex";
                let status = Command::new("powershell")
                    .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd_str])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        println!();
                        println!("  [+] Upgrade complete! Run 'torcrypt' or 'dt' to launch.");
                        println!();
                    }
                    _ => {
                        eprintln!("[!] Automated update encountered an error. Run manually via:");
                        eprintln!("    irm https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.ps1 | iex");
                    }
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                let cmd_str = "curl -fsSL https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.sh | bash";
                let status = Command::new("bash")
                    .args(&["-c", cmd_str])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        println!();
                        println!("  [+] Upgrade complete! Run 'torcrypt' or 'dt' to launch.");
                        println!();
                    }
                    _ => {
                        eprintln!("[!] Automated update encountered an error. Run manually via:");
                        eprintln!("    curl -fsSL https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.sh | bash");
                    }
                }
            }
        }
        None => {
            eprintln!("[!] Could not connect to GitHub to check for updates.");
            eprintln!("    Please verify your internet connection or run the installer script.");
        }
    }

    Ok(())
}

fn fetch_latest_release_tag(api_url: &str) -> Option<String> {
    // 1. Try curl
    if let Ok(output) = Command::new("curl")
        .args(&["-sSL", "-H", "User-Agent: torcrypt-updater", api_url])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            if let Some(tag) = parse_tag_from_json(&text) {
                return Some(tag);
            }
        }
    }

    // 2. Windows fallback: PowerShell Invoke-RestMethod
    #[cfg(target_os = "windows")]
    {
        let ps_cmd = format!("(Invoke-RestMethod -Uri '{}' -UseBasicParsing).tag_name", api_url);
        if let Ok(output) = Command::new("powershell")
            .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
            .output()
        {
            if output.status.success() {
                let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !tag.is_empty() {
                    return Some(tag);
                }
            }
        }
    }

    None
}

pub fn parse_tag_from_json(json: &str) -> Option<String> {
    let key = "\"tag_name\":";
    let idx = json.find(key)?;
    let after = &json[idx + key.len()..];
    let start = after.find('"')? + 1;
    let end = after[start..].find('"')? + start;
    Some(after[start..end].trim().to_string())
}

pub fn cli_uninstall(purge: bool) -> io::Result<()> {
    println!();
    println!("  ╔═══════════════════════════════════════════════════════════════╗");
    println!("  ║            🗑️  TORCRYPT — UNINSTALLATION WIZARD              ║");
    println!("  ╚═══════════════════════════════════════════════════════════════╝");
    println!();

    #[cfg(target_os = "windows")]
    {
        uninstall_windows(purge)
    }

    #[cfg(not(target_os = "windows"))]
    {
        uninstall_unix(purge)
    }
}

#[cfg(target_os = "windows")]
fn uninstall_windows(purge: bool) -> io::Result<()> {
    let localappdata = match std::env::var("LOCALAPPDATA") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("[-] Error: Could not determine LOCALAPPDATA directory.");
            return Ok(());
        }
    };

    let install_dir = localappdata.join("Programs").join("torcrypt");
    let alt_data_dir = localappdata.join("torcrypt");

    println!("  This will remove TORCRYPT from your Windows system:");
    println!("    • Executables & Shortcuts: {}", install_dir.display());
    println!("    • Downloaded Wordlists (RockYou, etc.)");
    println!("    • Downloaded Recovery Backends & Tools");
    println!("    • Session Registry & Potfile History");
    println!("    • Removes from User PATH environment variable");
    println!();

    if !purge {
        print!("  Are you sure you want to completely uninstall TORCRYPT? [y/N]: ");
        let _ = io::stdout().flush();
        let mut answer = String::new();
        let _ = io::stdin().read_line(&mut answer);
        let trimmed = answer.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("[*] Uninstallation cancelled.");
            return Ok(());
        }
    }

    println!("[*] Cleaning User PATH environment variable...");
    let clean_path_script = r#"
        $p = [Environment]::GetEnvironmentVariable('Path', 'User')
        if ($p) {
            $newP = ($p -split ';' | Where-Object { $_ -and $_ -notlike '*\Programs\torcrypt*' }) -join ';'
            [Environment]::SetEnvironmentVariable('Path', $newP, 'User')
        }
    "#;
    let _ = Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", clean_path_script])
        .status();

    println!("[*] Removing program files, wordlists, and databases...");
    // Since Windows locks the currently running executable, spawn a detached PowerShell script
    // that sleeps 1 second for torcrypt.exe to exit, then cleans up the directory completely.
    let cleanup_script = format!(
        "Start-Sleep -Milliseconds 800; Remove-Item -Recurse -Force -LiteralPath '{}' -ErrorAction SilentlyContinue; Remove-Item -Recurse -Force -LiteralPath '{}' -ErrorAction SilentlyContinue",
        install_dir.display(),
        alt_data_dir.display()
    );

    let _ = Command::new("powershell")
        .args(&["-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-Command", &cleanup_script])
        .spawn();

    println!();
    println!("  ═════════════════════════════════════════════════════════════════");
    println!("    [+] TORCRYPT has been completely uninstalled from Windows.");
    println!("    [+] Cleaned shortcuts, wordlists, databases, and User PATH.");
    println!("  ═════════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn uninstall_unix(purge: bool) -> io::Result<()> {
    let home = match std::env::var("HOME") {
        Ok(v) => PathBuf::from(v),
        Err(_) => {
            eprintln!("[-] Error: Could not determine HOME directory.");
            return Ok(());
        }
    };

    let bin_torcrypt = home.join(".local/bin/torcrypt");
    let bin_dt = home.join(".local/bin/dt");
    let data_dir = home.join(".local/share/torcrypt");
    let cache_dir = home.join(".cache/torcrypt");

    println!("  This will remove TORCRYPT from your system:");
    println!("    • Binaries : {} and {}", bin_torcrypt.display(), bin_dt.display());
    println!("    • Data     : {} (sessions, potfiles, wordlists)", data_dir.display());
    println!();

    if !purge {
        print!("  Are you sure you want to completely uninstall TORCRYPT? [y/N]: ");
        let _ = io::stdout().flush();
        let mut answer = String::new();
        let _ = io::stdin().read_line(&mut answer);
        let trimmed = answer.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("[*] Uninstallation cancelled.");
            return Ok(());
        }
    }

    if bin_torcrypt.exists() {
        let _ = std::fs::remove_file(&bin_torcrypt);
        println!("[+] Removed: {}", bin_torcrypt.display());
    }
    if bin_dt.exists() {
        let _ = std::fs::remove_file(&bin_dt);
        println!("[+] Removed: {}", bin_dt.display());
    }
    if data_dir.exists() {
        let _ = std::fs::remove_dir_all(&data_dir);
        println!("[+] Purged data, wordlists & databases: {}", data_dir.display());
    }
    if cache_dir.exists() {
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    println!();
    println!("  ═════════════════════════════════════════════════════════════════");
    println!("    [+] TORCRYPT has been completely uninstalled from your system.");
    println!("  ═════════════════════════════════════════════════════════════════");
    println!();

    Ok(())
}

pub fn is_newer_version(remote: &str, current: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|p| p.trim_matches(|c: char| !c.is_ascii_digit()).parse().ok())
            .collect()
    };
    let r_parts = parse(remote);
    let c_parts = parse(current);
    for i in 0..r_parts.len().max(c_parts.len()) {
        let r = r_parts.get(i).copied().unwrap_or(0);
        let c = c_parts.get(i).copied().unwrap_or(0);
        if r > c { return true; }
        if r < c { return false; }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.1.25", "0.1.24"));
        assert!(is_newer_version("0.2.0", "0.1.99"));
        assert!(is_newer_version("1.0.0", "0.9.9"));
        assert!(!is_newer_version("0.1.24", "0.1.24"));
        assert!(!is_newer_version("0.1.23", "0.1.24"));
        assert!(!is_newer_version("0.1.24", "0.1.25"));
    }

    #[test]
    fn test_parse_tag_from_json() {
        let sample = r#"{"tag_name":"v0.1.24","name":"v0.1.24","draft":false}"#;
        assert_eq!(parse_tag_from_json(sample), Some("v0.1.24".into()));

        let sample_spaces = r#"  "tag_name":   "v1.0.0"  , "name": "1.0" "#;
        assert_eq!(parse_tag_from_json(sample_spaces), Some("v1.0.0".into()));
    }

    #[test]
    fn test_handle_cli_args_dispatch() {
        let args_none = vec!["torcrypt".to_string()];
        assert!(handle_cli_args(&args_none).is_none());

        let args_file = vec!["torcrypt".to_string(), "/path/to/archive.zip".to_string()];
        assert!(handle_cli_args(&args_file).is_none());

        let args_ver = vec!["torcrypt".to_string(), "--version".to_string()];
        assert!(handle_cli_args(&args_ver).is_some());

        let args_help = vec!["torcrypt".to_string(), "help".to_string()];
        assert!(handle_cli_args(&args_help).is_some());
    }
}
