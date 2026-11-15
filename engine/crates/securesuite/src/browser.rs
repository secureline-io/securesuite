//! Built-in testing browser: launches an installed Chromium-family browser in
//! its own profile, already routed through the proxy and trusting the
//! SecureSuite CA, so nothing on the system has to change.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hudsucker::rcgen::{KeyPair, PublicKeyData};

/// Chromium's `--ignore-certificate-errors-spki-list` pin for the CA key.
/// hudsucker signs every site certificate with the CA key itself, so this one
/// pin covers every intercepted HTTPS site and nothing else.
pub fn spki_pin(ca_key_pem: &str) -> anyhow::Result<String> {
    let key = KeyPair::from_pem(ca_key_pem)?;
    let spki = key.subject_public_key_info();
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &spki);
    Ok(B64.encode(hash.as_ref()))
}

/// Arguments for a dedicated, proxied browser profile.
pub fn chromium_args(profile: &Path, proxy_port: u16, pin: &str) -> Vec<String> {
    vec![
        format!("--user-data-dir={}", profile.display()),
        format!("--proxy-server=127.0.0.1:{proxy_port}"),
        // Chromium skips the proxy for localhost unless told otherwise.
        "--proxy-bypass-list=<-loopback>".to_string(),
        format!("--ignore-certificate-errors-spki-list={pin}"),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "about:blank".to_string(),
    ]
}

/// The first installed Chromium-family browser.
// shortcut: uses an installed Chrome/Edge/Brave/Chromium rather than bundling ~150 MB of Chromium; bundle one if users without any of these become common.
pub fn find_chromium() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_default();
        for app in [
            "Google Chrome.app/Contents/MacOS/Google Chrome",
            "Chromium.app/Contents/MacOS/Chromium",
            "Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "Brave Browser.app/Contents/MacOS/Brave Browser",
        ] {
            candidates.push(Path::new("/Applications").join(app));
            candidates.push(Path::new(&home).join("Applications").join(app));
        }
    } else if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Ok(base) = std::env::var(var) {
                let base = PathBuf::from(base);
                candidates.push(base.join(r"Google\Chrome\Application\chrome.exe"));
                candidates.push(base.join(r"Microsoft\Edge\Application\msedge.exe"));
                candidates.push(base.join(r"BraveSoftware\Brave-Browser\Application\brave.exe"));
            }
        }
    } else {
        let path = std::env::var_os("PATH").unwrap_or_default();
        for dir in std::env::split_paths(&path) {
            for name in [
                "google-chrome",
                "google-chrome-stable",
                "chromium",
                "chromium-browser",
                "microsoft-edge",
                "brave-browser",
            ] {
                candidates.push(dir.join(name));
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Start the testing browser; returns the executable that was launched.
pub fn launch(data_dir: &Path, proxy_port: u16, pin: &str) -> anyhow::Result<PathBuf> {
    let exe = find_chromium().ok_or_else(|| {
        anyhow::anyhow!(
            "no Chrome, Edge, Brave or Chromium found; install one to use the built-in browser"
        )
    })?;
    let profile = data_dir.join("browser-profile");
    std::fs::create_dir_all(&profile)?;
    let mut child = Command::new(&exe)
        .args(chromium_args(&profile, proxy_port, pin))
        .spawn()?;
    // Reap it when it exits so it never lingers as a zombie.
    std::thread::spawn(move || child.wait());
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_is_a_base64_sha256_and_is_stable() {
        let key = KeyPair::generate().unwrap().serialize_pem();
        let pin = spki_pin(&key).unwrap();
        assert_eq!(B64.decode(&pin).unwrap().len(), 32);
        assert_eq!(pin, spki_pin(&key).unwrap());
    }

    #[test]
    fn args_route_every_host_through_the_proxy() {
        let args = chromium_args(Path::new("/p"), 8086, "PIN");
        assert!(args.contains(&"--proxy-server=127.0.0.1:8086".to_string()));
        assert!(args.contains(&"--proxy-bypass-list=<-loopback>".to_string()));
        assert!(args.contains(&"--ignore-certificate-errors-spki-list=PIN".to_string()));
        assert!(args.contains(&"--user-data-dir=/p".to_string()));
    }
}
