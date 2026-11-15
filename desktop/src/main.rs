//! SecureSuite desktop window: shows the engine's console in a native app
//! window (system WebView) instead of a browser tab. The engine runs as its
//! own process; this window only displays it.
//!
//! Usage: `securesuite-desktop [ui-port]` (default: $SECURESUITE_UI_PORT or 8081).

use std::path::PathBuf;

use muda::{Menu, PredefinedMenuItem, Submenu};
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop};
use tao::window::WindowBuilder;
use wry::WebViewBuilder;

fn ui_port() -> u16 {
    std::env::args()
        .nth(1)
        .or_else(|| std::env::var("SECURESUITE_UI_PORT").ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(8081)
}

/// Standard menus. On macOS the Edit menu is what makes Cmd+C/V/X/A/Z work
/// in the request and response editors.
fn menu() -> muda::Result<Menu> {
    let app = Submenu::with_items(
        "SecureSuite",
        true,
        &[
            &PredefinedMenuItem::about(None, None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::hide(None),
            &PredefinedMenuItem::hide_others(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::quit(None),
        ],
    )?;
    let edit = Submenu::with_items(
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(None),
            &PredefinedMenuItem::redo(None),
            &PredefinedMenuItem::separator(),
            &PredefinedMenuItem::cut(None),
            &PredefinedMenuItem::copy(None),
            &PredefinedMenuItem::paste(None),
            &PredefinedMenuItem::select_all(None),
        ],
    )?;
    let window = Submenu::with_items(
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(None),
            &PredefinedMenuItem::maximize(None),
            &PredefinedMenuItem::fullscreen(None),
        ],
    )?;
    Menu::with_items(&[&app, &edit, &window])
}

/// Exported files (CA certificate, CSV) go to ~/Downloads under their own name.
fn download_target(path: &mut PathBuf) -> bool {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_default();
    let name = path
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| "securesuite-download".into());
    *path = home.join("Downloads").join(name);
    true
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("http://127.0.0.1:{}/", ui_port());
    let event_loop = EventLoop::new();

    let menu = menu()?;
    #[cfg(target_os = "macos")]
    menu.init_for_nsapp();

    let window = WindowBuilder::new()
        .with_title("SecureSuite")
        .with_inner_size(LogicalSize::new(1440.0, 900.0))
        .with_min_inner_size(LogicalSize::new(900.0, 600.0))
        .build(&event_loop)?;

    #[cfg(target_os = "windows")]
    {
        use tao::platform::windows::WindowExtWindows;
        // SAFETY: the HWND belongs to the window built just above.
        unsafe { menu.init_for_hwnd(window.hwnd() as _)? };
    }

    let _webview = WebViewBuilder::new()
        .with_url(&url)
        .with_clipboard(true)
        .with_download_started_handler(|_url, path| download_target(path))
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloads_keep_their_name_under_downloads() {
        let mut p = PathBuf::from("ca-cert.pem");
        assert!(download_target(&mut p));
        assert!(p.ends_with("Downloads/ca-cert.pem"));
        assert!(p.is_absolute());
    }
}
