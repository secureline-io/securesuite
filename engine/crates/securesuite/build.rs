// Build script: embed the SecureSuite app icon into the Windows .exe.
// No-op when not targeting Windows, or when the .ico is absent (mac/Linux).
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let ico = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../packaging/brand/securesuite.ico"
        );
        if std::path::Path::new(ico).exists() {
            let mut res = winresource::WindowsResource::new();
            res.set_icon(ico);
            res.set("ProductName", "SecureSuite");
            res.set("FileDescription", "SecureSuite engine");
            res.set("CompanyName", "SecureSuite");
            if let Err(e) = res.compile() {
                println!("cargo:warning=icon embed skipped: {e}");
            }
        } else {
            println!("cargo:warning=securesuite.ico not found; building without an .exe icon");
        }
    }
}
