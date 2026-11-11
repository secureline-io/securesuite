# Packaging SecureSuite

SecureSuite ships as a **single native binary per OS** (no bundled JVM — unlike
Burp Suite, which ships a ~640 MB Java monolith + private JRE). Each platform has
a one-command packaging script, and CI (`.github/workflows/release.yml`) builds
all three on native runners and uploads artifacts on every `v*` tag.

| OS | Command | Produces | Status |
|---|---|---|---|
| macOS | `./packaging/build-macos-app.sh` | `SecureSuite.app` + `.dmg` | ✅ built & verified |
| Linux | `./packaging/build-linux.sh` | `.tar.gz` + `.deb` | ✅ built & verified (aarch64 locally; x86_64 on CI) |
| Windows | `packaging/build-windows.ps1` | `.zip` (+ Inno Setup `.exe`) | ✅ script + CI (built on `windows-latest`) |

## macOS (.app + .dmg)

```
./packaging/build-macos-app.sh
```

Produces `dist/SecureSuite.app` and `dist/SecureSuite.dmg`. Double-click the app
(or mount the DMG and drag it to `/Applications`): it launches the engine and
opens the console at <http://127.0.0.1:8081>. Not yet notarized — first launch:
**right-click → Open**, or `xattr -dr com.apple.quarantine dist/SecureSuite.app`.

## Linux (.tar.gz + .deb)

```
sudo apt-get install -y cmake nasm       # crypto (aws-lc-rs) build deps
./packaging/build-linux.sh
```

Produces `dist/securesuite-<ver>-linux-<arch>.tar.gz` and, when `dpkg-deb` is
present, `dist/securesuite_<ver>_<arch>.deb`. Install:

```
sudo dpkg -i dist/securesuite_<ver>_<arch>.deb && securesuite
# or: tar xzf securesuite-<ver>-linux-<arch>.tar.gz && ./securesuite-*/securesuite
```

Cross-build from macOS/Windows with Docker (no local toolchain needed):

```
docker run --rm -e CARGO_TARGET_DIR=/work/target/linux-build \
  -v "$PWD":/work -w /work rust:bookworm \
  bash -c 'apt-get update && apt-get install -y cmake nasm dpkg-dev && ./packaging/build-linux.sh'
```

## Windows (.zip + optional installer)

```
powershell -ExecutionPolicy Bypass -File packaging/build-windows.ps1
```

Produces `dist/securesuite-<ver>-windows-x64.zip` (and `SecureSuite-<ver>-setup.exe`
if [Inno Setup](https://jrsoftware.org/isinfo.php) / `iscc` is installed). Unzip and
run `securesuite.exe`, or `SecureSuite.bat` to also open the console. SmartScreen
(unsigned): **More info → Run anyway**.

### Cross-build the Windows .exe from macOS/Linux (Docker, no Windows host)

Verified working with [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin):

```
docker run --rm -e CARGO_TARGET_DIR=/work/target/win -e XWIN_ACCEPT_LICENSE=1 \
  -v "$PWD":/work -w /work rust:bookworm bash -c '
  apt-get update && apt-get install -y clang llvm lld nasm cmake
  LLVMBIN=$(ls -d /usr/lib/llvm-*/bin | tail -1); export PATH="$LLVMBIN:$PATH"
  command -v llvm-lib || ln -sf "$LLVMBIN/llvm-ar" /usr/local/bin/llvm-lib
  rustup target add x86_64-pc-windows-msvc
  cargo install cargo-xwin
  cargo xwin build --release -p securesuite --target x86_64-pc-windows-msvc'
# -> target/win/x86_64-pc-windows-msvc/release/securesuite.exe
```

Required: `llvm` (provides `llvm-lib`/`llvm-rc`), `lld` (`lld-link`), and
`nasm` + `cmake` (to build `aws-lc-rs`'s assembly/C).

## Notes

- Binaries are not yet code-signed / notarized (tracked as future work).
- A **native-window shell** (Tauri / WKWebView) is planned; today the console
  opens in your default browser. The release binary is fully functional on all
  three platforms now.
- Everything is **AGPL-3.0** — all features free and open.
