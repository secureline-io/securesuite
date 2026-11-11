# Build SecureSuite for Windows: release exe -> .zip (+ Inno Setup installer if iscc present).
# Run from anywhere: powershell -ExecutionPolicy Bypass -File packaging/build-windows.ps1
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> cargo build --release -p securesuite"
cargo build --release -p securesuite

$ver = (Select-String -Path "Cargo.toml" -Pattern '^version\s*=\s*"(.*)"').Matches[0].Groups[1].Value
$dist = Join-Path $Root "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$stage = Join-Path $dist "securesuite-$ver-windows-x64"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item "target/release/securesuite.exe" (Join-Path $stage "securesuite.exe")
@"
@echo off
rem SecureSuite launcher: start the engine and open the console.
start "" http://127.0.0.1:8081
securesuite.exe
"@ | Set-Content -Encoding ASCII (Join-Path $stage "SecureSuite.bat")
Copy-Item "packaging/README.md" (Join-Path $stage "README.md") -ErrorAction SilentlyContinue

$zip = Join-Path $dist "securesuite-$ver-windows-x64.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path "$stage/*" -DestinationPath $zip
Write-Host "==> $zip"

# Optional native installer if Inno Setup is installed.
if (Get-Command iscc -ErrorAction SilentlyContinue) {
  & iscc "/DAppVersion=$ver" (Join-Path $PSScriptRoot "securesuite.iss")
  Write-Host "==> Inno Setup installer built"
}
Write-Host "done"
