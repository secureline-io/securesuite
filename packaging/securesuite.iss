; Inno Setup script for SecureSuite (optional; used by build-windows.ps1 when iscc is present).
; Build:  iscc /DAppVersion=0.0.1 packaging/securesuite.iss
#ifndef AppVersion
  #define AppVersion "0.0.1"
#endif

[Setup]
AppName=SecureSuite
AppVersion={#AppVersion}
AppPublisher=SecureSuite
DefaultDirName={autopf}\SecureSuite
DefaultGroupName=SecureSuite
OutputDir=..\dist
OutputBaseFilename=SecureSuite-{#AppVersion}-setup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64
SetupIconFile=brand\securesuite.ico
UninstallDisplayIcon={app}\securesuite.exe

[Files]
Source: "..\target\release\securesuite.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SecureSuite"; Filename: "{app}\securesuite.exe"
Name: "{group}\Open SecureSuite Console"; Filename: "http://127.0.0.1:8081"

[Run]
Filename: "{app}\securesuite.exe"; Description: "Launch SecureSuite"; Flags: nowait postinstall skipifsilent
