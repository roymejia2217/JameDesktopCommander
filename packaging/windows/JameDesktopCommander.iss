#define InputDir GetEnv("JDC_INSTALLER_SOURCE")
#define CandidateVersion GetEnv("JDC_INSTALLER_VERSION")
#define OutputPath GetEnv("JDC_INSTALLER_OUTPUT")
#if InputDir == ""
  #error JDC_INSTALLER_SOURCE must identify an independently verified candidate
#endif
#if CandidateVersion == ""
  #error JDC_INSTALLER_VERSION is required
#endif
#if OutputPath == ""
  #error JDC_INSTALLER_OUTPUT is required
#endif
[Setup]
AppId={{C812A487-AF99-4640-9F77-31DD4A9A7F12}
AppName=JameDesktopCommander
AppVersion={#CandidateVersion}
AppPublisher=JameDesktopCommander
AppPublisherURL=https://github.com/roymejia2217/JameDesktopCommander
DefaultDirName={localappdata}\Programs\JameDesktopCommander
DefaultGroupName=JameDesktopCommander
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
OutputDir={#OutputPath}
OutputBaseFilename=UNPUBLISHED-JDC-{#CandidateVersion}-win32-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
UninstallDisplayName=JameDesktopCommander
LicenseFile={#InputDir}\LICENSE

[Files]
Source: "{#InputDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourcePath}jdc.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{userprograms}\JameDesktopCommander (MCP console)"; Filename: "{app}\jdc.cmd"; WorkingDir: "{app}"
