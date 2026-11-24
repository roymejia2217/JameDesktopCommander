#define InputDir GetEnv("JDC_INSTALLER_SOURCE")
#define CandidateVersion GetEnv("JDC_INSTALLER_VERSION")
#define OutputPath GetEnv("JDC_INSTALLER_OUTPUT")
#define TunnelClientSource GetEnv("JDC_TUNNEL_CLIENT_SOURCE")
#define OperatorUiDir GetEnv("JDC_OPERATOR_UI_SOURCE")
#if InputDir == ""
  #error JDC_INSTALLER_SOURCE must identify an independently verified candidate
#endif
#if CandidateVersion == ""
  #error JDC_INSTALLER_VERSION is required
#endif
#if OutputPath == ""
  #error JDC_INSTALLER_OUTPUT is required
#endif
#if TunnelClientSource == ""
  #error JDC_TUNNEL_CLIENT_SOURCE requires verified official files
#endif
#if OperatorUiDir == ""
  #error JDC_OPERATOR_UI_SOURCE requires a validated native UI overlay
#endif
[Setup]
#ifdef JDC_PROTECTED_INSTALL
AppId={{B3A49286-DB7B-4BD1-B84D-9DC922260810}
AppName=JameDesktopCommander Managed Candidate
#else
AppId={{C812A487-AF99-4640-9F77-31DD4A9A7F12}
AppName=JameDesktopCommander
#endif
AppVersion={#CandidateVersion}
AppPublisher=JameDesktopCommander
AppPublisherURL=https://github.com/roymejia2217/JameDesktopCommander
#ifdef JDC_PROTECTED_INSTALL
; Experimental clean-room custody candidate; never migrates the per-user app.
DefaultDirName={autopf}\JameDesktopCommander Managed Candidate
DefaultGroupName=JameDesktopCommander Managed Candidate
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
DisableDirPage=yes
UsePreviousAppDir=no
#else
DefaultDirName={localappdata}\Programs\JameDesktopCommander
DefaultGroupName=JameDesktopCommander
PrivilegesRequired=lowest
#endif
ArchitecturesAllowed=x64compatible
OutputDir={#OutputPath}
#ifdef JDC_PROTECTED_INSTALL
OutputBaseFilename=UNPUBLISHED-jdc-managed-custody-win32-x64
#else
OutputBaseFilename=UNPUBLISHED-jdc-installer-win32-x64
#endif
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
#ifdef JDC_PROTECTED_INSTALL
UninstallDisplayName=JameDesktopCommander Managed Candidate
#else
UninstallDisplayName=JameDesktopCommander
#endif
LicenseFile={#InputDir}\LICENSE

[Files]
Source: "{#InputDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourcePath}jdc.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#TunnelClientSource}\*"; DestDir: "{app}\tools\tunnel-client"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#OperatorUiDir}\jdc-tunnel-operator-ui.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OperatorUiDir}\operator-ui-manifest.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#OperatorUiDir}\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
#ifdef JDC_PROTECTED_INSTALL
Name: "{commonprograms}\JameDesktopCommander Managed Candidate - Tunnel Operator"; Filename: "{app}\jdc-tunnel-operator-ui.exe"; WorkingDir: "{app}"
#else
Name: "{userprograms}\JameDesktopCommander (MCP console)"; Filename: "{app}\jdc.cmd"; WorkingDir: "{app}"
Name: "{userprograms}\JameDesktopCommander - Tunnel Operator"; Filename: "{app}\jdc-tunnel-operator-ui.exe"; WorkingDir: "{app}"
#endif

#ifdef JDC_PROTECTED_INSTALL
[Code]
function GetFileAttributesW(lpFileName: String): LongWord;
  external 'GetFileAttributesW@kernel32.dll stdcall';

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ParentAttributes, TargetAttributes: LongWord;
  TargetError: Integer;
begin
  Result := 'E_PROTECTED_INSTALL_TARGET_UNVERIFIED';
  if not IsAdminInstallMode then exit;
  if CompareText(ExpandConstant('{app}'),
    ExpandConstant('{autopf}\JameDesktopCommander Managed Candidate')) <> 0 then exit;
  ParentAttributes := GetFileAttributesW(ExpandConstant('{autopf}'));
  if (ParentAttributes = $FFFFFFFF) or
     ((ParentAttributes and $10) = 0) or
     ((ParentAttributes and $400) <> 0) then exit;
  TargetAttributes := GetFileAttributesW(ExpandConstant('{app}'));
  TargetError := DLLGetLastError;
  if TargetAttributes <> $FFFFFFFF then begin
    Result := 'E_PROTECTED_INSTALL_TARGET_EXISTS';
    exit;
  end;
  { Only ERROR_FILE_NOT_FOUND permits clean creation. No upgrade or adoption. }
  if TargetError <> 2 then exit;
  Result := '';
end;
#endif
