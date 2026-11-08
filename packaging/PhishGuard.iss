; PhishGuard installer (Inno Setup 6).  Build: ISCC.exe packaging\PhishGuard.iss
; Installs for the current Windows user only, so no administrator rights are needed.
;   Program:  %LOCALAPPDATA%\Programs\PhishGuard
;   Data:     %LOCALAPPDATA%\PhishGuard  (history, settings, Tor once downloaded)

#define AppVersion "1.1.1"

[Setup]
AppId={{8F1C2B4E-6A3D-4F7B-9C21-5E0A7D3B9F11}
AppName=PhishGuard
AppVersion={#AppVersion}
AppVerName=PhishGuard {#AppVersion}
AppPublisher=Nikhil P
AppCopyright=© 2026 Nikhil P
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\PhishGuard
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
OutputDir=..\build\installer
OutputBaseFilename=PhishGuard-Setup-{#AppVersion}
SetupIconFile=phishguard.ico
UninstallDisplayIcon={app}\PhishGuard.exe
UninstallDisplayName=PhishGuard
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=no

[Tasks]
Name: "desktopicon"; Description: "Add a desktop shortcut"; Flags: unchecked

[Files]
Source: "..\build\dist\PhishGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\PhishGuard"; Filename: "{app}\PhishGuard.exe"; Comment: "Open the PhishGuard dashboard"
Name: "{userdesktop}\PhishGuard"; Filename: "{app}\PhishGuard.exe"; Comment: "Open the PhishGuard dashboard"; Tasks: desktopicon

[Run]
Filename: "{app}\PhishGuard.exe"; Description: "Open PhishGuard now"; Flags: nowait postinstall skipifsilent
; A silent install is an automatic update (phishguard/updater.py): start the new engine straight away.
Filename: "{app}\PhishGuard.exe"; Parameters: "--after-update"; Flags: nowait runhidden; Check: WizardSilent

[UninstallRun]
; Stop the engine (and Tor with it), then remove PhishGuard as a link handler.
Filename: "{app}\PhishGuard.exe"; Parameters: "--stop"; Flags: runhidden waituntilterminated; RunOnceId: "StopEngine"
Filename: "{app}\PhishGuard.exe"; Parameters: "--unregister"; Flags: runhidden waituntilterminated; RunOnceId: "Unregister"
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM PhishGuard.exe /IM PhishGuardEngine.exe"; Flags: runhidden waituntilterminated; RunOnceId: "CloseWindows"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
procedure StopRunningCopy();
var
  Code: Integer;
begin
  if FileExists(ExpandConstant('{app}\PhishGuard.exe')) then
    Exec(ExpandConstant('{app}\PhishGuard.exe'), '--stop', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM PhishGuard.exe /IM PhishGuardEngine.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { An update replaces files the running engine has open, so stop it first. }
  StopRunningCopy();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Data: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    Data := ExpandConstant('{localappdata}\PhishGuard');
    if DirExists(Data) and not UninstallSilent() then
      if MsgBox('Also delete your PhishGuard history and settings?' + #13#10#13#10 + Data,
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
        DelTree(Data, True, True, True);
  end;
end;
