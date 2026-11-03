; Whalescale installer for Windows (NSIS 3). scripts/ci/release-archives.sh
; builds it:
;
;   makensis -DVERSION=0.1.1 -DARCH=amd64 -DSRCDIR=build/windows_amd64 \
;            -DOUTFILE=dist/whalescale-setup-windows-amd64.exe packaging/windows/whalescale.nsi
;
; SRCDIR holds ws.exe, wsd.exe, wintun.dll and wintun-LICENSE.txt. The
; installer copies them to Program Files, sets up the Whalescale service
; ('wsd install-service', which also puts ws on PATH) and, given the join
; code from the dashboard, joins the network ('ws login').
;
; Silent install: whalescale-setup-windows-amd64.exe /S /JOIN=wsjoin-...
;
; Keep this file ASCII: makensis reads files without a byte order mark in
; the system code page.

Unicode true
ManifestDPIAware true

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef NUMVERSION
  !define NUMVERSION "0.0.0"
!endif
!ifndef ARCH
  !define ARCH "amd64"
!endif
!ifndef SRCDIR
  !error "define SRCDIR: the directory with ws.exe, wsd.exe and wintun.dll"
!endif
!ifndef OUTFILE
  !define OUTFILE "whalescale-setup-windows-${ARCH}.exe"
!endif

!define APP "Whalescale"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Whalescale"

Name "${APP}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Whalescale"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APP} ${VERSION}"
ShowInstDetails show
ShowUninstDetails show

VIProductVersion "${NUMVERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Whalescale contributors"

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "x64.nsh"

Var JoinCode
Var JoinField
Var FinishText

!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Install Whalescale"
!define MUI_WELCOMEPAGE_TEXT "Whalescale puts this PC on your own private network, so your devices can reach each other from anywhere, as if they were in the same room.$\r$\n$\r$\nHave the join code from your Whalescale dashboard ready: Machines -> Add device."
!insertmacro MUI_PAGE_WELCOME
Page custom JoinPage JoinPageLeave
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TITLE "Whalescale is installed"
!define MUI_FINISHPAGE_TEXT "$FinishText"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  !if "${ARCH}" == "arm64"
    ${IfNot} ${IsNativeARM64}
      MessageBox MB_ICONSTOP "This installer is for Windows on ARM. Download whalescale-setup-windows-amd64.exe instead."
      Abort
    ${EndIf}
  !else
    ${IfNot} ${IsNativeAMD64}
      ${If} ${IsNativeARM64}
        MessageBox MB_ICONSTOP "This PC has an ARM processor: download whalescale-setup-windows-arm64.exe instead."
      ${Else}
        MessageBox MB_ICONSTOP "Whalescale needs 64-bit Windows."
      ${EndIf}
      Abort
    ${EndIf}
  !endif
  SetRegView 64
  ${GetParameters} $R0
  ${GetOptions} $R0 "/JOIN=" $JoinCode
FunctionEnd

Function un.onInit
  SetRegView 64
FunctionEnd

Function JoinPage
  ${If} $JoinCode != ""
    Abort ; given on the command line
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "Join your network" "Paste the join code from your Whalescale dashboard."
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${NSD_CreateLabel} 0 0 100% 44u "In the dashboard, open Machines -> Add device and copy the join code. It starts with wsjoin-.$\r$\n$\r$\nNo code yet? Leave the box empty: you can join later with 'ws login <code>'."
  Pop $0
  ${NSD_CreateText} 0 52u 100% 14u ""
  Pop $JoinField
  nsDialogs::Show
FunctionEnd

Function JoinPageLeave
  ${NSD_GetText} $JoinField $JoinCode
  ; Pasted text often brings spaces along: drop leading ones (ws login
  ; ignores the rest).
  ${DoWhile} $JoinCode != ""
    StrCpy $0 $JoinCode 1
    ${If} $0 != " "
      ${ExitDo}
    ${EndIf}
    StrCpy $JoinCode $JoinCode "" 1
  ${Loop}
  ${If} $JoinCode != ""
    StrCpy $0 $JoinCode 7
    ${If} $0 != "wsjoin-"
      MessageBox MB_ICONEXCLAMATION "That isn't a join code: it should start with wsjoin-. Copy it again from the dashboard, or leave the box empty to join later."
      Abort
    ${EndIf}
  ${EndIf}
FunctionEnd

Section "Install"
  SetShellVarContext all ; Start menu entries for every user
  SetOutPath "$INSTDIR"
  ; Upgrading: the running service holds the files.
  ${If} ${FileExists} "$INSTDIR\wsd.exe"
    DetailPrint "Stopping the running Whalescale service..."
    nsExec::ExecToLog '"$INSTDIR\wsd.exe" uninstall-service'
    Pop $0
  ${EndIf}
  ; Forward slashes: makensis runs on Linux in CI, and accepts them on Windows.
  File "${SRCDIR}/ws.exe"
  File "${SRCDIR}/wsd.exe"
  File "${SRCDIR}/wintun.dll"
  File "${SRCDIR}/wintun-LICENSE.txt"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr HKLM "${UNINSTKEY}" "DisplayName" "${APP}"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTKEY}" "Publisher" "Whalescale"
  WriteRegStr HKLM "${UNINSTKEY}" "DisplayIcon" "$INSTDIR\wsd.exe"
  WriteRegStr HKLM "${UNINSTKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTKEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTKEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINSTKEY}" "EstimatedSize" $0

  DetailPrint "Setting up the Whalescale service..."
  nsExec::ExecToLog '"$INSTDIR\wsd.exe" install-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Setting up the Whalescale service failed: click 'Show details' to see why, then run the installer again."
    SetErrorLevel 1
    Abort
  ${EndIf}

  ; 'ws status' talks to the service, which only Administrators may do.
  CreateDirectory "$SMPROGRAMS\Whalescale"
  CreateShortcut "$SMPROGRAMS\Whalescale\Whalescale status.lnk" "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" \
    "-NoProfile -WindowStyle Hidden -Command Start-Process -Verb RunAs cmd.exe -ArgumentList '/k ws status'" "$INSTDIR\wsd.exe" 0
  CreateShortcut "$SMPROGRAMS\Whalescale\Uninstall Whalescale.lnk" "$INSTDIR\uninstall.exe"

  StrCpy $FinishText "To put this PC on your network, get a join code in the dashboard (Machines -> Add device) and run in a terminal opened as Administrator:$\r$\n$\r$\n    ws login <join code>"
  ${If} $JoinCode != ""
    DetailPrint "Joining your network..."
    nsExec::ExecToLog '"$INSTDIR\ws.exe" login "$JoinCode"'
    Pop $0
    ${If} $0 == 0
      StrCpy $FinishText "This PC is now on your network: it shows up in your dashboard under Machines.$\r$\n$\r$\nTo see your other devices: Start menu -> Whalescale -> Whalescale status."
    ${Else}
      StrCpy $FinishText "Whalescale is installed, but joining your network failed: the code may be used up or expired (see 'Show details' on the previous page).$\r$\n$\r$\nGet a new code in the dashboard and run, in a terminal opened as Administrator:$\r$\n$\r$\n    ws login <join code>"
      SetErrorLevel 2
    ${EndIf}
  ${EndIf}
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  nsExec::ExecToLog '"$INSTDIR\wsd.exe" uninstall-service'
  Pop $0
  Delete "$INSTDIR\ws.exe"
  Delete "$INSTDIR\wsd.exe"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\wintun-LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Whalescale\Whalescale status.lnk"
  Delete "$SMPROGRAMS\Whalescale\Uninstall Whalescale.lnk"
  RMDir "$SMPROGRAMS\Whalescale"
  DeleteRegKey HKLM "${UNINSTKEY}"
SectionEnd
