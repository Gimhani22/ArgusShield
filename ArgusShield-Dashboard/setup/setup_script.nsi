; ArgusShield NSIS Installer Script
; Requires NSIS 3.x

;--------------------------------
; Include Modern UI
!include "MUI2.nsh"
!include "FileFunc.nsh"

;--------------------------------
; General Settings
!define PRODUCT_NAME "ArgusShield"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "ArgusShield Security"
!define PRODUCT_WEB_SITE "https://argusshield.com"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\app.exe"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; Request admin privileges
RequestExecutionLevel admin

; Installer name and output file
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "ArgusShield_Setup.exe"

; Default installation directory (Program Files x86)
InstallDir "$PROGRAMFILES32\${PRODUCT_NAME}"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""

; Show installation details
ShowInstDetails show
ShowUnInstDetails show

;--------------------------------
; Interface Settings
!define MUI_ABORTWARNING
; Icons are optional - comment out if not present
; !define MUI_ICON "..\dist\icon.ico"
; !define MUI_UNICON "..\dist\icon.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\win.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT

;--------------------------------
; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "license.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\app.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${PRODUCT_NAME}"
!define MUI_FINISHPAGE_SHOWREADME ""
!define MUI_FINISHPAGE_SHOWREADME_NOTCHECKED
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Create Desktop Shortcut"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateDesktopShortcut
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

;--------------------------------
; Languages
!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Installer Sections
Section "MainSection" SEC01
    SetOutPath "$INSTDIR"
    SetOverwrite on
    
    ; Copy main application files
    File "..\dist\app.exe"
    
    ; Copy icon if exists
    File /nonfatal "..\dist\icon.ico"
    
    ; Create Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk" "$INSTDIR\app.exe" "" "$INSTDIR\app.exe" 0
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninst.exe" "" "" 0
    
    ; Create Desktop shortcut
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\app.exe" "" "$INSTDIR\app.exe" 0
    
    ; Register application for Windows startup (system tray)
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}" '"$INSTDIR\app.exe"'
    
    ; Store installation folder
    WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\app.exe"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninst.exe"
    
    ; Write uninstall information to registry
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninst.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\app.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    
    ; Get installed size
    ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
    IntFmt $0 "0x%08X" $0
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

;--------------------------------
; Desktop shortcut function (called from finish page)
Function CreateDesktopShortcut
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\app.exe" "" "$INSTDIR\app.exe" 0
FunctionEnd

;--------------------------------
; Uninstaller Section
Section Uninstall
    ; Kill running process
    nsExec::ExecToLog 'taskkill /F /IM app.exe'
    
    ; Remove from Windows startup
    DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCT_NAME}"
    
    ; Remove files and directories
    Delete "$INSTDIR\app.exe"
    Delete "$INSTDIR\icon.ico"
    Delete "$INSTDIR\uninst.exe"
    RMDir "$INSTDIR"
    
    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\${PRODUCT_NAME}.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT_NAME}"
    
    ; Remove Desktop shortcut
    Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
    
    ; Remove registry keys
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
    DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
    
    ; Remove AppData folder (optional - uncomment if you want to remove user data)
    ; RMDir /r "$APPDATA\${PRODUCT_NAME}"
    
    SetAutoClose true
SectionEnd

;--------------------------------
; Installer Functions
Function .onInit
    ; Check if already installed
    ReadRegStr $R0 ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString"
    StrCmp $R0 "" done
    
    MessageBox MB_YESNO|MB_ICONQUESTION "${PRODUCT_NAME} is already installed. Do you want to uninstall the previous version first?" IDYES uninst IDNO done
    
    uninst:
        ExecWait '$R0 /S'
    done:
FunctionEnd

Function un.onInit
    MessageBox MB_ICONQUESTION|MB_YESNO "Are you sure you want to completely remove ${PRODUCT_NAME}?" IDYES +2
    Abort
FunctionEnd

Function un.onUninstSuccess
    HideWindow
    MessageBox MB_ICONINFORMATION|MB_OK "${PRODUCT_NAME} was successfully removed."
FunctionEnd