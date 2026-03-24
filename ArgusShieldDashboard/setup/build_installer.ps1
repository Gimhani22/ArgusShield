# ArgusShield Setup Builder Script
# Requirements:
# 1. Provide a static C# build output at bin\Release\net8.0-windows\win-x64\publish\ArgusShieldDashboard.exe
# 2. Services built at ..\ArgusShieldService\x64\Release\ArgusShieldService.exe
# 3. NSIS Installed

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$DistDir = Join-Path $ProjectDir "publish-output"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ArgusShield NSIS Setup Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Checking dependencies..." -ForegroundColor Green
$DashboardExe = Join-Path $ProjectDir "bin\Debug\net8.0-windows\win-x64\publish\ArgusShieldDashboard.exe"

if (-not (Test-Path $DashboardExe)) {
    Write-Host "  WARNING: Dashboard executable not found at:" -ForegroundColor Yellow
    Write-Host "  $DashboardExe" -ForegroundColor Yellow
    Write-Host "  Please run 'dotnet publish -c Debug -r win-x64 --self-contained true -p:PublishSingleFile=true' first." -ForegroundColor Yellow
    exit 1
}

Write-Host "  Dashboard statically built exe found." -ForegroundColor Gray

Write-Host ""
Write-Host "[2/3] Locating NSIS Compiler..." -ForegroundColor Green

$NSISPath = $null
$PossiblePaths = @(
    "C:\Program Files (x86)\NSIS\makensis.exe",
    "C:\Program Files\NSIS\makensis.exe",
    (Get-Command makensis -ErrorAction SilentlyContinue).Source
)

foreach ($path in $PossiblePaths) {
    if ($path -and (Test-Path $path)) {
        $NSISPath = $path
        break
    }
}

if (-not $NSISPath) {
    Write-Host "  ERROR: NSIS (makensis.exe) not found!" -ForegroundColor Red
    Write-Host "  Please install NSIS from: https://nsis.sourceforge.io/Download" -ForegroundColor Red
    exit 1
}

Write-Host "  NSIS found at: $NSISPath" -ForegroundColor Gray

Write-Host ""
Write-Host "[3/3] Building NSIS installer..." -ForegroundColor Green

$NSISScript = Join-Path $ScriptDir "setup_script.nsi"
Push-Location $ScriptDir

Write-Host "  Running: $NSISPath `"$NSISScript`"" -ForegroundColor Gray
& $NSISPath "`"$NSISScript`""

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: NSIS compilation failed!" -ForegroundColor Red
    Pop-Location
    exit 1
}

Pop-Location

# Move resulting setup to DistDir
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

$InstallerSource = Join-Path $ScriptDir "ArgusShield_Setup.exe"
$InstallerDest = Join-Path $DistDir "ArgusShield_Setup.exe"

if (Test-Path $InstallerSource) {
    Move-Item $InstallerSource -Destination $InstallerDest -Force
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  SUCCESS! Installer generated at:" -ForegroundColor Green
    Write-Host "  $InstallerDest" -ForegroundColor White
    Write-Host "========================================" -ForegroundColor Cyan
}