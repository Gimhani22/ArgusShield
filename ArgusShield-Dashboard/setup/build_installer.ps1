# ArgusShield Installer Build Script
# This script builds the PyInstaller executable and NSIS installer

param(
    [switch]$SkipPyInstaller,
    [switch]$SkipNSIS
)

$ErrorActionPreference = "Stop"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$DistDir = Join-Path $ProjectDir "dist"
$SetupDir = $ScriptDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ArgusShield Installer Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Build Python executable with PyInstaller
if (-not $SkipPyInstaller) {
    Write-Host "[1/4] Building Python executable with PyInstaller..." -ForegroundColor Green
    
    Push-Location $ProjectDir
    
    # Use spec file for admin privileges
    $SpecFile = Join-Path $ProjectDir "app.spec"
    
    if (Test-Path $SpecFile) {
        Write-Host "  Using spec file: $SpecFile" -ForegroundColor Gray
        & python -m PyInstaller --clean $SpecFile
    } else {
        # Fallback to direct build with admin privileges
        Write-Host "  Building with default options (no spec file)..." -ForegroundColor Gray
        & python -m PyInstaller --onefile --windowed --uac-admin --name=app --clean app.py
    }
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: PyInstaller failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    # Copy icon to dist folder if exists
    $IconPath = Join-Path $ProjectDir "icon.ico"
    if (Test-Path $IconPath) {
        Copy-Item $IconPath -Destination $DistDir -Force
        Write-Host "  Copied icon to dist folder" -ForegroundColor Gray
    }
    
    Pop-Location
    Write-Host "  PyInstaller build complete!" -ForegroundColor Green
} else {
    Write-Host "[1/4] Skipping PyInstaller build..." -ForegroundColor Yellow
}

Write-Host ""

# Step 2: Check if NSIS is installed
Write-Host "[2/4] Checking NSIS installation..." -ForegroundColor Green

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
    Write-Host "  WARNING: NSIS not found!" -ForegroundColor Yellow
    Write-Host "  Please install NSIS from: https://nsis.sourceforge.io/Download" -ForegroundColor Yellow
    Write-Host "  After installing NSIS, re-run this script." -ForegroundColor Yellow
    
    if (-not $SkipNSIS) {
        $response = Read-Host "  Do you want to continue without building installer? (y/n)"
        if ($response -ne 'y') {
            exit 1
        }
        $SkipNSIS = $true
    }
} else {
    Write-Host "  NSIS found at: $NSISPath" -ForegroundColor Gray
}

Write-Host ""

# Step 3: Create license file if not exists
Write-Host "[3/4] Checking license file..." -ForegroundColor Green

$LicensePath = Join-Path $SetupDir "license.txt"
if (-not (Test-Path $LicensePath)) {
    Write-Host "  Creating default license file..." -ForegroundColor Gray
    @"
ArgusShield - DLL Injection Detector
=====================================

Copyright (c) 2026 ArgusShield Security
All Rights Reserved.

This software is provided for educational and security research purposes.

By installing this software, you agree to use it responsibly and in 
accordance with all applicable laws and regulations.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
"@ | Out-File -FilePath $LicensePath -Encoding UTF8
    Write-Host "  License file created." -ForegroundColor Gray
} else {
    Write-Host "  License file exists." -ForegroundColor Gray
}

Write-Host ""

# Step 4: Build NSIS installer
if (-not $SkipNSIS -and $NSISPath) {
    Write-Host "[4/4] Building NSIS installer..." -ForegroundColor Green
    
    # Check if app.exe exists
    $AppExePath = Join-Path $DistDir "app.exe"
    if (-not (Test-Path $AppExePath)) {
        Write-Host "  ERROR: app.exe not found in dist folder!" -ForegroundColor Red
        Write-Host "  Run without -SkipPyInstaller first." -ForegroundColor Red
        exit 1
    }
    
    # Compile NSIS script
    $NSISScript = Join-Path $SetupDir "setup_script.nsi"
    
    Push-Location $SetupDir
    
    Write-Host "  Running: $NSISPath $NSISScript" -ForegroundColor Gray
    & $NSISPath $NSISScript
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: NSIS compilation failed!" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Pop-Location
    
    # Move installer to dist folder
    $InstallerSource = Join-Path $SetupDir "ArgusShield_Setup.exe"
    $InstallerDest = Join-Path $DistDir "ArgusShield_Setup.exe"
    
    if (Test-Path $InstallerSource) {
        Move-Item $InstallerSource -Destination $InstallerDest -Force
        Write-Host "  Installer created: $InstallerDest" -ForegroundColor Green
    }
} else {
    Write-Host "[4/4] Skipping NSIS installer build..." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files in: $DistDir" -ForegroundColor White

if (Test-Path (Join-Path $DistDir "app.exe")) {
    Write-Host "  - app.exe (standalone executable)" -ForegroundColor Gray
}
if (Test-Path (Join-Path $DistDir "ArgusShield_Setup.exe")) {
    Write-Host "  - ArgusShield_Setup.exe (installer)" -ForegroundColor Gray
}

Write-Host ""