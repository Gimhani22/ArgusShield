# ArgusShield Installer Build Script
# Builds the PyInstaller executable and NSIS installer

param(
    [switch]$SkipPyInstaller,
    [switch]$SkipNSIS,
    [string]$PythonExe
)

$ErrorActionPreference = "Stop"

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$DistDir = Join-Path $ProjectDir "dist"
$SetupDir = $ScriptDir

function Resolve-PythonExe {
    param(
        [string]$ProjectDir
    )

    function Test-RealPython {
        param(
            [Parameter(Mandatory = $true)]
            [string]$PythonExe
        )

        try {
            $out = & $PythonExe -c "import sys; print(sys.executable)" 2>&1

            # Microsoft Store stub commonly prints this message and may still return 0
            if ($out -match "Python was not found" -or $out -match "go\.microsoft\.com/fwlink\?LinkID=135170") {
                return $false
            }

            if ($LASTEXITCODE -ne 0) { return $false }

            # Expect sys.executable to be a real file path to python.exe
            $exePath = ($out | Select-Object -First 1).Trim()
            if ([string]::IsNullOrWhiteSpace($exePath)) { return $false }
            if (-not ($exePath -like "*python*.exe")) { return $false }
            if (-not (Test-Path $exePath)) { return $false }
            if ($exePath -match "WindowsApps") { return $false }

            return $true
        } catch {
            return $false
        }
    }

    # 1) Prefer a local venv if present
    $venvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
    if ((Test-Path $venvPython) -and (Test-RealPython -PythonExe $venvPython)) {
        return $venvPython
    }

    # 2) Use python.exe if it resolves to a real interpreter (not Microsoft Store alias)
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd -and $pythonCmd.Source -and (Test-Path $pythonCmd.Source)) {
        if (Test-RealPython -PythonExe $pythonCmd.Source) {
            return $pythonCmd.Source
        }
    }

    # 3) Use the Python Launcher (py.exe) if present
    $pyCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCmd -and $pyCmd.Source) {
        if (Test-RealPython -PythonExe "py") {
            return "py"
        }
    }

    # 4) Probe common python.org install locations (PATH may not be refreshed in old terminals)
    $localPythonRoot = Join-Path $env:LOCALAPPDATA "Programs\Python"
    if (Test-Path $localPythonRoot) {
        $pythonDirs = Get-ChildItem -Path $localPythonRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "Python*" } |
            Sort-Object Name -Descending

        foreach ($dir in $pythonDirs) {
            $candidate = Join-Path $dir.FullName "python.exe"
            if ((Test-Path $candidate) -and (Test-RealPython -PythonExe $candidate)) {
                return $candidate
            }
        }
    }

    # 5) Probe registry install paths
    $regRoots = @(
        "HKCU:\Software\Python\PythonCore",
        "HKLM:\Software\Python\PythonCore",
        "HKLM:\Software\WOW6432Node\Python\PythonCore"
    )
    foreach ($regRoot in $regRoots) {
        if (-not (Test-Path $regRoot)) { continue }
        $versions = Get-ChildItem -Path $regRoot -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending
        foreach ($ver in $versions) {
            $installPathKey = Join-Path $ver.PSPath "InstallPath"
            try {
                $installPath = (Get-ItemProperty -Path $installPathKey -ErrorAction SilentlyContinue)."(default)"
                if ($installPath) {
                    $candidate = Join-Path $installPath "python.exe"
                    if ((Test-Path $candidate) -and (Test-RealPython -PythonExe $candidate)) {
                        return $candidate
                    }
                }
            } catch {
                # ignore
            }
        }
    }

    return $null
}

function Ensure-Pip {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExe
    )

    & $PythonExe -m pip -V *> $null
    if ($LASTEXITCODE -eq 0) { return }

    Write-Host "  pip not found. Bootstrapping pip (ensurepip)..." -ForegroundColor Yellow
    & $PythonExe -m ensurepip --upgrade
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to bootstrap pip (ensurepip)."
    }
}

function Ensure-PyInstaller {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExe
    )

    & $PythonExe -m PyInstaller --version *> $null
    if ($LASTEXITCODE -eq 0) { return }

    Ensure-Pip -PythonExe $PythonExe

    Write-Host "  PyInstaller not found. Installing it into the active Python environment..." -ForegroundColor Yellow
    & $PythonExe -m pip install --upgrade pip
    & $PythonExe -m pip install pyinstaller
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller."
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ArgusShield Installer Builder" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Resolve Python
if (-not $PythonExe) {
    $PythonExe = Resolve-PythonExe -ProjectDir $ProjectDir
}

if (-not $PythonExe) {
    Write-Host "ERROR: Python interpreter not found." -ForegroundColor Red
    Write-Host "Install Python 3.x (python.org) and ensure 'Add Python to PATH' is enabled." -ForegroundColor Red
    Write-Host "If PowerShell still uses the Windows Store alias, disable it: Settings > Apps > Advanced app settings > App execution aliases > turn off 'python.exe' and 'python3.exe'." -ForegroundColor Yellow
    exit 1
}

Write-Host "Using Python: $PythonExe" -ForegroundColor Gray
Write-Host ""

# Paths
$ServiceDir = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$ServiceExePath = Join-Path $ServiceDir "ArgusShieldService\x64\Debug\ArgusShieldService.exe"
$BinDir = Join-Path $ProjectDir "bin"

# Step 0: Copy service executable to bin folder
Write-Host "[0/4] Setting up bin folder with service executable..." -ForegroundColor Green

if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

if (Test-Path $ServiceExePath) {
    Copy-Item $ServiceExePath -Destination $BinDir -Force
    Write-Host "  Copied ArgusShieldService.exe to bin folder" -ForegroundColor Gray
} else {
    Write-Host "  WARNING: ArgusShieldService.exe not found at: $ServiceExePath" -ForegroundColor Yellow
    Write-Host "  Make sure to build the service project first!" -ForegroundColor Yellow
}

$AgentExePath = Join-Path $ServiceDir "ArgusShieldAgent\x64\Debug\ArgusShieldAgent.exe"
if (Test-Path $AgentExePath) {
    Copy-Item $AgentExePath -Destination $BinDir -Force
    Write-Host "  Copied ArgusShieldAgent.exe to bin folder" -ForegroundColor Gray
} else {
    Write-Host "  WARNING: ArgusShieldAgent.exe not found at: $AgentExePath" -ForegroundColor Yellow
    Write-Host "  Make sure to build the agent project first!" -ForegroundColor Yellow
}

Write-Host ""

# Step 1: Build Python executable with PyInstaller
if (-not $SkipPyInstaller) {
    Write-Host "[1/4] Building Python executable with PyInstaller..." -ForegroundColor Green
    Push-Location $ProjectDir

    Ensure-PyInstaller -PythonExe $PythonExe

    # Use spec file for admin privileges
    $SpecFile = Join-Path $ProjectDir "ArgusShield.spec"

    if (Test-Path $SpecFile) {
        Write-Host "  Using spec file: $SpecFile" -ForegroundColor Gray
        & $PythonExe -m PyInstaller --clean $SpecFile
    } else {
        Write-Host "  Building with default options (no spec file)..." -ForegroundColor Gray
        & $PythonExe -m PyInstaller --onefile --windowed --uac-admin --name=ArgusShield --clean src\ArgusShield.py
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

    $AppExePath = Join-Path $DistDir "ArgusShield.exe"
    if (-not (Test-Path $AppExePath)) {
        Write-Host "  ERROR: ArgusShield.exe not found in dist folder!" -ForegroundColor Red
        Write-Host "  Run without -SkipPyInstaller first." -ForegroundColor Red
        exit 1
    }

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

if (Test-Path (Join-Path $DistDir "ArgusShield.exe")) {
    Write-Host "  - ArgusShield.exe (standalone executable)" -ForegroundColor Gray
}
if (Test-Path (Join-Path $DistDir "ArgusShield_Setup.exe")) {
    Write-Host "  - ArgusShield_Setup.exe (installer)" -ForegroundColor Gray
}

Write-Host ""