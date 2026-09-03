[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$solution = Join-Path $projectRoot 'AmdHypervisorDetector.sln'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$visualStudioPath = & $vswhere -latest -products Microsoft.VisualStudio.Product.Community -property installationPath
if (-not $visualStudioPath) {
    throw 'Visual Studio Community with the Desktop C++ workload and WDK integration is required.'
}

$msbuild = Join-Path $visualStudioPath 'MSBuild\Current\Bin\amd64\MSBuild.exe'
$driverToolset = Join-Path $visualStudioPath 'MSBuild\Microsoft\VC\v180\Platforms\x64\PlatformToolsets\WindowsKernelModeDriver10.0'
if (-not (Test-Path -LiteralPath $msbuild)) {
    throw "MSBuild was not found at $msbuild"
}
if (-not (Test-Path -LiteralPath $driverToolset)) {
    throw 'The WindowsKernelModeDriver10.0 platform toolset is not integrated into this Visual Studio installation.'
}

& $msbuild $solution `
    /m `
    /t:Rebuild `
    /p:Configuration=$Configuration `
    /p:Platform=x64 `
    /p:WindowsTargetPlatformVersion=10.0.28000.0 `
    /p:SignMode=Off `
    /v:minimal
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE."
}

$binaryDirectory = Join-Path $projectRoot "bin\x64\$Configuration"
if (-not $SkipTests) {
    $testExecutable = Join-Path $binaryDirectory 'AmdHypervisorDetectorTests.exe'
    & $testExecutable
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed with exit code $LASTEXITCODE."
    }
}

$artifactDirectory = Join-Path $projectRoot "artifacts\$Configuration"
New-Item -ItemType Directory -Path $artifactDirectory -Force | Out-Null

$files = @(
    'AmdHypervisorDetector.exe',
    'AmdHypervisorDetector.pdb',
    'AmdHvDetectorDriver.sys',
    'AmdHvDetectorDriver.pdb'
)
foreach ($file in $files) {
    $source = Join-Path $binaryDirectory $file
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination $artifactDirectory -Force
    }
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $artifactDirectory -Force

Write-Host "Build and validation succeeded. Artifacts: $artifactDirectory"
Write-Host 'The driver was built unsigned and was not loaded or mapped.'

