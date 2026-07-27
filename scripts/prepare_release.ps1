[CmdletBinding()]
param(
    [switch]$RequireCleanGit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )

    Write-Host "+ $Executable $($ArgumentList -join ' ')"
    & $Executable @ArgumentList

    $exitCode = $LASTEXITCODE
    if ($null -eq $exitCode) {
        $exitCode = 0
    }
    if ($exitCode -ne 0) {
        throw "Command failed with exit code $exitCode`: $Executable $($ArgumentList -join ' ')"
    }
}

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Invoke-Native -Executable "py" -ArgumentList @("-3.13", "-m", "venv", ".venv")
}

$Py = (Resolve-Path ".venv\Scripts\python.exe").Path

Invoke-Native -Executable $Py -ArgumentList @(
    "-m", "pip", "install", "--upgrade", "pip"
)

Invoke-Native -Executable $Py -ArgumentList @(
    "-m", "pip", "install", "-e", ".[dev,enterprise]"
)

$verifyArguments = @("scripts\verify_release.py", "--full")
if ($RequireCleanGit) {
    $verifyArguments += "--require-clean"
}
Invoke-Native -Executable $Py -ArgumentList $verifyArguments

Write-Host ""
Write-Host "Release preparation passed. Review release-output\SHA256SUMS.txt before tagging."

& git rev-parse --is-inside-work-tree *> $null
if ($LASTEXITCODE -eq 0) {
    Invoke-Native -Executable "git" -ArgumentList @("status", "--short", "--branch")
} else {
    Write-Warning "This folder is not yet a Git repository. Run 'git init' before using -RequireCleanGit or creating a release tag."
}
