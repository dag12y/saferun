#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DefaultVersion = 'v1.0.3'
$DefaultReleaseBaseUrl = 'https://github.com/dag12y/saferun/releases/download'

function Get-SafeRunVersion {
    if ([string]::IsNullOrWhiteSpace($env:SAFERUN_VERSION)) {
        return $DefaultVersion
    }
    return $env:SAFERUN_VERSION.Trim()
}

function Get-SafeRunReleaseBaseUrl {
    if ([string]::IsNullOrWhiteSpace($env:SAFERUN_RELEASE_BASE_URL)) {
        return $DefaultReleaseBaseUrl
    }
    return $env:SAFERUN_RELEASE_BASE_URL.TrimEnd('/')
}

function Get-SafeRunInstallDirectory {
    if (-not [string]::IsNullOrWhiteSpace($env:SAFERUN_INSTALL_DIR)) {
        return $env:SAFERUN_INSTALL_DIR
    }
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is not set; specify SAFERUN_INSTALL_DIR.'
    }
    return Join-Path $env:LOCALAPPDATA 'SafeRun\bin'
}

function Get-SafeRunArchitecture {
    $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if ([string]::IsNullOrWhiteSpace($nativeArchitecture)) {
        $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')
    }
    return Convert-SafeRunArchitecture -Architecture $nativeArchitecture
}

function Convert-SafeRunArchitecture {
    param([Parameter(Mandatory = $true)][string]$Architecture)

    switch ($Architecture.ToUpperInvariant()) {
        'AMD64' { return 'amd64' }
        'ARM64' { return 'arm64' }
        default { throw "Unsupported Windows architecture: $Architecture. Supported architectures: amd64 and arm64." }
    }
}

function Get-SafeRunReleaseInfo {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ReleaseBaseUrl,
        [Parameter(Mandatory = $true)][ValidateSet('amd64', 'arm64')][string]$Architecture
    )

    if ($ReleaseBaseUrl -notmatch '^https://') {
        throw 'SAFERUN_RELEASE_BASE_URL must use HTTPS.'
    }

    $binaryName = "saferun-windows-$Architecture.exe"
    $releaseUrl = "$($ReleaseBaseUrl.TrimEnd('/'))/$Version"
    return [pscustomobject]@{
        BinaryName = $binaryName
        BinaryUrl = "$releaseUrl/$binaryName"
        ChecksumsUrl = "$releaseUrl/SHA256SUMS"
    }
}

function Get-SafeRunChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$ChecksumsContent,
        [Parameter(Mandatory = $true)][string]$BinaryName
    )

    foreach ($line in ($ChecksumsContent -split "`r?`n")) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+[* ]?(.+?)\s*$' -and $Matches[2] -eq $BinaryName) {
            return $Matches[1].ToLowerInvariant()
        }
    }
    throw "SHA256SUMS does not contain a valid checksum for $BinaryName."
}

function Test-SafeRunChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Actual
    )
    return $Expected -ceq $Actual.ToLowerInvariant()
}

function Get-SafeRunPathUpdate {
    param(
        [AllowNull()][string]$ExistingPath,
        [Parameter(Mandatory = $true)][string]$InstallDirectory
    )

    $entries = @()
    if (-not [string]::IsNullOrWhiteSpace($ExistingPath)) {
        $entries = @($ExistingPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    $alreadyPresent = $entries | Where-Object { $_.TrimEnd('\') -ieq $InstallDirectory.TrimEnd('\') }
    return [pscustomobject]@{
        Added = ($null -eq $alreadyPresent)
        Path = if ($null -eq $alreadyPresent) { (($entries + $InstallDirectory) -join ';') } else { $ExistingPath }
    }
}

function Add-SafeRunUserPath {
    param([Parameter(Mandatory = $true)][string]$InstallDirectory)

    $existingPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $pathUpdate = Get-SafeRunPathUpdate -ExistingPath $existingPath -InstallDirectory $InstallDirectory
    if ($pathUpdate.Added) {
        [Environment]::SetEnvironmentVariable('Path', $pathUpdate.Path, 'User')
        return $true
    }
    return $false
}

function Write-SafeRunError {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Error "SafeRun installation failed: $Message"
}

function Invoke-SafeRunInstaller {
    $temporaryDirectory = $null
    $stagedPath = $null
    try {
        if ($env:OS -ne 'Windows_NT') {
            throw 'This installer supports Windows only.'
        }

        $version = Get-SafeRunVersion
        $releaseBaseUrl = Get-SafeRunReleaseBaseUrl
        $installDirectory = Get-SafeRunInstallDirectory
        $architecture = Get-SafeRunArchitecture
        $release = Get-SafeRunReleaseInfo -Version $version -ReleaseBaseUrl $releaseBaseUrl -Architecture $architecture

        Write-Host 'SafeRun Windows Installer' -ForegroundColor Cyan
        Write-Host '-------------------------'
        Write-Host "Version: $version"
        Write-Host "Architecture: $architecture"
        Write-Host "Download URL: $($release.BinaryUrl)"
        Write-Host "Installation directory: $installDirectory"
        Write-Host ''

        $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) "saferun-installer-$([guid]::NewGuid().ToString('N'))"
        New-Item -ItemType Directory -Path $temporaryDirectory -Force | Out-Null
        $downloadPath = Join-Path $temporaryDirectory $release.BinaryName
        $checksumsPath = Join-Path $temporaryDirectory 'SHA256SUMS'

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host 'Downloading SafeRun...'
        Invoke-WebRequest -Uri $release.BinaryUrl -OutFile $downloadPath -UseBasicParsing
        Write-Host 'Downloading checksums...'
        Invoke-WebRequest -Uri $release.ChecksumsUrl -OutFile $checksumsPath -UseBasicParsing

        $checksumsContent = [IO.File]::ReadAllText($checksumsPath)
        $expectedChecksum = Get-SafeRunChecksum -ChecksumsContent $checksumsContent -BinaryName $release.BinaryName
        $actualChecksum = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-Host 'Verifying checksum...'
        if (-not (Test-SafeRunChecksum -Expected $expectedChecksum -Actual $actualChecksum)) {
            throw "Checksum verification failed for $($release.BinaryName)."
        }
        Write-Host 'Checksum verified.' -ForegroundColor Green

        New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
        $destinationPath = Join-Path $installDirectory 'saferun.exe'
        $stagedPath = Join-Path $installDirectory ".saferun-$([guid]::NewGuid().ToString('N')).tmp"
        Copy-Item -LiteralPath $downloadPath -Destination $stagedPath -Force
        Move-Item -LiteralPath $stagedPath -Destination $destinationPath -Force
        $stagedPath = $null

        if (-not (Test-Path -LiteralPath $destinationPath -PathType Leaf)) {
            throw 'The installed executable was not found.'
        }
        $installedChecksum = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($installedChecksum -ne $expectedChecksum) {
            throw 'The installed executable failed post-install checksum verification.'
        }

        $pathAdded = Add-SafeRunUserPath -InstallDirectory $installDirectory
        if ($pathAdded) {
            Write-Host "PATH: added $installDirectory to the user PATH." -ForegroundColor Green
            $env:Path = "$installDirectory;$env:Path"
            Write-Host 'Open a new PowerShell session for the PATH change to be available everywhere.'
        }
        else {
            Write-Host 'PATH: installation directory is already in the user PATH.'
        }

        $versionOutput = & $destinationPath --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw 'The installed SafeRun executable could not be run.'
        }
        Write-Host "Installed binary: $versionOutput"
        Write-Host ''
        Write-Host 'SafeRun installed successfully.' -ForegroundColor Green
        Write-Host 'Next:'
        Write-Host '  saferun setup'
        Write-Host '  saferun npm install <package>'
        Write-Host 'SafeRun requires Docker for sandboxed package analysis.'
    }
    catch {
        Write-SafeRunError $_.Exception.Message
        throw
    }
    finally {
        if ($null -ne $stagedPath -and (Test-Path -LiteralPath $stagedPath)) {
            Remove-Item -LiteralPath $stagedPath -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $temporaryDirectory -and (Test-Path -LiteralPath $temporaryDirectory)) {
            Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SafeRunInstaller
}
