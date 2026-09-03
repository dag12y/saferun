# Requires Pester and PowerShell 5.1 or newer.
. (Join-Path $PSScriptRoot '..\install.ps1')

function Assert-SafeRunEqual {
    param([Parameter(Mandatory = $true)]$Actual, [Parameter(Mandatory = $true)]$Expected)
    if ($Actual -ne $Expected) {
        throw "Expected '$Expected' but got '$Actual'."
    }
}

function Assert-SafeRunThrows {
    param([Parameter(Mandatory = $true)][scriptblock]$Script)
    try {
        & $Script
    }
    catch {
        return
    }
    throw 'Expected the script to throw.'
}

Describe 'SafeRun Windows installer pure logic' {
    It 'maps supported architectures to release names' {
        Assert-SafeRunEqual (Convert-SafeRunArchitecture -Architecture 'AMD64') 'amd64'
        Assert-SafeRunEqual (Convert-SafeRunArchitecture -Architecture 'ARM64') 'arm64'
        Assert-SafeRunEqual (Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download' -Architecture 'amd64').BinaryName 'saferun-windows-amd64.exe'
        Assert-SafeRunEqual (Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download' -Architecture 'arm64').BinaryName 'saferun-windows-arm64.exe'
    }

    It 'rejects unsupported architectures' {
        Assert-SafeRunThrows { Convert-SafeRunArchitecture -Architecture 'x86' }
    }

    It 'maps the Windows PowerShell x64 identifier without RuntimeInformation' {
        Assert-SafeRunEqual (Convert-SafeRunArchitecture -Architecture 'AMD64') 'amd64'
        if ((Get-Command Get-SafeRunArchitecture).ScriptBlock.ToString() -match 'RuntimeInformation') { throw 'RuntimeInformation must not be used.' }
    }

    It 'supports the native architecture reported for a 32-bit process' {
        Assert-SafeRunEqual (Convert-SafeRunArchitecture -Architecture 'ARM64') 'arm64'
    }

    It 'constructs release URLs without duplicate separators' {
        $release = Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download/' -Architecture 'amd64'
        Assert-SafeRunEqual $release.BinaryUrl 'https://example.test/releases/download/v1.0.3/saferun-windows-amd64.exe'
        Assert-SafeRunEqual $release.ChecksumsUrl 'https://example.test/releases/download/v1.0.3/SHA256SUMS'
    }

    It 'rejects non-HTTPS release sources' {
        Assert-SafeRunThrows { Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'http://example.test/releases' -Architecture 'amd64' }
    }

    It 'parses the exact binary checksum' {
        $checksum = 'A' * 64
        $checksums = ('B' * 64) + "  saferun-linux-amd64`n" + $checksum + " *saferun-windows-amd64.exe`n"
        Assert-SafeRunEqual (Get-SafeRunChecksum -ChecksumsContent $checksums -BinaryName 'saferun-windows-amd64.exe') $checksum.ToLowerInvariant()
    }

    It 'rejects a missing checksum' {
        Assert-SafeRunThrows { Get-SafeRunChecksum -ChecksumsContent ('A' * 64) -BinaryName 'saferun-windows-arm64.exe' }
    }

    It 'rejects a checksum mismatch' {
        Assert-SafeRunEqual (Test-SafeRunChecksum -Expected ('A' * 64) -Actual ('B' * 64)) $false
    }

    It 'uses the configured installation directory' {
        $env:SAFERUN_INSTALL_DIR = 'C:\SafeRun\custom-bin'
        try {
            Assert-SafeRunEqual (Get-SafeRunInstallDirectory) 'C:\SafeRun\custom-bin'
        }
        finally {
            Remove-Item Env:SAFERUN_INSTALL_DIR -ErrorAction SilentlyContinue
        }
    }

    It 'adds PATH once and preserves existing entries' {
        $update = Get-SafeRunPathUpdate -ExistingPath 'C:\Tools;C:\SafeRun\bin' -InstallDirectory 'c:\saferun\bin'
        Assert-SafeRunEqual $update.Added $false
        Assert-SafeRunEqual $update.Path 'C:\Tools;C:\SafeRun\bin'

        $update = Get-SafeRunPathUpdate -ExistingPath 'C:\Tools' -InstallDirectory 'C:\SafeRun\bin'
        Assert-SafeRunEqual $update.Added $true
        Assert-SafeRunEqual $update.Path 'C:\Tools;C:\SafeRun\bin'
    }
}
