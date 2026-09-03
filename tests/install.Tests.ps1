# Requires Pester 5 and PowerShell 5.1 or newer.
BeforeAll {
    . (Join-Path $PSScriptRoot '..\install.ps1')
}

Describe 'SafeRun Windows installer pure logic' {
    It 'maps supported architectures to release names' {
        Convert-SafeRunArchitecture -Architecture 'X64' | Should -Be 'amd64'
        Convert-SafeRunArchitecture -Architecture 'Arm64' | Should -Be 'arm64'
        (Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download' -Architecture 'amd64').BinaryName | Should -Be 'saferun-windows-amd64.exe'
        (Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download' -Architecture 'arm64').BinaryName | Should -Be 'saferun-windows-arm64.exe'
    }

    It 'rejects unsupported architectures' {
        { Convert-SafeRunArchitecture -Architecture 'X86' } | Should -Throw
    }

    It 'constructs release URLs without duplicate separators' {
        $release = Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'https://example.test/releases/download/' -Architecture 'amd64'
        $release.BinaryUrl | Should -Be 'https://example.test/releases/download/v1.0.3/saferun-windows-amd64.exe'
        $release.ChecksumsUrl | Should -Be 'https://example.test/releases/download/v1.0.3/SHA256SUMS'
    }

    It 'rejects non-HTTPS release sources' {
        { Get-SafeRunReleaseInfo -Version 'v1.0.3' -ReleaseBaseUrl 'http://example.test/releases' -Architecture 'amd64' } | Should -Throw
    }

    It 'parses the exact binary checksum' {
        $checksum = 'A' * 64
        $checksums = ('B' * 64) + "  saferun-linux-amd64`n" + $checksum + " *saferun-windows-amd64.exe`n"
        Get-SafeRunChecksum -ChecksumsContent $checksums -BinaryName 'saferun-windows-amd64.exe' | Should -Be $checksum.ToLowerInvariant()
    }

    It 'rejects a missing checksum' {
        { Get-SafeRunChecksum -ChecksumsContent ('A' * 64) -BinaryName 'saferun-windows-arm64.exe' } | Should -Throw
    }

    It 'rejects a checksum mismatch' {
        Test-SafeRunChecksum -Expected ('A' * 64) -Actual ('B' * 64) | Should -BeFalse
    }

    It 'uses the configured installation directory' {
        $env:SAFERUN_INSTALL_DIR = 'C:\SafeRun\custom-bin'
        try {
            Get-SafeRunInstallDirectory | Should -Be 'C:\SafeRun\custom-bin'
        }
        finally {
            Remove-Item Env:SAFERUN_INSTALL_DIR -ErrorAction SilentlyContinue
        }
    }

    It 'adds PATH once and preserves existing entries' {
        $update = Get-SafeRunPathUpdate -ExistingPath 'C:\Tools;C:\SafeRun\bin' -InstallDirectory 'c:\saferun\bin'
        $update.Added | Should -BeFalse
        $update.Path | Should -Be 'C:\Tools;C:\SafeRun\bin'

        $update = Get-SafeRunPathUpdate -ExistingPath 'C:\Tools' -InstallDirectory 'C:\SafeRun\bin'
        $update.Added | Should -BeTrue
        $update.Path | Should -Be 'C:\Tools;C:\SafeRun\bin'
    }
}
