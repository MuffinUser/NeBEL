# Copyright (C) 2026 Marwin Moellers
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Installs nebel from a GitHub release, for Windows:
#
#   irm https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.ps1 | iex
#
# From cmd.exe:
#   powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/MuffinUser/NeBEL/main/scripts/install.ps1 | iex"
#
# Env vars (set before piping into iex):
#   NEBEL_VERSION      tag to install, e.g. v0.5.2 (default: latest release)
#   NEBEL_INSTALL_DIR  where to put nebel.exe (default: $env:LOCALAPPDATA\Programs\nebel)
#
# Written for Windows PowerShell 5.1 as well as PowerShell 7+, and for
# running via `iex` (which executes in the caller's scope) as well as by
# double-click or `.\install.ps1` -- everything is wrapped in a function so
# a truncated download or a thrown error can't leak loose statements into
# the caller's shell, and errors use `throw` rather than `exit` so they
# don't close the caller's terminal.

function Install-Nebel {
    $prevEap = $ErrorActionPreference
    $prevProgress = $ProgressPreference
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        if (-not [Environment]::Is64BitOperatingSystem) {
            throw "nebel: only 64-bit Windows is supported"
        }

        $repo = 'MuffinUser/NeBEL'
        $version = $env:NEBEL_VERSION
        if (-not $version) {
            $version = Get-LatestNebelVersion -Repo $repo
        }
        $installDir = $env:NEBEL_INSTALL_DIR
        if (-not $installDir) {
            $installDir = Join-Path $env:LOCALAPPDATA 'Programs\nebel'
        }

        $asset = "nebel_${version}_windows_amd64.zip"
        $baseUrl = "https://github.com/$repo/releases/download/$version"

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('nebel-install-' + [Guid]::NewGuid().ToString())
        New-Item -ItemType Directory -Path $tmp | Out-Null
        try {
            Write-Host "nebel: downloading $asset ($version)"
            $zipPath = Join-Path $tmp $asset
            Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/$asset" -OutFile $zipPath
            $checksumsPath = Join-Path $tmp 'checksums.txt'
            Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/checksums.txt" -OutFile $checksumsPath

            Confirm-NebelChecksum -FilePath $zipPath -AssetName $asset -ChecksumsPath $checksumsPath

            Unblock-File -Path $zipPath
            $extractDir = Join-Path $tmp 'extracted'
            Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

            $exe = Get-ChildItem -Path $extractDir -Recurse -Filter 'nebel.exe' | Select-Object -First 1
            if (-not $exe) {
                throw "nebel: couldn't find nebel.exe inside $asset"
            }

            New-Item -ItemType Directory -Force -Path $installDir | Out-Null
            $destExe = Join-Path $installDir 'nebel.exe'
            Copy-Item -Path $exe.FullName -Destination $destExe -Force

            Add-NebelToUserPath -Dir $installDir
            Add-NebelToGitBashProfile -Dir $installDir

            Write-Host "nebel: installed to $destExe"
            Write-Host 'nebel: open a new terminal for PATH changes to take effect'
            Write-Host "nebel: if using IntelliJ's bundled Git Bash, fully restart IntelliJ (File > Exit, not just closing the project) for its PATH to pick this up"

            & $destExe version
        }
        finally {
            Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
        }
    }
    finally {
        $ErrorActionPreference = $prevEap
        $ProgressPreference = $prevProgress
    }
}

function Get-LatestNebelVersion {
    param([string]$Repo)

    # Invoke-WebRequest's response-URI property differs between Windows
    # PowerShell 5.1 (BaseResponse.ResponseUri) and PowerShell 7+
    # (BaseResponse.RequestMessage.RequestUri). Using the raw
    # HttpWebRequest redirect instead avoids that split entirely and
    # behaves the same on both.
    $req = [System.Net.HttpWebRequest]::Create("https://github.com/$Repo/releases/latest")
    $req.Method = 'HEAD'
    $req.AllowAutoRedirect = $false
    $location = $null
    try {
        $resp = $req.GetResponse()
        $location = $resp.Headers['Location']
        $resp.Close()
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($resp) {
            $location = $resp.Headers['Location']
            $resp.Close()
        }
    }
    if (-not $location) {
        throw 'nebel: could not resolve the latest release tag'
    }
    return ($location.TrimEnd('/') -split '/')[-1]
}

function Confirm-NebelChecksum {
    param(
        [string]$FilePath,
        [string]$AssetName,
        [string]$ChecksumsPath
    )
    $match = Get-Content -Path $ChecksumsPath | Where-Object { ($_ -split '\s+')[1] -eq $AssetName } | Select-Object -First 1
    if (-not $match) {
        throw "nebel: no checksum entry for $AssetName in checksums.txt"
    }
    $expected = ($match -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "nebel: checksum mismatch for $AssetName (expected $expected, got $actual)"
    }
}

function Add-NebelToUserPath {
    param([string]$Dir)
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries = @()
    if ($userPath) {
        $entries = @($userPath -split ';' | Where-Object { $_ -ne '' })
    }
    if ($entries -notcontains $Dir) {
        $newPath = if ($entries.Count -gt 0) { ($entries + $Dir) -join ';' } else { $Dir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }
    if (($env:Path -split ';') -notcontains $Dir) {
        $env:Path = "$env:Path;$Dir"
    }
}

function Add-NebelToGitBashProfile {
    param([string]$Dir)
    # Git Bash (including IntelliJ's bundled one) reads PATH from
    # ~/.bash_profile, not the Windows user PATH set above.
    $posix = '/' + $Dir.Substring(0, 1).ToLowerInvariant() + $Dir.Substring(2).Replace('\', '/')
    $profilePath = Join-Path $HOME '.bash_profile'
    $exportLine = "export PATH=`"`$PATH:$posix`""
    $existing = if (Test-Path $profilePath) { Get-Content $profilePath -Raw } else { '' }
    if ($existing -notmatch [regex]::Escape($posix)) {
        Add-Content -Path $profilePath -Value "`n$exportLine"
    }
}

Install-Nebel
