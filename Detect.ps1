# Detect-NotepadPP.ps1 (PS 5.1-kompatibel, robust när choco saknas)

#region Parameters
$PackageId   = 'notepadplusplus.install'
$ChocoSource = $null
$ExitCompliantWhenChocoMissing = $true
$LogFolder   = 'C:\Temp'
$LogFile     = Join-Path $LogFolder 'Detect-NotepadPP.log'
#endregion

#region Logging
$ErrorActionPreference = 'Stop'
function Initialize-Log {
    if (-not (Test-Path $LogFolder)) { New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null }
    Set-Content -Path $LogFile -Value ("[{0}] [INFO] Log initialized" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -Force
}
function Write-Log { param([Parameter(Mandatory)][string]$Message,[ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Level,$Message
    Add-Content -Path $LogFile -Value $line; Write-Output $line
}
#endregion

#region Helpers
function ConvertTo-VersionSafe { param([string]$InputString) try { [version]$InputString } catch { $null } }

function Test-Choco { try { Get-Command choco.exe -ErrorAction Stop | Out-Null; $true } catch { $false } }

function Get-NppInstalledVersions {
    $roots=@(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $versions = New-Object System.Collections.Generic.List[version]

    foreach ($root in $roots) {
        if (Test-Path $root) {
            Get-ChildItem $root | ForEach-Object {
                $p = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                if ($p.DisplayName -and $p.DisplayName -like 'Notepad++*' -and $p.DisplayVersion) {
                    $ver = ConvertTo-VersionSafe -InputString $p.DisplayVersion
                    if ($ver) { $versions.Add($ver) | Out-Null }
                }
            }
        }
    }

    if ($versions.Count -eq 0) {
        foreach ($exe in @('C:\Program Files\Notepad++\notepad++.exe','C:\Program Files (x86)\Notepad++\notepad++.exe')) {
            if (Test-Path $exe) {
                $fv = (Get-Item $exe).VersionInfo.ProductVersion
                $ver = ConvertTo-VersionSafe $fv
                if ($ver) { $versions.Add($ver) | Out-Null; break }
            }
        }
    }

    return ($versions | Sort-Object -Unique)
}

function Get-LatestAvailableVersion {
    $args=@('search',$PackageId,'--exact','--all-versions','--limit-output','--no-color')
    if ($ChocoSource) { $args += @('--source',$ChocoSource) }
    $out = choco @args 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $out) { throw "Kunde inte hämta versioner från källa." }

    $vers = $out | Where-Object {$_ -match '^\s*'+[regex]::Escape($PackageId)+'\|'} |
            ForEach-Object { ($_ -split '\|')[1] } |
            ForEach-Object { ConvertTo-VersionSafe $_ } |
            Where-Object { $_ } | Sort-Object -Descending

    if ($vers.Count -eq 0) { throw "Inga versioner för $PackageId på källan." }
    return $vers[0]
}
#endregion

#region Main
try {
    Initialize-Log
    $sourceLabel = 'standard'
    if ($null -ne $ChocoSource -and $ChocoSource -ne '') { $sourceLabel = $ChocoSource }
    Write-Log ("Startar detektion (källa: {0})." -f $sourceLabel)

    $installed = Get-NppInstalledVersions
    if ($installed.Count -gt 0) {
        Write-Log ("Installerade Notepad++-versioner: " + ($installed -join ', '))
    } else {
        Write-Log "Notepad++ saknas. Policy: compliant."
        exit 0
    }

    if ($installed.Count -gt 1) {
        Write-Log "Dubbletter hittade → Non-compliant."
        exit 1
    }

    $hasChoco = Test-Choco
    if (-not $hasChoco) {
        if ($ExitCompliantWhenChocoMissing) {
            Write-Log "Chocolatey hittades inte. Skippar versionsjämförelse (compliant)."
            exit 0
        } else {
            Write-Log "Chocolatey saknas och kan inte verifiera version → Non-compliant."
            exit 1
        }
    }

    $latest  = Get-LatestAvailableVersion
    Write-Log "Senaste tillgängliga version: $latest"

    $current = $installed | Select-Object -Last 1
    if ($current -eq $latest) {
        Write-Log "Compliant: Installerad version ($current) är senaste."
        exit 0
    } else {
        Write-Log "Non-compliant: Installerad ($current) != Senaste ($latest)."
        exit 1
    }
}
catch {
    Write-Log "Ohanterat fel i detektion: $($_ | Out-String)" 'ERROR'
    exit 1
}
#endregion