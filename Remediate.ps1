# Remediate-NotepadPP.ps1 (PS 5.1-kompatibel, utan [ref] i loopar)

#region Parameters
$PackageId                   = 'notepadplusplus.install'  # systemomfattande paket
$ChocoSource                 = $null        # t.ex. 'https://community.chocolatey.org/api/v2/' eller intern feed
$InstallChocolateyIfMissing  = $true        # OPTION A enligt din begäran
$LogFolder                   = 'C:\Temp'
$LogFile                     = Join-Path $LogFolder 'Remediate-NotepadPP.log'
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

function Install-Choco {
    Write-Log "Installerar Chocolatey (kräver internet/admin)."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    Write-Log "Chocolatey installation klar."
}

function Close-NppProcess {
    $procs = Get-Process -Name 'notepad++' -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Log "Stänger Notepad++-process(er)."
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
}

function Get-NppInstalledVersions {
    $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $versions = New-Object System.Collections.Generic.List[version]

    foreach ($root in $roots) {
        if (Test-Path $root) {
            Get-ChildItem $root | ForEach-Object {
                $p = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue
                if ($p.DisplayName -and $p.DisplayName -like 'Notepad++*' -and $p.DisplayVersion) {
                    $ver = ConvertTo-VersionSafe -InputString $p.DisplayVersion
                    if ($ver) { [void]$versions.Add($ver) }
                }
            }
        }
    }

    if ($versions.Count -eq 0) {
        foreach ($exe in @('C:\Program Files\Notepad++\notepad++.exe','C:\Program Files (x86)\Notepad++\notepad++.exe')) {
            if (Test-Path $exe) {
                $fv = (Get-Item $exe).VersionInfo.ProductVersion
                $ver = ConvertTo-VersionSafe $fv
                if ($ver) { [void]$versions.Add($ver); break }
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

function Uninstall-ChocoPackages {
    foreach ($id in @('notepadplusplus','notepadplusplus.install','notepadplusplus.portable')) {
        try {
            $args=@('uninstall',$id,'-y','--force','--no-progress','--limit-output')
            if ($ChocoSource) { $args += @('--source',$ChocoSource) }
            Write-Log "Chocolatey: choco $($args -join ' ')"
            $null = choco @args 2>&1
        } catch {
            Write-Log "Varning: choco-uninstall '$id' gav fel: $($_.Exception.Message)" 'WARN'
        }
    }
}

function Uninstall-RegistryEntries {
    $roots=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root | ForEach-Object {
            $k=$_.PsPath; $p=Get-ItemProperty $k -ErrorAction SilentlyContinue
            if ($p.DisplayName -and $p.DisplayName -like 'Notepad++*') {
                try {
                    if ($p.WindowsInstaller -and $_.PSChildName -match '^\{[0-9A-F\-]+\}$') {
                        Write-Log "MSI-uninstall: $($p.DisplayName) {$($_.PSChildName)}"
                        Start-Process "msiexec.exe" -ArgumentList "/x $($_.PSChildName) /qn /norestart" -Wait -WindowStyle Hidden
                    } elseif ($p.UninstallString) {
                        $cmd=$p.UninstallString
                        if ($cmd -notmatch '(/S|/silent|/quiet|/qn)\b') { $cmd += ' /S' }
                        Write-Log "EXE-uninstall: $($p.DisplayName) via: $cmd"
                        Start-Process "cmd.exe" -ArgumentList "/c $cmd" -Wait -WindowStyle Hidden
                    }
                } catch {
                    Write-Log "Avinstallationsfel för '$($p.DisplayName)': $($_.Exception.Message)" 'WARN'
                }
            }
        }
    }
}

function Remove-NppLeftovers {
    foreach ($path in @(
        'C:\Program Files\Notepad++',
        'C:\Program Files (x86)\Notepad++',
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++"
    )) {
        try {
            if (Test-Path $path) { Write-Log "Rensar rest: $path"; Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue }
        } catch { Write-Log "Kunde inte ta bort $path $($_.Exception.Message)" 'WARN' }
    }
}
#endregion

#region Main
try {
    Initialize-Log
    $sourceLabel='standard'; if ($null -ne $ChocoSource -and $ChocoSource -ne '') { $sourceLabel=$ChocoSource }
    Write-Log ("Startar remediation: rensa alla gamla Notepad++ och installera senaste (maskinomfattande). Källa: {0}" -f $sourceLabel)

    if (-not (Test-Choco)) {
        if ($InstallChocolateyIfMissing) {
            Install-Choco
            if (-not (Test-Choco)) { Write-Log "Chocolatey saknas fortfarande efter installation." 'ERROR'; exit 1 }
        } else {
            Write-Log "Chocolatey saknas. Policy stoppar installation → avslutar 0."
            exit 0
        }
    }
    Write-Log "Chocolatey tillgängligt."

    $installed = Get-NppInstalledVersions
    if ($installed.Count -eq 0) {
        Write-Log "Notepad++ saknas. Policy: gör inget (compliant)."
        exit 0
    }

    if ($installed.Count -eq 1) {
        $latest = Get-LatestAvailableVersion
        Write-Log "Senaste tillgängliga version enligt källa: $latest"

        if ($installed[0] -eq $latest) {
            Write-Log "Redan senaste ($latest). Ingen åtgärd."
            exit 0
        }
    } else {
        Write-Log ("Dubbletter upptäckta: " + ($installed -join ', '))
    }

    Close-NppProcess
    Uninstall-ChocoPackages
    Uninstall-RegistryEntries
    Remove-NppLeftovers

    $args=@('upgrade',$PackageId,'-y','--force','--no-progress','--limit-output')
    if ($ChocoSource) { $args += @('--source',$ChocoSource) }
    Write-Log "Installerar: choco $($args -join ' ')"
    $out = choco @args 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Log "Chocolatey installer returnerade fel ($LASTEXITCODE)." 'ERROR'; exit 1 }

    $post = Get-NppInstalledVersions
    if ($post.Count -eq 0) { Write-Log "Verifiering misslyckades: ingen version hittad." 'ERROR'; exit 1 }
    $top  = ($post | Sort-Object -Descending | Select-Object -First 1)
    $latest = Get-LatestAvailableVersion

    if ($top -eq $latest) {
        Write-Log "Klar: Notepad++ $top installerad. Dubbletter kvar: $($post.Count-1)."
        exit 0
    } else {
        Write-Log "Installerad ($top) matchar inte senaste ($latest). (Källa kan ha uppdaterats)." 'WARN'
        exit 0
    }
}
catch {
    Write-Log "Ohanterat fel i remediation: $($_ | Out-String)" 'ERROR'
    exit 1
}
#endregion