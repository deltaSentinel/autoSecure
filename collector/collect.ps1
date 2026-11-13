<# =====================================================================
File: collect.ps1 — AutoSecure WINDOWS posture collector
Place beside the Linux collector package (does not import it).

SCHEMA CONTRACT (Phase 0):
  Emits the same snapshot envelope as collector/collect.py:
    { meta: {...}, features_raw: {...}, features_ml: {...} }

  features_ml carries THE SAME 25 core keys as the Linux collector:
    - Keys with a genuine Windows analog are populated.
    - Keys that are structurally inapplicable on Windows are emitted
      as null (NOT omitted) so downstream consumers see an identical
      key set: risk_ssh_permit_root_login, risk_ssh_password_auth,
      risk_ssh_empty_passwords, risk_world_writable_etc_files,
      risk_world_writable_dirs_no_sticky, risk_suid_binaries,
      risk_sgid_binaries, risk_shadow_*, risk_fail2ban_absent,
      risk_pending_security_updates (WU classification is locale-
      dependent -> unreliable).
    - TWO deliberate semantic bridges (both auditable in features_raw
      and both flagged here):
        risk_users_uid0_extra    <- extra members of local
                                    Administrators (minus -ExpectedAdmins)
        risk_sudo_nopasswd       <- UAC EnableLUA=0 (privilege elevation
                                    without challenge; closest analog)
  PLUS additive Windows extension keys (risk_win_*). Until the model is
  retrained cross-platform, arb_experiment/train code should select the
  25-key core intersection; extensions are for slicing + future training.

  features_raw uses Windows-native section names (win_*). Linux L0
  rules never touch them; Windows-specific L0 rules get written later.

Usage (elevated PowerShell, en-US VM strongly recommended):
  sudo-equivalent check is automatic; most probes need admin.

  .\collect.ps1 -HostId win-target-a -Tag baseline -Out ..\dataset -Label clean
  .\collect.ps1 -HostId win-target-a -Tag W01-applied -Out ..\dataset `
                -Label vulnerable -Inject W01 -ExpectedAdmins Administrator
  .\collect.ps1 -HostId w -Tag x -Fast      # skip slow WUA COM search

Known limitations (documented, not hidden):
  - net accounts / manage-bde / netsh outputs are LOCALE-SENSITIVE.
    Parsing targets English; other locales degrade to null with a
    check error rather than a wrong number. Build the VM with en-US.
  - Pending-updates COM search can take minutes and may fail offline.
    Use -Fast in the air-gapped lab.
  - SMB1 registry value absent -> null (cannot distinguish a pre-1709
    default from a post-1709 default without more probing).
===================================================================== #>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HostId,
    [Parameter(Mandatory = $true)][string]$Tag,
    [string]$Out = ".",
    [ValidateSet("clean", "vulnerable")][string]$Label = $null,
    [string[]]$Inject = @(),
    [string[]]$ExpectedAdmins = @("Administrator"),
    [switch]$Fast
)

$COLLECTOR_VERSION = "0.1.0-win"
$script:CheckErrors = New-Object System.Collections.Generic.List[string]

# --------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path $Path) {
            $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
            return $v
        }
    } catch {
        try { return (Get-Item $Path -ErrorAction Stop).GetValue($Name) } catch { return $null }
    }
    return $null
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --------------------------------------------------------------------
# checks (each returns a hashtable; failures -> null + check error)
# --------------------------------------------------------------------

function Get-Ports {
    $tcp = @(); $udp = @()
    try {
        $tcp = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            ForEach-Object { [int]$_.LocalPort })
        $udp = @(Get-NetUDPEndpoint -ErrorAction Stop |
            ForEach-Object { [int]$_.LocalPort })
    } catch {
        # netstat fallback for older boxes lacking the NetTCPIP module
        try {
            $lines = netstat -an | Select-String '^\s*(TCP|UDP)'
            foreach ($l in $lines) {
                $p = ($l.ToString().Trim() -split '\s+')
                $addr = $p[1]
                $port = [int]$addr.Substring($addr.LastIndexOf(':') + 1)
                if ($p[0] -eq 'TCP' -and $p[3] -match 'Listen') { $tcp += $port }
                elseif ($p[0] -eq 'UDP') { $udp += $port }
            }
        } catch {
            $script:CheckErrors.Add("services:ports_failed:$($_.Exception.Message)")
            return $null
        }
    }
    return @{
        tcp = @($tcp | Sort-Object -Unique)
        udp = @($udp | Sort-Object -Unique)
    }
}

function Get-AdminMembers {
    try {
        return @(Get-LocalGroupMember -Group Administrators -ErrorAction Stop |
            ForEach-Object { $_.Name })
    } catch {
        try {
            $grp = [ADSI]"WinNT://./Administrators,group"
            $names = @()
            foreach ($m in $grp.Invoke('Members')) {
                $names += $m.GetType().InvokeMember('Name', 'GetProperty', $null, $m, $null)
            }
            return $names
        } catch {
            $script:CheckErrors.Add("win_accounts:admin_enum_failed")
            return $null
        }
    }
}

function Get-LocalUsersSafe {
    try { return @(Get-LocalUser -ErrorAction Stop) }
    catch { $script:CheckErrors.Add("win_accounts:user_enum_failed"); return $null }
}

function Get-AccountPolicy {
    # net accounts output is LOCALE-SENSITIVE; only English parses.
    $out = net accounts 2>$null
    if (-not $out) { $script:CheckErrors.Add("win_policy:net_accounts_failed"); return $null }
    $text = $out -join "`n"
    $minLen = $null; $maxAge = $null
    if ($text -match '(?im)minimum\s+password\s+length.*?:\s*(\d+)\s*$')  { $minLen = [int]$Matches[1] }
    if ($text -match '(?im)maximum\s+password\s+age.*?:\s*(\d+)\s*$')      { $maxAge = [int]$Matches[1] }
    if ($null -eq $minLen -and $null -eq $maxAge) {
        $script:CheckErrors.Add("win_policy:net_accounts_parse_failed_locale")
    }
    return @{ min_len = $minLen; max_age = $maxAge }
}

function Get-FirewallState {
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
        $state = [ordered]@{}
        foreach ($p in $profiles) { $state[$p.Name] = [bool]$p.Enabled }
        $active = ($profiles.Count -gt 0) -and
                  (@($profiles | Where-Object { -not $_.Enabled }).Count -eq 0)
        return @{ profiles = $state; active = [bool]$active }
    } catch {
        $script:CheckErrors.Add("win_netdef:fw_query_failed")
        return @{ profiles = $null; active = $null }
    }
}

function Get-AutoUpdateState {
    # AUOptions: 1=never check 2=notify download 3=auto download+notify
    #            install 4=auto install 5=disabled
    $au = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions'
    if ($null -ne $au) {
        switch ([int]$au) {
            3       { return $true }
            4       { return $true }
            1       { return $false }
            2       { return $false }
            5       { return $false }
            default { return $null }
        }
    }
    # fall back to service state: wuauserv disabled => definitely not auto
    $svc = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.StartType -eq 'Disabled') { return $false }
        return $null        # enabled service but no readable AU setting
    }
    return $null
}

function Get-PendingUpdates {
    # COM search can take MINUTES and requires connectivity.
    if ($Fast) {
        $script:CheckErrors.Add("updating:skipped_fast_flag")
        return @{ total = $null; security = $null }
    }
    try {
        $sess = New-Object -ComObject Microsoft.Update.Session
        $searcher = $sess.CreateUpdateSearcher()
        $res = $searcher.Search("IsInstalled=0")
        # security split skipped: WU categories are localized -> unreliable
        return @{ total = [int]$res.Updates.Count; security = $null }
    } catch {
        $script:CheckErrors.Add("updating:wua_com_failed")
        return @{ total = $null; security = $null }
    }
}

function Get-RunningServicesCount {
    try { return [int](@(Get-Service | Where-Object { $_.Status -eq 'Running' })).Count }
    catch { $script:CheckErrors.Add("services:svc_enum_failed"); return $null }
}

function Get-SshdPresence {
    # OpenSSH-for-Windows ships optionally; mirror Linux semantics when
    # present, null (N/A) when the host simply doesn't run sshd.
    $svc = Get-Service sshd -ErrorAction SilentlyContinue
    if ($svc) { return ($svc.Status -eq 'Running') }
    return $null
}

function Get-DefenderStatus {
    try {
        $st = Get-MpComputerStatus -ErrorAction Stop
        return @{ rtp_enabled = [bool]$st.RealTimeProtectionEnabled
                  service_running = [bool]$st.AMServiceEnabled }
    } catch {
        $script:CheckErrors.Add("win_defender:query_failed_or_absent")
        return $null
    }
}

function Get-BitLockerStatus {
    $drv = "$env:SystemDrive"
    try {
        $out = manage-bde -status $drv 2>$null
        if ($LASTEXITCODE -ne 0) {
            $script:CheckErrors.Add("win_bitlocker:manage_bde_failed")
            return $null
        }
        $text = $out -join "`n"
        if ($text -match 'Protection\s+Status:\s+Protection\s+On')  { return @{ protected = $true } }
        if ($text -match 'Protection\s+Status:\s+Protection\s+Off') { return @{ protected = $false } }
        $script:CheckErrors.Add("win_bitlocker:parse_failed_locale")
        return $null
    } catch {
        $script:CheckErrors.Add("win_bitlocker:query_failed")
        return $null
    }
}

function Get-Smb1Status {
    $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
    if ($null -eq $v) { return $null }   # absent: can't infer default era
    return [bool][int]$v
}

function Get-UacStatus {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    if ($null -eq $v) { return $true }   # documented default = enabled
    return [bool][int]$v
}

function Get-AutologonStatus {
    $v = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    return ($v -eq "1")
}

# --------------------------------------------------------------------
# run everything
# --------------------------------------------------------------------

$elevated   = Test-Elevated
$ports      = Get-Ports
$adminList  = Get-AdminMembers
$users      = Get-LocalUsersSafe
$policy     = Get-AccountPolicy
$fw         = Get-FirewallState
$autoUpd    = Get-AutoUpdateState
$pending    = Get-PendingUpdates
$svcCount   = Get-RunningServicesCount
$sshdRun    = Get-SshdPresence
$defender   = Get-DefenderStatus
$bitlocker  = Get-BitLockerStatus
$smb1       = Get-Smb1Status
$uac        = Get-UacStatus
$autologon  = Get-AutologonStatus

# --- derived account data -------------------------------------------------

$adminExtra = $null
$noPwUsers  = $null
$enabledUserCount = $null
if ($null -ne $adminList) {
    $adminExtra = @($adminList | ForEach-Object {
        $short = ($_ -split '\\')[-1]
        if ($ExpectedAdmins -notcontains $short) { $_ }
    })
}
if ($null -ne $users) {
    $noPwUsers = @($users | Where-Object { -not $_.PasswordRequired } |
        ForEach-Object { $_.Name })
    $enabledUserCount = [int](@($users | Where-Object { $_.Enabled })).Count
}

# --- derived network flags -------------------------------------------------

$tcpPorts = @(); $udpPorts = @()
if ($null -ne $ports) { $tcpPorts = $ports.tcp; $udpPorts = $ports.udp }

$telnetOpen = $null; $ftpOpen = $null; $snmpOpen = $null
$rdpOpen = $null; $winrmOpen = $null
if ($null -ne $ports) {
    $telnetOpen = [bool](23   -in $tcpPorts)
    $ftpOpen    = [bool](21   -in $tcpPorts)
    $snmpOpen   = [bool](161  -in $udpPorts)
    $rdpOpen    = [bool](3389 -in $tcpPorts)
    $winrmOpen  = [bool]((5985 -in $tcpPorts) -or (5986 -in $tcpPorts))
}

# ssh parity only meaningful when sshd actually runs on the box
$sshPortRisk = $null
if ($sshdRun -eq $true)  { $sshPortRisk = [int][bool](22 -in $tcpPorts) }
if ($sshdRun -eq $false) { $sshPortRisk = 0 }

# --- derived policy risks ---------------------------------------------------

$weakPolicy = $null
if ($null -ne $policy) {
    $minLen = $policy.min_len; $maxAge = $policy.max_age
    if ($null -ne $minLen -or $null -ne $maxAge) {
        # NOTE deviation from Linux rule (>90 = weak): on Windows
        # max_age 0 == password NEVER EXPIRES, which is the weak case.
        $weakPolicy = [int](
            ($null -ne $minLen -and $minLen -lt 8) -or
            ($null -ne $maxAge -and $maxAge -eq 0))
    }
}

$numPorts = $null
if ($null -ne $ports) {
    $numPorts = [Math]::Min([int](@($tcpPorts + $udpPorts | Sort-Object -Unique)).Count, 60)
}

$pendTotal = $null
if ($null -ne $pending -and $null -ne $pending.total) {
    $pendTotal = [Math]::Min([int]$pending.total, 100)
}

$clipSvcCount = $null
if ($null -ne $svcCount) { $clipSvcCount = [Math]::Min([int]$svcCount, 80) }

# --------------------------------------------------------------------
# features_raw (Windows-native section names)
# --------------------------------------------------------------------

$featuresRaw = [ordered]@{
    win_accounts  = [ordered]@{
        admin_members        = $adminList
        admin_expected       = $ExpectedAdmins
        admin_extra          = $adminExtra
        users_no_password    = $noPwUsers
        enabled_user_count   = $enabledUserCount
    }
    win_policy     = [ordered]@{
        min_password_length  = $policy.min_len
        max_password_age     = $policy.max_age
    }
    win_netdef     = [ordered]@{
        firewall_profiles    = $fw.profiles
        firewall_active       = $fw.active
    }
    win_updating   = [ordered]@{
        auto_updates_enabled = $autoUpd
        pending_updates      = $pending.total
        wu_backend           = "wua"
    }
    win_services   = [ordered]@{
        tcp_ports            = $tcpPorts
        udp_ports            = $udpPorts
        telnet_open          = $telnetOpen
        ftp_open             = $ftpOpen
        snmp_open            = $snmpOpen
        rdp_open             = $rdpOpen
        winrm_open           = $winrmOpen
        sshd_running         = $sshdRun
        running_services     = $svcCount
    }
    win_winlogon   = [ordered]@{ autologon_enabled = $autologon }
    win_defender   = [ordered]@{
        rtp_enabled          = if ($defender) { $defender.rtp_enabled } else { $null }
        service_running      = if ($defender) { $defender.service_running } else { $null }
    }
    win_bitlocker  = [ordered]@{
        protected            = if ($bitlocker) { $bitlocker.protected } else { $null }
    }
    win_smb        = [ordered]@{ smb1_enabled = $smb1 }
    win_uac        = [ordered]@{ uac_enabled = $uac }
}

# --------------------------------------------------------------------
# features_ml — 25 core keys (identical key set to Linux), in the SAME
# order, null where N/A; then additive risk_win_* extensions.
# --------------------------------------------------------------------

$featuresMl = [ordered]@{
    risk_ssh_permit_root_login        = $null          # N/A
    risk_ssh_password_auth            = $null          # N/A
    risk_ssh_empty_passwords          = $null          # N/A
    risk_world_writable_etc_files     = $null          # N/A
    risk_world_writable_dirs_no_sticky = $null         # N/A
    risk_suid_binaries                = $null          # N/A
    risk_sgid_binaries                = $null          # N/A
    risk_shadow_world_readable        = $null          # N/A
    risk_shadow_group_writable        = $null          # N/A
    risk_users_uid0_extra             = if ($null -ne $adminExtra)   { [int]([Math]::Min($adminExtra.Count, 5)) } else { $null }
    risk_users_empty_password         = if ($null -ne $noPwUsers)    { [int]([Math]::Min($noPwUsers.Count, 5)) }  else { $null }
    risk_sudo_nopasswd                = if ($null -ne $uac)         { [int](-not $uac) }                         else { $null }
    num_accounts_with_shell           = if ($null -ne $enabledUserCount) { [int]([Math]::Min($enabledUserCount, 30)) } else { $null }
    risk_weak_password_policy         = $weakPolicy
    risk_firewall_disabled            = if ($null -ne $fw.active)    { [int](-not $fw.active) }  else { $null }
    risk_fail2ban_absent              = $null          # N/A
    risk_autoupdates_disabled         = if ($null -ne $autoUpd)      { [int](-not $autoUpd) }   else { $null }
    risk_pending_updates              = $pendTotal
    risk_pending_security_updates     = $null          # WU categories localized; unreliable
    risk_telnet_open                  = if ($null -ne $telnetOpen)  { [int]$telnetOpen }       else { $null }
    risk_ftp_open                     = if ($null -ne $ftpOpen)     { [int]$ftpOpen }          else { $null }
    risk_snmp_open                    = if ($null -ne $snmpOpen)    { [int]$snmpOpen }         else { $null }
    risk_ssh_default_port_open        = $sshPortRisk
    num_listening_ports               = $numPorts
    num_running_services              = $clipSvcCount

    # ---- additive Windows extensions (select-out until retraining) ----
    risk_win_defender_rtp_disabled    = if ($defender) { [int](-not $defender.rtp_enabled) }  else { $null }
    risk_win_bitlocker_absent         = if ($bitlocker) { [int](-not $bitlocker.protected) }  else { $null }
    risk_win_smb1_enabled             = if ($null -ne $smb1) { [int]$smb1 }                  else { $null }
    risk_win_autologon_enabled        = [int]$autologon
    risk_win_uac_disabled             = [int](-not $uac)
    risk_win_rdp_open                 = if ($null -ne $rdpOpen)   { [int]$rdpOpen }          else { $null }
    risk_win_winrm_open               = if ($null -ne $winrmOpen) { [int]$winrmOpen }        else { $null }
}

# --------------------------------------------------------------------
# snapshot + emit
# --------------------------------------------------------------------

$osInfo = $null
try { $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }

$snapshot = [ordered]@{
    meta = [ordered]@{
        collector_version    = $COLLECTOR_VERSION
        collected_at         = [DateTime]::UtcNow.ToString("o")
        host_id              = $HostId
        tag                  = $Tag
        label                = $Label
        injected_misconfigs  = @($Inject)
        ran_as_root          = [bool]$elevated          # schema parity; means "elevated"
        check_errors         = @($script:CheckErrors)
        platform             = "windows"
        os_release_id        = "windows"
        os_version_id        = if ($osInfo) { $osInfo.Version } else { $null }
        os_caption           = if ($osInfo) { $osInfo.Caption } else { $null }
        pkg_backend          = "wua"
    }
    features_raw = $featuresRaw
    features_ml  = $featuresMl
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$safe  = ($HostId + "_" + $Tag) -replace '[^A-Za-z0-9_-]+', '_'
$fname = Join-Path $Out ("{0}_{1}.json" -f $safe, $stamp)

$json = $snapshot | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($fname, $json + "`n")

$nFeats = @($featuresMl.Keys).Count
$nNone  = @($featuresMl.Values | Where-Object { $null -eq $_ }).Count
Write-Host "[+] wrote $fname"
Write-Host ("[+] {0} ML features ({1} unresolved, {2} check errors)" -f `
    ($nFeats + @($featuresMl.Keys).Count - $nFeats), $nNone, $script:CheckErrors.Count)
Write-Host "[+] label=$Label inject=$(if ($Inject) { $Inject -join ',' } else { 'none' })"
