# windows_audit.ps1
# Collects Windows host security state and emits a single JSON document to stdout.
# Invoked from WSL by security_audit.py via powershell.exe.
# Read-only: this script never changes settings.

$ErrorActionPreference = 'SilentlyContinue'

function Safe($block) {
    try { & $block } catch { @{ error = $_.Exception.Message } }
}

$result = [ordered]@{}

# --- OS info ---
$result.os = Safe {
    $os = Get-CimInstance Win32_OperatingSystem
    @{
        caption       = $os.Caption
        version       = $os.Version
        build         = $os.BuildNumber
        install_date  = $os.InstallDate
        last_boot     = $os.LastBootUpTime
        architecture  = $os.OSArchitecture
    }
}

# --- Windows Defender ---
$result.defender = Safe {
    $mp = Get-MpComputerStatus
    @{
        antivirus_enabled        = $mp.AntivirusEnabled
        realtime_protection      = $mp.RealTimeProtectionEnabled
        tamper_protection        = $mp.IsTamperProtected
        signature_age_days       = $mp.AntivirusSignatureAge
        signature_last_updated   = $mp.AntivirusSignatureLastUpdated
        quick_scan_age_days      = $mp.QuickScanAge
        full_scan_age_days       = $mp.FullScanAge
        engine_version           = $mp.AMEngineVersion
    }
}

$result.defender_threats = Safe {
    Get-MpThreatDetection | Select-Object -First 20 | ForEach-Object {
        @{
            threat_id       = $_.ThreatID
            name            = (Get-MpThreat -ThreatID $_.ThreatID).ThreatName
            detection_time  = $_.InitialDetectionTime
            action_success  = $_.ActionSuccess
            resources       = $_.Resources
        }
    }
}

# --- Firewall ---
$result.firewall = Safe {
    Get-NetFirewallProfile | ForEach-Object {
        @{
            profile         = $_.Name
            enabled         = $_.Enabled.ToString()
            default_inbound = $_.DefaultInboundAction.ToString()
            default_outbound= $_.DefaultOutboundAction.ToString()
        }
    }
}

# --- SMB config (SMBv1 is a classic LAN risk) ---
$result.smb = Safe {
    $cfg = Get-SmbServerConfiguration
    @{
        smb1_enabled               = $cfg.EnableSMB1Protocol
        smb2_enabled               = $cfg.EnableSMB2Protocol
        require_signing            = $cfg.RequireSecuritySignature
        encrypt_data               = $cfg.EncryptData
        guest_auth                 = $cfg.EnableInsecureGuestLogons
    }
}

$result.smb_shares = Safe {
    Get-SmbShare | Where-Object { $_.Name -notmatch '^[A-Z]\$$|^IPC\$$|^ADMIN\$$' } | ForEach-Object {
        @{
            name        = $_.Name
            path        = $_.Path
            description = $_.Description
        }
    }
}

# --- Local accounts ---
$result.local_users = Safe {
    Get-LocalUser | ForEach-Object {
        @{
            name              = $_.Name
            enabled           = $_.Enabled
            last_logon        = $_.LastLogon
            password_required = $_.PasswordRequired
            password_last_set = $_.PasswordLastSet
            password_expires  = $_.PasswordExpires
        }
    }
}

$result.administrators = Safe {
    Get-LocalGroupMember -Group "Administrators" | ForEach-Object {
        @{ name = $_.Name; type = $_.ObjectClass.ToString() }
    }
}

# --- Pending Windows Updates ---
$result.pending_updates = Safe {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $hits     = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $hits.Updates | ForEach-Object {
        @{
            title    = $_.Title
            severity = $_.MsrcSeverity
            kb       = ($_.KBArticleIDs -join ',')
            security = $_.CveIDs.Count -gt 0
        }
    }
}

# --- UAC ---
$result.uac = Safe {
    $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    @{
        enabled         = (Get-ItemProperty $key).EnableLUA -eq 1
        consent_prompt  = (Get-ItemProperty $key).ConsentPromptBehaviorAdmin
    }
}

# --- BitLocker ---
$result.bitlocker = Safe {
    Get-BitLockerVolume | ForEach-Object {
        @{
            mount_point      = $_.MountPoint
            protection_status= $_.ProtectionStatus.ToString()
            encryption_pct   = $_.EncryptionPercentage
            volume_type      = $_.VolumeType.ToString()
        }
    }
}

# --- Auto-start programs ---
$result.startup = Safe {
    Get-CimInstance Win32_StartupCommand | ForEach-Object {
        @{ name = $_.Name; command = $_.Command; location = $_.Location; user = $_.User }
    }
}

# --- Installed software (via winget if available, else registry) ---
$result.software = Safe {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $output = winget list --accept-source-agreements 2>$null | Out-String
        # winget output is human-formatted; we send it as-is, the LLM can parse it.
        # Cap length so we don't blow the prompt.
        if ($output.Length -gt 30000) { $output = $output.Substring(0, 30000) + "...[truncated]" }
        @{ source = 'winget'; raw = $output }
    } else {
        $apps = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        @{ source = 'registry'; apps = $apps }
    }
}

# --- Listening ports (cross-check with what nmap sees externally) ---
$result.listening_ports = Safe {
    Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess -Unique | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        @{
            address = $_.LocalAddress
            port    = $_.LocalPort
            pid     = $_.OwningProcess
            process = if ($proc) { $proc.ProcessName } else { 'unknown' }
        }
    }
}

# --- RDP exposure ---
$result.rdp = Safe {
    @{
        enabled = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0
        nla_required = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1
    }
}

# Emit a single compact JSON object. Depth 6 is enough for our shape.
$result | ConvertTo-Json -Depth 6 -Compress
