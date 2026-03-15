<#
.SYNOPSIS
    Bulk Secure Boot 2023 certificate remediation for VMware VMs on ESXi 8.
    Optionally takes a snapshot before making any changes. Includes rollback,
    snapshot cleanup, and NVRAM cleanup modes for post-validation housekeeping.
    Includes a read-only assessment mode (-Assess) and hardware version upgrade
    mode (-UpgradeHardware).

    Process per VM (default):
    0. BitLocker safety check
    1. Take snapshot (skipped with -NoSnapshot)
    2. Power off
    2b. Upgrade hardware version (only if -UpgradeHardware specified)
    3. Rename .nvram -> .nvram_old (ESXi regenerates with 2023 KEK on next boot)
    4. Power on, wait for Tools, verify 2023 certs in new NVRAM
    5. Clear any stale Servicing registry state
    6. Set AvailableUpdates = 0x5944, trigger Secure-Boot-Update task
    7. Reboot, trigger task again
    8. Verify final status
    9. Remove snapshot on success (unless -RetainSnapshots or -NoSnapshot)

.PARAMETER VMName
    One or more VM display names. Accepts wildcards. Can be combined with
    -VMListCsv - both sources are merged and deduplicated.
    If neither VMName nor VMListCsv is specified, targets all in-scope
    Windows Server VMs with Secure Boot enabled (main mode) or all Windows
    Server VMs (cleanup/rollback modes).

.PARAMETER VMListCsv
    Path to a CSV file containing VM names to target. The CSV must have a
    column named "VMName". Any other columns are ignored, which means you can
    feed the script's own output CSVs directly back in as input to re-run or
    clean up a specific batch. Can be combined with -VMName.

.PARAMETER GuestCredential
    Guest OS credential (domain admin). Required for the main remediation
    mode. Not required for -CleanupSnapshots, -CleanupNvram, or -Rollback.

.PARAMETER NoSnapshot
    Skip snapshot creation entirely. Use when datastore space is constrained
    or snapshots are managed externally. Cannot be combined with
    -RetainSnapshots. Note: without a snapshot there is no automated rollback
    path - the -Rollback mode will still restore the .nvram_old file if one
    exists, but cannot revert VM state (registry changes etc.).

.PARAMETER Confirm
    Suppress the "Continue? (Y/N)" prompt and proceed automatically. Use this
    when running the script unattended or in a scheduled task, and you have
    already verified sufficient datastore space for snapshots.

.PARAMETER RetainSnapshots
    Keep snapshots even on success. Use this when you want to validate VMs
    over a period of days before removing snapshots. Use -CleanupSnapshots
    later to remove them. Cannot be combined with -NoSnapshot.

.PARAMETER CleanupSnapshots
    Snapshot cleanup mode. Finds and removes all Pre-SecureBoot-Fix* snapshots
    on target VMs. Does not require -GuestCredential. Run this after a
    validation period to reclaim datastore space.
    Always run -CleanupSnapshots BEFORE -CleanupNvram - the snapshot is your
    rollback path.

.PARAMETER CleanupHWSnapshots
    Hardware upgrade snapshot cleanup mode. Finds and removes all
    Pre-HWUpgrade* snapshots created by standalone -UpgradeHardware runs.
    Does not require -GuestCredential. Run this after verifying the hardware
    version upgrade is stable and no rollback is needed.

.PARAMETER CleanupNvram
    NVRAM cleanup mode. Finds and deletes all .nvram_old files left on target
    VM datastores. Does not require -GuestCredential. Run this AFTER
    -CleanupSnapshots, once you are fully satisfied there are no issues and
    no rollback will be needed. The script will warn if a VM still has a
    Pre-SecureBoot-Fix* snapshot, indicating the validation period may not
    be complete.

.PARAMETER Rollback
    Rollback mode. For each target VM:
      - Powers off the VM
      - Renames the current .nvram -> .nvram_new (preserves it)
      - Renames .nvram_old -> .nvram (restores original NVRAM)
      - Reverts to the Pre-SecureBoot-Fix* snapshot if one exists
      - Powers the VM back on
    Does not require -GuestCredential. If no snapshot exists the NVRAM is
    still restored, but VM state (registry changes etc.) will not be reverted.

.PARAMETER PKDerPath
    Path to WindowsOEMDevicesPK.der downloaded from the Microsoft secureboot_objects
    GitHub repository. When provided, the script enrolls a valid Platform Key on any
    VM where the PK is NULL, invalid, or an ESXi-generated placeholder (Valid_Other)
    after cert remediation. VMs with a proper Microsoft or OEM PK are skipped.

    Download:
    https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der

    Required for step 9 PK remediation. If omitted, invalid/placeholder PKs are
    reported in the output CSV but not remediated.

    NOTE: The script converts WindowsOEMDevicesPK.der from DER certificate
    format to EFI Signature List format internally via Format-SecureBootUEFI.
    No manual conversion is required.

.PARAMETER KEKDerPath
    Path to the Microsoft KEK 2K CA 2023 certificate in DER format. Optional - only
    needed if the KEK 2023 cert is somehow absent after NVRAM regeneration (should
    not occur on ESXi 8.0.2+). Download:
    https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/KEK/Certificates/microsoft%20corporation%20kek%202k%20ca%202023.der

.PARAMETER WaitSeconds
    Seconds to wait after issuing a reboot before polling for Tools.
    Default 90. Increase for slower VMs.

.PARAMETER IgnoreCertificateWarnings
    When specified, sets PowerCLI InvalidCertificateAction to Ignore for the
    current session before connecting to vCenter. Only use this if your vCenter
    uses a self-signed or otherwise untrusted certificate and you have accepted
    that risk. Omitting this flag leaves your existing PowerCLI certificate
    configuration unchanged. If your vCenter has a properly signed certificate
    this flag is not needed and should not be used.

.PARAMETER Assess
    Read-only assessment mode. No changes are made to any VM. Collects current
    state for all target VMs and outputs a CSV and console summary identifying
    which VMs need remediation and what steps are required. Includes hardware
    version, ESXi host version, firmware type, Secure Boot state, KEK/DB/PK
    certificate status, registry deployment status, event log signals, BitLocker
    state, and snapshot/nvram_old presence.
    If -GuestCredential is provided, guest-level data (cert status, registry,
    events, BitLocker) is collected from powered-on VMs with Tools running.
    If -GuestCredential is omitted, only hypervisor-level data is collected.
    No VMs are powered on or off. Mutually exclusive with all action modes.

.PARAMETER UpgradeHardware
    Upgrades VM hardware version to the latest version supported by the host.
    Hardware version 21 or later is required for ESXi to populate regenerated
    NVRAM with the 2023 KEK certificate.
    Standalone use (-UpgradeHardware only, no -GuestCredential): powers off
    each VM, takes a snapshot by default for rollback purposes, upgrades
    hardware version, powers back on. Use -NoSnapshot to skip the snapshot.
    Combined use (-UpgradeHardware with -GuestCredential): hardware upgrade is
    performed between step 2 (power off) and step 3 (NVRAM rename) as part of
    the full remediation sequence; the snapshot taken at step 1 serves as the
    rollback point. VMs already at version 21 or later are skipped automatically.
    NOTE: VMware does not provide a supported API or UI method to downgrade VM
    hardware versions. A snapshot is the only supported rollback path. Reverting
    to the pre-upgrade snapshot restores the previous hardware version.

.EXAMPLE
    # Run fix on a single VM, remove snapshot on success
    .\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred

    # Run fix without taking snapshots
    .\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred -NoSnapshot

    # Run fix on a batch using a CSV file, retain snapshots for review
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred -RetainSnapshots

    # Combine VMName and VMListCsv (merged and deduplicated)
    .\FixSecureBootBulk.ps1 -VMName "vm01" -VMListCsv ".\batch1.csv" -GuestCredential $cred

    # Run fix on all VMs matching a wildcard, retain snapshots
    .\FixSecureBootBulk.ps1 -VMName "AppServer*" -GuestCredential $cred -RetainSnapshots

    # Rollback specific VMs
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -Rollback

    # Rollback using a previous run's output CSV
    .\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260227_124728.csv" -Rollback

    # After validation period - remove snapshots for specific VMs
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02","vm03","vm04" -CleanupSnapshots

    # After validation period - remove snapshots for ALL VMs at once
    .\FixSecureBootBulk.ps1 -CleanupSnapshots

    # Feed a previous run's output CSV back in to clean up snapshots for that batch
    .\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260227_124728.csv" -CleanupSnapshots

    # After snapshots are removed - delete .nvram_old files for ALL VMs
    .\FixSecureBootBulk.ps1 -CleanupNvram

    # Feed a previous run's output CSV back in to clean up NVRAM for that batch
    .\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260227_124728.csv" -CleanupNvram

    # Remove Pre-HWUpgrade* snapshots after verifying hardware upgrade is stable
    .\FixSecureBootBulk.ps1 -CleanupHWSnapshots

    # Remove Pre-HWUpgrade* snapshots for specific VMs
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -CleanupHWSnapshots

    # Full remediation including PK enrollment (recommended - download WindowsOEMDevicesPK.der first)
    .\FixSecureBootBulk.ps1 -VMListCsv ".atch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

    # Full remediation with PK enrollment and BitLocker key backup
    .\FixSecureBootBulk.ps1 -VMListCsv ".atch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -BitLockerBackupShare "\\fileserver\BitLockerKeys"

    # Assess all VMs - hypervisor-level data only (no guest credentials needed)
    .\FixSecureBootBulk.ps1 -Assess

    # Assess all VMs - full data including guest cert and registry status
    .\FixSecureBootBulk.ps1 -Assess -GuestCredential $cred

    # Assess specific VMs
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -Assess -GuestCredential $cred

    # Upgrade hardware version only (snapshot taken by default for rollback)
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardware

    # Upgrade hardware version without taking a snapshot
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardware -NoSnapshot

    # Run unattended without the datastore space confirmation prompt
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm

    # Full remediation including hardware version upgrade
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -UpgradeHardware

.NOTES
    Do not include domain controllers in automated runs - handle DCs manually.
    VMs with BitLocker active will be skipped unless -BitLockerBackupShare is
    provided, in which case recovery keys are backed up to the share and
    BitLocker is suspended for the duration of the process.
    PK remediation (-PKDerPath) requires ESXi 8.0+ hosts. VMs with a proper
    Microsoft or OEM PK (Valid_WindowsOEM / Valid_Microsoft) are skipped for the
    PK step automatically. ESXi-generated placeholder PKs (Valid_Other) are treated
    as needing enrollment per Broadcom KB 423919.
    References: Broadcom KB 423893, KB 423919, Microsoft secureboot_objects GitHub.
    Ensure sufficient datastore space for snapshots before running large batches.
    Requires VMware.PowerCLI module and an active vCenter connection, or
    the script will prompt for vCenter credentials on first run.
#>

param(
    [string[]]$VMName,
    [string]$VMListCsv,
    [PSCredential]$GuestCredential,
    [switch]$NoSnapshot,
    [switch]$Confirm,
    [switch]$RetainSnapshots,
    [switch]$CleanupSnapshots,
    [switch]$CleanupHWSnapshots,
    [switch]$CleanupNvram,
    [switch]$Rollback,
    [string]$BitLockerBackupShare,
    [string]$PKDerPath,
    [string]$KEKDerPath,
    [int]$WaitSeconds = 90,
    [switch]$IgnoreCertificateWarnings,
    [switch]$Assess,
    [switch]$UpgradeHardware
)

# =============================================================================
# PARAMETER VALIDATION
# =============================================================================
if ($NoSnapshot -and $RetainSnapshots) {
    Write-Error "-NoSnapshot and -RetainSnapshots cannot be used together."
    return
}

$modeSwitches = @($CleanupSnapshots, $CleanupHWSnapshots, $CleanupNvram, $Rollback, $Assess) | Where-Object { $_ }
if ($modeSwitches.Count -gt 1) {
    Write-Error "-CleanupSnapshots, -CleanupHWSnapshots, -CleanupNvram, -Rollback, and -Assess are mutually exclusive. Specify only one."
    return
}
if ($Assess -and ($NoSnapshot -or $RetainSnapshots -or $BitLockerBackupShare -or $PKDerPath -or $KEKDerPath)) {
    Write-Error "-Assess is read-only and cannot be combined with -NoSnapshot, -RetainSnapshots, -BitLockerBackupShare, -PKDerPath, or -KEKDerPath."
    return
}
if ($UpgradeHardware -and ($CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram -or $Rollback -or $Assess)) {
    Write-Error "-UpgradeHardware cannot be combined with -CleanupSnapshots, -CleanupHWSnapshots, -CleanupNvram, -Rollback, or -Assess."
    return
}
if ($BitLockerBackupShare) {
    if (-not (Test-Path $BitLockerBackupShare)) {
        Write-Error "BitLockerBackupShare path not accessible: $BitLockerBackupShare"
        Write-Error "Ensure the share exists and is writable from this machine."
        return
    }
    Write-Host "BitLocker backup share: $BitLockerBackupShare" -ForegroundColor Yellow
    Write-Warning "Recovery keys written to this share are sensitive. Ensure access is restricted to authorized administrators."
    Write-Host ""
}

if ($PKDerPath -and -not (Test-Path $PKDerPath)) {
    Write-Error "PKDerPath not found: $PKDerPath"
    Write-Error "Download WindowsOEMDevicesPK.der from:"
    Write-Error "  https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
    return
}
if ($KEKDerPath -and -not (Test-Path $KEKDerPath)) {
    Write-Error "KEKDerPath not found: $KEKDerPath"
    return
}
if ($PKDerPath) {
    Write-Host "PK der file : $PKDerPath" -ForegroundColor Cyan
    if ($KEKDerPath) { Write-Host "KEK der file: $KEKDerPath" -ForegroundColor Cyan }
}

# =============================================================================
# VCENTER CONNECTION
# Update the server name below to match your vCenter instance.
# =============================================================================
if (-not $global:DefaultVIServer) {
    if ($IgnoreCertificateWarnings) {
        Write-Warning "-IgnoreCertificateWarnings specified: disabling certificate validation for this session."
        Write-Warning "Only use this flag if your vCenter certificate is self-signed or untrusted and you have accepted that risk."
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false
    }
    Connect-VIServer -Server "vcenter.yourdomain.com" -Credential (Get-Credential -Message "vCenter credentials")
}

$isMainMode         = -not $CleanupSnapshots -and -not $CleanupHWSnapshots -and -not $CleanupNvram -and -not $Rollback -and -not $Assess -and -not ($UpgradeHardware -and -not $GuestCredential)
$isStandaloneUpgrade = $UpgradeHardware -and -not $GuestCredential
if ($isMainMode -and -not $GuestCredential) {
    $GuestCredential = Get-Credential -Message "Guest OS credentials (domain admin)"
}
if ($Assess -and $GuestCredential) {
    Write-Host "Assess mode: guest-level data will be collected (cert status, registry, events, BitLocker)." -ForegroundColor Cyan
} elseif ($Assess) {
    Write-Host "Assess mode: hypervisor-level data only (-GuestCredential not provided)." -ForegroundColor Yellow
}

$snapshotBaseName = "Pre-SecureBoot-Fix"
$snapshotName     = "${snapshotBaseName}_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# =============================================================================
# CSV VALIDATION
# Validates path and required column up front to fail fast before any vCenter
# operations, rather than discovering a bad path mid-run.
# =============================================================================
$csvVMNames = @()
if ($VMListCsv) {
    if (-not (Test-Path -Path $VMListCsv -PathType Leaf)) {
        Write-Error "VMListCsv path not found: $VMListCsv"
        return
    }
    try {
        $csvData = Import-Csv -Path $VMListCsv -ErrorAction Stop
    } catch {
        Write-Error "Failed to read CSV file '$VMListCsv': $($_.Exception.Message)"
        return
    }
    if (-not ($csvData | Get-Member -Name "VMName" -ErrorAction SilentlyContinue)) {
        Write-Error "CSV file '$VMListCsv' does not contain a 'VMName' column. Expected a header row with at least a 'VMName' column."
        return
    }
    $csvVMNames = $csvData | Where-Object { $_.VMName -ne "" } |
                  Select-Object -ExpandProperty VMName -Unique
    Write-Host "Loaded $($csvVMNames.Count) VM name(s) from CSV: $VMListCsv" -ForegroundColor Cyan
}

# =============================================================================
# RESOLVE-TARGETVMS
# Merges -VMName and -VMListCsv into a single deduplicated VM list.
# When neither is specified, falls back to querying all in-scope VMs.
# The -SecureBootFilter switch applies EFI/SecureBoot filtering used by the
# main remediation loop, but is skipped in cleanup/rollback modes.
# =============================================================================
function Resolve-TargetVMs {
    param([switch]$SecureBootFilter)

    $names = @()
    if ($VMName)     { $names += $VMName     }
    if ($csvVMNames) { $names += $csvVMNames }
    $names = $names | Select-Object -Unique

    if ($names.Count -gt 0) {
        # When specific VM names are provided, look them up directly.
        # Do not apply OS or Secure Boot filters - the operator has explicitly
        # named the target VMs and guest info may be stale after a revert or reboot.
        $resolved = foreach ($name in $names) {
            $found = Get-VM -Name $name -ErrorAction SilentlyContinue
            if (-not $found) {
                Write-Warning "VM not found in vCenter: '$name' - skipping."
            }
            $found
        }
        $resolved = $resolved | Where-Object { $_ } | Sort-Object -Property Id -Unique
        return $resolved
    }

    # No names specified - return all in-scope Windows VMs.
    # OSFullName filter is only safe here since we are querying all VMs
    # and need to narrow the scope to Windows guests.
    $all = Get-VM | Where-Object { $_.Guest.OSFullName -match "Windows (Server|10|11)" }
    if ($SecureBootFilter) {
        $all = $all | Where-Object {
            $_.ExtensionData.Config.Firmware -eq "efi" -and
            $_.ExtensionData.Config.BootOptions.EfiSecureBootEnabled -eq $true
        }
    }
    return $all
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

function Wait-VMTools {
    param($VMObj, [int]$TimeoutSeconds = 300)
    $elapsed = 0
    Write-Host "    Waiting for VMware Tools..." -ForegroundColor Gray
    while ($elapsed -lt $TimeoutSeconds) {
        $current = Get-VM -Name $VMObj.Name
        if ($current.Guest.State -eq "Running") {
            Start-Sleep -Seconds 15  # Extra buffer after Tools report ready
            return $true
        }
        Start-Sleep -Seconds 10
        $elapsed += 10
        Write-Host "    ...${elapsed}s" -ForegroundColor DarkGray
    }
    Write-Warning "Timed out waiting for VMware Tools on $($VMObj.Name)"
    return $false
}

function New-VMSnapshotSafe {
    param($VMObj, [string]$Name, [string]$Description)
    try {
        New-Snapshot -VM $VMObj -Name $Name -Description $Description `
            -Memory:$false -Quiesce:$false -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "    Snapshot created: '$Name'" -ForegroundColor Green
        return $true
    } catch {
        Write-Warning "    Snapshot failed: $($_.Exception.Message)"
        return $false
    }
}

function Remove-VMSnapshotSafe {
    param($VMObj, [string]$Name)
    try {
        $snap = Get-Snapshot -VM $VMObj -Name $Name -ErrorAction SilentlyContinue
        if ($snap) {
            Remove-Snapshot -Snapshot $snap -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "    Snapshot removed: '$Name'" -ForegroundColor Green
        }
    } catch {
        Write-Warning "    Could not remove snapshot '$Name': $($_.Exception.Message)"
        Write-Warning "    Remove manually via vSphere client when ready."
    }
}

# Shared helper: returns the datastore context needed for file operations.
# Used by both Rename-VMNvram and Restore-VMNvram to avoid duplicating the
# browser/filemanager setup in every caller.
function Get-VMDatastoreContext {
    param($VMObj)
    $vmView  = $VMObj | Get-View
    $vmxPath = $vmView.Config.Files.VmPathName
    $dsName  = $vmxPath -replace '^\[(.+?)\].*',         '$1'
    $vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'
    $ds      = Get-Datastore -Name $dsName -ErrorAction Stop

    $datacenter      = Get-Datacenter -VM $VMObj
    $datacenterView  = $datacenter | Get-View
    $serviceInstance = Get-View ServiceInstance

    return @{
        DsName      = $dsName
        VmDir       = $vmDir
        DsBrowser   = Get-View $ds.ExtensionData.Browser
        DcRef       = $datacenterView.MoRef
        FileManager = Get-View $serviceInstance.Content.FileManager
    }
}

# Waits for an async datastore file operation task. Returns $true on success.
function Wait-DatastoreTask {
    param($Task, [int]$TimeoutSeconds = 30)
    $taskView = Get-View $Task
    $elapsed  = 0
    while ($taskView.Info.State -notin @("success","error") -and $elapsed -lt $TimeoutSeconds) {
        Start-Sleep -Seconds 2
        $elapsed += 2
        $taskView = Get-View $Task
    }
    if ($taskView.Info.State -eq "success") { return $true }
    Write-Warning "    Datastore task failed: $($taskView.Info.Error.LocalizedMessage)"
    return $false
}

# Upgrades VM hardware version to the latest supported by the host.
# Returns a hashtable: { Upgraded = $true/$false; FromVersion = N; ToVersion = N; Notes = "" }
function Invoke-VMHardwareUpgrade {
    param($VMObj)
    $result = @{ Upgraded = $false; FromVersion = ""; ToVersion = ""; Notes = "" }
    try {
        $vmView     = $VMObj | Get-View
        $currentVer = $vmView.Config.Version  # e.g. "vmx-19"
        $currentNum = [int]($currentVer -replace 'vmx-', '')
        $result.FromVersion = $currentNum

        # Get the maximum hardware version supported by the host
        $vmHost      = Get-VMHost -VM $VMObj -ErrorAction Stop
        $hostView    = $vmHost | Get-View
        $maxVerStr   = ($hostView.Capability.SupportedEVCMode |
            Where-Object { $_ -match 'vmx-' } |
            ForEach-Object { [int]($_ -replace '.*vmx-(\d+).*','$1') } |
            Measure-Object -Maximum).Maximum
        if (-not $maxVerStr) {
            # Fallback: use Get-VMHostHardware or derive from ESXi version
            $esxiVer = [version]$vmHost.Version
            $maxVerStr = switch ($esxiVer.Major) {
                9 { 22 }
                8 { 21 }
                7 { 19 }
                default { 21 }
            }
        }
        $result.ToVersion = $maxVerStr

        if ($currentNum -ge $maxVerStr) {
            $result.Notes = "Already at version $currentNum - no upgrade needed."
            return $result
        }

        Write-Host "    Upgrading hardware version: $currentNum -> $maxVerStr" -ForegroundColor Gray
        $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
        $spec.Version = "vmx-$maxVerStr"
        $task = $vmView.ReconfigVM_Task($spec)
        $taskView = Get-View $task
        $elapsed  = 0
        while ($taskView.Info.State -notin @('success','error') -and $elapsed -lt 60) {
            Start-Sleep -Seconds 3; $elapsed += 3
            $taskView = Get-View $task
        }
        if ($taskView.Info.State -eq 'success') {
            Write-Host "    Hardware version upgraded to $maxVerStr." -ForegroundColor Green
            $result.Upgraded = $true
        } else {
            $result.Notes = "Upgrade failed: $($taskView.Info.Error.LocalizedMessage)"
            Write-Warning "    $($result.Notes)"
        }
    } catch {
        $result.Notes = "Upgrade error: $($_.Exception.Message)"
        Write-Warning "    $($result.Notes)"
    }
    return $result
}

# Renames the active .nvram file to .nvram_old so ESXi regenerates a fresh
# one with 2023 certificates on next boot.
function Rename-VMNvram {
    param($VMObj)
    try {
        $ctx  = Get-VMDatastoreContext -VMObj $VMObj
        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.MatchPattern = "*.nvram"
        $results = $ctx.DsBrowser.SearchDatastoreSubFolders(
            "[$($ctx.DsName)] $($ctx.VmDir)", $spec)

        if (-not $results -or -not $results.File) {
            Write-Warning "    No .nvram file found for $($VMObj.Name)"
            return $false
        }

        # Exclude already-renamed files
        $nvramFile = $results.File |
            Where-Object { $_.Path -notmatch "_old|_new" } |
            Select-Object -First 1

        if (-not $nvramFile) {
            Write-Warning "    Active .nvram file not found (may already be renamed)"
            return $false
        }

        $oldPath = "[$($ctx.DsName)] $($ctx.VmDir)/$($nvramFile.Path)"
        $newName = $nvramFile.Path -replace '\.nvram$', '.nvram_old'
        $newPath = "[$($ctx.DsName)] $($ctx.VmDir)/$newName"

        Write-Host "    Renaming: $($nvramFile.Path) -> $newName" -ForegroundColor Gray
        $task = $ctx.FileManager.MoveDatastoreFile_Task(
            $oldPath, $ctx.DcRef, $newPath, $ctx.DcRef, $true)

        if (Wait-DatastoreTask -Task $task) {
            Write-Host "    NVRAM renamed successfully." -ForegroundColor Green
            return $true
        }
        return $false
    } catch {
        Write-Warning "    NVRAM rename failed: $($_.Exception.Message)"
        return $false
    }
}

# Restores .nvram_old back to .nvram. If a current .nvram exists (e.g. from
# a re-fix attempt after rollback), it is first preserved as .nvram_new so
# nothing is permanently lost.
function Restore-VMNvram {
    param($VMObj)
    try {
        $ctx  = Get-VMDatastoreContext -VMObj $VMObj
        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.MatchPattern = "*.nvram*"
        $results = $ctx.DsBrowser.SearchDatastoreSubFolders(
            "[$($ctx.DsName)] $($ctx.VmDir)", $spec)

        if (-not $results -or -not $results.File) {
            Write-Warning "    No NVRAM files found on datastore for $($VMObj.Name)"
            return $false
        }

        $files    = $results.File | Select-Object -ExpandProperty Path
        $oldFile  = $files | Where-Object { $_ -match '\.nvram_old$' } | Select-Object -First 1
        $currFile = $files | Where-Object { $_ -match '\.nvram$'     } | Select-Object -First 1

        if (-not $oldFile) {
            Write-Warning "    No .nvram_old file found - nothing to restore for $($VMObj.Name)"
            return $false
        }

        # Preserve current .nvram if one exists (could be from a re-fix attempt)
        if ($currFile) {
            $currPath = "[$($ctx.DsName)] $($ctx.VmDir)/$currFile"
            $savePath = "[$($ctx.DsName)] $($ctx.VmDir)/$($currFile -replace '\.nvram$', '.nvram_new')"
            Write-Host "    Preserving current NVRAM as .nvram_new..." -ForegroundColor Gray
            $task = $ctx.FileManager.MoveDatastoreFile_Task(
                $currPath, $ctx.DcRef, $savePath, $ctx.DcRef, $true)
            if (-not (Wait-DatastoreTask -Task $task)) {
                Write-Warning "    Could not preserve current .nvram - aborting restore to avoid data loss."
                return $false
            }
        }

        # Restore .nvram_old -> .nvram
        $restoreSrc = "[$($ctx.DsName)] $($ctx.VmDir)/$oldFile"
        $restoreDst = "[$($ctx.DsName)] $($ctx.VmDir)/$($oldFile -replace '\.nvram_old$', '.nvram')"
        Write-Host "    Restoring: $oldFile -> $($oldFile -replace '\.nvram_old$', '.nvram')" -ForegroundColor Gray
        $task = $ctx.FileManager.MoveDatastoreFile_Task(
            $restoreSrc, $ctx.DcRef, $restoreDst, $ctx.DcRef, $true)

        if (Wait-DatastoreTask -Task $task) {
            Write-Host "    NVRAM restored successfully." -ForegroundColor Green
            return $true
        }
        return $false
    } catch {
        Write-Warning "    NVRAM restore failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# GUEST SCRIPTS
# =============================================================================

# Assess mode - reads all deployment signals from the guest in a single
# Invoke-VMScript call: registry status, cert presence, event log, BitLocker.
$assessGuestScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$r = @{}

# Registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"
$r["UEFICA2023Status"]  = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Status" -EA SilentlyContinue
$r["AvailableUpdates"]  = "0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue))"
$errVal = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Error" -EA SilentlyContinue
$r["UEFICA2023ErrorExists"] = ($null -ne $errVal).ToString()
$r["UEFICA2023ErrorValue"]  = if ($null -ne $errVal) { $errVal } else { "" }

# Cert presence via ASCII scan
try {
    $r["KEK_2023"] = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek -EA Stop).Bytes) -match "Microsoft Corporation KEK 2K CA 2023").ToString()
    $r["DB_2023"]  = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db  -EA Stop).Bytes) -match "Windows UEFI CA 2023").ToString()
} catch {
    $r["KEK_2023"] = "CheckFailed"; $r["DB_2023"] = "CheckFailed"
}

# PK status
try {
    $pk = Get-SecureBootUEFI -Name PK -EA Stop
    if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 44) {
        $r["PK_Status"] = "Invalid_NULL"
    } else {
        $t = [System.Text.Encoding]::ASCII.GetString($pk.Bytes[44..($pk.Bytes.Length-1)])
        $r["PK_Status"] = if     ($t -match "Windows OEM Devices") { "Valid_WindowsOEM" }
                          elseif ($t -match "Microsoft")            { "Valid_Microsoft"  }
                          else                                       { "Valid_Other"      }
    }
} catch { $r["PK_Status"] = "CheckFailed" }

# Events
$evts = @{ Evt1808=$false; Evt1801=$false; Evt1802=$false; Evt1803=$false; Evt1800=$false; Evt1795=$false }
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName="System"; ProviderName="Microsoft-Windows-TPM-WMI"; Id=@(1795,1800,1801,1802,1803,1808) } -MaxEvents 50 -EA Stop
    foreach ($e in $events) { $evts["Evt$($e.Id)"] = $true }
} catch {}
foreach ($k in $evts.Keys) { $r[$k] = $evts[$k].ToString() }

# BitLocker
$bl = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" }
$r["BitLockerActive"] = ($null -ne $bl -and @($bl).Count -gt 0).ToString()

$r | ConvertTo-Json -Compress
'@

# BitLocker / TPM safety check
# $ErrorActionPreference = 'SilentlyContinue' suppresses CommandNotFoundException when
# Get-BitLockerVolume is not available (BitLocker module not installed on the guest).
# Without this, the error text is written into ScriptOutput ahead of the JSON and breaks
# ConvertFrom-Json. $WarningPreference and $ProgressPreference suppress additional
# non-JSON output from Get-Tpm on VMs without a vTPM.
$tpmCheckScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$tpm = Get-Tpm
$bl  = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" }
[PSCustomObject]@{
    TPMPresent      = ($null -ne $tpm -and $tpm.TpmPresent)
    BitLockerActive = ($null -ne $bl -and @($bl).Count -gt 0)
} | ConvertTo-Json -Compress
'@

# Export all BitLocker recovery keys from the guest (returns JSON array)
$bitLockerExportScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$keys = @()
$volumes = Get-BitLockerVolume
foreach ($vol in $volumes) {
    foreach ($protector in $vol.KeyProtector) {
        if ($protector.KeyProtectorType -eq 'RecoveryPassword') {
            $keys += [PSCustomObject]@{
                DriveLetter      = $vol.MountPoint
                VolumeStatus     = $vol.VolumeStatus.ToString()
                ProtectionStatus = $vol.ProtectionStatus.ToString()
                KeyProtectorType = $protector.KeyProtectorType.ToString()
                KeyID            = $protector.KeyProtectorId
                RecoveryPassword = $protector.RecoveryPassword
            }
        }
    }
}
if ($keys.Count -gt 0) { $keys | ConvertTo-Json -Compress } else { "[]" }
'@

# Suspend BitLocker on all encrypted volumes.
# RebootCount 2 covers the power-off/power-on cycle and the post-fix reboot.
$bitLockerSuspendScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$result = @{ Suspended = @(); Failed = @(); Notes = "" }
$volumes = Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" }
foreach ($vol in $volumes) {
    try {
        Suspend-BitLocker -MountPoint $vol.MountPoint -RebootCount 2 -ErrorAction Stop | Out-Null
        $result["Suspended"] += $vol.MountPoint
    } catch {
        $result["Failed"] += $vol.MountPoint
        $result["Notes"]  += "Failed to suspend $($vol.MountPoint): $($_.Exception.Message) "
    }
}
$result["Notes"] += if ($result["Suspended"].Count -gt 0) {
    "Suspended on: $($result['Suspended'] -join ', '). Auto-resumes after 2 reboots. "
} else { "" }
$result | ConvertTo-Json -Compress
'@

# Verify 2023 certs present in NVRAM after regeneration
$certVerifyScript = @'
try {
    $kek = [System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI kek -ErrorAction Stop).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
    $db  = [System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI db -ErrorAction Stop).Bytes) -match 'Windows UEFI CA 2023'
    [PSCustomObject]@{ KEK_2023 = $kek.ToString(); DB_2023 = $db.ToString() } | ConvertTo-Json -Compress
} catch {
    [PSCustomObject]@{ KEK_2023 = "CheckFailed"; DB_2023 = "CheckFailed" } | ConvertTo-Json -Compress
}
'@

# Clear stale registry state, set AvailableUpdates via SYSTEM task, trigger update
$updateScript = @'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

if (Test-Path $svcPath) {
    Remove-Item -Path $svcPath -Recurse -Force
    Write-Host "Stale Servicing subkey cleared"
}

# Set AvailableUpdates via SYSTEM scheduled task to ensure proper elevation
$taskName = "SecureBootFix_$(Get-Random)"
$action   = New-ScheduledTaskAction -Execute "powershell.exe" -Argument `
    '-NoProfile -NonInteractive -Command "Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot -Name AvailableUpdates -Value 0x5944 -Type DWord -Force"'
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
    -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 10
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false | Out-Null

$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates set to: 0x$("{0:X4}" -f $val)"

Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Write-Host "Secure-Boot-Update task triggered"
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
'@

# Trigger update task after reboot
$taskTriggerScript = @'
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Write-Host "Secure-Boot-Update task triggered (post-reboot)"
Start-Sleep -Seconds 30
$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after second task run: 0x$("{0:X4}" -f $val)"
'@

# Final verification - registry status, firmware cert presence, and event log
$verifyScript = @'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

$svcStatus = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Status" -EA SilentlyContinue
$auRaw = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
if ($null -ne $auRaw) { $auHex = ("0x{0:X4}" -f [int]$auRaw) } else { $auHex = "not found" }
$errExists = "False"
$errValue  = ""
$svcProps = Get-ItemProperty -Path $svcPath -EA SilentlyContinue
if ($svcProps -and $null -ne $svcProps.UEFICA2023Error) {
    $errExists = "True"
    $errValue  = [string]$svcProps.UEFICA2023Error
}

$kek = "CheckFailed"
$db  = "CheckFailed"
try {
    $kekBytes = (Get-SecureBootUEFI kek -EA Stop).Bytes
    if ($kekBytes) { $kek = ([System.Text.Encoding]::ASCII.GetString($kekBytes) -match "Microsoft Corporation KEK 2K CA 2023").ToString() }
} catch {}
try {
    $dbBytes = (Get-SecureBootUEFI db -EA Stop).Bytes
    if ($dbBytes) { $db = ([System.Text.Encoding]::ASCII.GetString($dbBytes) -match "Windows UEFI CA 2023").ToString() }
} catch {}

$e1808 = "False"; $e1801 = "False"; $e1802 = "False"
$e1803 = "False"; $e1800 = "False"; $e1795 = "False"
try {
    $startTime = [datetime]"VERIFY_START_TIME"
    $evts = Get-WinEvent -LogName "System" -EA Stop |
        Where-Object { $_.ProviderName -eq "Microsoft-Windows-TPM-WMI" -and $_.Id -in @(1795,1800,1801,1802,1803,1808) -and $_.TimeCreated -ge $startTime } |
        Select-Object -First 50
    foreach ($e in $evts) {
        if ($e.Id -eq 1808) { $e1808 = "True" }
        if ($e.Id -eq 1801) { $e1801 = "True" }
        if ($e.Id -eq 1802) { $e1802 = "True" }
        if ($e.Id -eq 1803) { $e1803 = "True" }
        if ($e.Id -eq 1800) { $e1800 = "True" }
        if ($e.Id -eq 1795) { $e1795 = "True" }
    }
} catch {}

Write-Output "VERIFY_START"
Write-Output "Servicing_Status=$svcStatus"
Write-Output "AvailableUpdates=$auHex"
Write-Output "UEFICA2023ErrorExists=$errExists"
Write-Output "UEFICA2023ErrorValue=$errValue"
Write-Output "KEK_2023=$kek"
Write-Output "DB_2023=$db"
Write-Output "Evt1808=$e1808"
Write-Output "Evt1801=$e1801"
Write-Output "Evt1802=$e1802"
Write-Output "Evt1803=$e1803"
Write-Output "Evt1800=$e1800"
Write-Output "Evt1795=$e1795"
Write-Output "VERIFY_END"
'@

# Builds a timestamped copy of $verifyScript with the run start time injected.
# This ensures event log checks only return events from the current run,
# not events from prior runs or reboots that remain in the System log indefinitely.
function Get-TimestampedVerifyScript {
    param([datetime]$StartTime)
    return $verifyScript -replace 'VERIFY_START_TIME', $StartTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# Check Platform Key validity in guest (used before PK remediation).
# PK_Status values:
#   Valid_WindowsOEM - Microsoft WindowsOEMDevicesPK, proper for Windows Update KEK auth
#   Valid_Microsoft  - Microsoft-signed PK, proper for Windows Update KEK auth
#   Valid_Other      - ESXi writes placeholder data when regenerating NVRAM on < 9.0 hosts.
#                      Broadcom KB 423919: "For ESXi versions earlier than 9.0, a valid PK
#                      is not present." This PK will not authenticate Windows Update KEK
#                      changes - treat as needing enrollment.
#   Invalid_NULL     - No PK data at all (original state before NVRAM regeneration)
$pkCheckScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$blActive = ((Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "On" }).Count -gt 0).ToString()
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 44) {
    [PSCustomObject]@{ PK_Status = "Invalid_NULL"; BitLockerActive = $blActive } | ConvertTo-Json -Compress
} else {
    $cert = $pk.Bytes[44..($pk.Bytes.Length - 1)]
    if ($null -eq $cert -or $cert.Length -eq 0) {
        [PSCustomObject]@{ PK_Status = "Invalid_NULL"; BitLockerActive = $blActive } | ConvertTo-Json -Compress
    } else {
        $t = [System.Text.Encoding]::ASCII.GetString($cert)
        $s = if ($t -match 'Windows OEM Devices') { "Valid_WindowsOEM" }
             elseif ($t -match 'Microsoft')        { "Valid_Microsoft"  }
             else                                  { "Valid_Other"      }
        [PSCustomObject]@{ PK_Status = $s; BitLockerActive = $blActive } | ConvertTo-Json -Compress
    }
}
'@

# Post-enrollment PK verification
$verifyPKScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$pk = Get-SecureBootUEFI -Name PK
$pkStatus = "Unknown"
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 44) {
    $pkStatus = "Invalid_NULL"
} else {
    $cert = $pk.Bytes[44..($pk.Bytes.Length - 1)]
    if ($null -eq $cert -or $cert.Length -eq 0) {
        $pkStatus = "Invalid_NULL"
    } else {
        $pkText = [System.Text.Encoding]::ASCII.GetString($cert)
        if     ($pkText -match 'Windows OEM Devices') { $pkStatus = "Valid_WindowsOEM" }
        elseif ($pkText -match 'Microsoft')           { $pkStatus = "Valid_Microsoft"  }
        else                                          { $pkStatus = "Valid_Other"       }
    }
}
[PSCustomObject]@{ PK_Status = $pkStatus } | ConvertTo-Json -Compress
'@

# Enroll PK (and optionally KEK) while guest is in UEFI SetupMode.
# Expects DER-encoded certificate files copied to C:\Windows\Temp\.
# Uses Format-SecureBootUEFI to convert the DER cert to EFI Signature List
# format, then pipes directly to Set-SecureBootUEFI. This is required because
# Set-SecureBootUEFI -ContentFilePath expects ESL format, not raw DER.
# In SetupMode (PK slot empty/placeholder) no signing is needed.
$enrollPKScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$result = @{ PKEnrolled = $false; KEKUpdated = $false; Notes = "" }

$setupMode = (Get-SecureBootUEFI SetupMode -EA SilentlyContinue).Bytes
if ($setupMode -and $setupMode[0] -eq 1) {
    try {
        $pkFile = "C:\Windows\Temp\WindowsOEMDevicesPK.der"
        if (Test-Path $pkFile) {
            # Microsoft SignatureOwner GUID for Windows OEM Devices PK
            $ownerGuid = "55555555-0000-0000-0000-000000000000"
            Format-SecureBootUEFI -Name PK `
                -CertificateFilePath $pkFile `
                -SignatureOwner $ownerGuid `
                -FormatWithCert `
                -Time "2025-10-23T11:00:00Z" `
                -ErrorAction Stop |
            Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z" -ErrorAction Stop
            $result["PKEnrolled"] = $true
            $result["Notes"] += "PK enrolled successfully (from WindowsOEMDevicesPK.der). "
        } else {
            $result["Notes"] += "WindowsOEMDevicesPK.der not found at $pkFile. "
        }
    } catch {
        $result["Notes"] += "PK enrollment failed: $($_.Exception.Message) "
    }

    $kekFile = "C:\Windows\Temp\kek2023.der"
    if (Test-Path $kekFile) {
        try {
            $ownerGuid = "77fa9abd-0359-4d32-bd60-28f4e78f784b"
            Format-SecureBootUEFI -Name KEK `
                -CertificateFilePath $kekFile `
                -SignatureOwner $ownerGuid `
                -FormatWithCert `
                -AppendWrite `
                -Time "2025-10-23T11:00:00Z" `
                -ErrorAction Stop |
            Set-SecureBootUEFI -AppendWrite -Time "2025-10-23T11:00:00Z" -ErrorAction Stop
            $result["KEKUpdated"] = $true
            $result["Notes"] += "KEK 2023 updated successfully. "
        } catch {
            $result["Notes"] += "KEK update failed: $($_.Exception.Message) "
        }
    }
} else {
    $result["Notes"] = "VM is NOT in SetupMode. Check uefi.secureBootMode.overrideOnce VMX option."
}

$result | ConvertTo-Json -Compress
'@

# =============================================================================
# VMX OPTION HELPERS (used for UEFI SetupMode PK enrollment)
# =============================================================================
function Set-VMXOption {
    param($VMObj, [string]$Key, [string]$Value)
    $spec        = New-Object VMware.Vim.VirtualMachineConfigSpec
    $extra       = New-Object VMware.Vim.OptionValue
    $extra.Key   = $Key
    $extra.Value = $Value
    $spec.ExtraConfig = @($extra)
    ($VMObj | Get-View).ReconfigVM($spec)
}

function Get-VMXOption {
    param($VMObj, [string]$Key)
    return ($VMObj | Get-View).Config.ExtraConfig |
        Where-Object { $_.Key -eq $Key } |
        Select-Object -ExpandProperty Value -First 1
}

# =============================================================================
# ASSESS MODE
# Read-only. Collects hypervisor-level data for all target VMs.
# If -GuestCredential provided, also collects cert/registry/event/BitLocker data
# via Invoke-VMScript on powered-on VMs with Tools running.
# No changes are made to any VM.
# =============================================================================
if ($Assess) {
    Write-Host "`n=== ASSESS MODE (READ-ONLY) ===" -ForegroundColor Cyan
    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }
    Write-Host "Assessing $($vms.Count) VM(s)..." -ForegroundColor Cyan

    $assessReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($vm in $vms) {
        $vmName = $vm.Name
        Write-Host "`n$('='*60)" -ForegroundColor White
        Write-Host "Assessing: $vmName" -ForegroundColor White
        Write-Host "$('='*60)" -ForegroundColor White

        $vmView   = $vm | Get-View
        $vmHost   = Get-VMHost -VM $vm -EA SilentlyContinue
        $hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')
        $firmware = $vmView.Config.Firmware
        $sbEnabled = $vmView.Config.BootOptions.EfiSecureBootEnabled

        # Check for existing nvram_old and snapshot
        $hasNvramOld = $false
        $hasSnapshot = $false
        try {
            $ctx  = Get-VMDatastoreContext -VMObj $vm
            $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
            $spec.MatchPattern = "*.nvram*"
            $results = $ctx.DsBrowser.SearchDatastoreSubFolders("[$($ctx.DsName)] $($ctx.VmDir)", $spec)
            if ($results -and $results.File) {
                $hasNvramOld = ($null -ne ($results.File | Where-Object { $_.Path -match '_old' }))
            }
        } catch {}
        try {
            $snaps = Get-Snapshot -VM $vm -EA SilentlyContinue
            $hasSnapshot = ($null -ne ($snaps | Where-Object { $_.Name -match "Pre-SecureBoot-Fix|Pre-HWUpgrade" }))
        } catch {}

        $row = [PSCustomObject]@{
            VMName           = $vmName
            PowerState       = $vm.PowerState
            HWVersion        = $hwVerNum
            HWVersionOK      = ($hwVerNum -ge 21)
            ESXiHost         = if ($vmHost) { $vmHost.Name } else { "" }
            ESXiVersion      = if ($vmHost) { $vmHost.Version } else { "" }
            Firmware         = $firmware
            SecureBoot       = if ($firmware -eq "efi") { $sbEnabled.ToString() } else { "N/A (BIOS)" }
            NvramOldExists   = $hasNvramOld
            SnapshotExists   = $hasSnapshot
            # Guest-level (populated below if credentials provided and VM accessible)
            KEK_2023         = "Not collected"
            DB_2023          = "Not collected"
            PK_Status        = "Not collected"
            UEFICA2023Status = "Not collected"
            AvailableUpdates = "Not collected"
            UEFICA2023Error  = "Not collected"
            Evt1808          = "Not collected"
            Evt1801          = "Not collected"
            Evt1802          = "Not collected"
            Evt1803          = "Not collected"
            Evt1800          = "Not collected"
            Evt1795          = "Not collected"
            BitLockerActive  = "Not collected"
            ActionNeeded     = ""
            Notes            = ""
        }

        Write-Host "  HW Version : $hwVerNum $(if ($hwVerNum -lt 21) { '(< 21 - KEK may be absent after NVRAM regeneration)' } else { '' })" -ForegroundColor $(if ($hwVerNum -lt 21) { "Yellow" } else { "Green" })
        Write-Host "  ESXi Host  : $($row.ESXiHost) v$($row.ESXiVersion)"
        Write-Host "  Firmware   : $firmware | Secure Boot: $($row.SecureBoot)"
        Write-Host "  Power      : $($vm.PowerState)"
        Write-Host "  nvram_old  : $hasNvramOld | Snapshot: $hasSnapshot"

        if ($hwVerNum -lt 21) { $row.Notes += "HW version $hwVerNum < 21 - upgrade before remediation. " }
        if ($firmware -ne "efi") { $row.Notes += "BIOS firmware - not eligible for Secure Boot cert update. " }

        # Guest-level collection
        if ($GuestCredential -and $vm.PowerState -eq "PoweredOn") {
            try {
                $aOut  = Invoke-VMScript -VM $vm -ScriptText $assessGuestScript `
                    -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                $aData = $aOut.ScriptOutput.Trim() | ConvertFrom-Json

                $row.KEK_2023         = $aData.KEK_2023
                $row.DB_2023          = $aData.DB_2023
                $row.PK_Status        = $aData.PK_Status
                $row.UEFICA2023Status = if ($aData.UEFICA2023Status) { $aData.UEFICA2023Status } else { "not found" }
                $row.AvailableUpdates = $aData.AvailableUpdates
                $row.UEFICA2023Error  = if ($aData.UEFICA2023ErrorExists -eq "True") { "ERROR ($($aData.UEFICA2023ErrorValue))" } else { "" }
                $row.Evt1808 = $aData.Evt1808; $row.Evt1801 = $aData.Evt1801
                $row.Evt1802 = $aData.Evt1802; $row.Evt1803 = $aData.Evt1803
                $row.Evt1800 = $aData.Evt1800; $row.Evt1795 = $aData.Evt1795
                $row.BitLockerActive = $aData.BitLockerActive

                Write-Host "  UEFICA2023Status : $($row.UEFICA2023Status)" -ForegroundColor $(switch ($row.UEFICA2023Status.ToLower()) { "updated" {"Green"} "in progress" {"Yellow"} default {"Red"} })
                Write-Host "  AvailableUpdates : $($row.AvailableUpdates)"
                Write-Host "  KEK 2023 : $($row.KEK_2023) | DB 2023: $($row.DB_2023) | PK: $($row.PK_Status)"
                Write-Host "  Evt1808  : $($row.Evt1808) | Evt1801: $($row.Evt1801) | Evt1795: $($row.Evt1795)"
                if ($row.UEFICA2023Error) { Write-Host "  RegError : $($row.UEFICA2023Error)" -ForegroundColor Red }
                if ($aData.BitLockerActive -eq "True") { $row.Notes += "BitLocker active. " }
            } catch {
                $row.Notes += "Guest data collection failed: $($_.Exception.Message) "
                Write-Warning "  Guest collection failed: $($_.Exception.Message)"
            }
        } elseif ($GuestCredential -and $vm.PowerState -ne "PoweredOn") {
            $row.Notes += "VM powered off - guest data not collected. "
            Write-Host "  Guest data: skipped (VM powered off)" -ForegroundColor Gray
        } else {
            Write-Host "  Guest data: skipped (no -GuestCredential)" -ForegroundColor Gray
        }

        # Derive ActionNeeded summary
        $actions = [System.Collections.Generic.List[string]]::new()
        if ($firmware -ne "efi")                               { $actions.Add("N/A - BIOS") }
        elseif ($sbEnabled -eq $false)                         { $actions.Add("Enable Secure Boot") }
        else {
            if ($hwVerNum -lt 21)                              { $actions.Add("Upgrade HW version") }
            if ($row.UEFICA2023Status -notin @("updated","Not collected")) {
                if ($row.KEK_2023 -eq "False" -or $row.DB_2023 -eq "False") { $actions.Add("Rename NVRAM + run cert update") }
                elseif ($row.UEFICA2023Status -eq "not found")               { $actions.Add("Trigger cert update task") }
                elseif ($row.UEFICA2023Status -eq "in progress")             { $actions.Add("Reboot + trigger task again") }
            }
            if ($row.PK_Status -in @("Valid_Other","Invalid_NULL"))          { $actions.Add("Enroll PK") }
            if ($row.UEFICA2023Error)                                         { $actions.Add("Investigate reg error") }
            if ($row.Evt1802 -eq "True")                                      { $actions.Add("OEM firmware update (Evt 1802)") }
            if ($row.Evt1795 -eq "True")                                      { $actions.Add("OEM firmware update (Evt 1795)") }
            if ($actions.Count -eq 0 -and $row.UEFICA2023Status -eq "updated") { $actions.Add("None - complete") }
            elseif ($actions.Count -eq 0 -and $row.UEFICA2023Status -eq "Not collected") { $actions.Add("Run with -GuestCredential for full assessment") }
        }
        $row.ActionNeeded = $actions -join " | "
        Write-Host "  Action     : $($row.ActionNeeded)" -ForegroundColor $(if ($row.ActionNeeded -eq "None - complete") { "Green" } else { "Yellow" })

        $assessReport.Add($row)
    }

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "ASSESS SUMMARY" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White
    $assessReport | Format-Table VMName, PowerState, HWVersion, HWVersionOK, ESXiVersion,
        SecureBoot, KEK_2023, DB_2023, PK_Status, UEFICA2023Status,
        UEFICA2023Error, Evt1808, BitLockerActive, ActionNeeded -AutoSize

    $csvPath = ".\SecureBoot_Assess_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $assessReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green

    $needHW      = ($assessReport | Where-Object { $_.HWVersionOK -eq $false -and $_.Firmware -eq "efi" }).Count
    $needPK      = ($assessReport | Where-Object { $_.PK_Status -in @("Valid_Other","Invalid_NULL") }).Count
    $notDone     = ($assessReport | Where-Object { $_.UEFICA2023Status -notin @("updated","Not collected") }).Count
    $complete    = ($assessReport | Where-Object { $_.UEFICA2023Status -eq "updated" -and $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft","Not collected") }).Count
    $regErrors   = ($assessReport | Where-Object { $_.UEFICA2023Error -ne "" -and $_.UEFICA2023Error -ne "Not collected" }).Count
    Write-Host ""
    Write-Host "Complete (Updated + valid PK) : $complete / $($assessReport.Count)" -ForegroundColor Green
    if ($needHW     -gt 0) { Write-Host "Need HW upgrade (< v21)       : $needHW"    -ForegroundColor Yellow }
    if ($needPK     -gt 0) { Write-Host "Need PK enrollment             : $needPK"   -ForegroundColor Yellow }
    if ($notDone    -gt 0) { Write-Host "Cert update not complete       : $notDone"  -ForegroundColor Yellow }
    if ($regErrors  -gt 0) { Write-Host "Registry errors                : $regErrors" -ForegroundColor Red   }
    return
}

# =============================================================================
# STANDALONE HARDWARE UPGRADE MODE
# Upgrades hardware version on target VMs without running cert remediation.
# Powers each VM off, upgrades, powers back on. Does not require GuestCredential.
# =============================================================================
if ($isStandaloneUpgrade) {
    Write-Host "`n=== HARDWARE UPGRADE MODE ===" -ForegroundColor Cyan
    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }
    Write-Host "Targeting $($vms.Count) VM(s) for hardware version upgrade..." -ForegroundColor Cyan

    # Rollback warning - no supported API/UI path to downgrade hardware version.
    # A snapshot is the only supported rollback method. Taken by default unless
    # -NoSnapshot is specified.
    Write-Host ""
    Write-Warning "VMware does not provide a supported method to downgrade VM hardware versions."
    Write-Warning "A snapshot taken before the upgrade is the only supported rollback path."
    if ($NoSnapshot) {
        Write-Warning "-NoSnapshot specified: no snapshot will be taken. There will be no automated rollback path if issues arise."
    } else {
        Write-Host "Snapshots will be taken before each upgrade. Revert via vSphere Client or -Rollback if needed." -ForegroundColor Cyan
    }
    Write-Host ""

    $hwSnapName = "Pre-HWUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    $hwReport = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($vm in $vms) {
        $vmName   = $vm.Name
        $vmView   = $vm | Get-View
        $hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')
        Write-Host "`nProcessing: $vmName (current HW version: $hwVerNum)" -ForegroundColor White

        $hwRow = [PSCustomObject]@{
            VMName          = $vmName
            FromVersion     = $hwVerNum
            ToVersion       = ""
            SnapshotCreated = $false
            SnapshotName    = ""
            Upgraded        = $false
            Result          = ""
            Notes           = ""
        }

        if ($hwVerNum -ge 21) {
            Write-Host "  Already at version $hwVerNum (>= 21) - skipping." -ForegroundColor Green
            $hwRow.ToVersion = $hwVerNum
            $hwRow.Result    = "Skipped - already >= 21"
            $hwReport.Add($hwRow); continue
        }

        try {
            $wasPoweredOn = ($vm.PowerState -eq "PoweredOn")

            # Take snapshot before any changes (VM must be powered on for snapshot,
            # so snap before power off)
            if (-not $NoSnapshot) {
                if ($vm.PowerState -eq "PoweredOn") {
                    Write-Host "  Taking snapshot '$hwSnapName'..." -ForegroundColor Cyan
                    $snapOk = New-VMSnapshotSafe -VMObj $vm -Name $hwSnapName `
                        -Description "Pre-hardware-version-upgrade snapshot - rollback by reverting this snapshot"
                    $hwRow.SnapshotCreated = $snapOk
                    $hwRow.SnapshotName   = if ($snapOk) { $hwSnapName } else { "" }
                    if (-not $snapOk) {
                        $hwRow.Notes += "Snapshot failed - proceeding without rollback point. "
                        Write-Warning "  Snapshot failed - proceeding without rollback point."
                    }
                } else {
                    # VM is already powered off - snapshot a powered-off VM
                    Write-Host "  Taking snapshot of powered-off VM '$hwSnapName'..." -ForegroundColor Cyan
                    $snapOk = New-VMSnapshotSafe -VMObj $vm -Name $hwSnapName `
                        -Description "Pre-hardware-version-upgrade snapshot - rollback by reverting this snapshot"
                    $hwRow.SnapshotCreated = $snapOk
                    $hwRow.SnapshotName   = if ($snapOk) { $hwSnapName } else { "" }
                    if (-not $snapOk) {
                        $hwRow.Notes += "Snapshot failed - proceeding without rollback point. "
                        Write-Warning "  Snapshot failed - proceeding without rollback point."
                    }
                }
            }

            if ($wasPoweredOn) {
                Write-Host "  Powering off..." -ForegroundColor Cyan
                Stop-VM -VM $vm -Confirm:$false -Kill -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 10
            }

            $upResult = Invoke-VMHardwareUpgrade -VMObj $vm
            $hwRow.ToVersion = $upResult.ToVersion
            $hwRow.Upgraded  = $upResult.Upgraded
            if ($upResult.Notes) { $hwRow.Notes += $upResult.Notes }

            if ($upResult.Upgraded) {
                if ($wasPoweredOn) {
                    Write-Host "  Powering on..." -ForegroundColor Cyan
                    Start-VM -VM $vm | Out-Null
                }
                $hwRow.Result = "Upgraded $($upResult.FromVersion) -> $($upResult.ToVersion)"
                if ($hwRow.SnapshotCreated) {
                    Write-Host "  Snapshot '$hwSnapName' retained for rollback. Remove when satisfied." -ForegroundColor Yellow
                }
            } else {
                if ($wasPoweredOn) { Start-VM -VM $vm | Out-Null }
                $hwRow.Result = "FAILED"
            }
        } catch {
            $hwRow.Result = "ERROR"
            $hwRow.Notes += $_.Exception.Message
            Write-Warning "  Error: $($_.Exception.Message)"
        }
        $hwReport.Add($hwRow)
    }

    Write-Host "`n=== HARDWARE UPGRADE SUMMARY ===" -ForegroundColor White
    $hwReport | Format-Table VMName, FromVersion, ToVersion, SnapshotCreated, Upgraded, Result, Notes -AutoSize
    $csvPath = ".\SecureBoot_HWUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $hwReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green
    $upgraded  = ($hwReport | Where-Object { $_.Upgraded }).Count
    $skipped   = ($hwReport | Where-Object { $_.Result -like "Skipped*" }).Count
    $failed    = ($hwReport | Where-Object { $_.Result -in @("FAILED","ERROR") }).Count
    $snapped   = ($hwReport | Where-Object { $_.SnapshotCreated }).Count
    Write-Host "Upgraded: $upgraded | Skipped (already OK): $skipped | Failed: $failed | Snapshots taken: $snapped"
    if ($snapped -gt 0) {
        Write-Host "Remove snapshots via vSphere Client or -CleanupHWSnapshots once upgrade is verified." -ForegroundColor Yellow
    }
    return
}

# =============================================================================
# SNAPSHOT CLEANUP MODE
# Finds and removes all Pre-SecureBoot-Fix* snapshots on target VMs.
# Run after validation period. Always run before -CleanupNvram.
# =============================================================================
if ($CleanupSnapshots) {
    Write-Host "`n=== SNAPSHOT CLEANUP MODE ===" -ForegroundColor Cyan
    Write-Host "Searching for 'Pre-SecureBoot-Fix*' snapshots..." -ForegroundColor Cyan

    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }

    $snapsToRemove = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($vm in $vms) {
        $snaps = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like "${snapshotBaseName}*" }
        foreach ($snap in $snaps) {
            $snapsToRemove.Add([PSCustomObject]@{
                VMName   = $vm.Name
                SnapName = $snap.Name
                Created  = $snap.Created
                SizeMB   = [math]::Round($snap.SizeMB, 1)
                Snapshot = $snap
            })
        }
    }

    if ($snapsToRemove.Count -eq 0) {
        Write-Host "No matching snapshots found on target VMs." -ForegroundColor Green
        return
    }

    Write-Host "`nSnapshots to be removed:" -ForegroundColor Yellow
    $snapsToRemove | Format-Table VMName, SnapName, Created,
        @{N="Size(MB)"; E={$_.SizeMB}} -AutoSize

    $totalSizeMB = ($snapsToRemove | Measure-Object -Property SizeMB -Sum).Sum
    Write-Host "Total snapshots : $($snapsToRemove.Count)"
    Write-Host "Space reclaimed : $([math]::Round($totalSizeMB / 1024, 2)) GB" -ForegroundColor Yellow

    $confirm = Read-Host "`nProceed with removal? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Aborted."; return }

    $cleanupReport = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($item in $snapsToRemove) {
        Write-Host "  Removing snapshot on $($item.VMName)..." -ForegroundColor Cyan
        $resultRow = [PSCustomObject]@{
            VMName   = $item.VMName
            SnapName = $item.SnapName
            SizeMB   = $item.SizeMB
            Result   = "Pending"
            Notes    = ""
        }
        try {
            Remove-Snapshot -Snapshot $item.Snapshot -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "    Removed: $($item.SnapName)" -ForegroundColor Green
            $resultRow.Result = "Removed"
        } catch {
            Write-Warning "    Failed on $($item.VMName): $($_.Exception.Message)"
            $resultRow.Result = "Failed"
            $resultRow.Notes  = $_.Exception.Message
        }
        $cleanupReport.Add($resultRow)
    }

    Write-Host "`n=== CLEANUP SUMMARY ===" -ForegroundColor White
    $cleanupReport | Format-Table VMName, SnapName, SizeMB, Result, Notes -AutoSize

    $removed = ($cleanupReport | Where-Object { $_.Result -eq "Removed" }).Count
    $failed  = ($cleanupReport | Where-Object { $_.Result -eq "Failed"  }).Count
    Write-Host "Removed : $removed" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed  : $failed (remove manually via vSphere client)" -ForegroundColor Red
    }

    $csvPath = ".\SecureBoot_SnapshotCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $cleanupReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green
    return
}

# =============================================================================
# HW UPGRADE SNAPSHOT CLEANUP MODE
# Finds and removes all Pre-HWUpgrade* snapshots created by -UpgradeHardware.
# Run after verifying the hardware version upgrade is stable.
# =============================================================================
if ($CleanupHWSnapshots) {
    Write-Host "`n=== HW UPGRADE SNAPSHOT CLEANUP MODE ===" -ForegroundColor Cyan
    Write-Host "Searching for 'Pre-HWUpgrade*' snapshots..." -ForegroundColor Cyan

    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }

    $snapsToRemove = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($vm in $vms) {
        $snaps = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -like "Pre-HWUpgrade*" }
        foreach ($snap in $snaps) {
            $snapsToRemove.Add([PSCustomObject]@{
                VMName   = $vm.Name
                SnapName = $snap.Name
                Created  = $snap.Created
                SizeMB   = [math]::Round($snap.SizeMB, 1)
                Snapshot = $snap
            })
        }
    }

    if ($snapsToRemove.Count -eq 0) {
        Write-Host "No Pre-HWUpgrade* snapshots found on target VMs." -ForegroundColor Green
        return
    }

    Write-Host "`nSnapshots to be removed:" -ForegroundColor Yellow
    $snapsToRemove | Format-Table VMName, SnapName, Created,
        @{N="Size(MB)"; E={$_.SizeMB}} -AutoSize

    $totalSizeMB = ($snapsToRemove | Measure-Object -Property SizeMB -Sum).Sum
    Write-Host "Total snapshots : $($snapsToRemove.Count)"
    Write-Host "Space reclaimed : $([math]::Round($totalSizeMB / 1024, 2)) GB" -ForegroundColor Yellow

    $confirm = Read-Host "`nProceed with removal? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Aborted."; return }

    $cleanupReport = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($item in $snapsToRemove) {
        Write-Host "  Removing snapshot on $($item.VMName)..." -ForegroundColor Cyan
        $resultRow = [PSCustomObject]@{
            VMName   = $item.VMName
            SnapName = $item.SnapName
            SizeMB   = $item.SizeMB
            Result   = "Pending"
            Notes    = ""
        }
        try {
            Remove-Snapshot -Snapshot $item.Snapshot -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "    Removed: $($item.SnapName)" -ForegroundColor Green
            $resultRow.Result = "Removed"
        } catch {
            Write-Warning "    Failed on $($item.VMName): $($_.Exception.Message)"
            $resultRow.Result = "Failed"
            $resultRow.Notes  = $_.Exception.Message
        }
        $cleanupReport.Add($resultRow)
    }

    Write-Host "`n=== HW SNAPSHOT CLEANUP SUMMARY ===" -ForegroundColor White
    $cleanupReport | Format-Table VMName, SnapName, SizeMB, Result, Notes -AutoSize

    $removed = ($cleanupReport | Where-Object { $_.Result -eq "Removed" }).Count
    $failed  = ($cleanupReport | Where-Object { $_.Result -eq "Failed"  }).Count
    Write-Host "Removed : $removed" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed  : $failed (remove manually via vSphere client)" -ForegroundColor Red
    }

    $csvPath = ".\SecureBoot_HWSnapshotCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $cleanupReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green
    return
}

# =============================================================================
# NVRAM CLEANUP MODE
# Deletes .nvram_old files left on datastores by the fix process.
# Run AFTER -CleanupSnapshots. Warns if snapshots still exist.
# =============================================================================
if ($CleanupNvram) {
    Write-Host "`n=== NVRAM CLEANUP MODE ===" -ForegroundColor Cyan
    Write-Host "Searching for .nvram_old files on target VM datastores..." -ForegroundColor Cyan

    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }

    $nvramToDelete    = [System.Collections.Generic.List[PSObject]]::new()
    $snapshotWarnings = [System.Collections.Generic.List[string]]::new()

    $serviceInstance = Get-View ServiceInstance
    $fileManager     = Get-View $serviceInstance.Content.FileManager

    foreach ($vm in $vms) {
        $lingering = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like "${snapshotBaseName}*" }
        if ($lingering) { $snapshotWarnings.Add($vm.Name) }

        $vmView  = $vm | Get-View
        $vmxPath = $vmView.Config.Files.VmPathName
        $dsName  = $vmxPath -replace '^\[(.+?)\].*',         '$1'
        $vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'

        try {
            $dcRef     = (Get-Datacenter -VM $vm | Get-View).MoRef
            $ds        = Get-Datastore -Name $dsName -ErrorAction Stop
            $dsBrowser = Get-View $ds.ExtensionData.Browser
            $spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
            $spec.MatchPattern = "*.nvram_old"
            $results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)

            if ($results -and $results.File) {
                foreach ($file in $results.File) {
                    $nvramToDelete.Add([PSCustomObject]@{
                        VMName   = $vm.Name
                        FileName = $file.Path
                        FilePath = "[$dsName] $vmDir/$($file.Path)"
                        SizeKB   = [math]::Round($file.FileSize / 1KB, 1)
                        DcRef    = $dcRef
                        FM       = $fileManager
                    })
                }
            }
        } catch {
            Write-Warning "  Could not search datastore for $($vm.Name): $($_.Exception.Message)"
        }
    }

    if ($snapshotWarnings.Count -gt 0) {
        Write-Host ""
        Write-Warning "The following VMs still have Pre-SecureBoot-Fix* snapshots:"
        $snapshotWarnings | ForEach-Object { Write-Warning "  $_" }
        Write-Warning "Snapshots are your rollback path. Run -CleanupSnapshots first."
        Write-Warning "You may still proceed, but you will have no rollback option."
        Write-Host ""
    }

    if ($nvramToDelete.Count -eq 0) {
        Write-Host "No .nvram_old files found on target VM datastores." -ForegroundColor Green
        return
    }

    Write-Host "`n.nvram_old files to be deleted:" -ForegroundColor Yellow
    $nvramToDelete | Format-Table VMName, FileName,
        @{N="Size(KB)"; E={$_.SizeKB}} -AutoSize

    $totalKB = ($nvramToDelete | Measure-Object -Property SizeKB -Sum).Sum
    Write-Host "Total files     : $($nvramToDelete.Count)"
    Write-Host "Space reclaimed : $([math]::Round($totalKB / 1KB, 2)) MB" -ForegroundColor Yellow

    $confirm = Read-Host "`nProceed with deletion? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Aborted."; return }

    $nvramReport = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($item in $nvramToDelete) {
        Write-Host "  Deleting $($item.FileName) on $($item.VMName)..." -ForegroundColor Cyan
        $resultRow = [PSCustomObject]@{
            VMName   = $item.VMName
            FileName = $item.FileName
            SizeKB   = $item.SizeKB
            Result   = "Pending"
            Notes    = ""
        }
        try {
            $task = $item.FM.DeleteDatastoreFile_Task($item.FilePath, $item.DcRef)
            if (Wait-DatastoreTask -Task $task -TimeoutSeconds 30) {
                Write-Host "    Deleted: $($item.FileName)" -ForegroundColor Green
                $resultRow.Result = "Deleted"
            } else {
                $resultRow.Result = "Failed"
                $resultRow.Notes  = "Task did not complete successfully"
            }
        } catch {
            Write-Warning "    Exception: $($_.Exception.Message)"
            $resultRow.Result = "Failed"
            $resultRow.Notes  = $_.Exception.Message
        }
        $nvramReport.Add($resultRow)
    }

    Write-Host "`n=== NVRAM CLEANUP SUMMARY ===" -ForegroundColor White
    $nvramReport | Format-Table VMName, FileName, SizeKB, Result, Notes -AutoSize

    $deleted = ($nvramReport | Where-Object { $_.Result -eq "Deleted" }).Count
    $failed  = ($nvramReport | Where-Object { $_.Result -eq "Failed"  }).Count
    Write-Host "Deleted : $deleted" -ForegroundColor Green
    if ($failed -gt 0) {
        Write-Host "Failed  : $failed (delete manually via datastore browser in vSphere client)" -ForegroundColor Red
    }

    $csvPath = ".\SecureBoot_NvramCleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $nvramReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green
    return
}

# =============================================================================
# ROLLBACK MODE
# For each target VM:
#   1. Power off
#   2. Restore .nvram_old -> .nvram (preserves current .nvram as .nvram_new)
#   3. Revert to Pre-SecureBoot-Fix* snapshot if one exists
#   4. Power on
# Does not require GuestCredential - all operations go through vCenter.
# Registry changes are only reverted if a snapshot exists.
# =============================================================================
if ($Rollback) {
    Write-Host "`n=== ROLLBACK MODE ===" -ForegroundColor Cyan

    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }

    Write-Host "Targeting $($vms.Count) VM(s) for rollback:`n  $($vms.Name -join "`n  ")" -ForegroundColor Cyan
    Write-Host ""
    Write-Warning "This will power off each VM, restore the original NVRAM, revert to the"
    Write-Warning "Pre-SecureBoot-Fix snapshot (if one exists), and power the VM back on."
    Write-Warning "Registry changes made during the fix are only reverted if a snapshot"
    Write-Warning "exists - NVRAM restore alone does not undo registry changes."
    Write-Host ""

    $confirm = Read-Host "Proceed with rollback? (Y/N)"
    if ($confirm -notmatch '^[Yy]') { Write-Host "Aborted."; return }

    $rollbackReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($vm in $vms) {
        $vmName = $vm.Name
        Write-Host "`n$('='*60)" -ForegroundColor White
        Write-Host "Rolling back: $vmName" -ForegroundColor White
        Write-Host "$('='*60)" -ForegroundColor White

        $row = [PSCustomObject]@{
            VMName           = $vmName
            PoweredOff       = $false
            NVRAMRestored    = $false
            SnapshotReverted = $false
            PoweredOn        = $false
            Result           = "Pending"
            Notes            = ""
        }

        try {
            # Step 1 - Power off
            Write-Host "  [1/4] Powering off..." -ForegroundColor Cyan
            if ($vm.PowerState -eq "PoweredOn") {
                Stop-VM -VM $vm -Confirm:$false -Kill -ErrorAction Stop | Out-Null
                Start-Sleep -Seconds 10
            }
            $row.PoweredOff = $true

            # Step 2 - Restore NVRAM
            Write-Host "  [2/4] Restoring NVRAM file..." -ForegroundColor Cyan
            $row.NVRAMRestored = Restore-VMNvram -VMObj $vm
            if (-not $row.NVRAMRestored) {
                $row.Notes += "NVRAM restore failed or no .nvram_old found. "
                Write-Warning "  NVRAM restore failed - check datastore manually."
            }

            # Step 3 - Revert snapshot if one exists
            Write-Host "  [3/4] Checking for Pre-SecureBoot-Fix snapshot..." -ForegroundColor Cyan
            $snap = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "${snapshotBaseName}*" } |
                    Sort-Object -Property Created -Descending |
                    Select-Object -First 1

            if ($snap) {
                Write-Host "    Found: '$($snap.Name)' (created $($snap.Created))" -ForegroundColor Gray
                Write-Host "    Reverting to snapshot..." -ForegroundColor Gray
                try {
                    Set-VM -VM $vm -Snapshot $snap -Confirm:$false | Out-Null
                    $row.SnapshotReverted = $true
                    Write-Host "    Snapshot reverted successfully." -ForegroundColor Green
                } catch {
                    Write-Warning "    Snapshot revert failed: $($_.Exception.Message)"
                    $row.Notes += "Snapshot revert failed: $($_.Exception.Message). "
                }
            } else {
                Write-Host "    No Pre-SecureBoot-Fix snapshot found." -ForegroundColor Yellow
                $row.Notes += "No snapshot found - only NVRAM restored. Registry changes NOT reverted. "
            }

            # Step 4 - Power on
            Write-Host "  [4/4] Powering on..." -ForegroundColor Cyan
            $vm = Get-VM -Name $vmName
            Start-VM -VM $vm | Out-Null
            if (Wait-VMTools -VM $vm -TimeoutSeconds 300) {
                $row.PoweredOn = $true
                Write-Host "  VM is back online." -ForegroundColor Green
            } else {
                $row.Notes += "Tools timeout after power on - VM may still be booting. "
            }

            $row.Result = if     ($row.NVRAMRestored -and $row.SnapshotReverted -and $row.PoweredOn) { "Rolled Back (NVRAM + Snapshot)" }
                          elseif ($row.NVRAMRestored -and $row.PoweredOn)                             { "Rolled Back (NVRAM only - no snapshot)" }
                          elseif ($row.PoweredOn)                                                     { "Partial - NVRAM not restored" }
                          else                                                                         { "Partial - check VM" }

            $color = if ($row.Result -like "Rolled Back*") { "Green" } else { "Yellow" }
            Write-Host ("  NVRAM Restored: {0} | Snapshot Reverted: {1} | Result: {2}" -f
                $row.NVRAMRestored, $row.SnapshotReverted, $row.Result) -ForegroundColor $color

        } catch {
            $row.Result  = "ERROR"
            $row.Notes  += "Exception: $($_.Exception.Message)"
            Write-Warning "  Error rolling back $vmName`: $($_.Exception.Message)"
        }

        $rollbackReport.Add($row)
    }

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "ROLLBACK SUMMARY" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White
    $rollbackReport | Format-Table VMName, PoweredOff, NVRAMRestored,
        SnapshotReverted, PoweredOn, Result, Notes -AutoSize

    $csvPath = ".\SecureBoot_Rollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $rollbackReport | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green

    $full    = ($rollbackReport | Where-Object { $_.Result -like "Rolled Back*" }).Count
    $partial = ($rollbackReport | Where-Object { $_.Result -like "Partial*"     }).Count
    $errors  = ($rollbackReport | Where-Object { $_.Result -eq  "ERROR"         }).Count

    Write-Host ""
    Write-Host "Rolled back : $full / $($rollbackReport.Count)" -ForegroundColor Green
    if ($partial -gt 0) { Write-Host "Partial     : $partial (review Notes column)" -ForegroundColor Yellow }
    if ($errors  -gt 0) { Write-Host "Errors      : $errors"                        -ForegroundColor Red    }
    return
}

# =============================================================================
# PULL TARGET VMs (main remediation mode)
# =============================================================================
Write-Host "`nQuerying vCenter for target VMs..." -ForegroundColor Cyan
$vms = Resolve-TargetVMs -SecureBootFilter

if (-not $vms) { Write-Warning "No matching VMs found."; return }
Write-Host "Targeting $($vms.Count) VM(s):`n  $($vms.Name -join "`n  ")" -ForegroundColor Cyan

if ($NoSnapshot) {
    Write-Host "Snapshot mode   : DISABLED (-NoSnapshot specified)" -ForegroundColor Yellow
} else {
    Write-Host "Snapshot name   : $snapshotName" -ForegroundColor Cyan
    Write-Host "Retain snapshots: $RetainSnapshots" -ForegroundColor Cyan
    Write-Host "`nEnsure sufficient datastore space for $($vms.Count) snapshot(s) before proceeding." -ForegroundColor Yellow
}

if ($Confirm) {
    Write-Host "Continue? (Y/N): y (auto-confirmed via -Confirm)" -ForegroundColor Gray
} else {
    $confirmInput = Read-Host "Continue? (Y/N)"
    if ($confirmInput -notmatch '^[Yy]') { Write-Host "Aborted."; return }
}

$report = [System.Collections.Generic.List[PSObject]]::new()

# =============================================================================
# BITLOCKER KEY BACKUP FUNCTION
# =============================================================================
function Backup-BitLockerKeys {
    param($VMObj, [string]$BackupShare, [string]$Timestamp)
    Write-Host "    Exporting BitLocker recovery keys from guest..." -ForegroundColor Gray
    try {
        $exportOut = Invoke-VMScript -VM $VMObj -ScriptText $bitLockerExportScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
        $jsonLine = ($exportOut.ScriptOutput -split "`r?`n" |
            Where-Object { $_.Trim() -match '^\[' -or $_.Trim() -match '^\{' } |
            Select-Object -Last 1).Trim()
        if (-not $jsonLine -or $jsonLine -eq "[]") {
            Write-Host "    No RecoveryPassword protectors found on this VM." -ForegroundColor Gray
            return $true
        }
        $keyData = $jsonLine | ConvertFrom-Json
        if (-not $keyData) { return $true }
        if ($keyData -isnot [System.Array]) { $keyData = @($keyData) }
        Write-Host "    Found $($keyData.Count) recovery key(s)." -ForegroundColor Yellow

        $lines  = @()
        $lines += "BitLocker Recovery Key Backup"
        $lines += "============================="
        $lines += "VM Name    : $($VMObj.Name)"
        $lines += "Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $lines += "Purpose    : Pre-Secure-Boot-fix backup per Broadcom KB 423919"
        $lines += ""
        $lines += "SECURITY NOTICE: This file contains sensitive cryptographic recovery"
        $lines += "material. Store securely and restrict access to authorized personnel."
        $lines += ""
        $lines += ("-" * 60)
        foreach ($key in $keyData) {
            $lines += ""
            $lines += "Drive            : $($key.DriveLetter)"
            $lines += "Volume Status    : $($key.VolumeStatus)"
            $lines += "Protection Status: $($key.ProtectionStatus)"
            $lines += "Protector Type   : $($key.KeyProtectorType)"
            $lines += "Key ID           : $($key.KeyID)"
            $lines += "Recovery Password: $($key.RecoveryPassword)"
            $lines += ("-" * 60)
        }

        $fileName  = "$($VMObj.Name)_BitLockerKeys_${Timestamp}.txt"
        $sharePath = Join-Path $BackupShare $fileName
        try {
            $lines | Out-File -FilePath $sharePath -Encoding UTF8 -ErrorAction Stop
            Write-Host "    Recovery key(s) written to: $sharePath" -ForegroundColor Green
            return $true
        } catch {
            Write-Warning "    Failed to write backup file to share: $($_.Exception.Message)"
            return $false
        }
    } catch {
        Write-Warning "    BitLocker key export from guest failed: $($_.Exception.Message)"
        return $false
    }
}

# =============================================================================
# MAIN PROCESSING LOOP
# =============================================================================
foreach ($vm in $vms) {
    $vmName      = $vm.Name
    $snapCreated = $false
    # Capture timestamp before any changes so event log checks only consider
    # events generated during this run, not from prior runs or reboots.
    $vmRunStart  = (Get-Date).AddSeconds(-5)  # 5s buffer for clock skew

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "Processing: $vmName" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White

    $row = [PSCustomObject]@{
        VMName              = $vmName
        SnapshotCreated     = $false
        BitLockerSkipped    = $false
        BitLockerKeysBacked = $false
        BitLockerSuspended  = $false
        NVRAMRenamed        = $false
        KEK_AfterNVRAM      = "Not checked"
        DB_AfterNVRAM       = "Not checked"
        HWUpgraded          = "N/A"
        UpdateTriggered     = $false
        KEK_2023            = "Not checked"
        DB_2023             = "Not checked"
        FinalStatus         = "Not checked"
        UEFICA2023Error     = ""
        Evt1808             = ""
        Evt1801             = ""
        Evt1802             = ""
        Evt1803             = ""
        Evt1800             = ""
        Evt1795             = ""
        PK_Status           = "Not checked"
        PKEnrolled          = $false
        PKRemediated        = $false
        SnapshotRetained    = $false
        Notes               = ""
    }

    try {
        # ------------------------------------------------------------------
        # Step 0 - BitLocker safety check (only if VM is powered on)
        # ------------------------------------------------------------------
        if ($vm.PowerState -eq "PoweredOn") {
            Write-Host "  [0/9] Checking BitLocker/TPM..." -ForegroundColor Cyan
            try {
                $tpmOut  = Invoke-VMScript -VM $vm -ScriptText $tpmCheckScript `
                    -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                $jsonLine = ($tpmOut.ScriptOutput -split "`r?`n" | Where-Object { $_.Trim() -match '^{' } | Select-Object -Last 1).Trim()
                if (-not $jsonLine) { throw "No JSON output from BitLocker check script" }
                $tpmData = $jsonLine | ConvertFrom-Json

                if ($tpmData.BitLockerActive) {
                    if (-not $BitLockerBackupShare) {
                        Write-Warning "  BitLocker ACTIVE on $vmName - SKIPPING."
                        Write-Warning "  Provide -BitLockerBackupShare to back up keys and proceed automatically."
                        $row.BitLockerSkipped = $true
                        $row.Notes = "SKIPPED - BitLocker active. Provide -BitLockerBackupShare to process."
                        $report.Add($row)
                        continue
                    }

                    Write-Host "  BitLocker ACTIVE - backing up keys and suspending before proceeding..." -ForegroundColor Yellow

                    # Back up recovery keys to share - abort if backup fails
                    $blTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                    $backupOk = Backup-BitLockerKeys -VMObj $vm -BackupShare $BitLockerBackupShare -Timestamp $blTimestamp
                    $row.BitLockerKeysBacked = $backupOk
                    if (-not $backupOk) {
                        Write-Warning "  Recovery key backup failed. Skipping $vmName to avoid lockout."
                        Write-Warning "  Resolve the share access issue and re-run."
                        $row.BitLockerSkipped = $true
                        $row.Notes = "SKIPPED - BitLocker key backup to share failed."
                        $report.Add($row)
                        continue
                    }

                    # Suspend BitLocker (RebootCount 2 covers power-off/on + post-fix reboot)
                    $suspendOut  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                    $suspendJson = ($suspendOut.ScriptOutput -split "`r?`n" |
                        Where-Object { $_.Trim() -match '^{' } |
                        Select-Object -Last 1).Trim()
                    if ($suspendJson) {
                        $suspendData = $suspendJson | ConvertFrom-Json
                        $row.BitLockerSuspended = ($suspendData.Suspended.Count -gt 0)
                        Write-Host "    $($suspendData.Notes)" -ForegroundColor $(if ($row.BitLockerSuspended) {"Green"} else {"Yellow"})
                        $row.Notes += "BL: $($suspendData.Notes) "
                        if (-not $row.BitLockerSuspended) {
                            Write-Warning "  BitLocker suspension failed - proceeding but recovery may trigger on reboot."
                            Write-Warning "  Recovery key is backed up at: $BitLockerBackupShare"
                        }
                    }
                }
                if ($tpmData.TPMPresent -and -not $tpmData.BitLockerActive) {
                    Write-Host "  vTPM present, BitLocker not active - proceeding." -ForegroundColor Yellow
                    $row.Notes += "vTPM present. "
                }
            } catch {
                Write-Warning "  BitLocker check failed ($($_.Exception.Message)) - proceeding."
            }
        }

        # ------------------------------------------------------------------
        # Step 1 - Take snapshot (skipped if -NoSnapshot)
        # ------------------------------------------------------------------
        if ($NoSnapshot) {
            Write-Host "  [1/9] Skipping snapshot (-NoSnapshot specified)." -ForegroundColor Yellow
            $row.Notes += "No snapshot taken (-NoSnapshot). "
        } else {
            Write-Host "  [1/9] Taking snapshot..." -ForegroundColor Cyan
            $snapResult          = New-VMSnapshotSafe -VMObj $vm -Name $snapshotName `
                -Description "Pre Secure Boot 2023 cert fix - automated snapshot"
            $row.SnapshotCreated = $snapResult
            $snapCreated         = $snapResult
            if (-not $snapResult) {
                $row.Notes += "Snapshot failed - no rollback available. "
                Write-Warning "  Continuing without snapshot. Ensure datastore has sufficient space."
            }
        }

        # ------------------------------------------------------------------
        # Pre-check - assess current VM state to determine which steps can
        # be skipped. Only runs if VM is powered on and GuestCredential is
        # available. Sets $entryStep to control step gating below.
        #
        # entryStep values:
        #   "full"       - run all steps (default; NVRAM stale or unknown)
        #   "skipNvram"  - skip steps 2/2b/3/4 (KEK already present in NVRAM)
        #   "skipToStep6"- skip steps 2/2b/3/4/5 (0x4100, need reboot only)
        #   "certDone"   - skip to step 8 (cert update complete, PK check only)
        #   "allDone"    - VM fully remediated, skip entirely
        # ------------------------------------------------------------------
        $entryStep = "full"
        if ($vm.PowerState -eq "PoweredOn") {
            Write-Host "  [Pre] Assessing current state to determine required steps..." -ForegroundColor Cyan
            try {
                $preOut  = Invoke-VMScript -VM $vm -ScriptText $assessGuestScript `
                    -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                $preJson = ($preOut.ScriptOutput -split "`r?`n" |
                    Where-Object { $_.Trim() -match '^{' } | Select-Object -Last 1).Trim()
                if ($preJson) {
                    $pre = $preJson | ConvertFrom-Json

                    $certsDone = ($pre.UEFICA2023Status -eq "updated" -or $pre.AvailableUpdates -eq "0x4000")
                    $nvramGood = ($pre.KEK_2023 -eq "True" -and $pre.DB_2023 -eq "True")
                    $halfwayThere = ($nvramGood -and $pre.AvailableUpdates -eq "0x4100")
                    $pkGoodAlready = ($pre.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft"))

                    if ($certsDone -and ($pkGoodAlready -or -not $PKDerPath)) {
                        $entryStep = "allDone"
                        Write-Host "  [Pre] Already complete - skipping VM." -ForegroundColor Green
                        $row.FinalStatus    = "Updated"
                        $row.KEK_2023       = $pre.KEK_2023
                        $row.DB_2023        = $pre.DB_2023
                        $row.PK_Status      = $pre.PK_Status
                        $row.Evt1808        = $pre.Evt1808
                        $row.Notes         += "Pre-check: already complete - no changes made. "
                        $report.Add($row)
                        continue
                    } elseif ($certsDone) {
                        $entryStep = "certDone"
                        Write-Host "  [Pre] Cert update already complete - skipping to PK check (step 8)." -ForegroundColor Green
                        $row.KEK_2023    = $pre.KEK_2023
                        $row.DB_2023     = $pre.DB_2023
                        $row.FinalStatus = "Updated"
                        $row.Evt1808     = $pre.Evt1808
                        $row.Notes      += "Pre-check: cert update already complete - skipped steps 2-7. "
                    } elseif ($halfwayThere) {
                        $entryStep = "skipToStep6"
                        Write-Host "  [Pre] AvailableUpdates=0x4100 - KEK/DB applied, Boot Manager pending. Skipping to step 6 (reboot)." -ForegroundColor Yellow
                        $row.KEK_AfterNVRAM = "True"
                        $row.DB_AfterNVRAM  = "True"
                        $row.Notes         += "Pre-check: AvailableUpdates=0x4100 - skipped steps 2-5. "
                    } elseif ($nvramGood) {
                        $entryStep = "skipNvram"
                        Write-Host "  [Pre] KEK 2023 already present in NVRAM - skipping power off/rename/power on (steps 2-4)." -ForegroundColor Yellow
                        $row.KEK_AfterNVRAM = "True"
                        $row.DB_AfterNVRAM  = "True"
                        $row.Notes         += "Pre-check: KEK 2023 already in NVRAM - skipped steps 2-4. "
                    } else {
                        Write-Host "  [Pre] KEK 2023 not present - full NVRAM regeneration required." -ForegroundColor Yellow
                    }
                }
            } catch {
                Write-Host "  [Pre] Pre-check failed ($($_.Exception.Message)) - running full sequence." -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [Pre] VM is powered off - running full sequence." -ForegroundColor Yellow
        }

        # ------------------------------------------------------------------
        # Step 2 - Power off (skipped if NVRAM already has 2023 certs)
        # ------------------------------------------------------------------
        if ($entryStep -notin @("skipNvram","skipToStep6","certDone")) {
        Write-Host "  [2/9] Powering off..." -ForegroundColor Cyan
        if ($vm.PowerState -eq "PoweredOn") {
            Stop-VM -VM $vm -Confirm:$false -Kill -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 10
        }

        # ------------------------------------------------------------------
        # Step 2b - Upgrade hardware version (only if -UpgradeHardware specified)
        # VM must be powered off. VMs already at version 21+ are skipped.
        # ------------------------------------------------------------------
        if ($UpgradeHardware) {
            $vmView   = $vm | Get-View
            $hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')
            if ($hwVerNum -lt 21) {
                Write-Host "  [2b/9] Upgrading hardware version (current: $hwVerNum)..." -ForegroundColor Cyan
                $upResult = Invoke-VMHardwareUpgrade -VMObj $vm
                if ($upResult.Upgraded) {
                    $row.HWUpgraded = "$hwVerNum -> $($upResult.ToVersion)"
                    $vm = Get-VM -Name $vmName
                } else {
                    $row.HWUpgraded = "FAILED"
                    $row.Notes += "Hardware upgrade failed: $($upResult.Notes) "
                    Write-Warning "  Hardware upgrade failed - continuing with existing version $hwVerNum."
                }
            } else {
                Write-Host "  [2b/9] Hardware version $hwVerNum >= 21 - no upgrade needed." -ForegroundColor Green
                $row.HWUpgraded = "Already OK ($hwVerNum)"
            }
        }

        # ------------------------------------------------------------------
        # Step 3 - Rename NVRAM (triggers fresh generation with 2023 certs)
        # ------------------------------------------------------------------
        Write-Host "  [3/9] Renaming NVRAM file on datastore..." -ForegroundColor Cyan
        $row.NVRAMRenamed = Rename-VMNvram -VMObj $vm
        if (-not $row.NVRAMRenamed) {
            $row.Notes += "NVRAM rename failed - cert update may not succeed. "
        }

        # ------------------------------------------------------------------
        # Step 4 - Power on (ESXi regenerates NVRAM with 2023 KEK)
        # ------------------------------------------------------------------
        Write-Host "  [4/9] Powering on (ESXi regenerates NVRAM with 2023 certs)..." -ForegroundColor Cyan
        Start-VM -VM $vm | Out-Null
        $vm = Get-VM -Name $vmName
        if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
            $row.Notes          += "Tools timeout after NVRAM boot. "
            $row.SnapshotRetained = $snapCreated
            $report.Add($row)
            continue
        }

        Write-Host "    Verifying 2023 certs in new NVRAM..." -ForegroundColor Gray
        try {
            $certOut  = Invoke-VMScript -VM $vm -ScriptText $certVerifyScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $certData = $certOut.ScriptOutput.Trim() | ConvertFrom-Json
            $row.KEK_AfterNVRAM = $certData.KEK_2023
            $row.DB_AfterNVRAM  = $certData.DB_2023
            Write-Host "    KEK 2023: $($certData.KEK_2023) | DB 2023: $($certData.DB_2023)" -ForegroundColor Gray

            if ($certData.KEK_2023 -ne "True") {
                Write-Warning "    KEK 2023 not present after NVRAM regeneration - update may fail."
                $row.Notes += "KEK 2023 not in NVRAM after regeneration. "
            }
        } catch {
            Write-Warning "    Could not verify NVRAM certs: $($_.Exception.Message)"
            $row.Notes += "NVRAM cert verify failed. "
        }

        } # end skip-NVRAM gate (steps 2-4)

        # ------------------------------------------------------------------
        # Step 5 - Clear stale registry state, set AvailableUpdates, trigger task
        # (skipped if cert update already complete or only reboot needed)
        # ------------------------------------------------------------------
        if ($entryStep -notin @("skipToStep6","certDone")) {
        Write-Host "  [5/9] Clearing stale state and triggering update..." -ForegroundColor Cyan
        $updateOut = Invoke-VMScript -VM $vm -ScriptText $updateScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
        Write-Host $updateOut.ScriptOutput -ForegroundColor Gray
        $row.UpdateTriggered = $true

        } # end skip-cert-update gate (step 5)

        # ------------------------------------------------------------------
        # Step 6 - Reboot, trigger task again (skipped if cert update complete)
        # ------------------------------------------------------------------
        if ($entryStep -ne "certDone") {
        Write-Host "  [6/9] Rebooting..." -ForegroundColor Cyan
        Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
        Start-Sleep -Seconds $WaitSeconds
        $vm = Get-VM -Name $vmName
        if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
            $row.Notes          += "Tools timeout after reboot. "
            $row.SnapshotRetained = $snapCreated
            $report.Add($row)
            continue
        }

        $taskOut = Invoke-VMScript -VM $vm -ScriptText $taskTriggerScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
        Write-Host $taskOut.ScriptOutput -ForegroundColor Gray

        } # end cert-done gate (step 6)

        # ------------------------------------------------------------------
        # Step 7 - Final verification (KEK/DB cert status)
        # ------------------------------------------------------------------
        Write-Host "  [7/9] Verifying final KEK/DB cert status..." -ForegroundColor Cyan

        $verifyOut  = Invoke-VMScript -VM $vm -ScriptText (Get-TimestampedVerifyScript -StartTime $vmRunStart) `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop

        $verifyData = $null
        try {
            $lines = $verifyOut.ScriptOutput -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            if ($lines -contains "VERIFY_START" -and $lines -contains "VERIFY_END") {
                $map = @{}
                foreach ($line in $lines) {
                    if ($line -match '^([^=]+)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
                }
                $verifyData = [PSCustomObject]$map
            }
        } catch {}

        if ($null -eq $verifyData) {
            Write-Warning "  Verify script returned no parseable output - skipping VM."
            Write-Warning "  Raw output: $($verifyOut.ScriptOutput.Trim())"
            Write-Warning "  ExitCode: $($verifyOut.ExitCode) | ScriptError: $($verifyOut.ScriptError)"
            $row.Notes += "Verify script returned no output - check VM manually. "
            $report.Add($row)
            continue
        }

        $row.KEK_2023    = $verifyData.KEK_2023
        $row.DB_2023     = $verifyData.DB_2023
        # \Servicing may be absent on fully-complete VMs; fall back to AvailableUpdates = 0x4000
        $row.FinalStatus = if ($verifyData.Servicing_Status) {
            $verifyData.Servicing_Status
        } elseif ($verifyData.AvailableUpdates -eq "0x4000") {
            "Updated"
        } else {
            "Unknown"
        }

        if ($verifyData.UEFICA2023ErrorExists -eq "True") {
            $row.UEFICA2023Error = "ERROR ($($verifyData.UEFICA2023ErrorValue))"
            $row.Notes += "UEFICA2023Error key present (value: $($verifyData.UEFICA2023ErrorValue)) - deployment error not visible in Event Log; trace via Secure Boot DB/DBX events. "
        }

        # Populate event log results
        $row.Evt1808 = $verifyData.Evt1808
        $row.Evt1801 = $verifyData.Evt1801
        $row.Evt1802 = $verifyData.Evt1802
        $row.Evt1803 = $verifyData.Evt1803
        $row.Evt1800 = $verifyData.Evt1800
        $row.Evt1795 = $verifyData.Evt1795

        # Flag persistent error events in Notes. 1801 and 1800 are handled by
        # step 7b which reboots and re-checks before adding a Note.
        # 1808 absence is not flagged - may not fire until after an extra reboot.
        if ($verifyData.Evt1802 -eq "True") {
            $row.Notes += "Event 1802: update blocked by known firmware issue - contact OEM for firmware update. "
        }
        if ($verifyData.Evt1803 -eq "True") {
            $row.Notes += "Event 1803: no PK-signed KEK found - PK remediation required. "
        }
        if ($verifyData.Evt1795 -eq "True") {
            $row.Notes += "Event 1795: firmware returned error on Secure Boot variable write - contact OEM for firmware update. "
        }

        # ------------------------------------------------------------------
        # Step 7b - Extra reboot if Event 1801 or 1800 detected WITHOUT 1808
        # Event 1801 is an intermediate state that is always followed by 1808
        # once the firmware write completes. If 1808 is already present, the
        # process is done and 1801 is simply a historical record from earlier
        # in the same update sequence - no reboot needed.
        # ------------------------------------------------------------------
        if (($verifyData.Evt1801 -eq "True" -or $verifyData.Evt1800 -eq "True") -and $verifyData.Evt1808 -ne "True") {
            Write-Host "  [7b/9] Extra reboot required (Event $( if ($verifyData.Evt1801 -eq 'True') {'1801'} else {'1800'} ) detected) - rebooting and re-verifying..." -ForegroundColor Yellow
            Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
            Start-Sleep -Seconds $WaitSeconds
            $vm = Get-VM -Name $vmName
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $row.Notes += "Tools timeout after 7b extra reboot. "
                $row.SnapshotRetained = $snapCreated
                $report.Add($row)
                continue
            }

            $taskOut2 = Invoke-VMScript -VM $vm -ScriptText $taskTriggerScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            Write-Host $taskOut2.ScriptOutput -ForegroundColor Gray

            Write-Host "  [7b/9] Re-verifying after extra reboot..." -ForegroundColor Cyan
            $verifyOut2  = Invoke-VMScript -VM $vm -ScriptText (Get-TimestampedVerifyScript -StartTime $vmRunStart) `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $verifyData2 = $null
            try {
                $lines2 = $verifyOut2.ScriptOutput -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
                if ($lines2 -contains "VERIFY_START" -and $lines2 -contains "VERIFY_END") {
                    $map2 = @{}
                    foreach ($line2 in $lines2) {
                        if ($line2 -match '^([^=]+)=(.*)$') { $map2[$Matches[1]] = $Matches[2] }
                    }
                    $verifyData2 = [PSCustomObject]$map2
                }
            } catch {}

            if ($null -ne $verifyData2) {
                # Update row with fresh verify data
                $verifyData      = $verifyData2
                $row.KEK_2023    = $verifyData.KEK_2023
                $row.DB_2023     = $verifyData.DB_2023
                $row.FinalStatus = if ($verifyData.Servicing_Status) {
                    $verifyData.Servicing_Status
                } elseif ($verifyData.AvailableUpdates -eq "0x4000") {
                    "Updated"
                } else {
                    "Unknown"
                }
                $row.Evt1808 = $verifyData.Evt1808
                $row.Evt1801 = $verifyData.Evt1801
                $row.Evt1800 = $verifyData.Evt1800
                $row.Evt1802 = $verifyData.Evt1802
                $row.Evt1803 = $verifyData.Evt1803
                $row.Evt1795 = $verifyData.Evt1795
                if ($verifyData.UEFICA2023ErrorExists -eq "True") {
                    $row.UEFICA2023Error = "ERROR ($($verifyData.UEFICA2023ErrorValue))"
                }

                $color2 = if ($row.FinalStatus -eq "Updated" -and $verifyData.Evt1801 -ne "True") { "Green" } else { "Yellow" }
                Write-Host (("  [7b/9] Post-reboot: Status: {0} | KEK 2023: {1} | DB 2023: {2} | AvailableUpdates: {3} | Evt 1808: {4}") -f
                    $row.FinalStatus, $row.KEK_2023, $row.DB_2023,
                    $verifyData.AvailableUpdates, $row.Evt1808) -ForegroundColor $color2

                # If 1801 still present and 1808 still absent after extra reboot, diagnose the cause
                if ($verifyData.Evt1801 -eq "True" -and $verifyData.Evt1808 -ne "True") {
                    Write-Warning "  [7b/9] Event 1801 persists after extra reboot - investigating cause..."
                    $row.Notes += "Event 1801 persisted after extra reboot. "

                    if ($verifyData.Evt1802 -eq "True") {
                        Write-Warning "    Event 1802: update blocked by known firmware issue - OEM firmware update required."
                        $row.Notes += "Cause: Event 1802 - OEM firmware issue blocking update. Contact OEM for firmware update. "
                    } elseif ($verifyData.Evt1795 -eq "True") {
                        Write-Warning "    Event 1795: UEFI variable write-protected - OEM firmware update required."
                        $row.Notes += "Cause: Event 1795 - UEFI variable write-protected. Contact OEM for firmware update. "
                    } elseif ($verifyData.UEFICA2023ErrorExists -eq "True") {
                        Write-Warning "    UEFICA2023Error registry key present (value: $($verifyData.UEFICA2023ErrorValue)) - deployment error occurred."
                        $row.Notes += "Cause: UEFICA2023Error = $($verifyData.UEFICA2023ErrorValue). Trace via Event Viewer > System > TPM-WMI. "
                    } elseif ($verifyData.AvailableUpdates -ne "0x4000" -and $verifyData.AvailableUpdates -ne "not found") {
                        Write-Warning "    AvailableUpdates = $($verifyData.AvailableUpdates) - update task may not have completed. Trigger Secure-Boot-Update task manually."
                        $row.Notes += "Cause: AvailableUpdates = $($verifyData.AvailableUpdates) after extra reboot - task may need manual trigger. "
                    } else {
                        Write-Warning "    No specific blocking event found - may need another reboot cycle or Windows Update."
                        $row.Notes += "Cause undetermined - Event 1801 persists with no blocking error event. May resolve after Windows Update or another reboot cycle. "
                    }
                } else {
                    Write-Host "  [7b/9] Complete - Event 1808 present$(if ($verifyData.Evt1801 -eq 'True') {' (1801 also present but 1808 confirms completion)'})." -ForegroundColor Green
                }
            } else {
                Write-Warning "  [7b/9] Re-verify script returned no output after extra reboot."
                $row.Notes += "Re-verify after 7b reboot returned no output - check VM manually. "
            }
        }

        $certGood = ($row.FinalStatus -eq "Updated"   -and
                     $row.KEK_2023   -eq "True"        -and
                     $row.DB_2023    -eq "True"         -and
                     $row.UEFICA2023Error -eq "")

        $color = if ($certGood) { "Green" } else { "Yellow" }
        Write-Host (("  Status: {0} | KEK 2023: {1} | DB 2023: {2} | AvailableUpdates: {3} | Evt 1808: {4}{5}") -f
            $row.FinalStatus, $row.KEK_2023, $row.DB_2023,
            $verifyData.AvailableUpdates, $row.Evt1808,
            $(if ($row.UEFICA2023Error) { " | RegError: $($row.UEFICA2023Error)" } else { "" })) -ForegroundColor $color
        if ($verifyData.Evt1802 -eq "True") { Write-Host "    Event 1802: update blocked by known firmware issue - contact OEM." -ForegroundColor Red }
        if ($verifyData.Evt1803 -eq "True") { Write-Host "    Event 1803: no PK-signed KEK found - PK remediation required." -ForegroundColor Yellow }
        if ($verifyData.Evt1795 -eq "True") { Write-Host "    Event 1795: firmware error on variable write - contact OEM." -ForegroundColor Red }

        # ------------------------------------------------------------------
        # Step 8 - Platform Key (PK) check
        # VMs on ESXi < 9.0 have a NULL PK by default. A valid PK is required
        # for Windows to authenticate future KEK/DB updates. Without it the
        # same certificate expiry situation will recur. This step always runs;
        # remediation (step 9) is skipped only when PK is already valid.
        # ------------------------------------------------------------------
        Write-Host "  [8/9] Checking Platform Key (PK) validity..." -ForegroundColor Cyan
        $pkGood = $false
        $pkBitLockerActive = $false
        try {
            $pkOut  = Invoke-VMScript -VM $vm -ScriptText $pkCheckScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $pkJson = ($pkOut.ScriptOutput -split "`r?`n" |
                Where-Object { $_.Trim() -match '^\{' } | Select-Object -Last 1).Trim()
            if ($pkJson) {
                $pkData = $pkJson | ConvertFrom-Json
                $row.PK_Status     = $pkData.PK_Status
                # Only WindowsOEM and Microsoft PKs are trusted by Windows Update
                # for authenticating future KEK changes. Valid_Other is ESXi's
                # placeholder - per Broadcom KB 423919 ESXi < 9.0 has no valid PK.
                $pkGood            = $pkData.PK_Status -in @("Valid_WindowsOEM", "Valid_Microsoft")
                $pkBitLockerActive = $pkData.BitLockerActive -eq "True"
                $pkColor = if ($pkGood) { "Green" } elseif ($pkData.PK_Status -eq "Valid_Other") { "Yellow" } else { "Red" }
                Write-Host ("    PK Status    : {0}" -f $pkData.PK_Status) -ForegroundColor $pkColor
                if ($pkData.PK_Status -eq "Valid_Other") {
                    Write-Host "    NOTE: Valid_Other = ESXi placeholder PK (not trusted by Windows Update for KEK auth)." -ForegroundColor Yellow
                    Write-Host "    Enrollment of proper PK required per Broadcom KB 423919." -ForegroundColor Yellow
                }
                Write-Host ("    BitLocker    : {0}" -f $(if ($pkBitLockerActive) {"Active"} else {"Inactive"})) `
                    -ForegroundColor $(if ($pkBitLockerActive) {"Yellow"} else {"Gray"})
            }
        } catch {
            Write-Warning "    PK check failed: $($_.Exception.Message)"
            $row.Notes += "PK check failed. "
        }

        if ($pkGood) {
            Write-Host ("    PK is valid ({0}) - no remediation needed." -f $row.PK_Status) -ForegroundColor Green
            $row.PKRemediated = $true

        } elseif (-not $PKDerPath) {
            Write-Warning "    PK is invalid/NULL/placeholder. Provide -PKDerPath to remediate automatically."
            Write-Warning "    Download WindowsOEMDevicesPK.der from:"
            Write-Warning "    https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
            $row.Notes += "PK invalid/placeholder - re-run with -PKDerPath to remediate. "

        } else {
            # ------------------------------------------------------------------
            # Step 9 - PK remediation
            #
            # Broadcom KB 423919 (updated March 2026) documents a manual procedure
            # using uefi.allowAuthBypass + FAT32 VMDK + Force EFI Setup for all
            # ESXi versions (7.x, 8.x, 9.x). That method requires manual UEFI
            # UI interaction and cannot be automated.
            #
            # This script uses UEFI SetupMode (ESXi 8.0+), an automatable
            # alternative: uefi.secureBootMode.overrideOnce = SetupMode allows
            # PK enrollment from the guest OS via Format-SecureBootUEFI.
            # SetupMode is not available on ESXi 7.x - those hosts require the
            # manual KB 423919 disk procedure.
            #
            # NOTE: BitLocker suspension from step 0 is consumed by the cert
            # update reboots (steps 2 and 6). If BitLocker has auto-resumed by
            # the time we get here, it is re-suspended before the SetupMode
            # reboot to prevent a PCR 7 change from triggering recovery mode.
            # ------------------------------------------------------------------

            # Check ESXi host version - SetupMode requires ESXi >= 8.0
            $vmHost    = Get-VMHost -VM $vm -ErrorAction SilentlyContinue
            $hostVerStr = $vmHost.Version
            $hostMajor  = [int]($hostVerStr -split '\.')[0]

            if ($hostMajor -lt 8) {
                Write-Warning "  [9/9] PK remediation skipped - ESXi host is version $hostVerStr (SetupMode requires 8.0+)."
                Write-Warning "  For ESXi 7.x, use the manual allowAuthBypass + FAT32 disk procedure in Broadcom KB 423919."
                $row.Notes += "PK remediation skipped - host ESXi $hostVerStr requires manual disk/BIOS method (KB 423919). "
            } else {

            Write-Host "  [9/9] Remediating PK via UEFI SetupMode (ESXi $hostVerStr)..." -ForegroundColor Cyan

            # --- BitLocker re-check before SetupMode reboot ---
            # The step 0 suspension (RebootCount 2) covers the cert-update power
            # cycle (step 2) and the cert-update reboot (step 6). By the time we
            # reach here BitLocker may have auto-resumed. Re-suspend if active.
            $skipPKRemediation = $false
            if ($pkBitLockerActive) {
                Write-Host "    BitLocker has auto-resumed - re-suspending before SetupMode reboot..." -ForegroundColor Yellow
                if (-not $BitLockerBackupShare) {
                    Write-Warning "    BitLocker is active but no -BitLockerBackupShare was provided."
                    Write-Warning "    Cannot safely proceed with PK remediation - skipping to avoid lockout."
                    $row.Notes += "PK remediation skipped - BitLocker active at PK step, no backup share. Re-run with -BitLockerBackupShare to process. "
                    $skipPKRemediation = $true
                } else {
                    # Back up keys again - state may have changed since step 0
                    $pkTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                    $pkBackupOk  = Backup-BitLockerKeys -VMObj $vm -BackupShare $BitLockerBackupShare -Timestamp "PK_$pkTimestamp"
                    if (-not $pkBackupOk) {
                        Write-Warning "    Recovery key backup failed - skipping PK remediation to avoid lockout."
                        $row.Notes += "PK remediation skipped - BitLocker re-backup failed at PK step. "
                        $skipPKRemediation = $true
                    } else {
                        $suspendOut2  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                            -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                        $suspendJson2 = ($suspendOut2.ScriptOutput -split "`r?`n" |
                            Where-Object { $_.Trim() -match '^\{' } | Select-Object -Last 1).Trim()
                        if ($suspendJson2) {
                            $suspendData2 = $suspendJson2 | ConvertFrom-Json
                            Write-Host ("    $($suspendData2.Notes)") -ForegroundColor $(if ($suspendData2.Suspended.Count -gt 0) {"Green"} else {"Yellow"})
                            $row.Notes += "BL re-suspend at PK step: $($suspendData2.Notes) "
                        }
                    }
                }
            }

            if (-not $skipPKRemediation) {

            # [1/5] Set SetupMode VMX option
            Write-Host "  [PK 1/5] Setting UEFI SetupMode VMX option..." -ForegroundColor Cyan
            Set-VMXOption -VMObj $vm -Key "uefi.secureBootMode.overrideOnce" -Value "SetupMode"
            $optVal = Get-VMXOption -VMObj (Get-VM -Name $vmName) -Key "uefi.secureBootMode.overrideOnce"
            if ($optVal -ne "SetupMode") {
                throw "Failed to set uefi.secureBootMode.overrideOnce - check vCenter permissions."
            }
            Write-Host "    SetupMode VMX option confirmed." -ForegroundColor Green

            # [2/5] Power off and on - SetupMode takes effect on next boot
            Write-Host "  [PK 2/5] Rebooting into SetupMode..." -ForegroundColor Cyan
            Stop-VM -VM $vm -Confirm:$false -Kill -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 5
            Start-VM -VM $vm | Out-Null
            $vm = Get-VM -Name $vmName
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                throw "Tools timeout after SetupMode reboot."
            }
            Write-Host "    VM is back online." -ForegroundColor Green

            # [3/5] Copy .der certificate file(s) to guest temp
            Write-Host "  [PK 3/5] Copying .der certificate file(s) to guest..." -ForegroundColor Cyan
            try {
                Copy-VMGuestFile -Source $PKDerPath `
                    -Destination "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
                    -VM $vm -LocalToGuest -GuestCredential $GuestCredential -Force -ErrorAction Stop
                Write-Host "    WindowsOEMDevicesPK.der copied." -ForegroundColor Green
            } catch {
                throw "Failed to copy PK der file to guest: $($_.Exception.Message)"
            }
            if ($KEKDerPath) {
                try {
                    Copy-VMGuestFile -Source $KEKDerPath `
                        -Destination "C:\Windows\Temp\kek2023.der" `
                        -VM $vm -LocalToGuest -GuestCredential $GuestCredential -Force -ErrorAction Stop
                    Write-Host "    kek2023.der copied." -ForegroundColor Green
                } catch {
                    Write-Warning "    Failed to copy KEK der - KEK update will be skipped: $($_.Exception.Message)"
                }
            }

            # [4/5] Enroll PK via Set-SecureBootUEFI
            Write-Host "  [PK 4/5] Enrolling PK via Set-SecureBootUEFI..." -ForegroundColor Cyan
            Write-Host "    NOTE: If this fails due to UAC, run Set-SecureBootUEFI directly" -ForegroundColor Yellow
            Write-Host "    on the VM console in an elevated PowerShell session." -ForegroundColor Yellow

            $enrollOut  = Invoke-VMScript -VM $vm -ScriptText $enrollPKScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
            $enrollJson = ($enrollOut.ScriptOutput -split "`r?`n" |
                Where-Object { $_.Trim() -match '^\{' } | Select-Object -Last 1).Trim()
            if ($enrollJson) {
                $enrollData = $enrollJson | ConvertFrom-Json
                Write-Host ("    PKEnrolled : {0}" -f $enrollData.PKEnrolled) -ForegroundColor $(if ($enrollData.PKEnrolled) {"Green"} else {"Red"    })
                Write-Host ("    KEKUpdated : {0}" -f $enrollData.KEKUpdated) -ForegroundColor $(if ($enrollData.KEKUpdated) {"Green"} else {"Yellow" })
                Write-Host ("    Notes      : {0}" -f $enrollData.Notes)      -ForegroundColor Gray
                $row.Notes += "PK enroll: $($enrollData.Notes) "
                if (-not $enrollData.PKEnrolled) {
                    Write-Warning "    PK enrollment did not succeed via Invoke-VMScript (may be a UAC elevation issue)."
                    Write-Warning "    Run the following directly on the VM in an elevated PowerShell session:"
                    Write-Host   '    Format-SecureBootUEFI -Name PK -CertificateFilePath "C:\Windows\Temp\WindowsOEMDevicesPK.der" -SignatureOwner "55555555-0000-0000-0000-000000000000" -FormatWithCert -Time "2025-10-23T11:00:00Z" | Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z"' -ForegroundColor White
                }
            } else {
                Write-Warning "    No JSON output from enrollment script."
                $row.Notes += "Enrollment script returned no parseable output. "
            }

            # [5/5] Clear SetupMode VMX option, reboot, verify
            Write-Host "  [PK 5/5] Clearing SetupMode, rebooting, and verifying PK..." -ForegroundColor Cyan
            # Clear explicitly - if enrollment failed the option must be cleared
            # before retry to avoid persisting SetupMode unexpectedly
            Set-VMXOption -VMObj (Get-VM -Name $vmName) -Key "uefi.secureBootMode.overrideOnce" -Value ""
            Write-Host "    SetupMode VMX option cleared." -ForegroundColor Gray

            Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
            Start-Sleep -Seconds $WaitSeconds
            $vm = Get-VM -Name $vmName
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                throw "Tools timeout after post-enrollment reboot."
            }

            $pkVerifyOut  = Invoke-VMScript -VM $vm -ScriptText $verifyPKScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $pkVerifyJson = ($pkVerifyOut.ScriptOutput -split "`r?`n" |
                Where-Object { $_.Trim() -match '^\{' } | Select-Object -Last 1).Trim()
            if ($pkVerifyJson) {
                $pkVerifyData  = $pkVerifyJson | ConvertFrom-Json
                $row.PK_Status    = $pkVerifyData.PK_Status
                $row.PKEnrolled   = $true   # enrollment was attempted this run
                $row.PKRemediated = ($pkVerifyData.PK_Status -like "Valid*")
                $pkColor = if ($row.PKRemediated) { "Green" } else { "Red" }
                Write-Host ("  PK Status after remediation: {0}" -f $pkVerifyData.PK_Status) -ForegroundColor $pkColor
                if (-not $row.PKRemediated) {
                    $row.Notes += "PK still invalid after enrollment - manual intervention required. "
                }
            }

            if ($row.BitLockerKeysBacked) {
                Write-Host "  BitLocker recovery keys retained at: $BitLockerBackupShare" -ForegroundColor Yellow
                Write-Host "  BitLocker auto-resumes after 2 reboots. Verify protection status after this maintenance window." -ForegroundColor Yellow
            }

            } # end if (-not $skipPKRemediation)
            } # end if ($hostMajor -ge 8)
        }

        # ------------------------------------------------------------------
        # Snapshot disposition
        # allGood requires: cert update complete AND (PK valid OR remediated
        # OR no PKDerPath provided - in which case PK is flagged for follow-up
        # but cert update is complete, which is the minimum for allGood)
        # ------------------------------------------------------------------
        $allGood = $certGood -and ($pkGood -or $row.PKRemediated -or (-not $PKDerPath))

        if ($NoSnapshot) {
            $row.SnapshotRetained = $false
        } elseif ($allGood -and $snapCreated -and -not $RetainSnapshots) {
            Write-Host "  Removing snapshot (completed successfully)..." -ForegroundColor Gray
            Remove-VMSnapshotSafe -VMObj $vm -Name $snapshotName
            $row.SnapshotRetained = $false
        } elseif ($snapCreated) {
            $row.SnapshotRetained = $true
            if ($RetainSnapshots -and $allGood) {
                Write-Host "  Snapshot retained (-RetainSnapshots). Run -CleanupSnapshots when ready." -ForegroundColor Yellow
            } elseif (-not $certGood) {
                Write-Host "  Snapshot retained (cert update incomplete - may need second reboot cycle)." -ForegroundColor Yellow
                $row.Notes += "Cert update incomplete - may need manual second reboot cycle. "
            } elseif (-not $allGood) {
                Write-Host "  Snapshot retained (PK remediation incomplete)." -ForegroundColor Yellow
            }
        }

    } catch {
        $row.FinalStatus      = "ERROR"
        $row.SnapshotRetained = $snapCreated
        $row.Notes           += "Exception: $($_.Exception.Message)"
        Write-Warning "  Error processing $vmName`: $($_.Exception.Message)"
        if ($snapCreated) {
            Write-Warning "  Snapshot retained for rollback: '$snapshotName'"
        }
    }

    $report.Add($row)
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "`n$('='*60)" -ForegroundColor White
Write-Host "SUMMARY" -ForegroundColor White
Write-Host "$('='*60)" -ForegroundColor White
$report | Format-Table VMName, SnapshotCreated, BitLockerKeysBacked, BitLockerSuspended,
    NVRAMRenamed, HWUpgraded, KEK_AfterNVRAM, UpdateTriggered, KEK_2023, DB_2023,
    FinalStatus, UEFICA2023Error, Evt1808, Evt1801, Evt1802, Evt1803, Evt1800, Evt1795,
    PK_Status, PKEnrolled, PKRemediated, SnapshotRetained, Notes -AutoSize

$csvPath = ".\SecureBoot_Bulk_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Exported to: $csvPath" -ForegroundColor Green

$total      = $report.Count
$complete   = ($report | Where-Object { $_.FinalStatus -eq "Updated" }).Count
$skipped    = ($report | Where-Object { $_.BitLockerSkipped }).Count
$failed     = ($report | Where-Object { $_.FinalStatus -eq "ERROR" }).Count
$pending    = $total - $complete - $skipped - $failed
$retained   = ($report | Where-Object { $_.SnapshotRetained }).Count
$blBacked   = ($report | Where-Object { $_.BitLockerKeysBacked -eq $true }).Count
# PK counters - distinguish already-valid from newly enrolled
# Valid_Other is expected on ESXi-regenerated NVRAM (VMware's own PK).
# Valid_WindowsOEM / Valid_Microsoft indicate a vendor/MS-signed PK.
# All three are treated as valid by the script.
# Valid_Other = ESXi placeholder; only WindowsOEM/Microsoft count as already-good
$pkAlreadyValid = ($report | Where-Object { $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft") -and -not $_.PKEnrolled }).Count
$pkPlaceholder  = ($report | Where-Object { $_.PK_Status -eq "Valid_Other" -and -not $_.PKEnrolled }).Count
$pkEnrolledOk   = ($report | Where-Object { $_.PKEnrolled -and $_.PKRemediated }).Count
$pkEnrolledFail = ($report | Where-Object { $_.PKEnrolled -and -not $_.PKRemediated }).Count
$pkNeeds        = ($report | Where-Object { $_.PK_Status -notlike "Valid*" -and $_.PK_Status -ne "Not checked" }).Count

Write-Host ""
Write-Host "Completed          : $complete / $total" -ForegroundColor Green
if ($pkAlreadyValid -gt 0) { Write-Host "PK already valid   : $pkAlreadyValid  (WindowsOEM/Microsoft - no enrollment needed)"  -ForegroundColor Green  }
if ($pkPlaceholder  -gt 0) { Write-Host "PK placeholder     : $pkPlaceholder  (ESXi-generated - enrolled this run)"              -ForegroundColor Green  }
if ($pkEnrolledOk   -gt 0) { Write-Host "PK enrolled        : $pkEnrolledOk  (newly enrolled this run)"                        -ForegroundColor Green  }
if ($pkEnrolledFail -gt 0) { Write-Host "PK enroll failed   : $pkEnrolledFail  (manual intervention required - see Notes)"     -ForegroundColor Red    }
if ($pkNeeds        -gt 0) { Write-Host "PK still invalid   : $pkNeeds  (provide -PKDerPath and re-run)"                       -ForegroundColor Yellow }
if ($blBacked       -gt 0) { Write-Host "BL keys backed up  : $blBacked  (files at: $BitLockerBackupShare)"                    -ForegroundColor Yellow }
if ($skipped        -gt 0) { Write-Host "Skipped (BitLocker): $skipped  (provide -BitLockerBackupShare to process)"            -ForegroundColor Yellow }
if ($pending        -gt 0) { Write-Host "Pending            : $pending (may need second reboot cycle)"                         -ForegroundColor Yellow }
if ($failed         -gt 0) { Write-Host "Errors             : $failed"                                                         -ForegroundColor Red    }
if ($retained       -gt 0) { Write-Host "Snapshots retained : $retained - run -CleanupSnapshots when ready."                   -ForegroundColor Yellow }

if ($pkNeeds -gt 0 -and -not $PKDerPath) {
    Write-Host ""
    Write-Host "To remediate the NULL/placeholder PK on affected VMs, download WindowsOEMDevicesPK.der from:" -ForegroundColor Cyan
    Write-Host "  https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der" -ForegroundColor Cyan
    Write-Host "Then re-run with: -PKDerPath '.\WindowsOEMDevicesPK.der'" -ForegroundColor Cyan
}

# Notes block - shown separately so nothing is truncated by Format-Table
$noteVMs = $report | Where-Object { $_.Notes -ne "" }
if ($noteVMs) {
    Write-Host "`nNOTES" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White
    foreach ($n in $noteVMs) {
        Write-Host "  $($n.VMName):" -ForegroundColor Cyan
        Write-Host "    $($n.Notes)"
    }
}
