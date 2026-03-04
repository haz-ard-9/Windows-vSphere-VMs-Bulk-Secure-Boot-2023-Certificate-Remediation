<#
.SYNOPSIS
    Bulk Secure Boot 2023 certificate remediation for VMware VMs on ESXi 8.
    Optionally takes a snapshot before making any changes. Includes rollback,
    snapshot cleanup, and NVRAM cleanup modes for post-validation housekeeping.

    Process per VM (default):
    0. BitLocker safety check
    1. Take snapshot (skipped with -NoSnapshot)
    2. Power off
    3. Rename .nvram -> .nvram_old (ESXi regenerates with 2023 KEK on next boot)
    4. Power on, wait for Tools, verify 2023 certs in new NVRAM
    5. Clear any stale Servicing registry state
    6. Set AvailableUpdates = 0x5944, trigger Secure-Boot-Update task
    7. Reboot, trigger task again
    8. Verify final status
    9. Remove snapshot on success (unless -RetainSnapshots or -NoSnapshot)

.PARAMETER VMName
    One or more VM display names. Accepts wildcards. Can be combined with
    -VMListCsv — both sources are merged and deduplicated.
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
    path — the -Rollback mode will still restore the .nvram_old file if one
    exists, but cannot revert VM state (registry changes etc.).

.PARAMETER RetainSnapshots
    Keep snapshots even on success. Use this when you want to validate VMs
    over a period of days before removing snapshots. Use -CleanupSnapshots
    later to remove them. Cannot be combined with -NoSnapshot.

.PARAMETER CleanupSnapshots
    Snapshot cleanup mode. Finds and removes all Pre-SecureBoot-Fix* snapshots
    on target VMs. Does not require -GuestCredential. Run this after a
    validation period to reclaim datastore space.
    Always run -CleanupSnapshots BEFORE -CleanupNvram — the snapshot is your
    rollback path.

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

.PARAMETER WaitSeconds
    Seconds to wait after issuing a reboot before polling for Tools.
    Default 90. Increase for slower VMs.

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

.NOTES
    Do not include domain controllers in automated runs — handle DCs manually.
    VMs with BitLocker active will be skipped automatically.
    Ensure sufficient datastore space for snapshots before running large batches.
    Requires VMware.PowerCLI module and an active vCenter connection, or
    the script will prompt for vCenter credentials on first run.
#>

param(
    [string[]]$VMName,
    [string]$VMListCsv,
    [PSCredential]$GuestCredential,
    [switch]$NoSnapshot,
    [switch]$RetainSnapshots,
    [switch]$CleanupSnapshots,
    [switch]$CleanupNvram,
    [switch]$Rollback,
    [int]$WaitSeconds = 90
)

# =============================================================================
# PARAMETER VALIDATION
# =============================================================================
if ($NoSnapshot -and $RetainSnapshots) {
    Write-Error "-NoSnapshot and -RetainSnapshots cannot be used together."
    return
}

$modeSwitches = @($CleanupSnapshots, $CleanupNvram, $Rollback) | Where-Object { $_ }
if ($modeSwitches.Count -gt 1) {
    Write-Error "-CleanupSnapshots, -CleanupNvram, and -Rollback are mutually exclusive. Specify only one."
    return
}

# =============================================================================
# VCENTER CONNECTION
# Update the server name below to match your vCenter instance.
# =============================================================================
if (-not $global:DefaultVIServer) {
    Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope User -Confirm:$false
    Connect-VIServer -Server "vcenter.yourdomain.com" -Credential (Get-Credential -Message "vCenter credentials")
}

$isMainMode = -not $CleanupSnapshots -and -not $CleanupNvram -and -not $Rollback
if ($isMainMode -and -not $GuestCredential) {
    $GuestCredential = Get-Credential -Message "Guest OS credentials (domain admin)"
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
        $resolved = foreach ($name in $names) {
            $found = Get-VM -Name $name -ErrorAction SilentlyContinue
            if (-not $found) {
                Write-Warning "VM not found in vCenter: '$name' - skipping."
            }
            $found
        }
        $resolved = $resolved |
            Where-Object { $_ -and $_.Guest.OSFullName -match "Windows Server" } |
            Sort-Object -Property Id -Unique
        return $resolved
    }

    # No names specified — return all in-scope Windows Server VMs
    $all = Get-VM | Where-Object { $_.Guest.OSFullName -match "Windows Server" }
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

    $datacenter      = Get-Datacenter | Select-Object -First 1
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

# Final verification - registry status and firmware cert presence
$verifyScript = @'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"
$result  = @{}

$result["Servicing_Status"] = Get-ItemPropertyValue -Path $svcPath `
    -Name "UEFICA2023Status" -EA SilentlyContinue
$result["AvailableUpdates"] = "0x$("{0:X4}" -f (Get-ItemPropertyValue `
    -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue))"

try {
    $result["KEK_2023"] = ([System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI kek -EA Stop).Bytes) -match
        'Microsoft Corporation KEK 2K CA 2023').ToString()
    $result["DB_2023"]  = ([System.Text.Encoding]::ASCII.GetString(
        (Get-SecureBootUEFI db -EA Stop).Bytes) -match
        'Windows UEFI CA 2023').ToString()
} catch {
    $result["KEK_2023"] = "CheckFailed"
    $result["DB_2023"]  = "CheckFailed"
}

$result | ConvertTo-Json -Compress
'@

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

    $datacenter      = Get-Datacenter | Select-Object -First 1
    $datacenterView  = $datacenter | Get-View
    $dcRef           = $datacenterView.MoRef
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
    Write-Warning "exists — NVRAM restore alone does not undo registry changes."
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
                Stop-VM -VM $vm -Confirm:$false -Force -ErrorAction Stop | Out-Null
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

$confirm = Read-Host "Continue? (Y/N)"
if ($confirm -notmatch '^[Yy]') { Write-Host "Aborted."; return }

$report = [System.Collections.Generic.List[PSObject]]::new()

# =============================================================================
# MAIN PROCESSING LOOP
# =============================================================================
foreach ($vm in $vms) {
    $vmName      = $vm.Name
    $snapCreated = $false

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "Processing: $vmName" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White

    $row = [PSCustomObject]@{
        VMName           = $vmName
        SnapshotCreated  = $false
        BitLockerSkipped = $false
        NVRAMRenamed     = $false
        KEK_AfterNVRAM   = "Not checked"
        DB_AfterNVRAM    = "Not checked"
        UpdateTriggered  = $false
        KEK_2023         = "Not checked"
        DB_2023          = "Not checked"
        FinalStatus      = "Not checked"
        SnapshotRetained = $false
        Notes            = ""
    }

    try {
        # ------------------------------------------------------------------
        # Step 0 - BitLocker safety check (only if VM is powered on)
        # ------------------------------------------------------------------
        if ($vm.PowerState -eq "PoweredOn") {
            Write-Host "  [0/7] Checking BitLocker/TPM..." -ForegroundColor Cyan
            try {
                $tpmOut  = Invoke-VMScript -VM $vm -ScriptText $tpmCheckScript `
                    -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                $jsonLine = ($tpmOut.ScriptOutput -split "`r?`n" | Where-Object { $_.Trim() -match '^{' } | Select-Object -Last 1).Trim()
                if (-not $jsonLine) { throw "No JSON output from BitLocker check script" }
                $tpmData = $jsonLine | ConvertFrom-Json

                if ($tpmData.BitLockerActive) {
                    Write-Warning "  BitLocker ACTIVE on $vmName - SKIPPING."
                    Write-Warning "  Suspend BitLocker first, then re-run against this VM."
                    $row.BitLockerSkipped = $true
                    $row.Notes = "SKIPPED - BitLocker active. Suspend BitLocker then re-run."
                    $report.Add($row)
                    continue
                }
                if ($tpmData.TPMPresent) {
                    Write-Host "  vTPM present, BitLocker not active - proceeding with caution." -ForegroundColor Yellow
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
            Write-Host "  [1/7] Skipping snapshot (-NoSnapshot specified)." -ForegroundColor Yellow
            $row.Notes += "No snapshot taken (-NoSnapshot). "
        } else {
            Write-Host "  [1/7] Taking snapshot..." -ForegroundColor Cyan
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
        # Step 2 - Power off
        # ------------------------------------------------------------------
        Write-Host "  [2/7] Powering off..." -ForegroundColor Cyan
        if ($vm.PowerState -eq "PoweredOn") {
            Stop-VM -VM $vm -Confirm:$false -Force -ErrorAction Stop | Out-Null
            Start-Sleep -Seconds 10
        }

        # ------------------------------------------------------------------
        # Step 3 - Rename NVRAM (triggers fresh generation with 2023 certs)
        # ------------------------------------------------------------------
        Write-Host "  [3/7] Renaming NVRAM file on datastore..." -ForegroundColor Cyan
        $row.NVRAMRenamed = Rename-VMNvram -VMObj $vm
        if (-not $row.NVRAMRenamed) {
            $row.Notes += "NVRAM rename failed - cert update may not succeed. "
        }

        # ------------------------------------------------------------------
        # Step 4 - Power on (ESXi regenerates NVRAM with 2023 KEK)
        # ------------------------------------------------------------------
        Write-Host "  [4/7] Powering on (ESXi regenerates NVRAM with 2023 certs)..." -ForegroundColor Cyan
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

        # ------------------------------------------------------------------
        # Step 5 - Clear stale registry state, set AvailableUpdates, trigger task
        # ------------------------------------------------------------------
        Write-Host "  [5/7] Clearing stale state and triggering update..." -ForegroundColor Cyan
        $updateOut = Invoke-VMScript -VM $vm -ScriptText $updateScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
        Write-Host $updateOut.ScriptOutput -ForegroundColor Gray
        $row.UpdateTriggered = $true

        # ------------------------------------------------------------------
        # Step 6 - Reboot, trigger task again
        # ------------------------------------------------------------------
        Write-Host "  [6/7] Rebooting..." -ForegroundColor Cyan
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

        # ------------------------------------------------------------------
        # Step 7 - Final verification
        # ------------------------------------------------------------------
        Write-Host "  [7/7] Verifying final status..." -ForegroundColor Cyan
        $verifyOut  = Invoke-VMScript -VM $vm -ScriptText $verifyScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
        $verifyData = $verifyOut.ScriptOutput.Trim() | ConvertFrom-Json

        $row.KEK_2023    = $verifyData.KEK_2023
        $row.DB_2023     = $verifyData.DB_2023
        $row.FinalStatus = $verifyData.Servicing_Status

        $allGood = ($row.FinalStatus -eq "Updated" -and
                    $row.KEK_2023   -eq "True"     -and
                    $row.DB_2023    -eq "True")

        $color = if ($allGood) { "Green" } else { "Yellow" }
        Write-Host ("  Status: {0} | KEK 2023: {1} | DB 2023: {2} | AvailableUpdates: {3}" -f
            $row.FinalStatus, $row.KEK_2023, $row.DB_2023,
            $verifyData.AvailableUpdates) -ForegroundColor $color

        # Snapshot disposition
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
            } elseif (-not $allGood) {
                Write-Host "  Snapshot retained (not fully updated - may need second reboot cycle)." -ForegroundColor Yellow
                $row.Notes += "Not fully updated - may need manual second reboot cycle. "
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
$report | Format-Table VMName, SnapshotCreated, NVRAMRenamed, KEK_AfterNVRAM,
    UpdateTriggered, KEK_2023, DB_2023, FinalStatus, SnapshotRetained, Notes -AutoSize

$csvPath = ".\SecureBoot_Bulk_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Exported to: $csvPath" -ForegroundColor Green

$total    = $report.Count
$complete = ($report | Where-Object { $_.FinalStatus -eq "Updated" }).Count
$skipped  = ($report | Where-Object { $_.BitLockerSkipped }).Count
$failed   = ($report | Where-Object { $_.FinalStatus -eq "ERROR" }).Count
$pending  = $total - $complete - $skipped - $failed
$retained = ($report | Where-Object { $_.SnapshotRetained }).Count

Write-Host ""
Write-Host "Completed          : $complete / $total" -ForegroundColor Green
if ($skipped  -gt 0) { Write-Host "Skipped (BitLocker): $skipped"                                      -ForegroundColor Yellow }
if ($pending  -gt 0) { Write-Host "Pending            : $pending (may need second reboot cycle)"        -ForegroundColor Yellow }
if ($failed   -gt 0) { Write-Host "Errors             : $failed"                                        -ForegroundColor Red    }
if ($retained -gt 0) { Write-Host "Snapshots retained : $retained - run -CleanupSnapshots when ready."  -ForegroundColor Yellow }
