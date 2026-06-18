# Domain Controller Secure Boot 2023 Certificate Remediation
## Manual Procedure for Domain Controllers

---

## Overview

Domain controllers require manual handling due to UAC restrictions that prevent
`Invoke-VMScript` from running elevated commands. The process is identical for
both DCs but must be performed **sequentially** - complete and verify DC1
entirely before touching DC2 (the PDC Emulator holder).

This remediation enrolls the Microsoft 2023 Secure Boot certificates before the
2011 certificates expire. Per
[Microsoft KB 5062710](https://support.microsoft.com/en-us/help/5062710)
(updated May 18, 2026), the relevant dates are: Microsoft Corporation KEK CA 2011
expires **June 24, 2026** (the near-term driver, as it signs DB/DBX updates).
Microsoft UEFI CA 2011 expires **June 27, 2026**. Microsoft Windows Production
PCA 2011 expires **October 19, 2026**. DCs continue to boot normally after expiry,
but lose future Secure Boot and boot-manager security updates until the 2023
certificates are enrolled.

**Order of operations:**
1. **DC1** (secondary / no FSMO roles) - lower risk, process first
2. **DC2** (PDC Emulator holder) - after DC1 is confirmed healthy, transfer PDC Emulator role first

**Time required per DC:** Approximately 45-60 minutes including reboots. Add
15-20 minutes if PK remediation is required.

> Substitute your actual DC hostnames for `DC1` and `DC2` throughout this guide.

**Prerequisites:**
- ESXi host must be on **8.0.2 or later** - earlier versions will not regenerate NVRAM with 2023 certificates
- VM hardware version must be **13 or later** - required for EFI/Secure Boot support
- VM hardware version must be **21 or later** - required for ESXi to populate regenerated NVRAM with the 2023 KEK certificate. Upgrade hardware version before proceeding if below 21
- **VMware Tools must be installed and running** on the DC - required for `Invoke-VMScript` to verify NVRAM cert presence after power-on. Tools should be current with your ESXi host version. Outdated Tools can cause guest script execution to fail silently. Check status in vSphere Client or with PowerCLI:
  ```powershell
  (Get-VM "DC1").Guest.ExtensionData.ToolsStatus  # Expected: toolsOk
  (Get-VM "DC1").Guest.ToolsVersion               # Compare against ESXi bundled version
  ```
- **BitLocker:** If BitLocker is enabled on the DC, you must back up the recovery key and suspend protection **before** rebooting. Changing Secure Boot variables alters PCR 7 measurements and will trigger BitLocker recovery mode if protection is not suspended. See the BitLocker section in each phase below.
- **PK remediation:** Download `WindowsOEMDevicesPK.der` from Microsoft's repository before starting if you intend to enroll the Platform Key:
  ```
  https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der
  ```
  Use the **Download raw file** button on that page to get the binary. Place it somewhere accessible from your admin workstation (e.g., `C:\Tools\WindowsOEMDevicesPK.der`).

---

> ## Important notice regarding support status
>
> This guide includes a step that renames the VM's `.nvram` file to force ESXi to regenerate it fresh with the 2023 KEK certificate on next boot. Broadcom previously documented this approach in [KB 421593](https://web.archive.org/web/20260212085158/https://knowledge.broadcom.com/external/article/421593/missing-microsoft-corporation-kek-ca-202.html) *(archived - Broadcom has removed this KB)*. A Broadcom employee has stated in the [Broadcom community forums](https://community.broadcom.com/vmware-cloud-foundation/discussion/uefi-2023-fully-automated-script-also-with-plattform-key-change) that renaming or deleting the NVRAM file is **not endorsed by VMware engineering and not supported**. **ESXi 8.0 P09 (May 27, 2026) now delivers an official automated PK remediation solution for vTPM-disabled VMs via a simple guest OS reboot. For vTPM-enabled Linux and other non-Windows VMs, Broadcom documents the `uefi.secureBoot.PK.resetOnce` VMX method. For vTPM-enabled Windows VMs, Broadcom currently recommends waiting for the forthcoming capsule-based automated solution rather than using the VMX method, since changing the PK from outside the guest OS can trigger BitLocker recovery or break TPM-sealed secrets. If your hosts are on 8.0 P09 or later, consider following [Broadcom KB 423893](https://knowledge.broadcom.com/external/article/423893) directly instead.** Subsequently, [KB 423919](https://knowledge.broadcom.com/external/article/423919/manual-update-of-secure-boot-variables-i.html) was updated to explicitly state that it replaces KB 421593 specifically **"to avoid suggestions of deleting NVRAM, as that behavior can lead to unexpected corruptions of the associated VM."** This method has been tested and works reliably on ESXi 8.0.2 and later with hardware version 21 VMs. No issues have been encountered by the community that has used this approach in practice. Given the official unsupported position from Broadcom and the explicit corruption warning in KB 423919, use this guide with your own judgment and at your own risk.
>
> The NVRAM file is **renamed** rather than deleted so that rollback is possible - the original file is preserved as `.nvram_old`. A snapshot is also taken before any changes are made. If you encounter any issues, reverting to the snapshot will restore the original NVRAM and return the DC to its pre-change state.
>
> **You may be able to skip the NVRAM rename entirely.** If the KEK 2023 certificate is already present in the VM's NVRAM (which is the case for VMs created on ESXi 8.0.2 or later, or VMs that have already had a partial remediation), the rename is not needed. Check before proceeding - see the KEK Pre-Check step below.

---

## KEK Pre-Check (Do This First)

Before touching the NVRAM, check whether the 2023 KEK certificate is already present. If it is, skip straight to [Phase 1, Step 5](#step-5---apply-registry-fix-directly-on-dc1) - the NVRAM rename and power cycle steps are not needed.

**Option A - PowerShell on the VM** (requires console or RDP access):

Open an elevated PowerShell session on the DC and run:

```powershell
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
```

- `True` - KEK 2023 is present. **Skip the NVRAM rename (Steps 3-4).** Proceed directly to Step 5 to trigger the cert update task.
- `False` - KEK 2023 is missing. Proceed with the full procedure including the NVRAM rename.

**Option B - PowerCLI from your admin workstation** (no console access needed):

```powershell
$cred = Get-Credential
$out  = Invoke-VMScript -VM "DC1" -ScriptText {
    [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
} -ScriptType Powershell -GuestCredential $cred
$out.ScriptOutput.Trim()
```

> **Note:** `Invoke-VMScript` may fail on domain controllers due to UAC restrictions depending on your environment. If it does, use Option A from the VM console instead.

---

## Pre-Work (Complete Before Any Maintenance Window)

### 1. Verify replication health

Run from any domain-joined admin workstation:

```powershell
repadmin /replsummary
repadmin /showrepl
dcdiag /test:replications
```

Do not proceed if replication errors are present. Resolve all replication issues first.

### 2. Confirm FSMO role holders

```powershell
netdom query fsmo
```

Confirm which DC holds the PDC Emulator role. That DC should be processed **second**.
The DC holding no FSMO roles is the lower-risk choice to process first.

### 3. Check SYSVOL replication

```powershell
dfsrdiag replicationstate
```

Confirm SYSVOL is healthy before proceeding.

---

## Phase 1 - DC1 (Secondary DC / No FSMO Roles)

### Step 1 - Take snapshot

Run from your admin workstation PowerCLI session:

```powershell
$vm = Get-VM -Name "DC1"
New-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix" `
    -Description "Pre Secure Boot 2023 cert fix - manual" `
    -Memory:$false -Quiesce:$false -Confirm:$false
```

Verify the snapshot appears in vSphere before continuing.

### Step 2 - BitLocker pre-check (if applicable)

If BitLocker is enabled on DC1, perform these steps **before** powering off.
Skip this step entirely if BitLocker is not in use on this DC.

**Check BitLocker status** (run from an elevated PowerShell session on DC1 via
RDP or console):

```powershell
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, KeyProtector
```

If `ProtectionStatus` is `On`, you must:

**A. Save the recovery key to a secure location:**

```powershell
# Run on DC1 in an elevated PowerShell session
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
    Select-Object KeyProtectorId, RecoveryPassword |
    Format-List
```

Copy the `RecoveryPassword` value and store it in your password manager or
a secure file share accessible to your team. You will need this if the
suspension fails and BitLocker prompts for recovery on reboot.

**B. Suspend BitLocker protection:**

```powershell
# RebootCount 2 covers the power-off/on cycle and the post-cert-update reboot.
# NOTE: If PK remediation is also needed (see Step 9), BitLocker will have
# auto-resumed by that point. The BitLocker pre-check at Step 9 addresses this.
Suspend-BitLocker -MountPoint "C:" -RebootCount 2
```

Verify suspension:

```powershell
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus
# ProtectionStatus should now show: Off (suspended)
```

> BitLocker automatically resumes full protection after the second reboot.
> No manual re-enable step is required unless PK remediation adds additional reboots.

### Step 3 - Rename NVRAM file

```powershell
$vm = Get-VM -Name "DC1"

# Power off
Stop-VM -VM $vm -Confirm:$false
Start-Sleep -Seconds 10

# Locate and rename NVRAM
$vmView  = $vm | Get-View
$vmxPath = $vmView.Config.Files.VmPathName
$dsName  = $vmxPath -replace '^\[(.+?)\].*', '$1'
$vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'

# Resolve the datastore by MoRef from the VM's own attached-datastore list.
# Get-Datastore -Name returns every datastore with that name across the
# inventory, which picks the wrong one when duplicate datastore names exist
# across datacenters or clusters. Match by MoRef instead, the same way the
# script does, and fail loudly if the VMX datastore cannot be resolved.
$ds = $null
foreach ($dsRef in $vmView.Datastore) {
    $candidate = Get-Datastore -Id $dsRef -ErrorAction SilentlyContinue
    if ($candidate -and $candidate.Name -eq $dsName) {
        $ds = $candidate
        break
    }
}
if (-not $ds) {
    throw "Could not resolve VMX datastore '$dsName' from this VM's attached datastore list."
}
$dsBrowser = Get-View $ds.ExtensionData.Browser
$spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$spec.MatchPattern = "*.nvram"
$results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)
$nvramFile = $results.File | Where-Object { $_.Path -notmatch "_old" } | Select-Object -First 1

# Safety: confirm an active .nvram file was actually found before proceeding.
if (-not $nvramFile) {
    throw "No active .nvram file found. The VM may already have been renamed or partially rolled back. Stop and investigate."
}

$oldBackupName = $nvramFile.Path -replace '\.nvram$', '.nvram_old'

# Safety: do NOT overwrite an existing .nvram_old. If one is present, a prior
# partial attempt likely left it, and it is the only rollback copy. Stop rather
# than destroy it. (This mirrors the protection the bulk script performs.)
$oldSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$oldSpec.MatchPattern = $oldBackupName
$oldCheck = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $oldSpec)
if ($oldCheck -and $oldCheck.File) {
    throw "$oldBackupName already exists. Stop and investigate before proceeding. Do not overwrite the existing rollback copy - roll back first, or remove the file only if you intentionally no longer need it."
}

$oldPath = "[$dsName] $vmDir/$($nvramFile.Path)"
$newPath = "[$dsName] $vmDir/$oldBackupName"

$dcRef = (Get-Datacenter -VM $vm | Get-View).MoRef
$fm    = Get-View (Get-View ServiceInstance).Content.FileManager
# Final argument $false = do NOT force-overwrite the destination.
$task  = $fm.MoveDatastoreFile_Task($oldPath, $dcRef, $newPath, $dcRef, $false)

# Wait for task to complete
do { Start-Sleep -Seconds 2; $t = Get-View $task } while ($t.Info.State -notin @("success","error"))

if ($t.Info.State -eq "success") { Write-Host "NVRAM renamed successfully." -ForegroundColor Green }
else { Write-Warning "NVRAM rename failed: $($t.Info.Error.LocalizedMessage)" }
```

**Stop here if NVRAM rename failed.** Do not power on until it succeeds.

### Step 4 - Power on and verify 2023 certs in new NVRAM

```powershell
Start-VM -VM $vm
```

Wait 2-3 minutes for the DC to fully boot and AD services to start, then verify:

```powershell
$verify = @'
$kek = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
$db  = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023'
"KEK 2023 present: $kek"
"DB  2023 present: $db"
'@
$out = Invoke-VMScript -VM $vm -ScriptText $verify -ScriptType Powershell -GuestCredential $cred
Write-Host $out.ScriptOutput
```

**Both must return True before continuing.** If either returns False:
- Stop - do not proceed with registry changes
- Check whether the NVRAM rename was successful on the datastore
- Verify the ESXi host version supports NVRAM regeneration (requires ESXi 8.0.2 or later)
- Revert to the snapshot and investigate before retrying

### Step 5 - Apply registry fix directly on DC1

RDP or console into **DC1**. Open PowerShell **as Administrator**
(right-click → Run as Administrator). Run the following:

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

# Before clearing stale state, record the current servicing diagnostics.
# Microsoft uses these values to determine where a Secure Boot update is stuck,
# so capture them in case you need to troubleshoot a failure later.
if (Test-Path $svcPath) {
    Write-Host "Pre-clear Secure Boot servicing diagnostics:"
    Write-Host "  UEFICA2023Status     : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
    Write-Host "  UEFICA2023Error      : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Error' -EA SilentlyContinue))"
    Write-Host "  UEFICA2023ErrorEvent : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023ErrorEvent' -EA SilentlyContinue))"
    Write-Host "  AvailableUpdates     : $((Get-ItemPropertyValue -Path $regPath -Name 'AvailableUpdates' -EA SilentlyContinue))"
    # Optional stronger preservation - export the whole Secure Boot key first:
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot" "$env:TEMP\SecureBoot-preclear.reg" /y

    # Clear any stale state from previous failed attempts
    Remove-Item -Path $svcPath -Recurse -Force
    Write-Host "Stale Servicing subkey cleared."
}

# Set AvailableUpdates
Set-ItemProperty -Path $regPath -Name "AvailableUpdates" -Value 0x5944 -Type DWord -Force
Write-Host "AvailableUpdates set: 0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates"))"

# Trigger update task immediately rather than waiting up to 12 hours
Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

# Report state after task runs
$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
# Expected value at this point: 0x4100 (certs applied, boot manager reboot pending)
# or 0x4000 (fully complete if boot manager was already updated)
```

### Step 6 - Reboot DC1

From the elevated PowerShell session on DC1:

```powershell
Restart-Computer -Force
```

Wait for it to fully come back up. Confirm the Netlogon service is running and
you can authenticate before continuing:

```powershell
# Run from admin workstation after DC1 reboots
Test-NetConnection -ComputerName DC1 -Port 389  # LDAP
```

### Step 7 - Run task again after reboot

Log back into DC1 via RDP or console, elevated PowerShell:

```powershell
Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates: 0x$("{0:X4}" -f $val)"
# Expected: 0x4000 (fully complete)
```

### Step 8 - Verify cert update success on DC1

Still in the elevated PowerShell session on DC1:

```powershell
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
Write-Host "Servicing Status : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
Write-Host "KEK 2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023')"
Write-Host "DB  2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023')"
$errVal = Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Error' -EA SilentlyContinue
Write-Host "Reg Error key    : $(if ($null -ne $errVal) { "EXISTS - value: $errVal" } else { 'Not present (no error)' })"
```

**Expected output:**
```
Servicing Status : Updated
KEK 2023 present : True
DB  2023 present : True
Reg Error key    : Not present (no error)
```

> **Important:** `UEFICA2023Error` does not appear in the Windows Event Log.
> If this key exists with a non-zero value, a deployment error has occurred
> even if `UEFICA2023Status` shows `Updated`. Note the error value and check
> Event Viewer (System log, TPM-WMI source) for the events below.

**Check Event Viewer for relevant TPM-WMI events (System log):**

| Event ID | Meaning |
|----------|---------|
| **1036** | Success - Windows UEFI CA 2023 added to Secure Boot DB |
| **1043** | Success - KEK 2K CA 2023 applied |
| **1044** | Success - Microsoft Option ROM UEFI CA 2023 added to DB |
| **1045** | Success - Microsoft UEFI CA 2023 added to DB |
| **1795** | ERROR - firmware returned error on variable write, contact OEM for firmware update |
| **1797** | ERROR - boot manager update failed, check firmware |
| **1799** | Success - boot manager signed by Windows UEFI CA 2023 applied |
| **1800** | Warning - reboot required before Secure Boot update can proceed |
| **1801** | ERROR - certificates updated but not yet applied to firmware, an additional reboot may be required |
| **1802** | ERROR - update blocked by known firmware issue, contact OEM for firmware update |
| **1803** | ERROR - no PK-signed KEK found, PK remediation (Step 9) required |
| **1808** | Success - all certificates and boot manager applied to firmware (definitive success) |

Event 1808 may not appear until an extra reboot after the update task completes. Absence of 1808 alone is not a failure indicator - use `UEFICA2023Status = Updated` as the primary completion signal.

If status shows `InProgress` rather than `Updated`, allow 30 minutes and check
again. The task runs every 12 hours - trigger it manually if needed.

### Step 9 - Check and remediate Platform Key (PK)

Check the current PK status from DC1 (elevated PowerShell):

```powershell
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 28) {
    Write-Host "PK Status: Invalid_NULL (no PK present)" -ForegroundColor Red
} else {
    $b = $pk.Bytes
    $sigType = [Guid]([byte[]]$b[0..15])
    if ($sigType -ne [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072") {
        Write-Host "PK Status: Valid_Other (populated but not an X.509 certificate - typically the ESXi placeholder)" -ForegroundColor Yellow
    } else {
        $hdr   = [BitConverter]::ToUInt32($b, 20)
        $size  = [BitConverter]::ToUInt32($b, 24)
        $start = 28 + [int]$hdr + 16
        $len   = [int]$size - 16
        try {
            $certBytes = New-Object byte[] $len
            [Array]::Copy($b, $start, $certBytes, 0, $len)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
            Write-Host ("PK Subject   : {0}" -f $cert.Subject)
            Write-Host ("PK Thumbprint: {0}" -f $cert.Thumbprint)
            if ($cert.Subject -match 'CN=Windows OEM Devices PK') {
                Write-Host "PK Status: Valid_WindowsOEM" -ForegroundColor Green
            } elseif ($cert.Subject -match 'O=Microsoft Corporation' -or $cert.Subject -match 'CN=Microsoft') {
                Write-Host "PK Status: Valid_Microsoft" -ForegroundColor Green
            } else {
                Write-Host "PK Status: Valid_Other (real certificate, not a recognized Microsoft PK)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "PK Status: Valid_Other (certificate could not be parsed)" -ForegroundColor Yellow
        }
    }
}
```

**If PK Status is `Valid_WindowsOEM` or `Valid_Microsoft`:** No action needed.
Skip to Step 10.

**If PK Status is `Valid_Other` or `Invalid_NULL`:** The ESXi-generated placeholder
PK must be replaced. `Valid_Other` is the expected result after NVRAM regeneration
on ESXi < 9.0 - it will not authenticate future Windows Update KEK changes.

> **Note:** Broadcom KB 423919 (updated March 2026) documents a manual procedure
> using `uefi.allowAuthBypass` and a FAT32 VMDK for all ESXi versions. That method
> enrolls the PK via the UEFI setup UI and does not require deleting the NVRAM
> file. The SetupMode procedure below is an alternative that is confirmed working
> on ESXi 8.x. Use whichever approach suits your environment.

Continue with the PK remediation sub-steps below.

#### Step 9a - BitLocker re-check before SetupMode reboot

The `RebootCount 2` suspension from Step 2 was consumed by the power-off/on at
Step 3 and the reboot at Step 6. If BitLocker was active, it has now auto-resumed.
Check and re-suspend before the SetupMode reboot:

```powershell
# Run on DC1 (elevated PowerShell)
$blVol = Get-BitLockerVolume -MountPoint "C:" -EA SilentlyContinue
if ($blVol -and $blVol.ProtectionStatus -eq "On") {
    Write-Host "BitLocker has auto-resumed. Save the recovery key and re-suspend." -ForegroundColor Yellow

    # Save recovery key
    (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
        Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
        Select-Object KeyProtectorId, RecoveryPassword |
        Format-List

    # Suspend for 2 reboots (SetupMode reboot + post-enrollment reboot)
    Suspend-BitLocker -MountPoint "C:" -RebootCount 2
    Write-Host "BitLocker re-suspended for 2 reboots." -ForegroundColor Green
} else {
    Write-Host "BitLocker not active - no action needed." -ForegroundColor Green
}
```

Store the recovery key output before proceeding.

#### Step 9b - Enable UEFI SetupMode via PowerCLI

Run from your admin workstation PowerCLI session. The VM must be powered off for
the VMX option to take effect on next boot:

```powershell
$vm = Get-VM -Name "DC1"
$vmConfig = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfig.ExtraConfig = @(
    New-Object VMware.Vim.OptionValue -Property @{
        Key   = "uefi.secureBootMode.overrideOnce"
        Value = "SetupMode"
    }
)
# Apply via ReconfigVM_Task and wait for completion (matches the script's behavior;
# surfaces errors instead of failing silently)
$view = $vm | Get-View
$taskMoRef = $view.ReconfigVM_Task($vmConfig)
$task = Get-View -Id $taskMoRef
do {
    Start-Sleep -Seconds 2
    $task = Get-View -Id $taskMoRef
} while ($task.Info.State -in @("queued","running"))

if ($task.Info.State -ne "success") {
    throw "VM reconfiguration failed: $($task.Info.Error.LocalizedMessage)"
}
Write-Host "SetupMode VMX option set." -ForegroundColor Green

# Verify
$optVal = ($vm | Get-View).Config.ExtraConfig |
    Where-Object { $_.Key -eq "uefi.secureBootMode.overrideOnce" } |
    Select-Object -ExpandProperty Value
Write-Host "uefi.secureBootMode.overrideOnce = $optVal"
```

Power off and back on to enter SetupMode:

```powershell
Stop-VM -VM $vm -Confirm:$false -Kill
Start-Sleep -Seconds 5
Start-VM -VM $vm
```

Wait for the DC to fully boot (2-3 minutes) and confirm Tools is running:

```powershell
do {
    Start-Sleep -Seconds 10
    $vm = Get-VM -Name "DC1"
    Write-Host "Tools: $($vm.Guest.ExtensionData.ToolsStatus)"
} while ($vm.Guest.ExtensionData.ToolsStatus -ne "toolsOk")
Write-Host "VM is back online." -ForegroundColor Green
```

#### Step 9c - Enroll the Platform Key

Copy `WindowsOEMDevicesPK.der` to the DC guest. From your admin workstation:

```powershell
Copy-VMGuestFile -Source "C:\Tools\WindowsOEMDevicesPK.der" `
    -Destination "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
    -VM $vm -LocalToGuest -GuestCredential $cred
```

Then RDP or console into **DC1** and run from an elevated PowerShell session:

```powershell
# Confirm the VM is in SetupMode (should return 1)
$sm = (Get-SecureBootUEFI SetupMode -EA SilentlyContinue).Bytes
Write-Host "SetupMode active: $($sm -and $sm[0] -eq 1)"

# Enroll the PK
Format-SecureBootUEFI -Name PK `
    -CertificateFilePath "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
    -SignatureOwner "55555555-0000-0000-0000-000000000000" `
    -FormatWithCert `
    -Time "2025-10-23T11:00:00Z" |
Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z"

Write-Host "PK enrollment submitted. Reboot required to verify." -ForegroundColor Green
```

#### Step 9d - Clear SetupMode and reboot

From your admin workstation PowerCLI session, clear the VMX option:

```powershell
$vm = Get-VM -Name "DC1"
$vmConfig = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfig.ExtraConfig = @(
    New-Object VMware.Vim.OptionValue -Property @{
        Key   = "uefi.secureBootMode.overrideOnce"
        Value = ""
    }
)
# Apply via ReconfigVM_Task and wait for completion (matches the script's behavior;
# surfaces errors instead of failing silently)
$view = $vm | Get-View
$taskMoRef = $view.ReconfigVM_Task($vmConfig)
$task = Get-View -Id $taskMoRef
do {
    Start-Sleep -Seconds 2
    $task = Get-View -Id $taskMoRef
} while ($task.Info.State -in @("queued","running"))

if ($task.Info.State -ne "success") {
    throw "VM reconfiguration failed: $($task.Info.Error.LocalizedMessage)"
}
Write-Host "SetupMode VMX option cleared." -ForegroundColor Green
```

Reboot DC1 (from the elevated PS session on DC1):

```powershell
Restart-Computer -Force
```

#### Step 9e - Verify PK after reboot

After DC1 is fully back online, confirm PK from an elevated PowerShell session:

```powershell
# Set $derPath to the WindowsOEMDevicesPK.der you enrolled, then verify by thumbprint.
$derPath = "C:\Path\To\WindowsOEMDevicesPK.der"
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 28) {
    Write-Host "PK Status: Invalid_NULL - enrollment did not take" -ForegroundColor Red
} else {
    $b = $pk.Bytes
    $sigType = [Guid]([byte[]]$b[0..15])
    if ($sigType -ne [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072") {
        Write-Host "PK Status: Valid_Other (not an X.509 certificate) - enrollment did not take" -ForegroundColor Red
    } else {
        $hdr   = [BitConverter]::ToUInt32($b, 20)
        $size  = [BitConverter]::ToUInt32($b, 24)
        $start = 28 + [int]$hdr + 16
        $len   = [int]$size - 16
        $certBytes = New-Object byte[] $len
        [Array]::Copy($b, $start, $certBytes, 0, $len)
        $live = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
        $der  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($derPath)
        Write-Host ("Live PK Thumbprint: {0}" -f $live.Thumbprint)
        Write-Host ("DER  Thumbprint   : {0}" -f $der.Thumbprint)
        if ($live.Thumbprint -eq $der.Thumbprint) {
            Write-Host "PK VERIFIED: live Platform Key matches the enrolled certificate." -ForegroundColor Green
        } else {
            Write-Host "PK MISMATCH: live Platform Key does NOT match the DER you enrolled." -ForegroundColor Red
        }
    }
}
```

Expected: `PK VERIFIED: live Platform Key matches the enrolled certificate.`

### Step 10 - Verify DC health after all reboots

From admin workstation:

```powershell
repadmin /replsummary
dcdiag /test:replications
```

Confirm replication is healthy before proceeding to DC2.

### Step 11 - Retain snapshot for validation period

Leave the snapshot in place for several days while monitoring DC1. When
satisfied there are no issues, remove it from your admin workstation:

```powershell
$snap = Get-Snapshot -VM (Get-VM "DC1") -Name "Pre-SecureBoot-Fix"
Remove-Snapshot -Snapshot $snap -Confirm:$false
```

---

## Phase 2 - DC2 (PDC Emulator Holder)

**Do not start Phase 2 until DC1 is confirmed healthy and replication is clean.**

### Step 1 - Transfer PDC Emulator role to DC1

This prevents client authentication disruption during the DC2 reboot:

```powershell
# Transfer PDC Emulator to DC1
Move-ADDirectoryServerOperationMasterRole -Identity "DC1" `
    -OperationMasterRole PDCEmulator -Confirm:$false

# Verify transfer completed
$pdcHolder = (Get-ADDomain).PDCEmulator
Write-Host "PDC Emulator now held by: $pdcHolder"
# Expected: DC1.yourdomain.com
```

### Step 2 - Take snapshot

```powershell
$vm = Get-VM -Name "DC2"
New-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix" `
    -Description "Pre Secure Boot 2023 cert fix - manual" `
    -Memory:$false -Quiesce:$false -Confirm:$false
```

### Step 3 - BitLocker pre-check (if applicable)

If BitLocker is enabled on DC2, perform these steps **before** powering off.
Skip this step entirely if BitLocker is not in use on this DC.

**Check BitLocker status** (run from an elevated PowerShell session on DC2):

```powershell
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, KeyProtector
```

If `ProtectionStatus` is `On`:

**A. Save the recovery key:**

```powershell
(Get-BitLockerVolume -MountPoint "C:").KeyProtector |
    Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
    Select-Object KeyProtectorId, RecoveryPassword |
    Format-List
```

Store the `RecoveryPassword` in your password manager or secure file share.

**B. Suspend BitLocker:**

```powershell
# RebootCount 2 covers the power-off/on cycle and the post-cert-update reboot.
# If PK remediation is also needed, a second suspension will be required at Step 9a.
Suspend-BitLocker -MountPoint "C:" -RebootCount 2
```

Verify:

```powershell
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus
# ProtectionStatus should show: Off (suspended)
```

### Step 4 - Rename NVRAM file

```powershell
$vm = Get-VM -Name "DC2"

# Power off
Stop-VM -VM $vm -Confirm:$false
Start-Sleep -Seconds 10

# Locate and rename NVRAM (same process as DC1)
$vmView  = $vm | Get-View
$vmxPath = $vmView.Config.Files.VmPathName
$dsName  = $vmxPath -replace '^\[(.+?)\].*', '$1'
$vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'

# Resolve the datastore by MoRef from the VM's own attached-datastore list.
# Get-Datastore -Name returns every datastore with that name across the
# inventory, which picks the wrong one when duplicate datastore names exist
# across datacenters or clusters. Match by MoRef instead, the same way the
# script does, and fail loudly if the VMX datastore cannot be resolved.
$ds = $null
foreach ($dsRef in $vmView.Datastore) {
    $candidate = Get-Datastore -Id $dsRef -ErrorAction SilentlyContinue
    if ($candidate -and $candidate.Name -eq $dsName) {
        $ds = $candidate
        break
    }
}
if (-not $ds) {
    throw "Could not resolve VMX datastore '$dsName' from this VM's attached datastore list."
}
$dsBrowser = Get-View $ds.ExtensionData.Browser
$spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$spec.MatchPattern = "*.nvram"
$results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)
$nvramFile = $results.File | Where-Object { $_.Path -notmatch "_old" } | Select-Object -First 1

# Safety: confirm an active .nvram file was actually found before proceeding.
if (-not $nvramFile) {
    throw "No active .nvram file found. The VM may already have been renamed or partially rolled back. Stop and investigate."
}

$oldBackupName = $nvramFile.Path -replace '\.nvram$', '.nvram_old'

# Safety: do NOT overwrite an existing .nvram_old. If one is present, a prior
# partial attempt likely left it, and it is the only rollback copy. Stop rather
# than destroy it. (This mirrors the protection the bulk script performs.)
$oldSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$oldSpec.MatchPattern = $oldBackupName
$oldCheck = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $oldSpec)
if ($oldCheck -and $oldCheck.File) {
    throw "$oldBackupName already exists. Stop and investigate before proceeding. Do not overwrite the existing rollback copy - roll back first, or remove the file only if you intentionally no longer need it."
}

$oldPath = "[$dsName] $vmDir/$($nvramFile.Path)"
$newPath = "[$dsName] $vmDir/$oldBackupName"

$dcRef = (Get-Datacenter -VM $vm | Get-View).MoRef
$fm    = Get-View (Get-View ServiceInstance).Content.FileManager
# Final argument $false = do NOT force-overwrite the destination.
$task  = $fm.MoveDatastoreFile_Task($oldPath, $dcRef, $newPath, $dcRef, $false)

do { Start-Sleep -Seconds 2; $t = Get-View $task } while ($t.Info.State -notin @("success","error"))

if ($t.Info.State -eq "success") { Write-Host "NVRAM renamed successfully." -ForegroundColor Green }
else { Write-Warning "NVRAM rename failed: $($t.Info.Error.LocalizedMessage)" }
```

### Step 5 - Power on and verify 2023 certs in new NVRAM

```powershell
Start-VM -VM $vm
```

Wait 2-3 minutes, then verify:

```powershell
$verify = @'
$kek = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
$db  = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023'
"KEK 2023 present: $kek"
"DB  2023 present: $db"
'@
$out = Invoke-VMScript -VM $vm -ScriptText $verify -ScriptType Powershell -GuestCredential $cred
Write-Host $out.ScriptOutput
```

Both must return True before continuing.

### Step 6 - Apply registry fix on DC2

RDP or console into **DC2**, elevated PowerShell:

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

if (Test-Path $svcPath) {
    Write-Host "Pre-clear Secure Boot servicing diagnostics:"
    Write-Host "  UEFICA2023Status     : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
    Write-Host "  UEFICA2023Error      : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Error' -EA SilentlyContinue))"
    Write-Host "  UEFICA2023ErrorEvent : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023ErrorEvent' -EA SilentlyContinue))"
    Write-Host "  AvailableUpdates     : $((Get-ItemPropertyValue -Path $regPath -Name 'AvailableUpdates' -EA SilentlyContinue))"
    # Optional stronger preservation - export the whole Secure Boot key first:
    reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot" "$env:TEMP\SecureBoot-preclear.reg" /y

    Remove-Item -Path $svcPath -Recurse -Force
    Write-Host "Stale Servicing subkey cleared."
}

Set-ItemProperty -Path $regPath -Name "AvailableUpdates" -Value 0x5944 -Type DWord -Force
Write-Host "AvailableUpdates set: 0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates"))"

Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
```

### Step 7 - Reboot DC2

```powershell
Restart-Computer -Force
```

### Step 8 - Run task again after reboot

Log back into DC2, elevated PowerShell:

```powershell
Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates: 0x$("{0:X4}" -f $val)"
```

### Step 9 - Verify cert update success on DC2

```powershell
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
Write-Host "Servicing Status : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
Write-Host "KEK 2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023')"
Write-Host "DB  2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023')"
$errVal = Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Error' -EA SilentlyContinue
Write-Host "Reg Error key    : $(if ($null -ne $errVal) { "EXISTS - value: $errVal" } else { 'Not present (no error)' })"
```

Expected:
```
Servicing Status : Updated
KEK 2023 present : True
DB  2023 present : True
Reg Error key    : Not present (no error)
```

> **Important:** `UEFICA2023Error` does not appear in the Windows Event Log.
> If this key exists with a non-zero value, a deployment error has occurred
> even if `UEFICA2023Status` shows `Updated`. See the note at Phase 1 Step 8
> for guidance.

### Step 10 - Check and remediate Platform Key (PK) on DC2

Check PK status from DC2 (elevated PowerShell):

```powershell
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 28) {
    Write-Host "PK Status: Invalid_NULL (no PK present)" -ForegroundColor Red
} else {
    $b = $pk.Bytes
    $sigType = [Guid]([byte[]]$b[0..15])
    if ($sigType -ne [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072") {
        Write-Host "PK Status: Valid_Other (populated but not an X.509 certificate - typically the ESXi placeholder)" -ForegroundColor Yellow
    } else {
        $hdr   = [BitConverter]::ToUInt32($b, 20)
        $size  = [BitConverter]::ToUInt32($b, 24)
        $start = 28 + [int]$hdr + 16
        $len   = [int]$size - 16
        try {
            $certBytes = New-Object byte[] $len
            [Array]::Copy($b, $start, $certBytes, 0, $len)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
            Write-Host ("PK Subject   : {0}" -f $cert.Subject)
            Write-Host ("PK Thumbprint: {0}" -f $cert.Thumbprint)
            if ($cert.Subject -match 'CN=Windows OEM Devices PK') {
                Write-Host "PK Status: Valid_WindowsOEM" -ForegroundColor Green
            } elseif ($cert.Subject -match 'O=Microsoft Corporation' -or $cert.Subject -match 'CN=Microsoft') {
                Write-Host "PK Status: Valid_Microsoft" -ForegroundColor Green
            } else {
                Write-Host "PK Status: Valid_Other (real certificate, not a recognized Microsoft PK)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "PK Status: Valid_Other (certificate could not be parsed)" -ForegroundColor Yellow
        }
    }
}
```

**If PK Status is `Valid_WindowsOEM` or `Valid_Microsoft`:** Skip to Step 11.

**If PK Status is `Valid_Other` or `Invalid_NULL`:** Follow sub-steps 10a-10e,
which are identical to Phase 1 Step 9 sub-steps but for DC2. See the note at
Phase 1 Step 9 regarding the Broadcom KB 423919 disk method as an alternative.

#### Step 10a - BitLocker re-check before SetupMode reboot

```powershell
# Run on DC2 (elevated PowerShell)
$blVol = Get-BitLockerVolume -MountPoint "C:" -EA SilentlyContinue
if ($blVol -and $blVol.ProtectionStatus -eq "On") {
    Write-Host "BitLocker has auto-resumed. Save the recovery key and re-suspend." -ForegroundColor Yellow

    (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
        Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } |
        Select-Object KeyProtectorId, RecoveryPassword |
        Format-List

    Suspend-BitLocker -MountPoint "C:" -RebootCount 2
    Write-Host "BitLocker re-suspended for 2 reboots." -ForegroundColor Green
} else {
    Write-Host "BitLocker not active - no action needed." -ForegroundColor Green
}
```

#### Step 10b - Enable UEFI SetupMode via PowerCLI

```powershell
$vm = Get-VM -Name "DC2"
$vmConfig = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfig.ExtraConfig = @(
    New-Object VMware.Vim.OptionValue -Property @{
        Key   = "uefi.secureBootMode.overrideOnce"
        Value = "SetupMode"
    }
)
# Apply via ReconfigVM_Task and wait for completion (matches the script's behavior;
# surfaces errors instead of failing silently)
$view = $vm | Get-View
$taskMoRef = $view.ReconfigVM_Task($vmConfig)
$task = Get-View -Id $taskMoRef
do {
    Start-Sleep -Seconds 2
    $task = Get-View -Id $taskMoRef
} while ($task.Info.State -in @("queued","running"))

if ($task.Info.State -ne "success") {
    throw "VM reconfiguration failed: $($task.Info.Error.LocalizedMessage)"
}
Write-Host "SetupMode VMX option set." -ForegroundColor Green

Stop-VM -VM $vm -Confirm:$false -Kill
Start-Sleep -Seconds 5
Start-VM -VM $vm
```

Wait for DC2 to fully boot before continuing.

#### Step 10c - Enroll the Platform Key

Copy `WindowsOEMDevicesPK.der` to the DC2 guest:

```powershell
Copy-VMGuestFile -Source "C:\Tools\WindowsOEMDevicesPK.der" `
    -Destination "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
    -VM $vm -LocalToGuest -GuestCredential $cred
```

Then RDP or console into **DC2**, elevated PowerShell:

```powershell
$sm = (Get-SecureBootUEFI SetupMode -EA SilentlyContinue).Bytes
Write-Host "SetupMode active: $($sm -and $sm[0] -eq 1)"

Format-SecureBootUEFI -Name PK `
    -CertificateFilePath "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
    -SignatureOwner "55555555-0000-0000-0000-000000000000" `
    -FormatWithCert `
    -Time "2025-10-23T11:00:00Z" |
Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z"

Write-Host "PK enrollment submitted. Reboot required to verify." -ForegroundColor Green
```

#### Step 10d - Clear SetupMode and reboot

```powershell
# From admin workstation PowerCLI session
$vm = Get-VM -Name "DC2"
$vmConfig = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfig.ExtraConfig = @(
    New-Object VMware.Vim.OptionValue -Property @{
        Key   = "uefi.secureBootMode.overrideOnce"
        Value = ""
    }
)
# Apply via ReconfigVM_Task and wait for completion (matches the script's behavior;
# surfaces errors instead of failing silently)
$view = $vm | Get-View
$taskMoRef = $view.ReconfigVM_Task($vmConfig)
$task = Get-View -Id $taskMoRef
do {
    Start-Sleep -Seconds 2
    $task = Get-View -Id $taskMoRef
} while ($task.Info.State -in @("queued","running"))

if ($task.Info.State -ne "success") {
    throw "VM reconfiguration failed: $($task.Info.Error.LocalizedMessage)"
}
Write-Host "SetupMode VMX option cleared." -ForegroundColor Green
```

Reboot DC2:

```powershell
Restart-Computer -Force
```

#### Step 10e - Verify PK after reboot

```powershell
# Set $derPath to the WindowsOEMDevicesPK.der you enrolled, then verify by thumbprint.
$derPath = "C:\Path\To\WindowsOEMDevicesPK.der"
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 28) {
    Write-Host "PK Status: Invalid_NULL - enrollment did not take" -ForegroundColor Red
} else {
    $b = $pk.Bytes
    $sigType = [Guid]([byte[]]$b[0..15])
    if ($sigType -ne [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072") {
        Write-Host "PK Status: Valid_Other (not an X.509 certificate) - enrollment did not take" -ForegroundColor Red
    } else {
        $hdr   = [BitConverter]::ToUInt32($b, 20)
        $size  = [BitConverter]::ToUInt32($b, 24)
        $start = 28 + [int]$hdr + 16
        $len   = [int]$size - 16
        $certBytes = New-Object byte[] $len
        [Array]::Copy($b, $start, $certBytes, 0, $len)
        $live = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytes)
        $der  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($derPath)
        Write-Host ("Live PK Thumbprint: {0}" -f $live.Thumbprint)
        Write-Host ("DER  Thumbprint   : {0}" -f $der.Thumbprint)
        if ($live.Thumbprint -eq $der.Thumbprint) {
            Write-Host "PK VERIFIED: live Platform Key matches the enrolled certificate." -ForegroundColor Green
        } else {
            Write-Host "PK MISMATCH: live Platform Key does NOT match the DER you enrolled." -ForegroundColor Red
        }
    }
}
```

Expected: `PK VERIFIED: live Platform Key matches the enrolled certificate.`

### Step 11 - Transfer PDC Emulator back to DC2

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity "DC2" `
    -OperationMasterRole PDCEmulator -Confirm:$false

# Verify
$pdcHolder = (Get-ADDomain).PDCEmulator
Write-Host "PDC Emulator returned to: $pdcHolder"
# Expected: DC2.yourdomain.com
```

### Step 12 - Final replication health check

```powershell
repadmin /replsummary
dcdiag /test:replications
```

### Step 13 - Retain snapshot for validation period

Leave the snapshot in place for several days, then remove when satisfied:

```powershell
$snap = Get-Snapshot -VM (Get-VM "DC2") -Name "Pre-SecureBoot-Fix"
Remove-Snapshot -Snapshot $snap -Confirm:$false
```

---

## Rollback Procedure

> **Important: reverting a domain controller snapshot is an Active Directory
> recovery event, not a routine VM rollback.** When a virtualized DC is reverted
> to a snapshot, the hypervisor's VM-Generation ID change signals AD DS to invoke
> safeguards (resetting the InvocationID and discarding the RID pool) to prevent
> USN rollback and duplicate-SID problems. This is handled automatically on
> modern Windows Server with a hypervisor that exposes VM-Generation ID (vSphere
> does), but it has real consequences: the DC will re-replicate inbound, and any
> changes that originated on that DC but had not yet replicated outbound are lost.
> Before reverting a DC snapshot, confirm the host exposes VM-Generation ID,
> ensure you have a recent system-state or AD-aware backup, verify replication
> health before and after, and confirm FSMO role placement. Do not revert a DC
> snapshot as casual cleanup. If multiple DCs are affected, never restore more
> than one from snapshot and let them replicate against each other without
> verifying replication health between steps. The full VM-Generation ID and
> AD-recovery procedure is beyond the scope of this guide. Consult Microsoft's
> "Safely virtualizing Active Directory Domain Services" guidance before
> proceeding.

If anything goes wrong on either DC at any point, revert to snapshot.
This returns the VM to its exact pre-change state including the original NVRAM.

```powershell
# Rollback DC1
$vm   = Get-VM -Name "DC1"
$snap = Get-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix"
Set-VM -VM $vm -Snapshot $snap -Confirm:$false
Start-VM -VM $vm

# Rollback DC2 - also transfer PDC Emulator back if it was moved
Move-ADDirectoryServerOperationMasterRole -Identity "DC2" `
    -OperationMasterRole PDCEmulator -Confirm:$false
$vm   = Get-VM -Name "DC2"
$snap = Get-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix"
Set-VM -VM $vm -Snapshot $snap -Confirm:$false
Start-VM -VM $vm
```

---

## Quick Reference Checklist

### DC1 (Secondary DC)
- [ ] Replication health verified clean
- [ ] FSMO roles confirmed (none on DC1)
- [ ] `WindowsOEMDevicesPK.der` downloaded and available
- [ ] Snapshot taken: Pre-SecureBoot-Fix
- [ ] BitLocker recovery key saved (if BitLocker active)
- [ ] BitLocker suspended with RebootCount 2 (if BitLocker active)
- [ ] NVRAM renamed on datastore
- [ ] Powered on - KEK 2023: True, DB 2023: True
- [ ] Registry fix applied (elevated PS directly on DC)
- [ ] First reboot completed
- [ ] Task triggered post-reboot
- [ ] Servicing Status: Updated, KEK: True, DB: True
- [ ] PK Status checked
- [ ] If PK remediation needed: BitLocker re-suspended, SetupMode set, PK enrolled, SetupMode cleared, rebooted
- [ ] PK Status: Valid_WindowsOEM (if remediation performed)
- [ ] BitLocker protection resumed (verify after all reboots complete)
- [ ] Replication health re-verified
- [ ] Snapshot removed after validation period

### DC2 (PDC Emulator Holder)
- [ ] DC1 confirmed healthy first
- [ ] Replication clean
- [ ] PDC Emulator transferred to DC1
- [ ] Snapshot taken: Pre-SecureBoot-Fix
- [ ] BitLocker recovery key saved (if BitLocker active)
- [ ] BitLocker suspended with RebootCount 2 (if BitLocker active)
- [ ] NVRAM renamed on datastore
- [ ] Powered on - KEK 2023: True, DB 2023: True
- [ ] Registry fix applied (elevated PS directly on DC)
- [ ] First reboot completed
- [ ] Task triggered post-reboot
- [ ] Servicing Status: Updated, KEK: True, DB: True
- [ ] PK Status checked
- [ ] If PK remediation needed: BitLocker re-suspended, SetupMode set, PK enrolled, SetupMode cleared, rebooted
- [ ] PK Status: Valid_WindowsOEM (if remediation performed)
- [ ] BitLocker protection resumed (verify after all reboots complete)
- [ ] PDC Emulator transferred back to DC2
- [ ] Replication health re-verified
- [ ] Snapshot removed after validation period
