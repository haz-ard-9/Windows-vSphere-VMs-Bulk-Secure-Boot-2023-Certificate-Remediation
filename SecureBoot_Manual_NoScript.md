# Secure Boot 2023 Certificate Remediation - Manual Procedure (No Scripts)

## Background

Microsoft's Secure Boot certificate chain that protects the Windows pre-OS boot
process uses signing certificates that begin expiring in **June 2026**. Devices
that are not updated to trust the new 2023 certificates before that date will
lose the ability to receive future Secure Boot and boot manager security updates.

For VMware virtual machines, Windows cannot apply this update on its own because
the certificates live in the VM's NVRAM - a firmware-level file managed by ESXi,
not by Windows. The process therefore has two distinct phases:

1. **ESXi phase:** Rename the VM's NVRAM file so ESXi regenerates it fresh with
   the 2023 certificates on next boot. The original file is preserved as
   `.nvram_old` so rollback is possible if needed. Then enroll a proper
   Platform Key (PK) via UEFI SetupMode.
2. **Windows phase:** Set a registry value that tells the Windows Secure Boot
   Update task to write the new 2023 certificates into the UEFI firmware
   variables. Windows handles the KEK, DB, and boot manager updates
   automatically - no manual KEK enrollment is required.

---

> ## Important notice regarding support status
>
> This guide includes a step that renames the VM's `.nvram` file to force ESXi to regenerate it fresh with the 2023 KEK certificate on next boot. Broadcom previously documented this approach in [KB 421593](https://web.archive.org/web/20260212085158/https://knowledge.broadcom.com/external/article/421593/missing-microsoft-corporation-kek-ca-202.html) *(archived - Broadcom has removed this KB)*. It is not clear whether Broadcom removed it because the method is no longer recommended, because it was superseded by another approach, or for an unrelated reason.
>
> This method has been tested and works reliably on ESXi 8.0.2 and later with hardware version 21 VMs. No issues have been encountered in practice. However, because the original documentation no longer exists, this approach may be considered unsupported by Broadcom. Use this guide with your own judgment and at your own risk.
>
> The NVRAM file is **renamed** rather than deleted so that rollback is possible - the original file is preserved as `.nvram_old`. A snapshot is also taken at Step 1 before any changes are made. If you encounter any issues, the Rollback Procedure at the end of this guide will restore the original NVRAM and revert the VM to its pre-change state.
>
> **You may be able to skip the NVRAM rename entirely.** If the KEK 2023 certificate is already present in the VM's NVRAM (which is the case for VMs created on ESXi 8.0.2 or later, or VMs that have already had a partial remediation), Steps 4 and 5 are not needed. Run the KEK pre-check below before proceeding.

### Reference Documentation

| Source | Document |
|--------|----------|
| Broadcom | [KB 423919 - Manual Update of the Secure Boot Platform Key in Virtual Machines](https://knowledge.broadcom.com/external/article/423919) |
| Broadcom | [KB 423893 - Secure Boot 2023 Certificate Remediation for ESXi](https://knowledge.broadcom.com/external/article/423893) |
| Microsoft | [Secure Boot Certificate Updates - Guidance for IT Professionals](https://support.microsoft.com/en-us/topic/secure-boot-certificate-updates-guidance-for-it-professionals-and-organizations-e2b43f9f-b424-42df-bc6a-8476db65ab2f) |
| Microsoft | [Registry Key Updates for Secure Boot - IT-Managed Updates](https://support.microsoft.com/en-us/topic/registry-key-updates-for-secure-boot-windows-devices-with-it-managed-updates-a7be69c9-4634-42e1-9ca1-df06f43f360d) |
| Microsoft | [Secure Boot Playbook for Certificates Expiring in 2026](https://techcommunity.microsoft.com/blog/windows-itpro-blog/secure-boot-playbook-for-certificates-expiring-in-2026/4469235) |
| Microsoft | [Windows Server Secure Boot Playbook](https://techcommunity.microsoft.com/blog/windowsservernewsandbestpractices/windows-server-secure-boot-playbook-for-certificates-expiring-in-2026/4495789) |
| Microsoft | [Secure Boot DB and DBX Variable Update Events](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events) |
| Microsoft | [KB5085046 - Secure Boot Troubleshooting Guide](https://support.microsoft.com/en-us/kb/5085046) |

### Success and Failure Indicators

After completing this process, use the following to confirm success or
investigate failures:

| Indicator | Location | Meaning |
|-----------|----------|---------|
| `UEFICA2023Status = Updated` | `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing` | All certificates applied successfully |
| `UEFICA2023Status = InProgress` | Same path | Process is running - wait and check again |
| `UEFICA2023Error` key exists | Same path | An error occurred - value contains error code |
| `UEFICA2023ErrorEvent` key exists | Same path | Event ID associated with the error condition |
| Event ID **1036** (TPM-WMI) | Windows Event Viewer -> System log | Success - Windows UEFI CA 2023 added to Secure Boot DB |
| Event ID **1043** (TPM-WMI) | Windows Event Viewer -> System log | Success - KEK 2K CA 2023 applied |
| Event ID **1044** (TPM-WMI) | Windows Event Viewer -> System log | Success - Microsoft Option ROM UEFI CA 2023 added to DB |
| Event ID **1045** (TPM-WMI) | Windows Event Viewer -> System log | Success - Microsoft UEFI CA 2023 added to DB |
| Event ID **1795** (TPM-WMI) | Windows Event Viewer -> System log | ERROR - firmware returned error on Secure Boot variable write; contact OEM |
| Event ID **1797** (TPM-WMI) | Windows Event Viewer -> System log | ERROR - boot manager update failed; check firmware |
| Event ID **1799** (TPM-WMI) | Windows Event Viewer -> System log | Success - boot manager signed by Windows UEFI CA 2023 applied |
| Event ID **1800** (TPM-WMI) | Windows Event Viewer -> System log | Warning - reboot required before Secure Boot update can proceed |
| Event ID **1801** (TPM-WMI) | Windows Event Viewer -> System log | ERROR - certificates updated but not yet applied to firmware; device still needs attention |
| Event ID **1802** (TPM-WMI) | Windows Event Viewer -> System log | ERROR - update blocked by known firmware issue; contact OEM for firmware update |
| Event ID **1803** (TPM-WMI) | Windows Event Viewer -> System log | ERROR - no PK-signed KEK found; PK remediation (Step 12) is required |
| Event ID **1808** (TPM-WMI) | Windows Event Viewer -> System log | Success - all certificates and boot manager applied to firmware (definitive success) |

**How to find these events in Event Viewer:**
1. Press **Win + R**, type `eventvwr.msc`, click **OK**
2. Expand **Windows Logs** → **System**
3. Click **Filter Current Log** in the right panel
4. In the **Event sources** box, type `TPM-WMI`
5. Click **OK** - the list will filter to show only Secure Boot-related events

---

This guide covers the complete remediation process using only the vSphere Client
GUI and individual commands typed directly into PowerShell or Registry Editor
on the guest. No `.ps1` script files are required.

> **Note on PowerShell commands in this guide:** All PowerShell entries are
> single commands to be typed or pasted individually into an elevated PowerShell
> console window. They are not script files and do not require changing execution
> policy.

---

## Prerequisites

- ESXi host must be **8.0.2 or later** - earlier versions will not regenerate
  NVRAM with 2023 certificates
- VM hardware version must be **13 or later**
- **VMware Tools must be installed and running** on the VM - required for vSphere Client to show power state and for guest operations to complete correctly. Tools should be current with your ESXi host version; outdated Tools can cause guest script execution to fail. Check status in vSphere Client under the VM Summary tab, or with PowerCLI:
  ```powershell
  (Get-VM "vmname").Guest.ExtensionData.ToolsStatus  # Expected: toolsOk
  (Get-VM "vmname").Guest.ToolsVersion               # Compare against ESXi bundled version
  ```
- vSphere Client access with permissions to manage VMs and browse datastores
- RDP or console access to the guest VM
- `WindowsOEMDevicesPK.der` downloaded from Microsoft (required for PK
  remediation - see below)

### Download WindowsOEMDevicesPK.der

1. Navigate to:
   `https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der`
2. Click the **Download raw file** button (down-arrow icon near the top right
   of the file view)
3. Save the file to your admin workstation (e.g., `C:\Tools\WindowsOEMDevicesPK.der`)


---

## KEK Pre-Check (Do This Before Step 4)

Check whether the 2023 KEK certificate is already present in the VM's NVRAM. If it is, skip Steps 4 and 5 entirely and proceed directly to Step 6.

From an elevated PowerShell session on the VM (via RDP or console):

```powershell
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
```

- `True` - KEK 2023 is already present. **Skip Steps 4 and 5.** Go directly to Step 6 to trigger the cert update task.
- `False` - KEK 2023 is missing. Complete Steps 4 and 5 to rename the NVRAM and allow ESXi to regenerate it.

---

## Step 1 - Take a Snapshot

1. Open **vSphere Client** and log in to vCenter
2. In the left inventory panel, locate and select the target VM
3. Right-click the VM → **Snapshots** → **Take Snapshot**
4. Set the following:
   - **Name:** `Pre-SecureBoot-Fix`
   - **Description:** `Pre Secure Boot 2023 cert fix - manual`
   - Uncheck **Snapshot the virtual machine's memory**
   - Uncheck **Quiesce guest file system**
5. Click **OK**
6. Wait for the task to complete in the **Recent Tasks** panel at the bottom
7. Verify the snapshot appears: right-click the VM → **Snapshots** →
   **Manage Snapshots**

> **Do not proceed if the snapshot fails.** Ensure sufficient free space on the
> datastore before retrying.

---

## Step 2 - BitLocker Pre-Check (Skip if BitLocker Not in Use)

Perform this step while the VM is still powered on, before any power-off.

### 2a - Check BitLocker Status

RDP or console into the VM. Open **Control Panel** → **System and Security** →
**BitLocker Drive Encryption**.

If the C: drive shows **BitLocker on**, proceed with steps 2b and 2c.
If it shows **BitLocker off**, skip the rest of this step entirely.

Alternatively, open an elevated PowerShell console and type:

```
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus
```

If `ProtectionStatus` shows `On`, proceed with 2b and 2c.

### 2b - Save the Recovery Key

**Via Control Panel:**

1. In **BitLocker Drive Encryption**, click **Back up your recovery key** next
   to the C: drive
2. Choose **Save to a file**
3. Save the `.txt` file to a secure location accessible to your team (a
   restricted file share, password manager, or printout stored securely)

**Via elevated PowerShell (type individually):**

```
(Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object KeyProtectorId, RecoveryPassword | Format-List
```

Copy the `RecoveryPassword` value and store it securely before continuing.

### 2c - Suspend BitLocker Protection

**Via Control Panel:**

1. In **BitLocker Drive Encryption**, click **Suspend protection** next to the
   C: drive
2. Click **Yes** to confirm
3. The drive will show **BitLocker suspended**

> The Control Panel suspend does not accept a RebootCount parameter - it
> suspends for one reboot only. You will need to re-suspend before the
> post-fix reboot (Step 8) and again before the PK reboot (Step 12a) if
> BitLocker is in use.

**Via elevated PowerShell (recommended - allows specifying reboot count):**

```
Suspend-BitLocker -MountPoint "C:" -RebootCount 2
```

Verify:

```
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus
```

`ProtectionStatus` should show `Off (suspended)`.

---

## Step 3 - Power Off the VM

1. In vSphere Client, right-click the VM
2. Select **Power** → **Shut Down Guest OS**
3. If the guest does not respond within 2 minutes, use **Power** → **Power Off**
   (hard power off)
4. Wait for the VM status to show **Powered Off** in the inventory panel

---

## Step 4 - Rename the NVRAM File

This is the core step that causes ESXi to regenerate a fresh NVRAM with 2023
certificates on the next boot. The VM must be **powered off** before doing this.

### Navigate to the Datastore Browser

1. In vSphere Client, click **Storage** in the left navigation menu
2. Select the datastore where the VM resides
3. Click the **Files** tab at the top of the right panel
4. Navigate into the VM's folder (typically named the same as the VM)

### Rename the NVRAM File

5. Locate the file ending in `.nvram` (e.g., `vmname.nvram`)
   - There should be only one `.nvram` file - do not touch any other files
6. Right-click the `.nvram` file → **Rename**
7. Change the name by appending `_old` to the extension:
   - Example: `vmname.nvram` → `vmname.nvram_old`
8. Press **Enter** / click **OK** to confirm

> If the vSphere Client version does not offer a **Rename** option in the right-
> click menu, use the alternative approach: right-click the file → **Move to**,
> type the new filename including `_old`, and confirm. If neither is available,
> contact your vCenter administrator - the rename must be performed before
> proceeding.

**Stop here if the rename failed.** Do not power the VM on until the `.nvram`
file has been successfully renamed to `.nvram_old`.

---

## Step 5 - Power On and Verify 2023 Certificates in New NVRAM

1. Right-click the VM → **Power** → **Power On**
2. Wait 2–3 minutes for the VM to fully boot and for VMware Tools to report
   **Running**. You can monitor this in the VM's **Summary** tab.

### Verify the 2023 Certificates Are Present

RDP or console into the VM. Open an elevated PowerShell console
(**right-click** → **Run as Administrator**) and type each of the following
commands individually:

**Check KEK for 2023 certificate:**

```
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
```

Expected result: `True`

**Check DB for 2023 certificate:**

```
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes) -match 'Windows UEFI CA 2023'
```

Expected result: `True`

**Check Platform Key (PK) status:**

```
$pk = Get-SecureBootUEFI -Name PK
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 44) { Write-Host "PK Status: Invalid_NULL" -ForegroundColor Red } else { $t = [System.Text.Encoding]::ASCII.GetString($pk.Bytes[44..($pk.Bytes.Length-1)]); if ($t -match 'Windows OEM Devices') { Write-Host "PK Status: Valid_WindowsOEM" -ForegroundColor Green } elseif ($t -match 'Microsoft') { Write-Host "PK Status: Valid_Microsoft" -ForegroundColor Green } else { Write-Host "PK Status: Valid_Other (ESXi placeholder - PK remediation will be needed at Step 12)" -ForegroundColor Yellow } }
```

Note the PK status now. If it shows `Valid_Other` or `Invalid_NULL` and you
also need to update the KEK (KEK check returned `False`), you can handle both
in a single BIOS session using the `allowAuthBypass` + FAT32 disk method from
Broadcom KB 423919 - this saves an extra reboot compared to doing them
separately.

**If KEK or DB returns `False`:**
- Do not proceed with registry changes
- The NVRAM may not have regenerated correctly
- Verify the rename in the Datastore Browser (the `.nvram_old` should exist
  and no new `.nvram` should yet contain the old data)
- Verify the ESXi host is version 8.0.2 or later
- Revert to snapshot and investigate before retrying

---

## Step 6 - Clear Stale Registry State

Open an elevated PowerShell console on the guest and type the following
commands **one at a time**:

**Check if a stale Servicing subkey exists and remove it:**

```
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
```

If the above returns `True`, run:

```
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Recurse -Force
```

**Alternatively, via Registry Editor (regedit):**

1. Press **Win + R**, type `regedit`, click **OK**
2. Navigate to:
   `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot`
3. If a **Servicing** subkey exists, right-click it → **Delete** → **Yes**

---

## Step 7 - Set AvailableUpdates Registry Value

This tells the Windows Secure Boot Update task to apply the 2023 certificates.

### Via Registry Editor (regedit)

1. Press **Win + R**, type `regedit`, click **OK**
2. Navigate to:
   `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot`
3. In the right panel, look for a value named `AvailableUpdates`
   - If it exists: right-click → **Modify**
   - If it does not exist: right-click in the right panel →
     **New** → **DWORD (32-bit) Value**, name it `AvailableUpdates`
4. Set the value:
   - Select **Hexadecimal**
   - Enter: `5944`
   - Click **OK**

### Via Elevated PowerShell

```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value 0x5944 -Type DWord -Force
```

Verify it was set:

```
Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates"
```

Expected result: `22852` (decimal equivalent of 0x5944)

---

## Step 8 - Trigger the Secure Boot Update Task

Rather than waiting up to 12 hours for the task to run on its automatic
schedule, trigger it immediately.

### Via Task Scheduler (GUI)

1. Press **Win + R**, type `taskschd.msc`, click **OK**
2. In the left panel, expand:
   **Task Scheduler Library** → **Microsoft** → **Windows** → **PI**
3. In the center panel, locate **Secure-Boot-Update**
4. Right-click **Secure-Boot-Update** → **Run**
5. Wait 30–60 seconds for the task to complete
6. The **Last Run Result** column should update to `0x0` (success) or a
   status code indicating it ran

### Verify AvailableUpdates After Task Run

Open **regedit** and check:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates`

Expected value after the first task run: `0x4100` in hex (16640 decimal).
This indicates certificates were applied but the boot manager update is
pending a reboot.

---

## Step 9 - Reboot

From an elevated PowerShell console on the guest:

```
Restart-Computer -Force
```

Or via **Start** → **Power** → **Restart**.

Wait for the VM to fully come back online (2–3 minutes). Confirm you can
authenticate before continuing.

---

## Step 10 - Trigger the Task Again After Reboot

Log back into the guest. Open **Task Scheduler**:

1. **Task Scheduler Library** → **Microsoft** → **Windows** → **PI**
2. Right-click **Secure-Boot-Update** → **Run**
3. Wait 30–60 seconds

Check `AvailableUpdates` in **regedit** again:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\AvailableUpdates`

Expected value after second task run: `0x4000` (16384 decimal) - fully complete.

---

## Step 11 - Verify Certificate Update Success

### Via Registry (primary check)

Open **regedit** and navigate to:
`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing`

Check the value of `UEFICA2023Status`:
- `Updated` - complete, proceed to Step 12
- `InProgress` - still running, wait 30 minutes and trigger the task again
- `NotStarted` - registry value may not have been set correctly, revisit Step 7

Also check whether a `UEFICA2023Error` key exists in the same location. If it
does and has a non-zero value, an error occurred - note the value and check the
Event Viewer (see below) for Event IDs 1795, 1801, 1802, or 1803.

### Via PowerShell (alternative)

Open an elevated PowerShell console and type each command individually:

**Check servicing status:**

```
Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -Name "UEFICA2023Status" -ErrorAction SilentlyContinue
```

Expected: `Updated`

**Check KEK 2023:**

```
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023'
```

Expected: `True`

**Check DB 2023:**

```
[System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes) -match 'Windows UEFI CA 2023'
```

Expected: `True`

### Via Event Viewer

1. Press **Win + R**, type `eventvwr.msc`, click **OK**
2. Expand **Windows Logs** → **System**
3. Click **Filter Current Log** in the right panel
4. In the **Event sources** box, type `TPM-WMI`, click **OK**

Look for:
- **Event ID 1808** - success. All certificates and boot manager have been
  applied to firmware. This is your definitive confirmation that the process
  is complete.
- **Event ID 1801** - ERROR. Certificates were updated but have not yet been
  applied to the device firmware. The device still needs attention. Per the
  user who tested this process: another reboot after running the task twice
  resolved this.
- **Event ID 1800** - Warning. A reboot is required before the Secure Boot
  update can proceed. Reboot and trigger the task again.
- **Event ID 1802** - ERROR. The update was blocked due to a known firmware
  issue on the device. Contact your OEM for a firmware update.
- **Event ID 1795** - ERROR. The firmware returned an error when attempting
  to write a Secure Boot variable. Contact your OEM for a firmware update.
- **Event ID 1803** - ERROR. No PK-signed KEK was found. This means the
  Platform Key is missing or invalid and Step 12 (PK remediation) is required.

**All registry checks must pass and Event ID 1808 should be present before
considering the process complete.**

If `UEFICA2023Status` shows `InProgress`, wait 30 minutes and trigger the task
again via Task Scheduler. The task runs every 12 hours automatically but can
always be triggered manually.

---

## Step 12 - Check and Remediate the Platform Key (PK)

The Platform Key authenticates future KEK and DB updates via Windows Update.
ESXi versions earlier than 9.0 write a placeholder PK during NVRAM regeneration
that is not trusted by Windows Update - this must be replaced with the proper
Microsoft-signed key.

### 12a - Check Current PK Status

Open an elevated PowerShell console on the guest and type:

```
$pk = Get-SecureBootUEFI -Name PK
```

Then type:

```
if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 44) { Write-Host "PK Status: Invalid_NULL" -ForegroundColor Red } else { $t = [System.Text.Encoding]::ASCII.GetString($pk.Bytes[44..($pk.Bytes.Length-1)]); if ($t -match 'Windows OEM Devices') { Write-Host "PK Status: Valid_WindowsOEM" -ForegroundColor Green } elseif ($t -match 'Microsoft') { Write-Host "PK Status: Valid_Microsoft" -ForegroundColor Green } else { Write-Host "PK Status: Valid_Other (ESXi placeholder - remediation required)" -ForegroundColor Yellow } }
```

**If PK Status is `Valid_WindowsOEM` or `Valid_Microsoft`:** Skip to Step 13.
No PK remediation is needed.

**If PK Status is `Valid_Other` or `Invalid_NULL`:** Continue with the
sub-steps below.

### 12b - BitLocker Re-Check Before SetupMode Reboot

The BitLocker suspension from Step 2 was consumed by the power-off/on cycle
(Step 3/5) and the reboot (Step 9). If BitLocker was active, it has now
auto-resumed. Check and re-suspend before the SetupMode reboot.

**Via Control Panel:**

Open **Control Panel** → **System and Security** → **BitLocker Drive Encryption**.

If C: shows **BitLocker on**:
1. Save the recovery key again (Back up your recovery key → Save to a file)
2. Click **Suspend protection** → **Yes**

**Via elevated PowerShell:**

```
Get-BitLockerVolume -MountPoint "C:" | Select-Object MountPoint, ProtectionStatus
```

If `ProtectionStatus` is `On`:

Save the recovery key:

```
(Get-BitLockerVolume -MountPoint "C:").KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" } | Select-Object KeyProtectorId, RecoveryPassword | Format-List
```

Re-suspend:

```
Suspend-BitLocker -MountPoint "C:" -RebootCount 2
```

### 12c - Enable UEFI SetupMode via vSphere Client

SetupMode allows the PK to be enrolled without requiring the existing PK to
sign the update. This is set via a VMX configuration option in vSphere Client.

> **Note:** Broadcom KB 423919 (updated March 2026) documents an alternative
> manual procedure using `uefi.allowAuthBypass` and a FAT32 VMDK for all ESXi
> versions. That method enrolls the PK via the UEFI setup UI rather than from
> the guest OS and does not require deleting the NVRAM file. The SetupMode
> procedure here is an alternative that is confirmed working on ESXi 8.x. If
> you prefer to follow the Broadcom-documented disk method, refer to KB 423919
> directly.

**The VM must be powered off for this option to take effect on the next boot.**

First, power off the VM:
1. Right-click the VM → **Power** → **Shut Down Guest OS**
   (or **Power Off** if guest tools are unresponsive)
2. Wait for the VM to show **Powered Off**

Set the SetupMode VMX option:
1. Right-click the VM → **Edit Settings**
2. Click the **VM Options** tab
3. Expand **Advanced**
4. Click **Edit Configuration** (opens the Configuration Parameters dialog)
5. Click **Add Configuration Params** (or **Add Row**)
6. Enter:
   - **Key:** `uefi.secureBootMode.overrideOnce`
   - **Value:** `SetupMode`
7. Click **OK** → **OK** to close Edit Settings

Power the VM back on:
1. Right-click the VM → **Power** → **Power On**
2. Wait 2–3 minutes for the VM to fully boot

### 12d - Copy WindowsOEMDevicesPK.der to the Guest

The `.der` file needs to be accessible inside the guest VM. The simplest
method is to copy it via your RDP session.

**Via RDP file transfer:**

1. Before connecting via RDP, open **Remote Desktop Connection**
2. Click **Show Options** → **Local Resources** tab
3. Under **Local devices and resources**, click **More**
4. Check **Drives** (or expand and check your specific local drive)
5. Click **OK**, then connect to the VM via RDP
6. Inside the RDP session, open **File Explorer**
7. Under **This PC**, your local drive will appear (e.g.,
   `C on YOURWORKSTATION`)
8. Copy `WindowsOEMDevicesPK.der` from your workstation to
   `C:\Windows\Temp\WindowsOEMDevicesPK.der` on the guest

**Alternatively, via a UNC share or USB if your environment allows it.**

### 12e - Verify SetupMode Is Active

Open an elevated PowerShell console on the guest and type:

```
(Get-SecureBootUEFI SetupMode -ErrorAction SilentlyContinue).Bytes[0]
```

Expected result: `1`

If result is `0`, SetupMode did not activate - go back to Step 12c and verify
the VMX option was set correctly and that the VM was fully powered off before
powering on again. Note that `uefi.secureBootMode.overrideOnce` is
single-use - it clears automatically after boot regardless of whether
enrollment succeeds.

### 12f - Enroll the Platform Key

In the same elevated PowerShell console on the guest, type each line
individually (press Enter after each):

```
$pkFile = "C:\Windows\Temp\WindowsOEMDevicesPK.der"
```

```
$ownerGuid = "55555555-0000-0000-0000-000000000000"
```

```
Format-SecureBootUEFI -Name PK -CertificateFilePath $pkFile -SignatureOwner $ownerGuid -FormatWithCert -Time "2025-10-23T11:00:00Z" | Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z"
```

If the command completes without an error, the PK enrollment was submitted.
A reboot is required for it to take effect.

**If you receive an access denied or UAC error:** Confirm you opened PowerShell
using **Run as Administrator** (right-click the PowerShell icon →
**Run as Administrator**). Do not attempt to run this from a standard session.

### 12g - Clear the SetupMode VMX Option

Before rebooting, clear the VMX option to prevent it from persisting
unexpectedly. Do this from vSphere Client on your admin workstation:

1. Right-click the VM → **Edit Settings** → **VM Options** tab
2. Expand **Advanced** → **Edit Configuration**
3. Find the row with Key `uefi.secureBootMode.overrideOnce`
4. Clear the **Value** field (leave it empty) or delete the row entirely
5. Click **OK** → **OK**

### 12h - Reboot and Verify PK

Reboot the guest:

```
Restart-Computer -Force
```

After the VM fully comes back online, open an elevated PowerShell console
and type:

```
$pk = Get-SecureBootUEFI -Name PK
```

```
$t = [System.Text.Encoding]::ASCII.GetString($pk.Bytes[44..($pk.Bytes.Length-1)])
```

```
if ($t -match 'Windows OEM Devices') { Write-Host "PK Status: Valid_WindowsOEM" -ForegroundColor Green } elseif ($t -match 'Microsoft') { Write-Host "PK Status: Valid_Microsoft" -ForegroundColor Green } else { Write-Host "PK Status: Valid_Other - enrollment may not have succeeded" -ForegroundColor Red }
```

Expected: `PK Status: Valid_WindowsOEM`

If status is still `Valid_Other`, the enrollment did not take effect. Verify:
- SetupMode was active (Step 12e returned `1`) before running the enrollment
- The `.der` file path was correct
- The enrollment command completed without errors
- The VM was rebooted after enrollment

---

## Step 13 - Retain Snapshot for Validation Period

Leave the snapshot in place for several days while monitoring the VM. When you
are satisfied there are no issues:

1. Right-click the VM → **Snapshots** → **Manage Snapshots**
2. Select the **Pre-SecureBoot-Fix** snapshot
3. Click **Delete** → confirm

---

## Step 14 - Remove the .nvram_old File (After Snapshot Removed)

Once the snapshot has been removed and you are satisfied the VM is operating
correctly with no intention of rolling back, the `.nvram_old` file can be
cleaned up from the datastore. This file was preserved specifically to allow
rollback - do not remove it until the snapshot is gone and you are confident
the remediation is complete.

1. In vSphere Client, click **Storage**
2. Select the datastore, click the **Files** tab
3. Navigate into the VM's folder
4. Locate `vmname.nvram_old`
5. Right-click → **Delete** → confirm

---

## Rollback Procedure

If anything goes wrong at any point, revert to the snapshot. This returns the
VM to its exact pre-change state including the original NVRAM.

1. In vSphere Client, right-click the VM → **Power** → **Power Off**
   (if currently powered on)
2. Right-click the VM → **Snapshots** → **Manage Snapshots**
3. Select the **Pre-SecureBoot-Fix** snapshot
4. Click **Revert to** → confirm
5. Right-click the VM → **Power** → **Power On**

> Reverting to a snapshot automatically restores the original NVRAM state.
> You do not need to manually rename or restore the `.nvram_old` file when
> using the snapshot revert path.

---

## Quick Reference Checklist

- [ ] `WindowsOEMDevicesPK.der` downloaded to admin workstation
- [ ] Snapshot taken: `Pre-SecureBoot-Fix`
- [ ] BitLocker recovery key saved (if BitLocker active)
- [ ] BitLocker suspended (if BitLocker active)
- [ ] VM powered off
- [ ] NVRAM file renamed: `.nvram` → `.nvram_old` (via Datastore Browser)
- [ ] VM powered on - KEK 2023: True, DB 2023: True (verified in PowerShell)
- [ ] Stale Servicing registry subkey cleared (if present)
- [ ] `AvailableUpdates` set to `0x5944` (via regedit or PowerShell)
- [ ] Secure-Boot-Update task triggered (via Task Scheduler)
- [ ] VM rebooted
- [ ] Task triggered again post-reboot (via Task Scheduler)
- [ ] `UEFICA2023Status` = `Updated` (regedit or PowerShell)
- [ ] `UEFICA2023Error` key does not exist (regedit - if it exists, investigate)
- [ ] KEK 2023: `True` | DB 2023: `True`
- [ ] Event ID **1808** present in System log (TPM-WMI source) - definitive success
- [ ] PK Status checked
- [ ] If PK remediation needed:
  - [ ] BitLocker re-suspended (if BitLocker active)
  - [ ] SetupMode VMX option set via Edit Configuration in vSphere Client
  - [ ] VM powered off and back on
  - [ ] `WindowsOEMDevicesPK.der` copied to `C:\Windows\Temp\` on guest
  - [ ] SetupMode confirmed active (returned `1`)
  - [ ] PK enrollment command run in elevated PowerShell on guest
  - [ ] SetupMode VMX option cleared in vSphere Client
  - [ ] VM rebooted
  - [ ] PK Status: `Valid_WindowsOEM`
- [ ] BitLocker protection auto-resumed - verify after all reboots complete
- [ ] Snapshot retained for validation period
- [ ] Snapshot removed after validation
- [ ] `.nvram_old` file deleted from datastore after snapshot removed
