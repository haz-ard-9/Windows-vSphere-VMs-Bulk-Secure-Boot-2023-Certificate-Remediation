# FixSecureBootBulk.ps1

A PowerShell script for bulk remediating the Microsoft Secure Boot 2023 certificate
issue on Windows Server VMs running in VMware vSphere 8. Supports Windows
Server 2016, 2019, 2022, and 2025, as well as Windows 10 and 11.

---

> ## <span style="color:red">Important notice regarding support status</span>
>
> This script uses the NVRAM rename strategy to resolve 2023 certificate availability in VM UEFI firmware. The approach works by renaming the VM's existing `.nvram` file so that ESXi regenerates it fresh with the updated certificates on next boot.
>
> Broadcom previously documented this method in KB 421593. That KB has since been removed from their site with no replacement or explanation. **A Broadcom employee has since stated in the [Broadcom community forums](https://community.broadcom.com/vmware-cloud-foundation/discussion/uefi-2023-fully-automated-script-also-with-plattform-key-change) that deleting or renaming the NVRAM file is not endorsed by VMware engineering and not supported. Broadcom has indicated they are working on an official solution.** The archived version of KB 421593 is linked in the References section below for historical reference only.
>
> This method has been tested and works reliably on ESXi 8.0.2 and later with hardware version 21 VMs. No issues have been encountered in practice. However, given the official unsupported position from Broadcom, use this script with your own judgment and at your own risk.
>
> If you encounter issues, the script includes rollback options (`-Rollback`) that restore the original NVRAM file and revert to the pre-remediation snapshot. Retaining snapshots during remediation runs (`-RetainSnapshots`) is strongly recommended until you have validated the results.

---

## Background

Microsoft's original Secure Boot certificates (issued in 2011) expire in June 2026.
Windows Server requires updated 2023 KEK and DB certificates to continue booting
with Secure Boot enabled after that date.

VMs created before ESXi 8.0.2 have a NULL Platform Key (PK) signature in their
NVRAM that prevents the standard certificate enrollment process from working. The
fix is to delete the VM's NVRAM file and let ESXi regenerate it - ESXi 8.0.2 and
later automatically populate the new NVRAM with the 2023 certificates. Windows can
then detect and install them without requiring manual firmware enrollment.

**Platform Key (PK) note:** Even after NVRAM regeneration, ESXi versions earlier
than 9.0 write a placeholder PK into the new NVRAM rather than a proper
Microsoft-signed key. Per [Broadcom KB 423919](https://knowledge.broadcom.com/external/article/423919),
this placeholder PK will not authenticate future Windows Update KEK changes. The
script detects this condition (`Valid_Other` status) and can enroll the correct
Windows OEM Devices PK via UEFI SetupMode when `-PKDerPath` is provided.


---

**References:**
- [Microsoft KB5068202](https://support.microsoft.com/help/5068202) - AvailableUpdates registry key and monitoring
- [Microsoft KB5068198](https://support.microsoft.com/help/5068198) - Group Policy deployment (requires Windows Server 2025 ADMX templates)
- [Microsoft KB5085046](https://support.microsoft.com/en-us/kb/5085046) - Secure Boot troubleshooting guide; AvailableUpdates bit progression, event IDs, and failure scenarios (published March 2026)
- [Broadcom KB 421593](https://web.archive.org/web/20260212085158/https://knowledge.broadcom.com/external/article/421593/missing-microsoft-corporation-kek-ca-202.html) - NVRAM rename procedure for missing KEK CA 2023 on Windows VMs *(Broadcom has removed this KB; link points to archive.org)*
- [Broadcom KB 423919](https://knowledge.broadcom.com/external/article/423919) - Manual Update of the Secure Boot Platform Key in Virtual Machines

---

## Requirements

### VMware Infrastructure
- **ESXi 8.0.2 or later** on all hosts where target VMs are running
  - Earlier ESXi versions will not regenerate NVRAM with 2023 certificates
  - Check host versions: `Get-VMHost | Select Name, Version` in PowerCLI
- **vCenter Server** - the script connects via the PowerCLI vCenter API

### VM Hardware Version
- **Hardware version 13 or later** (introduced in vSphere 6.5) - required for EFI firmware and Secure Boot support
- **Hardware version 14 or later** - required for vTPM (relevant to the BitLocker safety check)
- **Hardware version 21 or later** - required for ESXi to populate regenerated NVRAM with the 2023 KEK certificate. VMs on version 13-20 will have NVRAM regenerated but the KEK will not be present afterward; upgrade hardware version before running the script on these VMs
- VMs below version 13 will be silently excluded by the EFI/Secure Boot filter and will not appear in the target list
- Check hardware versions:
  ```powershell
  Get-VM | Select Name, HardwareVersion | Sort-Object HardwareVersion
  ```
- The script can upgrade hardware version automatically using `-UpgradeHardware`. This can be run standalone (powers off, upgrades, powers on) or combined with the main remediation run where it runs between steps 2 and 3. See [Hardware Version Upgrade](#hardware-version-upgrade).
- To upgrade manually via vSphere Client (VM must be powered off): **Actions → Compatibility → Upgrade VM Compatibility**

### VMware Tools
- **VMware Tools must be installed, running, and recognized by vCenter** on all target VMs
  - The script uses `Invoke-VMScript` for all guest operations; vCenter will reject these calls if Tools is not running
  - Tools should be current with the ESXi host version. There is no fixed minimum version number; the "out of date" warning from vCenter is a relative comparison between the version installed in the guest and the version bundled with the ESXi host the VM is running on. Outdated Tools will appear in yellow in the console output and can cause `Invoke-VMScript` to fail silently with ExitCode 1 and no output. The script displays the installed Tools version and status for every VM at the start of each run so you can identify which VMs need an update before proceeding.
  - "Open VM Tools" (OVT) is supported on Windows Server 2019 and later as it ships inbox, but the standard VMware Tools package is preferred for full compatibility
- Check Tools status across all VMs:
  ```powershell
  Get-VM | Select Name,
      @{N="ToolsStatus";  E={$_.Guest.ExtensionData.ToolsStatus}},
      @{N="ToolsVersion"; E={$_.Guest.ToolsVersion}} |
      Where-Object { $_.ToolsStatus -ne "toolsOk" }
  ```
- VMs reporting `toolsNotInstalled`, `toolsNotRunning`, or `toolsOld` should be remediated before running the script

### Guest OS
- **Windows 10, Windows 11, and Windows Server 2016, 2019, 2022, or 2025**
- VMs must be configured with **EFI firmware** and **Secure Boot enabled** at the hypervisor level
- Domain, Server, or Local admin credentials with rights to run scheduled tasks and modify HKLM registry keys on the specified Windows VMs

### PowerShell & Modules
- **PowerShell 5.1 or later** (Windows) or **PowerShell 7+** (cross-platform)
- **VMware PowerCLI** module (see [Installing PowerCLI](#installing-powercli) below)

---

## Installing PowerCLI

PowerCLI is VMware's PowerShell module for managing vSphere infrastructure.
It must be installed on the machine you run this script from - it does not need
to be installed on the VMs themselves.

### Install from the PowerShell Gallery (recommended)

Open PowerShell as Administrator and run:

```powershell
Install-Module -Name VMware.PowerCLI -Scope CurrentUser
```

If prompted about an untrusted repository, type `Y` to confirm.

To install for all users on the machine instead:

```powershell
Install-Module -Name VMware.PowerCLI -Scope AllUsers
```

### Verify the installation

```powershell
Get-Module -Name VMware.PowerCLI -ListAvailable
```

### Update an existing installation

```powershell
Update-Module -Name VMware.PowerCLI
```

### Configure PowerCLI (one-time setup)

Suppress the Customer Experience Improvement Program prompt:

```powershell
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false
```

The script does **not** modify your PowerCLI certificate configuration. Your
existing `InvalidCertificateAction` setting is used as-is. If your vCenter has
a properly signed certificate, leave this at its default and certificate
validation will work normally.

If your vCenter uses a self-signed or untrusted certificate, you can either
configure this once permanently:

```powershell
Set-PowerCLIConfiguration -InvalidCertificateAction Warn -Scope User -Confirm:$false
```

or pass `-IgnoreCertificateWarnings` when calling the script to suppress
validation for that session only (see [Parameters](#parameters)).

---

## Configuration

Pass `-vCenter` on the command line to specify your vCenter server. If not provided and no connection is already active, the script will prompt for the server name:

```powershell
.\FixSecureBootBulk.ps1 -vCenter "vcenter.yourdomain.com" -VMName "vm01" -GuestCredential $cred
```

Alternatively, pre-connect to vCenter before running the script and it will use the existing session:

```powershell
Connect-VIServer -Server "vcenter.yourdomain.com"
.\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred
```

---

## Preparing for PK Remediation

Platform Key enrollment requires `WindowsOEMDevicesPK.der` from Microsoft's
secureboot_objects repository. Download it before your first production run:

```
https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der
```

On that GitHub page, click the **Download raw file** button (the download icon
in the top-right of the file view). Do not right-click Save As on the page itself
or you will get HTML instead of the binary.

Place the file in the same directory as the script. The relative path
`.\WindowsOEMDevicesPK.der` is used in all examples below.

> **Note:** The script converts `WindowsOEMDevicesPK.der` from DER certificate
> format to EFI Signature List format internally using `Format-SecureBootUEFI` -
> no manual conversion is required.

---

## Usage

On every run the script displays a support status notice in yellow referencing the official Broadcom position on the NVRAM rename approach and prompts for acknowledgement before proceeding. Pass `-Confirm` to suppress this prompt for unattended or scheduled runs.

### Prepare credentials

```powershell
$cred = Get-Credential  # Admin account with guest OS access
```

### Basic examples

```powershell
# Fix a single VM (snapshot taken, removed on success)
.\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred

# Fix a single VM without taking a snapshot
.\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred -NoSnapshot

# Fix multiple VMs, keep snapshots for a validation period
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02","vm03" -GuestCredential $cred -RetainSnapshots

# Fix all VMs matching a wildcard
.\FixSecureBootBulk.ps1 -VMName "AppServer*" -GuestCredential $cred -RetainSnapshots

# Fix all eligible Windows Server VMs in vCenter (EFI + Secure Boot enabled)
.\FixSecureBootBulk.ps1 -GuestCredential $cred -RetainSnapshots

# Full remediation including PK enrollment (recommended)
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

# Full remediation with PK enrollment and BitLocker key backup
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
    -BitLockerBackupShare "\\fileserver\BitLockerKeys"

# Connect to a vCenter with a self-signed certificate
.\FixSecureBootBulk.ps1 -GuestCredential $cred -RetainSnapshots -IgnoreCertificateWarnings

# Assess all VMs - hypervisor-level data only (no guest credentials needed)
.\FixSecureBootBulk.ps1 -Assess

# Assess all VMs - full data including cert status, registry, and event log
.\FixSecureBootBulk.ps1 -Assess -GuestCredential $cred

# Upgrade hardware version to meet the version 21 requirement (snapshot taken by default)
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardware

# Upgrade hardware version and run full remediation in a single pass
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -UpgradeHardware

# Run unattended without the datastore space confirmation prompt
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm

# Process co-dependent VMs with a delay between each to allow services to start
.\FixSecureBootBulk.ps1 -VMName "AppDB01","AppServer01" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -InterVMDelay 120
```

### Using a CSV file for batch processing

Create a CSV with a `VMName` column:

```
VMName
vm01
vm02
vm03
vm04
```

Then pass it with `-VMListCsv`:

```powershell
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred -RetainSnapshots
```

You can also combine `-VMName` and `-VMListCsv` - they are merged and deduplicated:

```powershell
.\FixSecureBootBulk.ps1 -VMName "vm01" -VMListCsv ".\batch1.csv" -GuestCredential $cred
```

The script's own output CSV (written after each run) contains a `VMName` column,
so you can feed it back in to run cleanup on exactly the same set of VMs:

```powershell
# Feed a previous run's output CSV back in for cleanup
.\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260301_143000.csv" -CleanupSnapshots
```

---

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-VMName` | `string[]` | One or more VM display names. Accepts wildcards. VMs are processed in the order provided. |
| `-VMListCsv` | `string` | Path to a CSV file with a `VMName` column. |
| `-GuestCredential` | `PSCredential` | Admin credential for guest OS access. Required for main mode. |
| `-NoSnapshot` | `switch` | Skip snapshot creation. Cannot be combined with `-RetainSnapshots`. |
| `-RetainSnapshots` | `switch` | Keep snapshots even on success. Use with `-CleanupSnapshots` later. |
| `-CleanupSnapshots` | `switch` | Remove all `Pre-SecureBoot-Fix*` snapshots on target VMs. |
| `-CleanupNvram` | `switch` | Delete all `.nvram_old` files left on target VM datastores. |
| `-Rollback` | `switch` | Restore original NVRAM and revert to snapshot for target VMs. |
| `-BitLockerBackupShare` | `string` | UNC path to a file share for BitLocker recovery key backups. Required to process VMs with active BitLocker. Example: `\\server\BitLockerKeys` |
| `-PKDerPath` | `string` | Path to `WindowsOEMDevicesPK.der`. When provided, enrolls the Windows OEM Devices Platform Key on any VM where the PK is NULL, invalid, or an ESXi-generated placeholder (`Valid_Other`). See [Preparing for PK Remediation](#preparing-for-pk-remediation). |
| `-KEKDerPath` | `string` | Path to the Microsoft KEK 2K CA 2023 certificate in DER format. Optional - only needed if KEK 2023 is absent after NVRAM regeneration, which should not occur on ESXi 8.0.2+. |
| `-WaitSeconds` | `int` | Seconds to wait after reboot before polling for VMware Tools. Default: `90`. |
| `-GracefulShutdownTimeout` | `int` | Seconds to wait for a graceful guest OS shutdown before falling back to a hard power off. The script always attempts a graceful shutdown via VMware Tools first. Default: `120`. Set to `0` to always use hard power off. |
| `-InterVMDelay` | `int` | Seconds to wait between processing each VM. Default: `0`. Use when remediating paired or co-dependent VMs (primary/secondary, database/app server) to allow services to fully start before the next VM is processed. Not applied after the last VM in the batch. |
| `-IgnoreCertificateWarnings` | `switch` | Sets PowerCLI `InvalidCertificateAction` to `Ignore` for the current session before connecting to vCenter. Only use this if your vCenter uses a self-signed or untrusted certificate. Omitting this flag leaves your existing PowerCLI certificate configuration unchanged. |
| `-vCenter` | `string` | Hostname or IP address of the vCenter server. If not specified and no existing connection is active, the script will prompt for the server name. If a connection is already open the script uses it and this parameter is ignored. |
| `-Assess` | `switch` | Read-only assessment mode. No changes are made to any VM. Collects current state for all target VMs and produces a CSV and console summary. See [Assessment Mode](#assessment-mode). Mutually exclusive with all action modes. |
| `-UpgradeHardware` | `switch` | Upgrades VM hardware version to the latest supported by the host. Can be used standalone (powers off, upgrades, powers on - no cert work) or combined with the main remediation run, where it is inserted between step 2 and step 3. See [Hardware Version Upgrade](#hardware-version-upgrade). |
| `-CleanupHWSnapshots` | `switch` | Removes all `Pre-HWUpgrade*` snapshots created by standalone `-UpgradeHardware` runs. Run after verifying the hardware upgrade is stable. Does not require `-GuestCredential`. |
| `-Confirm` | `switch` | Suppresses all interactive confirmation prompts including the support status acknowledgement and the datastore space confirmation. Use for unattended or scheduled runs. |

---

## Process Flow

For each VM in the main remediation mode, the script performs the following steps:

```
[Pre]  Pre-check: assess current VM state via guest script to determine entry point.
       Skips steps already complete based on NVRAM cert status, AvailableUpdates,
       and UEFICA2023Status. See Smart Step Detection below.
[0/9] BitLocker / vTPM safety check
      Without -BitLockerBackupShare: skip VM if BitLocker active
      With    -BitLockerBackupShare: export recovery keys to share,
              suspend BitLocker (RebootCount 2), then proceed
[1/9] Take snapshot (skipped if -NoSnapshot)
[2/9] Power off VM  (skipped per pre-check if NVRAM already has 2023 certs)
[2b/9] Upgrade hardware version (only if -UpgradeHardware; skipped if already >= 21)
[3/9] Rename vmname.nvram -> vmname.nvram_old on datastore  (skipped per pre-check)
[4/9] Power on VM (ESXi regenerates NVRAM with 2023 KEK/DB certs)  (skipped per pre-check)
      └─ Verify KEK 2023 and DB 2023 are present in new NVRAM
[5/9] Clear stale Servicing registry state (if any)  (skipped per pre-check)
      Set AvailableUpdates = 0x5944 via SYSTEM scheduled task
      Trigger \Microsoft\Windows\PI\Secure-Boot-Update task
[6/9] Reboot VM  (skipped if cert update already complete)
      Trigger Secure-Boot-Update task again (completes Boot Manager update)
[7/9] Verify: Servicing Status = "Updated", KEK 2023 = True, DB 2023 = True
      Also reads TPM-WMI event log (1036, 1043, 1044, 1045, 1795, 1797, 1799, 1800, 1801, 1802, 1803, 1808) per KB5016061 and KB5085046
[7b/9] Extra reboot (only if Event 1801 or 1800 present AND Event 1808 absent)
       Reboots VM, triggers task, re-verifies. If 1801 persists after reboot,
       diagnoses cause (1802/1795/registry error/stuck AvailableUpdates).
[8/9] Check Platform Key (PK) validity
      Valid_WindowsOEM / Valid_Microsoft -> no action needed
      Valid_Other (ESXi placeholder) or Invalid_NULL -> proceed to step 9
                                                        if -PKDerPath provided
[9/9] PK remediation via UEFI SetupMode (requires -PKDerPath)
      [PK 1/5] Set uefi.secureBootMode.overrideOnce = SetupMode on VM
      [PK 2/5] Power off/on into SetupMode
               └─ Re-suspend BitLocker if it has auto-resumed (RebootCount 2)
      [PK 3/5] Copy WindowsOEMDevicesPK.der to guest C:\Windows\Temp\
      [PK 4/5] Enroll PK: Format-SecureBootUEFI | Set-SecureBootUEFI
      [PK 5/5] Clear SetupMode VMX option, reboot, verify PK = Valid_WindowsOEM
      Remove snapshot on success (unless -RetainSnapshots or -NoSnapshot)
```

### Smart Step Detection

Before running any changes, the script runs a lightweight guest assessment to determine which steps are still needed. This prevents unnecessary reboots and NVRAM operations on VMs where prior work (manual or from an earlier script run) has already completed some or all of the process.

| Pre-check result | Entry point | Steps skipped |
|---|---|---|
| KEK_2023 = False | Full run | None |
| KEK_2023 = True, DB_2023 = True | skipNvram | Steps 2/2b/3/4 |
| AvailableUpdates = 0x4100 | skipToStep6 | Steps 2/2b/3/4/5 |
| UEFICA2023Status = Updated or 0x4000 | certDone | Steps 2/2b/3/4/5/6 |
| Cert done + PK valid (or no -PKDerPath) | allDone | Entire VM skipped |

If the VM is powered off when the script runs, or the pre-check fails for any reason, the script falls back to a full run with no steps skipped.

### PK Status values

| Status | Meaning | Action |
|--------|---------|--------|
| `Valid_WindowsOEM` | Proper Microsoft Windows OEM Devices PK | No action |
| `Valid_Microsoft` | Microsoft-signed PK | No action |
| `Valid_Other` | ESXi-generated placeholder (ESXi < 9.0) - will not authenticate future Windows Update KEK changes | Enroll proper PK |
| `Invalid_NULL` | No PK data present | Enroll proper PK |
| `Not checked` | Step 8 was not reached (cert update failed) | Resolve cert update first |

### BitLocker and PK remediation

The initial BitLocker suspension at step 0 uses `RebootCount 2`, which covers
the power-off/on at step 2 and the reboot at step 6. By the time step 9 runs,
BitLocker will have auto-resumed. The script detects this and re-suspends
(with a second key backup to the share) before the SetupMode reboot. A VM
requiring PK remediation will have four total reboots and two backup files
written to the share.

### Registry key progression

The `AvailableUpdates` value under `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot`
tracks progress. Bits clear as each step completes:

| Value | Meaning |
|-------|---------|
| `0x5944` | Starting state - all update steps needed |
| `0x5904` | Windows UEFI CA 2023 added to DB (bit 0x0040 cleared) |
| `0x5104` | Microsoft Option ROM UEFI CA 2023 added to DB (bit 0x0800 cleared) |
| `0x4104` | Microsoft UEFI CA 2023 added to DB (bit 0x1000 cleared) - KEK update still pending |
| `0x4100` | KEK 2K CA 2023 applied (bit 0x0004 cleared) - Boot Manager update still pending |
| `0x4000` | Fully complete - Boot Manager updated (bit 0x0100 cleared); `0x4000` modifier remains permanently set |

Per [KB5085046](https://support.microsoft.com/en-us/kb/5085046), bit `0x4000` is a behavior modifier that is never cleared. A final value of `0x4000` indicates all applicable update actions have completed successfully.

### Verification

Final status is read from:
- `UEFICA2023Status` under `HKLM:\...\SecureBoot\Servicing` - expected value: `Updated`
- `UEFICA2023Error` under `HKLM:\...\SecureBoot\Servicing` - must be absent. This key exists only when a deployment error has occurred and does **not** appear in the Windows Event Log. A VM can show `UEFICA2023Status = Updated` while this key is present; the script treats this as an incomplete result and records it in the `UEFICA2023Error` CSV column and `Notes`.
- `UEFICA2023ErrorEvent` under `HKLM:\...\SecureBoot\Servicing` - companion to `UEFICA2023Error`, contains the event ID associated with the error condition when present. Recorded in VM `Notes` when set.
- `Get-SecureBootUEFI kek` - must contain `Microsoft Corporation KEK 2K CA 2023`
- `Get-SecureBootUEFI db` - must contain `Windows UEFI CA 2023`
- `Get-SecureBootUEFI PK` - expected `Valid_WindowsOEM` after PK enrollment

The script reads the following event IDs from the System log (TPM-WMI source) per [KB5016061](https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69) and [KB5085046](https://support.microsoft.com/en-us/kb/5085046) and records them in the CSV output:

| Event ID | Level | Meaning |
|----------|-------|---------|
| 1036 | Information | Windows UEFI CA 2023 added to Secure Boot DB |
| 1043 | Information | KEK 2K CA 2023 applied successfully |
| 1044 | Information | Microsoft Option ROM UEFI CA 2023 added to DB |
| 1045 | Information | Microsoft UEFI CA 2023 added to DB |
| 1795 | Error | Firmware returned error on Secure Boot variable write - contact OEM |
| 1797 | Error | Boot manager update failed - check firmware |
| 1799 | Information | Boot manager signed by Windows UEFI CA 2023 applied successfully |
| 1800 | Warning | Reboot required before Secure Boot update can proceed |
| 1801 | Error | Certificates updated but not yet applied to firmware - additional reboot may be needed |
| 1802 | Error | Update blocked by known firmware issue - contact OEM for firmware update |
| 1803 | Error | No PK-signed KEK found - PK remediation required |
| 1808 | Information | All certificates and boot manager applied to firmware - definitive success signal |

Event 1808 absence does **not** block a successful result in the CSV. Testing confirmed it may not fire until an extra reboot after the task completes, even on a fully successful deployment. The registry signals and cert checks are the primary pass/fail gate. Error events are recorded in `Notes` when present.

---

## Snapshot and Cleanup Workflow

The recommended workflow when processing VMs in batches is:

```
1. Run fix with -RetainSnapshots
   .\FixSecureBootBulk.ps1 -VMListCsv .\batch1.csv -GuestCredential $cred `
       -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

2. Validate VMs over several days (check application health, event logs, etc.)

3. Run all cleanup in one pass once satisfied
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv `
       -CleanupSnapshots -CleanupNvram

   # If -UpgradeHardware was also used, include -CleanupHWSnapshots
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv `
       -CleanupSnapshots -CleanupHWSnapshots -CleanupNvram
```

The cleanup switches can be combined freely in a single run. When combined, the script enforces a safe internal order regardless of what was specified: Pre-SecureBoot-Fix snapshots are removed first (children), then Pre-HWUpgrade snapshots (parents), then `.nvram_old` files. A single confirmation prompt covers all operations and results are written to one combined CSV (`SecureBoot_Cleanup_<timestamp>.csv`).

Before removing any snapshot, the script checks for non-managed child snapshots (snapshots not created by this script). If found, that snapshot is skipped with a warning and logged in the Notes column. Non-managed children must be removed manually in vSphere Client before re-running cleanup. Pre-SecureBoot-Fix child snapshots under a Pre-HWUpgrade parent are handled automatically when both `-CleanupSnapshots` and `-CleanupHWSnapshots` are specified.

If only `-CleanupNvram` is run while Pre-SecureBoot-Fix snapshots still exist on a VM, the script logs a warning noting that no rollback path will remain, but does not block the deletion.

---

## Rollback

To undo the fix on one or more VMs:

```powershell
# Rollback specific VMs
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -Rollback

# Rollback using a previous run's output CSV
.\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260301_143000.csv" -Rollback
```

Rollback does not require `-GuestCredential`. For each VM it:

1. Powers off the VM
2. Renames the current `.nvram` → `.nvram_new` (preserves it)
3. Renames `.nvram_old` → `.nvram` (restores the original)
4. Reverts to the `Pre-SecureBoot-Fix*` snapshot if one exists
5. Powers the VM back on

> **Note:** Registry changes (`AvailableUpdates`, Servicing keys) are only reverted
> if a snapshot exists. If no snapshot was taken (e.g., `-NoSnapshot` was used),
> the NVRAM is still restored but registry state is not.

The result column in the rollback CSV distinguishes between a full rollback
(`Rolled Back (NVRAM + Snapshot)`) and a partial one where only the NVRAM was
restored (`Rolled Back (NVRAM only - no snapshot)`).

---

## Output

The script writes a timestamped CSV to the current directory after each run:

| Mode | Output file |
|------|------------|
| Main remediation | `SecureBoot_Bulk_<timestamp>.csv` |
| Cleanup (any combination of -CleanupSnapshots, -CleanupHWSnapshots, -CleanupNvram) | `SecureBoot_Cleanup_<timestamp>.csv` |
| Rollback | `SecureBoot_Rollback_<timestamp>.csv` |

The main remediation CSV includes these columns:

`VMName`, `SnapshotCreated`, `BitLockerKeysBacked`, `BitLockerSuspended`,
`NVRAMRenamed`, `HWUpgraded`, `KEK_AfterNVRAM`, `DB_AfterNVRAM`, `UpdateTriggered`, `KEK_2023`,
`DB_2023`, `FinalStatus`, `UEFICA2023Error`, `Evt1808`, `Evt1801`, `Evt1802`,
`Evt1803`, `Evt1800`, `Evt1795`, `PK_Status`, `PKEnrolled`, `PKRemediated`,
`SnapshotRetained`, `Notes`

### Summary output

After each run the script prints a summary block with counts for each outcome
category. The PK section distinguishes four states:

```
PK already valid   : N  (Valid_WindowsOEM or Valid_Microsoft -- no enrollment needed)
PK placeholder     : N  (ESXi-generated Valid_Other -- enrolled this run)
PK enrolled        : N  (was Invalid_NULL -- enrolled this run)
PK enroll failed   : N  (manual intervention required -- see Notes)
PK still invalid   : N  (provide -PKDerPath and re-run)
```

A separate **NOTES** block is printed after the summary table to display full
per-VM notes without truncation.

---

## BitLocker Handling

The script automatically checks for active BitLocker encryption before processing
each VM. Modifying Secure Boot variables changes PCR 7 measurements, which can
trigger BitLocker recovery mode on the next boot if protection is active.

### Without `-BitLockerBackupShare` (default)

Any VM with BitLocker active is **skipped** with a warning. This is the safe
default - no changes are made to the VM.

### With `-BitLockerBackupShare`

When a UNC share path is provided, the script handles BitLocker automatically
before proceeding with remediation:

1. **Exports all recovery keys** from the guest and writes them to the share as
   `VMName_BitLockerKeys_YYYYMMDD_HHMMSS.txt` - one file per VM, one entry per
   protected volume
2. **Aborts if the backup fails** - the VM is skipped rather than risking a lockout
3. **Suspends BitLocker** with `RebootCount 2`, covering the power-off/on cycle
   and the post-cert-update reboot (steps 2 and 6)
4. **Proceeds with full remediation** - NVRAM rename, cert update, registry fix
5. BitLocker **automatically resumes** after the second reboot with no manual
   intervention required

If PK remediation runs (step 9), the step 0 suspension will have been consumed
by the time the SetupMode reboot is needed. The script re-checks BitLocker status
at step 8 and, if it has auto-resumed, performs a **second backup and suspension**
before the SetupMode reboot. A VM requiring PK remediation will produce two
backup files on the share.

```powershell
# Process VMs including those with active BitLocker, with full PK enrollment
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -BitLockerBackupShare "\\fileserver\BitLockerKeys" `
    -PKDerPath ".\WindowsOEMDevicesPK.der"
```

> **Security:** Recovery key files contain plaintext cryptographic material.
> Restrict share access to authorized administrators only. The share must be
> accessible (writable) from the machine running the script, not from the VMs.

---

## Platform Key Remediation

Per Broadcom KB 423919, ESXi versions earlier than 9.0 do not install a valid
Platform Key when regenerating NVRAM. Instead, ESXi writes a placeholder value
that is detected by the script as `Valid_Other`. This placeholder PK will not
authenticate future Windows Update KEK changes, meaning Windows Update will be
unable to update KEK or DB/DBX variables once the current 2023 KEK certificate
eventually requires rotation.

### Why this matters

The chain of trust for Secure Boot variable updates is:

```
PK (Platform Key) -> signs -> KEK (Key Exchange Key) -> signs -> DB/DBX updates
```

Without a proper PK, Microsoft cannot sign KEK updates that Windows will accept.
This is not an immediate boot failure risk, but it blocks future security updates
to the Secure Boot database.

### PK enrollment method used by this script (ESXi 8.x)

The script uses UEFI SetupMode, a feature available on ESXi 8.0 and later:

1. Sets `uefi.secureBootMode.overrideOnce = SetupMode` on the VM's VMX configuration
2. Reboots the VM - the UEFI enters Setup Mode on the next boot, temporarily
   allowing PK enrollment without requiring an existing PK signature
3. Copies `WindowsOEMDevicesPK.der` into the guest
4. Runs `Format-SecureBootUEFI | Set-SecureBootUEFI` in an elevated guest session
   to convert the DER certificate to EFI Signature List format and enroll it
5. Clears the VMX option, reboots, and verifies the PK reads as `Valid_WindowsOEM`

The VMX option `uefi.secureBootMode.overrideOnce` is single-use - it is
automatically cleared after the next boot regardless of whether enrollment
succeeded, so no persistent security relaxation is introduced.

### Broadcom-documented manual method (all ESXi versions)

Broadcom KB 423919 (updated March 2026) documents a manual procedure using
`uefi.allowAuthBypass` and a FAT32 VMDK that applies to all ESXi versions
(7.x, 8.x, 9.x). That procedure enrolls the PK via the UEFI setup UI rather
than from the guest OS. The KB also documents manual KEK enrollment for
environments where the KEK 2023 certificate is not present.

The SetupMode approach used by this script is an alternative that is confirmed
working on ESXi 8.x and can be fully automated. For manual procedures or ESXi
7.x hosts (where SetupMode is not available), follow Broadcom KB 423919.
For a no-script walkthrough of the SetupMode method, see `SecureBoot_Manual_NoScript.md`.

### ESXi 7.x (not supported by this script)

This script cannot automate PK remediation on ESXi 7.x hosts. For these hosts,
follow the Broadcom KB 423919 manual procedure using `uefi.allowAuthBypass` and
a FAT32 VMDK. The script will detect ESXi 7.x hosts at step 9 and emit a warning
with instructions.

---

## Domain Controllers

**Do not include domain controllers in automated runs.**

`Invoke-VMScript` cannot run elevated commands on domain controllers due to UAC
restrictions in most environments. A separate step-by-step guide covering the
full DC procedure (including FSMO role management, replication verification, PDC
Emulator transfer, and manual PK enrollment) is provided in
`DC_SecureBoot_Manual_Steps.md`.

---

## Assessment Mode

The `-Assess` switch runs a read-only inventory pass against all target VMs. No changes are made. It produces a CSV and console summary covering:

- VM hardware version and whether it meets the version 21 minimum for KEK regeneration
- ESXi host name and version
- Firmware type (EFI vs BIOS) and Secure Boot enabled state
- Presence of `.nvram_old` file and `Pre-SecureBoot-Fix` snapshot (indicates a remediation is in progress or pending cleanup)
- Datastore name, free space, capacity, and estimated snapshot size per VM (see Datastore Space Check below)
- KEK 2023, DB 2023, and PK status (requires `-GuestCredential`)
- `UEFICA2023Status`, `AvailableUpdates`, and `UEFICA2023Error` registry values (requires `-GuestCredential`)
- TPM-WMI event IDs 1808, 1801, 1802, 1803, 1800, 1795 (requires `-GuestCredential`)
- BitLocker active state (requires `-GuestCredential`)
- Derived `ActionNeeded` column summarizing what steps remain per VM, including a `Insufficient datastore space` flag if the space check fails

If `-GuestCredential` is omitted, only hypervisor-level data is collected (hardware version, ESXi host, firmware, Secure Boot state, datastore files, snapshot presence, and datastore space). This is useful for a quick pre-remediation inventory without needing guest credentials.

```powershell
# Hypervisor-level data only
.\FixSecureBootBulk.ps1 -Assess

# Full assessment including guest cert and registry status
.\FixSecureBootBulk.ps1 -Assess -GuestCredential $cred

# Assess specific VMs
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -Assess -GuestCredential $cred
```

The assessment CSV is written to `SecureBoot_Assess_<timestamp>.csv` in the current directory.

### Datastore Space Check

Before displaying the confirmation prompt, the script checks the datastore for each target VM and estimates whether there is sufficient space for a snapshot. The same check runs during `-Assess` and is included in the assessment CSV output.

The estimate uses different logic depending on whether the VM already has snapshots:

**VM has existing snapshots**  -  the disks are already in delta-write mode. The estimate is derived from the actual on-disk size of existing delta files (`snapshotData` and `snapshotExtent` entries from `$vmView.LayoutEx.File`), divided by the number of existing snapshots to produce a per-snapshot average. This reflects real observed write activity on the VM rather than a theoretical maximum.

**VM has no existing snapshots**  -  committed disk bytes from `PerDatastoreUsage` are used as a conservative upper bound, since the snapshot could theoretically grow to the full size of the written disk.

**LayoutEx data unavailable**  -  a fixed 2 GB fallback is used. A dedicated yellow `NOTE:` line is printed whenever the fallback is active, regardless of whether a space warning also fires.

In all cases a 16 MB per-disk baseline floor is applied. VMware allocates one 16 MB delta file per virtual disk at snapshot creation time regardless of I/O activity, so no estimate is reported below `16 MB * virtual disk count`. The disk count and applied baseline are noted in the estimate basis string.

A warning is issued when:
- The estimated snapshot size exceeds 80% of the available free space on the datastore, or
- The datastore has less than 5 GB free regardless of estimate

Warnings are shown in the pre-run summary, in the `-Assess` console output, and in the `ActionNeeded` and `Notes` columns of both CSVs. The script does not block on a space warning - it is informational and the operator can still proceed.

The assessment CSV includes the following datastore columns: `Datastore`, `DSFreeGB`, `DSCapacityGB`, `SnapshotEstimateGB`, `DSSpaceOK`.

---

## Hardware Version Upgrade

Hardware version 21 or later is required for ESXi to populate regenerated NVRAM with the 2023 KEK certificate. VMs below version 21 will have NVRAM regenerated but the KEK will not be present afterward. The `-UpgradeHardware` switch automates the upgrade.

> **Important:** VMware does not provide a supported API or UI method to downgrade VM hardware versions. A snapshot taken before the upgrade is the only supported rollback path. Reverting to the pre-upgrade snapshot restores the previous hardware version. If `-NoSnapshot` is specified, there is no automated rollback path.

### Standalone (upgrade only, no cert work)

By default a `Pre-HWUpgrade_<timestamp>` snapshot is taken before each upgrade to serve as a rollback point. Use `-NoSnapshot` to skip this.

```powershell
# Upgrade all eligible VMs (snapshot taken by default)
.\FixSecureBootBulk.ps1 -UpgradeHardware

# Upgrade specific VMs
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardware

# Upgrade without taking a snapshot (no rollback path)
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardware -NoSnapshot
```

Each VM is powered off, upgraded to the latest hardware version supported by its host, and powered back on. VMs already at version 21 or later are skipped. Output is written to `SecureBoot_HWUpgrade_<timestamp>.csv`.

Once the upgrade is verified stable, remove the `Pre-HWUpgrade*` snapshots:

```powershell
# Remove all Pre-HWUpgrade* snapshots
.\FixSecureBootBulk.ps1 -CleanupHWSnapshots

# Remove Pre-HWUpgrade* snapshots for specific VMs
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -CleanupHWSnapshots
```

Output is written to `SecureBoot_Cleanup_<timestamp>.csv`.

### Combined with remediation

When `-UpgradeHardware` is used alongside `-GuestCredential`, the hardware upgrade is inserted as step 2b between power off and NVRAM rename in the main remediation sequence. The snapshot taken at step 1 covers the hardware upgrade as well, so no additional snapshot is needed. This handles everything in a single run.

```powershell
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -UpgradeHardware
```

---

## Manual Remediation (No Scripts)

For environments where PowerShell script execution is restricted by security
policy, a fully manual version of the remediation procedure is provided in
`SecureBoot_Manual_NoScript.md`.

This guide covers the complete process using only the vSphere Client GUI,
Registry Editor, and Task Scheduler, with individual typed commands where
PowerShell is needed. No `.ps1` files are required and no changes to execution
policy are needed.

It includes:
- Step-by-step vSphere Client instructions for all hypervisor operations
  (snapshot, NVRAM rename, SetupMode, datastore cleanup)
- Registry Editor and Task Scheduler instructions for the Windows-side update
- PK enrollment steps using individual PowerShell commands typed directly into
  an elevated console
- BitLocker guidance including recovery key backup and suspension
- Event Viewer instructions for confirming success via Event ID 1808
- A reference table of relevant Broadcom and Microsoft documentation
- A printable checklist

---

## Parallel Execution

For larger environments, multiple instances of the script can be run simultaneously in separate PowerShell processes to parallelize remediation across different sets of VMs. Each instance maintains its own vCenter session, and timestamped output CSVs and snapshot names mean there is no file-level collision between concurrent runs.

### How to split workloads

Target non-overlapping sets of VMs across instances. The cleanest split is by ESXi host, which keeps snapshot I/O and Tools wait pressure localized:

```powershell
# Terminal 1 - VMs on esxi01
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02","vm03" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm

# Terminal 2 - VMs on esxi02
.\FixSecureBootBulk.ps1 -VMName "vm04","vm05","vm06" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm

# Terminal 3 - VMs on esxi03
.\FixSecureBootBulk.ps1 -VMName "vm07","vm08","vm09" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm
```

Use `-Confirm` on all instances so no interactive prompts block unattended runs.

### Caveats

**Datastore space estimates may be stale across parallel instances.** The space check runs once at startup before any snapshots are taken. If two instances target VMs on the same datastore, both will read the same free space figure without accounting for what the other is about to consume. For datastores with one VM per datastore (a common vSphere convention) this is not an issue. For shared datastores, multiply the per-VM snapshot estimates and verify there is sufficient headroom before running parallel instances against the same datastore.

**ESXi host load.** Simultaneous power-off/power-on cycles on multiple VMs on the same host compound each other's boot time. If Tools wait timeouts are occurring, increase `-WaitSeconds` for parallel runs. Splitting batches by host avoids this entirely.

**vCenter API concurrency.** vCenter handles concurrent sessions without issue under normal loads. Very high concurrency (10+ simultaneous instances) could begin approaching vCenter API rate limits depending on your environment configuration. For most environments 2-4 parallel instances is well within bounds. If you observe `Invoke-VMScript` failures or vCenter connection errors under high concurrency, reduce the number of parallel instances.

**Do not target the same VM from multiple instances.** There is no inter-process locking. Two instances processing the same VM simultaneously will conflict on the snapshot name, NVRAM rename, and guest script execution. Always ensure each VM appears in exactly one instance's target list.

**Maintain separate output CSVs per instance.** Each instance writes its own timestamped CSV. Review all output files after the run to confirm all VMs completed successfully. There is no merged output across parallel instances.

---

## Troubleshooting

### VM shows `KEK_AfterNVRAM = False` after NVRAM regeneration

The NVRAM was renamed and regenerated, but the 2023 KEK certificate is not
present. This usually means the ESXi host is not on 8.0.2 or later. Check the
host version with `Get-VMHost | Select Name, Version` in PowerCLI. If the host
is on an older build, vMotion the VM to a qualifying host and retry.

### `AvailableUpdates` stuck at `0x4004`

The value `0x4004` indicates the KEK update bit (`0x0004`) failed. This is the
classic symptom of the NULL Platform Key issue. Confirm the NVRAM rename succeeded
by checking the datastore for the `.nvram_old` file. If the rename completed but
the value is still stuck after NVRAM regeneration, the host may not be on ESXi
8.0.2+.

### FinalStatus shows `InProgress` instead of `Updated`

The Secure Boot update task has not completed all steps yet. The task runs on a
12-hour poll cycle. Trigger it manually from an elevated PowerShell session on
the VM:

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Start-Sleep -Seconds 30
Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates"
```

If `AvailableUpdates` is `0x4000` after triggering the task, the update is
complete - a second reboot may be required for `UEFICA2023Status` to flip
to `Updated`.

### PK enrollment failed - `PKEnrolled: False`

If step 9 completes but `PKEnrolled` is `False`, the most likely cause is UAC
preventing `Invoke-VMScript` from running the enrollment in an elevated context.
The `.der` file will have been copied to `C:\Windows\Temp\WindowsOEMDevicesPK.der`
on the guest. RDP or console into the VM and run from an elevated PowerShell
session while the VM is still in SetupMode:

```powershell
Format-SecureBootUEFI -Name PK `
    -CertificateFilePath "C:\Windows\Temp\WindowsOEMDevicesPK.der" `
    -SignatureOwner "55555555-0000-0000-0000-000000000000" `
    -FormatWithCert `
    -Time "2025-10-23T11:00:00Z" |
Set-SecureBootUEFI -Time "2025-10-23T11:00:00Z"
```

If you have already rebooted past the SetupMode window, re-run the script - it
will detect `Valid_Other` again and retry the full step 9 sequence.

### PK still shows `Valid_Other` after enrollment

A reboot is required for the enrolled PK to take effect. If `Valid_Other`
persists after reboot, verify that SetupMode was active during enrollment by
checking whether `Get-SecureBootUEFI SetupMode` returned `1` at the time the
enrollment script ran.

### Tools timeout errors

If the script times out waiting for VMware Tools after a reboot, the VM is likely
just slow to boot. The snapshot is retained automatically in this case. You can
re-run the script against the VM after it comes back up - it will detect the
existing `.nvram_old` file and skip the rename step if the NVRAM has already been
regenerated, or you can complete the registry steps manually using the verification
commands in the [Verification](#verification) section above.

Increase the Tools wait timeout with `-WaitSeconds`:

```powershell
.\FixSecureBootBulk.ps1 -VMName "slow-vm" -GuestCredential $cred -WaitSeconds 180
```

This applies to any reboot in the sequence, but is most commonly encountered at
step `[PK 2/5]` where the VM reboots into SetupMode for PK enrollment. If your
VM boots slowly, Tools may not come up within the default 90 seconds. The script
will report "VM is back online" once Tools responds - if this takes longer than
`-WaitSeconds`, the script moves on before the guest is fully ready and the
subsequent `Copy-VMGuestFile` at `[PK 3/5]` fails with a guest OS or file copy
error. If you see cert update steps 1-7 complete successfully but `[PK 3/5]`
fails with a guest operation error, a slow boot at the SetupMode reboot is the
most likely cause. Increasing `-WaitSeconds` to 120-180 resolves this.

### VMware Tools not installed or not running

`Invoke-VMScript` will fail immediately if VMware Tools is not installed, not
running, or in an unmanaged state. Check Tools status on a specific VM:

```powershell
(Get-VM "vm01").Guest.ExtensionData.ToolsStatus
# Expected: toolsOk
# Problem states: toolsNotInstalled, toolsNotRunning, toolsOld
```

If Tools is installed but not running, start it from an elevated command prompt
on the guest:

```cmd
net start "VMware Tools"
```

If Tools is not installed, deploy it via vSphere Client (**VM -> Guest OS ->
Install VMware Tools**) or through your software deployment tooling before
running the script. After installation a reboot is required.

### BitLocker recovery after Secure Boot update

Per [KB5085046](https://support.microsoft.com/en-us/kb/5085046), there are two BitLocker recovery scenarios related to Secure Boot updates:

**One-time recovery on first boot after update**  -  the VM enters BitLocker recovery once but boots normally on subsequent restarts. This happens because firmware does not immediately report updated Secure Boot values when Windows attempts to reseal BitLocker. Enter the recovery key to resume. Subsequent boots will not prompt recovery.

**Repeated recovery due to PXE first boot**  -  if the VM is configured to attempt PXE boot before the local disk, BitLocker will enter recovery on every boot. This occurs because the PXE boot path is signed by the Microsoft UEFI CA 2011 while the on-disk Windows boot manager is now signed by the Windows UEFI CA 2023. BitLocker observes two different signing authorities during startup and cannot establish stable TPM measurements to reseal against.

To resolve repeated PXE recovery: configure the firmware boot order so the local Windows boot manager boots first, or disable PXE if it is not required. If PXE is required, ensure the PXE infrastructure uses a 2023-signed Windows boot loader.

### Snapshot creation fails

Check available datastore space. Each snapshot consumes space proportional to the
amount of disk I/O that occurs while it exists. If space is constrained, use
`-NoSnapshot` and ensure you have an alternative rollback method (e.g., a storage
array snapshot or backup taken immediately before running the script).

---

## License

MIT License. See `LICENSE` for details.
