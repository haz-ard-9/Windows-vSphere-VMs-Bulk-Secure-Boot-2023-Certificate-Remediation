# FixSecureBootBulk.ps1

A PowerShell script for bulk remediating the Microsoft Secure Boot 2023 certificate
issue on Windows Server VMs running in VMware vSphere 8.

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

**References:**
- [Microsoft KB5068202](https://support.microsoft.com/help/5068202) - AvailableUpdates registry key and monitoring
- [Microsoft KB5068198](https://support.microsoft.com/help/5068198) - Group Policy deployment (requires Windows Server 2025 ADMX templates)
- [Broadcom KB 421593](https://knowledge.broadcom.com/external/article/421593) - VMware Platform Key issue
- [Broadcom KB 423919](https://knowledge.broadcom.com/external/article/423919) - Manual Secure Boot variable update procedure

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
- VMs below version 13 will be silently excluded by the EFI/Secure Boot filter and will not appear in the target list
- Check hardware versions:
  ```powershell
  Get-VM | Select Name, HardwareVersion | Sort-Object HardwareVersion
  ```
- Upgrade VM hardware version in vSphere Client (VM must be powered off):
  **Actions → Compatibility → Upgrade VM Compatibility**

### VMware Tools
- **VMware Tools must be installed, running, and recognized by vCenter** on all target VMs
  - The script uses `Invoke-VMScript` for all guest operations; vCenter will reject these calls if Tools is not running
  - Tools version **10.0 or later** recommended - older versions may not support all script execution features
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
- **Windows 10, Windows 11, and Windows Server 2016, 2019, or 2022**
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

Suppress the Customer Experience Improvement Program prompt and allow
connections to vCenter servers with self-signed certificates:

```powershell
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false
Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope User -Confirm:$false
```

> The script calls `Set-PowerCLIConfiguration -InvalidCertificateAction Ignore`
> automatically on first run, so this step is optional but useful if you want
> to suppress the warning permanently.

---

## Configuration

Before running the script, open `FixSecureBootBulk.ps1` in a text editor and
update the vCenter server address on this line:

```powershell
Connect-VIServer -Server "vcenter.yourdomain.com" ...
```

Replace `vcenter.yourdomain.com` with the hostname or IP address of your vCenter instance.

Alternatively, you can pre-connect to vCenter before running the script and it
will use the existing session:

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

> **Note:** Broadcom KB 423919 references a file called `PK_SigListContent.bin`
> which does not exist in the Microsoft repository. `WindowsOEMDevicesPK.der`
> is the correct file for ESXi 8.x SetupMode enrollment. The script converts it
> from DER certificate format to EFI Signature List format internally using
> `Format-SecureBootUEFI` - no manual conversion is required.

---

## Usage

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
| `-VMName` | `string[]` | One or more VM display names. Accepts wildcards. |
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

---

## Process Flow

For each VM in the main remediation mode, the script performs the following steps:

```
[0/9] BitLocker / vTPM safety check
      Without -BitLockerBackupShare: skip VM if BitLocker active
      With    -BitLockerBackupShare: export recovery keys to share,
              suspend BitLocker (RebootCount 2), then proceed
[1/9] Take snapshot (skipped if -NoSnapshot)
[2/9] Power off VM
[3/9] Rename vmname.nvram -> vmname.nvram_old on datastore
[4/9] Power on VM (ESXi regenerates NVRAM with 2023 KEK/DB certs)
      └─ Verify KEK 2023 and DB 2023 are present in new NVRAM
[5/9] Clear stale Servicing registry state (if any)
      Set AvailableUpdates = 0x5944 via SYSTEM scheduled task
      Trigger \Microsoft\Windows\PI\Secure-Boot-Update task
[6/9] Reboot VM
      Trigger Secure-Boot-Update task again (completes Boot Manager update)
[7/9] Verify: Servicing Status = "Updated", KEK 2023 = True, DB 2023 = True
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
| `0x4100` | KEK/DB certs applied, Boot Manager update pending (after first task run + reboot) |
| `0x4000` | Fully complete |

### Verification

Final status is read from:
- `UEFICA2023Status` under `HKLM:\...\SecureBoot\Servicing` - expected value: `Updated`
- `Get-SecureBootUEFI kek` - must contain `Microsoft Corporation KEK 2K CA 2023`
- `Get-SecureBootUEFI db` - must contain `Windows UEFI CA 2023`
- `Get-SecureBootUEFI PK` - expected `Valid_WindowsOEM` after PK enrollment

---

## Snapshot and Cleanup Workflow

The recommended workflow when processing VMs in batches is:

```
1. Run fix with -RetainSnapshots
   .\FixSecureBootBulk.ps1 -VMListCsv .\batch1.csv -GuestCredential $cred `
       -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

2. Validate VMs over several days (check application health, event logs, etc.)

3. Remove snapshots once satisfied
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv -CleanupSnapshots

4. Remove .nvram_old files (AFTER snapshots are gone)
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv -CleanupNvram
```

> **Important:** Always run `-CleanupSnapshots` before `-CleanupNvram`. The snapshot
> is the rollback mechanism - removing the `.nvram_old` file before the snapshot is
> gone leaves you without a recovery path.

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
| Snapshot cleanup | `SecureBoot_SnapshotCleanup_<timestamp>.csv` |
| NVRAM cleanup | `SecureBoot_NvramCleanup_<timestamp>.csv` |
| Rollback | `SecureBoot_Rollback_<timestamp>.csv` |

The main remediation CSV includes these columns:

`VMName`, `SnapshotCreated`, `BitLockerKeysBacked`, `BitLockerSuspended`,
`NVRAMRenamed`, `KEK_AfterNVRAM`, `DB_AfterNVRAM`, `UpdateTriggered`, `KEK_2023`,
`DB_2023`, `FinalStatus`, `PK_Status`, `PKEnrolled`, `PKRemediated`,
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

### PK enrollment method (ESXi 8.x)

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

### ESXi 7.x (not supported by this script)

For ESXi 7.x hosts, PK enrollment requires a different procedure: a FAT32 VMDK
containing `WindowsOEMDevicesPK.der` attached to the VM, and manual navigation
of the UEFI setup UI. This script detects ESXi 7.x hosts at step 9 and emits a
warning with instructions, but cannot automate this path. See Broadcom KB 423919
for the full manual procedure.

---

## Domain Controllers

**Do not include domain controllers in automated runs.**

`Invoke-VMScript` cannot run elevated commands on domain controllers due to UAC
restrictions in most environments. A separate step-by-step guide covering the
full DC procedure (including FSMO role management, replication verification, PDC
Emulator transfer, and manual PK enrollment) is provided in
`DC_SecureBoot_Manual_Steps.md`.

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

### Snapshot creation fails

Check available datastore space. Each snapshot consumes space proportional to the
amount of disk I/O that occurs while it exists. If space is constrained, use
`-NoSnapshot` and ensure you have an alternative rollback method (e.g., a storage
array snapshot or backup taken immediately before running the script).

---

## License

MIT License. See `LICENSE` for details.
