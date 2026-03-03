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
fix is to delete the VM's NVRAM file and let ESXi regenerate it — ESXi 8.0.2 and
later automatically populate the new NVRAM with the 2023 certificates. Windows can
then detect and install them without requiring manual firmware enrollment.

**References:**
- [Microsoft KB5068202](https://support.microsoft.com/help/5068202) — AvailableUpdates registry key and monitoring
- [Microsoft KB5068198](https://support.microsoft.com/help/5068198) — Group Policy deployment (requires Windows Server 2025 ADMX templates)
- [Broadcom KB 421593](https://knowledge.broadcom.com/external/article/421593) — VMware Platform Key issue
- [Broadcom KB 423919](https://knowledge.broadcom.com/external/article/423919) — NVRAM regeneration workaround

---

## Requirements

### VMware Infrastructure
- **ESXi 8.0.2 or later** on all hosts where target VMs are running
  - Earlier ESXi versions will not regenerate NVRAM with 2023 certificates
- **vCenter Server** — the script connects via the PowerCLI vCenter API
- **VMware Tools** installed and running on all target VMs

### Guest OS
- **Windows Server 2016, 2019, or 2022**
- VMs must be configured with **EFI firmware** and **Secure Boot enabled** at the hypervisor level
- Domain, Server, or Local admin credentials with rights to run scheduled tasks and modify HKLM registry keys on the specified Windows VMs

### PowerShell & Modules
- **PowerShell 5.1 or later** (Windows) or **PowerShell 7+** (cross-platform)
- **VMware PowerCLI** module (see [Installing PowerCLI](#installing-powercli) below)

---

## Installing PowerCLI

PowerCLI is VMware's PowerShell module for managing vSphere infrastructure.
It must be installed on the machine you run this script from — it does not need
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

You can also combine `-VMName` and `-VMListCsv` — they are merged and deduplicated:

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
| `-GuestCredential` | `PSCredential` | Domain admin credential for guest OS access. Required for main mode. |
| `-NoSnapshot` | `switch` | Skip snapshot creation. Cannot be combined with `-RetainSnapshots`. |
| `-RetainSnapshots` | `switch` | Keep snapshots even on success. Use with `-CleanupSnapshots` later. |
| `-CleanupSnapshots` | `switch` | Remove all `Pre-SecureBoot-Fix*` snapshots on target VMs. |
| `-CleanupNvram` | `switch` | Delete all `.nvram_old` files left on target VM datastores. |
| `-Rollback` | `switch` | Restore original NVRAM and revert to snapshot for target VMs. |
| `-WaitSeconds` | `int` | Seconds to wait after reboot before polling for VMware Tools. Default: `90`. |

---

## Process Flow

For each VM in the main remediation mode, the script performs the following steps:

```
[0/7] BitLocker / vTPM safety check
[1/7] Take snapshot (skipped if -NoSnapshot)
[2/7] Power off VM
[3/7] Rename vmname.nvram -> vmname.nvram_old on datastore
[4/7] Power on VM (ESXi regenerates NVRAM with 2023 KEK/DB certs)
      └─ Verify KEK 2023 and DB 2023 are present in new NVRAM
[5/7] Clear stale Servicing registry state (if any)
      Set AvailableUpdates = 0x5944 via SYSTEM scheduled task
      Trigger \Microsoft\Windows\PI\Secure-Boot-Update task
[6/7] Reboot VM
      Trigger Secure-Boot-Update task again (completes Boot Manager update)
[7/7] Verify: Servicing Status = "Updated", KEK 2023 = True, DB 2023 = True
      Remove snapshot on success (unless -RetainSnapshots or -NoSnapshot)
```

### Registry key progression

The `AvailableUpdates` value under `HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot`
tracks progress. Bits clear as each step completes:

| Value | Meaning |
|-------|---------|
| `0x5944` | Starting state — all update steps needed |
| `0x4100` | KEK/DB certs applied, Boot Manager update pending (after first task run + reboot) |
| `0x4000` | Fully complete |

### Verification

Final status is read from:
- `UEFICA2023Status` under `HKLM:\...\SecureBoot\Servicing` — expected value: `Updated`
- `Get-SecureBootUEFI kek` — must contain `Microsoft Corporation KEK 2K CA 2023`
- `Get-SecureBootUEFI db` — must contain `Windows UEFI CA 2023`

---

## Snapshot and Cleanup Workflow

The recommended workflow when processing VMs in batches is:

```
1. Run fix with -RetainSnapshots
   .\FixSecureBootBulk.ps1 -VMListCsv .\batch1.csv -GuestCredential $cred -RetainSnapshots

2. Validate VMs over several days (check application health, event logs, etc.)

3. Remove snapshots once satisfied
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv -CleanupSnapshots

4. Remove .nvram_old files (AFTER snapshots are gone)
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv -CleanupNvram
```

> **Important:** Always run `-CleanupSnapshots` before `-CleanupNvram`. The snapshot
> is the rollback mechanism — removing the `.nvram_old` file before the snapshot is
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

`VMName`, `SnapshotCreated`, `BitLockerSkipped`, `NVRAMRenamed`, `KEK_AfterNVRAM`,
`DB_AfterNVRAM`, `UpdateTriggered`, `KEK_2023`, `DB_2023`, `FinalStatus`,
`SnapshotRetained`, `Notes`

---

## BitLocker Warning

The script automatically checks for active BitLocker encryption before processing
each VM. **Any VM with BitLocker active will be skipped** with a warning. This is
intentional — modifying Secure Boot variables changes PCR 7 measurements and can
trigger BitLocker recovery mode on the next boot.

To process a BitLocker-protected VM:
1. Suspend BitLocker protection: `Suspend-BitLocker -MountPoint "C:" -RebootCount 2`
2. Re-run the script against that VM
3. BitLocker will automatically resume after the required reboots

---

## Domain Controllers

**Domain controllers in automated runs.**

I ran into an issue with domain controllers because `Invoke-VMScript` could not run
elevated commands due to UAC in my environment. A separate step-by-step guide covering the full DC
procedure (including FSMO role management, replication verification, and PDC
Emulator transfer) is provided in `DC_SecureBoot_Manual_Steps.md`. You are welcome to try running this on domain controllers in your environment but your mileage may vary.

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
complete — a second reboot may be required for `UEFICA2023Status` to flip
to `Updated`.

### Tools timeout errors

If the script times out waiting for VMware Tools after a reboot, the VM is likely
just slow to boot. The snapshot is retained automatically in this case. You can
re-run the script against the VM after it comes back up — it will detect the
existing `.nvram_old` file and skip the rename step if the NVRAM has already been
regenerated, or you can complete the registry steps manually using the verification
commands in the [Verification](#verification) section above.

Increase the Tools wait timeout with `-WaitSeconds`:

```powershell
.\FixSecureBootBulk.ps1 -VMName "slow-vm" -GuestCredential $cred -WaitSeconds 180
```

### Snapshot creation fails

Check available datastore space. Each snapshot consumes space proportional to the
amount of disk I/O that occurs while it exists. If space is constrained, use
`-NoSnapshot` and ensure you have an alternative rollback method (e.g., a storage
array snapshot or backup taken immediately before running the script).

---

## License

MIT License. See `LICENSE` for details.
