# FixSecureBootBulk.ps1

A PowerShell tool for **assessing and remediating** the Microsoft Secure Boot
2023 certificate issue on Windows Server VMs running in VMware vSphere 8.
Supports Windows Server 2016, 2019, 2022, and 2025, as well as Windows 10 and 11.

The tool provides assessment/inventory, the Microsoft certificate deployment
trigger, PK enrollment, hardware-version upgrade, BitLocker handling, and an
NVRAM-rename remediation path. The NVRAM rename is **not endorsed by VMware
engineering** (see notice below). Where a Broadcom-supported path is available
for your environment, prefer it. This tool is best used as an assessment and
orchestration aid, with NVRAM rename reserved as a field-tested fallback applied
with explicit risk acceptance, snapshots retained, and pilot validation.

---

> ## <span style="color:red">Important notice regarding support status</span>
>
> This script uses the NVRAM rename strategy to resolve 2023 certificate availability in VM UEFI firmware. The approach works by renaming the VM's existing `.nvram` file so that ESXi regenerates it fresh with the updated certificates on next boot.
>
> Broadcom previously documented this method in KB 421593. That KB has since been removed. **A Broadcom employee has stated in the [Broadcom community forums](https://community.broadcom.com/vmware-cloud-foundation/discussion/uefi-2023-fully-automated-script-also-with-plattform-key-change) that deleting or renaming the NVRAM file is not endorsed by VMware engineering and not supported.** Subsequently, [KB 423919](https://knowledge.broadcom.com/external/article/423919/manual-update-of-secure-boot-variables-i.html) was updated to explicitly state that it replaces KB 421593 specifically **"to avoid suggestions of deleting NVRAM, as that behavior can lead to unexpected corruptions of the associated VM."** The archived version of KB 421593 is linked in the References section below for historical reference only.
>
> **ESXi 8.0 P09 (released May 27, 2026 as part of ESXi 8.0 Update 3j) now delivers a supported official solution for vTPM-disabled VMs.** On patched hosts, a simple guest OS reboot automatically updates the PK with no NVRAM rename or manual intervention required. For vTPM-enabled **Linux/non-Windows** VMs, the `uefi.secureBoot.PK.resetOnce` VMX parameter is the Broadcom-documented path. For vTPM-enabled **Windows** VMs, Broadcom currently recommends waiting for the forthcoming capsule-based automated solution rather than using the VMX method (this script skips them by default). See [Broadcom KB 423893](https://knowledge.broadcom.com/external/article/423893) for full details. If your hosts are already on 8.0 P09 or later, consider following Broadcom's official guidance directly. If you do use this script on P09+ hosts and supply guest credentials, the smart pre-check can verify whether the 2023 KEK is already present in NVRAM and skips the rename for that VM, so there is no unnecessary rename on VMs already remediated via the official path. In no-credential hypervisor-only mode the script cannot inspect guest certificate state, so use `-SkipNVRAMRename` for any VM you know was already remediated through the official P09 path.
>
> This method has been tested and works reliably on ESXi 8.0.2 and later with hardware version 21 VMs. No issues have been encountered by myself or the community that has used this script in practice. However, given the official unsupported position from Broadcom and the explicit corruption warning in KB 423919, use this script with your own judgment and at your own risk.
>
> If you encounter issues, the script includes rollback options (`-Rollback`) that restore the original NVRAM file and revert to the pre-remediation snapshot. Retaining snapshots during remediation runs (`-RetainSnapshots`) is strongly recommended until you have validated the results. Users who wish to use the script's other capabilities (BitLocker backup, hardware version upgrade, cert update triggering, PK enrollment) without performing the NVRAM rename can use the `-SkipNVRAMRename` parameter.

---

## Recommended Approach

Choose the remediation path based on your environment. Prefer the highest
supported option that applies. Use the NVRAM rename only as a fallback. To have
the script enforce this automatically, pass `-SupportedMethodsOnly`, which keeps
the supported PK paths it automates (the P09 silent update on vTPM-disabled
Windows VMs, which is Broadcom's official path, and the script's SetupMode
automation, which reaches the same end state as the manual KB 423919 method) and
refuses the NVRAM regeneration entirely, reporting any VM that would need it with
`FinalStatus = NeedsOSNativeUpdate` instead. The `resetOnce` VMX path is
Broadcom-documented for Linux and other non-Windows VMs but is not automated by
this script.

1. **Assess first.** Run `-Assess` (read-only) to inventory every VM's firmware
   type, hardware version, ESXi build, cert status, PK status, and BitLocker
   state. This tells you which VMs need anything and which path fits each one.
2. **Supported Broadcom path where available.**
   - ESXi 8.0 U3j/P09+ hosts, **vTPM-disabled** VMs: patch the host, reboot the
     VM, and let the silent PK update apply. No NVRAM rename.
   - ESXi 8.0 U3j/P09+ hosts, **vTPM-enabled Linux/non-Windows** VMs: use the
     `uefi.secureBoot.PK.resetOnce` VMX parameter with encryption/TPM precautions.
   - ESXi 8.0 U3j/P09+ hosts, **vTPM-enabled Windows** VMs: assess and monitor.
     Broadcom currently recommends waiting for the forthcoming automated solution
     unless you have an approved exception.
3. **Microsoft certificate deployment.** Where the 2023 certs are already present
   in NVRAM (VMs created on ESXi 8.0.2+ or already remediated), use this tool with
   `-SkipNVRAMRename`, or use GPO/Intune/Windows Update, to set
   `AvailableUpdates = 0x5944` and trigger the Secure-Boot-Update task, then
   monitor `UEFICA2023Status`, `UEFICA2023Error`, `AvailableUpdates`, and the
   TPM-WMI events.
4. **Manual Broadcom PK remediation** (KB 423919) for VMs that need PK enrollment
   outside the automated paths.
5. **NVRAM rename (unsupported fallback).** Use only for pre-P09 VMs still missing
   the 2023 certs where the supported paths do not apply, and only with explicit
   risk acceptance: take and retain a snapshot, back up BitLocker recovery keys,
   pilot on a small batch first, keep the old NVRAM plus snapshot until
   application and event-log validation is complete, and avoid domain controllers
   (use the dedicated DC guide). This path is field-tested and has worked reliably
   on ESXi 8.0.2+ with HW21 VMs, but it is not endorsed by VMware engineering and
   carries a documented corruption risk per KB 423919.

This tool can drive the assessment, Windows guest-side certificate deployment, script-supported PK enrollment, hardware upgrade, cleanup, rollback, and fallback NVRAM-rename workflows. For Linux/non-Windows PK remediation and Broadcom's manual UI procedures, use the tool for assessment or hypervisor-only preparation where appropriate, then complete the OS-specific and vendor-specific steps outside the script. It is most valuable as the assessment and orchestration layer rather than as a one-shot bulk NVRAM fix.

---

## Background

Microsoft's original Secure Boot certificates (issued in 2011) begin expiring in
June 2026. The exact expiration dates, per
[Microsoft KB 5062710](https://support.microsoft.com/en-us/help/5062710)
(updated May 18, 2026), are:

| Expiring 2011 certificate | Expiration date | Replacement 2023 certificate | Store |
|---|---|---|---|
| Microsoft Corporation KEK CA 2011 | June 24, 2026 | Microsoft Corporation KEK 2K CA 2023 | KEK |
| Microsoft UEFI CA 2011 | June 27, 2026 | Microsoft UEFI CA 2023 | DB |
| Microsoft UEFI CA 2011 | June 27, 2026 | Microsoft Option ROM UEFI CA 2023 | DB |
| Microsoft Windows Production PCA 2011 | October 19, 2026 | Windows UEFI CA 2023 | DB |

The KEK CA 2011 expiration (June 24, 2026) is the near-term driver for this
remediation: that is the certificate that signs DB and DBX updates, and the 2023
KEK must be in place before it expires for future Secure Boot updates to validate.

After the expiry dates, VMs continue to boot normally. Secure Boot verification does
not check certificate expiration. Per Microsoft, devices that have not received the
2023 certificates keep starting and operating normally and continue to install
standard Windows updates, but can no longer receive new protections for the early
boot process, including updates to Windows Boot Manager, the Secure Boot databases,
revocation lists, or mitigations for newly discovered boot-level vulnerabilities.
The practical impact is on future certificate updates: new DB and DBX update payloads
signed solely by the 2023 KEK will fail on VMs still missing the 2023 KEK, and
OS-driven KEK updates will fail on any VM without a valid Platform Key (PK). Existing
payloads signed during the 2011 certificates' valid period continue to work
regardless of expiry.

VMs created before ESXi 8.0.2 have a NULL Platform Key (PK) signature in their
NVRAM that prevents the standard certificate enrollment process from working.
Historically, one field-tested workaround was to rename or remove the VM's NVRAM
file so ESXi regenerated it: ESXi 8.0.2 and later populate the regenerated NVRAM
with the 2023 certificates, after which Windows can detect and install them
without manual firmware enrollment. That NVRAM rename path is no longer the
preferred or vendor-endorsed remediation (see the support notice and Recommended
Approach above). Broadcom KB 423919 specifically replaced the earlier
NVRAM-deletion guidance to avoid recommending NVRAM deletion, which can cause
unexpected VM corruption. Use the supported Broadcom and Microsoft paths where
they apply, and reserve NVRAM rename as an unsupported fallback with rollback
controls.

Per [Broadcom KB 423893](https://knowledge.broadcom.com/external/article/423893), after the June 2026 expiry VMs will continue to boot normally since Secure Boot verification does not check certificate expiration. The practical impact is that new DB and DBX update payloads signed solely by the 2023 KEK will fail on VMs that are still missing the 2023 KEK, and OS-driven KEK updates will fail on any VM without a valid PK. Existing payloads signed during the 2011 certificates' valid period continue to work regardless of expiry.

**ESXi 8.0 P09 (ESXi 8.0 Update 3j, released May 27, 2026):** Broadcom has released the first official automated PK remediation solution. On hosts running 8.0 P09 or later:

- **vTPM-disabled VMs:** The PK is updated automatically during a guest OS reboot. No NVRAM rename or manual steps required. Simply patch your ESXi hosts to 8.0 P09 and reboot the VMs.
- **vTPM-enabled Linux/non-Windows VMs:** Use the `uefi.secureBoot.PK.resetOnce = TRUE` VMX advanced parameter while the VM is powered off, then power it on. This is the Broadcom-documented path for non-Windows VMs (KB 423893).
- **vTPM-enabled Windows VMs:** Broadcom currently recommends **waiting for the forthcoming capsule-based automated solution** rather than using the VMX `resetOnce` method. Changing the PK from outside the guest OS alters TPM PCR7 measurements and can trigger BitLocker recovery or break TPM-sealed secrets (DPAPI, Credential Guard). This script skips Windows vTPM-enabled VMs for PK remediation by default. Override only with `-AllowUnsupportedVTPMWindowsPKRemediation`, and only if you understand the risk and have either confirmed BitLocker is inactive or backed up recovery keys and successfully re-suspended protection.
- **Newly created VMs on 8.0 P09+:** Will receive the `WindowsOEMDevicesPK` automatically.

When `-PKDerPath` is provided, the script selects the appropriate PK enrollment path per Windows VM based on host version, vTPM status, and BitLocker state:

- P09+ host, no vTPM: guest OS reboot (official silent path). When BitLocker is active it is suspended before the reboot and resumed after, since a vTPM-disabled volume has no PCR seal and the PK change cannot trigger recovery. This requires `-BitLockerBackupShare`. If the suspension cannot be confirmed the VM falls through to the SetupMode fallback rather than rebooting.
- P09+ host, vTPM present, **Windows or unknown-risk guest**: skipped by default (Broadcom recommends waiting for the capsule-based solution). `-AllowUnsupportedVTPMWindowsPKRemediation` overrides to the resetOnce-then-SetupMode path
- P09+ host, vTPM present, BitLocker active: resetOnce is skipped to avoid a PCR7 change without guest OS awareness. Windows/unknown-risk vTPM VMs are skipped by default. SetupMode is attempted only with `-AllowUnsupportedVTPMWindowsPKRemediation` and only after BitLocker re-backup and re-suspension succeed
- Pre-P09 host, or P09 path does not produce a valid PK: SetupMode enrollment fallback (Windows/unknown-risk vTPM VMs still skipped by default)

**Linux/non-Windows VMs:** the script does not perform Linux guest-side PK verification or enrollment. The `uefi.secureBoot.PK.resetOnce` VMX method is Broadcom's documented path for Linux/non-Windows vTPM-enabled VMs (KB 423893), but this script does not automate it. A known Linux guest is skipped (`Skipped_NonWindowsGuest`) unless `-AllowNonWindowsTargets` is supplied, which runs hypervisor-only steps (snapshot, hardware upgrade, NVRAM rename) and leaves PK remediation to be completed via Broadcom or OS-vendor guidance. Use `-Assess` to identify candidates.

If your hosts are already on 8.0 P09 or later, the NVRAM rename performed by this script may not be necessary. For Windows VMs where the script-supported PK path applies, consider using `-SkipNVRAMRename` with `-PKDerPath` to trigger the cert update and PK enrollment without renaming the NVRAM file. For vTPM-enabled Windows VMs, Broadcom currently recommends waiting for the capsule-based solution unless you explicitly opt into the unsupported override (`-AllowUnsupportedVTPMWindowsPKRemediation`). For Linux/non-Windows VMs, follow Broadcom KB 423893 or OS-vendor guidance for PK remediation, or follow Broadcom's official guidance directly.

**Platform Key (PK) note:** On ESXi 8.x builds prior to P09, NVRAM regeneration writes a placeholder PK (`VMW.NULLPK`) rather than a proper Microsoft-signed key. This placeholder PK will not authenticate future Windows Update KEK changes. Per [KB 423893](https://knowledge.broadcom.com/external/article/423893), PK enrollment requires **hardware version 14 or later**. Hardware version 21 is required for NVRAM regeneration to include the 2023 KEK and DB certificates. VMs on version 13 must be upgraded to at least 14 before PK enrollment is possible, and to 21 before NVRAM regeneration will include the 2023 certs.


---

**References:**
- [Microsoft KB5068202](https://support.microsoft.com/help/5068202) - AvailableUpdates registry key and monitoring
- [Microsoft KB5068198](https://support.microsoft.com/help/5068198) - Group Policy deployment (requires Windows Server 2025 ADMX templates)
- [Microsoft KB5085046](https://support.microsoft.com/en-us/kb/5085046) - Secure Boot troubleshooting guide - AvailableUpdates bit progression, event IDs, and failure scenarios (published March 2026)
- [Broadcom KB 423893](https://knowledge.broadcom.com/external/article/423893) - Secure Boot Certificate Expirations and Update Failures in VMware Virtual Machines - includes FAQ on affected VMs, post-expiry impact, PK update methods, and planned automated remediation paths
- [Broadcom KB 421593](https://web.archive.org/web/20260212085158/https://knowledge.broadcom.com/external/article/421593/missing-microsoft-corporation-kek-ca-202.html) - NVRAM rename procedure for missing KEK CA 2023 on Windows VMs *(Broadcom has removed this KB, link points to archive.org)*
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
- **Hardware version 14 or later** - required for vTPM (relevant to the BitLocker safety check) and required for PK enrollment per [KB 423893](https://knowledge.broadcom.com/external/article/423893). VMs on version 13 must be upgraded to at least 14 before the `-PKDerPath` PK enrollment step will work
- **Hardware version 21 or later** - required for ESXi to populate regenerated NVRAM with the 2023 KEK certificate. VMs on version 13-20 will have NVRAM regenerated but the KEK will not be present afterward. Upgrade hardware version before running the script on these VMs
- VMs below version 13 will be silently excluded by the EFI/Secure Boot filter and will not appear in the target list
- Check hardware versions:
  ```powershell
  Get-VM | Select Name, HardwareVersion | Sort-Object HardwareVersion
  ```
- The script can upgrade hardware version automatically. Use `-UpgradeHardwareOnly` for a standalone hardware-only upgrade run, or `-UpgradeHardware` to add the upgrade as step 2b inside a full remediation run. See [Hardware Version Upgrade](#hardware-version-upgrade).
- To upgrade manually via vSphere Client (VM must be powered off): **Actions → Compatibility → Upgrade VM Compatibility**

### VMware Tools
- **VMware Tools must be installed, running, and recognized by vCenter** on all target VMs
  - The script uses `Invoke-VMScript` for all guest operations. vCenter will reject these calls if Tools is not running
  - Tools should be current with the ESXi host version. There is no fixed minimum version number. The "out of date" warning from vCenter is a relative comparison between the version installed in the guest and the version bundled with the ESXi host the VM is running on. Outdated Tools will appear in yellow in the console output and can cause `Invoke-VMScript` to fail silently with ExitCode 1 and no output. The script displays the installed Tools version and status for every VM at the start of each run so you can identify which VMs need an update before proceeding.
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
- **VMware PowerCLI** module (`VCF.PowerCLI` for new installs, `VMware.PowerCLI` for existing installations) (see [Installing PowerCLI](#installing-powercli) below)

---

## Installing PowerCLI

PowerCLI is VMware's PowerShell module for managing vSphere infrastructure.
It must be installed on the machine you run this script from - it does not need
to be installed on the VMs themselves.

There are currently two module names available depending on your version. `VMware.PowerCLI` is the traditional module and will produce a deprecation warning on newer installations. `VCF.PowerCLI` is the current replacement and offers performance improvements. Both provide the same functionality needed by this script. If you are doing a fresh install, `VCF.PowerCLI` is recommended. If you already have `VMware.PowerCLI` installed and it is working, there is no requirement to switch.

### Install from the PowerShell Gallery (recommended)

Open PowerShell as Administrator and run:

```powershell
# Current module (recommended for new installs)
Install-Module -Name VCF.PowerCLI -Scope CurrentUser

# Legacy module (still functional, deprecation warning may appear)
Install-Module -Name VMware.PowerCLI -Scope CurrentUser
```

If prompted about an untrusted repository, type `Y` to confirm.

To install for all users on the machine instead:

```powershell
Install-Module -Name VCF.PowerCLI -Scope AllUsers
```

### Verify the installation

```powershell
# If using VCF.PowerCLI
Get-Module -Name VCF.PowerCLI -ListAvailable

# If using VMware.PowerCLI
Get-Module -Name VMware.PowerCLI -ListAvailable
```

### Update an existing installation

```powershell
Update-Module -Name VCF.PowerCLI
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

### DER integrity verification

The PK DER is downloaded independently of this script, so it is the one input the
script cannot implicitly trust. A tampered or substituted PK certificate enrolled
into firmware would be a serious compromise. To guard against this, the script
verifies the file you pass to `-PKDerPath` against the known SHA-256 of Microsoft's
published `WindowsOEMDevicesPK.der` before it will enroll it:

- If the hash matches, the script proceeds and reports the verification.
- If the hash does not match, the script refuses to enroll the PK and stops,
  reporting the expected and actual hashes. Re-download the file from the
  Microsoft repository, or, if you are intentionally enrolling a different
  (custom or organizational) PK, re-run with `-AllowUnverifiedPKDer`.

You can independently confirm the file before use:

```powershell
Get-FileHash -Algorithm SHA256 .\WindowsOEMDevicesPK.der
```

The expected hash for the current Microsoft `WindowsOEMDevicesPK.der` is
`2F569E8EDAF9657DC4951C29598725255C7F821472DB71374211FE44D082546F`. Confirm this
against the value published at Microsoft's repository rather than trusting any
single source. For an even stronger post-enrollment check, supply
`-ExpectedPKThumbprint` so the script confirms the exact certificate thumbprint
became the live Platform Key after enrollment.

---

## Usage

On runs that may perform the NVRAM rename, the script displays a support status notice in yellow referencing the official Broadcom position on the NVRAM rename approach and prompts for acknowledgement before proceeding. Assess, cleanup, rollback, and hardware-only modes (and any run with `-SkipNVRAMRename` or `-SupportedMethodsOnly`) do not rename NVRAM, so the notice is not shown for them. Pass `-Confirm` to suppress the prompt for unattended or scheduled runs.

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

# Upgrade hardware version to meet the version 21 requirement (standalone, snapshot taken by default)
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardwareOnly

# Upgrade hardware version and run full remediation in a single pass
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -UpgradeHardware

# Run unattended without the datastore space confirmation prompt
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -Confirm

# Skip NVRAM rename - use for VMs that already have 2023 KEK in NVRAM
# (e.g. created on ESXi 8.0.2+ or previously remediated via another method)
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -SkipNVRAMRename

# Supported-methods-only - refuse the unsupported NVRAM regeneration entirely.
# Uses the silent and SetupMode PK paths plus OS servicing, and reports anything
# that would need the regeneration with FinalStatus NeedsOSNativeUpdate
.\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
    -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -SupportedMethodsOnly

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
| `-GuestCredential` | `PSCredential` | Admin credential for guest OS access. Required for guest-side steps (cert update, BitLocker handling, PK enrollment, verification). When omitted, the script runs in hypervisor-only mode: NVRAM rename, hardware upgrade, and snapshot management run normally, but guest steps are skipped. Re-run with `-GuestCredential` to complete cert update and PK enrollment. |
| `-NoSnapshot` | `switch` | Skip snapshot creation. Cannot be combined with `-RetainSnapshots`. |
| `-SkipNVRAMRename` | `switch` | Skip the NVRAM rename step (steps 2-4) entirely. The VM will not be powered off, the NVRAM file will not be renamed, and ESXi will not regenerate the NVRAM. Use when the KEK 2023 certificate is already present in the VM's NVRAM (e.g. VMs created on ESXi 8.0.2+ or already remediated via another method) and you only want cert update triggering and PK enrollment. Avoids any risk associated with NVRAM file manipulation. The script proceeds directly to step 5. |
| `-SupportedMethodsOnly` | `switch` | Refuse the unsupported NVRAM regeneration fallback and restrict PK remediation to the paths the script performs without it: the silent PK update on P09 vTPM-disabled Windows VMs, which is Broadcom's official supported path (KB 423893), and UEFI SetupMode enrollment as the fallback. SetupMode reaches the same end state as the manual vUEFI method in KB 423919 but is the script's own implementation rather than the KB's manual workflow, and is recorded as `SetupMode_KB423919` in the `PKMethod` column for the audit trail. The `uefi.secureBoot.PK.resetOnce` VMX path is Broadcom-documented for vTPM-enabled Linux and other non-Windows VMs but is not automated by this script, and on vTPM-enabled Windows VMs resetOnce is the unsupported override this switch refuses. KEK and DB updates are driven only through in-guest OS servicing, so a cert-absent VM whose guest OS cannot deliver the 2023 KEK/DB is reported with `FinalStatus = NeedsOSNativeUpdate` rather than force-remediated. Also refuses `-AllowUnsupportedVTPMWindowsPKRemediation`, since PK updates on vTPM-enabled Windows VMs remain unsupported per KB 423893. Supported methods are already preferred without this switch. It is a superset of `-SkipNVRAMRename`, which suppresses the same regeneration but keeps the override available. |
| `-RetainSnapshots` | `switch` | Keep snapshots even on success. Use with `-CleanupSnapshots` later. |
| `-CleanupSnapshots` | `switch` | Remove all `Pre-SecureBoot-Fix*` snapshots on target VMs. |
| `-CleanupHWSnapshots` | `switch` | Removes all `Pre-HWUpgrade*` snapshots created by `-UpgradeHardwareOnly` runs. Run after verifying the hardware upgrade is stable. Does not require `-GuestCredential`. |
| `-CleanupNvram` | `switch` | Delete NVRAM backup files left on target VM datastores. When run alone while `Pre-SecureBoot-Fix*` snapshots still exist, deletion is skipped by default to preserve rollback options. Use with `-CleanupSnapshots` to remove both together after validation. Also removes orphan `.nvram_new` files (backups left by a prior `-Rollback`). Unlike `.nvram_old` these do not protect a rollback path and are removed regardless of snapshot state. |
| `-Rollback` | `switch` | Restore original NVRAM and revert to snapshot for target VMs. |
| `-BitLockerBackupShare` | `string` | UNC path to a file share for BitLocker recovery key backups. Required to process VMs with active BitLocker. Example: `\\server\BitLockerKeys` |
| `-SkipBitLockerResume` | `switch` | Leave BitLocker suspended when a VM completes, instead of the default behavior of re-enabling protection as the final step. By default, on any VM where this script suspended BitLocker and that finishes with the guest reachable, protection is resumed so the protected state is deterministic at the end of the maintenance window rather than depending on the auto-resume reboot countdown. Supply this switch to keep protection suspended (for example when further maintenance will reboot the VM, or when you intend to resume manually). The volume still auto-resumes once its remaining reboot count expires. The resume runs only for VMs this run suspended and only when the guest is reachable, never fails the VM, and is recorded in the CSV `Notes` column. |
| `-PKDerPath` | `string` | Path to `WindowsOEMDevicesPK.der`. When provided, enrolls the Windows OEM Devices Platform Key on any Windows VM where the PK is NULL, invalid, or an ESXi-generated placeholder (`Valid_Other`). On ESXi 8.0 P09+ hosts the script tries the official path first: a guest OS reboot for vTPM-disabled VMs. vTPM-enabled Windows/unknown-risk VMs are skipped by default (override with `-AllowUnsupportedVTPMWindowsPKRemediation`). SetupMode enrollment is the fallback. The script does not perform Linux guest-side PK enrollment. For Linux/non-Windows vTPM VMs use Broadcom KB 423893 (`uefi.secureBoot.PK.resetOnce`). See [Preparing for PK Remediation](#preparing-for-pk-remediation). |
| `-KEKDerPath` | `string` | Path to the Microsoft KEK 2K CA 2023 certificate in DER format. Optional - only needed if KEK 2023 is absent after NVRAM regeneration, which should not occur on ESXi 8.0.2+. Must be supplied together with `-PKDerPath`. KEK enrollment is performed only during the PK SetupMode remediation path, so there is no KEK-only mode in this version. |
| `-AllowUnverifiedPKDer` | `switch` | By default the PK DER supplied via `-PKDerPath` is verified against the known SHA-256 of Microsoft's published `WindowsOEMDevicesPK.der` before enrollment. A mismatch (corrupted, wrong, or substituted file) causes the script to refuse to enroll it. Specify this switch to bypass the check, which is appropriate only when intentionally enrolling a custom or organizational PK. When bypassed, the CSV records that the DER was enrolled without verification. A custom PK only counts as remediated (status `Valid_CustomExpected`) when `-ExpectedPKThumbprint` is also supplied and the live PK thumbprint matches it. Without an expected thumbprint a non-Microsoft PK classifies as `Valid_Other` and is not counted as remediated. |
| `-ExpectedPKThumbprint` | `string` | Optional. Compares the PK certificate thumbprint against this value at every point the script reads or accepts a PK. After SetupMode enrollment a mismatch is a hard failure. On an existing valid PK (already-remediated, P09 silent reboot, or P09 resetOnce) a mismatch is not a failure: the VM has a working PK, so the script reports the existing PK's identity and leaves it in place (not counted as FullyRemediated) unless `-ReplaceExistingPK` is also supplied. Non-hex characters (spaces, colons) are ignored. |
| `-ReplaceExistingPK` | `switch` | Only meaningful with `-PKDerPath` and `-ExpectedPKThumbprint`. Makes a valid-but-non-matching PK eligible for SetupMode re-enrollment against the expected certificate. Still subject to all other safety gates: it does NOT override the vTPM-enabled Windows skip (use `-AllowUnsupportedVTPMWindowsPKRemediation` for that) or the BitLocker fail-closed checks. |
| `-WaitSeconds` | `int` | Seconds to wait after reboot before polling for VMware Tools. Default: `90`. |
| `-GracefulShutdownTimeout` | `int` | Seconds to wait for a graceful guest OS shutdown before falling back to a hard power off. The script always attempts a graceful shutdown via VMware Tools first. Default: `120`. Set to `0` to always use hard power off. |
| `-InterVMDelay` | `int` | Seconds to wait between processing each VM. Default: `0`. Use when remediating paired or co-dependent VMs (primary/secondary, database/app server) to allow services to fully start before the next VM is processed. Not applied after the last VM in the batch. |
| `-IgnoreCertificateWarnings` | `switch` | Sets PowerCLI `InvalidCertificateAction` to `Ignore` for the current session before connecting to vCenter. Only use this if your vCenter uses a self-signed or untrusted certificate. Omitting this flag leaves your existing PowerCLI certificate configuration unchanged. |
| `-vCenter` | `string` | Hostname or IP address of the vCenter server. If not specified and no existing connection is active, the script will prompt for the server name. If a connection is already open the script uses it and this parameter is ignored. |
| `-Assess` | `switch` | Read-only assessment mode. No changes are made to any VM. Collects current state for all target VMs and produces a CSV and console summary. See [Assessment Mode](#assessment-mode). Mutually exclusive with all action modes. |
| `-UpgradeHardwareOnly` | `switch` | Hardware-only operation. Upgrades VM hardware version to 21 without running cert remediation. VMs that were powered on are powered off for the upgrade and powered back on when complete. VMs already powered off remain powered off. A `Pre-HWUpgrade*` snapshot is taken by default unless `-NoSnapshot` is specified. See [Hardware Version Upgrade](#hardware-version-upgrade). |
| `-UpgradeHardware` | `switch` | Adds a hardware version upgrade (step 2b) to the main remediation sequence, between power-off and NVRAM rename. The snapshot taken at step 1 covers the upgrade. For hardware upgrade only with no cert work, use `-UpgradeHardwareOnly` instead. |
| `-AllowPoweredOffVMRemediation` | `switch` | Allow processing of VMs that are currently powered off. By default powered-off VMs are skipped since BitLocker state and guest data cannot be verified safely. |
| `-AllowNonWindowsTargets` | `switch` | Allow targeting non-Windows VMs. Hypervisor-only steps (NVRAM rename, hardware upgrade, snapshot) run normally. Guest-side steps are skipped. Cannot be combined with `-GuestCredential`. For Linux vTPM-enabled VMs requiring PK enrollment, follow Broadcom KB 423893 guidance. |
| `-AllowUnsupportedVTPMWindowsPKRemediation` | `switch` | Allow PK remediation on vTPM-enabled Windows VMs. By default these are skipped because VMX-based PK changes occur outside guest OS awareness and can trigger BitLocker recovery or break TPM-sealed secrets. Broadcom recommends waiting for the planned automated/capsule-based solution for vTPM-enabled Windows VMs. |
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
              suspend BitLocker (RebootCount 3), then proceed
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
[9/9] PK remediation when requested and supported (requires -PKDerPath)
      P09+ host, vTPM-disabled Windows: guest OS reboot triggers the silent PK update
      vTPM-enabled Windows/unknown-risk: skipped by default (override required)
      Linux/non-Windows: not performed guest-side (see Broadcom KB 423893)
      Otherwise (pre-P09, or P09 silent path did not produce a valid PK): SetupMode
      enrollment fallback, shown below:
      [PK 1/5] Set uefi.secureBootMode.overrideOnce = SetupMode on VM
      [PK 2/5] Power off/on into SetupMode
               └─ Re-suspend BitLocker if it has auto-resumed (RebootCount 3)
      [PK 3/5] Copy WindowsOEMDevicesPK.der to guest C:\Windows\Temp\
      [PK 4/5] Enroll PK: Format-SecureBootUEFI | Set-SecureBootUEFI
      [PK 5/5] Clear SetupMode VMX option, re-suspend BitLocker before the
               post-enrollment reboot (RebootCount 3), reboot, verify PK status and expected thumbprint
      Resume BitLocker on completion if this run suspended it and the guest is
              reachable (unless -SkipBitLockerResume)
      Remove snapshot on success (unless -RetainSnapshots or -NoSnapshot)
```

### Smart Step Detection

Before running any changes, the script runs a lightweight guest assessment to determine which steps are still needed. This prevents unnecessary reboots and NVRAM operations on VMs where prior work (manual or from an earlier script run) has already completed some or all of the process.

| Pre-check result | Entry point | Steps skipped |
|---|---|---|
| KEK_2023 = False | Full run | None |
| KEK_2023 = True, DB_2023 = True | skipNvram | Steps 2/2b/3/4 |
| AvailableUpdates = 0x4100 | skipToStep6 | Steps 2/2b/3/4/5 |
| UEFICA2023Status = Updated or AvailableUpdates = 0x4000, AND KEK_2023 = True, AND DB_2023 = True, AND no UEFICA2023Error | certDone | Steps 2/2b/3/4/5/6 |
| Cert verified + PK valid (matching `-ExpectedPKThumbprint` if supplied) | allDone | Entire VM skipped |
| Cert verified + no -PKDerPath supplied | no requested work remains | Entire VM skipped, but FullyRemediated may be False if PK is invalid or a placeholder |

If the guest pre-check cannot run but the VM is otherwise allowed to proceed, the script assumes a full sequence because it cannot prove which steps are complete. Powered-off VMs in guest-credential mode are still subject to the powered-off safety gates and may be skipped before this fallback.

### PK Status values

The Platform Key is classified by parsing the PK firmware variable as an
EFI_SIGNATURE_LIST, extracting the embedded X.509 certificate, and inspecting its
Subject. This is more reliable than scanning the raw bytes for text: the script
validates the EFI certificate-type GUID, computes the certificate offset from the
signature-list header, loads the certificate, and classifies by its Subject CN.
The certificate Subject, Issuer, Thumbprint, Serial, and NotAfter are recorded in
the CSV so the exact enrolled certificate can be confirmed.

| Status | Meaning | Action |
|--------|---------|--------|
| `Valid_WindowsOEM` | Certificate Subject is `CN=Windows OEM Devices PK` (the Microsoft-published PK) | No action |
| `Valid_Microsoft` | Certificate Subject is a Microsoft Corporation PK | No action |
| `Valid_CustomExpected` | A non-Microsoft certificate that was deliberately enrolled with `-AllowUnverifiedPKDer` and matches the supplied `-ExpectedPKThumbprint`. Counts as remediated, but is not a Microsoft PK. Only ever set after enrollment. | No action (custom PK by intent) |
| `Valid_Other` | A real certificate, but not a recognized Microsoft PK, or a populated PK variable whose contents are not a parseable X.509 certificate (the ESXi placeholder on hosts earlier than 9.0). Will not authenticate future Windows Update KEK changes | Enroll proper PK via `-PKDerPath` |
| `Invalid_NULL` | No PK data present (variable empty or shorter than a signature-list header) | Enroll proper PK via `-PKDerPath` |
| `CheckFailed` | `Get-SecureBootUEFI` threw while reading the PK (guest access or Secure Boot cmdlet error) | Investigate guest connectivity / Secure Boot state |
| `Not checked` | Step 8 was not reached (cert update failed or HW < 14) | Resolve cert update first |

`Valid_WindowsOEM` is the expected target for the VMware Secure Boot PK problem:
Broadcom KB 423919 specifies replacing the invalid/placeholder PK with the Windows
OEM Devices Key, and that is the certificate `-PKDerPath` enrolls. `Valid_Microsoft`
is accepted as a valid-looking Microsoft-subject PK and is treated as remediated by
default, but it is not the specific certificate Broadcom's workflow names. If you
need to guarantee a specific certificate is the live PK, supply
`-ExpectedPKThumbprint` (optionally with `-ReplaceExistingPK`). The thumbprint check
is a stronger guarantee than the subject-based status label alone.

### BitLocker and PK remediation

The initial BitLocker suspension at step 0 uses `RebootCount 3`, which covers the
power-off/on at step 2, the reboot at step 6, and the optional Server 2025 extra
reboot at step 7b. If BitLocker is still active when step 9 runs, the script
re-suspends it (with a second key backup to the share) before the SetupMode reboot,
and re-suspends again before the post-enrollment reboot so the enrollment sequence
stays covered. A VM requiring PK remediation has four total reboots (five if the
Server 2025 extra reboot is needed) and two backup files written to the share.

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
| `0x4000` | Fully complete - Boot Manager updated (bit 0x0100 cleared). `0x4000` modifier remains permanently set |

Per [KB5085046](https://support.microsoft.com/en-us/kb/5085046), bit `0x4000` is a behavior modifier that is never cleared. A final value of `0x4000` indicates all applicable update actions have completed successfully.

### Verification

Final status is read from:
- `UEFICA2023Status` under `HKLM:\...\SecureBoot\Servicing` - expected value: `Updated`
- `UEFICA2023Error` under `HKLM:\...\SecureBoot\Servicing` - must be absent. This key exists only when a deployment error has occurred and does **not** appear in the Windows Event Log. A VM can show `UEFICA2023Status = Updated` while this key is present. The script treats this as an incomplete result and records it in the `UEFICA2023Error` CSV column and `Notes`.
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

   # If -UpgradeHardwareOnly was also used, include -CleanupHWSnapshots
   .\FixSecureBootBulk.ps1 -VMListCsv .\SecureBoot_Bulk_<timestamp>.csv `
       -CleanupSnapshots -CleanupHWSnapshots -CleanupNvram
```

The cleanup switches can be combined freely in a single run. When combined, the script enforces a safe internal order regardless of what was specified: Pre-SecureBoot-Fix snapshots are removed first (children), then Pre-HWUpgrade snapshots (parents), then NVRAM backup files (`.nvram_old`, plus orphan `.nvram_new` files left by a prior rollback). A single confirmation prompt covers all operations and results are written to one combined CSV (`SecureBoot_Cleanup_<timestamp>.csv`).

Before removing any snapshot, the script checks for non-managed child snapshots (snapshots not created by this script). If found, that snapshot is skipped with a warning and logged in the Notes column. Non-managed children must be removed manually in vSphere Client before re-running cleanup. Pre-SecureBoot-Fix child snapshots under a Pre-HWUpgrade parent are handled automatically when both `-CleanupSnapshots` and `-CleanupHWSnapshots` are specified.

If only `-CleanupNvram` is run while `Pre-SecureBoot-Fix*` snapshots still exist on a VM, the script **skips** deleting that VM's `.nvram_old` file by default and logs the reason in the Notes column. The `.nvram_old` file is the NVRAM-only rollback path. Deleting it while the snapshot rollback path has not been removed would leave the VM with no recovery options if a problem surfaces later. To remove both together after validation, run `-CleanupSnapshots` and `-CleanupNvram` in the same command. The script removes the snapshots first, then deletes `.nvram_old` only for VMs whose snapshot removal succeeded.

`-CleanupNvram` also removes orphan `.nvram_new` files. A `-Rollback` preserves the current `.nvram` as `.nvram_new` before restoring `.nvram_old`, and nothing else cleans those up afterward. Unlike `.nvram_old`, a `.nvram_new` file does not protect a rollback path, so it is always deleted when `-CleanupNvram` runs, regardless of whether `Pre-SecureBoot-Fix*` snapshots still exist.

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

The result column in the rollback CSV distinguishes the possible outcomes. When
a snapshot is reverted (which restores NVRAM wholesale), the result is
`Rolled Back (NVRAM + Snapshot)` if the NVRAM file was also restored, or
`Rolled Back (via snapshot, NVRAM file restore not needed)` if the file restore
was skipped (for example because a prior rollback left a `.nvram_new` backup) but
the snapshot revert still completed the rollback. When no snapshot exists, the
NVRAM file restore is the only path and the result is
`Rolled Back (NVRAM file only - no snapshot, registry NOT reverted)`. If neither
the file restore nor a snapshot revert succeeded, the result is
`Partial - NVRAM not restored and no snapshot reverted`.

---

## Output

The script writes a timestamped CSV to the current directory after each run:

| Mode | Output file |
|------|------------|
| Main remediation | `SecureBoot_Bulk_<timestamp>.csv` |
| Cleanup (any combination of -CleanupSnapshots, -CleanupHWSnapshots, -CleanupNvram) | `SecureBoot_Cleanup_<timestamp>.csv` |
| Rollback | `SecureBoot_Rollback_<timestamp>.csv` |

The main remediation CSV includes these columns (in order):

`VMName`, `SnapshotCreated`, `BitLockerSkipped`, `BitLockerKeysBacked`,
`BitLockerSuspended`, `NVRAMRenamed`, `KEK_AfterNVRAM`, `DB_AfterNVRAM`,
`HWUpgraded`, `UpdateTriggered`, `KEK_2023`, `DB_2023`, `FinalStatus`,
`UEFICA2023Error`, `Evt1036`, `Evt1043`, `Evt1044`, `Evt1045`, `Evt1795`,
`Evt1797`, `Evt1799`, `Evt1800`, `Evt1801`, `Evt1802`, `Evt1803`, `Evt1808`,
`PK_Status`, `PK_Subject`, `PK_Issuer`, `PK_Thumbprint`, `PK_Serial`,
`PK_NotAfter`, `PKEnrolled`, `PKRemediated`, `FullyRemediated`,
`CertUpdateVerified`, `PKMethod`, `CertMethod`, `SnapshotRetained`, `Notes`

The CSV is also prefixed with a `ScriptVersion` column identifying the script
version that produced it.

The `PK_Subject`, `PK_Issuer`, `PK_Thumbprint`, `PK_Serial`, and `PK_NotAfter`
columns hold the Platform Key certificate's identity as parsed from the live
firmware. They are populated whenever the PK is read (assessment, the step 8 PK
check, and post-enrollment verification) and let you confirm exactly which
certificate is enrolled rather than relying on the status label alone. They are
empty when the PK is NULL or could not be read.

`CertUpdateVerified` is `True` when the 2023 KEK and DB certificates are
confirmed present in NVRAM and no `UEFICA2023Error` key exists. `FullyRemediated`
is `True` only when `CertUpdateVerified` is true **and** the PK is valid
(`Valid_WindowsOEM` or `Valid_Microsoft`). A VM can have `FinalStatus = Updated`
and `CertUpdateVerified = True` while `FullyRemediated = False` if its PK still
needs enrollment.

`PKMethod` records how the Platform Key was handled on each VM: `AlreadyValid`
(already a valid PK at pre-check or the step 8 check), `Silent` (P09 silent
reboot), `ResetOnce` (P09 resetOnce VMX path, used only for the explicit Windows or unknown-risk unsupported override), `SetupMode` (SetupMode
enrollment, recorded as `SetupMode_KB423919` under `-SupportedMethodsOnly`),
`Skipped_vTPMWindows` (a vTPM-enabled Windows VM deferred pending the Capsule
solution), or `NotAttempted`. `CertMethod` records how the 2023 KEK and DB
certificates were delivered: `AlreadyPresent` (already in NVRAM at pre-check),
`OSServicing` (in-guest Windows servicing delivered them without an NVRAM
regeneration), `NVRAMRegen` (the NVRAM regeneration fallback ran), or
`NotAttempted`. Together
they show at a glance whether each VM took a supported path or the unsupported
NVRAM fallback, and a count of `CertMethod = NVRAMRegen` is a direct measure of
how often the fallback fired.

### Summary output

After each run the script prints a summary block with counts for each outcome
category. Key fields:

```
Registry Updated   : N  (FinalStatus=Updated, use CertUpdateVerified column for confirmed cert state)
Cert update done   : N  (KEK/DB confirmed in NVRAM + no UEFICA2023Error)
Fully remediated   : N  (cert update + PK valid or enrolled)
```

Three additional outcome states are reported when they occur:

```
Skipped (snapshot)     : N  (snapshot failed; VM not modified - see Notes for reason)
Needs attention        : N  (PK updated; OS-side cert apply incomplete - Event 1801, awaiting 1808)
Needs OS-native        : N  (-SupportedMethodsOnly refused the NVRAM fallback and OS servicing did not deliver KEK/DB)
```

`Skipped_SnapshotFailed` means the pre-remediation snapshot could not be created,
so the VM was skipped before any NVRAM change. The failure reason is in the CSV
`Notes` column. `NeedsAttention_1801` means the certificate update is staged but
not yet applied to firmware: Event 1801 persisted after the extra reboot while
Event 1808 (completion) is still absent. The PK update itself may have succeeded.
The gap is the OS-side certificate application, which typically resolves after a
further reboot or Windows Update cycle. These VMs retain their snapshot and do not
count as fully remediated. Re-run the script to re-verify.

`NeedsOSNativeUpdate` appears only under `-SupportedMethodsOnly`, and only when
the guest reports no determinable servicing progress (no Windows servicing status
and the 2023 KEK and DB still absent). The NVRAM regeneration fallback was refused
and in-guest OS servicing did not deliver the certificates, so the VM needs an
OS-native, Broadcom, or vendor-specific update. A VM whose Windows servicing is
still in progress keeps that status and falls under the normal pending outcome.
The Notes column records the same detail.

The PK section distinguishes six states:

```
PK already valid   : N  (Valid_WindowsOEM or Valid_Microsoft -- no enrollment needed)
PK placeholder     : N  (ESXi-generated Valid_Other -- still needs enrollment via -PKDerPath)
PK enrolled        : N  (was Invalid_NULL or Valid_Other -- enrolled this run)
PK valid, mismatch : N  (valid PK present but does not match -ExpectedPKThumbprint -- re-run with -ReplaceExistingPK to replace)
PK enroll failed   : N  (manual intervention required -- see Notes)
PK still invalid   : N  (provide -PKDerPath and re-run)
```

`Valid_Other` in the CSV means the live PK is still a placeholder or otherwise unrecognized key and is not considered remediated. A VM that started with `Valid_Other` is counted under `PK enrolled` only if enrollment succeeded and the final PK status changed to a remediated value such as `Valid_WindowsOEM`, `Valid_Microsoft`, or `Valid_CustomExpected`. A final CSV status of `Valid_Other` always means the PK still needs enrollment.

BitLocker skip categories are reported separately:

```
Skipped (BL active)  : N  (no -BitLockerBackupShare provided)
Skipped (BL backup)  : N  (key backup to share failed)
Skipped (BL susp)    : N  (suspension failed, partial, or returned no status)
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
   `VMName_BitLockerKeys_YYYYMMDD_HHMMSS.txt`, one file per VM, one entry per
   protected volume. The export also verifies that every active-protected volume
   has a RecoveryPassword protector. If any volume lacks one, the VM is skipped.
2. **Skips if backup fails.** The VM is skipped with `Skipped_BitLockerBackupFailed`
   rather than risking a lockout
3. **Suspends BitLocker** on all active volumes with `RebootCount 3`, covering
   the power-off/on cycle, the post-cert-update reboot, and the optional Server
   2025 extra reboot (steps 2, 6, and 7b). If suspension fails or returns no JSON,
   or if any volume fails to suspend, the VM is skipped with
   `Skipped_BitLockerSuspendFailed`
4. **Proceeds with full remediation.** NVRAM rename, cert update, registry fix
5. **Resumes BitLocker on completion (default).** When the VM finishes with the
   guest reachable, the script re-enables protection on the volumes it suspended,
   so the protected state is deterministic at the end of the maintenance window.
   Pass `-SkipBitLockerResume` to leave it suspended instead. In that case the
   volume auto-resumes on its own once its remaining reboot count expires. If the
   guest is not reachable at the end of the run (for example a VM stranded at the
   pre-boot prompt), the script leaves BitLocker on its auto-resume countdown and
   notes that in the CSV.

If PK remediation runs (step 9), the step 0 suspension may have been consumed by
the time the SetupMode reboot is needed. The script re-checks BitLocker status at
step 8 and, if it is active, performs a **second backup and suspension** before the
SetupMode reboot, and re-suspends again before the post-enrollment reboot so the
multi-reboot enrollment sequence stays covered. If re-suspension fails or returns
partial results, PK remediation is skipped to avoid a PCR7-altering firmware change
with active BitLocker. A VM requiring PK remediation will produce two backup files
on the share.

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

The script selects the enrollment path per VM based on host version, vTPM status, and OS type:

**ESXi 8.0 P09+ (build 25429389+), preferred path:**

- **vTPM-disabled Windows VMs:** The PK is updated automatically on the next guest OS reboot. The script triggers a reboot after cert update and verifies the result. No NVRAM rename or manual steps required. When BitLocker is active the script suspends it before this reboot and resumes it afterward (this requires `-BitLockerBackupShare`). A vTPM-disabled volume has no PCR seal, so the silent PK update cannot trigger recovery. If the suspension cannot be confirmed the VM falls through to the SetupMode fallback rather than rebooting with BitLocker armed.
- **vTPM-enabled, non-Windows/Linux VMs:** Broadcom documents the `uefi.secureBoot.PK.resetOnce = TRUE` VMX method for this profile (KB 423893). This script does not perform Linux/non-Windows guest-side PK enrollment or verification. Use `-Assess` to identify candidates, or `-AllowNonWindowsTargets` only for hypervisor-only preparation (snapshot, hardware upgrade, NVRAM rename), then complete PK remediation and validation using Broadcom KB 423893 or OS-vendor guidance.
- **vTPM-enabled, Windows VMs:** Skipped by default. VMX-based PK changes occur outside the guest OS's awareness and can change TPM PCR7 measurements, potentially triggering BitLocker recovery or breaking TPM-sealed secrets (DPAPI machine keys, Credential Guard). Broadcom recommends waiting for the planned capsule-based automated solution. Override with `-AllowUnsupportedVTPMWindowsPKRemediation` only if you understand the risk and have either confirmed BitLocker is inactive or backed up recovery keys and successfully re-suspended protection.

**Pre-P09 hosts or P09 path fallback, SetupMode:**

1. Sets `uefi.secureBootMode.overrideOnce = SetupMode` on the VM's VMX configuration
2. Reboots the VM. The UEFI enters Setup Mode on the next boot, temporarily allowing PK enrollment without requiring an existing PK signature
3. Copies `WindowsOEMDevicesPK.der` into the guest
4. Runs `Format-SecureBootUEFI | Set-SecureBootUEFI` in an elevated guest session to convert the DER certificate to EFI Signature List format and enroll it
5. Clears the VMX option, reboots, and verifies the PK reads as `Valid_WindowsOEM`

The VMX option `uefi.secureBootMode.overrideOnce` is single-use. It is
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
- PK certificate identity: Subject, Issuer, Thumbprint, Serial, and NotAfter, parsed from the live firmware so the exact enrolled certificate can be confirmed (requires `-GuestCredential`)
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

Hardware version 21 or later is required for ESXi to populate regenerated NVRAM with the 2023 KEK certificate. VMs below version 21 will have NVRAM regenerated but the KEK will not be present afterward. The `-UpgradeHardwareOnly` switch upgrades VMs without running cert remediation. `-UpgradeHardware` adds the upgrade as step 2b inside a full remediation run.

> **Important:** VMware does not provide a supported API or UI method to downgrade VM hardware versions. A snapshot taken before the upgrade is the only supported rollback path. Reverting to the pre-upgrade snapshot restores the previous hardware version. If `-NoSnapshot` is specified, there is no automated rollback path.

### Standalone (upgrade only, no cert work)

Use `-UpgradeHardwareOnly` when you want to bring VMs to HW21 as a separate step before running full remediation. By default a `Pre-HWUpgrade_<timestamp>` snapshot is taken before each upgrade. VMs that were powered on are powered off for the upgrade and powered back on when complete. VMs already powered off remain powered off.

```powershell
# Upgrade all eligible VMs (snapshot taken by default)
.\FixSecureBootBulk.ps1 -UpgradeHardwareOnly

# Upgrade specific VMs
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardwareOnly

# Upgrade without taking a snapshot (no rollback path)
.\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardwareOnly -NoSnapshot
```

VMs already at version 21 or later are skipped. Output is written to `SecureBoot_HWUpgrade_<timestamp>.csv`.

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

> **Note:** `-UpgradeHardware` adds the upgrade step to a full remediation run. To upgrade hardware version only, without cert work, use `-UpgradeHardwareOnly`.

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
Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
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

### Scheduled tasks with stored passwords fail after remediation

On vTPM-enabled VMs, changes to Secure Boot variables alter TPM PCR7 measurements. This can occur via the NVRAM rename, the `uefi.secureBoot.PK.resetOnce` VMX parameter (on P09+ hosts), or the SetupMode PK enrollment path. Windows uses DPAPI to encrypt stored credentials including scheduled task passwords. On machines where the DPAPI machine key is sealed to PCR7, those stored credentials become unreadable after a PCR7 change and Task Scheduler will report error `2147943726` (`ERROR_LOGON_FAILURE`).

Scheduled tasks using gMSA accounts or tasks with no stored password are not affected since they don't rely on DPAPI-encrypted credentials. Credential Manager entries and other DPAPI-protected secrets may also be affected.

If Virtualization Based Security (VBS) or Credential Guard is active, the same PCR7 change may affect VBS-sealed secrets and cause Credential Guard to reinitialize. Domain logins should continue to work but cached credentials may be flushed and VBS-protected secrets resealed. The script detects VBS and Credential Guard status and will display a specific warning when either is active before proceeding with any path that changes Secure Boot variables.

If guest credentials are supplied and the smart pre-check can confirm the 2023 KEK is already present in the VM's NVRAM, the script skips the NVRAM rename automatically. In no-credential hypervisor-only mode, guest certificate state cannot be checked, so use `-SkipNVRAMRename` for any VM already remediated through the official P09 path. On P09+ hosts with no vTPM, the silent reboot path does not alter Secure Boot variables from outside the guest OS so the PCR7 risk does not apply to that path. The script will warn in yellow when a vTPM is detected without BitLocker active before any path that may trigger a PCR7 change.

If you encounter this after running the script, re-entering the stored passwords in Task Scheduler for the affected tasks will restore normal operation.

### Snapshot creation fails

Check available datastore space. Each snapshot consumes space proportional to the
amount of disk I/O that occurs while it occurs. If space is constrained, use
`-NoSnapshot` and ensure you have an alternative rollback method (e.g., a storage
array snapshot or backup taken immediately before running the script).

### Clock drift after NVRAM regeneration

When ESXi regenerates the NVRAM file it resets the virtual RTC. On first boot after
the regeneration the VM clock loses its timezone offset, so the time may appear
correct in UTC but be several hours off for the local timezone. NTP sync corrects
this within a minute or two on most VMs, but during that window the following issues
can occur:

- Domain-joined VMs will fail Kerberos authentication until the clock corrects,
  meaning RDP and domain logins will be blocked until NTP syncs
- Event log timestamps will reflect the wrong time until NTP syncs
- Time-sensitive services like DHCP failover and database servers may behave
  unexpectedly during the drift window

For most VMs the NTP sync window is short enough to accept. For time-sensitive VMs
you can set the following advanced VMX parameter before the first post-regeneration
boot to pre-configure the correct timezone offset:

```
rtc.diffFromUTC = <offset in seconds>
```

For example, UTC-5 (Eastern Standard Time) would be `-18000`. This is a standard
VMware parameter documented in [Broadcom KB 419717](https://knowledge.broadcom.com/external/article/419717).
Remove the parameter after the VM has completed NTP sync and is running normally.

**Domain Controllers:** Handle DCs last in your remediation sequence, especially
the PDC Emulator FSMO role holder. The PDC is the authoritative time source for the
domain and a clock reset on it can cascade to all domain members. Using
`rtc.diffFromUTC` on the PDC Emulator before its first post-regeneration boot
prevents this. Test the parameter on non-DC VMs first to confirm the correct offset
for your environment before applying it to DCs.

---

## License

MIT License. See `LICENSE` for details.
