<#
.SYNOPSIS
    Bulk Secure Boot 2023 certificate remediation for VMware VMs on ESXi 8.
    Optionally takes a snapshot before making any changes. Includes rollback,
    snapshot cleanup, and NVRAM cleanup modes for post-validation housekeeping.
    Includes a read-only assessment mode (-Assess) and hardware version upgrade
    mode (-UpgradeHardware).

    Process per VM (default):
    Pre. Read-only guest pre-check when credentials are available. Determines
         entry point and exits early if no work is needed.
    Compute required work ($needsNvramWork / $needsHWUpgrade) and run late
         ESXi/HW safety gates now that entryStep is known.
    0. BitLocker/TPM safety check (only after gates confirm work is needed)
    1. Take snapshot unless -NoSnapshot
    2. Power off (only if NVRAM rename or HW upgrade is needed)
    2b. Upgrade to HW version 21 (only if -UpgradeHardware and VM is below HW21)
    3. Rename .nvram -> .nvram_old (ESXi regenerates NVRAM with 2023 KEK on next boot)
    4. Power on, wait for Tools, verify 2023 certs are present in new NVRAM
    5. Clear stale Servicing registry state
    6. Set AvailableUpdates = 0x5944, trigger Secure-Boot-Update scheduled task
    7. Reboot, trigger task again, wait for Tools
    8. Check Platform Key (PK) validity (ESXi < 9.0 installs a NULL PK by default)
    9. Remediate PK: P09 silent reboot for vTPM-disabled Windows, UEFI SetupMode for vTPM-enabled Windows under the unsupported override, and P09 resetOnce only for unknown-risk vTPM guests (resetOnce is a Linux and non-Windows mechanism that is skipped for confirmed Windows, and this script does not perform Linux guest PK enrollment)
    Post. Remove snapshot if fully successful, retain if remediation incomplete.

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
    Guest OS credential (domain admin). Required for guest-side remediation
    steps: BitLocker check and suspension, registry updates, Secure-Boot-Update
    task triggering, event-log checks, certificate verification, and PK
    enrollment. If omitted, the script runs in hypervisor-only mode: snapshot,
    optional hardware upgrade, NVRAM rename, and power cycle only. Guest-side
    certificate update and PK enrollment are skipped and must be completed by
    re-running with -GuestCredential from a machine with guest OS access.
    Note: in hypervisor-only mode the script cannot check or suspend BitLocker.
    Ensure recovery keys are backed up and protection is suspended by another
    process before running without this parameter on VMs where BitLocker or
    other TPM-sealed encryption may be active.

.PARAMETER NoSnapshot
    Skip snapshot creation entirely. Use when datastore space is constrained
    or snapshots are managed externally. Cannot be combined with
    -RetainSnapshots. Note: without a snapshot there is no automated rollback
    path - the -Rollback mode will still restore the .nvram_old file if one
    exists, but cannot revert VM state (registry changes etc.).

.PARAMETER SkipNVRAMRename
    Skip the NVRAM rename step (steps 2-4) entirely. The VM will not be powered
    off, the NVRAM file will not be renamed, and ESXi will not regenerate the
    NVRAM. Use this when the KEK 2023 certificate is already present in the VM's
    NVRAM (e.g. VMs created on ESXi 8.0.2+ or already remediated via another
    method) and you only want to use the script for cert update triggering and
    PK enrollment. This avoids any risk associated with NVRAM file manipulation.
    The script will proceed directly to step 5 (cert update trigger).

.PARAMETER SupportedMethodsOnly
    Refuse the unsupported NVRAM regeneration fallback and restrict PK remediation
    to the paths the script performs without it: the silent PK update on P09
    vTPM-disabled Windows VMs, which is Broadcom's official supported path
    (KB 423893), and UEFI SetupMode enrollment as the fallback. SetupMode reaches
    the same end state as the manual vUEFI procedure in Broadcom KB 423919 but is
    the script's own implementation rather than the KB's manual workflow, and is
    recorded as SetupMode_KB423919 in the PKMethod column for the audit trail. The
    uefi.secureBoot.PK.resetOnce VMX path is Broadcom-documented for vTPM-enabled
    Linux and other non-Windows VMs, but this script does not perform Linux guest
    PK enrollment, so resetOnce stays external to it. On vTPM-enabled Windows VMs
    resetOnce is the unsupported override that this switch refuses.
    KEK and DB updates are driven only through in-guest OS servicing. The NVRAM
    regeneration fallback (the NVRAM manipulation KB 423919 discourages) is
    refused, so a cert-absent VM whose guest OS cannot deliver the 2023 KEK/DB is
    reported with FinalStatus NeedsOSNativeUpdate rather than force-remediated. This
    switch also refuses -AllowUnsupportedVTPMWindowsPKRemediation, since PK
    updates on vTPM-enabled Windows VMs remain unsupported per KB 423893 (wait
    for the Capsule solution). Supported methods are already preferred without
    this switch. -SupportedMethodsOnly removes the unsupported fallback entirely
    and is a superset of -SkipNVRAMRename, which suppresses the same regeneration
    but keeps the override available.

.PARAMETER AllowUnsupportedVTPMWindowsPKRemediation
    Allow PK remediation on vTPM-enabled Windows VMs. By default, the script
    skips all PK enrollment for vTPM-enabled Windows VMs (both the
    uefi.secureBoot.PK.resetOnce VMX path and the SetupMode path) because
    Broadcom KB 423893 recommends waiting for a forthcoming capsule-based
    automated solution for this VM profile. The VMX resetOnce method is
    explicitly listed in KB 423893 as recommended only for Linux vTPM-enabled
    VMs, so when this switch is supplied the script uses SetupMode directly for
    a confirmed Windows guest and attempts resetOnce first only for an
    unknown-risk guest that might be a misidentified non-Windows OS.
    Provide this switch only if you have reviewed the risk of PCR7
    measurement changes on vTPM-enabled VMs, confirmed that recovery keys are
    backed up, and accept that TPM-sealed applications (BitLocker, Credential
    Guard, stored credentials) may require recovery after this operation.

.PARAMETER AllowPoweredOffVMRemediation
    Allow remediation of VMs that are powered off at the start of the run. By
    default, in guest-credential mode the script skips powered-off VMs because
    BitLocker and TPM-sealed application state cannot be confirmed before
    hardware, NVRAM, or Secure Boot changes are made. With this switch the script
    proceeds with
    a prominent warning. Only use this switch if you have verified recovery keys
    are backed up and BitLocker protection is suspended by another process, or
    if you know the VMs do not have BitLocker or TPM-sealed encryption active.

.PARAMETER AllowNonWindowsTargets
    Allow the script to process VMs that are positively identified as non-Windows
    (Linux) guests. By default the script skips known Linux VMs in main
    remediation mode because this script targets Windows Secure Boot remediation
    and the Windows/Linux PK remediation paths differ per Broadcom KB 423893.
    For Linux vTPM PK remediation use Broadcom-supported methods described in
    KB 423893 or the OS vendor's guidance. Use this switch only if you have
    reviewed those paths and intend to run hypervisor-only steps on Linux VMs.

.PARAMETER Confirm
    Suppress the "Continue? (Y/N)" prompt and proceed automatically. Use this
    when running the script unattended or in a scheduled task, and you have
    already verified sufficient datastore space for snapshots.

.PARAMETER RetainSnapshots
    Keep snapshots even on success. Use this when you want to validate VMs
    over a period of days before removing snapshots. Use -CleanupSnapshots
    later to remove them. Cannot be combined with -NoSnapshot.

.PARAMETER CleanupSnapshots
    Removes all Pre-SecureBoot-Fix* snapshots on target VMs. Does not require
    -GuestCredential. Can be combined with -CleanupHWSnapshots and -CleanupNvram
    in a single run. When combined, ordering is enforced internally: SecureBoot-Fix
    snapshots are removed first, then HWUpgrade snapshots, then NVRAM backup files
    (.nvram_old, plus orphan .nvram_new files left by a prior rollback).
    Non-managed child snapshots on a VM will cause that snapshot to be skipped
    with a warning.

.PARAMETER CleanupHWSnapshots
    Removes all Pre-HWUpgrade* snapshots created by -UpgradeHardwareOnly runs. Does not require -GuestCredential. Can be combined with -CleanupSnapshots
    and -CleanupNvram. If a Pre-HWUpgrade snapshot has Pre-SecureBoot-Fix child
    snapshots, it will be skipped unless -CleanupSnapshots is also specified, in
    which case the children are removed first automatically.

.PARAMETER CleanupNvram
    Deletes NVRAM backup files left on target VM datastores: .nvram_old rollback
    files and orphan .nvram_new files left by a prior -Rollback. Does not require
    -GuestCredential. Can be combined with -CleanupSnapshots and -CleanupHWSnapshots.
    When combined, NVRAM backup files are always deleted last, after all snapshots
    have been removed. If run alone while Pre-SecureBoot-Fix* snapshots still exist,
    .nvram_old deletion is skipped by default to preserve rollback options.
    Use -CleanupSnapshots with -CleanupNvram to remove both together after validation.
    The orphan .nvram_new files (a rollback preserves the current .nvram as
    .nvram_new before restoring .nvram_old) do not protect a rollback path, so unlike
    .nvram_old they are removed regardless of whether snapshots still exist.

.PARAMETER Rollback
    Rollback mode. For each target VM:
      - Confirms a .nvram_old backup or a Pre-SecureBoot-Fix* snapshot exists.
        If neither is present, the VM is left untouched with no power cycle.
      - Powers off the VM
      - Renames the current .nvram -> .nvram_new (preserves it)
      - Renames .nvram_old -> .nvram (restores original NVRAM)
      - Reverts to the Pre-SecureBoot-Fix* snapshot if one exists
      - Powers the VM back on
    Does not require -GuestCredential. If no snapshot exists the NVRAM is
    still restored, but VM state (registry changes etc.) will not be reverted.

.PARAMETER BitLockerBackupShare
    UNC path to a writable file share for BitLocker recovery key backups. When
    provided, VMs with active BitLocker are processed rather than skipped. The
    script exports all recovery keys to the share as VMName_BitLockerKeys_<timestamp>.txt
    before making any changes, aborts if the backup fails, then suspends BitLocker
    for the duration of the remediation. If PK remediation also runs (step 9),
    a second backup and suspension are performed before the SetupMode reboot.
    Without this parameter, any VM with active BitLocker is skipped with a warning.
    Example: \\fileserver\BitLockerKeys

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

.PARAMETER AllowUnverifiedPKDer
    By default, the PK DER supplied via -PKDerPath is verified against the known
    SHA-256 of Microsoft's published WindowsOEMDevicesPK.der before it will be
    enrolled. If the file does not match (corrupted, wrong file, or substituted),
    the script refuses to enroll it. Specify -AllowUnverifiedPKDer to bypass this
    check, which is appropriate only when intentionally enrolling a custom or
    organizational PK. When bypassed, the CSV records that the DER was enrolled
    without verification.

.PARAMETER ExpectedPKThumbprint
    Optional. When supplied, the Platform Key certificate thumbprint is compared
    against this value at every point the script reads or accepts a PK. Behavior
    on a mismatch depends on context:
      - After SetupMode enrollment: a mismatch is a hard failure (the script
        enrolled a specific certificate and the live PK does not match it). The
        VM is not counted as PK-remediated.
      - On an existing valid PK (already-remediated pre-check, P09 silent reboot,
        or P09 resetOnce that resolved to a valid certificate): a mismatch is NOT
        treated as a failure, because the VM has a working PK. Instead the script
        surfaces a note with the existing PK's identity (Subject, Issuer,
        Thumbprint, Serial, NotAfter) so the operator can decide whether to
        replace it, and does not mark the VM FullyRemediated. To replace the
        existing valid PK with the expected certificate, re-run with
        -ReplaceExistingPK.
    Non-hex characters (spaces, colons) are ignored, so values copied from
    certificate dialogs can be pasted directly.

.PARAMETER ReplaceExistingPK
    Optional. Only meaningful together with -PKDerPath and -ExpectedPKThumbprint.
    By default, a VM that already has a valid Platform Key is left alone even if
    its thumbprint does not match -ExpectedPKThumbprint (the script reports the
    existing PK for review). When -ReplaceExistingPK is specified, a valid-but-
    non-matching PK is made eligible for SetupMode re-enrollment against the
    expected certificate, reusing the same SetupMode machinery used for NULL or
    placeholder PKs.

    Replacing an existing valid PK is more consequential than enrolling onto a
    NULL or placeholder PK. It is still subject to all other safety gates: it does
    NOT override the vTPM-enabled Windows skip (use
    -AllowUnsupportedVTPMWindowsPKRemediation for that) and it does NOT override
    the BitLocker fail-closed checks. -ReplaceExistingPK only makes the PK
    eligible for replacement. It does not bypass the conditions that normally
    govern writing a PK.

.PARAMETER WaitSeconds
    Seconds to wait after issuing a reboot before polling for Tools.
    Default 90. Increase for slower VMs.

.PARAMETER GracefulShutdownTimeout
    Seconds to wait for a graceful guest OS shutdown before falling back to a
    hard power off. The script always attempts a graceful shutdown via VMware
    Tools first (equivalent to clicking Shut Down in Windows). If the guest has
    not powered off within this timeout, a hard power off is issued automatically.
    Default 120. Set to 0 to skip the graceful shutdown attempt and always use
    hard power off.

.PARAMETER InterVMDelay
    Seconds to wait between processing each VM. Useful when remediating paired
    or co-dependent VMs (e.g. primary/secondary, database/app server) where the
    first VM needs time to fully start its services before the next VM is processed.
    Default 0 (no delay). The delay is applied after each VM completes, except
    the last VM in the batch.

.PARAMETER IgnoreCertificateWarnings
    When specified, sets PowerCLI InvalidCertificateAction to Ignore for the
    current session before connecting to vCenter. Only use this if your vCenter
    uses a self-signed or otherwise untrusted certificate and you have accepted
    that risk. Omitting this flag leaves your existing PowerCLI certificate
    configuration unchanged. If your vCenter has a properly signed certificate
    this flag is not needed and should not be used.

.PARAMETER vCenter
    Hostname or IP address of the vCenter server to connect to. If not specified
    and no existing vCenter connection is active, the script will prompt for a
    server name. If an existing connection is already open the script uses it
    and this parameter is ignored.

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

.PARAMETER UpgradeHardwareOnly
    Hardware-only operation. Upgrades each VM's hardware version to the minimum
    required for Secure Boot 2023 certificate remediation (HW version 21). VMs
    already at HW21 or later are skipped. VMs that were powered on are powered
    off for the upgrade and powered back on when complete. VMs that were already
    powered off remain powered off. No Secure Boot remediation snapshot is taken.
    A Pre-HWUpgrade snapshot is taken by default unless -NoSnapshot is specified.
    No NVRAM rename is performed, and no guest-side certificate update or PK
    enrollment steps run. Use this when you want to bring VMs to HW21 as a
    separate step before running the full remediation. Results are exported to
    SecureBoot_HWUpgrade_<timestamp>.csv.

    This switch replaces the previous behavior where -UpgradeHardware without
    -GuestCredential performed hardware-only upgrade. That combination now runs
    hypervisor-only remediation (snapshot + hardware upgrade + NVRAM rename).

.PARAMETER UpgradeHardware
    Ensures VM hardware version is at 21 or later before NVRAM regeneration.
    Hardware version 21 is required for ESXi to populate regenerated NVRAM
    with the 2023 KEK certificate. VMs already at HW21 or later are not
    upgraded further.
    Use in the main remediation run: hardware upgrade is performed between step 2
    (power off) and step 3 (NVRAM rename) as part of the remediation sequence.
    With -GuestCredential: full remediation including guest cert update and PK
    enrollment. Without -GuestCredential: hypervisor-only remediation (snapshot,
    hardware upgrade, NVRAM rename, power cycle) with guest steps deferred.
    Can also be combined with -SkipNVRAMRename to upgrade hardware only without
    renaming the NVRAM file.
    NOTE: VMware does not provide a supported API or UI method to downgrade VM
    hardware versions. A snapshot is the only supported rollback path.

.PARAMETER SkipBitLockerResume
    By default, when this script suspended BitLocker on a VM and that VM completes
    the run with the guest reachable, the script re-enables (resumes) BitLocker
    protection on the affected volumes as its final action, rather than leaving
    protection suspended on an auto-resume reboot countdown. This makes the
    protected state deterministic at the end of the maintenance window instead of
    depending on a future reboot to re-arm, and avoids leaving a VM that will
    prompt for a password or recovery key on its next (possibly unattended) reboot.
    Supply -SkipBitLockerResume to leave BitLocker suspended on completion (the
    pre-v2.0.0 behavior) - for example when chaining additional maintenance
    that will itself reboot the VM, or when you intend to resume manually. When
    suspension is left in place, the volume still auto-resumes after its remaining
    reboot count expires. The resume step only runs for VMs this script suspended
    (BitLockerSuspended = True) and only when the guest is powered on with VMware
    Tools running. A failed or skipped resume is recorded in the CSV Notes and
    never fails the VM.

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

    # After validation period - clean up all snapshots and NVRAM backup files in one pass
    .\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260227_124728.csv" `
        -CleanupSnapshots -CleanupNvram

    # If -UpgradeHardwareOnly was used, include -CleanupHWSnapshots as well
    .\FixSecureBootBulk.ps1 -VMListCsv ".\SecureBoot_Bulk_20260227_124728.csv" `
        -CleanupSnapshots -CleanupHWSnapshots -CleanupNvram

    # Cleanup can also target specific VMs or all VMs without a CSV
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02","vm03","vm04" -CleanupSnapshots -CleanupNvram
    .\FixSecureBootBulk.ps1 -CleanupSnapshots -CleanupNvram

    # Individual cleanup operations are still supported when needed
    .\FixSecureBootBulk.ps1 -CleanupSnapshots
    .\FixSecureBootBulk.ps1 -CleanupNvram
    .\FixSecureBootBulk.ps1 -CleanupHWSnapshots

    # Full remediation including PK enrollment (recommended - download WindowsOEMDevicesPK.der first)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der"

    # Full remediation with PK enrollment and BitLocker key backup
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -BitLockerBackupShare "\\fileserver\BitLockerKeys"

    # Assess all VMs - hypervisor-level data only (no guest credentials needed)
    .\FixSecureBootBulk.ps1 -Assess

    # Assess all VMs - full data including guest cert and registry status
    .\FixSecureBootBulk.ps1 -Assess -GuestCredential $cred

    # Assess specific VMs
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -Assess -GuestCredential $cred

    # Upgrade hardware version only (no NVRAM rename, no cert work)
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardwareOnly

    # Upgrade hardware version only without taking a snapshot
    .\FixSecureBootBulk.ps1 -VMName "vm01","vm02" -UpgradeHardwareOnly -NoSnapshot

    # Hypervisor-only remediation: snapshot + hardware upgrade + NVRAM rename (no guest steps)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -UpgradeHardware -Confirm

    # Full remediation including hardware version upgrade
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -UpgradeHardware

    # Skip NVRAM rename - use for VMs already created on ESXi 8.0.2+ or previously
    # remediated via another method (cert update triggering and PK enrollment only)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" -SkipNVRAMRename

    # Full remediation with BitLocker key backup to a file share
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -BitLockerBackupShare "\\fileserver\BitLockerKeys"

    # Same, but leave BitLocker suspended on completion (e.g. more maintenance follows)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -BitLockerBackupShare "\\fileserver\BitLockerKeys" -SkipBitLockerResume

    # Specify vCenter server on the command line (avoids prompt)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -vCenter "vcenter.yourdomain.com"

    # Connect to a vCenter with a self-signed or untrusted certificate
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -IgnoreCertificateWarnings

    # Increase Tools wait timeout for slow-booting VMs (default 90 seconds)
    .\FixSecureBootBulk.ps1 -VMName "slow-vm" -GuestCredential $cred `
        -RetainSnapshots -WaitSeconds 180

    # Increase graceful shutdown timeout (default 120 seconds). Use 0 to always
    # force hard power off without waiting for guest OS shutdown
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -GracefulShutdownTimeout 180

    # Add a delay between VMs for co-dependent workloads (e.g. DB then app server)
    .\FixSecureBootBulk.ps1 -VMName "AppDB01","AppServer01" -GuestCredential $cred `
        -RetainSnapshots -InterVMDelay 120

    # Provide a KEK certificate manually (only needed if KEK 2023 is absent after
    # NVRAM regeneration - should not be required on ESXi 8.0.2+)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -KEKDerPath ".\KEK-2023.der"

    # Allow PK remediation on vTPM-enabled Windows VMs (by default skipped per
    # Broadcom KB 423893 guidance, requires explicit opt-in). Review the
    # .PARAMETER AllowUnsupportedVTPMWindowsPKRemediation help before using.
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -AllowUnsupportedVTPMWindowsPKRemediation

    # Remediate a powered-off VM (by default skipped because BitLocker and guest
    # state cannot be verified safely, requires explicit opt-in)
    .\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -AllowPoweredOffVMRemediation

    # Hypervisor-only run that also targets non-Windows VMs (no -GuestCredential,
    # only NVRAM rename / hardware upgrade / snapshot run, no guest-side steps)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\linux-vms.csv" -UpgradeHardware `
        -AllowNonWindowsTargets -Confirm

    # Confirm a specific certificate is the live PK after enrollment by thumbprint
    # (stronger than the subject-based status label alone)
    .\FixSecureBootBulk.ps1 -VMListCsv ".\batch1.csv" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -ExpectedPKThumbprint "A1B2C3D4E5F6...."

    # Enroll a custom / organizational (non-Microsoft) PK. -AllowUnverifiedPKDer
    # bypasses the Microsoft WindowsOEMDevicesPK.der SHA-256 check, and
    # -ExpectedPKThumbprint confirms the intended certificate became the live PK.
    # The result classifies as Valid_CustomExpected (not a Microsoft PK).
    .\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\OrgCustomPK.der" `
        -AllowUnverifiedPKDer -ExpectedPKThumbprint "A1B2C3D4E5F6...."

    # Replace an existing valid PK that does not match the expected thumbprint.
    # Without -ReplaceExistingPK, a valid-but-non-matching PK is left in place and
    # reported for review. With it, the PK is re-enrolled via SetupMode against the
    # expected certificate (still subject to the vTPM-Windows and BitLocker gates).
    .\FixSecureBootBulk.ps1 -VMName "vm01" -GuestCredential $cred `
        -RetainSnapshots -PKDerPath ".\WindowsOEMDevicesPK.der" `
        -ExpectedPKThumbprint "A1B2C3D4E5F6...." -ReplaceExistingPK

.NOTES
    Certificate expiration dates (per Microsoft KB 5062710, updated May 18, 2026):
      Microsoft Corporation KEK CA 2011      expires June 24, 2026    (replaced by Microsoft Corporation KEK 2K CA 2023, KEK)
      Microsoft UEFI CA 2011                 expires June 27, 2026    (replaced by Microsoft UEFI CA 2023, DB)
      Microsoft UEFI CA 2011                 expires June 27, 2026    (replaced by Microsoft Option ROM UEFI CA 2023, DB)
      Microsoft Windows Production PCA 2011   expires October 19, 2026 (replaced by Windows UEFI CA 2023, DB)
    The KEK CA 2011 expiry (June 24, 2026) is the near-term driver: it signs DB/DBX
    updates, so the 2023 KEK must be enrolled before then for future Secure Boot
    updates to validate. VMs continue to boot normally after expiry (Secure Boot
    does not check certificate expiration). The impact is on future boot-chain
    security updates.

    Do not include domain controllers in automated runs - handle DCs manually.
    VMs with BitLocker active will be skipped unless -BitLockerBackupShare is
    provided, in which case recovery keys are backed up to the share and
    BitLocker is suspended for the duration of the process.
    PK remediation (-PKDerPath) requires ESXi 8.0+ hosts. VMs with a proper
    Microsoft or OEM PK (Valid_WindowsOEM / Valid_Microsoft) are skipped for the
    PK step automatically. ESXi-generated placeholder PKs (Valid_Other) are treated
    as needing enrollment per Broadcom KB 423919.
    PK remediation prefers the script-supported paths and applies them first: the
    silent PK update on ESXi 8.0 P09 (U3j) vTPM-disabled Windows VMs, and UEFI
    SetupMode enrollment as the automated fallback (reaching the same end state as
    the manual vUEFI method in KB 423919, implemented by this script rather than
    the KB's manual workflow). Broadcom documents the resetOnce VMX path for
    vTPM-enabled Linux and other non-Windows VMs, but this script does not perform
    Linux guest-side PK enrollment. The NVRAM regeneration is the unsupported fallback for the KEK and
    DB certificates and is refused by -SupportedMethodsOnly or -SkipNVRAMRename.
    The output CSV records the method used per VM in the PKMethod and CertMethod
    columns.
    References: Broadcom KB 423893, KB 423919, Microsoft KB 5062710,
    Microsoft secureboot_objects GitHub.
    Ensure sufficient datastore space for snapshots before running large batches.
    Requires VMware.PowerCLI module and an active vCenter connection, or
    the script will prompt for vCenter credentials on first run.
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter','VMName', Justification='VMName is read by Resolve-TargetVMs via PowerShell dynamic scoping at script scope. PSScriptAnalyzer does not credit nested-function reads of script-level parameters, so this is a false positive.')]
param(
    [string[]]$VMName,
    [string]$VMListCsv,
    [PSCredential]$GuestCredential,
    [switch]$NoSnapshot,
    [switch]$SkipNVRAMRename,
    [switch]$SupportedMethodsOnly,
    [switch]$AllowUnsupportedVTPMWindowsPKRemediation,
    [switch]$AllowPoweredOffVMRemediation,
    [switch]$AllowNonWindowsTargets,
    [switch]$Confirm,
    [switch]$RetainSnapshots,
    [switch]$CleanupSnapshots,
    [switch]$CleanupHWSnapshots,
    [switch]$CleanupNvram,
    [switch]$Rollback,
    [string]$BitLockerBackupShare,
    [switch]$SkipBitLockerResume,
    [string]$PKDerPath,
    [string]$KEKDerPath,
    [switch]$AllowUnverifiedPKDer,
    [string]$ExpectedPKThumbprint,
    [switch]$ReplaceExistingPK,
    [int]$WaitSeconds = 90,
    [int]$InterVMDelay = 0,
    [int]$GracefulShutdownTimeout = 120,
    [switch]$IgnoreCertificateWarnings,
    [string]$vCenter,
    [switch]$Assess,
    [switch]$UpgradeHardwareOnly,
    [switch]$UpgradeHardware
)

$ScriptVersion = "v2.0.0 / 2026-06-18"

# =============================================================================
# PARAMETER VALIDATION
# =============================================================================
if ($NoSnapshot -and $RetainSnapshots) {
    Write-Error "-NoSnapshot and -RetainSnapshots cannot be used together."
    return
}

# Cleanup switches can be combined freely with each other.
$cleanupCount = @($CleanupSnapshots, $CleanupHWSnapshots, $CleanupNvram) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
$nonCleanupCount = @($Rollback, $Assess) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
if ($cleanupCount -gt 0 -and $nonCleanupCount -gt 0) {
    Write-Error "-CleanupSnapshots, -CleanupHWSnapshots, and -CleanupNvram cannot be combined with -Rollback or -Assess."
    return
}
if ($nonCleanupCount -gt 1) {
    Write-Error "-Rollback and -Assess are mutually exclusive."
    return
}
if ($Assess -and ($NoSnapshot -or $RetainSnapshots -or $BitLockerBackupShare -or $PKDerPath -or $KEKDerPath -or $AllowUnverifiedPKDer -or $ExpectedPKThumbprint -or $ReplaceExistingPK -or $SkipBitLockerResume -or $SkipNVRAMRename -or $SupportedMethodsOnly)) {
    Write-Error "-Assess is read-only and cannot be combined with -NoSnapshot, -RetainSnapshots, -BitLockerBackupShare, -PKDerPath, -KEKDerPath, -AllowUnverifiedPKDer, -ExpectedPKThumbprint, -ReplaceExistingPK, -SkipBitLockerResume, -SkipNVRAMRename, or -SupportedMethodsOnly."
    return
}
if ($UpgradeHardware -and ($CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram -or $Rollback -or $Assess)) {
    Write-Error "-UpgradeHardware cannot be combined with -CleanupSnapshots, -CleanupHWSnapshots, -CleanupNvram, -Rollback, or -Assess."
    return
}

# Mode variables - assigned first, before ALL compatibility checks and path validation.
$isActionMode        = $CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram -or $Rollback -or $Assess
$isHardwareOnly      = $UpgradeHardwareOnly -and -not $isActionMode
$isMainMode          = -not $isActionMode -and -not $isHardwareOnly
$isStandaloneUpgrade = $isHardwareOnly

# Mode incompatibility checks - all before path validation so they fire first.
if ($UpgradeHardwareOnly -and $UpgradeHardware) {
    Write-Error "-UpgradeHardwareOnly and -UpgradeHardware cannot be combined."
    return
}
if ($UpgradeHardwareOnly -and ($CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram -or $Rollback -or $Assess)) {
    Write-Error "-UpgradeHardwareOnly cannot be combined with cleanup, rollback, or assess modes."
    return
}
if ($UpgradeHardwareOnly -and ($PKDerPath -or $KEKDerPath -or $BitLockerBackupShare -or $SkipNVRAMRename -or $SupportedMethodsOnly -or $AllowUnsupportedVTPMWindowsPKRemediation -or $AllowUnverifiedPKDer -or $ExpectedPKThumbprint -or $ReplaceExistingPK -or $SkipBitLockerResume)) {
    Write-Error "-UpgradeHardwareOnly cannot be combined with remediation-specific switches (-PKDerPath, -KEKDerPath, -BitLockerBackupShare, -SkipNVRAMRename, -SupportedMethodsOnly, -AllowUnsupportedVTPMWindowsPKRemediation, -AllowUnverifiedPKDer, -ExpectedPKThumbprint, -ReplaceExistingPK, -SkipBitLockerResume)."
    return
}
if ($UpgradeHardwareOnly -and $GuestCredential) {
    Write-Warning "-UpgradeHardwareOnly performs hardware upgrade only - -GuestCredential will not be used."
}
if ($AllowNonWindowsTargets -and $GuestCredential) {
    Write-Error "-AllowNonWindowsTargets is supported only in hypervisor-only mode (no -GuestCredential). Remove -GuestCredential or remove -AllowNonWindowsTargets."
    return
}
# Reject PK-remediation-specific switches in cleanup and rollback modes, where
# they have no effect. (Assess and UpgradeHardwareOnly are already guarded above.)
if (($CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram -or $Rollback) -and
    ($PKDerPath -or $KEKDerPath -or $AllowUnverifiedPKDer -or $ExpectedPKThumbprint -or $ReplaceExistingPK -or $BitLockerBackupShare -or $AllowUnsupportedVTPMWindowsPKRemediation -or $SkipBitLockerResume -or $SkipNVRAMRename -or $SupportedMethodsOnly)) {
    Write-Error "Cleanup and rollback modes cannot be combined with remediation-specific switches (-PKDerPath, -KEKDerPath, -AllowUnverifiedPKDer, -ExpectedPKThumbprint, -ReplaceExistingPK, -BitLockerBackupShare, -AllowUnsupportedVTPMWindowsPKRemediation, -SkipBitLockerResume, -SkipNVRAMRename, -SupportedMethodsOnly)."
    return
}
# -ReplaceExistingPK and -AllowUnverifiedPKDer require -PKDerPath to do anything.
if ($ReplaceExistingPK -and -not $PKDerPath) {
    Write-Error "-ReplaceExistingPK requires -PKDerPath (the replacement certificate to enroll)."
    return
}
if ($ReplaceExistingPK -and -not $ExpectedPKThumbprint) {
    Write-Error "-ReplaceExistingPK requires -ExpectedPKThumbprint (the target certificate thumbprint that an existing PK is compared against)."
    return
}
if ($AllowUnverifiedPKDer -and -not $PKDerPath) {
    Write-Warning "-AllowUnverifiedPKDer has no effect without -PKDerPath. Ignoring."
}
if ($isMainMode -and ($SkipNVRAMRename -or $SupportedMethodsOnly) -and -not $GuestCredential -and -not $UpgradeHardware) {
    $noWorkSwitch = if ($SupportedMethodsOnly) { "-SupportedMethodsOnly" } else { "-SkipNVRAMRename" }
    Write-Error "$noWorkSwitch without -GuestCredential and without -UpgradeHardware has no actionable work. Both switches suppress the NVRAM regeneration, so the remaining cert and PK work requires -GuestCredential. Use -GuestCredential for cert/PK work, add -UpgradeHardware, or remove the switch."
    return
}
if ($SupportedMethodsOnly -and $SkipNVRAMRename) {
    Write-Warning "-SkipNVRAMRename is redundant with -SupportedMethodsOnly. Both suppress the NVRAM regeneration."
}
if ($SupportedMethodsOnly -and $AllowUnsupportedVTPMWindowsPKRemediation) {
    Write-Warning "-SupportedMethodsOnly refuses -AllowUnsupportedVTPMWindowsPKRemediation. PK updates on vTPM-enabled Windows VMs remain unsupported per KB 423893. These VMs will be skipped pending the Capsule solution."
    $AllowUnsupportedVTPMWindowsPKRemediation = $false
}
if ($isMainMode -and $SkipBitLockerResume -and (-not $BitLockerBackupShare -or -not $GuestCredential)) {
    Write-Warning "-SkipBitLockerResume has no effect unless the script both suspends BitLocker and could resume it, which requires -GuestCredential and -BitLockerBackupShare together. Without both, no BitLocker suspend or resume occurs."
}

# Path validation - runs after all mode/incompatibility checks.
if ($BitLockerBackupShare) {
    if (-not (Test-Path $BitLockerBackupShare)) {
        Write-Error "BitLockerBackupShare path not accessible: $BitLockerBackupShare"
        return
    }
    Write-Host "BitLocker backup share: $BitLockerBackupShare" -ForegroundColor Yellow
    Write-Warning "Recovery keys written to this share are sensitive."
    Write-Host ""
}
# Mode variables must be assigned before any validation that depends on them.
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
# KEK enrollment is performed only during the PK SetupMode remediation path, so
# -KEKDerPath is meaningless on its own. Require -PKDerPath to accompany it rather
# than silently ignoring the KEK file.
if ($KEKDerPath -and -not $PKDerPath) {
    Write-Error "-KEKDerPath requires -PKDerPath. KEK enrollment is performed only during the PK SetupMode remediation path. There is no KEK-only remediation mode in this version."
    return
}

# -----------------------------------------------------------------------------
# DER file integrity verification
# -----------------------------------------------------------------------------
# The PK (and optional KEK) DER files are downloaded independently of this script,
# so they are the one input the script cannot implicitly trust. A tampered or
# substituted PK certificate enrolled into firmware would be a serious compromise.
# The script verifies the supplied PK DER against the known SHA-256 of Microsoft's
# published WindowsOEMDevicesPK.der before it will enroll it.
#
# Source of the expected hash: Microsoft secureboot_objects repository,
#   PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der
# Verify independently with: Get-FileHash -Algorithm SHA256 .\WindowsOEMDevicesPK.der
$ExpectedPKDerSHA256  = "2F569E8EDAF9657DC4951C29598725255C7F821472DB71374211FE44D082546F"
# KEK 2023 DER hash is not pinned by default (the KEK path is rarely needed and
# only used if KEK 2023 is absent after NVRAM regeneration). Populate this with
# Microsoft's published KEK 2023 DER SHA-256 to enforce KEK verification too.
$ExpectedKEKDerSHA256 = ""

if ($PKDerPath) {
    $pkActualHash = (Get-FileHash -Path $PKDerPath -Algorithm SHA256).Hash.ToUpperInvariant()
    $pkExpected   = $ExpectedPKDerSHA256.ToUpperInvariant()
    if ($pkActualHash -eq $pkExpected) {
        Write-Host "PK der file : $PKDerPath" -ForegroundColor Cyan
        Write-Host "  SHA-256 verified against Microsoft WindowsOEMDevicesPK.der." -ForegroundColor Green
    } elseif ($AllowUnverifiedPKDer) {
        Write-Warning "PK der SHA-256 does NOT match the known Microsoft WindowsOEMDevicesPK.der."
        Write-Warning "  Expected: $pkExpected"
        Write-Warning "  Actual:   $pkActualHash"
        Write-Warning "  Proceeding anyway because -AllowUnverifiedPKDer was specified."
        Write-Warning "  This is appropriate only if you are intentionally enrolling a custom/organizational PK."
        $script:PKDerUnverified = $true
    } else {
        Write-Error "PK der SHA-256 does NOT match the known Microsoft WindowsOEMDevicesPK.der and -AllowUnverifiedPKDer was not specified."
        Write-Error "  Expected: $pkExpected"
        Write-Error "  Actual:   $pkActualHash"
        Write-Error "  The file may be corrupted, the wrong file, or substituted. Re-download from:"
        Write-Error "    https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
        Write-Error "  If you are intentionally enrolling a different (custom/organizational) PK, re-run with -AllowUnverifiedPKDer."
        return
    }
}

# KEK DER integrity verification. Separate from the PK block so the KEK file is
# always validated when supplied (it has already been confirmed to accompany
# -PKDerPath above). The KEK 2023 hash is not pinned by default. Populate
# $ExpectedKEKDerSHA256 to enforce it.
if ($KEKDerPath) {
    if ([string]::IsNullOrWhiteSpace($ExpectedKEKDerSHA256)) {
        Write-Host "KEK der file: $KEKDerPath" -ForegroundColor Cyan
        Write-Warning "  KEK der SHA-256 verification is not configured (no pinned hash). Proceeding without KEK integrity check."
    } else {
        $kekActualHash = (Get-FileHash -Path $KEKDerPath -Algorithm SHA256).Hash.ToUpperInvariant()
        $kekExpected   = $ExpectedKEKDerSHA256.ToUpperInvariant()
        if ($kekActualHash -eq $kekExpected) {
            Write-Host "KEK der file: $KEKDerPath" -ForegroundColor Cyan
            Write-Host "  SHA-256 verified against pinned KEK 2023 DER." -ForegroundColor Green
        } elseif ($AllowUnverifiedPKDer) {
            Write-Warning "KEK der SHA-256 does NOT match the pinned KEK 2023 DER. Proceeding (-AllowUnverifiedPKDer)."
            Write-Warning "  Expected: $kekExpected"
            Write-Warning "  Actual:   $kekActualHash"
        } else {
            Write-Error "KEK der SHA-256 does NOT match the pinned KEK 2023 DER and -AllowUnverifiedPKDer was not specified."
            Write-Error "  Expected: $kekExpected"
            Write-Error "  Actual:   $kekActualHash"
            return
        }
    }
}

# =============================================================================
# VCENTER CONNECTION
# Pass -vCenter to specify the server name on the command line.
# If -vCenter is not provided and no connection is active, the script will prompt.
# =============================================================================
if (-not $global:DefaultVIServer) {
    if ($IgnoreCertificateWarnings) {
        Write-Warning "-IgnoreCertificateWarnings specified: disabling certificate validation for this session."
        Write-Warning "Only use this flag if your vCenter certificate is self-signed or untrusted and you have accepted that risk."
        Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Scope Session -Confirm:$false
    }
    $vcServer = if ($vCenter) { $vCenter } else { Read-Host "vCenter server hostname or IP" }
    Connect-VIServer -Server $vcServer -Credential (Get-Credential -Message "vCenter credentials")
}

Write-Host "FixSecureBootBulk.ps1 $ScriptVersion" -ForegroundColor Cyan

# Support status notice - shown only when the run may perform NVRAM rename.
# Assess, cleanup, rollback, and hardware-only modes do not rename NVRAM so
# the unsupported-path warning is not relevant.
$willPotentiallyRenameNvram = $isMainMode -and -not $SkipNVRAMRename -and -not $SupportedMethodsOnly
if ($willPotentiallyRenameNvram) {
Write-Host ""
Write-Host "  IMPORTANT: Support Status Notice" -ForegroundColor Yellow
Write-Host "  =================================" -ForegroundColor Yellow
Write-Host "  This run may perform an NVRAM regeneration (rename of the .nvram file so" -ForegroundColor Yellow
Write-Host "  ESXi rebuilds it with the 2023 certificates). A Broadcom employee has" -ForegroundColor Yellow
Write-Host "  stated in the Broadcom community forums that renaming or deleting the" -ForegroundColor Yellow
Write-Host "  NVRAM file is NOT endorsed by VMware engineering and is NOT supported," -ForegroundColor Yellow
Write-Host "  and KB 423919 was updated to warn that deleting NVRAM can lead to" -ForegroundColor Yellow
Write-Host "  unexpected VM corruption. This script uses it only as a fallback for the" -ForegroundColor Yellow
Write-Host "  KEK and DB certificates when the guest OS cannot deliver them. Use at" -ForegroundColor Yellow
Write-Host "  your own risk, or pass -SupportedMethodsOnly (or -SkipNVRAMRename) to" -ForegroundColor Yellow
Write-Host "  refuse the regeneration entirely." -ForegroundColor Yellow
Write-Host "  Supported PK methods are preferred and applied first: silent reboot on" -ForegroundColor Cyan
Write-Host "  ESXi 8.0 P09 (U3j) vTPM-disabled Windows VMs, then UEFI SetupMode" -ForegroundColor Cyan
Write-Host "  enrollment (the automation of the manual vUEFI method in KB 423919) as the" -ForegroundColor Cyan
Write-Host "  fallback. The resetOnce VMX path is Broadcom-documented for vTPM-enabled" -ForegroundColor Cyan
Write-Host "  Linux and other non-Windows VMs, but this script does not perform Linux" -ForegroundColor Cyan
Write-Host "  guest PK enrollment. For vTPM-enabled Windows VMs Broadcom recommends" -ForegroundColor Cyan
Write-Host "  waiting for the forthcoming capsule solution, so this script skips them by" -ForegroundColor Cyan
Write-Host "  default. Use -AllowUnsupportedVTPMWindowsPKRemediation to override after" -ForegroundColor Cyan
Write-Host "  reviewing the risk." -ForegroundColor Cyan
Write-Host "  Reference: https://community.broadcom.com/vmware-cloud-foundation/discussion/uefi-2023-fully-automated-script-also-with-plattform-key-change" -ForegroundColor Gray
Write-Host "  Reference: https://knowledge.broadcom.com/external/article/423919" -ForegroundColor Gray
Write-Host "  Reference: https://knowledge.broadcom.com/external/article/423893" -ForegroundColor Gray
Write-Host ""
if (-not $Confirm) {
    $ack = Read-Host "  I understand and accept the risk. Continue? (Y/N)"
    if ($ack -notmatch '^[Yy]') {
        Write-Host "Aborted." -ForegroundColor Red
        return
    }
}
}
if ($isMainMode -and -not $GuestCredential) {
    Write-Host "  Note: -GuestCredential not provided. Running in hypervisor-only mode." -ForegroundColor Yellow
    Write-Host "        Guest-level steps (BitLocker check, cert update trigger, verification," -ForegroundColor Yellow
    Write-Host "        PK enrollment) will be skipped. Only hypervisor-level steps (snapshot," -ForegroundColor Yellow
    Write-Host "        HW upgrade, NVRAM rename, power cycle) will run." -ForegroundColor Yellow
    if ($AllowNonWindowsTargets) {
        Write-Host "        Non-Windows targets: complete OS-specific Secure Boot/PK remediation" -ForegroundColor Yellow
        Write-Host "        using Broadcom or OS-vendor guidance per KB 423893." -ForegroundColor Yellow
    } else {
        Write-Host "        Re-run with -GuestCredential to complete cert update and PK enrollment." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Warning "  HYPERVISOR-ONLY MODE: The script cannot check BitLocker status, suspend"
    Write-Warning "  BitLocker, back up recovery keys, or verify guest Secure Boot cert state."
    Write-Warning "  If BitLocker or other TPM-sealed protection is active on any target VM,"
    Write-Warning "  NVRAM/firmware changes may trigger BitLocker recovery mode."
    Write-Warning "  Ensure recovery keys are backed up and protection is suspended by another"
    Write-Warning "  process before proceeding."
    Write-Host ""
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
                  Select-Object -ExpandProperty VMName
    # Deduplicate while preserving input order
    $seen = @{}; $csvVMNames = $csvVMNames | Where-Object { -not $seen[$_] -and ($seen[$_] = $true) }
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
    # Deduplicate while preserving input order
    $seen = @{}; $names = $names | Where-Object { -not $seen[$_] -and ($seen[$_] = $true) }

    if ($names.Count -gt 0) {
        # When specific VM names are provided, look them up directly in the order given.
        # Do not apply OS or Secure Boot filters - the operator has explicitly
        # named the target VMs and guest info may be stale after a revert or reboot.
        $resolved = foreach ($name in $names) {
            $found = Get-VM -Name $name -ErrorAction SilentlyContinue
            if (-not $found) {
                Write-Warning "VM not found in vCenter: '$name' - skipping."
            }
            $found
        }
        # Filter nulls, preserve order without sorting
        $seenIds = @{}
        $resolved = $resolved | Where-Object { $_ -and -not $seenIds[$_.Id] -and ($seenIds[$_.Id] = $true) }
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

# Attempts a graceful guest OS shutdown via VMware Tools (equivalent to
# clicking Shut Down in Windows). Waits up to $GracefulShutdownTimeout seconds
# for the VM to power off. Falls back to hard power off if the timeout expires
# or if Tools is not running. Set $GracefulShutdownTimeout to 0 to always use
# hard power off.
function Stop-VMGraceful {
    param(
        [Parameter(Mandatory)][VMware.VimAutomation.ViCore.Types.V1.Inventory.VirtualMachine]$VM,
        [int]$TimeoutSeconds = 120
    )

    $vmId = $VM.Id   # captured before any branch so hard-poweroff fallback can use it

    if ($TimeoutSeconds -gt 0 -and $VM.Guest.State -eq "Running") {
        Write-Host "    Requesting graceful shutdown..." -ForegroundColor Cyan
        try {
            Stop-VMGuest -VM $VM -Confirm:$false -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "    Graceful shutdown request failed ($($_.Exception.Message)) - falling back to hard power off."
            $TimeoutSeconds = 0
        }

        $elapsed = 0
        while ($TimeoutSeconds -gt 0 -and $elapsed -lt $TimeoutSeconds) {
            Start-Sleep -Seconds 5
            $elapsed += 5
            $VM = Get-VM -Id $vmId -ErrorAction SilentlyContinue
            if ($VM -and $VM.PowerState -eq "PoweredOff") {
                Write-Host "    Guest shutdown complete." -ForegroundColor Green
                return
            }
        }

        if ($TimeoutSeconds -gt 0) {
            Write-Warning "    Graceful shutdown timed out after ${TimeoutSeconds}s - falling back to hard power off."
        }
    }

    # Hard power off fallback - use $vmId captured at function entry for safe refresh
    $VM = Get-VM -Id $vmId -ErrorAction SilentlyContinue
    if ($VM -and $VM.PowerState -ne "PoweredOff") {
        Stop-VM -VM $VM -Confirm:$false -Kill -ErrorAction Stop | Out-Null
    }
}

function Wait-VMTools {
    param($VMObj, [int]$TimeoutSeconds = 300)
    $elapsed = 0
    $vmId    = $VMObj.Id
    Write-Host "    Waiting for VMware Tools..." -ForegroundColor Gray
    while ($elapsed -lt $TimeoutSeconds) {
        $current = Get-VM -Id $vmId -ErrorAction SilentlyContinue
        if ($current -and $current.Guest.State -eq "Running") {
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

# After a SetupMode reboot, VMware Tools sets Guest.State = "Running" early but
# GuestFamily and HostName are populated asynchronously 15-20 seconds later.
# Copy-VMGuestFile requires a fully populated GuestInfo context and fails with
# "guest OS unknown" / "A specified parameter was not correct" if GuestFamily or
# HostName are still empty. This function polls until all three fields are set.
# Called in [PK 2/5] after Wait-VMTools before Copy-VMGuestFile in [PK 3/5].
# Root cause diagnosis and fix contributed by @thezeus123 (GitHub issue #8).
function Wait-GuestIdKnown {
    param($VMObj, [int]$TimeoutSeconds = 180)
    $elapsed = 0
    $vmId    = $VMObj.Id
    Write-Host "    Waiting for full guest context (GuestId + GuestFamily + HostName)..." -ForegroundColor Gray
    while ($elapsed -lt $TimeoutSeconds) {
        $current    = Get-VM -Id $vmId -ErrorAction SilentlyContinue
        if (-not $current) {
            Start-Sleep -Seconds 5; $elapsed += 5; continue
        }
        $guestId    = $current.GuestId
        $guestFam   = $current.Guest.GuestFamily
        $hostName   = $current.Guest.HostName
        $guestIdOk  = $guestId  -and $guestId  -notmatch "other|unknown"
        $guestFamOk = $guestFam -and $guestFam -notmatch "other|unknown"
        $hostNameOk = $hostName -and $hostName -ne ""
        if ($guestIdOk -and $guestFamOk -and $hostNameOk) {
            Write-Host "    Guest context confirmed: GuestId=$guestId | Family=$guestFam | Host=$hostName" -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 5
        $elapsed += 5
        Write-Host ("    ...${elapsed}s (GuestId={0} | Family={1} | HostName={2})" -f
            $(if ($guestId)  { $guestId  } else { "?" }),
            $(if ($guestFam) { $guestFam } else { "?" }),
            $(if ($hostName) { $hostName } else { "?" })) -ForegroundColor DarkGray
    }
    Write-Warning "    Timed out waiting for full guest context on $($VMObj.Name) - proceeding anyway."
    return $false
}

function New-VMSnapshotSafe {
    param($VMObj, [string]$Name, [string]$Description)
    try {
        New-Snapshot -VM $VMObj -Name $Name -Description $Description `
            -Memory:$false -Quiesce:$false -Confirm:$false -ErrorAction Stop | Out-Null
        Write-Host "    Snapshot created: '$Name'" -ForegroundColor Green
        return [PSCustomObject]@{ Success = $true; Error = $null }
    } catch {
        $msg = $_.Exception.Message
        Write-Warning "    Snapshot failed: $msg"
        return [PSCustomObject]@{ Success = $false; Error = $msg }
    }
}

function Remove-VMSnapshotSafe {
    param($VMObj, [string]$Name)
    try {
        $snap = Get-Snapshot -VM $VMObj -Name $Name -ErrorAction SilentlyContinue
        if ($snap) {
            Remove-Snapshot -Snapshot $snap -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host "    Snapshot removed: '$Name'" -ForegroundColor Green
            return $true
        }
        # Snapshot not found - treat as already gone (not an error)
        Write-Host "    Snapshot '$Name' not found, treating as already removed." -ForegroundColor Gray
        return $true
    } catch {
        Write-Warning "    Could not remove snapshot '$Name': $($_.Exception.Message)"
        Write-Warning "    Remove manually via vSphere client when ready."
        return $false
    }
}

# Resolves the datastore that contains the VM's VMX/NVRAM file by matching the
# datastore name from Config.Files.VmPathName against the VM's attached datastore
# MoRef list. This ensures the correct datastore is used when a VM spans multiple
# datastores or when two datastores share the same name in different clusters.
function Resolve-VMXDatastore {
    param($VMObj, $VMViewObj)
    $vmxPath = $VMViewObj.Config.Files.VmPathName
    $dsName  = $vmxPath -replace '^\[(.+?)\].*', '$1'

    # Iterate the VM's attached datastores and find the one whose name matches
    # the VMX path. Using the MoRef guarantees we get the correct datastore even
    # when duplicate names exist in the vCenter inventory.
    foreach ($ref in $VMViewObj.Datastore) {
        $candidate = Get-Datastore -Id $ref -ErrorAction SilentlyContinue
        if ($candidate -and $candidate.Name -eq $dsName) {
            return $candidate
        }
    }

    # Fallback: no MoRef matched by name - warn and try name lookup.
    Write-Warning "Resolve-VMXDatastore: could not match VMX datastore '$dsName' by MoRef for $($VMObj.Name). Falling back to name lookup (may be wrong if duplicate datastore names exist)."
    return Get-Datastore -Name $dsName -ErrorAction Stop | Select-Object -First 1
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

    # Use Resolve-VMXDatastore to find the correct datastore by MoRef match.
    $ds = Resolve-VMXDatastore -VMObj $VMObj -VMViewObj $vmView

    # Check for a custom nvram = path in the VMX ExtraConfig. When set, the
    # NVRAM file may have a non-default name and the script must use that name
    # rather than assuming *.nvram matches only the active file.
    $nvramSetting = $vmView.Config.ExtraConfig | Where-Object { $_.Key -eq "nvram" }
    $customNvramName = if ($nvramSetting) { $nvramSetting.Value } else { $null }

    $datacenter      = Get-Datacenter -VM $VMObj
    $datacenterView  = $datacenter | Get-View
    $serviceInstance = Get-View ServiceInstance

    return @{
        DsName          = $dsName
        VmDir           = $vmDir
        DsBrowser       = Get-View $ds.ExtensionData.Browser
        DcRef           = $datacenterView.MoRef
        FileManager     = Get-View $serviceInstance.Content.FileManager
        CustomNvramName = $customNvramName
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

# Upgrades VM hardware version. In main-mode (-UpgradeHardware) only upgrades
# VMs below HW21 to meet the Secure Boot 2023 KEK requirement. In hardware-only
# mode (-UpgradeHardwareOnly) also upgrades only VMs below HW21. Both modes use
# the same HW21 minimum target for the Secure Boot remediation workflow.
# Returns a hashtable: { Upgraded = $true/$false; FromVersion = N; ToVersion = N; Notes = "" }
function Invoke-VMHardwareUpgrade {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$VMObj,
        [int]$TargetVersion,
        [int]$TimeoutSeconds = 120
    )
    $result = [ordered]@{ Upgraded = $false; FromVersion = $null; ToVersion = $null; Notes = "" }
    try {
        $vmView     = $VMObj | Get-View -ErrorAction Stop
        $currentVer = $vmView.Config.Version
        $currentNum = [int]($currentVer -replace '^vmx-', '')
        $result.FromVersion = $currentNum

        if (-not $PSBoundParameters.ContainsKey('TargetVersion')) {
            throw "TargetVersion is required. Call Get-MaxHWVersionForHost first to determine the correct target."
        }

        $result.ToVersion = $TargetVersion

        if ($currentNum -ge $TargetVersion) {
            $result.Notes = "Already at version $currentNum or higher."
            return [pscustomobject]$result
        }

        Write-Host "    Upgrading hardware version: vmx-$currentNum -> vmx-$TargetVersion" -ForegroundColor Gray
        $taskMoRef = $vmView.UpgradeVM_Task("vmx-$TargetVersion")
        $taskView  = Get-View -Id $taskMoRef -ErrorAction Stop
        $elapsed   = 0
        while ($taskView.Info.State -in @("running","queued")) {
            if ($elapsed -ge $TimeoutSeconds) { throw "Timed out waiting for hardware upgrade task." }
            Start-Sleep -Seconds 3
            $elapsed += 3
            $taskView = Get-View -Id $taskMoRef
        }
        if ($taskView.Info.State -eq "success") {
            $vmView = Get-VM -Id $VMObj.Id -ErrorAction Stop | Get-View -ErrorAction Stop
            $newNum = [int]($vmView.Config.Version -replace '^vmx-', '')
            $result.ToVersion = $newNum
            $result.Upgraded  = $true
            $result.Notes     = "Hardware upgraded successfully."
            Write-Host "    Hardware version upgraded to vmx-$newNum." -ForegroundColor Green
        } else {
            $err = $taskView.Info.Error.LocalizedMessage
            if (-not $err) { $err = "Unknown task error." }
            $result.Notes = "Upgrade failed: $err"
            Write-Warning "    $($result.Notes)"
        }
    } catch {
        $result.Notes = "Upgrade error: $($_.Exception.Message)"
        Write-Warning "    $($result.Notes)"
    }
    [pscustomobject]$result
}

# Returns the maximum hardware version supported by the ESXi host a VM is
# running on. Uses the ESXi version string as the source of truth since the
# PowerCLI capability object properties for HW version are not consistently
# populated across all vCenter/PowerCLI versions.
# Returns $true if the VM is running on ESXi 8.0 P09 or later (8.0 U3j, build 25429389+).
# ESXi 8.0 P09 introduced silent PK update on reboot for vTPM-disabled VMs and the
# uefi.secureBoot.PK.resetOnce VMX parameter path for Linux/non-Windows vTPM-enabled
# VMs. This script automates the silent-reboot path and, on the Windows override
# path only, the resetOnce path. It does not perform resetOnce for Linux guests.
function Get-IsP09Host {
    param($VMObj)
    try {
        $vmHost = Get-VMHost -VM $VMObj -ErrorAction Stop
        return ($vmHost.Version -like "8.0.*" -and [int]$vmHost.Build -ge 25429389)
    } catch {
        return $false
    }
}

function Test-ExpectedPKThumbprint {
    # Compares a live PK thumbprint against the operator-supplied expected value.
    # Normalizes both sides (strip non-hex, uppercase) so values copied from
    # certificate dialogs (with spaces or colons) compare correctly. Returns
    # $true when the expected value is empty/not supplied (nothing to enforce) or
    # when the thumbprints match, $false only on a real mismatch.
    param(
        [string]$Expected,
        [string]$Actual
    )
    if ([string]::IsNullOrWhiteSpace($Expected)) { return $true }
    $e = ($Expected -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    $a = (("" + $Actual) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    return ($a -eq $e)
}

function Get-MaxHWVersionForHost {
    param($VMObj)
    try {
        $vmHost  = Get-VMHost -VM $VMObj -ErrorAction Stop
        $esxiVer = [version]$vmHost.Version

        if ($esxiVer.Major -ge 9) { return 22 }

        if ($esxiVer.Major -eq 8) {
            # HW21 support requires ESXi 8.0.2 or later for this Secure Boot
            # remediation workflow. 8.0.0 and 8.0.1 do not regenerate NVRAM with
            # 2023 certificates and should not be treated as HW21-capable here.
            if ($esxiVer -ge [version]"8.0.2") { return 21 }
            Write-Warning "Get-MaxHWVersionForHost: ESXi $esxiVer ($($VMObj.Name)) is below 8.0.2 - returning 0. NVRAM regeneration with 2023 certs requires ESXi 8.0.2+."
            return 0
        }

        if ($esxiVer.Major -eq 7) { return 19 }

        Write-Warning "Get-MaxHWVersionForHost: unrecognized ESXi major version $($esxiVer.Major) for $($VMObj.Name) - returning 0 (caller will skip)."
        return 0
    } catch {
        Write-Warning "Get-MaxHWVersionForHost: could not determine ESXi host version for $($VMObj.Name) - returning 0 (caller will skip)."
        return 0
    }
}

# Returns datastore name, free space, estimated snapshot size, and whether
# there is sufficient space for a snapshot of this VM.
# Snapshot size estimate: sum of committed (written) bytes across all VM disks
# on the datastore. This represents the worst-case snapshot growth if every
# block is overwritten during the remediation window. In practice snapshots
# will be much smaller, so this is a conservative upper bound.
# Warns if estimated snapshot exceeds the configured threshold of free space.
# Formats a byte count into a human-readable string at the most appropriate unit.
# Removes a list of snapshot items in parallel across hosts, serializing within
# shared datastores to avoid competing I/O consolidation on the same storage.
# Items with Skip=$true are passed through without removal.
# Returns result PSObjects with Type, VMName, VMId, Item, SizeMB, Result, Notes.
function Remove-SnapshotsParallel {
    param(
        [System.Collections.Generic.List[PSObject]]$Items,
        [string]$TypeLabel,
        [int]$TaskTimeoutSeconds = 300
    )
    $results = [System.Collections.Generic.List[PSObject]]::new()

    # Separate skipped items immediately
    $toRemove = $Items | Where-Object { -not $_.Skip }
    foreach ($item in ($Items | Where-Object { $_.Skip })) {
        $results.Add([PSCustomObject]@{
            Type   = $TypeLabel
            VMName = $item.VMName
            VMId   = $item.VMId
            Item   = $item.SnapName
            SizeMB = $item.SizeMB
            Result = "Skipped"
            Notes  = $item.Notes
        })
    }

    if (-not $toRemove) { return $results }

    # Group by datastore. Work items now carry DsName populated at build time to
    # avoid re-resolving VMs by display name (which can match wrong VM if duplicate
    # names exist). DsName falls back to "unknown" only if field is absent.
    $dsGroups = @{}
    foreach ($item in $toRemove) {
        $ds = if ($item.PSObject.Properties['DsName'] -and $item.DsName) { $item.DsName } else { "unknown" }
        if (-not $dsGroups.ContainsKey($ds)) { $dsGroups[$ds] = [System.Collections.Generic.List[PSObject]]::new() }
        $dsGroups[$ds].Add($item)
    }

    # Fire the first item in each datastore group async, then process remaining
    # items in that group sequentially once the first completes.
    # This gives parallelism across hosts/datastores while protecting shared storage.
    $activeTasks = @{}   # dsName -> @{ Task; Item; Remaining }

    # Launch one task per datastore group simultaneously
    foreach ($ds in $dsGroups.Keys) {
        $group = $dsGroups[$ds]
        $first = $group[0]
        Write-Host "  [$ds] Starting removal of '$($first.SnapName)' on $($first.VMName)..." -ForegroundColor Cyan
        try {
            $task = Remove-Snapshot -Snapshot $first.Snapshot -Confirm:$false -RunAsync -ErrorAction Stop
            $activeTasks[$ds] = @{
                Task        = $task
                Item        = $first
                Remaining   = ($group | Select-Object -Skip 1)
                TaskStarted = [datetime]::UtcNow
            }
        } catch {
            Write-Warning "  [$ds] Failed to start removal for $($first.VMName): $($_.Exception.Message)"
            $results.Add([PSCustomObject]@{
                Type   = $TypeLabel
                VMName = $first.VMName
                VMId   = $first.VMId
                Item   = $first.SnapName
                SizeMB = $first.SizeMB
                Result = "Failed"
                Notes  = $_.Exception.Message
            })
            # Still queue remaining items in this group for sequential processing
            $activeTasks[$ds] = @{ Task = $null; Item = $first; Remaining = ($group | Select-Object -Skip 1) }
        }
    }

    # Poll until all tasks and remaining queued items are done
    while ($activeTasks.Count -gt 0) {
        Start-Sleep -Seconds 5
        $completed = @()
        foreach ($ds in $activeTasks.Keys) {
            $entry = $activeTasks[$ds]

            # Check task state
            if ($null -ne $entry.Task) {
                $taskView = Get-View $entry.Task -ErrorAction SilentlyContinue

                # Enforce per-task timeout
                $taskElapsed = ([datetime]::UtcNow - $entry.TaskStarted).TotalSeconds
                $taskTimedOut = ($taskElapsed -ge $TaskTimeoutSeconds) -and
                               ($taskView -and $taskView.Info.State -in @("running","queued"))

                if ($taskTimedOut) {
                    Write-Warning "  [$ds] Task timed out after ${TaskTimeoutSeconds}s for '$($entry.Item.SnapName)' on $($entry.Item.VMName)."
                    Write-Warning "  [$ds] The snapshot may still be removing. Check vSphere Client and run -CleanupSnapshots again if needed."
                    $results.Add([PSCustomObject]@{
                        Type   = $TypeLabel
                        VMName = $entry.Item.VMName
                        VMId   = $entry.Item.VMId
                        Item   = $entry.Item.SnapName
                        SizeMB = $entry.Item.SizeMB
                        Result = "Timeout"
                        Notes  = "Task timed out after ${TaskTimeoutSeconds}s. Snapshot may still be removing."
                    })
                    $entry.Task = $null
                    # Fall through to remaining-item handling below
                }
                elseif (-not $taskView -or $taskView.Info.State -notin @("running","queued")) {
                    $success = ($taskView -and $taskView.Info.State -eq "success")
                    $errMsg  = if (-not $success -and $taskView) { $taskView.Info.Error.LocalizedMessage } else { "" }
                    if ($success) {
                        Write-Host "  [$ds] Removed '$($entry.Item.SnapName)' on $($entry.Item.VMName)." -ForegroundColor Green
                    } else {
                        Write-Warning "  [$ds] Failed '$($entry.Item.SnapName)' on $($entry.Item.VMName): $errMsg"
                    }
                    $results.Add([PSCustomObject]@{
                        Type   = $TypeLabel
                        VMName = $entry.Item.VMName
                        VMId   = $entry.Item.VMId
                        Item   = $entry.Item.SnapName
                        SizeMB = $entry.Item.SizeMB
                        Result = if ($success) { "Removed" } else { "Failed" }
                        Notes  = $errMsg
                    })
                    $entry.Task = $null  # mark done

                    # Start next item in this datastore group if any remain
                    if ($entry.Remaining -and @($entry.Remaining).Count -gt 0) {
                        $next = @($entry.Remaining)[0]
                        $entry.Remaining = @($entry.Remaining) | Select-Object -Skip 1
                        Write-Host "  [$ds] Starting removal of '$($next.SnapName)' on $($next.VMName)..." -ForegroundColor Cyan
                        try {
                            $entry.Task        = Remove-Snapshot -Snapshot $next.Snapshot -Confirm:$false -RunAsync -ErrorAction Stop
                            $entry.Item        = $next
                            $entry.TaskStarted = [datetime]::UtcNow
                        } catch {
                            Write-Warning "  [$ds] Failed to start removal for $($next.VMName): $($_.Exception.Message)"
                            $results.Add([PSCustomObject]@{
                                Type   = $TypeLabel
                                VMName = $next.VMName
                                VMId   = $next.VMId
                                Item   = $next.SnapName
                                SizeMB = $next.SizeMB
                                Result = "Failed"
                                Notes  = $_.Exception.Message
                            })
                            $entry.Item = $next
                        }
                    } else {
                        $completed += $ds
                    }
                }
            } else {
                # Task is null: either the initial start failed or the previous task
                # completion already cleared it. If items remain in this group,
                # try to start the next one rather than abandoning the group.
                if ($entry.Remaining -and @($entry.Remaining).Count -gt 0) {
                    $next = @($entry.Remaining)[0]
                    $entry.Remaining = @($entry.Remaining) | Select-Object -Skip 1
                    Write-Host "  [$ds] Starting removal of '$($next.SnapName)' on $($next.VMName)..." -ForegroundColor Cyan
                    try {
                        $entry.Task        = Remove-Snapshot -Snapshot $next.Snapshot -Confirm:$false -RunAsync -ErrorAction Stop
                        $entry.Item        = $next
                        $entry.TaskStarted = [datetime]::UtcNow
                    } catch {
                        Write-Warning "  [$ds] Failed to start removal for $($next.VMName): $($_.Exception.Message)"
                        $results.Add([PSCustomObject]@{
                            Type   = $TypeLabel
                            VMName = $next.VMName
                            VMId   = $next.VMId
                            Item   = $next.SnapName
                            SizeMB = $next.SizeMB
                            Result = "Failed"
                            Notes  = $_.Exception.Message
                        })
                        $entry.Item = $next
                        # Task stays null. Next poll iteration will retry remaining items
                    }
                } else {
                    $completed += $ds
                }
            }
        }
        foreach ($ds in $completed) { $activeTasks.Remove($ds) }
    }

    return $results
}

# Deletes a list of NVRAM backup file items (.nvram_old and orphan .nvram_new) in
# parallel. Each file deletion is fired as an async vSphere task via
# DeleteDatastoreFile_Task. All files are dispatched simultaneously since they are
# small and deletion does not involve disk consolidation. Polls every 3 seconds
# until all tasks complete. Items with Skip=$true are passed through without deletion.
# Returns result PSObjects with Type, VMName, VMId, Item, SizeMB, Result, Notes.
function Remove-NvramFilesParallel {
    param(
        [System.Collections.Generic.List[PSObject]]$Items,
        [int]$TaskTimeoutSeconds = 120
    )

    $results = [System.Collections.Generic.List[PSObject]]::new()

    $toDelete = $Items | Where-Object { -not $_.Skip }
    foreach ($item in ($Items | Where-Object { $_.Skip })) {
        $results.Add([PSCustomObject]@{
            Type   = "NVRAM file"
            VMName = $item.VMName
            VMId   = $item.VMId
            Item   = $item.FileName
            SizeMB = [math]::Round($item.SizeKB / 1KB, 3)
            Result = "Skipped"
            Notes  = $item.Notes
        })
    }

    if (-not $toDelete) { return $results }

    # Fire all deletions simultaneously - files are small, no consolidation involved
    $activeTasks = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($item in $toDelete) {
        Write-Host "  Starting deletion of $($item.FileName) on $($item.VMName)..." -ForegroundColor Cyan
        try {
            $task = $item.FM.DeleteDatastoreFile_Task($item.FilePath, $item.DcRef)
            $activeTasks.Add([PSCustomObject]@{
                Task        = $task
                Item        = $item
                Done        = $false
                TaskStarted = [datetime]::UtcNow
            })
        } catch {
            Write-Warning "  Failed to start deletion for $($item.VMName)/$($item.FileName): $($_.Exception.Message)"
            $results.Add([PSCustomObject]@{
                Type   = "NVRAM file"
                VMName = $item.VMName
                VMId   = $item.VMId
                Item   = $item.FileName
                SizeMB = [math]::Round($item.SizeKB / 1KB, 3)
                Result = "Failed"
                Notes  = $_.Exception.Message
            })
        }
    }

    # Poll until all tasks complete
    while (($activeTasks | Where-Object { -not $_.Done }).Count -gt 0) {
        Start-Sleep -Seconds 3
        foreach ($entry in $activeTasks | Where-Object { -not $_.Done }) {
            $taskView = Get-View $entry.Task -ErrorAction SilentlyContinue

            # Enforce per-task timeout
            $taskElapsed = ([datetime]::UtcNow - $entry.TaskStarted).TotalSeconds
            $taskTimedOut = ($taskElapsed -ge $TaskTimeoutSeconds) -and
                           ($taskView -and $taskView.Info.State -in @("running","queued"))

            if ($taskTimedOut) {
                Write-Warning "  Task timed out after ${TaskTimeoutSeconds}s for $($entry.Item.FileName) on $($entry.Item.VMName)."
                Write-Warning "  The file may still be deleting. Check the datastore and re-run -CleanupNvram if needed."
                $results.Add([PSCustomObject]@{
                    Type   = "NVRAM file"
                    VMName = $entry.Item.VMName
                    VMId   = $entry.Item.VMId
                    Item   = $entry.Item.FileName
                    SizeMB = [math]::Round($entry.Item.SizeKB / 1KB, 3)
                    Result = "Timeout"
                    Notes  = "Task timed out after ${TaskTimeoutSeconds}s. File may still be deleting."
                })
                $entry.Done = $true
            }
            elseif (-not $taskView -or $taskView.Info.State -notin @("running","queued")) {
                $success = ($taskView -and $taskView.Info.State -eq "success")
                $errMsg  = if (-not $success -and $taskView) { $taskView.Info.Error.LocalizedMessage } else { "" }
                if ($success) {
                    Write-Host "  Deleted $($entry.Item.FileName) on $($entry.Item.VMName)." -ForegroundColor Green
                } else {
                    Write-Warning "  Failed $($entry.Item.FileName) on $($entry.Item.VMName): $errMsg"
                }
                $results.Add([PSCustomObject]@{
                    Type   = "NVRAM file"
                    VMName = $entry.Item.VMName
                    VMId   = $entry.Item.VMId
                    Item   = $entry.Item.FileName
                    SizeMB = [math]::Round($entry.Item.SizeKB / 1KB, 3)
                    Result = if ($success) { "Deleted" } else { "Failed" }
                    Notes  = $errMsg
                })
                $entry.Done = $true
            }
        }
    }

    return $results
}

function Format-Bytes {
    param([double]$Bytes)
    if     ($Bytes -ge 1GB) { return "$([math]::Round($Bytes / 1GB, 2)) GB" }
    elseif ($Bytes -ge 1MB) { return "$([math]::Round($Bytes / 1MB, 2)) MB" }
    elseif ($Bytes -ge 1KB) { return "$([math]::Round($Bytes / 1KB, 2)) KB" }
    else                    { return "$([math]::Round($Bytes, 0)) B" }
}

function Get-VMDatastoreSpaceInfo {
    param(
        $VMObj,
        [double]$WarnThresholdPct = 0.80,  # warn if snapshot estimate > 80% of free space
        [double]$SnapFallbackGB   = 2.0    # fallback estimate when VM has snapshots but size unavailable
    )
    try {
        $vmView  = $VMObj | Get-View
        $dsName  = ($vmView.Config.Files.VmPathName -replace '^\[(.+?)\].*', '$1')
        $ds = Resolve-VMXDatastore -VMObj $VMObj -VMViewObj $vmView
        $freeGB  = [math]::Round($ds.FreeSpaceGB, 2)
        $capGB   = [math]::Round($ds.CapacityGB, 2)
        $usedGB  = [math]::Round($capGB - $freeGB, 2)

        # Check for existing snapshots - if any exist the VM's disks are already
        # in delta-write mode. A new snapshot will only capture writes made during
        # the remediation window (a few reboots) rather than the full committed
        # disk size, so the estimate should be much smaller.
        $existingSnaps   = Get-Snapshot -VM $VMObj -EA SilentlyContinue
        $hasSnaps        = ($null -ne $existingSnaps -and @($existingSnaps).Count -gt 0)
        $estimateGB      = 0
        $estimateBasis   = ""

        # VMware creates one 16 MB delta file per virtual disk at snapshot time.
        # This is the documented minimum snapshot size regardless of VM activity.
        $diskCount     = @($vmView.Config.Hardware.Device |
            Where-Object { $_ -is [VMware.Vim.VirtualDisk] }).Count
        $baselineBytes = [math]::Max($diskCount, 1) * 16MB

        if ($hasSnaps) {
            # Get actual on-disk sizes of existing snapshot delta files from LayoutEx.
            # LayoutEx.File contains every file associated with the VM with real byte sizes.
            # snapshotData = -delta.vmdk files. snapshotExtent = additional delta extents.
            # This gives actual disk consumption per snapshot, not provisioned capacity.
            $snapFiles = $vmView.LayoutEx.File |
                Where-Object { $_.Type -in @("snapshotData","snapshotExtent") }
            $totalSnapBytes = ($snapFiles | Measure-Object -Property Size -Sum).Sum

            if ($totalSnapBytes -gt 0) {
                $snapCount      = @($existingSnaps).Count
                $estimateBytes  = $totalSnapBytes / $snapCount
                $estimateGB     = [math]::Round($estimateBytes / 1GB, 2)
                $estimateDisplay = Format-Bytes -Bytes $estimateBytes
                $estimateBasis  = "delta avg ($snapCount existing snapshot(s), actual on-disk size)"
                $fallbackUsed   = $false
            } else {
                # LayoutEx data unavailable - use conservative fixed fallback
                $estimateBytes   = $SnapFallbackGB * 1GB
                $estimateGB      = $SnapFallbackGB
                $estimateDisplay = Format-Bytes -Bytes $estimateBytes
                $estimateBasis   = "fixed $($SnapFallbackGB) GB fallback (existing snapshots detected but delta size unavailable from vCenter)"
                $fallbackUsed    = $true
            }
        } else {
            # No existing snapshots - use committed disk bytes as upper bound
            $storageUsage = $vmView.Storage.PerDatastoreUsage |
                Where-Object { (Get-Datastore -Id $_.Datastore -EA SilentlyContinue).Name -eq $dsName }
            $estimateBytes = if ($storageUsage) {
                ($storageUsage | Measure-Object -Property Committed -Sum).Sum
            } else { 0 }
            $estimateGB      = [math]::Round($estimateBytes / 1GB, 2)
            $estimateDisplay = Format-Bytes -Bytes $estimateBytes
            $estimateBasis   = "committed disk size (no existing snapshots)"
            $fallbackUsed    = $false
        }

        # Apply 16 MB per-disk baseline floor. VMware allocates a 16 MB delta
        # file per virtual disk at snapshot creation time regardless of activity.
        if ($estimateBytes -lt $baselineBytes) {
            $estimateBytes   = $baselineBytes
            $estimateGB      = [math]::Round($estimateBytes / 1GB, 2)
            $estimateDisplay = Format-Bytes -Bytes $estimateBytes
            $estimateBasis   += " (raised to 16 MB/disk baseline: $diskCount disk(s))"
        }

        $sufficient = $true
        $warning    = ""
        if ($estimateGB -gt 0 -and $estimateGB -gt ($freeGB * $WarnThresholdPct)) {
            $sufficient = $false
            $warning    = "Estimated snapshot ($estimateDisplay, basis: $estimateBasis) exceeds $([int]($WarnThresholdPct*100))% of free space ($freeGB GB free on $dsName)."
        } elseif ($freeGB -lt 5) {
            $sufficient = $false
            $warning    = "Less than 5 GB free on datastore $dsName ($freeGB GB free)."
        }

        return [PSCustomObject]@{
            Datastore        = $dsName
            CapacityGB       = $capGB
            FreeGB           = $freeGB
            UsedGB           = $usedGB
            EstimateGB       = $estimateGB
            EstimateDisplay  = $estimateDisplay
            EstimateBasis    = $estimateBasis
            HasSnapshots     = $hasSnaps
            FallbackUsed     = $fallbackUsed
            Sufficient       = $sufficient
            Warning          = $warning
        }
    } catch {
        return [PSCustomObject]@{
            Datastore        = "Unknown"
            CapacityGB       = 0
            FreeGB           = 0
            UsedGB           = 0
            EstimateGB       = 0
            EstimateDisplay  = "0 B"
            EstimateBasis    = "check failed"
            HasSnapshots     = $false
            FallbackUsed     = $false
            Sufficient       = $true   # don't block on lookup failure
            Warning          = "Datastore space check failed: $($_.Exception.Message)"
        }
    }
}

# Renames the active .nvram file to .nvram_old so ESXi regenerates a fresh
# one with 2023 certificates on next boot.
function Rename-VMNvram {
    param($VMObj)
    try {
        $ctx  = Get-VMDatastoreContext -VMObj $VMObj
        $spec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $spec.MatchPattern = if ($ctx.CustomNvramName) { $ctx.CustomNvramName } else { "*.nvram" }
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

        # Abort if .nvram_old already exists - a prior partial run may have left
        # a backup file. Overwriting it would destroy the only rollback copy.
        # The user should roll back first or remove the file intentionally.
        $oldSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
        $oldSpec.MatchPattern = $newName
        $oldCheck = $ctx.DsBrowser.SearchDatastoreSubFolders(
            "[$($ctx.DsName)] $($ctx.VmDir)", $oldSpec)
        if ($oldCheck -and $oldCheck.File) {
            Write-Warning "    $newName already exists on the datastore."
            Write-Warning "    Aborting NVRAM rename to protect existing backup."
            Write-Warning "    To proceed: roll back using -Rollback, or remove the .nvram_old file manually."
            return $false
        }

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
        $preservedCurrent = $false
        if ($currFile) {
            $saveName = $currFile -replace '\.nvram$', '.nvram_new'
            $savePath = "[$($ctx.DsName)] $($ctx.VmDir)/$saveName"

            # Abort if .nvram_new already exists - a prior rollback may have left
            # a backup. Overwriting it would destroy that copy.
            $newSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
            $newSpec.MatchPattern = $saveName
            $newCheck = $ctx.DsBrowser.SearchDatastoreSubFolders(
                "[$($ctx.DsName)] $($ctx.VmDir)", $newSpec)
            if ($newCheck -and $newCheck.File) {
                Write-Warning "    $saveName already exists on the datastore (left by a prior rollback)."
                Write-Warning "    Skipping the NVRAM file restore to protect that existing backup."
                Write-Warning "    If a Pre-SecureBoot-Fix snapshot exists, the snapshot revert below will"
                Write-Warning "    still restore NVRAM and complete the rollback. To clear the orphan"
                Write-Warning "    .nvram_new file, run -CleanupNvram (it now removes .nvram_new as well)."
                return $false
            }

            $currPath = "[$($ctx.DsName)] $($ctx.VmDir)/$currFile"
            Write-Host "    Preserving current NVRAM as .nvram_new..." -ForegroundColor Gray
            $task = $ctx.FileManager.MoveDatastoreFile_Task(
                $currPath, $ctx.DcRef, $savePath, $ctx.DcRef, $true)
            if (-not (Wait-DatastoreTask -Task $task)) {
                Write-Warning "    Could not preserve current .nvram - aborting restore to avoid data loss."
                return $false
            }
            $preservedCurrent = $true
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

        # Restore failed. If we already moved the active .nvram to .nvram_new,
        # try to move it back so the VM is not left without an active NVRAM file.
        if ($preservedCurrent -and $savePath -and $currPath) {
            Write-Warning "    Restore of .nvram_old failed. Attempting to recover .nvram_new -> .nvram..."
            try {
                $undoTask = $ctx.FileManager.MoveDatastoreFile_Task(
                    $savePath, $ctx.DcRef, $currPath, $ctx.DcRef, $true)
                if (Wait-DatastoreTask -Task $undoTask) {
                    Write-Warning "    Recovered: .nvram_new moved back to .nvram. VM has its pre-rollback NVRAM."
                    Write-Warning "    The original .nvram_old backup is still present for a future rollback attempt."
                } else {
                    Write-Warning "    CRITICAL: Could not recover .nvram_new back to .nvram."
                    Write-Warning "    VM may have no active NVRAM file. Do not power on - restore manually via vSphere Client."
                }
            } catch {
                Write-Warning "    CRITICAL: Exception during .nvram_new recovery: $($_.Exception.Message)"
                Write-Warning "    VM may have no active NVRAM file. Do not power on - restore manually via vSphere Client."
            }
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

# Shared PK classification snippet, injected into the guest scripts that need to
# classify the Platform Key. Replaces the previous brittle ASCII-substring match
# with proper EFI_SIGNATURE_LIST parsing and X.509 certificate inspection.
#
# It parses the PK variable as an EFI_SIGNATURE_LIST, validates the signature
# type GUID is EFI_CERT_X509_GUID, extracts the DER certificate at the offset
# computed from the list header (not a fixed 44-byte skip), loads it as an
# X509Certificate2, and classifies by the certificate Subject. It also emits the
# certificate Subject, Issuer, Thumbprint, Serial, and NotAfter so the result can
# be recorded for verification.
#
# Defines, in the guest scope: function Get-PKClassification returning a hashtable
# with keys PK_Status, PK_Subject, PK_Issuer, PK_Thumbprint, PK_Serial, PK_NotAfter.
# Guest scripts inject this by replacing the token __PK_CLASSIFY_FUNCTION__.
$pkClassifyFunction = @'
function Get-PKClassification {
    $r = @{ PK_Status="Unknown"; PK_Subject=""; PK_Issuer=""; PK_Thumbprint=""; PK_Serial=""; PK_NotAfter="" }
    try { $pk = Get-SecureBootUEFI -Name PK -ErrorAction Stop } catch { $r.PK_Status="CheckFailed"; return $r }
    if ($null -eq $pk -or $null -eq $pk.Bytes -or $pk.Bytes.Length -lt 28) { $r.PK_Status="Invalid_NULL"; return $r }
    $b = $pk.Bytes
    $x509 = [Guid]"a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
    try { $tb = New-Object byte[] 16; [Array]::Copy($b,0,$tb,0,16); $st = New-Object Guid (,$tb) } catch { $r.PK_Status="Invalid_NULL"; return $r }
    if ($st -ne $x509) { $r.PK_Status="Valid_Other"; $r.PK_Subject="(non-X509 signature type: $st)"; return $r }
    $hs = [BitConverter]::ToUInt32($b,20); $ss = [BitConverter]::ToUInt32($b,24)
    $cStart = 28 + [int]$hs + 16; $cLen = [int]$ss - 16
    if ($cLen -le 0 -or ($cStart + $cLen) -gt $b.Length) { $r.PK_Status="Valid_Other"; $r.PK_Subject="(malformed signature list)"; return $r }
    $cb = New-Object byte[] $cLen; [Array]::Copy($b,$cStart,$cb,0,$cLen)
    try { $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$cb) } catch { $r.PK_Status="Valid_Other"; $r.PK_Subject="(unparseable certificate)"; return $r }
    $r.PK_Subject=$c.Subject; $r.PK_Issuer=$c.Issuer; $r.PK_Thumbprint=$c.Thumbprint; $r.PK_Serial=$c.SerialNumber; $r.PK_NotAfter=$c.NotAfter.ToString("yyyy-MM-dd")
    $s = $c.Subject
    if ($s -match 'CN=Windows OEM Devices PK') { $r.PK_Status="Valid_WindowsOEM" }
    elseif ($s -match 'CN=Microsoft.*Production PCA' -or $s -match 'O=Microsoft Corporation' -or $s -match 'CN=Microsoft Corporation') { $r.PK_Status="Valid_Microsoft" }
    else { $r.PK_Status="Valid_Other" }
    return $r
}
'@


# Assess mode - reads all deployment signals from the guest in a single
# Invoke-VMScript call: registry status, cert presence, event log, BitLocker.
$assessGuestScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
__PK_CLASSIFY_FUNCTION__
$r = @{}

# Registry
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"
$r["UEFICA2023Status"]  = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Status" -EA SilentlyContinue
$r["AvailableUpdates"]  = "0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue))"
$errVal = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Error" -EA SilentlyContinue
$r["UEFICA2023ErrorExists"] = ($null -ne $errVal).ToString()
$r["UEFICA2023ErrorValue"]  = if ($null -ne $errVal) { $errVal } else { "" }
$errEvt = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023ErrorEvent" -EA SilentlyContinue
$r["UEFICA2023ErrorEvent"]  = if ($null -ne $errEvt) { $errEvt } else { "" }

# Cert presence via ASCII scan
try {
    $r["KEK_2023"] = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek -EA Stop).Bytes) -match "Microsoft Corporation KEK 2K CA 2023").ToString()
    $r["DB_2023"]  = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db  -EA Stop).Bytes) -match "Windows UEFI CA 2023").ToString()
} catch {
    $r["KEK_2023"] = "CheckFailed"; $r["DB_2023"] = "CheckFailed"
}

# PK status - robust EFI signature list + X.509 parsing
$pkc = Get-PKClassification
$r["PK_Status"]     = $pkc.PK_Status
$r["PK_Subject"]    = $pkc.PK_Subject
$r["PK_Issuer"]     = $pkc.PK_Issuer
$r["PK_Thumbprint"] = $pkc.PK_Thumbprint
$r["PK_Serial"]     = $pkc.PK_Serial
$r["PK_NotAfter"]   = $pkc.PK_NotAfter

# Events (KB5016061 + KB5085046)
$evts = @{ Evt1036=$false; Evt1043=$false; Evt1044=$false; Evt1045=$false; Evt1795=$false; Evt1797=$false; Evt1799=$false; Evt1800=$false; Evt1801=$false; Evt1802=$false; Evt1803=$false; Evt1808=$false }
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName="System"; ProviderName="Microsoft-Windows-TPM-WMI"; Id=@(1036,1043,1044,1045,1795,1797,1799,1800,1801,1802,1803,1808) } -MaxEvents 100 -EA Stop
    foreach ($e in $events) { $evts["Evt$($e.Id)"] = $true }
} catch {}
foreach ($k in $evts.Keys) { $r[$k] = $evts[$k].ToString() }

# BitLocker (treat suspended-but-encrypted volumes as active - they auto-resume)
$blVols = Get-BitLockerVolume
$blOn = $blVols | Where-Object { $_.ProtectionStatus -eq "On" }
$blSusp = $blVols | Where-Object {
    $_.ProtectionStatus -eq "Off" -and $_.VolumeStatus -ne "FullyDecrypted" -and @($_.KeyProtector).Count -gt 0
}
$r["BitLockerActive"] = ((@($blOn).Count + @($blSusp).Count) -gt 0).ToString()

# Secure-Boot-Update task registration status
$sbuTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -EA SilentlyContinue
if ($null -ne $sbuTask) {
    $r["SBUTaskStatus"] = "Registered"
} elseif (Test-Path "C:\Windows\System32\Tasks\Microsoft\Windows\PI\Secure-Boot-Update") {
    $r["SBUTaskStatus"] = "NotRegistered_XMLPresent"
} else {
    $r["SBUTaskStatus"] = "NotRegistered_XMLMissing"
}

$r | ConvertTo-Json -Compress
'@
# Inject the shared PK classification function into the assess script.
$assessGuestScript = $assessGuestScript.Replace('__PK_CLASSIFY_FUNCTION__', $pkClassifyFunction)

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
$blVols = Get-BitLockerVolume
$blProtected = $blVols | Where-Object { $_.ProtectionStatus -eq "On" }
# A suspended-but-encrypted volume (ProtectionStatus=Off, still encrypted, has key
# protectors) will auto-resume when its existing reboot counter expires. That could
# happen mid-sequence and trigger BitLocker recovery on a PCR7 change, so it must be
# treated as active and re-suspended (which resets the counter) before proceeding.
$blSuspended = $blVols | Where-Object {
    $_.ProtectionStatus -eq "Off" -and $_.VolumeStatus -ne "FullyDecrypted" -and @($_.KeyProtector).Count -gt 0
}
$vbs = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -EA SilentlyContinue
$vbsRunning = ($null -ne $vbs -and $vbs.VirtualizationBasedSecurityStatus -eq 2)
$cgRunning  = ($null -ne $vbs -and $vbs.SecurityServicesRunning -contains 1)
[PSCustomObject]@{
    TPMPresent      = ($null -ne $tpm -and $tpm.TpmPresent)
    BitLockerActive = ((@($blProtected).Count + @($blSuspended).Count) -gt 0)
    BitLockerSuspendedPending = (@($blSuspended).Count -gt 0)
    VBSRunning      = $vbsRunning
    CGRunning       = $cgRunning
} | ConvertTo-Json -Compress
'@

# Export all BitLocker recovery keys from the guest (returns JSON object).
# Output fields:
#   Keys               - array of RecoveryPassword protectors found
#   UnprotectedVolumes - array of active-protected volume mount points with
#                        no RecoveryPassword protector (unsafe for backup)
$bitLockerExportScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$keys = @()
$unprotected = @()
$volumes = Get-BitLockerVolume
foreach ($vol in $volumes) {
    $hasRecovery = $false
    foreach ($protector in $vol.KeyProtector) {
        if ($protector.KeyProtectorType -eq 'RecoveryPassword') {
            $hasRecovery = $true
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
    # Track active-protected volumes that have no RecoveryPassword protector
    if ($vol.ProtectionStatus -eq 'On' -and -not $hasRecovery) {
        $unprotected += $vol.MountPoint
    }
}
[PSCustomObject]@{
    Keys               = $keys
    UnprotectedVolumes = $unprotected
} | ConvertTo-Json -Compress -Depth 5
'@

# Suspend BitLocker on all encrypted volumes that are protected OR suspended.
# RebootCount 3 covers the reboots between this suspension and the next re-suspension
# checkpoint: the power-off/power-on cycle, the post-fix reboot, and the optional 7b
# extra reboot (Event 1801) that Server 2025 may require. The PK/SetupMode phase
# re-suspends separately (before BOTH the SetupMode reboot and the post-enrollment
# reboot), and a re-suspend check also runs before the 7b reboot, so no more than a
# few reboots ever elapse on a single counter.
#
# A volume that is already SUSPENDED (ProtectionStatus=Off but still encrypted, with
# key protectors) will auto-resume when its existing reboot counter expires - which
# could happen mid-sequence and strand a TPM-less password-protected OS volume at the
# pre-boot password prompt, or drop a TPM-sealed volume into recovery on a PCR7
# change. Such volumes are re-suspended here to refresh the counter.
#
# IMPORTANT: calling Suspend-BitLocker on a volume that is ALREADY suspended does not
# reliably refresh the auto-resume reboot counter - the cmdlet can treat the volume as
# already in the desired state and leave the existing (possibly nearly-exhausted)
# counter in place. To force a genuine reset we Resume first and then immediately
# re-suspend. This runs on the live OS with no reboot in between, so there is no
# window in which an unsuspended reboot could occur, and if the Suspend after a Resume
# were to fail, protection is left ON (the safe direction) and the caller fails closed
# on the unconfirmed-suspend result. Truly decrypted volumes (FullyDecrypted, no
# protectors) are left alone. Re-suspending does not decrypt or re-encrypt.
$bitLockerSuspendScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$result = @{ Suspended = @(); ReSuspended = @(); Failed = @(); Notes = "" }
$all = Get-BitLockerVolume
foreach ($vol in $all) {
    $isProtected = ($vol.ProtectionStatus -eq "On")
    $isSuspendedButEncrypted = (
        $vol.ProtectionStatus -eq "Off" -and
        $vol.VolumeStatus -ne "FullyDecrypted" -and
        @($vol.KeyProtector).Count -gt 0
    )
    if (-not ($isProtected -or $isSuspendedButEncrypted)) { continue }
    try {
        if ($isSuspendedButEncrypted) {
            # Force a clean counter reset (see comment above): resume, then re-suspend.
            Resume-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
        }
        Suspend-BitLocker -MountPoint $vol.MountPoint -RebootCount 3 -ErrorAction Stop | Out-Null
        $result["Suspended"] += $vol.MountPoint
        if ($isSuspendedButEncrypted) { $result["ReSuspended"] += $vol.MountPoint }
    } catch {
        $result["Failed"] += $vol.MountPoint
        $result["Notes"]  += "Failed to suspend $($vol.MountPoint): $($_.Exception.Message) "
    }
}
$result["Notes"] += if ($result["Suspended"].Count -gt 0) {
    "Suspended on: $($result['Suspended'] -join ', '). Auto-resumes after 3 reboots. "
} else { "" }
$result["Notes"] += if ($result["ReSuspended"].Count -gt 0) {
    "Note: $($result['ReSuspended'] -join ', ') arrived already suspended and was resumed and re-suspended to force a fresh auto-resume counter. "
} else { "" }
$result | ConvertTo-Json -Compress
'@

# Resume (re-enable) BitLocker on volumes this run suspended. Used as the final
# action on a VM that completes with the guest reachable, so the protected state is
# deterministic at the end of the maintenance window rather than depending on the
# auto-resume reboot countdown. Only acts on suspended-but-encrypted volumes. Volumes
# already protected or fully decrypted are left alone. Confirms ProtectionStatus=On
# after resuming so a silent failure is reported rather than assumed successful.
$bitLockerResumeScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$result = @{ Resumed = @(); Failed = @(); Notes = "" }
$all = Get-BitLockerVolume
foreach ($vol in $all) {
    $isSuspendedButEncrypted = (
        $vol.ProtectionStatus -eq "Off" -and
        $vol.VolumeStatus -ne "FullyDecrypted" -and
        @($vol.KeyProtector).Count -gt 0
    )
    if (-not $isSuspendedButEncrypted) { continue }
    try {
        Resume-BitLocker -MountPoint $vol.MountPoint -ErrorAction Stop | Out-Null
        $after = Get-BitLockerVolume -MountPoint $vol.MountPoint
        if ($after.ProtectionStatus -eq "On") {
            $result["Resumed"] += $vol.MountPoint
        } else {
            $result["Failed"] += $vol.MountPoint
            $result["Notes"]  += "Resume on $($vol.MountPoint) did not return ProtectionStatus=On (now $($after.ProtectionStatus)). "
        }
    } catch {
        $result["Failed"] += $vol.MountPoint
        $result["Notes"]  += "Failed to resume $($vol.MountPoint): $($_.Exception.Message) "
    }
}
$result["Notes"] += if ($result["Resumed"].Count -gt 0) {
    "Resumed on: $($result['Resumed'] -join ', '). "
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
    # Capture diagnostic state before clearing. UEFICA2023Status, UEFICA2023Error,
    # UEFICA2023ErrorEvent, and AvailableUpdates are Microsoft's primary signals for
    # diagnosing where a stuck update failed. Emit them so the host script can record
    # them before the subkey is removed (clearing is only done to retry a stale state).
    $preStatus = (Get-ItemProperty -Path $svcPath -Name "UEFICA2023Status"      -EA SilentlyContinue).UEFICA2023Status
    $preError  = (Get-ItemProperty -Path $svcPath -Name "UEFICA2023Error"       -EA SilentlyContinue).UEFICA2023Error
    $preErrEvt = (Get-ItemProperty -Path $svcPath -Name "UEFICA2023ErrorEvent"  -EA SilentlyContinue).UEFICA2023ErrorEvent
    $preAvail  = (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue)
    Write-Host "ServicingPreClear_UEFICA2023Status=$preStatus"
    Write-Host "ServicingPreClear_UEFICA2023Error=$preError"
    Write-Host "ServicingPreClear_UEFICA2023ErrorEvent=$preErrEvt"
    if ($null -ne $preAvail) {
        Write-Host ("ServicingPreClear_AvailableUpdates=0x{0:X4}" -f [int]$preAvail)
    } else {
        Write-Host "ServicingPreClear_AvailableUpdates=(absent)"
    }
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

# Verify Secure-Boot-Update task is registered in COM database before triggering.
# On VMs cloned from Sysprep templates the XML may exist on disk but the task
# may not be registered in the Task Scheduler COM database. Start-ScheduledTask
# returns silently with no error in this case making the failure invisible.
$sbuTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -EA SilentlyContinue
if ($null -eq $sbuTask) {
    $xmlPath = "C:\Windows\System32\Tasks\Microsoft\Windows\PI\Secure-Boot-Update"
    if (Test-Path $xmlPath) {
        Write-Host "Secure-Boot-Update task not registered - re-registering from XML..."
        Register-ScheduledTask -Xml (Get-Content $xmlPath -Raw) -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI" -Force | Out-Null
        $sbuTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -EA SilentlyContinue
        if ($null -eq $sbuTask) { Write-Host "TASK_REREGISTER_FAILED" } else { Write-Host "Task re-registered successfully." }
    } else {
        Write-Host "TASK_XML_MISSING"
    }
}
if ($null -ne $sbuTask) {
    Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
    Write-Host "Secure-Boot-Update task triggered"
} else {
    Write-Host "Secure-Boot-Update task not triggered - task not registered and re-registration failed."
}
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
'@

# Trigger update task after reboot
$taskTriggerScript = @'
$sbuTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -EA SilentlyContinue
if ($null -eq $sbuTask) {
    $xmlPath = "C:\Windows\System32\Tasks\Microsoft\Windows\PI\Secure-Boot-Update"
    if (Test-Path $xmlPath) {
        Register-ScheduledTask -Xml (Get-Content $xmlPath -Raw) -TaskName "Secure-Boot-Update" -TaskPath "\Microsoft\Windows\PI" -Force | Out-Null
        $sbuTask = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -EA SilentlyContinue
    }
}
if ($null -ne $sbuTask) {
    Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"
    Write-Host "Secure-Boot-Update task triggered (post-reboot)"
} else {
    Write-Host "Secure-Boot-Update task not triggered - task not registered (post-reboot)."
}
Start-Sleep -Seconds 30
$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after second task run: 0x$("{0:X4}" -f $val)"
'@

# Final verification - registry status, firmware cert presence, and event log
$verifyScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

$svcStatus = Get-ItemPropertyValue -Path $svcPath -Name "UEFICA2023Status" -EA SilentlyContinue
$auRaw = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
if ($null -ne $auRaw) { $auHex = ("0x{0:X4}" -f [int]$auRaw) } else { $auHex = "not found" }
$errExists = "False"
$errValue  = ""
$errEvtVal = ""
$svcProps = Get-ItemProperty -Path $svcPath -EA SilentlyContinue
if ($svcProps -and $null -ne $svcProps.UEFICA2023Error) {
    $errExists = "True"
    $errValue  = [string]$svcProps.UEFICA2023Error
}
if ($svcProps -and $null -ne $svcProps.UEFICA2023ErrorEvent) {
    $errEvtVal = [string]$svcProps.UEFICA2023ErrorEvent
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

# Event collection via FilterHashTable + Group-Object contributed by @ckitt-git-hub-1020
$EvtGroup = @()
try {
    $startTime = [datetime]::ParseExact("VERIFY_START_TIME", "yyyy-MM-dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
    $EvtGroup = Get-WinEvent -FilterHashTable @{ProviderName="Microsoft-Windows-TPM-WMI";Id=1036,1043,1044,1045,1795,1797,1799,1800,1801,1802,1803,1808} -MaxEvents 100 -EA Stop |
        Where-Object { $_.TimeCreated -ge $startTime } | Group-Object -Property Id
} catch {}
$e1036 = ($EvtGroup.Name -Contains 1036).ToString(); $e1043 = ($EvtGroup.Name -Contains 1043).ToString()
$e1044 = ($EvtGroup.Name -Contains 1044).ToString(); $e1045 = ($EvtGroup.Name -Contains 1045).ToString()
$e1795 = ($EvtGroup.Name -Contains 1795).ToString(); $e1797 = ($EvtGroup.Name -Contains 1797).ToString()
$e1799 = ($EvtGroup.Name -Contains 1799).ToString(); $e1800 = ($EvtGroup.Name -Contains 1800).ToString()
$e1801 = ($EvtGroup.Name -Contains 1801).ToString(); $e1802 = ($EvtGroup.Name -Contains 1802).ToString()
$e1803 = ($EvtGroup.Name -Contains 1803).ToString(); $e1808 = ($EvtGroup.Name -Contains 1808).ToString()

Write-Output "VERIFY_START"
Write-Output "Servicing_Status=$svcStatus"
Write-Output "AvailableUpdates=$auHex"
Write-Output "UEFICA2023ErrorExists=$errExists"
Write-Output "UEFICA2023ErrorValue=$errValue"
Write-Output "UEFICA2023ErrorEvent=$errEvtVal"
Write-Output "KEK_2023=$kek"
Write-Output "DB_2023=$db"
Write-Output "Evt1036=$e1036"
Write-Output "Evt1043=$e1043"
Write-Output "Evt1044=$e1044"
Write-Output "Evt1045=$e1045"
Write-Output "Evt1795=$e1795"
Write-Output "Evt1797=$e1797"
Write-Output "Evt1799=$e1799"
Write-Output "Evt1800=$e1800"
Write-Output "Evt1801=$e1801"
Write-Output "Evt1802=$e1802"
Write-Output "Evt1803=$e1803"
Write-Output "Evt1808=$e1808"
Write-Output "VERIFY_END"
'@

# Builds a timestamped copy of $verifyScript with the run start time injected.
# This ensures event log checks only return events from the current run,
# not events from prior runs or reboots that remain in the System log indefinitely.
# Extracts the last JSON object line from script output, returning $null if
# none is found. Avoids calling .Trim() on $null (which silently returns $null
# in non-strict mode but throws under Set-StrictMode -Version Latest).
function Get-LastJsonLine {
    param([string]$Text)
    if (-not $Text) { return $null }
    $line = $Text -split "`r?`n" |
        Where-Object { $_ -and $_.Trim() -match '^\{' } |
        Select-Object -Last 1
    if ($line) { return $line.Trim() }
    return $null
}

function Get-TimestampedVerifyScript {
    param([datetime]$StartTime)
    return $verifyScript -replace 'VERIFY_START_TIME', $StartTime.ToString('yyyy-MM-dd HH:mm:ss')
}

# Invoke-VMScript has an undocumented ScriptText size limit (observed ~2869 chars,
# varies by guest OS and script type). Scripts that exceed this limit return
# ExitCode 1 with completely empty output and no error message.
# This function works around the limit by writing the script to a temp file on the
# guest via Copy-VMGuestFile, executing it, then deleting the temp file.
function Invoke-VMScriptViaFile {
    param(
        [Parameter(Mandatory)]$VM,
        [Parameter(Mandatory)][string]$ScriptContent,
        [Parameter(Mandatory)][PSCredential]$GuestCredential,
        [string]$TempPath = "C:\Windows\Temp\__sb_verify_$([System.IO.Path]::GetRandomFileName()).ps1"
    )
    # Write script to a local temp file to copy to guest
    $localTemp = [System.IO.Path]::GetTempFileName() + ".ps1"
    try {
        [System.IO.File]::WriteAllText($localTemp, $ScriptContent, [System.Text.Encoding]::UTF8)
        Copy-VMGuestFile -Source $localTemp -Destination $TempPath `
            -VM $VM -LocalToGuest -GuestCredential $GuestCredential `
            -Force -ErrorAction Stop | Out-Null
    } finally {
        Remove-Item $localTemp -ErrorAction SilentlyContinue
    }

    # Execute the file on the guest then clean up
    $execScript = "& powershell.exe -NoProfile -ExecutionPolicy Bypass -File '$TempPath'; Remove-Item '$TempPath' -Force -ErrorAction SilentlyContinue"
    return Invoke-VMScript -VM $VM -ScriptText $execScript `
        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
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
__PK_CLASSIFY_FUNCTION__
$blVols = Get-BitLockerVolume
$blActiveVols = $blVols | Where-Object { $_.ProtectionStatus -eq "On" }
$blSuspendedVols = $blVols | Where-Object {
    $_.ProtectionStatus -eq "Off" -and $_.VolumeStatus -ne "FullyDecrypted" -and @($_.KeyProtector).Count -gt 0
}
# BitLockerActive is true if any volume is protected OR suspended-but-encrypted
# (a suspended volume will auto-resume and must be handled before PCR7 changes).
$blActive = ((@($blActiveVols).Count + @($blSuspendedVols).Count) -gt 0).ToString()
$blSuspendedPending = (@($blSuspendedVols).Count -gt 0).ToString()
$pkc = Get-PKClassification
[PSCustomObject]@{
    PK_Status       = $pkc.PK_Status
    PK_Subject      = $pkc.PK_Subject
    PK_Issuer       = $pkc.PK_Issuer
    PK_Thumbprint   = $pkc.PK_Thumbprint
    PK_Serial       = $pkc.PK_Serial
    PK_NotAfter     = $pkc.PK_NotAfter
    BitLockerActive = $blActive
    BitLockerSuspendedPending = $blSuspendedPending
} | ConvertTo-Json -Compress
'@
$pkCheckScript = $pkCheckScript.Replace('__PK_CLASSIFY_FUNCTION__', $pkClassifyFunction)

# Post-enrollment PK verification
$verifyPKScript = @'
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
__PK_CLASSIFY_FUNCTION__
$pkc = Get-PKClassification
[PSCustomObject]@{
    PK_Status     = $pkc.PK_Status
    PK_Subject    = $pkc.PK_Subject
    PK_Issuer     = $pkc.PK_Issuer
    PK_Thumbprint = $pkc.PK_Thumbprint
    PK_Serial     = $pkc.PK_Serial
    PK_NotAfter   = $pkc.PK_NotAfter
} | ConvertTo-Json -Compress
'@
$verifyPKScript = $verifyPKScript.Replace('__PK_CLASSIFY_FUNCTION__', $pkClassifyFunction)

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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$VMObj,
        [Parameter(Mandatory)][string]$Key,
        [AllowEmptyString()][string]$Value,
        [int]$TimeoutSeconds = 120
    )
    $spec        = New-Object VMware.Vim.VirtualMachineConfigSpec
    $extra       = New-Object VMware.Vim.OptionValue
    $extra.Key   = $Key
    $extra.Value = $Value
    $spec.ExtraConfig = @($extra)

    $vmView    = $VMObj | Get-View -ErrorAction Stop
    $taskMoRef = $vmView.ReconfigVM_Task($spec)

    # Wait for the reconfiguration task to complete
    $taskView = Get-View -Id $taskMoRef -ErrorAction Stop
    $elapsed  = 0
    while ($taskView.Info.State -in @("running","queued")) {
        if ($elapsed -ge $TimeoutSeconds) {
            throw "Timed out waiting for VMX option '$Key' to be set (${TimeoutSeconds}s)."
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
        $taskView = Get-View -Id $taskMoRef
    }
    if ($taskView.Info.State -ne "success") {
        $errMsg = if ($taskView.Info.Error.LocalizedMessage) {
            $taskView.Info.Error.LocalizedMessage
        } else { "Unknown VM reconfiguration error." }
        throw "Failed to set VMX option '$Key': $errMsg"
    }
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
        $currentVMName = [string]$vm.Name
        Write-Host "`n$('='*60)" -ForegroundColor White
        Write-Host "Assessing: $currentVMName" -ForegroundColor White
        Write-Host "$('='*60)" -ForegroundColor White

        $vmView   = $vm | Get-View
        $vmHost   = Get-VMHost -VM $vm -EA SilentlyContinue
        $hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')
        $firmware = $vmView.Config.Firmware
        $sbEnabled = $vmView.Config.BootOptions.EfiSecureBootEnabled

        # Hardware-based vTPM and guest OS detection (same as main loop).
        # Must use VM hardware config, not guest-reported data, to be reliable
        # regardless of whether the VM is powered on or credentials are available.
        $assessHasVTPM    = @($vmView.Config.Hardware.Device |
                              Where-Object { $_.GetType().Name -eq "VirtualTPM" }).Count -gt 0
        $assessCfgGuestId = [string]$vmView.Config.GuestId
        $assessRtFamily   = [string]$vm.Guest.GuestFamily
        $assessLinux      = ($assessRtFamily -eq "linuxGuest") -or
                            ($assessCfgGuestId -match 'linux|ubuntu|debian|rhel|redhat|centos|oracle|sles|suse|rocky|alma|photon|freebsd|otherLinux')
        $assessGuestRisk  = if ($assessLinux) { "Linux" } elseif ($assessRtFamily -eq "windowsGuest" -or $assessCfgGuestId -like "windows*") { "Windows" } else { "Unknown" }

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

        # Datastore space check
        $dsInfo = Get-VMDatastoreSpaceInfo -VMObj $vm

        $row = [PSCustomObject]@{
            VMName           = $currentVMName
            PowerState       = $vm.PowerState
            HWVersion        = $hwVerNum
            HWVersionOK      = ($hwVerNum -ge 21)
            ESXiHost         = if ($vmHost) { $vmHost.Name } else { "" }
            ESXiVersion      = if ($vmHost) { $vmHost.Version } else { "" }
            Firmware         = $firmware
            SecureBoot       = if ($firmware -eq "efi") { $sbEnabled.ToString() } else { "N/A (BIOS)" }
            NvramOldExists   = $hasNvramOld
            SnapshotExists   = $hasSnapshot
            Datastore        = $dsInfo.Datastore
            DSFreeGB         = $dsInfo.FreeGB
            DSCapacityGB     = $dsInfo.CapacityGB
            SnapshotEstimateGB = $dsInfo.EstimateGB
            DSSpaceOK        = $dsInfo.Sufficient
            # Guest-level (populated below if credentials provided and VM accessible)
            KEK_2023         = "Not collected"
            DB_2023          = "Not collected"
            PK_Status        = "Not collected"
            PK_Subject       = "Not collected"
            PK_Issuer        = "Not collected"
            PK_Thumbprint    = "Not collected"
            PK_Serial        = "Not collected"
            PK_NotAfter      = "Not collected"
            UEFICA2023Status = "Not collected"
            AvailableUpdates = "Not collected"
            UEFICA2023Error  = "Not collected"
            Evt1036          = "Not collected"
            Evt1043          = "Not collected"
            Evt1044          = "Not collected"
            Evt1045          = "Not collected"
            Evt1795          = "Not collected"
            Evt1797          = "Not collected"
            Evt1799          = "Not collected"
            Evt1800          = "Not collected"
            Evt1801          = "Not collected"
            Evt1802          = "Not collected"
            Evt1803          = "Not collected"
            Evt1808          = "Not collected"
            BitLockerActive  = "Not collected"
            SBUTaskStatus    = "Not collected"
            P09Compatible    = $false
            vTPM             = $assessHasVTPM
            GuestRiskClass   = $assessGuestRisk
            ActionNeeded     = ""
            Notes            = ""
        }

        # Detect P09+ host early so it can be used in console output and ActionNeeded
        $isP09Host = Get-IsP09Host -VMObj $vm
        $row.P09Compatible = $isP09Host

        Write-Host "  HW Version : $hwVerNum $(if ($hwVerNum -lt 21) { '(< 21 - KEK may be absent after NVRAM regeneration)' } else { '' })" -ForegroundColor $(if ($hwVerNum -lt 21) { "Yellow" } else { "Green" })
        Write-Host "  ESXi Host  : $($row.ESXiHost) v$($row.ESXiVersion)"
        Write-Host "  Firmware   : $firmware | Secure Boot: $($row.SecureBoot)"
        Write-Host "  Power      : $($vm.PowerState)"
        $toolsVer    = $vm.Guest.ToolsVersion
        $toolsStatus = $vm.Guest.ExtensionData.ToolsVersionStatus
        $toolsColor  = if ($toolsStatus -eq "guestToolsCurrent") { "Green" } elseif ($toolsStatus -eq "guestToolsNeedUpgrade") { "Yellow" } else { "Gray" }
        Write-Host "  VMware Tools: $toolsVer ($toolsStatus)" -ForegroundColor $toolsColor
        Write-Host "  nvram_old  : $hasNvramOld | Snapshot: $hasSnapshot"
        $dsColor = if ($dsInfo.Sufficient) { "Gray" } else { "Yellow" }
        Write-Host "  Datastore  : $($dsInfo.Datastore) | Free: $($dsInfo.FreeGB) GB / $($dsInfo.CapacityGB) GB | Snapshot est: $($dsInfo.EstimateDisplay) ($($dsInfo.EstimateBasis))" -ForegroundColor $dsColor
        if ($dsInfo.FallbackUsed) {
            Write-Host "  NOTE: Snapshot estimate is a fixed $($dsInfo.EstimateDisplay) fallback - vCenter could not determine delta size from existing snapshots." -ForegroundColor Yellow
        }
        if (-not $dsInfo.Sufficient) {
            Write-Warning "  Space warning: $($dsInfo.Warning)"
            $row.Notes += "Datastore space warning: $($dsInfo.Warning) "
            if (-not ("Insufficient datastore space" -in ($row.ActionNeeded -split " \| "))) {
                # will be appended to ActionNeeded below if no other actions already set
            }
        }

        if ($hwVerNum -lt 21) { $row.Notes += "HW version $hwVerNum < 21 - upgrade before remediation. " }
        if ($firmware -ne "efi") { $row.Notes += "BIOS firmware - not eligible for Secure Boot cert update. " }

        # Guest-level collection
        if ($GuestCredential -and $vm.PowerState -eq "PoweredOn") {
            try {
                $aOut  = Invoke-VMScriptViaFile -VM $vm -ScriptContent $assessGuestScript `
                    -GuestCredential $GuestCredential
                if (-not $aOut.ScriptOutput) { throw "Guest script returned no output" }
                $aData = $aOut.ScriptOutput.Trim() | ConvertFrom-Json
                if ($null -eq $aData) { throw "Guest script returned no output - check VMware Tools version and guest PowerShell execution policy" }

                $row.KEK_2023         = $aData.KEK_2023
                $row.DB_2023          = $aData.DB_2023
                $row.PK_Status        = $aData.PK_Status
                $row.PK_Subject       = $aData.PK_Subject
                $row.PK_Issuer        = $aData.PK_Issuer
                $row.PK_Thumbprint    = $aData.PK_Thumbprint
                $row.PK_Serial        = $aData.PK_Serial
                $row.PK_NotAfter      = $aData.PK_NotAfter
                $row.UEFICA2023Status = if ($aData.UEFICA2023Status -and $aData.UEFICA2023Status -notlike "") { $aData.UEFICA2023Status } else { "not found" }
                $row.AvailableUpdates = $aData.AvailableUpdates
                $row.UEFICA2023Error  = if ($aData.UEFICA2023ErrorExists -eq "True") { "ERROR ($($aData.UEFICA2023ErrorValue))" } else { "" }
                if ($aData.UEFICA2023ErrorEvent) { $row.Notes += "UEFICA2023ErrorEvent: $($aData.UEFICA2023ErrorEvent). " }
                $row.Evt1036 = $aData.Evt1036; $row.Evt1043 = $aData.Evt1043
                $row.Evt1044 = $aData.Evt1044; $row.Evt1045 = $aData.Evt1045
                $row.Evt1795 = $aData.Evt1795; $row.Evt1797 = $aData.Evt1797
                $row.Evt1799 = $aData.Evt1799; $row.Evt1800 = $aData.Evt1800
                $row.Evt1801 = $aData.Evt1801; $row.Evt1802 = $aData.Evt1802
                $row.Evt1803 = $aData.Evt1803; $row.Evt1808 = $aData.Evt1808
                $row.BitLockerActive = $aData.BitLockerActive
                $row.SBUTaskStatus   = $aData.SBUTaskStatus

                Write-Host "  UEFICA2023Status : $($row.UEFICA2023Status)" -ForegroundColor $(switch ($row.UEFICA2023Status.ToLower()) { "updated" {"Green"} "in progress" {"Yellow"} default {"Red"} })
                Write-Host "  AvailableUpdates : $($row.AvailableUpdates)"
                Write-Host "  KEK 2023 : $($row.KEK_2023) | DB 2023: $($row.DB_2023) | PK: $($row.PK_Status)"
                Write-Host "  Evt1808  : $($row.Evt1808) | Evt1799: $($row.Evt1799) | Evt1801: $($row.Evt1801) | Evt1803: $($row.Evt1803) | Evt1795: $($row.Evt1795)"
                $taskColor = if ($row.SBUTaskStatus -eq "Registered") { "Green" } elseif ($row.SBUTaskStatus -eq "NotRegistered_XMLPresent") { "Yellow" } else { "Red" }
                Write-Host "  SBU Task : $($row.SBUTaskStatus)" -ForegroundColor $taskColor
                $p09Color = if ($isP09Host) { "Green" } else { "Gray" }
                Write-Host "  P09+ Host: $(if ($isP09Host) { 'Yes (silent PK update available, resetOnce per KB423893 for Linux/non-Windows)' } else { 'No' })" -ForegroundColor $p09Color
                if ($row.UEFICA2023Error) { Write-Host "  RegError : $($row.UEFICA2023Error)" -ForegroundColor Red }
                if ($aData.BitLockerActive -eq "True") { $row.Notes += "BitLocker active. " }
                if ($row.SBUTaskStatus -eq "NotRegistered_XMLPresent") { $row.Notes += "Secure-Boot-Update task not registered in COM database (Sysprep/template clone artifact) - script will re-register automatically. " }
                if ($row.SBUTaskStatus -eq "NotRegistered_XMLMissing")  { $row.Notes += "Secure-Boot-Update task XML missing - cumulative update may be required (minimum KB5044284 for WS2025). " }
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
        if (-not $dsInfo.Sufficient)                               { $actions.Add("Insufficient datastore space") }
        if ($firmware -ne "efi")                               { $actions.Add("N/A - BIOS") }
        elseif ($sbEnabled -eq $false)                         { $actions.Add("Enable Secure Boot") }
        else {
            if ($hwVerNum -lt 21)                              { $actions.Add("Upgrade HW version") }
            if ($row.UEFICA2023Status -notin @("updated","Not collected")) {
                if ($row.KEK_2023 -eq "False" -or $row.DB_2023 -eq "False") { $actions.Add("Rename NVRAM + run cert update") }
                elseif ($row.UEFICA2023Status -eq "not found")               { $actions.Add("Trigger cert update task") }
                elseif ($row.UEFICA2023Status -eq "in progress")             { $actions.Add("Reboot + trigger task again") }
            }
            if ($row.PK_Status -in @("Valid_Other","Invalid_NULL")) {
                if ($isP09Host -and -not $assessHasVTPM) {
                    $actions.Add("Enroll PK (P09+ host, no vTPM: official silent update on reboot)")
                } elseif ($isP09Host -and $assessHasVTPM) {
                    if ($assessLinux) {
                        $actions.Add("PK needed (P09+ vTPM Linux: follow KB423893 resetOnce / OS-vendor procedure. This script does not perform Linux guest PK enrollment)")
                    } else {
                        $actions.Add("Enroll PK (P09+ host, vTPM, Windows/unknown: Broadcom recommends waiting for capsule solution. Use -AllowUnsupportedVTPMWindowsPKRemediation to override)")
                    }
                } else {
                    $actions.Add("Enroll PK")
                }
            }
            if ($row.UEFICA2023Error)                                         { $actions.Add("Investigate reg error") }
            if ($row.Evt1802 -eq "True")                                          { $actions.Add("OEM firmware update (Evt 1802)") }
            if ($row.Evt1795 -eq "True")                                          { $actions.Add("OEM firmware update (Evt 1795)") }
            if ($row.Evt1797 -eq "True")                                          { $actions.Add("Boot manager update failed (Evt 1797) - check firmware") }
            if ($row.SBUTaskStatus -eq "NotRegistered_XMLPresent")               { $actions.Add("SBU task not registered (Sysprep artifact) - script will re-register automatically") }
            if ($row.SBUTaskStatus -eq "NotRegistered_XMLMissing")               { $actions.Add("SBU task XML missing - cumulative update required") }
            # Use the same cert-verification standard as the main pre-check:
            # registry "updated" alone is not enough - KEK/DB must be confirmed
            # in NVRAM and no UEFICA2023Error registry key may be present.
            $assessHasDeployError = ($row.UEFICA2023Error -ne "" -and $row.UEFICA2023Error -ne "Not collected")
            $assessCertsDone = ($row.UEFICA2023Status -eq "updated" -or $row.AvailableUpdates -eq "0x4000")
            $assessNvramGood = ($row.KEK_2023 -eq "True" -and $row.DB_2023 -eq "True")
            $assessCertsVerified = $assessCertsDone -and $assessNvramGood -and -not $assessHasDeployError

            if ($actions.Count -eq 0 -and $assessCertsVerified) { $actions.Add("None - complete") }
            elseif ($actions.Count -eq 0 -and $assessCertsDone -and -not $assessNvramGood) { $actions.Add("UEFI cert update registered but KEK/DB not confirmed in NVRAM - may need reboot") }
            elseif ($actions.Count -eq 0 -and $assessCertsDone -and $assessHasDeployError) { $actions.Add("UEFI cert update registered but UEFICA2023Error key present - deployment error - investigate") }
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
        SecureBoot, vTPM, GuestRiskClass, Datastore, DSFreeGB, SnapshotEstimateGB, DSSpaceOK,
        KEK_2023, DB_2023, PK_Status, PK_Thumbprint, UEFICA2023Status,
        UEFICA2023Error, Evt1808, BitLockerActive, ActionNeeded -AutoSize

    $csvPath = ".\SecureBoot_Assess_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $assessReport | Select-Object @{N="ScriptVersion";E={$ScriptVersion}},* | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green

    $needHW      = ($assessReport | Where-Object { $_.HWVersionOK -eq $false -and $_.Firmware -eq "efi" }).Count
    $needPK      = ($assessReport | Where-Object { $_.PK_Status -in @("Valid_Other","Invalid_NULL") }).Count
    $notDone     = ($assessReport | Where-Object { $_.UEFICA2023Status -notin @("updated","Not collected") }).Count
    # VMs where cert update is verified (KEK/DB confirmed, no error key) regardless of PK state
    $certVerifiedOnly = ($assessReport | Where-Object {
        $_.UEFICA2023Status -eq "updated" -and
        $_.KEK_2023 -eq "True" -and $_.DB_2023 -eq "True" -and
        ($_.UEFICA2023Error -eq "" -or $_.UEFICA2023Error -eq "Not collected")
    }).Count
    # VMs where cert is verified AND PK is valid (fully ready for Secure Boot operations)
    $complete    = ($assessReport | Where-Object {
        $_.UEFICA2023Status -eq "updated" -and
        $_.KEK_2023 -eq "True" -and $_.DB_2023 -eq "True" -and
        ($_.UEFICA2023Error -eq "" -or $_.UEFICA2023Error -eq "Not collected") -and
        $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft","Not collected")
    }).Count
    # VMs where registry says "updated" but KEK/DB are not confirmed or an error key exists
    $certRegNotVerified = ($assessReport | Where-Object {
        $_.UEFICA2023Status -eq "updated" -and
        -not ($_.KEK_2023 -eq "True" -and $_.DB_2023 -eq "True")
    }).Count
    $regErrors   = ($assessReport | Where-Object { $_.UEFICA2023Error -ne "" -and $_.UEFICA2023Error -ne "Not collected" }).Count
    Write-Host ""
    Write-Host "Cert update verified           : $certVerifiedOnly / $($assessReport.Count)  (KEK/DB confirmed in NVRAM, no error key)" -ForegroundColor $(if ($certVerifiedOnly -eq $assessReport.Count) {"Green"} else {"Cyan"})
    Write-Host "Cert verified + PK valid       : $complete / $($assessReport.Count)  (fully ready for Secure Boot operations)" -ForegroundColor Green
    if ($certVerifiedOnly -gt $complete) {
        Write-Host "PK still needs enrollment      : $($certVerifiedOnly - $complete)  (cert done, PK is placeholder or invalid - run with -PKDerPath)" -ForegroundColor Yellow
    }
    if ($certRegNotVerified -gt 0) { Write-Host "Reg updated, KEK/DB unconfirmed: $certRegNotVerified  (may need reboot to populate NVRAM)" -ForegroundColor Yellow }
    if ($needHW     -gt 0) { Write-Host "Need HW upgrade (< v21)        : $needHW"    -ForegroundColor Yellow }
    if ($needPK     -gt 0) { Write-Host "Need PK enrollment             : $needPK"    -ForegroundColor Yellow }
    if ($notDone    -gt 0) { Write-Host "Cert update not complete       : $notDone"   -ForegroundColor Yellow }
    if ($regErrors  -gt 0) { Write-Host "Registry errors (UEFICA2023E.) : $regErrors" -ForegroundColor Red   }
    return
}

# =============================================================================
# STANDALONE HARDWARE UPGRADE MODE
# Upgrades hardware version on target VMs without running cert remediation.
# Powers off VMs that are running, upgrades hardware version, then powers them
# back on. VMs that were already powered off remain powered off after upgrade.
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
        Write-Host "Snapshots will be taken before each upgrade. Revert the Pre-HWUpgrade snapshot manually in vSphere Client if needed. The -Rollback switch does not restore hardware-upgrade snapshots." -ForegroundColor Cyan
    }
    Write-Host ""

    $hwSnapName = "Pre-HWUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    $hwReport = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($vm in $vms) {
        $currentVMName   = [string]$vm.Name
        $vmView   = $vm | Get-View
        $hwVerNum = [int](($vmView.Config.Version) -replace 'vmx-', '')
        Write-Host "`nProcessing: $currentVMName (current HW version: $hwVerNum)" -ForegroundColor White

        $hwRow = [PSCustomObject]@{
            VMName          = $currentVMName
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

        # Check host supports HW21 before taking a snapshot or powering off.
        $hostMaxHWCheck = Get-MaxHWVersionForHost -VMObj $vm
        if ($hostMaxHWCheck -lt 21) {
            $reason = if ($hostMaxHWCheck -eq 0) { "host version unknown or unsupported" } else { "host max HW is $hostMaxHWCheck" }
            Write-Warning "  Cannot upgrade to HW21 on this host ($reason) - skipping."
            $hwRow.Result  = "Skipped - host cannot support HW21 ($reason)"
            $hwRow.Notes  += "$reason. ESXi host must support HW21 for Secure Boot 2023 remediation. "
            $hwReport.Add($hwRow); continue
        }

        try {
            $wasPoweredOn = ($vm.PowerState -eq "PoweredOn")

            # Take snapshot before any changes (VM must be powered on for snapshot,
            # so snap before power off). Hardware version upgrade is irreversible
            # without a snapshot, so a snapshot failure skips the VM.
            if (-not $NoSnapshot) {
                if ($vm.PowerState -eq "PoweredOn") {
                    Write-Host "  Taking snapshot '$hwSnapName'..." -ForegroundColor Cyan
                } else {
                    Write-Host "  Taking snapshot of powered-off VM '$hwSnapName'..." -ForegroundColor Cyan
                }
                $snapRes = New-VMSnapshotSafe -VMObj $vm -Name $hwSnapName `
                    -Description "Pre-hardware-version-upgrade snapshot - rollback by reverting this snapshot"
                $hwRow.SnapshotCreated = $snapRes.Success
                $hwRow.SnapshotName    = if ($snapRes.Success) { $hwSnapName } else { "" }
                if (-not $snapRes.Success) {
                    Write-Warning "  Snapshot failed - skipping hardware upgrade for this VM (no rollback point)."
                    $hwRow.Result = "Skipped - snapshot failed"
                    $hwRow.Notes += "SKIPPED - snapshot failed, hardware upgrade not attempted. Reason: $($snapRes.Error) "
                    $hwReport.Add($hwRow)
                    continue
                }
            }

            if ($wasPoweredOn) {
                Write-Host "  Powering off..." -ForegroundColor Cyan
                Stop-VMGraceful -VM $vm -TimeoutSeconds $GracefulShutdownTimeout
            }

            $upResult = Invoke-VMHardwareUpgrade -VMObj $vm -TargetVersion 21
            $hwRow.Upgraded  = $upResult.Upgraded
            if ($upResult.Notes) { $hwRow.Notes += $upResult.Notes }

            if ($upResult.Upgraded) {
                if ($wasPoweredOn) {
                    Write-Host "  Powering on..." -ForegroundColor Cyan
                    Start-VM -VM $vm | Out-Null
                }
                $hwRow.ToVersion = $upResult.ToVersion
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
    $hwReport | Select-Object @{N="ScriptVersion";E={$ScriptVersion}},* | Export-Csv -Path $csvPath -NoTypeInformation
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
# =============================================================================
# CLEANUP MODE
# Handles -CleanupSnapshots, -CleanupHWSnapshots, and -CleanupNvram.
# All three can be combined in a single run. Ordering is enforced internally:
#   1. Pre-SecureBoot-Fix* snapshots (children - removed first)
#   2. Pre-HWUpgrade* snapshots      (parents  - removed second)
#   3. NVRAM backup files           (.nvram_old plus orphan .nvram_new, removed last, after snapshot rollback path is gone)
# Child snapshots are detected before removal. If a managed snapshot has non-managed
# children, it is skipped with a warning to avoid unexpected consolidation.
# =============================================================================
if ($CleanupSnapshots -or $CleanupHWSnapshots -or $CleanupNvram) {
    Write-Host "`n=== CLEANUP MODE ===" -ForegroundColor Cyan
    $modeList = @()
    if ($CleanupSnapshots)   { $modeList += "Pre-SecureBoot-Fix* snapshots" }
    if ($CleanupHWSnapshots) { $modeList += "Pre-HWUpgrade* snapshots" }
    if ($CleanupNvram)       { $modeList += "NVRAM backup files (.nvram_old/.nvram_new)" }
    Write-Host "Operations : $($modeList -join ', ')" -ForegroundColor Cyan
    Write-Host "Order      : SecureBoot-Fix snapshots -> HWUpgrade snapshots -> NVRAM files" -ForegroundColor Gray

    $vms = Resolve-TargetVMs
    if (-not $vms) { Write-Warning "No matching VMs found."; return }

    $serviceInstance = Get-View ServiceInstance
    $fileManager     = Get-View $serviceInstance.Content.FileManager

    # -------------------------------------------------------------------------
    # Build the full work list across all VMs and all requested operations
    # -------------------------------------------------------------------------
    $sbSnaps    = [System.Collections.Generic.List[PSObject]]::new()  # Pre-SecureBoot-Fix*
    $hwSnaps    = [System.Collections.Generic.List[PSObject]]::new()  # Pre-HWUpgrade*
    $nvramFiles = [System.Collections.Generic.List[PSObject]]::new()  # .nvram_old

    foreach ($vm in $vms) {
        # $vmView and $vmxDsName are used by snapshot work items for datastore grouping.
        # Assigned once here so they are available regardless of which cleanup switches
        # are active (-CleanupSnapshots / -CleanupHWSnapshots do not reach $CleanupNvram).
        $vmView    = $vm | Get-View
        $vmxDsName = ($vmView.Config.Files.VmPathName -replace '^\[(.+?)\].*', '$1')
        $allSnaps = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue

        if ($CleanupSnapshots) {
            $snaps = $allSnaps | Where-Object { $_.Name -like "${snapshotBaseName}*" }
            foreach ($snap in $snaps) {
                # Check for non-managed children - if any exist, warn and skip
                $children = $allSnaps | Where-Object { $_.ParentSnapshotId -eq $snap.Id }
                $unmanagedChildren = $children | Where-Object {
                    $_.Name -notlike "${snapshotBaseName}*" -and $_.Name -notlike "Pre-HWUpgrade*"
                }
                $notes = ""
                $skip  = $false
                if ($unmanagedChildren) {
                    $notes = "SKIPPED - has non-managed child snapshot(s): $($unmanagedChildren.Name -join ', '). Remove children first."
                    $skip  = $true
                    Write-Warning "  $($vm.Name): skipping '$($snap.Name)' - non-managed child snapshot(s) present: $($unmanagedChildren.Name -join ', ')"
                }
                $sbSnaps.Add([PSCustomObject]@{
                    VMName   = $vm.Name
                    VMId     = $vm.Id
                    DsName   = $vmxDsName
                    SnapName = $snap.Name
                    Created  = $snap.Created
                    SizeMB   = [math]::Round($snap.SizeMB, 1)
                    Snapshot = $snap
                    Skip     = $skip
                    Notes    = $notes
                })
            }
        }

        if ($CleanupHWSnapshots) {
            $snaps = $allSnaps | Where-Object { $_.Name -like "Pre-HWUpgrade*" }
            foreach ($snap in $snaps) {
                $children = $allSnaps | Where-Object { $_.ParentSnapshotId -eq $snap.Id }
                $unmanagedChildren = $children | Where-Object {
                    $_.Name -notlike "${snapshotBaseName}*" -and $_.Name -notlike "Pre-HWUpgrade*"
                }
                # Managed children (SecureBoot-Fix*) are handled first in step 1 above.
                # Only warn if non-managed children remain after step 1 would run.
                $managedChildren = $children | Where-Object { $_.Name -like "${snapshotBaseName}*" }
                $notes = ""
                $skip  = $false
                if ($unmanagedChildren) {
                    $notes = "SKIPPED - has non-managed child snapshot(s): $($unmanagedChildren.Name -join ', '). Remove children first."
                    $skip  = $true
                    Write-Warning "  $($vm.Name): skipping '$($snap.Name)' - non-managed child snapshot(s) present: $($unmanagedChildren.Name -join ', ')"
                } elseif ($managedChildren -and -not $CleanupSnapshots) {
                    $notes = "SKIPPED - has Pre-SecureBoot-Fix* child snapshot(s). Add -CleanupSnapshots to remove children first."
                    $skip  = $true
                    Write-Warning "  $($vm.Name): skipping '$($snap.Name)' - has Pre-SecureBoot-Fix* child(ren). Include -CleanupSnapshots to handle them."
                }
                $hwSnaps.Add([PSCustomObject]@{
                    VMName   = $vm.Name
                    VMId     = $vm.Id
                    DsName   = $vmxDsName
                    SnapName = $snap.Name
                    Created  = $snap.Created
                    SizeMB   = [math]::Round($snap.SizeMB, 1)
                    Snapshot = $snap
                    Skip     = $skip
                    Notes    = $notes
                })
            }
        }

        if ($CleanupNvram) {
            $vmView  = $vm | Get-View
            $vmxPath = $vmView.Config.Files.VmPathName
            $dsName  = $vmxPath -replace '^\[(.+?)\].*',         '$1'
            $vmDir   = $vmxPath -replace '^\[.+?\] (.+)/[^/]+$', '$1'
            try {
                $dcRef     = (Get-Datacenter -VM $vm | Get-View).MoRef
                $ds        = Resolve-VMXDatastore -VMObj $vm -VMViewObj $vmView
                $dsBrowser = Get-View $ds.ExtensionData.Browser
                $spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                $spec.MatchPattern = "*.nvram_old"
                $results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)
                if ($results -and $results.File) {
                    foreach ($file in $results.File) {
                        $lingering = $allSnaps | Where-Object { $_.Name -like "${snapshotBaseName}*" }
                        $notes = ""
                        $skip  = $false
                        if ($lingering -and -not $CleanupSnapshots) {
                            # Default: skip to protect the rollback path.
                            # The .nvram_old file is the only way to restore firmware state
                            # independently of the snapshot. Deleting it while the snapshot
                            # still exists removes the NVRAM-only rollback option.
                            # Add -CleanupSnapshots to remove both together, or remove
                            # snapshots manually first and re-run with -CleanupNvram alone.
                            $notes = "SKIPPED - Pre-SecureBoot-Fix* snapshot(s) still exist. Add -CleanupSnapshots to remove both together, or remove snapshots first."
                            $skip  = $true
                            Write-Warning "  $($vm.Name): skipping .nvram_old - Pre-SecureBoot-Fix* snapshot(s) still exist."
                            Write-Warning "  Add -CleanupSnapshots to remove both together, or remove snapshots first."
                        } elseif ($lingering -and $CleanupSnapshots) {
                            Write-Host "  $($vm.Name): snapshots will be removed first, then .nvram_old will be cleaned up after." -ForegroundColor Gray
                        }
                        $nvramFiles.Add([PSCustomObject]@{
                            VMName   = $vm.Name
                            VMId     = $vm.Id
                            FileName = $file.Path
                            FilePath = "[$dsName] $vmDir/$($file.Path)"
                            SizeKB   = [math]::Round($file.FileSize / 1KB, 1)
                            DcRef    = $dcRef
                            FM       = $fileManager
                            Skip     = $skip
                            Notes    = $notes
                            Kind     = "old"
                        })
                    }
                }
                # .nvram_new files are orphan backups left by a prior -Rollback (it
                # preserves the current .nvram as .nvram_new before restoring .nvram_old).
                # Nothing else removes them, so -CleanupNvram cleans them here. Unlike
                # .nvram_old they do NOT protect a rollback path, so they are never
                # skipped on account of lingering snapshots.
                $newSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                $newSpec.MatchPattern = "*.nvram_new"
                $newResults = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $newSpec)
                if ($newResults -and $newResults.File) {
                    foreach ($file in $newResults.File) {
                        Write-Host "  $($vm.Name): found orphan .nvram_new backup (left by a prior rollback) - will remove." -ForegroundColor Gray
                        $nvramFiles.Add([PSCustomObject]@{
                            VMName   = $vm.Name
                            VMId     = $vm.Id
                            FileName = $file.Path
                            FilePath = "[$dsName] $vmDir/$($file.Path)"
                            SizeKB   = [math]::Round($file.FileSize / 1KB, 1)
                            DcRef    = $dcRef
                            FM       = $fileManager
                            Skip     = $false
                            Notes    = "Orphan .nvram_new backup from a prior rollback."
                            Kind     = "new"
                        })
                    }
                }
            } catch {
                Write-Warning "  Could not search datastore for $($vm.Name): $($_.Exception.Message)"
            }
        }
    }

    $totalItems = $sbSnaps.Count + $hwSnaps.Count + $nvramFiles.Count
    if ($totalItems -eq 0) {
        Write-Host "`nNothing to clean up on target VMs." -ForegroundColor Green
        return
    }

    # -------------------------------------------------------------------------
    # Display summary and confirm
    # -------------------------------------------------------------------------
    if ($sbSnaps.Count -gt 0) {
        Write-Host "`nPre-SecureBoot-Fix* snapshots to remove:" -ForegroundColor Yellow
        $sbSnaps | Format-Table VMName, SnapName, Created,
            @{N="Size(MB)"; E={$_.SizeMB}}, @{N="Status"; E={if ($_.Skip) {"SKIP"} else {"Remove"}}} -AutoSize
    }
    if ($hwSnaps.Count -gt 0) {
        Write-Host "Pre-HWUpgrade* snapshots to remove:" -ForegroundColor Yellow
        $hwSnaps | Format-Table VMName, SnapName, Created,
            @{N="Size(MB)"; E={$_.SizeMB}}, @{N="Status"; E={if ($_.Skip) {"SKIP"} else {"Remove"}}} -AutoSize
    }
    if ($nvramFiles.Count -gt 0) {
        Write-Host "NVRAM backup files to delete:" -ForegroundColor Yellow
        $nvramFiles | Format-Table VMName, FileName,
            @{N="Size(KB)"; E={$_.SizeKB}}, @{N="Status"; E={if ($_.Skip) {"SKIP"} else {"Delete"}}} -AutoSize
    }

    $snapTotal  = (($sbSnaps + $hwSnaps) | Where-Object { -not $_.Skip } | Measure-Object -Property SizeMB -Sum).Sum
    $nvramTotal = ($nvramFiles | Where-Object { -not $_.Skip } | Measure-Object -Property SizeKB -Sum).Sum
    Write-Host "Space reclaimed : $([math]::Round(($snapTotal + $nvramTotal / 1KB) / 1024, 2)) GB (approx)" -ForegroundColor Yellow

    if (-not $Confirm) {
        $confirmInput = Read-Host "`nProceed? (Y/N)"
        if ($confirmInput -notmatch '^[Yy]') { Write-Host "Aborted."; return }
    } else {
        Write-Host "Proceed? (Y/N): y (auto-confirmed via -Confirm)" -ForegroundColor Gray
    }

    # -------------------------------------------------------------------------
    # Step 1: Remove Pre-SecureBoot-Fix* snapshots (parallel across datastores)
    # -------------------------------------------------------------------------
    $cleanupReport = [System.Collections.Generic.List[PSObject]]::new()
    $step1Results  = $null   # SecureBoot-Fix snapshot removal results (populated if -CleanupSnapshots)
    $step2Results  = $null   # HWUpgrade snapshot removal results (populated if -CleanupHWSnapshots)

    if ($CleanupSnapshots -and $sbSnaps.Count -gt 0) {
        Write-Host "`n--- Removing Pre-SecureBoot-Fix* snapshots ---" -ForegroundColor Cyan
        $step1Results = Remove-SnapshotsParallel -Items $sbSnaps -TypeLabel "Snapshot (SecureBoot-Fix)"
        foreach ($r in $step1Results) { $cleanupReport.Add($r) }
    }

    # -------------------------------------------------------------------------
    # Step 2: Remove Pre-HWUpgrade* snapshots (parallel across datastores)
    # -------------------------------------------------------------------------
    if ($CleanupHWSnapshots -and $hwSnaps.Count -gt 0) {
        Write-Host "`n--- Removing Pre-HWUpgrade* snapshots ---" -ForegroundColor Cyan
        $step2Results = Remove-SnapshotsParallel -Items $hwSnaps -TypeLabel "Snapshot (HWUpgrade)"
        foreach ($r in $step2Results) { $cleanupReport.Add($r) }
    }

    # -------------------------------------------------------------------------
    # Before Step 3: if -CleanupSnapshots ran, re-check which VMs had incomplete
    # SecureBoot snapshot removal and protect their .nvram_old from deletion.
    # A .nvram_old file is the NVRAM-only rollback path. If the snapshot rollback
    # path could not be removed (failure or skip), the .nvram_old must be kept.
    # This only matters when both -CleanupSnapshots and -CleanupNvram are used.
    # -------------------------------------------------------------------------
    if ($CleanupSnapshots -and $CleanupNvram -and $step1Results) {
        # Build a set of VMs whose SecureBoot snapshots were NOT fully removed.
        # Keyed by VMId (MoRef), not display name, so duplicate VM display names
        # cannot cause one VM's failed snapshot cleanup to protect another VM's
        # .nvram_old. Consistent with the MoRef-based resolution used elsewhere.
        $snapNotCleared = @{}
        foreach ($r in $step1Results) {
            if ($r.Result -ne "Removed") {
                $snapNotCleared[$r.VMId] = $r.Result
            }
        }
        if ($snapNotCleared.Count -gt 0) {
            foreach ($item in $nvramFiles) {
                # Only .nvram_old files protect a rollback path and must be preserved
                # when a snapshot was not cleared. .nvram_new orphans never protect a
                # rollback and are always safe to delete, so they are excluded here.
                if ($item.Kind -eq "old" -and -not $item.Skip -and $snapNotCleared.ContainsKey($item.VMId)) {
                    $item.Skip  = $true
                    $item.Notes = "SKIPPED - SecureBoot snapshot removal did not complete ($($snapNotCleared[$item.VMId])). Preserving .nvram_old as rollback protection."
                    Write-Warning "  $($item.VMName): protecting .nvram_old - snapshot removal result was '$($snapNotCleared[$item.VMId])'."
                }
            }
        }
    }

    # -------------------------------------------------------------------------
    # Step 3: Delete NVRAM backup files (.nvram_old and orphan .nvram_new)
    # -------------------------------------------------------------------------
    if ($CleanupNvram -and $nvramFiles.Count -gt 0) {
        Write-Host "`n--- Deleting NVRAM backup files ---" -ForegroundColor Cyan
        $step3Results = Remove-NvramFilesParallel -Items $nvramFiles
        foreach ($r in $step3Results) { $cleanupReport.Add($r) }
    }

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    Write-Host "`n=== CLEANUP SUMMARY ===" -ForegroundColor White
    $cleanupReport | Format-Table Type, VMName, Item, SizeMB, Result, Notes -AutoSize

    $removed = ($cleanupReport | Where-Object { $_.Result -in @("Removed","Deleted") }).Count
    $skipped = ($cleanupReport | Where-Object { $_.Result -eq "Skipped" }).Count
    $failed  = ($cleanupReport | Where-Object { $_.Result -in @("Failed","Timeout") }).Count
    Write-Host "Completed : $removed" -ForegroundColor Green
    if ($skipped -gt 0) { Write-Host "Skipped   : $skipped (see Notes column)" -ForegroundColor Yellow }
    if ($failed  -gt 0) { Write-Host "Failed    : $failed (remove manually via vSphere client)" -ForegroundColor Red }

    $csvPath = ".\SecureBoot_Cleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $cleanupReport | Select-Object @{N="ScriptVersion";E={$ScriptVersion}},* | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green
    return
}

# =============================================================================
# ROLLBACK MODE
# For each target VM:
#   0. Confirm a .nvram_old backup or Pre-SecureBoot-Fix* snapshot exists.
#      If neither is present, skip the VM with no power cycle.
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

    if (-not $Confirm) {
        $proceedRollback = Read-Host "Proceed with rollback? (Y/N)"
        if ($proceedRollback -notmatch '^[Yy]') { Write-Host "Aborted."; return }
    } else {
        Write-Host "Proceed with rollback? (Y/N): y (auto-confirmed via -Confirm)" -ForegroundColor Gray
    }

    $rollbackReport = [System.Collections.Generic.List[PSObject]]::new()

    foreach ($vm in $vms) {
        $currentVMName = [string]$vm.Name
        $currentVMId   = $vm.Id
        Write-Host "`n$('='*60)" -ForegroundColor White
        Write-Host "Rolling back: $currentVMName" -ForegroundColor White
        Write-Host "$('='*60)" -ForegroundColor White

        $row = [PSCustomObject]@{
            VMName           = $currentVMName
            PoweredOff       = $false
            NVRAMRestored    = $false
            SnapshotReverted = $false
            PoweredOn        = $false
            Result           = "Pending"
            Notes            = ""
        }

        try {
            # Pre-flight - confirm there is something to roll back to before
            # powering off. Rollback acts on a .nvram_old backup (NVRAM file
            # restore) or a Pre-SecureBoot-Fix snapshot (revert). With neither
            # present there is nothing to restore, so the VM is left untouched
            # instead of being power cycled for no reason.
            $hasNvramOld  = $false
            $nvramCheckOk = $true
            try {
                $preCtx  = Get-VMDatastoreContext -VMObj $vm
                $preSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                $preSpec.MatchPattern = "*.nvram*"
                $preResults = $preCtx.DsBrowser.SearchDatastoreSubFolders(
                    "[$($preCtx.DsName)] $($preCtx.VmDir)", $preSpec)
                if ($preResults -and $preResults.File) {
                    $hasNvramOld = ($null -ne ($preResults.File | Where-Object { $_.Path -match '\.nvram_old$' }))
                }
            } catch {
                $nvramCheckOk = $false
                Write-Warning "  Could not check for a .nvram_old backup: $($_.Exception.Message)"
            }

            $snap = Get-Snapshot -VM $vm -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "${snapshotBaseName}*" } |
                    Sort-Object -Property Created -Descending |
                    Select-Object -First 1

            if (-not $hasNvramOld -and -not $snap) {
                if ($nvramCheckOk) {
                    Write-Host "  Nothing to roll back - no .nvram_old backup and no $snapshotBaseName snapshot found." -ForegroundColor Yellow
                    $row.Result = "Skipped - nothing to roll back"
                    $row.Notes  = "No .nvram_old backup and no $snapshotBaseName snapshot present. VM not powered off."
                } else {
                    Write-Warning "  Could not verify a .nvram_old backup and found no $snapshotBaseName snapshot. Resolve datastore access and re-run."
                    $row.Result = "Skipped - could not verify rollback targets"
                    $row.Notes  = "Datastore .nvram_old check failed and no $snapshotBaseName snapshot present. VM not powered off."
                }
                Write-Host "  Leaving VM powered $($vm.PowerState) and untouched - no power cycle performed." -ForegroundColor Gray
                $rollbackReport.Add($row)
                continue
            }

            # Step 1 - Power off
            Write-Host "  [1/4] Powering off..." -ForegroundColor Cyan
            if ($vm.PowerState -eq "PoweredOn") {
                Stop-VMGraceful -VM $vm -TimeoutSeconds $GracefulShutdownTimeout
                $vm = Get-VM -Id $currentVMId -ErrorAction SilentlyContinue
            }
            $row.PoweredOff = $true

            # Step 2 - Restore NVRAM
            Write-Host "  [2/4] Restoring NVRAM file..." -ForegroundColor Cyan
            $row.NVRAMRestored = Restore-VMNvram -VMObj $vm
            if (-not $row.NVRAMRestored) {
                $row.Notes += "NVRAM restore failed or no .nvram_old found. "
                Write-Warning "  NVRAM restore failed - check datastore manually."
            }

            # Step 3 - Revert snapshot if one exists ($snap was located during pre-flight)
            Write-Host "  [3/4] Checking for Pre-SecureBoot-Fix snapshot..." -ForegroundColor Cyan
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
            # Before powering on, verify an active .nvram file exists.
            # If Restore-VMNvram logged a CRITICAL failure and could not recover
            # .nvram_new back to .nvram, the VM may have no active NVRAM file.
            # Powering it on without NVRAM would cause firmware initialization errors.
            Write-Host "  [4/4] Verifying NVRAM state before power-on..." -ForegroundColor Cyan
            $nvramOk = $false
            try {
                $rollCtx = Get-VMDatastoreContext -VMObj $vm
                $nvramCheckSpec = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
                $nvramCheckSpec.MatchPattern = "*.nvram"
                $nvramCheckResult = $rollCtx.DsBrowser.SearchDatastoreSubFolders(
                    "[$($rollCtx.DsName)] $($rollCtx.VmDir)", $nvramCheckSpec)
                $nvramOk = ($nvramCheckResult -and $nvramCheckResult.File)
            } catch {
                # Cannot verify - log warning but allow power-on attempt
                Write-Warning "  Could not verify NVRAM presence: $($_.Exception.Message) - proceeding."
                $nvramOk = $true
            }

            if (-not $nvramOk) {
                Write-Warning "  CRITICAL: No active .nvram file found - skipping power-on to protect VM."
                Write-Warning "  Restore NVRAM manually via vSphere Client before powering on."
                $row.Notes += "Power-on skipped - no active .nvram file found after restore. Restore manually. "
                $row.Result = "Failed - no active NVRAM"
                $rollbackReport.Add($row)
                continue
            }

            Write-Host "  [4/4] Powering on..." -ForegroundColor Cyan
            $vm = Get-VM -Id $currentVMId
            Start-VM -VM $vm | Out-Null
            if (Wait-VMTools -VM $vm -TimeoutSeconds 300) {
                $row.PoweredOn = $true
                Write-Host "  VM is back online." -ForegroundColor Green
            } else {
                $row.Notes += "Tools timeout after power on - VM may still be booting. "
            }

            $row.Result = if     ($row.NVRAMRestored -and $row.SnapshotReverted -and $row.PoweredOn) { "Rolled Back (NVRAM + Snapshot)" }
                          elseif ($row.SnapshotReverted -and $row.PoweredOn)                          { "Rolled Back (via snapshot, NVRAM file restore not needed)" }
                          elseif ($row.NVRAMRestored -and $row.PoweredOn)                             { "Rolled Back (NVRAM file only - no snapshot, registry NOT reverted)" }
                          elseif ($row.PoweredOn)                                                     { "Partial - NVRAM not restored and no snapshot reverted" }
                          else                                                                         { "Partial - check VM" }

            $color = if ($row.Result -like "Rolled Back*") { "Green" } else { "Yellow" }
            Write-Host ("  NVRAM Restored: {0} | Snapshot Reverted: {1} | Result: {2}" -f
                $row.NVRAMRestored, $row.SnapshotReverted, $row.Result) -ForegroundColor $color

        } catch {
            $row.Result  = "ERROR"
            $row.Notes  += "Exception: $($_.Exception.Message)"
            Write-Warning "  Error rolling back $currentVMName`: $($_.Exception.Message)"
        }

        $rollbackReport.Add($row)
    }

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "ROLLBACK SUMMARY" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White
    $rollbackReport | Format-Table VMName, PoweredOff, NVRAMRestored,
        SnapshotReverted, PoweredOn, Result, Notes -AutoSize

    $csvPath = ".\SecureBoot_Rollback_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $rollbackReport | Select-Object @{N="ScriptVersion";E={$ScriptVersion}},* | Export-Csv -Path $csvPath -NoTypeInformation
    Write-Host "Exported to: $csvPath" -ForegroundColor Green

    $full    = ($rollbackReport | Where-Object { $_.Result -like "Rolled Back*" }).Count
    $partial = ($rollbackReport | Where-Object { $_.Result -like "Partial*"     }).Count
    $skipped = ($rollbackReport | Where-Object { $_.Result -like "Skipped*"     }).Count
    $errors  = ($rollbackReport | Where-Object { $_.Result -eq  "ERROR"         }).Count

    Write-Host ""
    Write-Host "Rolled back : $full / $($rollbackReport.Count)" -ForegroundColor Green
    if ($partial -gt 0) { Write-Host "Partial     : $partial (review Notes column)" -ForegroundColor Yellow }
    if ($skipped -gt 0) { Write-Host "Skipped     : $skipped (nothing to roll back - see Notes)" -ForegroundColor Gray   }
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
    Write-Host "Snapshot mode   : DISABLED (-NoSnapshot specified)." -ForegroundColor Yellow
} else {
    Write-Host "Snapshot name   : $snapshotName" -ForegroundColor Cyan
    Write-Host "Retain snapshots: $RetainSnapshots" -ForegroundColor Cyan

    # Datastore space check - run before confirmation so issues are visible upfront
    Write-Host "`nChecking datastore space for $($vms.Count) VM(s)..." -ForegroundColor Cyan
    $spaceWarnings = 0
    foreach ($sv in $vms) {
        $dsInfo = Get-VMDatastoreSpaceInfo -VMObj $sv
        $color  = if ($dsInfo.Sufficient) { "Gray" } else { "Yellow" }
        Write-Host ("  {0,-30} DS: {1,-25} Free: {2,7} GB   Est snapshot: {3,10}   {4}" -f
            $sv.Name, $dsInfo.Datastore, $dsInfo.FreeGB, $dsInfo.EstimateDisplay,
            $(if (-not $dsInfo.Sufficient) { "<<< WARNING" } elseif ($dsInfo.FallbackUsed) { "(fixed fallback)" } else { "" })) -ForegroundColor $color
        if ($dsInfo.FallbackUsed) {
            Write-Host "    NOTE: $($sv.Name) - snapshot estimate is a fixed $($dsInfo.EstimateDisplay) fallback (existing snapshots detected, delta size unavailable from vCenter)." -ForegroundColor Yellow
        }
        if (-not $dsInfo.Sufficient) {
            Write-Warning "  $($dsInfo.Warning)"
            $spaceWarnings++
        }
    }
    if ($spaceWarnings -gt 0) {
        Write-Warning "$spaceWarnings VM(s) have potential datastore space issues. Review warnings above before continuing."
    } else {
        Write-Host "  Space check OK." -ForegroundColor Green
    }
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
        $jsonLine = Get-LastJsonLine -Text $exportOut.ScriptOutput
        if (-not $jsonLine) {
            Write-Warning "    BitLocker key export returned no parseable JSON - skipping VM."
            return $false
        }
        $exportData = $jsonLine | ConvertFrom-Json
        if (-not $exportData) {
            Write-Warning "    BitLocker recovery key export returned no usable data - skipping VM."
            return $false
        }

        # Check for active-protected volumes with no RecoveryPassword protector.
        # These volumes cannot be recovered if PCR7 changes trigger recovery mode.
        $unprotected = @($exportData.UnprotectedVolumes)
        if ($unprotected.Count -gt 0) {
            Write-Warning "    The following active-protected volume(s) have no RecoveryPassword protector:"
            foreach ($mp in $unprotected) { Write-Warning "      $mp" }
            Write-Warning "    Skipping VM - cannot proceed without recovery keys for all protected volumes."
            Write-Warning "    Add a RecoveryPassword protector to each volume and re-run."
            return $false
        }

        $keyData = @($exportData.Keys)
        if ($keyData.Count -eq 0) {
            Write-Warning "    BitLocker is active but no RecoveryPassword protectors were found on this VM."
            Write-Warning "    Skipping VM - cannot proceed without a recovery key backup."
            Write-Warning "    Ensure at least one RecoveryPassword protector is configured before running."
            return $false
        }

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
            Write-Warning "    Note: this file is written by the account running this script (the process"
            Write-Warning "    identity), NOT the -GuestCredential used inside the VM. If the share works in"
            Write-Warning "    File Explorer but is denied here, common causes are: the SMB (share-level)"
            Write-Warning "    permission grants only Read while NTFS grants Full (effective access is the"
            Write-Warning "    more restrictive of the two), a UAC token difference between an elevated"
            Write-Warning "    session and Explorer, or a cached SMB session under a different account."
            Write-Warning "    Verify the script account has write access at BOTH the share and NTFS levels."
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
    $currentVMName      = [string]$vm.Name
    $currentVMId        = $vm.Id   # MoRef-based Id for safe refresh when duplicate names exist
    $snapCreated        = $false
    $tpmData            = $null   # populated in step 0 only when GuestCredential is provided
    $skipPKRemediation  = $false  # may be set true by BitLocker/safety checks before step 9
    $certGood           = $false  # set in snapshot disposition, init here to prevent stale values
    $pkGoodAlready      = $false  # set by the guest pre-check, init here to prevent stale cross-VM values
    $pkGood             = $false  # set in step 8, init here to prevent stale values across VMs
    $pkExistingMismatch = $false  # set in step 8 when an existing valid PK does not match -ExpectedPKThumbprint
    $pkThumbMatchesExpected = $true
    $pkBitLockerActive  = $false  # set in step 8, init here to prevent stale values across VMs
    $pkCheckOk          = $false  # set in step 8, init here to prevent stale value when HW<14 skips step 8
    # Capture timestamp before any changes so event log checks only consider
    # events generated during this run, not from prior runs or reboots.
    $vmRunStart  = (Get-Date).AddSeconds(-5)  # 5s buffer for clock skew

    Write-Host "`n$('='*60)" -ForegroundColor White
    Write-Host "Processing: $currentVMName" -ForegroundColor White
    Write-Host "$('='*60)" -ForegroundColor White
    $toolsVer    = $vm.Guest.ToolsVersion
    $toolsStatus = $vm.Guest.ExtensionData.ToolsVersionStatus
    $toolsColor  = if ($toolsStatus -eq "guestToolsCurrent") { "Green" } elseif ($toolsStatus -eq "guestToolsNeedUpgrade") { "Yellow" } else { "Gray" }
    Write-Host "  VMware Tools: $toolsVer ($toolsStatus)" -ForegroundColor $toolsColor

    $row = [PSCustomObject]@{
        VMName              = $currentVMName
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
        Evt1036             = ""
        Evt1043             = ""
        Evt1044             = ""
        Evt1045             = ""
        Evt1795             = ""
        Evt1797             = ""
        Evt1799             = ""
        Evt1800             = ""
        Evt1801             = ""
        Evt1802             = ""
        Evt1803             = ""
        Evt1808             = ""
        PK_Status           = "Not checked"
        PK_Subject          = ""
        PK_Issuer           = ""
        PK_Thumbprint       = ""
        PK_Serial           = ""
        PK_NotAfter         = ""
        PKEnrolled          = $false
        PKRemediated        = $false
        FullyRemediated     = $false
        CertUpdateVerified  = $false
        PKMethod            = "NotAttempted"
        CertMethod          = "NotAttempted"
        SnapshotRetained    = $false
        Notes               = ""
    }

    try {
        # Detect vTPM and Windows guest OS from VM hardware config. This uses
        # vCenter data only and is not dependent on guest credentials or step 0
        # succeeding. Used in step 9 for PK remediation path selection and gating
        # so it must be set before any guest-dependent data is collected.
        $vmViewForTpm       = $vm | Get-View
        $hasVirtualTPM      = @($vmViewForTpm.Config.Hardware.Device |
                                Where-Object { $_.GetType().Name -eq "VirtualTPM" }).Count -gt 0

        # Determine whether the guest OS is a known Linux/non-Windows type.
        # GuestFamily "linuxGuest" is the most authoritative indicator. GuestId
        # pattern-matching covers cases where GuestFamily is not yet populated.
        # vTPM-enabled VMs that are NOT positively identified as Linux are treated
        # as Windows-risk per Broadcom KB 423893, which recommends the VMX
        # resetOnce path only for Linux vTPM-enabled VMs and advises waiting for
        # the capsule-based solution for Windows vTPM-enabled VMs.
        $cfgGuestId           = [string]$vmViewForTpm.Config.GuestId
        $rtGuestFamily        = [string]$vm.Guest.GuestFamily
        $knownLinuxGuest      = ($rtGuestFamily -eq "linuxGuest") -or
                                ($cfgGuestId -match 'linux|ubuntu|debian|rhel|redhat|centos|oracle|sles|suse|rocky|alma|photon|freebsd|otherLinux')
        $hwGuestIsWindows     = ($rtGuestFamily -eq "windowsGuest" -or $cfgGuestId -like "windows*")
        # Conservative gate: treat as Windows-risk unless positively identified as Linux
        $hwGuestIsWindowsOrUnknownRisk = $hwGuestIsWindows -or -not $knownLinuxGuest

        # ------------------------------------------------------------------
        # Pre-mutation safety gate
        # Applied to all VMs including those named explicitly via -VMName.
        # Explicitly named VMs bypass discovery filters but must still pass
        # these safety checks before any mutating operation is performed.
        # ------------------------------------------------------------------
        $vmViewGate = $vm | Get-View
        $gateFirmware  = $vmViewGate.Config.Firmware
        $gateSecureBoot = $vmViewGate.Config.BootOptions.EfiSecureBootEnabled
        $gateHWVerNum   = [int](($vmViewGate.Config.Version) -replace 'vmx-', '')
        $gateHostVer    = (Get-VMHost -VM $vm -EA SilentlyContinue).Version
        # Parse full version for accurate minimum-version checks (8.0.2+ required
        # for NVRAM regeneration to include 2023 certificates).
        $gateHostVerObj = $null
        try { $gateHostVerObj = [version]$gateHostVer } catch {}
        $hostSupports2023Nvram = ($null -ne $gateHostVerObj -and $gateHostVerObj -ge [version]"8.0.2")
        $gateSkip       = $false

        if ($gateFirmware -ne "efi") {
            Write-Warning "  Skipping $currentVMName - BIOS firmware. Secure Boot not supported."
            $row.Notes += "SKIPPED - BIOS firmware, Secure Boot not supported. "
            $gateSkip = $true
        } elseif (-not $gateSecureBoot) {
            Write-Warning "  Skipping $currentVMName - Secure Boot is disabled."
            $row.Notes += "SKIPPED - Secure Boot disabled. "
            $gateSkip = $true
        } elseif ($gateHWVerNum -lt 13) {
            Write-Warning "  Skipping $currentVMName - Hardware version $gateHWVerNum < 13. Secure Boot not supported."
            $row.Notes += "SKIPPED - HW version $gateHWVerNum < 13. Secure Boot requires HW13+. "
            $gateSkip = $true
        }
        # Note: ESXi 8.0.2+ and HW <21 gates are applied AFTER the smart pre-check
        # (see late NVRAM gates below) so that VMs already remediated can still
        # complete guest cert/PK work even on older ESXi or sub-21 hardware.

        if ($gateSkip) {
            $row.FinalStatus = "Skipped_SafetyGate"
            $report.Add($row)
            continue
        }

        # Skip positively identified non-Windows/Linux guests by default.
        # The script targets Windows Secure Boot remediation. Linux vTPM PK
        # guidance follows separate Broadcom/OS-vendor paths (KB 423893).
        if ($knownLinuxGuest -and -not $AllowNonWindowsTargets) {
            Write-Warning "  Skipping $currentVMName - Linux guest detected. This script targets Windows Secure Boot remediation."
            Write-Warning "  For Linux vTPM PK remediation use Broadcom-supported methods per KB 423893."
            Write-Warning "  Use -AllowNonWindowsTargets to override (hypervisor-only steps only, Windows guest scripts will fail)."
            $row.FinalStatus = "Skipped_NonWindowsGuest"
            $row.Notes      += "SKIPPED - Linux guest. Use Broadcom/OS-vendor guidance for Linux Secure Boot remediation. "
            $report.Add($row)
            continue
        }
        if ($knownLinuxGuest -and $AllowNonWindowsTargets) {
            Write-Warning "  Note: $currentVMName is a Linux guest. Hypervisor-only steps will run (no guest scripts)."
            Write-Warning "  For Linux PK remediation follow Broadcom methods per KB 423893."
        }

        # ------------------------------------------------------------------
        # Powered-off VM safety checks (guest-credential mode only)
        # In no-credential mode powered-off VMs are handled naturally since
        # step 0 is skipped. The NVRAM rename proceeds after power-off in step 2.
        # In guest-credential mode a powered-off VM means BitLocker state cannot
        # be confirmed before hardware, NVRAM, or Secure Boot changes are made.
        # ------------------------------------------------------------------
        $nvramSuppressed      = $SkipNVRAMRename -or $SupportedMethodsOnly
        $hwUpgradeWillPowerOn = $UpgradeHardware -and ($gateHWVerNum -lt 21)
        if ($GuestCredential -and $vm.PowerState -ne "PoweredOn") {
            if ($nvramSuppressed -and -not $hwUpgradeWillPowerOn) {
                # -SkipNVRAMRename and -SupportedMethodsOnly both suppress the NVRAM
                # regeneration. With no hardware upgrade that would power the VM on,
                # no power cycle will occur, but step 5+ require the VM to be running.
                # Skip rather than fail.
                $skipSwitch = if ($SupportedMethodsOnly) { "-SupportedMethodsOnly" } else { "-SkipNVRAMRename" }
                Write-Warning "  Skipping $currentVMName - VM is powered off with $skipSwitch and no power cycle scheduled."
                Write-Warning "  Guest cert and PK steps require the VM to be powered on. Power on and re-run."
                $row.FinalStatus = "Skipped_VMOff"
                $row.Notes      += "SKIPPED - VM powered off with $skipSwitch and no power cycle scheduled. Guest steps require the VM to be running. "
                $report.Add($row)
                continue
            } elseif (-not $AllowPoweredOffVMRemediation) {
                # Any powered-off VM that would be power-cycled, by an NVRAM rename or
                # by a hardware upgrade that powers it on, is skipped by default because
                # BitLocker/TPM state cannot be confirmed before those changes.
                Write-Warning "  Skipping $currentVMName - VM is powered off."
                Write-Warning "  BitLocker/TPM state cannot be confirmed before hardware, NVRAM, or Secure Boot changes are made."
                Write-Warning "  Power on the VM and re-run, or use -AllowPoweredOffVMRemediation to override"
                Write-Warning "  only if recovery keys are backed up and protection is suspended."
                $row.FinalStatus      = "Skipped_BitLockerStateUnknown"
                $row.BitLockerSkipped = $true
                $row.Notes           += "SKIPPED - VM powered off, so BitLocker/TPM state cannot be confirmed before hardware, NVRAM, or Secure Boot changes. Use -AllowPoweredOffVMRemediation to override. "
                $report.Add($row)
                continue
            } else {
                Write-Warning "  VM is powered off - BitLocker/TPM state not checked (-AllowPoweredOffVMRemediation)."
                Write-Warning "  Ensure recovery keys are backed up and protection is suspended."
            }
        }

        # ------------------------------------------------------------------


        # ------------------------------------------------------------------
        # Pre-check - assess current VM state to determine which steps can
        # be skipped. Only runs if VM is powered on and GuestCredential is
        # available. Sets $entryStep to control step gating below.
        #
        # entryStep values:
        #   "full"       - run all steps (default, NVRAM stale or unknown)
        #   "skipNvram"  - skip steps 2/2b/3/4 (KEK already present in NVRAM)
        #   "skipToStep6"- skip steps 2/2b/3/4/5 (0x4100, need reboot only)
        #   "certDone"   - skip to step 8 (cert update complete, PK check only)
        #   "allDone"    - VM fully remediated, skip entirely
        # ------------------------------------------------------------------
        $entryStep = "full"
        if ($vm.PowerState -eq "PoweredOn" -and $GuestCredential) {
            Write-Host "  [Pre] Assessing current state to determine required steps..." -ForegroundColor Cyan
            try {
                $preOut  = Invoke-VMScriptViaFile -VM $vm -ScriptContent $assessGuestScript `
                    -GuestCredential $GuestCredential
                $preJson = Get-LastJsonLine -Text $preOut.ScriptOutput
                if ($preJson) {
                    $pre = $preJson | ConvertFrom-Json

                    $hasDeployError = ($pre.UEFICA2023ErrorExists -eq "True")
                    $certsDone  = ($pre.UEFICA2023Status -eq "updated" -or $pre.AvailableUpdates -eq "0x4000")
                    $nvramGood  = ($pre.KEK_2023 -eq "True" -and $pre.DB_2023 -eq "True")
                    if ($nvramGood) { $row.CertMethod = "AlreadyPresent" }
                    $halfwayThere = ($nvramGood -and $pre.AvailableUpdates -eq "0x4100")
                    $pkGoodAlready = ($pre.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft"))
                    # If an expected thumbprint was supplied, an already-valid PK
                    # only counts as "done" when it actually matches that value.
                    $preThumbMatches = Test-ExpectedPKThumbprint -Expected $ExpectedPKThumbprint -Actual $pre.PK_Thumbprint
                    $pkGoodAndMatches = ($pkGoodAlready -and $preThumbMatches)
                    # allDone and certDone require KEK/DB confirmed in NVRAM and no error key.
                    # Registry status "updated" alone is insufficient if firmware cert
                    # verification failed or a UEFICA2023Error registry key is present.
                    $certsVerified = $certsDone -and $nvramGood -and -not $hasDeployError

                    if ($certsVerified -and $pkGoodAlready -and -not $preThumbMatches -and -not ($ReplaceExistingPK -and $PKDerPath)) {
                        # Certs are done and the PK is valid, but it does not match
                        # -ExpectedPKThumbprint and the operator did not ask to
                        # replace it. Not a failure (working PK present). Surface
                        # the existing PK for review and do not mark FullyRemediated.
                        $entryStep = "allDone"
                        Write-Host "  [Pre] Certs verified and PK valid, but PK does NOT match -ExpectedPKThumbprint - skipping VM." -ForegroundColor Yellow
                        Write-Host "        The VM has a working Platform Key. It is simply not the certificate you specified." -ForegroundColor Yellow
                        $row.FinalStatus     = "Updated"
                        $row.KEK_2023        = $pre.KEK_2023
                        $row.DB_2023         = $pre.DB_2023
                        $row.PK_Status       = $pre.PK_Status
                        if ($pre.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pre.PK_Subject }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pre.PK_Issuer }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pre.PK_Thumbprint }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pre.PK_Serial }
                        if ($pre.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pre.PK_NotAfter }
                        Write-Host ("        Existing PK Thumbprint: {0}" -f $row.PK_Thumbprint) -ForegroundColor Gray
                        Write-Host ("        Existing PK Subject   : {0}" -f $row.PK_Subject) -ForegroundColor Gray
                        Write-Host "        Re-run with -ReplaceExistingPK -PKDerPath <file> to replace it." -ForegroundColor Yellow
                        $row.Evt1808         = $pre.Evt1808
                        $row.SnapshotRetained = $snapCreated
                        $row.FullyRemediated    = $false
                        $row.CertUpdateVerified = $true
                        $expectTpNorm = ($ExpectedPKThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                        $row.Notes          += "Pre-check: certs verified, existing valid PK does not match -ExpectedPKThumbprint (expected $expectTpNorm, found $($row.PK_Thumbprint), Subject $($row.PK_Subject), NotAfter $($row.PK_NotAfter)). Re-run with -ReplaceExistingPK to replace it. "
                        $report.Add($row)
                        continue
                    } elseif ($certsVerified -and $pkGoodAndMatches) {
                        $entryStep = "allDone"
                        Write-Host "  [Pre] Fully remediated - skipping VM." -ForegroundColor Green
                        $row.FinalStatus     = "Updated"
                        $row.KEK_2023        = $pre.KEK_2023
                        $row.DB_2023         = $pre.DB_2023
                        $row.PK_Status       = $pre.PK_Status
                        if ($pre.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pre.PK_Subject }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pre.PK_Issuer }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pre.PK_Thumbprint }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pre.PK_Serial }
                        if ($pre.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pre.PK_NotAfter }
                        $row.Evt1808         = $pre.Evt1808
                        $row.SnapshotRetained = $snapCreated
                        $row.FullyRemediated    = $true
                        $row.CertUpdateVerified = $true
                        $row.PKMethod           = "AlreadyValid"
                        $matchNote = if ($ExpectedPKThumbprint) { " PK thumbprint matched expected value." } else { "" }
                        $row.Notes          += "Pre-check: fully remediated (certs verified + PK valid) - no changes made.$matchNote "
                        $report.Add($row)
                        continue
                    } elseif ($certsVerified -and -not $PKDerPath) {
                        $entryStep = "allDone"
                        Write-Host "  [Pre] Cert update complete. PK remediation not requested - skipping VM." -ForegroundColor Green
                        $row.FinalStatus     = "Updated"
                        $row.KEK_2023        = $pre.KEK_2023
                        $row.DB_2023         = $pre.DB_2023
                        $row.PK_Status       = $pre.PK_Status
                        if ($pre.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pre.PK_Subject }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pre.PK_Issuer }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pre.PK_Thumbprint }
                        if ($pre.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pre.PK_Serial }
                        if ($pre.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pre.PK_NotAfter }
                        $row.Evt1808         = $pre.Evt1808
                        $row.SnapshotRetained = $snapCreated
                        $row.FullyRemediated    = $false
                        $row.CertUpdateVerified = $true
                        $row.Notes          += "Pre-check: cert update verified (KEK/DB confirmed, no error key). PK remediation not requested (-PKDerPath not supplied). "
                        $report.Add($row)
                        continue
                    } elseif ($certsVerified) {
                        $entryStep = "certDone"
                        Write-Host "  [Pre] Cert update already complete - skipping to PK check (step 8)." -ForegroundColor Green
                        $row.KEK_2023           = $pre.KEK_2023
                        $row.DB_2023            = $pre.DB_2023
                        $row.FinalStatus        = "Updated"
                        $row.Evt1808            = $pre.Evt1808
                        $row.CertUpdateVerified = $true
                        $row.Notes             += "Pre-check: cert update already complete - skipped steps 2-7. "
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
            if (-not $GuestCredential) {
                Write-Host "  [Pre] Guest pre-check skipped (no -GuestCredential) - assuming full hypervisor sequence." -ForegroundColor Yellow
            } else {
                Write-Host "  [Pre] VM is powered off - running full sequence." -ForegroundColor Yellow
            }
        }
        # ------------------------------------------------------------------
        # Steps 2/2b/3/4 - Power off, optional HW upgrade, NVRAM rename, power on
        #
        # Explicit booleans drive control flow to avoid nested condition bugs.
        # $needsNvramWork  - NVRAM rename + power cycle is required
        # $needsHWUpgrade  - hardware upgrade was requested
        # $needsPowerOff   - must power off (either reason)
        # ------------------------------------------------------------------
        $needsNvramWork = (-not $SkipNVRAMRename) -and (-not $SupportedMethodsOnly) -and
                          ($entryStep -notin @("skipNvram","skipToStep6","certDone"))
        # Only power off for HW upgrade if the VM is actually below target (HW21+).
        # Avoids unnecessary downtime on VMs already at or above the minimum requirement.
        $needsHWUpgrade = $UpgradeHardware -and ($gateHWVerNum -lt 21)
        $needsPowerOff  = $needsNvramWork -or $needsHWUpgrade

        # Host HW21 capability check - runs here (before BitLocker check, snapshot,
        # and power-off) so no guest or power state changes occur if the host
        # cannot support the required upgrade. Skips only when HW upgrade is actually
        # needed. VMs already at HW21+ pass needsHWUpgrade=false and skip this.
        if ($needsHWUpgrade) {
            $hostMaxHW = Get-MaxHWVersionForHost -VMObj $vm
            if ($hostMaxHW -lt 21) {
                $hwReason = if ($hostMaxHW -eq 0) { "host version unknown or unsupported" } else { "host max HW is $hostMaxHW" }
                Write-Warning "  Skipping $currentVMName - hardware upgrade to HW21 not possible ($hwReason)."
                Write-Warning "  Ensure the ESXi host supports HW21 before running with -UpgradeHardware."
                $row.HWUpgraded  = "FAILED"
                $row.FinalStatus = "Skipped_HWUpgradeFailed"
                $row.Notes      += "Hardware upgrade skipped - $hwReason. Cannot reach required HW21. "
                $report.Add($row)
                continue
            }
        }

        # ------------------------------------------------------------------
        # Late NVRAM-specific safety gates (applied after pre-check)
        # These gates are deferred from the early gate block so that VMs
        # already remediated (entryStep = skipNvram/certDone) are not blocked
        # from completing guest cert/PK work on ESXi <8.0.2 or HW <21 hosts.
        # In no-credential/powered-off mode $needsNvramWork defaults to $true
        # since the pre-check cannot run, so these gates still fire conservatively.
        # ------------------------------------------------------------------
        if ($needsNvramWork -and -not $hostSupports2023Nvram) {
            Write-Warning "  Skipping $currentVMName - ESXi $gateHostVer does not regenerate NVRAM with 2023 certs."
            Write-Warning "  NVRAM regeneration requires ESXi 8.0.2 or later. Use -SkipNVRAMRename to"
            Write-Warning "  run only cert update and PK enrollment steps on VMs with pre-populated certs."
            $row.FinalStatus = "Skipped_SafetyGate"
            $row.Notes      += "SKIPPED - ESXi $gateHostVer. NVRAM regeneration requires ESXi 8.0.2+. Use -SkipNVRAMRename to skip rename on already-remediated VMs. "
            $row.SnapshotRetained = $snapCreated
            $report.Add($row)
            continue
        }

        if ($needsNvramWork -and $gateHWVerNum -lt 21 -and -not $needsHWUpgrade) {
            Write-Warning "  Skipping $currentVMName - Hardware version $gateHWVerNum < 21."
            Write-Warning "  Regenerated NVRAM on HW < 21 will not include the 2023 KEK certificate."
            Write-Warning "  Use -UpgradeHardware to upgrade to HW21 first, or -SkipNVRAMRename if the"
            Write-Warning "  2023 KEK is already present in NVRAM (e.g. VM was created on ESXi 8.0.2+)."
            $row.FinalStatus = "Skipped_SafetyGate"
            $row.Notes      += "SKIPPED - HW version $gateHWVerNum < 21. Use -UpgradeHardware or -SkipNVRAMRename. "
            $row.SnapshotRetained = $snapCreated
            $report.Add($row)
            continue
        }

        # ------------------------------------------------------------------
        # Step 0 - BitLocker safety check
        # Runs AFTER late NVRAM safety gates so VMs that will be skipped
        # (ESXi <8.0.2, HW <21) do not have BitLocker suspension triggered.
        # BitLocker suspension is itself a guest change that should only occur
        # if the VM has passed all gates for the actual remediation work.
        # For powered-off VMs or no-credential mode, step 0 is skipped.
        # ------------------------------------------------------------------
        # ------------------------------------------------------------------
        if ($vm.PowerState -eq "PoweredOn" -and $GuestCredential) {
            Write-Host "  [0/9] Checking BitLocker/TPM..." -ForegroundColor Cyan
            try {
                $tpmOut  = Invoke-VMScript -VM $vm -ScriptText $tpmCheckScript `
                    -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                $jsonLine = Get-LastJsonLine -Text $tpmOut.ScriptOutput
                if (-not $jsonLine) { throw "No JSON output from BitLocker check script" }
                $tpmData = $jsonLine | ConvertFrom-Json

                if ($tpmData.BitLockerActive) {
                    if ($tpmData.BitLockerSuspendedPending) {
                        Write-Warning "  NOTE: BitLocker arrived already SUSPENDED on $currentVMName (encrypted with a"
                        Write-Warning "  pending auto-resume). This can result from a pending update, a prior"
                        Write-Warning "  interrupted run, or a baseline snapshot captured mid-suspension. The"
                        Write-Warning "  suspension counter will be reset to cover this update sequence so the"
                        Write-Warning "  volume does not auto-resume mid-sequence and trigger recovery. Verify"
                        Write-Warning "  BitLocker protection status after this maintenance window."
                    }
                    if (-not $BitLockerBackupShare) {
                        Write-Warning "  BitLocker ACTIVE on $currentVMName - SKIPPING."
                        Write-Warning "  Provide -BitLockerBackupShare to back up keys and proceed automatically."
                        $row.BitLockerSkipped = $true
                        $row.FinalStatus      = "Skipped_BitLockerActive"
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
                        Write-Warning "  Recovery key backup failed. Skipping $currentVMName to avoid lockout."
                        Write-Warning "  Resolve the share access issue and re-run."
                        $row.BitLockerSkipped = $true
                        $row.FinalStatus      = "Skipped_BitLockerBackupFailed"
                        $row.Notes = "SKIPPED - BitLocker key backup to share failed."
                        $report.Add($row)
                        continue
                    }

                    # Suspend BitLocker (RebootCount 3 covers power-off/on, post-fix reboot, and 7b extra reboot)
                    $suspendOut  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                    $suspendJson = Get-LastJsonLine -Text $suspendOut.ScriptOutput
                    if ($suspendJson) {
                        $suspendData = $suspendJson | ConvertFrom-Json
                        # Require ALL active volumes suspended and NONE failed.
                        # Partial suspension (some volumes succeed, others fail) means
                        # some protected volumes may trigger recovery on PCR7 change.
                        $row.BitLockerSuspended = (
                            (@($suspendData.Suspended).Count -gt 0) -and
                            (@($suspendData.Failed).Count -eq 0)
                        )
                        Write-Host "    $($suspendData.Notes)" -ForegroundColor $(if ($row.BitLockerSuspended) {"Green"} else {"Yellow"})
                        # Persisted Notes record outcomes, not every successful suspend.
                        # Only flag the noteworthy baseline condition (the VM arrived with
                        # BitLocker already suspended). The columns BitLockerKeysBacked /
                        # BitLockerSuspended and the end-of-run resume note carry the rest.
                        if (@($suspendData.ReSuspended).Count -gt 0) {
                            $row.Notes += "BL: arrived suspended at baseline. Counter reset. "
                        }
                        if (-not $row.BitLockerSuspended) {
                            Write-Warning "  BitLocker suspension failed - skipping VM to avoid triggering recovery mode."
                            Write-Warning "  Recovery keys were backed up. Resolve BitLocker state and re-run."
                            $row.BitLockerSkipped = $true
                            $row.FinalStatus      = "Skipped_BitLockerSuspendFailed"
                            $row.Notes           += "SKIPPED - BitLocker keys backed up but suspension failed. Resolve BitLocker state and re-run. "
                            $report.Add($row)
                            continue
                        }
                    } else {
                        # No parseable JSON returned from suspension script.
                        # Cannot confirm suspension state - fail closed to avoid
                        # proceeding with PCR7-affecting changes on an unknown state.
                        Write-Warning "  BitLocker suspension returned no status data - skipping VM."
                        Write-Warning "  Recovery keys were backed up. Resolve guest/Tools output and re-run."
                        $row.BitLockerSkipped = $true
                        $row.FinalStatus      = "Skipped_BitLockerSuspendFailed"
                        $row.Notes           += "SKIPPED - BitLocker suspension status unknown. No JSON returned from suspension script. "
                        $report.Add($row)
                        continue
                    }
                }
                if ($tpmData.TPMPresent -and -not $tpmData.BitLockerActive) {
                    Write-Host "  WARNING: vTPM is present on this VM." -ForegroundColor Yellow
                    Write-Host "           Secure Boot variable changes, such as NVRAM regeneration, SetupMode" -ForegroundColor Yellow
                    Write-Host "           enrollment, or resetOnce, can alter TPM PCR7 measurements. On vTPM-enabled" -ForegroundColor Yellow
                    Write-Host "           VMs, Windows DPAPI machine keys may be" -ForegroundColor Yellow
                    Write-Host "           sealed to PCR7. If so, stored credentials (scheduled task passwords," -ForegroundColor Yellow
                    Write-Host "           Credential Manager entries) may stop working after this run." -ForegroundColor Yellow
                    Write-Host "           gMSA-based tasks and tasks with no stored password are unaffected." -ForegroundColor Yellow
                    Write-Host "           Note: if the 2023 KEK is already present in NVRAM, the pre-check will" -ForegroundColor Yellow
                    Write-Host "           skip the NVRAM regeneration. That removes the NVRAM-regeneration" -ForegroundColor Yellow
                    Write-Host "           risk, but PK remediation paths such as SetupMode or resetOnce can" -ForegroundColor Yellow
                    Write-Host "           still alter PCR7 if you explicitly run them." -ForegroundColor Yellow
                    if ($tpmData.CGRunning) {
                        Write-Host "  WARNING: Credential Guard is active on this VM." -ForegroundColor Yellow
                        Write-Host "           Credential Guard seals its keys using the TPM. A PCR7 change may" -ForegroundColor Yellow
                        Write-Host "           cause domain credential caching and pass-the-hash protection to" -ForegroundColor Yellow
                        Write-Host "           reinitialize. Domain logins should continue to work but cached" -ForegroundColor Yellow
                        Write-Host "           credentials may be flushed and VBS-protected secrets resealed." -ForegroundColor Yellow
                    }
                    if ($tpmData.VBSRunning) {
                        $row.Notes += "VBS active - PCR7 change may affect VBS-sealed secrets. "
                    }
                    $row.Notes += "vTPM present - DPAPI/stored credential risk if PCR7 changes. "
                }
            } catch {
                Write-Warning "  BitLocker/TPM safety check failed: $($_.Exception.Message)"
                Write-Warning "  Skipping $currentVMName - cannot confirm BitLocker status."
                Write-Warning "  Guest operations failed (often a VIX guest-authentication error)."
                Write-Warning "  Possible causes: incorrect or insufficient guest credentials, VMware Tools"
                Write-Warning "  not ready, or a broken Active Directory secure channel (common after a"
                Write-Warning "  snapshot revert on a domain-joined VM. Repair from inside the guest with"
                Write-Warning "  Test-ComputerSecureChannel -Repair)."
                Write-Warning "  Modifying NVRAM or Secure Boot state without confirming BitLocker is suspended"
                Write-Warning "  risks triggering recovery mode. Resolve guest connectivity and re-run."
                $row.BitLockerSkipped = $true
                $row.FinalStatus      = "Skipped_BitLockerCheckFailed"
                $row.Notes            = "SKIPPED - BitLocker/TPM safety check failed. Guest state unknown. Possible causes: guest credentials, VMware Tools readiness, or a broken AD secure channel after snapshot revert (Test-ComputerSecureChannel -Repair). Resolve guest connectivity and re-run. "
                $report.Add($row)
                continue
            }
        }

        # No-credential mode: BitLocker and vTPM state cannot be checked.
        # Warn once per VM before any mutating work.
        if (-not $GuestCredential) {
            Write-Host ""
            Write-Warning "  Hypervisor-only mode: BitLocker/TPM state not checked. Ensure"
            Write-Warning "  recovery keys are backed up before proceeding with this VM."
            Write-Host ""
        }
        # Snapshot is taken after pre-check, needsNvramWork computation, and late
        # safety gates for both credential modes, so no-action VMs are not snapshotted.
        # ------------------------------------------------------------------
        # Step 1 - Take snapshot
        # Unified for both credential modes. Already-complete VMs and
        # safety-gate-skipped VMs exited above. All VMs here need work.
        # In no-credential mode: skip if there is nothing to do.
        # ------------------------------------------------------------------
        if (-not $GuestCredential -and -not $needsNvramWork -and -not $needsHWUpgrade) {
            Write-Host "  No hypervisor work needed and no guest credential supplied - skipping." -ForegroundColor Yellow
            $row.FinalStatus = "Skipped_NoAction"
            $row.Notes      += "SKIPPED - no NVRAM rename or HW upgrade needed, and no guest credential for cert/PK work. "
            $report.Add($row)
            continue
        }

        # Check for powered-off VM that needs guest steps but no power cycle will occur.
        # Applies when -SkipNVRAMRename and -UpgradeHardware are both supplied but the VM
        # is already at HW21+ (so needsHWUpgrade is false) and no power cycle will run.
        if ($GuestCredential -and $vm.PowerState -ne "PoweredOn" -and -not $needsPowerOff) {
            Write-Warning "  Skipping $currentVMName - VM is powered off and no power cycle will occur."
            Write-Warning "  Guest cert/PK steps require the VM to be powered on. Power it on and re-run."
            $row.FinalStatus = "Skipped_VMOff"
            $row.Notes      += "SKIPPED - powered off with no power cycle scheduled. Guest steps require VM to be running. "
            $report.Add($row)
            continue
        }

        if ($NoSnapshot) {
            Write-Host "  [1/9] Skipping snapshot (-NoSnapshot specified)." -ForegroundColor Yellow
            $row.Notes += "No snapshot taken (-NoSnapshot). "
        } else {
            Write-Host "  [1/9] Taking snapshot..." -ForegroundColor Cyan
            $snapRes             = New-VMSnapshotSafe -VMObj $vm -Name $snapshotName `
                -Description "Pre Secure Boot 2023 cert fix - automated snapshot"
            $row.SnapshotCreated = $snapRes.Success
            $snapCreated         = $snapRes.Success
            if (-not $snapRes.Success) {
                # Snapshot is the only rollback path for NVRAM manipulation, which
                # is a Broadcom-unsupported operation with a documented (if uncommon)
                # corruption risk. Without a snapshot there is no recovery path, so
                # skip the VM entirely rather than proceeding. The failure reason is
                # captured for the terminal output and the CSV.
                Write-Warning "  Snapshot failed - skipping VM. No rollback path is available for NVRAM changes."
                Write-Warning "  Reason: $($snapRes.Error)"
                $row.FinalStatus = "Skipped_SnapshotFailed"
                $row.Notes      += "SKIPPED - snapshot failed, no rollback available. Reason: $($snapRes.Error) "
                $report.Add($row)
                continue
            }
        }


        if ($needsPowerOff) {
            Write-Host "  [2/9] Powering off..." -ForegroundColor Cyan
            if ($vm.PowerState -eq "PoweredOn") {
                Stop-VMGraceful -VM $vm -TimeoutSeconds $GracefulShutdownTimeout
                $vm = Get-VM -Id $currentVMId -ErrorAction SilentlyContinue
            }
        }

        # ------------------------------------------------------------------
        # Step 2b - Upgrade hardware version (only if -UpgradeHardware)
        # Runs regardless of -SkipNVRAMRename so the two switches combine cleanly.
        # ------------------------------------------------------------------
        if ($needsHWUpgrade) {
            $vmViewHW  = $vm | Get-View
            $hwVerNum  = [int](($vmViewHW.Config.Version) -replace 'vmx-', '')
            # Host capability was already verified before snapshot/BitLocker.
            # $hostMaxHW is in scope from the pre-snapshot gate above.
            Write-Host "  [2b/9] Upgrading hardware version (current: $hwVerNum -> 21)..." -ForegroundColor Cyan
            $upResult = Invoke-VMHardwareUpgrade -VMObj $vm -TargetVersion 21
            if ($upResult.Upgraded) {
                $row.HWUpgraded = "$hwVerNum -> $($upResult.ToVersion)"
                $vm             = Get-VM -Id $currentVMId
                # Refresh gateHWVerNum so step 8 PK gate uses the post-upgrade version
                $gateHWVerNum   = [int]((($vm | Get-View).Config.Version) -replace 'vmx-', '')
            } else {
                $row.HWUpgraded = "FAILED"
                # If the upgrade failed and HW is still <21 NVRAM rename must be
                # skipped - regenerated NVRAM on HW <21 does not include 2023 KEK.
                if ($hwVerNum -lt 21 -and $needsNvramWork) {
                    Write-Warning "  Hardware upgrade failed - HW version still $hwVerNum < 21."
                    Write-Warning "  NVRAM rename skipped to avoid regenerating NVRAM without 2023 KEK."
                    Write-Warning "  Powering VM back on. Resolve upgrade failure and re-run."
                    $row.FinalStatus      = "Skipped_HWUpgradeFailed"
                    $row.Notes           += "Hardware upgrade failed. NVRAM rename skipped - HW $hwVerNum < 21 would regenerate without 2023 KEK. $($upResult.Notes) "
                    $row.SnapshotRetained = $snapCreated
                    if ($vm.PowerState -eq "PoweredOff") { Start-VM -VM $vm | Out-Null }
                    $report.Add($row)
                    continue
                } else {
                    $row.Notes += "Hardware upgrade failed: $($upResult.Notes) "
                    Write-Warning "  Hardware upgrade failed - continuing (HW version already >= 21 or NVRAM rename not needed)."
                }
            }
        } elseif ($UpgradeHardware -and $gateHWVerNum -ge 21) {
            Write-Host "  [2b/9] Hardware version $gateHWVerNum >= 21 - no upgrade needed." -ForegroundColor Green
            $row.HWUpgraded = "Already OK ($gateHWVerNum)"
        }

        # ------------------------------------------------------------------
        # Step 3 - Rename NVRAM (triggers fresh generation with 2023 certs)
        # ------------------------------------------------------------------
        if ($needsNvramWork) {
            Write-Host "  [3/9] Renaming NVRAM file on datastore..." -ForegroundColor Cyan
            $row.NVRAMRenamed = Rename-VMNvram -VMObj $vm
            if ($row.NVRAMRenamed -eq $true) { $row.CertMethod = "NVRAMRegen" }

            if (-not $row.NVRAMRenamed) {
                # Rename failed or was blocked (.nvram_old collision). Do not
                # proceed with guest cert update against unchanged NVRAM state.
                Write-Warning "  NVRAM rename failed or was blocked - powering VM back on and skipping guest steps."
                Write-Warning "  If .nvram_old already exists use -Rollback to restore or remove the file manually."
                $row.FinalStatus      = "Skipped_NVRAMRenameFailed"
                $row.Notes           += "NVRAM rename failed or blocked. Guest cert update skipped. "
                $row.SnapshotRetained = $snapCreated
                if ($vm.PowerState -eq "PoweredOff") { Start-VM -VM $vm | Out-Null }
                $report.Add($row)
                continue
            }

            # ------------------------------------------------------------------
            # Step 4 - Power on (ESXi regenerates NVRAM with 2023 KEK)
            # ------------------------------------------------------------------
            Write-Host "  [4/9] Powering on (ESXi regenerates NVRAM with 2023 certs)..." -ForegroundColor Cyan
            Start-VM -VM $vm | Out-Null
            $vm = Get-VM -Id $currentVMId
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $row.Notes          += "Tools timeout after NVRAM boot. "
                $row.SnapshotRetained = $snapCreated
                $report.Add($row)
                continue
            }

            Write-Host "    Verifying 2023 certs in new NVRAM..." -ForegroundColor Gray
            if ($GuestCredential) {
                try {
                    $certOut  = Invoke-VMScript -VM $vm -ScriptText $certVerifyScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                    if (-not $certOut.ScriptOutput) { throw "Cert verify script returned no output" }
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
            } else {
                $row.KEK_AfterNVRAM = "Not checked (no GuestCredential)"
                $row.DB_AfterNVRAM  = "Not checked (no GuestCredential)"
                Write-Host "    NVRAM cert verify skipped (hypervisor-only mode)." -ForegroundColor Gray
            }

        } elseif ($needsHWUpgrade -and $vm.PowerState -eq "PoweredOff") {
            # HW upgrade ran but NVRAM rename was skipped (-SkipNVRAMRename or
            # entryStep). Power the VM back on before guest-side cert work.
            Write-Host "  [4/9] Powering on after hardware upgrade (NVRAM rename skipped)..." -ForegroundColor Cyan
            Start-VM -VM $vm | Out-Null
            $vm = Get-VM -Id $currentVMId
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $row.Notes          += "Tools timeout after HW upgrade power-on. "
                $row.SnapshotRetained = $snapCreated
                $report.Add($row)
                continue
            }
            Wait-GuestIdKnown -VMObj $vm -TimeoutSeconds 180 | Out-Null
            $vm = Get-VM -Id $currentVMId
            $row.NVRAMRenamed = "Skipped"
        } else {
            # Neither NVRAM work nor HW upgrade ran - NVRAM is unchanged
            if ($SkipNVRAMRename -or $SupportedMethodsOnly) {
                $skipReason = if ($SupportedMethodsOnly) { "-SupportedMethodsOnly" } else { "-SkipNVRAMRename" }
                Write-Host "  [3/9] NVRAM rename skipped ($skipReason)." -ForegroundColor Yellow
                $row.NVRAMRenamed = "Skipped"
                if ($SupportedMethodsOnly) {
                    $row.Notes += "NVRAM regeneration refused by -SupportedMethodsOnly. Relying on supported and OS-native paths. "
                }
            }
        }

        # ------------------------------------------------------------------
        # Step 5 - Clear stale registry state, set AvailableUpdates, trigger task
        # (skipped if cert update already complete or only reboot needed)
        # (skipped if no GuestCredential - hypervisor-only run)
        # ------------------------------------------------------------------
        if (-not $GuestCredential) {
            # Hypervisor-only run complete. Set a clear status and continue to
            # next VM before falling into guest-dependent steps 5-9, snapshot
            # disposition, and allGood evaluation which all require guest data.
            Write-Host "  [5-9/9] Hypervisor-only phase complete." -ForegroundColor Yellow
            Write-Host "          Guest cert update, verification, and PK enrollment are pending." -ForegroundColor Yellow
            if ($knownLinuxGuest) {
                Write-Host "          Non-Windows guest: complete OS-specific Secure Boot/PK remediation" -ForegroundColor Yellow
                Write-Host "          using Broadcom or OS-vendor guidance (KB 423893)." -ForegroundColor Yellow
            } else {
                Write-Host "          Re-run with -GuestCredential from a machine with guest OS access." -ForegroundColor Yellow
            }
            $row.FinalStatus      = "HypervisorOnly_GuestStepsPending"
            $row.SnapshotRetained = $snapCreated
            if ($knownLinuxGuest) {
                $row.Notes += "Hypervisor-only phase complete for non-Windows VM. Complete OS-specific Secure Boot/PK remediation using Broadcom or OS-vendor guidance per KB 423893. "
            } else {
                $row.Notes += "Hypervisor-only phase complete (snapshot/HW/NVRAM/power-cycle). Guest cert update, verification, and PK enrollment were skipped - no guest credential provided. Re-run with -GuestCredential. "
            }
            $report.Add($row)
            continue
        } elseif ($entryStep -notin @("skipToStep6","certDone")) {
        Write-Host "  [5/9] Clearing stale state and triggering update..." -ForegroundColor Cyan
        $updateOut = Invoke-VMScript -VM $vm -ScriptText $updateScript `
            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
        Write-Host $updateOut.ScriptOutput -ForegroundColor Gray
        $row.UpdateTriggered = $true

        # If the Servicing key had a prior error before we cleared it, preserve that
        # diagnostic in Notes so it survives into the CSV (the live key is now gone).
        if ($updateOut.ScriptOutput -match 'ServicingPreClear_UEFICA2023Error=(.+)') {
            $preClearErr = $Matches[1].Trim()
            if ($preClearErr -and $preClearErr -ne 'False') {
                $row.Notes += "Pre-clear Servicing had UEFICA2023Error=$preClearErr (cleared for retry). "
            }
        }

        } # end skip-cert-update gate (step 5)

        # ------------------------------------------------------------------
        # Step 6 - Reboot, trigger task again (skipped if cert update complete)
        # ------------------------------------------------------------------
        if ($entryStep -ne "certDone") {
        Write-Host "  [6/9] Rebooting..." -ForegroundColor Cyan
        Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
        Start-Sleep -Seconds $WaitSeconds
        $vm = Get-VM -Id $currentVMId
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

        $verifyOut  = Invoke-VMScriptViaFile -VM $vm -ScriptContent (Get-TimestampedVerifyScript -StartTime $vmRunStart) `
            -GuestCredential $GuestCredential

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
            Write-Warning "  Raw output: $(if ($verifyOut.ScriptOutput) { $verifyOut.ScriptOutput.Trim() } else { '<empty>' })"
            Write-Warning "  ExitCode: $($verifyOut.ExitCode) | ScriptError: $($verifyOut.ScriptError)"
            $row.SnapshotRetained = $snapCreated
            $row.Notes += "Verify script returned no output - check VM manually. "
            $report.Add($row)
            continue
        }

        $row.KEK_2023    = $verifyData.KEK_2023
        $row.DB_2023     = $verifyData.DB_2023
        # \Servicing may be absent on fully-complete VMs. Fall back to AvailableUpdates = 0x4000
        $row.FinalStatus = if ($verifyData.Servicing_Status) {
            $verifyData.Servicing_Status
        } elseif ($verifyData.AvailableUpdates -eq "0x4000") {
            "Updated"
        } else {
            "Unknown"
        }

        if ($verifyData.UEFICA2023ErrorExists -eq "True") {
            $row.UEFICA2023Error = "ERROR ($($verifyData.UEFICA2023ErrorValue))"
            $row.Notes += "UEFICA2023Error key present (value: $($verifyData.UEFICA2023ErrorValue)) - deployment error not visible in Event Log. Trace via Secure Boot DB/DBX events. "
        }

        # Populate event log results
        $row.Evt1036 = $verifyData.Evt1036
        $row.Evt1043 = $verifyData.Evt1043
        $row.Evt1044 = $verifyData.Evt1044
        $row.Evt1045 = $verifyData.Evt1045
        $row.Evt1795 = $verifyData.Evt1795
        $row.Evt1797 = $verifyData.Evt1797
        $row.Evt1799 = $verifyData.Evt1799
        $row.Evt1800 = $verifyData.Evt1800
        $row.Evt1801 = $verifyData.Evt1801
        $row.Evt1802 = $verifyData.Evt1802
        $row.Evt1803 = $verifyData.Evt1803
        $row.Evt1808 = $verifyData.Evt1808

        # Flag persistent error events in Notes. 1801 and 1800 are handled by
        # step 7b which reboots and re-checks before adding a Note.
        # 1808 absence is not flagged - may not fire until after an extra reboot.
        if ($verifyData.Evt1797 -eq "True") {
            $row.Notes += "Event 1797: boot manager update failed - check firmware. "
        }
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
            # If this VM had BitLocker suspended in step 0, the extra reboot here can
            # be the one that exhausts the suspension count. Re-suspend before the
            # reboot so a PCR7 change from the in-progress update does not drop the
            # VM into BitLocker recovery (which would halt at the recovery prompt and
            # cause a Tools timeout). Keys were already backed up in step 0.
            if ($row.BitLockerSuspended) {
                try {
                    $reSuspendOut  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                    $reSuspendJson = Get-LastJsonLine -Text $reSuspendOut.ScriptOutput
                    if ($reSuspendJson) {
                        $reSuspendData = $reSuspendJson | ConvertFrom-Json
                        if (@($reSuspendData.Suspended).Count -gt 0) {
                            Write-Host "    BitLocker re-suspended before extra reboot: $($reSuspendData.Suspended -join ', ')." -ForegroundColor Green
                        }
                    } else {
                        Write-Warning "    Could not confirm BitLocker re-suspension before extra reboot - the VM may prompt for a recovery key."
                        $row.Notes += "BL re-suspend before 7b reboot: status unconfirmed. "
                    }
                } catch {
                    Write-Warning "    BitLocker re-suspension before extra reboot failed: $($_.Exception.Message)"
                    Write-Warning "    The VM may prompt for a recovery key on the next reboot."
                    $row.Notes += "BL re-suspend before 7b reboot failed: $($_.Exception.Message) "
                }
            }
            Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
            Start-Sleep -Seconds $WaitSeconds
            $vm = Get-VM -Id $currentVMId
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $row.Notes += "Tools timeout after 7b extra reboot. "
                if ($row.BitLockerSuspended) {
                    $row.Notes += "The VM may be stranded at the BitLocker pre-boot prompt. Open the console and enter the password, or press ESC for recovery and use the key backed up to '$BitLockerBackupShare'. "
                }
                $row.SnapshotRetained = $snapCreated
                $report.Add($row)
                continue
            }

            $taskOut2 = Invoke-VMScript -VM $vm -ScriptText $taskTriggerScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            Write-Host $taskOut2.ScriptOutput -ForegroundColor Gray

            Write-Host "  [7b/9] Re-verifying after extra reboot..." -ForegroundColor Cyan
            $verifyOut2  = Invoke-VMScriptViaFile -VM $vm -ScriptContent (Get-TimestampedVerifyScript -StartTime $vmRunStart) `
                -GuestCredential $GuestCredential
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
                $row.Evt1036 = $verifyData.Evt1036
                $row.Evt1043 = $verifyData.Evt1043
                $row.Evt1044 = $verifyData.Evt1044
                $row.Evt1045 = $verifyData.Evt1045
                $row.Evt1795 = $verifyData.Evt1795
                $row.Evt1797 = $verifyData.Evt1797
                $row.Evt1799 = $verifyData.Evt1799
                $row.Evt1800 = $verifyData.Evt1800
                $row.Evt1801 = $verifyData.Evt1801
                $row.Evt1802 = $verifyData.Evt1802
                $row.Evt1803 = $verifyData.Evt1803
                $row.Evt1808 = $verifyData.Evt1808
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

        # Record OS-servicing as the cert delivery method when the 2023 KEK and DB
        # were confirmed without an NVRAM regeneration. Under -SkipNVRAMRename or
        # -SupportedMethodsOnly the regeneration is suppressed, so a verified cert
        # state with an update triggered means in-guest OS servicing delivered them.
        if ($certGood -and $row.CertMethod -eq "NotAttempted" -and $row.UpdateTriggered) {
            $row.CertMethod = "OSServicing"
        }

        # Graded Event 1801 handling (evaluated after step 7b has had its chance to
        # complete the firmware write). 1801 means "updated certs are available but
        # not yet applied to firmware" - it is a normal intermediate state during a
        # multi-reboot sequence, so its mere presence is NOT failure. It is only a
        # concern when it persists alongside an authoritative incomplete state:
        # 1808 absent AND status not Updated (or AvailableUpdates not cleared).
        # The registry/cert state is the source of truth. The event corroborates.
        $avail1801 = $verifyData.AvailableUpdates
        if ($row.Evt1801 -eq "True" -and $row.Evt1808 -ne "True" -and -not $certGood -and
            ($row.FinalStatus -ne "Updated" -or ($avail1801 -and $avail1801 -ne "0x4000"))) {
            # PK may have enrolled fine. The gap is the OS-side cert apply.
            $row.FinalStatus = "NeedsAttention_1801"
            $row.Notes += "PK update succeeded but Secure Boot certificates not yet applied on the OS side (Event 1801 present, Event 1808 absent). VM needs another reboot/Windows Update cycle. Re-run to re-verify. "
            Write-Warning "  [7/9] Needs attention: certs staged but not yet applied to firmware (Event 1801, awaiting 1808)."
        }

        # Under -SupportedMethodsOnly the NVRAM regeneration fallback is refused. When
        # the guest reports no determinable servicing progress (FinalStatus "Unknown":
        # no Servicing_Status, AvailableUpdates not 0x4000, and certs still absent), the
        # supported paths are exhausted and the VM needs an OS-native, Broadcom, or
        # vendor-specific update. Report it explicitly. Transient states are left alone:
        # NeedsAttention_1801 (certs staged, awaiting a reboot) and an in-guest servicing
        # status still in progress both resolve on their own schedule and fall under the
        # normal pending outcome rather than a servicing failure.
        if ($SupportedMethodsOnly -and -not $certGood -and $row.FinalStatus -eq "Unknown") {
            $row.Notes += "SupportedMethodsOnly: NVRAM regeneration was refused and in-guest OS servicing did not deliver a confirmed 2023 KEK and DB. Complete OS-native, Broadcom, or vendor-specific remediation. "
            $row.FinalStatus = "NeedsOSNativeUpdate"
        }

        $color = if ($certGood) { "Green" } else { "Yellow" }
        Write-Host (("  Status: {0} | KEK 2023: {1} | DB 2023: {2} | AvailableUpdates: {3} | Evt 1808: {4}{5}") -f
            $row.FinalStatus, $row.KEK_2023, $row.DB_2023,
            $verifyData.AvailableUpdates, $row.Evt1808,
            $(if ($row.UEFICA2023Error) { " | RegError: $($row.UEFICA2023Error)" } else { "" })) -ForegroundColor $color
        if ($verifyData.Evt1797 -eq "True") { Write-Host "    Event 1797: boot manager update failed - check firmware." -ForegroundColor Red }
        if ($verifyData.Evt1802 -eq "True") { Write-Host "    Event 1802: update blocked by known firmware issue - contact OEM." -ForegroundColor Red }
        if ($verifyData.Evt1803 -eq "True") { Write-Host "    Event 1803: no PK-signed KEK found - PK remediation required." -ForegroundColor Yellow }
        if ($verifyData.Evt1795 -eq "True") { Write-Host "    Event 1795: firmware error on variable write - contact OEM." -ForegroundColor Red }

        # ------------------------------------------------------------------
        # Step 8 - Platform Key (PK) check
        # VMs on ESXi < 9.0 have a NULL PK by default. A valid PK is required
        # for Windows to authenticate future KEK/DB updates. Without it the
        # same certificate expiry situation will recur. This step always runs.
        # Remediation (step 9) is skipped only when PK is already valid.
        # ------------------------------------------------------------------
        # Per Broadcom KB 423893, PK enrollment requires hardware version 14+.
        # HW version 13 must be upgraded to 14+ before PK update is possible.
        # The safety gate earlier blocked HW < 21 for NVRAM rename, but a VM
        # could arrive here at HW 14-20 via -SkipNVRAMRename. Gate PK work too.
        if ($gateHWVerNum -lt 14) {
            Write-Warning "  [8/9] Skipping PK check - hardware version $gateHWVerNum < 14."
            Write-Warning "        PK enrollment requires HW version 14+ per Broadcom KB 423893."
            $row.Notes += "PK check and enrollment skipped - HW version $gateHWVerNum < 14 (upgrade required). "
        } else {

        Write-Host "  [8/9] Checking Platform Key (PK) validity..." -ForegroundColor Cyan
        # $pkGood, $pkBitLockerActive, and $pkCheckOk initialized at loop start.
        try {
            $pkOut  = Invoke-VMScript -VM $vm -ScriptText $pkCheckScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $pkJson = Get-LastJsonLine -Text $pkOut.ScriptOutput
            if (-not $pkJson) {
                throw "PK check returned no parseable JSON. ExitCode: $($pkOut.ExitCode)"
            }
            $pkData = $pkJson | ConvertFrom-Json
            $row.PK_Status     = $pkData.PK_Status
            if ($pkData.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pkData.PK_Subject }
            if ($pkData.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pkData.PK_Issuer }
            if ($pkData.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pkData.PK_Thumbprint }
            if ($pkData.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pkData.PK_Serial }
            if ($pkData.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pkData.PK_NotAfter }
            # Only WindowsOEM and Microsoft PKs are trusted by Windows Update
            # for authenticating future KEK changes. Valid_Other is ESXi's
            # placeholder - per Broadcom KB 423919 ESXi < 9.0 has no valid PK.
            $pkGood            = $pkData.PK_Status -in @("Valid_WindowsOEM", "Valid_Microsoft")
            $pkBitLockerActive = $pkData.BitLockerActive -eq "True"
            $pkCheckOk         = $true
            # Evaluate -ExpectedPKThumbprint against an already-valid PK. A
            # mismatch here is NOT a failure (the VM has a working PK). It means
            # the existing PK is not the specific certificate the operator named.
            # With -ReplaceExistingPK the VM becomes eligible for SetupMode
            # re-enrollment. Without it, the existing PK is reported for review.
            $pkThumbMatchesExpected = Test-ExpectedPKThumbprint -Expected $ExpectedPKThumbprint -Actual $pkData.PK_Thumbprint
            $pkExistingMismatch     = ($pkGood -and -not $pkThumbMatchesExpected)
            $pkColor = if ($pkGood) { "Green" } elseif ($pkData.PK_Status -eq "Valid_Other") { "Yellow" } else { "Red" }
            Write-Host ("    PK Status    : {0}" -f $pkData.PK_Status) -ForegroundColor $pkColor
            if ($pkData.PK_Subject) { Write-Host ("    PK Subject   : {0}" -f $pkData.PK_Subject) -ForegroundColor Gray }
            if ($pkData.PK_Thumbprint) { Write-Host ("    PK Thumbprint: {0}" -f $pkData.PK_Thumbprint) -ForegroundColor Gray }
            if ($pkData.PK_Status -eq "Valid_Other") {
                Write-Host "    NOTE: Valid_Other = ESXi placeholder PK (not trusted by Windows Update for KEK auth)." -ForegroundColor Yellow
                Write-Host "    Enrollment of proper PK required per Broadcom KB 423919." -ForegroundColor Yellow
            }
            Write-Host ("    BitLocker    : {0}" -f $(if ($pkBitLockerActive) {"Active"} else {"Inactive"})) `
                -ForegroundColor $(if ($pkBitLockerActive) {"Yellow"} else {"Gray"})
        } catch {
            Write-Warning "    PK check failed: $($_.Exception.Message)"
            Write-Warning "    PK remediation skipped to avoid changing Secure Boot state without current PK/BitLocker data."
            $row.Notes += "PK check failed. PK remediation skipped. "
        }

        if (-not $pkCheckOk) {
            # PK check failed or returned no data. Skip remediation entirely.
            # $pkGood stays $false (loop-start init) but we must not proceed
            # into PK remediation without confirmed state.
        } elseif ($pkGood -and -not $pkExistingMismatch) {
            # PK is valid and either no expected thumbprint was supplied or it
            # matches. Accept as remediated.
            $row.PKRemediated = $true
            # Distinguish a PK delivered during this run's OS cert servicing from one
            # that was already valid before the run. On a P09 host the silent path
            # enrolls the PK alongside the certificates, so a vTPM-disabled VM whose
            # certs came via OS servicing this run (CertMethod OSServicing) and whose
            # PK was not valid at the pre-check has just been silently enrolled. A PK
            # that was already valid before the run stays AlreadyValid.
            if (-not $hasVirtualTPM -and $row.CertMethod -eq "OSServicing" -and -not $pkGoodAlready) {
                $row.PKMethod = "Silent"
                Write-Host ("    PK is valid ({0}) - delivered via the P09 silent path during OS cert servicing." -f $row.PK_Status) -ForegroundColor Green
                $row.Notes += "PK delivered via the P09 silent path during OS cert servicing this run. "
            } else {
                $row.PKMethod = "AlreadyValid"
                Write-Host ("    PK is valid ({0}) - no remediation needed." -f $row.PK_Status) -ForegroundColor Green
            }
            if ($ExpectedPKThumbprint) {
                Write-Host "    PK thumbprint matches -ExpectedPKThumbprint." -ForegroundColor Green
                $row.Notes += "PK valid and thumbprint matched expected value. "
            }

        } elseif ($pkExistingMismatch -and -not ($ReplaceExistingPK -and $PKDerPath)) {
            # PK is valid but does not match -ExpectedPKThumbprint, and the
            # operator has not asked to replace it. This is NOT a failure: the VM
            # has a working PK. Surface the existing PK identity for review and
            # do not mark the VM FullyRemediated. The operator can re-run with
            # -ReplaceExistingPK (plus -PKDerPath) to replace it.
            Write-Host "    PK is valid but does NOT match -ExpectedPKThumbprint." -ForegroundColor Yellow
            Write-Host "    The VM has a working Platform Key. It is simply not the certificate you specified." -ForegroundColor Yellow
            Write-Host ("      Existing PK Subject   : {0}" -f $row.PK_Subject) -ForegroundColor Gray
            Write-Host ("      Existing PK Issuer    : {0}" -f $row.PK_Issuer) -ForegroundColor Gray
            Write-Host ("      Existing PK Thumbprint: {0}" -f $row.PK_Thumbprint) -ForegroundColor Gray
            Write-Host ("      Existing PK Serial    : {0}" -f $row.PK_Serial) -ForegroundColor Gray
            Write-Host ("      Existing PK NotAfter  : {0}" -f $row.PK_NotAfter) -ForegroundColor Gray
            Write-Host "    To replace this PK with the expected certificate, re-run with -ReplaceExistingPK -PKDerPath <file>." -ForegroundColor Yellow
            $expectTpNorm = ($ExpectedPKThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            $row.Notes += "Existing valid PK does not match -ExpectedPKThumbprint (expected $expectTpNorm, found $($row.PK_Thumbprint), Subject $($row.PK_Subject), NotAfter $($row.PK_NotAfter)). Re-run with -ReplaceExistingPK to replace it. "
            # PKRemediated stays $false. FullyRemediated will not be set.

        } elseif (-not $PKDerPath) {
            Write-Warning "    PK is invalid/NULL/placeholder. Provide -PKDerPath to remediate automatically."
            Write-Warning "    Download WindowsOEMDevicesPK.der from:"
            Write-Warning "    https://github.com/microsoft/secureboot_objects/blob/main/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
            $row.Notes += "PK invalid/placeholder - re-run with -PKDerPath to remediate. "

        } else {
            # ------------------------------------------------------------------
            # Step 9 - PK remediation
            #
            # Reached when the PK needs enrollment: it is NULL/placeholder, OR it
            # is a valid-but-non-matching PK and -ReplaceExistingPK was supplied.
            # In the replacement case the existing valid PK is overwritten with
            # the expected certificate via the same SetupMode machinery.
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
            if ($pkExistingMismatch -and $ReplaceExistingPK) {
                Write-Host "    -ReplaceExistingPK: existing valid PK will be replaced with the expected certificate." -ForegroundColor Yellow
                Write-Host ("      Replacing PK Thumbprint: {0}" -f $row.PK_Thumbprint) -ForegroundColor Gray
                $row.Notes += "Replacing existing valid PK (was $($row.PK_Thumbprint)) with expected certificate via -ReplaceExistingPK. "
            }


            # Check ESXi host version - SetupMode requires ESXi >= 8.0
            $vmHost    = Get-VMHost -VM $vm -ErrorAction SilentlyContinue
            $hostVerStr = $vmHost.Version
            $hostMajor  = [int]($hostVerStr -split '\.')[0]
            $isP09      = Get-IsP09Host -VMObj $vm

            if ($hostMajor -lt 8) {
                Write-Warning "  [9/9] PK remediation skipped - ESXi host is version $hostVerStr (SetupMode requires 8.0+)."
                Write-Warning "  For ESXi 7.x, use the manual allowAuthBypass + FAT32 disk procedure in Broadcom KB 423919."
                $row.Notes += "PK remediation skipped - host ESXi $hostVerStr requires manual disk/BIOS method (KB 423919). "
            } else {

            # ------------------------------------------------------------------
            # P09+ fast paths (try before SetupMode fallback)
            # ESXi 8.0 P09+ provides distinct PK update paths by vTPM and OS:
            #   vTPM-disabled:         silent update on reboot (official supported path)
            #   vTPM-enabled Linux/non-Windows: Broadcom documents the
            #                          uefi.secureBoot.PK.resetOnce VMX parameter
            #                          (KB423893), but this script does not perform
            #                          Linux guest-side PK enrollment. Known Linux
            #                          guests exit before Step 8/9 unless run in
            #                          hypervisor-only mode. Use Broadcom or OS-vendor
            #                          guidance, or the KB helper script.
            #   vTPM-enabled, Windows: skipped by default. Broadcom recommends
            #                          waiting for the planned capsule-based automated
            #                          solution. Override with -AllowUnsupportedVTPMWindowsPKRemediation
            # SetupMode is used as fallback if P09 paths fail or are not applicable.
            # ------------------------------------------------------------------
            $pkResolvedViaP09 = $false

            if ($isP09 -and -not $skipPKRemediation) {
                # Use hardware-detected vTPM status (reliable regardless of whether
                # step 0 ran) instead of guest-reported $tpmData.TPMPresent.
                # $tpmData may be null if step 0 was skipped or threw an exception.

                if (-not $hasVirtualTPM) {
                    # vTPM-disabled on P09+: silent PK update on reboot is the
                    # officially supported Broadcom path (KB 423893). BitLocker on a
                    # vTPM-disabled VM uses a password or recovery-key protector with
                    # no PCR seal, so the PK change itself does not trigger recovery.
                    # The only exposure is the reboot landing at the pre-boot prompt,
                    # so suspend BitLocker first using the same fail-closed pattern as
                    # the SetupMode path, then take the supported silent path. If the
                    # suspension cannot be confirmed, the silent reboot is not taken and
                    # control falls through to the SetupMode fallback, which re-evaluates
                    # BitLocker and fails closed on its own.
                    $silentSuspendOk = $true
                    if ($pkBitLockerActive) {
                        Write-Host "  [9/9] P09+ host / no vTPM, BitLocker active - re-suspending before the supported silent PK reboot..." -ForegroundColor Yellow
                        if (-not $BitLockerBackupShare) {
                            Write-Warning "    BitLocker is active but no -BitLockerBackupShare was provided."
                            Write-Warning "    Cannot safely reboot for the silent PK update - deferring to SetupMode fallback."
                            $row.Notes += "Silent PK path deferred - BitLocker active at PK step, no backup share. "
                            $silentSuspendOk = $false
                        } else {
                            $blsTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
                            $blsBackupOk  = Backup-BitLockerKeys -VMObj $vm -BackupShare $BitLockerBackupShare -Timestamp "PKsilent_$blsTimestamp"
                            if (-not $blsBackupOk) {
                                Write-Warning "    Recovery key backup failed - deferring silent PK path to SetupMode fallback."
                                $row.Notes += "Silent PK path deferred - BitLocker re-backup failed at PK step. "
                                $silentSuspendOk = $false
                            } else {
                                $blsSuspendOut  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                                    -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                                $blsSuspendJson = Get-LastJsonLine -Text $blsSuspendOut.ScriptOutput
                                if ($blsSuspendJson) {
                                    $blsSuspendData = $blsSuspendJson | ConvertFrom-Json
                                    $blsSuspendConfirmed = ((@($blsSuspendData.Suspended).Count -gt 0) -and
                                                            (@($blsSuspendData.Failed).Count -eq 0))
                                    Write-Host ("    $($blsSuspendData.Notes)") -ForegroundColor $(if ($blsSuspendConfirmed) {"Green"} else {"Yellow"})
                                    if (-not $blsSuspendConfirmed) {
                                        Write-Warning "    BitLocker re-suspension failed at PK step - deferring silent PK path to SetupMode fallback."
                                        $row.Notes += "Silent PK path deferred - BitLocker re-suspension failed at PK step. "
                                        $silentSuspendOk = $false
                                    }
                                } else {
                                    Write-Warning "    BitLocker re-suspension returned no status data - deferring silent PK path to SetupMode fallback."
                                    $row.Notes += "Silent PK path deferred - BitLocker re-suspension status unknown at PK step. "
                                    $silentSuspendOk = $false
                                }
                            }
                        }
                    }
                    if ($silentSuspendOk) {
                    Write-Host "  [9/9] P09+ host detected with no vTPM - attempting silent PK update via reboot..." -ForegroundColor Cyan
                    Write-Host "        This is the officially supported Broadcom path (KB 423893)." -ForegroundColor Gray
                    try {
                        Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
                        Start-Sleep -Seconds $WaitSeconds
                        $vm = Get-VM -Id $currentVMId
                        if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) { throw "Tools timeout after silent PK reboot." }
                        $pkSilentOut  = Invoke-VMScript -VM $vm -ScriptText $pkCheckScript `
                            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                        $pkSilentJson = Get-LastJsonLine -Text $pkSilentOut.ScriptOutput
                        if ($pkSilentJson) {
                            $pkSilentData = $pkSilentJson | ConvertFrom-Json
                            $pkResolvedViaP09 = $pkSilentData.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft")
                            Write-Host ("    PK Status after silent reboot: {0}" -f $pkSilentData.PK_Status) `
                                -ForegroundColor $(if ($pkResolvedViaP09) { "Green" } else { "Yellow" })
                            if ($pkResolvedViaP09) {
                                $row.PK_Status    = $pkSilentData.PK_Status
                                if ($pkSilentData.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pkSilentData.PK_Subject }
                                if ($pkSilentData.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pkSilentData.PK_Issuer }
                                if ($pkSilentData.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pkSilentData.PK_Thumbprint }
                                if ($pkSilentData.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pkSilentData.PK_Serial }
                                if ($pkSilentData.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pkSilentData.PK_NotAfter }
                                $row.PKEnrolled   = $true
                                $row.PKMethod     = "Silent"
                                if (Test-ExpectedPKThumbprint -Expected $ExpectedPKThumbprint -Actual $pkSilentData.PK_Thumbprint) {
                                    $row.PKRemediated = $true
                                    $row.Notes += "PK updated via P09 silent reboot. "
                                    if ($ExpectedPKThumbprint) { Write-Host "    PK thumbprint matches -ExpectedPKThumbprint." -ForegroundColor Green }
                                } else {
                                    $expectTpNorm = ($ExpectedPKThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                                    Write-Warning "    P09 silent reboot produced a valid PK but it does NOT match -ExpectedPKThumbprint."
                                    Write-Warning "      Expected: $expectTpNorm"
                                    Write-Warning "      Actual:   $($row.PK_Thumbprint)"
                                    $row.Notes += "P09 silent reboot produced a valid PK ($($row.PK_Thumbprint)) that does not match -ExpectedPKThumbprint ($expectTpNorm). Not marked fully remediated. "
                                    # PKRemediated stays $false. Valid PK present but not the expected certificate.
                                }
                            } else {
                                Write-Host "    Silent reboot did not update PK - falling back to SetupMode." -ForegroundColor Yellow
                                $row.Notes += "P09 silent reboot did not update PK - fell back to SetupMode. "
                            }
                        }
                    } catch {
                        Write-Warning "    Silent PK reboot failed ($($_.Exception.Message)) - falling back to SetupMode."
                        $row.Notes += "P09 silent reboot failed - fell back to SetupMode. "
                    }
                    } else {
                        Write-Host "        Silent PK path not taken (BitLocker could not be safely suspended) - using SetupMode fallback." -ForegroundColor Yellow
                    } # end silent PK suspend gate

                } elseif ($hasVirtualTPM -and -not $pkBitLockerActive) {
                    # vTPM-enabled on P09+: this script reaches resetOnce only for the
                    # Windows or unknown-risk unsupported override path, because known Linux
                    # guests exit before Step 8/9. Broadcom documents resetOnce for Linux
                    # and non-Windows vTPM-enabled VMs, but those are handled outside this
                    # script. For Windows vTPM-enabled VMs, Broadcom recommends waiting for
                    # the forthcoming capsule-based automated solution. Skip unless the user
                    # has explicitly accepted this risk via -AllowUnsupportedVTPMWindowsPKRemediation.
                    if ($hwGuestIsWindowsOrUnknownRisk -and -not $AllowUnsupportedVTPMWindowsPKRemediation) {
                        Write-Host "  [9/9] P09+ host / vTPM-enabled Windows or unknown-risk VM - skipping resetOnce." -ForegroundColor Yellow
                        Write-Host "        Broadcom KB 423893 recommends waiting for the forthcoming" -ForegroundColor Yellow
                        Write-Host "        capsule-based automated solution for Windows vTPM-enabled VMs." -ForegroundColor Yellow
                        Write-Host "        Use -AllowUnsupportedVTPMWindowsPKRemediation to override." -ForegroundColor Yellow
                        $row.Notes += "PK resetOnce skipped for Windows vTPM-enabled VM per KB 423893. Use -AllowUnsupportedVTPMWindowsPKRemediation to override. "
                    } elseif ($hwGuestIsWindows) {
                        # resetOnce is Broadcom's documented path for Linux and
                        # non-Windows vTPM-enabled guests and does not enroll the PK
                        # on Windows. For a confirmed Windows guest under the override,
                        # skip it and go straight to SetupMode rather than spend a
                        # reboot and an extra PCR7 change on a path that cannot update
                        # a Windows PK. SetupMode runs below while the PK is unresolved.
                        Write-Host "  [9/9] P09+ host / vTPM-enabled Windows VM (override) - skipping resetOnce." -ForegroundColor Yellow
                        Write-Host "        resetOnce is the Linux and non-Windows path and does not enroll a Windows PK." -ForegroundColor Yellow
                        Write-Host "        Proceeding directly to SetupMode enrollment." -ForegroundColor Yellow
                        $row.Notes += "resetOnce skipped for confirmed Windows guest (Linux and non-Windows mechanism). Used SetupMode directly. "
                    } else {
                    if ($hwGuestIsWindowsOrUnknownRisk) {
                        Write-Host "  [9/9] P09+ host / unknown-risk vTPM VM (override) - attempting resetOnce..." -ForegroundColor Yellow
                        Write-Host "        Broadcom recommends waiting for the capsule-based automated solution." -ForegroundColor Yellow
                        Write-Host "        Proceeding because -AllowUnsupportedVTPMWindowsPKRemediation was supplied." -ForegroundColor Yellow
                    } else {
                        Write-Host "  [9/9] P09+ host detected with vTPM - attempting PK update via resetOnce VMX parameter..." -ForegroundColor Cyan
                        Write-Host "        This is the officially supported Broadcom path (KB 423893)." -ForegroundColor Gray
                    }
                    if ($null -ne $tpmData -and $tpmData.CGRunning) {
                        Write-Host "  WARNING: Credential Guard is active. resetOnce updates the PK from outside" -ForegroundColor Yellow
                        Write-Host "           the guest OS which alters TPM PCR7 measurements. Credential Guard" -ForegroundColor Yellow
                        Write-Host "           may reinitialize and cached credentials may be flushed." -ForegroundColor Yellow
                    }
                    if ($null -ne $tpmData -and $tpmData.VBSRunning) {
                        Write-Host "  WARNING: VBS is active. The PCR7 change from resetOnce may affect" -ForegroundColor Yellow
                        Write-Host "           VBS-sealed secrets. Stored credentials may stop working." -ForegroundColor Yellow
                    }
                    try {
                        Stop-VMGraceful -VM $vm -TimeoutSeconds $GracefulShutdownTimeout
                        $vm = Get-VM -Id $currentVMId -ErrorAction SilentlyContinue
                        Set-VMXOption -VMObj $vm -Key "uefi.secureBoot.PK.resetOnce" -Value "TRUE"
                        $resetVal = Get-VMXOption -VMObj (Get-VM -Id $currentVMId) -Key "uefi.secureBoot.PK.resetOnce"
                        if ($resetVal -ne "TRUE") { throw "Failed to set uefi.secureBoot.PK.resetOnce." }
                        Write-Host "    resetOnce VMX option set." -ForegroundColor Green
                        Start-VM -VM $vm | Out-Null
                        $vm = Get-VM -Id $currentVMId
                        if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) { throw "Tools timeout after resetOnce power on." }
                        Write-Host "    VM is back online." -ForegroundColor Green
                        $vm = Get-VM -Id $currentVMId
                        Wait-GuestIdKnown -VMObj $vm -TimeoutSeconds 180 | Out-Null
                        $vm = Get-VM -Id $currentVMId
                        $pkResetOut  = Invoke-VMScript -VM $vm -ScriptText $pkCheckScript `
                            -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
                        $pkResetJson = Get-LastJsonLine -Text $pkResetOut.ScriptOutput
                        if ($pkResetJson) {
                            $pkResetData = $pkResetJson | ConvertFrom-Json
                            $pkResolvedViaP09 = $pkResetData.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft")
                            Write-Host ("    PK Status after resetOnce: {0}" -f $pkResetData.PK_Status) `
                                -ForegroundColor $(if ($pkResolvedViaP09) { "Green" } else { "Yellow" })
                            if ($pkResolvedViaP09) {
                                $row.PK_Status    = $pkResetData.PK_Status
                                if ($pkResetData.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pkResetData.PK_Subject }
                                if ($pkResetData.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pkResetData.PK_Issuer }
                                if ($pkResetData.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pkResetData.PK_Thumbprint }
                                if ($pkResetData.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pkResetData.PK_Serial }
                                if ($pkResetData.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pkResetData.PK_NotAfter }
                                $row.PKEnrolled   = $true
                                $row.PKMethod     = "ResetOnce"
                                if (Test-ExpectedPKThumbprint -Expected $ExpectedPKThumbprint -Actual $pkResetData.PK_Thumbprint) {
                                    $row.PKRemediated = $true
                                    $row.Notes += "PK updated via P09 resetOnce VMX parameter. "
                                    if ($ExpectedPKThumbprint) { Write-Host "    PK thumbprint matches -ExpectedPKThumbprint." -ForegroundColor Green }
                                } else {
                                    $expectTpNorm = ($ExpectedPKThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
                                    Write-Warning "    P09 resetOnce produced a valid PK but it does NOT match -ExpectedPKThumbprint."
                                    Write-Warning "      Expected: $expectTpNorm"
                                    Write-Warning "      Actual:   $($row.PK_Thumbprint)"
                                    $row.Notes += "P09 resetOnce produced a valid PK ($($row.PK_Thumbprint)) that does not match -ExpectedPKThumbprint ($expectTpNorm). Not marked fully remediated. "
                                    # PKRemediated stays $false. Valid PK present but not the expected certificate.
                                }
                                # Verify parameter auto-cleared. Clear explicitly if not
                                $resetCheck = Get-VMXOption -VMObj (Get-VM -Id $currentVMId) -Key "uefi.secureBoot.PK.resetOnce"
                                if ($resetCheck -and $resetCheck -ne "") {
                                    Set-VMXOption -VMObj (Get-VM -Id $currentVMId) -Key "uefi.secureBoot.PK.resetOnce" -Value "" -ErrorAction SilentlyContinue
                                    Write-Host "    resetOnce VMX option cleared (was not auto-cleared by firmware)." -ForegroundColor Gray
                                }
                            } else {
                                Write-Host "    resetOnce did not update PK - falling back to SetupMode." -ForegroundColor Yellow
                                # Clear the parameter before SetupMode takes over
                                Set-VMXOption -VMObj (Get-VM -Id $currentVMId) -Key "uefi.secureBoot.PK.resetOnce" -Value ""
                                $row.Notes += "P09 resetOnce did not update PK - fell back to SetupMode. "
                            }
                        }
                    } catch {
                        Write-Warning "    resetOnce path failed ($($_.Exception.Message)) - falling back to SetupMode."
                        Set-VMXOption -VMObj (Get-VM -Id $currentVMId) -Key "uefi.secureBoot.PK.resetOnce" -Value "" -ErrorAction SilentlyContinue
                        $row.Notes += "P09 resetOnce failed - fell back to SetupMode. "
                    }
                    } # end AllowUnsupportedVTPMWindowsPKRemediation gate
                } elseif ($hasVirtualTPM -and $pkBitLockerActive) {
                    # vTPM-enabled + BitLocker active on P09+: skip both P09 paths
                    # to avoid triggering PCR7 change without guest OS awareness.
                    Write-Host "  [9/9] P09+ host with vTPM + BitLocker active - skipping P09 paths to avoid lockout." -ForegroundColor Yellow
                    if ($hwGuestIsWindowsOrUnknownRisk -and -not $AllowUnsupportedVTPMWindowsPKRemediation) {
                        Write-Host "        SetupMode will also be skipped (Windows vTPM VM per KB 423893)." -ForegroundColor Yellow
                        Write-Host "        Use -AllowUnsupportedVTPMWindowsPKRemediation to allow SetupMode fallback." -ForegroundColor Yellow
                    } else {
                        Write-Host "        Falling back to SetupMode enrollment (BitLocker re-suspension will be handled)." -ForegroundColor Yellow
                    }
                    if ($hwGuestIsWindowsOrUnknownRisk -and -not $AllowUnsupportedVTPMWindowsPKRemediation) {
                        $row.Notes += "P09 resetOnce skipped - Windows/unknown-risk vTPM VM with BitLocker active. SetupMode also skipped per KB 423893. Use -AllowUnsupportedVTPMWindowsPKRemediation to override. "
                    } else {
                        $row.Notes += "P09 resetOnce skipped - BitLocker active at PK step, using SetupMode fallback. "
                    }
                }
            }

            if (-not $pkResolvedViaP09) {

            # Gate SetupMode enrollment for vTPM-enabled Windows VMs.
            # Per Broadcom KB 423893, manual PK update methods including SetupMode
            # alter Secure Boot variables and TPM PCR7 measurements without the
            # guest OS's awareness, risking BitLocker recovery and TPM-sealed app
            # lockout. Skip by default for Windows vTPM-enabled VMs and require
            # explicit opt-in via -AllowUnsupportedVTPMWindowsPKRemediation.
            if ($hasVirtualTPM -and $hwGuestIsWindowsOrUnknownRisk -and -not $AllowUnsupportedVTPMWindowsPKRemediation) {
                Write-Host "  [9/9] PK remediation skipped for vTPM-enabled Windows or unknown-risk VM." -ForegroundColor Yellow
                Write-Host "        Broadcom KB 423893 recommends waiting for the forthcoming" -ForegroundColor Yellow
                Write-Host "        capsule-based automated solution for this VM profile." -ForegroundColor Yellow
                Write-Host "        SetupMode PK enrollment alters TPM PCR7 measurements without" -ForegroundColor Yellow
                Write-Host "        guest OS awareness and may trigger BitLocker recovery or" -ForegroundColor Yellow
                Write-Host "        invalidate Credential Guard / stored credentials." -ForegroundColor Yellow
                Write-Host "        Use -AllowUnsupportedVTPMWindowsPKRemediation to override." -ForegroundColor Yellow
                $row.PKMethod = "Skipped_vTPMWindows"
                $row.Notes += "PK SetupMode enrollment skipped for Windows vTPM-enabled VM per KB 423893. Use -AllowUnsupportedVTPMWindowsPKRemediation to override. "
            } else {

            Write-Host "  [9/9] Remediating PK via UEFI SetupMode (ESXi $hostVerStr)..." -ForegroundColor Cyan
            # --- BitLocker re-check before SetupMode reboot ---
            # The step 0 suspension (RebootCount 3) covers the cert-update power
            # cycle (step 2), the cert-update reboot (step 6), and the optional 7b
            # extra reboot. By the time we reach here BitLocker may still have
            # auto-resumed (e.g. extra reboots beyond the count). Re-suspend if active.
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
                        $suspendJson2 = Get-LastJsonLine -Text $suspendOut2.ScriptOutput
                        if ($suspendJson2) {
                            $suspendData2 = $suspendJson2 | ConvertFrom-Json
                            $suspend2ok = ((@($suspendData2.Suspended).Count -gt 0) -and
                                          (@($suspendData2.Failed).Count -eq 0))
                            Write-Host ("    $($suspendData2.Notes)") -ForegroundColor $(if ($suspend2ok) {"Green"} else {"Yellow"})
                            if (-not $suspend2ok) {
                                Write-Warning "    BitLocker re-suspension failed at PK step - skipping PK remediation."
                                Write-Warning "    This prevents a PCR7-altering firmware change while BitLocker protection is active."
                                $row.Notes += "PK remediation skipped - BitLocker re-suspension failed at PK step. "
                                $skipPKRemediation = $true
                            }
                        } else {
                            # No JSON returned - cannot confirm suspension status. Fail safe
                            Write-Warning "    BitLocker re-suspension returned no status data - skipping PK remediation."
                            $row.Notes += "PK remediation skipped - BitLocker re-suspension status unknown at PK step. "
                            $skipPKRemediation = $true
                        }
                    }
                }
            }

            if (-not $skipPKRemediation) {

            $setupModeSet = $false
            try {

            # Record if the PK DER bypassed hash verification (audit trail in CSV).
            if ($script:PKDerUnverified) {
                $row.Notes += "PK DER enrolled WITHOUT SHA-256 verification (-AllowUnverifiedPKDer). "
            }

            # [1/5] Set SetupMode VMX option
            Write-Host "  [PK 1/5] Setting UEFI SetupMode VMX option..." -ForegroundColor Cyan
            Set-VMXOption -VMObj $vm -Key "uefi.secureBootMode.overrideOnce" -Value "SetupMode"
            $setupModeSet = $true
            $optVal = Get-VMXOption -VMObj (Get-VM -Id $vm.Id) -Key "uefi.secureBootMode.overrideOnce"
            if ($optVal -ne "SetupMode") {
                throw "Failed to set uefi.secureBootMode.overrideOnce - check vCenter permissions."
            }
            Write-Host "    SetupMode VMX option confirmed." -ForegroundColor Green

            # [2/5] Power off and on - SetupMode takes effect on next boot
            Write-Host "  [PK 2/5] Rebooting into SetupMode..." -ForegroundColor Cyan
            Stop-VMGraceful -VM $vm -TimeoutSeconds $GracefulShutdownTimeout
            $vm = Get-VM -Id $currentVMId -ErrorAction SilentlyContinue
            Start-VM -VM $vm | Out-Null
            $vm = Get-VM -Id $currentVMId
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $blStrandHint = if ($row.BitLockerSuspended) {
                    " The VM may be stranded at the BitLocker pre-boot prompt: open the VM console and enter the password, or press ESC for recovery and use the key backed up to '$BitLockerBackupShare'."
                } else { "" }
                throw "Tools timeout after SetupMode reboot.$blStrandHint"
            }
            Write-Host "    VM is back online." -ForegroundColor Green
            $vm = Get-VM -Id $currentVMId
            Wait-GuestIdKnown -VMObj $vm -TimeoutSeconds 180 | Out-Null
            $vm = Get-VM -Id $currentVMId
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
            $enrollJson = Get-LastJsonLine -Text $enrollOut.ScriptOutput
            if ($enrollJson) {
                $enrollData = $enrollJson | ConvertFrom-Json
                Write-Host ("    PKEnrolled : {0}" -f $enrollData.PKEnrolled) -ForegroundColor $(if ($enrollData.PKEnrolled) {"Green"} else {"Red"    })
                if ($KEKDerPath) {
                    Write-Host ("    KEKUpdated : {0}" -f $enrollData.KEKUpdated) -ForegroundColor $(if ($enrollData.KEKUpdated) {"Green"} else {"Yellow" })
                } else {
                    Write-Host  "    KEKUpdated : N/A (2023 KEK delivered via NVRAM regeneration, no -KEKDerPath supplied)" -ForegroundColor Gray
                }
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
            Set-VMXOption -VMObj (Get-VM -Id $vm.Id) -Key "uefi.secureBootMode.overrideOnce" -Value ""
            $setupModeSet = $false
            Write-Host "    SetupMode VMX option cleared." -ForegroundColor Gray

            # Re-suspend BitLocker before the post-enrollment reboot. The SetupMode
            # reboot above consumed one of the re-suspend counter's reboots, so refresh
            # it here so the post-enrollment boot is covered by a clear key. Without
            # this, a TPM-less password-protected OS volume can re-arm and halt at the
            # pre-boot password prompt - the OS never loads and the only symptom is a
            # Tools timeout below. Mirrors the re-suspend guard before the 7b reboot.
            if ($pkBitLockerActive) {
                try {
                    $pkReSuspendOut  = Invoke-VMScript -VM $vm -ScriptText $bitLockerSuspendScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                    $pkReSuspendJson = Get-LastJsonLine -Text $pkReSuspendOut.ScriptOutput
                    if ($pkReSuspendJson) {
                        $pkReSuspendData = $pkReSuspendJson | ConvertFrom-Json
                        if (@($pkReSuspendData.Suspended).Count -gt 0) {
                            Write-Host "    BitLocker re-suspended before post-enrollment reboot: $($pkReSuspendData.Suspended -join ', ')." -ForegroundColor Green
                        } else {
                            Write-Warning "    Could not confirm BitLocker re-suspension before post-enrollment reboot - the VM may prompt for a password or recovery key."
                            $row.Notes += "BL re-suspend before post-enrollment reboot: status unconfirmed. "
                        }
                    } else {
                        Write-Warning "    BitLocker re-suspension before post-enrollment reboot returned no status - the VM may prompt for a password or recovery key."
                        $row.Notes += "BL re-suspend before post-enrollment reboot: no status returned. "
                    }
                } catch {
                    Write-Warning "    BitLocker re-suspension before post-enrollment reboot failed: $($_.Exception.Message)"
                    Write-Warning "    The VM may prompt for a password or recovery key on the next reboot."
                    $row.Notes += "BL re-suspend before post-enrollment reboot failed: $($_.Exception.Message) "
                }
            }

            Restart-VMGuest -VM $vm -Confirm:$false | Out-Null
            Start-Sleep -Seconds $WaitSeconds
            $vm = Get-VM -Id $currentVMId
            if (-not (Wait-VMTools -VM $vm -TimeoutSeconds 300)) {
                $blStrandHint = if ($row.BitLockerSuspended) {
                    " The VM may be stranded at the BitLocker pre-boot prompt (password or recovery key): open the VM console and enter the password, or press ESC for recovery and use the key backed up to '$BitLockerBackupShare'. The PK was enrolled before this reboot, so Secure Boot is likely already remediated. Verify with -Assess after unlocking, then resume BitLocker (the script could not reach the guest to resume it)."
                } else { "" }
                throw "Tools timeout after post-enrollment reboot.$blStrandHint"
            }

            $pkVerifyOut  = Invoke-VMScript -VM $vm -ScriptText $verifyPKScript `
                -ScriptType Powershell -GuestCredential $GuestCredential -EA Stop
            $pkVerifyJson = Get-LastJsonLine -Text $pkVerifyOut.ScriptOutput
            if ($pkVerifyJson) {
                $pkVerifyData  = $pkVerifyJson | ConvertFrom-Json
                $row.PK_Status    = $pkVerifyData.PK_Status
                if ($pkVerifyData.PSObject.Properties.Name -contains 'PK_Subject')    { $row.PK_Subject    = $pkVerifyData.PK_Subject }
                if ($pkVerifyData.PSObject.Properties.Name -contains 'PK_Issuer')     { $row.PK_Issuer     = $pkVerifyData.PK_Issuer }
                if ($pkVerifyData.PSObject.Properties.Name -contains 'PK_Thumbprint') { $row.PK_Thumbprint = $pkVerifyData.PK_Thumbprint }
                if ($pkVerifyData.PSObject.Properties.Name -contains 'PK_Serial')     { $row.PK_Serial     = $pkVerifyData.PK_Serial }
                if ($pkVerifyData.PSObject.Properties.Name -contains 'PK_NotAfter')   { $row.PK_NotAfter   = $pkVerifyData.PK_NotAfter }
                $row.PKEnrolled   = $true   # enrollment was attempted this run
                $row.PKMethod     = if ($SupportedMethodsOnly) { "SetupMode_KB423919" } else { "SetupMode" }

                # Determine remediation success. Three accepted outcomes:
                #   1. A recognized Microsoft PK (Valid_WindowsOEM / Valid_Microsoft).
                #   2. A deliberately-enrolled custom/organizational PK: the operator
                #      supplied -AllowUnverifiedPKDer (acknowledging a non-Microsoft
                #      DER) AND -ExpectedPKThumbprint, and the live thumbprint matches
                #      the expected value. This classifies as Valid_CustomExpected so
                #      it is not confused with the ESXi placeholder (Valid_Other).
                #   3. (Not a success) anything else.
                # A supplied -ExpectedPKThumbprint that does NOT match is always a hard
                # failure: we enrolled a specific certificate and got something else.
                $expectTp = if ($ExpectedPKThumbprint) { ($ExpectedPKThumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() } else { "" }
                $actualTp = ("" + $pkVerifyData.PK_Thumbprint).ToUpperInvariant()
                $thumbSupplied = -not [string]::IsNullOrWhiteSpace($expectTp)
                $thumbMatches  = ($thumbSupplied -and $actualTp -eq $expectTp)
                $isMicrosoftPK = $pkVerifyData.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft")
                $isCustomExpected = ($AllowUnverifiedPKDer -and $thumbMatches -and $pkVerifyData.PK_Status -eq "Valid_Other")

                if ($thumbSupplied -and -not $thumbMatches) {
                    # Wrong certificate enrolled - hard failure regardless of status.
                    $row.PKRemediated = $false
                    Write-Warning ("  PK Status after remediation: {0}" -f $pkVerifyData.PK_Status)
                    Write-Warning "  PK thumbprint does NOT match -ExpectedPKThumbprint."
                    Write-Warning "    Expected: $expectTp"
                    Write-Warning "    Actual:   $actualTp"
                    $row.Notes += "PK thumbprint mismatch after enrollment: expected $expectTp, got $actualTp. Manual intervention required. "
                } elseif ($isMicrosoftPK) {
                    $row.PKRemediated = $true
                    Write-Host ("  PK Status after remediation: {0}" -f $pkVerifyData.PK_Status) -ForegroundColor Green
                    if ($pkVerifyData.PK_Thumbprint) { Write-Host ("  PK Thumbprint: {0}" -f $pkVerifyData.PK_Thumbprint) -ForegroundColor Gray }
                    if ($thumbMatches) {
                        Write-Host "  PK thumbprint matches -ExpectedPKThumbprint." -ForegroundColor Green
                        $row.Notes += "PK thumbprint matched expected value. "
                    }
                } elseif ($isCustomExpected) {
                    # Custom/organizational PK, deliberately enrolled and thumbprint-matched.
                    $row.PK_Status    = "Valid_CustomExpected"
                    $row.PKRemediated = $true
                    Write-Host "  PK Status after remediation: Valid_CustomExpected (non-Microsoft PK, matches -ExpectedPKThumbprint)" -ForegroundColor Green
                    if ($pkVerifyData.PK_Thumbprint) { Write-Host ("  PK Thumbprint: {0}" -f $pkVerifyData.PK_Thumbprint) -ForegroundColor Gray }
                    Write-Host "  Accepted because -AllowUnverifiedPKDer and -ExpectedPKThumbprint were supplied and the thumbprint matched." -ForegroundColor Gray
                    $row.Notes += "Custom PK enrolled and matched -ExpectedPKThumbprint (Valid_CustomExpected). Not a Microsoft PK. "
                } else {
                    $row.PKRemediated = $false
                    Write-Warning ("  PK Status after remediation: {0}" -f $pkVerifyData.PK_Status)
                    $row.Notes += "PK still invalid after enrollment - manual intervention required. "
                    if ($pkVerifyData.PK_Status -eq "Valid_Other" -and $AllowUnverifiedPKDer -and -not $thumbSupplied) {
                        Write-Warning "  A non-Microsoft PK was enrolled but -ExpectedPKThumbprint was not supplied, so it cannot be confirmed as the intended certificate."
                        $row.Notes += "Supply -ExpectedPKThumbprint to confirm a custom PK as remediated. "
                    }
                }
            }

            if ($row.BitLockerKeysBacked) {
                Write-Host "  BitLocker recovery keys retained at: $BitLockerBackupShare" -ForegroundColor Yellow
                Write-Host "  BitLocker auto-resumes after 3 reboots. Verify protection status after this maintenance window." -ForegroundColor Yellow
            }

            } catch {
                throw
            } finally {
                # Guarantee SetupMode VMX option is cleared even if an exception
                # occurs before the explicit clear in step [5/5]. Leaving this option
                # set can cause unexpected firmware state on next boot.
                if ($setupModeSet) {
                    try {
                        $vmForCleanup = Get-VM -Id $currentVMId -ErrorAction SilentlyContinue
                        if ($vmForCleanup) {
                            Set-VMXOption -VMObj $vmForCleanup `
                                -Key "uefi.secureBootMode.overrideOnce" -Value "" `
                                -ErrorAction SilentlyContinue
                        }
                    } catch {}
                }
            }

            } # end if (-not $skipPKRemediation)
            } # end AllowUnsupportedVTPMWindowsPKRemediation gate for SetupMode
            } # end if (-not $pkResolvedViaP09)
            } # end if ($hostMajor -ge 8)
        } # end else branch of if (-not $PKDerPath) - PK remediation block
        } # end if ($gateHWVerNum -ge 14) - Step 8/9 PK check and remediation

        # ------------------------------------------------------------------
        # Snapshot disposition
        # allGood requires: cert update complete AND (PK valid OR remediated
        # OR no PKDerPath provided - in which case PK is flagged for follow-up
        # but cert update is complete, which is the minimum for allGood)
        # ------------------------------------------------------------------
        # A valid PK that does not match -ExpectedPKThumbprint (and was not
        # replaced) is NOT counted as remediated here: $pkGoodEffective excludes
        # the unresolved-mismatch case. $row.PKRemediated already accounts for
        # successful enrollment/replacement and for P09 paths that matched.
        $pkGoodEffective = $pkGood -and -not ($pkExistingMismatch -and -not $row.PKRemediated)
        $snapshotSuccess = $certGood -and ($pkGoodEffective -or $row.PKRemediated -or (-not $PKDerPath))
        $row.CertUpdateVerified = $certGood
        # FullyRemediated requires PK actually valid or remediated - not merely omitted.
        # A VM with an invalid placeholder PK is not fully remediated just because
        # -PKDerPath was not supplied. A valid-but-non-matching PK (unresolved
        # -ExpectedPKThumbprint mismatch) is likewise not fully remediated.
        $row.FullyRemediated = $certGood -and ($pkGoodEffective -or $row.PKRemediated)

        if ($NoSnapshot) {
            $row.SnapshotRetained = $false
        } elseif ($snapshotSuccess -and $snapCreated -and -not $RetainSnapshots) {
            Write-Host "  Removing snapshot (completed successfully)..." -ForegroundColor Gray
            $snapRemoved = Remove-VMSnapshotSafe -VMObj $vm -Name $snapshotName
            $row.SnapshotRetained = -not $snapRemoved
            if (-not $snapRemoved) {
                $row.Notes += "Snapshot removal failed - retained for manual cleanup. "
            }
        } elseif ($snapCreated) {
            $row.SnapshotRetained = $true
            if ($RetainSnapshots -and $snapshotSuccess) {
                Write-Host "  Snapshot retained (-RetainSnapshots). Run -CleanupSnapshots when ready." -ForegroundColor Yellow
            } elseif (-not $certGood) {
                Write-Host "  Snapshot retained (cert update incomplete - may need second reboot cycle)." -ForegroundColor Yellow
                $row.Notes += "Cert update incomplete - may need manual second reboot cycle. "
            } elseif (-not $snapshotSuccess) {
                Write-Host "  Snapshot retained (PK remediation incomplete or not requested)." -ForegroundColor Yellow
            }
        }

        # ------------------------------------------------------------------
        # Resume BitLocker on completion (default, opt out with -SkipBitLockerResume).
        # Restores protection deterministically at the end of the maintenance window
        # rather than leaving it suspended on the auto-resume reboot countdown, so a
        # subsequent (possibly unattended) reboot does not strand the VM at the
        # pre-boot password/recovery prompt. Only for VMs this run suspended, only
        # when the guest is reachable, and never fatal: any failure is recorded in
        # Notes and the volume still auto-resumes on its own when its counter expires.
        # ------------------------------------------------------------------
        if ($row.BitLockerSuspended -and -not $SkipBitLockerResume -and $GuestCredential) {
            try {
                $vmResume = Get-VM -Id $currentVMId -ErrorAction Stop
                $guestRunning = ($vmResume.PowerState -eq "PoweredOn" -and
                                 $vmResume.ExtensionData.Guest.ToolsRunningStatus -eq "guestToolsRunning")
                if (-not $guestRunning) {
                    Write-Warning "  BitLocker left SUSPENDED - guest not reachable to resume (auto-resumes on its remaining reboot count, or resume manually)."
                    $row.Notes += "BL resume on completion skipped - guest not reachable. Left suspended (auto-resumes on remaining reboot count). "
                } else {
                    $resumeOut  = Invoke-VMScript -VM $vmResume -ScriptText $bitLockerResumeScript `
                        -ScriptType Powershell -GuestCredential $GuestCredential -ErrorAction Stop
                    $resumeJson = Get-LastJsonLine -Text $resumeOut.ScriptOutput
                    if ($resumeJson) {
                        $resumeData = $resumeJson | ConvertFrom-Json
                        if (@($resumeData.Resumed).Count -gt 0) {
                            Write-Host "  BitLocker protection resumed on: $($resumeData.Resumed -join ', ')." -ForegroundColor Green
                            $row.Notes += "BL: resumed on completion ($($resumeData.Resumed -join ', ')). "
                        }
                        if (@($resumeData.Failed).Count -gt 0) {
                            Write-Warning "  BitLocker resume did not confirm on: $($resumeData.Failed -join ', ') - verify protection status (auto-resumes on its remaining reboot count)."
                            $row.Notes += "BL: resume unconfirmed on $($resumeData.Failed -join ', ') (auto-resumes on remaining count). "
                        }
                    } else {
                        Write-Warning "  BitLocker resume returned no status - verify protection status (auto-resumes on its remaining reboot count)."
                        $row.Notes += "BL resume on completion: no status returned. Left to auto-resume. "
                    }
                }
            } catch {
                Write-Warning "  BitLocker resume on completion failed: $($_.Exception.Message) - auto-resumes on its remaining reboot count, or resume manually."
                $row.Notes += "BL resume on completion failed: $($_.Exception.Message) (left to auto-resume). "
            }
        } elseif ($row.BitLockerSuspended -and $SkipBitLockerResume) {
            Write-Host "  BitLocker left SUSPENDED (-SkipBitLockerResume). Auto-resumes on its remaining reboot count." -ForegroundColor Yellow
            $row.Notes += "BL left suspended on completion (-SkipBitLockerResume). "
        }

    } catch {
        $row.FinalStatus      = "ERROR"
        $row.SnapshotRetained = $snapCreated
        $row.Notes           += "Exception: $($_.Exception.Message)"
        Write-Warning "  Error processing $currentVMName`: $($_.Exception.Message)"
        if ($snapCreated) {
            Write-Warning "  Snapshot retained for rollback: '$snapshotName'"
        }
    }

    $report.Add($row)

    # Inter-VM delay - applied after each VM except the last in the batch.
    # Allows co-dependent or paired VMs time to fully start services before
    # the next VM is processed.
    if ($InterVMDelay -gt 0 -and $vm -ne $vms[-1]) {
        Write-Host "`n  Waiting $InterVMDelay second(s) before next VM (-InterVMDelay)..." -ForegroundColor Gray
        Start-Sleep -Seconds $InterVMDelay
    }
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "`n$('='*60)" -ForegroundColor White
Write-Host "SUMMARY" -ForegroundColor White
Write-Host "$('='*60)" -ForegroundColor White
$report | Format-Table VMName, SnapshotCreated, BitLockerKeysBacked, BitLockerSuspended,
    NVRAMRenamed, HWUpgraded, KEK_AfterNVRAM, UpdateTriggered, KEK_2023, DB_2023,
    FinalStatus, CertMethod, CertUpdateVerified, FullyRemediated, UEFICA2023Error,
    Evt1036, Evt1043, Evt1044, Evt1045,
    Evt1795, Evt1797, Evt1799, Evt1800, Evt1801, Evt1802, Evt1803, Evt1808,
    PK_Status, PKMethod, PKEnrolled, PKRemediated, SnapshotRetained, Notes -AutoSize

$csvPath = ".\SecureBoot_Bulk_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$report | Select-Object @{N="ScriptVersion";E={$ScriptVersion}},* | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Exported to: $csvPath" -ForegroundColor Green

$total            = $report.Count
$complete         = ($report | Where-Object { $_.FinalStatus -eq "Updated" }).Count
$certVerified     = ($report | Where-Object { $_.CertUpdateVerified -eq $true }).Count
$fullyRemediated  = ($report | Where-Object { $_.FullyRemediated -eq $true }).Count
$blActive   = ($report | Where-Object { $_.FinalStatus -eq "Skipped_BitLockerActive" }).Count
$blBackup   = ($report | Where-Object { $_.FinalStatus -eq "Skipped_BitLockerBackupFailed" }).Count
$blCheck    = ($report | Where-Object { $_.FinalStatus -eq "Skipped_BitLockerCheckFailed" }).Count
$blUnknown  = ($report | Where-Object { $_.FinalStatus -eq "Skipped_BitLockerStateUnknown" }).Count
$blSuspend  = ($report | Where-Object { $_.FinalStatus -eq "Skipped_BitLockerSuspendFailed" }).Count
$skipped    = $blActive + $blBackup + $blCheck + $blUnknown + $blSuspend
$failed     = ($report | Where-Object { $_.FinalStatus -eq "ERROR" }).Count
$retained   = ($report | Where-Object { $_.SnapshotRetained }).Count
$blBacked   = ($report | Where-Object { $_.BitLockerKeysBacked -eq $true }).Count
# PK counters - distinguish already-valid from newly enrolled
# Valid_Other is the ESXi-generated placeholder PK - it still needs enrollment.
# Valid_WindowsOEM / Valid_Microsoft / Valid_CustomExpected are the correct end states.
$pkAlreadyValid    = ($report | Where-Object { $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft") -and -not $_.PKEnrolled }).Count
$pkPlaceholder     = ($report | Where-Object { $_.PK_Status -eq "Valid_Other" -and -not $_.PKEnrolled }).Count
$pkEnrolledOk      = ($report | Where-Object { $_.PKEnrolled -and $_.PKRemediated }).Count
# A valid-but-nonmatching PK (PK is a genuine valid certificate, but its thumbprint
# does not match -ExpectedPKThumbprint, and the operator did not request
# replacement) is NOT an enrollment failure. Distinguish it: enrolled this run, not
# remediated, and the live PK is a real certificate (WindowsOEM/Microsoft/
# CustomExpected) rather than the ESXi placeholder.
$pkValidMismatch   = ($report | Where-Object { $_.PKEnrolled -and -not $_.PKRemediated -and $_.PK_Status -in @("Valid_WindowsOEM","Valid_Microsoft","Valid_CustomExpected") }).Count
# A genuine enrollment failure: enrolled this run, not remediated, and the live PK
# is not a real certificate (NULL, ESXi placeholder Valid_Other, check failed, or
# the wrong cert producing a non-valid status).
$pkEnrolledFail    = ($report | Where-Object { $_.PKEnrolled -and -not $_.PKRemediated -and $_.PK_Status -notin @("Valid_WindowsOEM","Valid_Microsoft","Valid_CustomExpected") }).Count
$pkNeeds           = ($report | Where-Object { $_.PK_Status -notlike "Valid*" -and $_.PK_Status -ne "Not checked" -and -not $_.PKEnrolled }).Count
$hypervisorPending = ($report | Where-Object { $_.FinalStatus -eq "HypervisorOnly_GuestStepsPending" }).Count
$snapFailed        = ($report | Where-Object { $_.FinalStatus -eq "Skipped_SnapshotFailed" }).Count
$needsAttn1801     = ($report | Where-Object { $_.FinalStatus -eq "NeedsAttention_1801" }).Count
$needsOSNative     = ($report | Where-Object { $_.FinalStatus -eq "NeedsOSNativeUpdate" }).Count
$safetySkipped     = ($report | Where-Object {
    $_.FinalStatus -like "Skipped_*" -and
    $_.FinalStatus -notmatch "^Skipped_BitLocker" -and
    $_.FinalStatus -ne "Skipped_SnapshotFailed"
}).Count
$pendingOther      = $total - $complete - $skipped - $failed - $hypervisorPending - $safetySkipped - $snapFailed - $needsAttn1801 - $needsOSNative

Write-Host ""
Write-Host "Registry Updated   : $complete / $total  (FinalStatus=Updated, use CertUpdateVerified column for confirmed cert state)" -ForegroundColor $(if ($complete -eq $total) {"Green"} else {"Cyan"})
Write-Host "Cert update done   : $certVerified / $total  (KEK/DB confirmed in NVRAM + no UEFICA2023Error)" -ForegroundColor $(if ($certVerified -eq $total) {"Green"} else {"Cyan"})
Write-Host "Fully remediated   : $fullyRemediated / $total  (cert update + PK valid or enrolled)" -ForegroundColor $(if ($fullyRemediated -eq $total) {"Green"} else {"Cyan"})
if ($pkAlreadyValid    -gt 0) { Write-Host "PK already valid   : $pkAlreadyValid  (WindowsOEM/Microsoft - no enrollment needed)"          -ForegroundColor Green  }
if ($pkPlaceholder     -gt 0) { Write-Host "PK placeholder     : $pkPlaceholder  (ESXi-generated - still needs PK enrollment)"            -ForegroundColor Yellow }
if ($pkEnrolledOk      -gt 0) { Write-Host "PK enrolled        : $pkEnrolledOk  (newly enrolled this run)"                                -ForegroundColor Green  }
if ($pkValidMismatch   -gt 0) { Write-Host "PK valid, mismatch : $pkValidMismatch  (valid PK present but does not match -ExpectedPKThumbprint, re-run with -ReplaceExistingPK to replace)" -ForegroundColor Yellow }
if ($pkEnrolledFail    -gt 0) { Write-Host "PK enroll failed   : $pkEnrolledFail  (manual intervention required - see Notes)"             -ForegroundColor Red    }
if ($pkNeeds           -gt 0) { Write-Host "PK still invalid   : $pkNeeds  (provide -PKDerPath and re-run)"                               -ForegroundColor Yellow }
if ($blBacked          -gt 0) { Write-Host "BL keys backed up  : $blBacked  (files at: $BitLockerBackupShare)"                                 -ForegroundColor Yellow }
if ($blActive          -gt 0) { Write-Host "Skipped (BL active): $blActive  (provide -BitLockerBackupShare to process)"                         -ForegroundColor Yellow }
if ($blBackup          -gt 0) { Write-Host "Skipped (BL backup): $blBackup  (key backup failed, resolve share access and re-run)"                -ForegroundColor Yellow }
if ($blCheck           -gt 0) { Write-Host "Skipped (BL check) : $blCheck  (BitLocker check failed, resolve guest connectivity)"                 -ForegroundColor Yellow }
if ($blUnknown         -gt 0) { Write-Host "Skipped (BL unknwn): $blUnknown  (VM powered off, use -AllowPoweredOffVMRemediation to override)"    -ForegroundColor Yellow }
if ($blSuspend         -gt 0) { Write-Host "Skipped (BL susp)  : $blSuspend  (suspension failed or partial, resolve BitLocker state and re-run)" -ForegroundColor Yellow }
if ($hypervisorPending -gt 0) { Write-Host "Hypervisor-only    : $hypervisorPending  (guest/OS-specific steps pending - see Notes column)" -ForegroundColor Yellow }
if ($snapFailed        -gt 0) { Write-Host "Skipped (snapshot) : $snapFailed  (snapshot failed, VM not modified - see Notes for reason)" -ForegroundColor Red    }
if ($needsAttn1801     -gt 0) { Write-Host "Needs attention    : $needsAttn1801  (PK updated, OS-side cert apply incomplete - Event 1801, awaiting 1808)" -ForegroundColor Yellow }
if ($needsOSNative     -gt 0) { Write-Host "Needs OS-native    : $needsOSNative  (-SupportedMethodsOnly refused the NVRAM fallback and OS servicing did not deliver KEK/DB - complete via OS or vendor remediation)" -ForegroundColor Yellow }
if ($safetySkipped     -gt 0) { Write-Host "Skipped (safety)   : $safetySkipped  (EFI/Secure Boot/ESXi/HW gate, NVRAM failure, or powered-off - see Notes)" -ForegroundColor Yellow }
if ($pendingOther      -gt 0) { Write-Host "Pending            : $pendingOther (may need second reboot cycle)"                            -ForegroundColor Yellow }
if ($failed            -gt 0) { Write-Host "Errors             : $failed"                                                                 -ForegroundColor Red    }
if ($retained          -gt 0) { Write-Host "Snapshots retained : $retained - run -CleanupSnapshots when ready."                          -ForegroundColor Yellow }

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
