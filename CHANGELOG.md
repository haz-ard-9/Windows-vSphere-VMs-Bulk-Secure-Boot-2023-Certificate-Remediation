# Changelog

All notable changes to FixSecureBootBulk.ps1 and its companion documentation.

This project began before a version banner was introduced. Entries dated earlier
than v1.5 (the first version to carry a `$ScriptVersion` string) are labeled by
date only, matching how they were actually published. From v1.5 onward, entries
are labeled by the version string the script reported at release.

## [2.0.0] - 2026-06-18

Major release, validated on pre-P09 and post-P09 hosts. Adds new operating
modes, stricter safety gates, vendor-guidance alignment, robust Platform Key
validation, and a documentation reframing. Review before upgrading from a 1.7.x
deployment. Consolidates all work since v1.7.7.

### Breaking Changes

- **`-UpgradeHardware` behavior changed.** It no longer performs a standalone
  hardware-only upgrade. It now adds a hardware upgrade step (2b) inside the main
  remediation sequence. Use the new `-UpgradeHardwareOnly` switch for a
  hardware-only run.
- **vTPM-enabled Windows VMs are skipped for PK remediation by default.** VMX-based
  PK changes occur outside the guest OS's awareness and can trigger BitLocker
  recovery or break TPM-sealed secrets. Broadcom recommends waiting for the
  planned capsule-based automated solution. Override with
  `-AllowUnsupportedVTPMWindowsPKRemediation`.
- **BitLocker now fails closed in more cases.** A VM is skipped (rather than
  proceeding) when: no RecoveryPassword protector exists on an active-protected
  volume, key backup fails, suspension fails or is partial, or the suspension
  script returns no parseable status. New `Skipped_BitLockerSuspendFailed` status.
- **Powered-off VMs are skipped by default.** BitLocker and guest state cannot be
  verified safely on a powered-off VM. Override with `-AllowPoweredOffVMRemediation`.
- **Snapshot failure now fails closed.** If a pre-remediation snapshot cannot be
  created, the VM is skipped entirely rather than proceeding with NVRAM
  manipulation that would have no rollback path. New `Skipped_SnapshotFailed`
  status. The failure reason is captured in the terminal output and the CSV
  `Notes` column. Applies to the main remediation path and `-UpgradeHardwareOnly`.
- **CSV output columns changed.** Added `CertUpdateVerified`, `FullyRemediated`,
  `BitLockerSkipped`, the PK identity columns `PK_Subject`, `PK_Issuer`,
  `PK_Thumbprint`, `PK_Serial`, `PK_NotAfter`, and the method-tracking columns
  `PKMethod` and `CertMethod`. A `ScriptVersion` column is prefixed to every
  export.

### New Features

- **Hypervisor-only mode (no `-GuestCredential`).** NVRAM rename, hardware
  upgrade, and snapshot management run without guest credentials. Guest-side
  steps are deferred. Re-run with `-GuestCredential` to complete cert update and
  PK enrollment. Status `HypervisorOnly_GuestStepsPending`.
- **`-UpgradeHardwareOnly`**: standalone hardware-version upgrade to HW21.
  Restores original power state (VMs already off stay off).
- **`-AllowNonWindowsTargets`**: allow targeting non-Windows VMs in
  hypervisor-only mode. Cannot be combined with `-GuestCredential`.
- **`-SupportedMethodsOnly`**: refuse the unsupported NVRAM regeneration and
  restrict PK remediation to the paths the script performs without it: the silent
  update on P09 vTPM-disabled Windows VMs (Broadcom's official path per KB 423893)
  and the SetupMode fallback (SetupMode reaches the same end state as the manual
  vUEFI method in KB 423919 but is the script's own implementation rather than the
  KB's manual workflow, and is labeled `SetupMode_KB423919` in `PKMethod`). The
  `resetOnce` VMX path is Broadcom-documented for Linux and other non-Windows
  VMs but is not automated by this script. Drives KEK/DB through in-guest OS
  servicing only, and reports a cert-absent VM the guest cannot service with
  `FinalStatus = NeedsOSNativeUpdate` rather
  than force-remediating it. Also refuses
  `-AllowUnsupportedVTPMWindowsPKRemediation`, since vTPM-enabled Windows PK
  updates remain unsupported per KB 423893. A superset of `-SkipNVRAMRename`,
  which suppresses the same regeneration but keeps the override available.
- **ESXi 8.0 P09 PK paths.** On P09+ hosts (build 25429389+), vTPM-disabled
  Windows VMs use the official silent PK update on guest reboot, including
  BitLocker-active volumes, which are suspended before the reboot and resumed
  after (a vTPM-disabled volume has no PCR seal, so the PK change cannot trigger
  recovery). Windows/unknown-risk vTPM VMs are skipped by default unless
  `-AllowUnsupportedVTPMWindowsPKRemediation` is supplied. SetupMode is the
  fallback. Known Linux/non-Windows guests are not remediated guest-side by this
  script. Use `-Assess` or `-AllowNonWindowsTargets` for identification and
  hypervisor-only preparation, then follow Broadcom KB 423893 or OS-vendor
  guidance for `resetOnce` and validation.
- **ESXi/HW safety gates enforced before mutation.** Host HW21 capability is
  verified before any snapshot, BitLocker, or power-off action.
  `Get-MaxHWVersionForHost` returns a fail-safe value for ESXi 8.x builds earlier
  than 8.0.2.
- **Stricter cert verification.** `CertUpdateVerified` requires the 2023 KEK and
  DB confirmed in NVRAM with no `UEFICA2023Error` key. `FullyRemediated`
  additionally requires a valid PK. Assessment mode uses the same standard.
- **Transactional rollback.** If NVRAM restore fails after the active `.nvram`
  was preserved as `.nvram_new`, the script attempts to recover it and refuses to
  power on a VM with no active NVRAM file.
- **Cleanup safety.** `.nvram_old` deletion is skipped by default when
  `Pre-SecureBoot-Fix*` snapshots still exist, and is re-checked after snapshot
  removal so a failed snapshot cleanup preserves the NVRAM rollback path. Parallel
  cleanup operations now have per-task timeouts. `-CleanupNvram` also removes
  orphan `.nvram_new` backups left by a prior `-Rollback` (the rollback preserves
  the current `.nvram` as `.nvram_new` before restoring `.nvram_old`). Unlike
  `.nvram_old` these never protect a rollback path and are removed regardless of
  snapshot state. The post-snapshot rollback-protection re-check is keyed by VM
  MoRef rather than display name so duplicate VM names cannot cross-protect.
- **BitLocker resumed on completion (default).** When the script suspended
  BitLocker on a VM and that VM finishes with the guest reachable, protection is
  re-enabled as the final step rather than being left on the auto-resume reboot
  countdown, so the protected state is deterministic at the end of the maintenance
  window instead of depending on a later reboot to re-arm. The new
  `-SkipBitLockerResume` switch restores the prior leave-suspended behavior (for
  example when further maintenance will reboot the VM, or when resuming manually).
  The resume runs only for VMs this run suspended, only when the guest is
  reachable, never fails the VM, and is recorded in the CSV `Notes` column.

### PK Validation

- **PK DER integrity verification.** The file supplied via `-PKDerPath` is
  verified against the known SHA-256 of Microsoft's published
  `WindowsOEMDevicesPK.der` before enrollment. A mismatch (corrupted, wrong, or
  substituted file) causes the script to refuse to enroll the PK and stop. The new
  `-AllowUnverifiedPKDer` switch bypasses the check for intentional custom or
  organizational PK enrollment, and the bypass is recorded in the CSV. The KEK DER
  has the same mechanism available but its hash is not pinned by default.
  `-KEKDerPath` now requires `-PKDerPath` (KEK enrollment happens only during the
  PK SetupMode path, so there is no KEK-only mode).
- **Certificate-exact PK control.** `-ExpectedPKThumbprint` compares the PK
  thumbprint against an operator-supplied value at every point the script reads or
  accepts a PK (already-remediated pre-check, step 8 already-valid, P09 silent
  reboot, P09 resetOnce, and SetupMode post-enrollment). After SetupMode enrollment
  a mismatch is a hard failure. On an existing valid PK a mismatch is not a failure:
  the VM has a working PK, so the script reports the existing PK's identity and
  leaves it in place (not counted as `FullyRemediated`) so the operator can decide
  whether to replace it. The new `-ReplaceExistingPK` switch (with `-PKDerPath` and
  `-ExpectedPKThumbprint`) makes a valid-but-non-matching PK eligible for SetupMode
  re-enrollment against the expected certificate, without bypassing the vTPM-Windows
  skip or the BitLocker fail-closed checks.
- **PK classification rewritten to parse certificates properly.** The previous
  approach scanned the raw PK variable bytes for the ASCII substrings "Windows OEM
  Devices" and "Microsoft", which was brittle (the "Microsoft" match in particular
  was far too broad). The PK variable is now parsed as an EFI_SIGNATURE_LIST: the
  signature-type GUID is validated against EFI_CERT_X509_GUID, the certificate
  offset is computed from the signature-list header (rather than a fixed 44-byte
  skip), and the embedded certificate is loaded as an X509Certificate2 and
  classified by its Subject. A populated PK whose contents are not a parseable
  X.509 certificate (the ESXi placeholder) is correctly reported as `Valid_Other`.
  `Valid_WindowsOEM` is the expected VMware remediation target. `Valid_Microsoft`
  is accepted as a valid-looking Microsoft-subject PK.
- **PK certificate identity recorded.** The `PK_Subject`, `PK_Issuer`,
  `PK_Thumbprint`, `PK_Serial`, and `PK_NotAfter` columns capture the parsed
  certificate identity from the live firmware at assessment, the step 8 PK check,
  and post-enrollment verification.
- **New `CheckFailed` PK status** distinguishes a `Get-SecureBootUEFI` read failure
  from a genuinely absent PK (`Invalid_NULL`).
- **Custom/organizational PK support.** When `-AllowUnverifiedPKDer` and
  `-ExpectedPKThumbprint` are both supplied and the post-enrollment thumbprint
  matches, a non-Microsoft PK is accepted as remediated with a distinct
  `Valid_CustomExpected` status (so it is not confused with the ESXi placeholder
  `Valid_Other`). Without an expected thumbprint, a non-Microsoft PK classifies as
  `Valid_Other` and is not counted as remediated.
- **Summary buckets distinguish a valid-but-nonmatching PK from an enrollment
  failure.** A PK that is a genuine valid certificate but does not match
  `-ExpectedPKThumbprint` (and was not replaced) is reported as "PK valid,
  mismatch" rather than "PK enroll failed."
- **Inert-switch rejection.** `-AllowUnverifiedPKDer`, `-ExpectedPKThumbprint`, and
  `-ReplaceExistingPK` are rejected in `-Assess`, `-UpgradeHardwareOnly`, cleanup,
  and rollback modes, consistent with the existing handling of `-PKDerPath` and
  `-KEKDerPath`.

### Behavior

- **Graded Event 1801 handling.** Event 1801 ("updated certificates available but
  not yet applied to firmware") is a normal intermediate state during a
  multi-reboot sequence, so its presence alone is no longer treated as failure. A
  VM is flagged `NeedsAttention_1801` only when 1801 persists after the step 7b
  extra reboot while Event 1808 is absent and the registry state is not `Updated`.
  These VMs are reported distinctly, do not count as `FullyRemediated`, and retain
  their snapshot.
- **Rollback confirms a restore target before powering off.** `-Rollback` now
  checks for a `.nvram_old` backup or a `Pre-SecureBoot-Fix*` snapshot before it
  powers a VM off. A VM with neither is left in its current power state and
  reported as skipped (`Skipped - nothing to roll back`), instead of being
  powered off, found to have nothing to restore, and powered back on as in
  v1.7.7. A VM whose `.nvram_old` presence cannot be verified due to a datastore
  read error, and that has no snapshot, is also left untouched
  (`Skipped - could not verify rollback targets`). The rollback summary adds a
  skipped tally.
- **Successful snapshot rollback no longer mislabeled.** A VM that reverts its
  `Pre-SecureBoot-Fix` snapshot but where the `.nvram_old` file restore was not
  needed (the snapshot revert already restored NVRAM) is now reported as
  `Rolled Back (via snapshot, NVRAM file restore not needed)`. In v1.7.7 the same
  outcome fell through to `Partial - NVRAM not restored`, a false negative on a
  rollback that actually succeeded.
- **`-Confirm` suppresses the rollback prompt.** `-Confirm` is a custom switch
  that suppresses the script's interactive confirmation prompts and proceeds
  automatically (the inverse of the standard PowerShell `-Confirm` convention).
  In v1.7.7 it suppressed the other confirmation prompts but not the `-Rollback`
  confirmation, which always required interactive input. v2.0.0 extends
  `-Confirm` to the rollback prompt as well, so `-Rollback -Confirm` runs
  unattended.

### Reliability

- All guest-script JSON extraction routed through a null-safe `Get-LastJsonLine`
  helper to behave correctly under `Set-StrictMode`.
- `Set-VMXOption` uses `ReconfigVM_Task` with task wait, error propagation, and a
  timeout.
- `SecureBoot\Servicing` diagnostics (`UEFICA2023Status`, `UEFICA2023Error`,
  `UEFICA2023ErrorEvent`, `AvailableUpdates`) are read and logged before the
  Servicing subkey is cleared for a retry, preserving the evidence needed to
  diagnose a stuck update.
- Scheduled task trigger uses the split
  `Start-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update"`
  form, matching the `Get-ScheduledTask` checks and the PowerShell object model.
- Snapshot removal failures are now reflected accurately in `SnapshotRetained`.
- VM refresh standardized on MoRef Id rather than display name to avoid
  mis-targeting when duplicate VM names exist.

### Documentation

- Reframed positioning: the tool is presented as an assessment and orchestration
  aid with a recommended remediation hierarchy (assess, supported Broadcom path,
  Microsoft certificate deployment, manual Broadcom PK remediation, NVRAM rename as
  an unsupported field-tested fallback) rather than a default bulk NVRAM fix. New
  "Recommended Approach" section.
- vTPM Windows vs. Linux wording corrected throughout: `resetOnce` is documented as
  the Broadcom path for Linux/non-Windows vTPM-enabled VMs only. Windows
  vTPM-enabled VMs are skipped by default pending Broadcom's automated solution.
- Companion guides (no-script and DC) hardened to match the script: robust EFI
  signature list + X.509 PK classification, Servicing diagnostics preserved before
  the key is cleared (both DC sections as well as the no-script guide), corrected
  Linux/non-Windows `resetOnce` wording, split `Start-ScheduledTask` form, and
  manual post-enrollment PK verification that compares the live PK thumbprint
  against the enrolled DER thumbprint. The post-enrollment expected-output text was
  reconciled to the `PK VERIFIED` message the snippet actually prints.
- DC rollback caution added: reverting a domain controller snapshot is an Active
  Directory recovery event (VM-Generation ID, InvocationID reset, RID pool
  discard) and not routine cleanup.
- README background corrected so it no longer describes NVRAM deletion as "the
  fix". It is framed as a historical, now-unsupported workaround.
- Added the exact 2011 certificate expiration dates (per Microsoft KB 5062710,
  updated May 18, 2026) to the README, the script header NOTES, and both manual
  guides: KEK CA 2011 (June 24, 2026), UEFI CA 2011 (June 27, 2026), and
  Windows Production PCA 2011 (October 19, 2026).
- Removed em dashes from README and CHANGELOG for consistency.

## [1.7.7] - 2026-05-12

### Changed

- Made `-GuestCredential` fully optional in main mode. Previously, omitting
  `-GuestCredential` without `-UpgradeHardware` triggered a mandatory credential
  prompt, and combining `-UpgradeHardware` without `-GuestCredential` ran only the
  standalone hardware upgrade path, skipping the NVRAM rename. `$isMainMode` now
  includes all runs that are not cleanup/rollback/assess regardless of credential
  presence. Guest-dependent steps (BitLocker check, pre-assess, cert update
  trigger, verify, PK enrollment) are gated on `$GuestCredential` being present and
  skipped with a clear message when omitted. Hypervisor-level steps (snapshot,
  hardware upgrade, NVRAM rename, power cycle) run regardless. This allows hardware
  upgrade and NVRAM rename to be combined in a single run without guest access.
  Reported by @zuerom (issue #15).

## [1.7.6] - 2026-05-12

### Added

- VBS and Credential Guard detection in `$tpmCheckScript`. Queries
  `Win32_DeviceGuard` via CIM for `VirtualizationBasedSecurityStatus` and
  `SecurityServicesRunning`, and surfaces `VBSRunning` and `CGRunning` in the JSON
  output.
- Specific Credential Guard warning at step 0 when a vTPM is present without
  BitLocker and Credential Guard is active, explaining that a PCR7 change may cause
  Credential Guard to reinitialize and flush cached credentials. VBS-active note
  added to the CSV Notes column.

### Fixed

- Cleanup confirmation prompt now respects `-Confirm`. The "Proceed? (Y/N)" prompt
  shown after the space-reclaimed estimate was always interactive regardless of
  `-Confirm`. It is now suppressed consistently with the other confirmation
  prompts. Reported by @zuerom (issue #15).

## [1.7.5] - 2026-05-07

### Changed

- Strengthened the vTPM warning at step 0 when a vTPM is present but BitLocker is
  not active. The previous single-line message was expanded to explain that the
  NVRAM rename alters TPM PCR7 measurements, which can invalidate DPAPI-sealed
  machine keys on vTPM-enabled VMs, causing stored credentials (scheduled task
  passwords, Credential Manager entries) to stop working. Notes that gMSA tasks and
  tasks with no stored password are unaffected, and suggests `-SkipNVRAMRename` as
  the mitigation for VMs that already have the 2023 KEK.

### Fixed

- NVRAM rename failure when multiple datastores share the same name.
  `Get-Datastore -Name` returns all matching datastores across the vCenter
  inventory and the script was silently picking the first. `Get-VMDatastoreContext`,
  `Get-VMDatastoreSpaceInfo`, and the `-CleanupNvram` datastore lookup now resolve
  the datastore by MoRef from the VM's own datastore list first (`$vmView.Datastore`)
  and fall back to name lookup only if MoRef resolution fails. Reported by @bao86
  (issue #12).
- NVRAM rename failure when a custom `nvram =` path is set in the VM's VMX
  ExtraConfig. The script was always searching for `*.nvram` by pattern regardless
  of a custom filename. `Get-VMDatastoreContext` now reads the `nvram` key from
  `Config.ExtraConfig` and surfaces it as `CustomNvramName`. `Rename-VMNvram` uses
  that exact filename as the search pattern when present.

## [1.7.4] - 2026-05-04

### Fixed

- `-Rollback` mode crash when answering the confirmation prompt. The local variable
  `$confirm` collided with PowerShell's built-in `-Confirm` common parameter
  (`SwitchParameter`), causing a type-conversion error when `Read-Host` assigned a
  string value to it. Renamed to `$proceedRollback`. The other two interactive
  prompts already used `$confirmInput` and were unaffected. Reported by @noegabriel
  (issue #11).

## [1.7.3] - 2026-04-24

### Added

- `-SkipNVRAMRename` switch. When specified, steps 2/2b/3/4 (power off, hardware
  upgrade, NVRAM rename, power on) are skipped entirely and the script proceeds
  directly to step 5 (cert update trigger). Intended for VMs where the 2023 KEK is
  already present in NVRAM (created on ESXi 8.0.2+ or previously remediated) and the
  operator wants the cert-update triggering and PK enrollment without the NVRAM file
  manipulation that Broadcom KB 423919 warns can lead to unexpected VM corruption.
  `NVRAMRenamed` is set to `Skipped` in the CSV. The gate is bypassed if smart step
  detection has already determined steps 2-4 should be skipped.
- `.PARAMETER SkipNVRAMRename` help block. Missing `.PARAMETER BitLockerBackupShare`
  help block, and `.EXAMPLE` entries for all parameters that lacked one. All 21
  script parameters now have both a `.PARAMETER` block and at least one `.EXAMPLE`.

### Changed

- Startup support-status notice updated to include the KB 423919 explicit
  corruption warning and a second reference link, in addition to the existing
  Broadcom community forum reference.

## [1.7.2] - 2026-04-16

### Added

- `Secure-Boot-Update` task registration check in `$updateScript` (step 5) and
  `$taskTriggerScript` (step 6). `Start-ScheduledTask` returns silently when the
  task is absent from the Task Scheduler COM database, causing the cert update to be
  a no-op on VMs cloned from Sysprep templates where the XML exists on disk but the
  COM database was reset. Both scripts now query `Get-ScheduledTask` and, if the
  task is absent, attempt re-registration via `Register-ScheduledTask -Xml` from the
  on-disk XML, writing a descriptive warning if re-registration or the XML is
  missing. Root cause and fix contributed by @thezeus123 (issue #9).
- `SBUTaskStatus` field in `$assessGuestScript` (`Registered`,
  `NotRegistered_XMLPresent`, or `NotRegistered_XMLMissing`), surfaced in assess
  output with color coding and in the Notes and ActionNeeded columns, to identify
  Sysprep template clones with unregistered tasks before remediation.
- Support status notice displayed on every run immediately after the version
  banner, printing the Broadcom official unsupported position with a link to the
  source thread, requiring `Y` to acknowledge and continue (suppressed by
  `-Confirm`).

## [1.7.1] - 2026-03-30

### Added

- `Wait-GuestIdKnown` helper. After a SetupMode reboot triggered by
  `uefi.secureBootMode.overrideOnce`, VMware Tools reports `Guest.State = "Running"`
  early but `GuestFamily` and `HostName` populate asynchronously 15-20 seconds
  later, and `Copy-VMGuestFile` fails ("guest OS unknown") when called too early.
  The function polls at 5-second intervals until `GuestId`, `GuestFamily`, and
  `HostName` are all set, timing out after 180 seconds. Inserted in `[PK 2/5]` after
  `Wait-VMTools` and before `[PK 3/5] Copy-VMGuestFile`. Contributed by @thezeus123
  (issue #8).

### Changed

- Verify script event collection rewritten to use `Get-WinEvent -FilterHashTable`
  with `Group-Object -Property Id`, reducing the verify script from 3280 to 3090
  characters and replacing 12 individual `if` statements with a `-Contains` check.
  Contributed by @ckitt-git-hub-1020. `Group-Object` used in place of the `Group`
  alias for cross-version safety.
- Inline attribution comments added for both contributions.

## [1.7] - 2026-03-30

### Fixed

- Routed both `$assessGuestScript` call sites (assess mode and main remediation
  pre-check) through `Invoke-VMScriptViaFile` instead of direct `Invoke-VMScript`.
  `$assessGuestScript` (2693 chars) and `$verifyScript` (3280 chars) both exceed the
  undocumented ~2600-char limit on `Invoke-VMScript` script-text payloads. Testing
  on Windows Server 2025 confirmed that the v1.6.1 fix alone still failed at step 7
  while the file-based approach completes successfully.

## [1.6.1] - 2026-03-30

### Fixed

- Added `$ErrorActionPreference`, `$WarningPreference`, and `$ProgressPreference`
  set to `SilentlyContinue` at the top of `$verifyScript`. Missing error suppression
  caused `Get-ItemPropertyValue` to throw a terminating error when the
  `UEFICA2023Error` registry key does not exist (observed on Windows Server 2025),
  aborting the entire script block before any output and producing ExitCode 1 with
  empty output at step 7.

## [1.6] - 2026-03-27

### Added

- `Get-MaxHWVersionForHost` helper. PowerCLI capability object properties
  (`SupportedEVCMode`, `SupportedVmWareVersion`, `MaxSupportedVmHardwareVersion`) are
  not consistently populated across vCenter/PowerCLI versions. The ESXi version
  string is the reliable source of truth. Maps ESXi 9.x to HW 22, 8.x to HW 21, 7.x
  to HW 19. Defaults to 21 if the host version cannot be determined.
- `[string]$vCenter` parameter and `.PARAMETER vCenter` help block. The connection
  block uses `$vCenter` when provided, falling back to a `Read-Host` prompt. The
  hardcoded `vcenter.yourdomain.com` placeholder is gone. Editing the source to set
  a server name is no longer required.

### Changed

- `Invoke-VMHardwareUpgrade` rewritten per community contribution (issue #6).
  Replaced `ReconfigVM_Task` with `UpgradeVM_Task`, the correct vSphere API for
  hardware version upgrades. Added a mandatory `TargetVersion` parameter. Used an
  `[ordered]` hashtable returning a proper `[pscustomobject]`. Increased the task
  timeout from 60 to 120 seconds, and refreshed the VM view after a successful
  upgrade. Both call sites now pass `Get-MaxHWVersionForHost` as `-TargetVersion`.
- VMware Tools status console output uses
  `$vm.Guest.ExtensionData.ToolsVersionStatus`, which is consistently available
  across PowerCLI versions.

### Removed

- `SupportedEVCMode` detection from the hardware upgrade path. EVC modes are CPU
  compatibility modes unrelated to VM hardware versions and were silently returning
  null in all tested environments.

## [1.5] - 2026-03-26

### Added

- `$ScriptVersion` variable (first versioned release), output to the console on
  every run after the vCenter connection and prepended as the first column in all
  five CSV exports.
- VMware Tools version and status in assess and main remediation console output,
  color coded.

### Fixed

- Verify script timestamp parsing uses `[datetime]::ParseExact` with
  `InvariantCulture` instead of a bare `[datetime]` cast, which is culture-sensitive
  and failed silently with ExitCode 1 on non-US system locales.
- `UEFICA2023Status` no longer shows "not found" when the JSON value is an empty
  string. A `-notlike ""` guard was added alongside the null check.

## [2026-03-24]

### Added

- `Stop-VMGraceful` helper. Attempts a graceful guest OS shutdown via
  `Stop-VMGuest` before falling back to a hard power off, polling every 5
  seconds until `PoweredOff` or timeout, then falling back to `Stop-VM -Kill`.
  Refreshes the VM object after shutdown.
- `-GracefulShutdownTimeout` parameter (default 120 seconds, 0 skips the graceful
  attempt). All four `Stop-VM -Kill` call sites (main step 2, PK 2/5 SetupMode
  reboot, hardware upgrade, rollback) replaced with `Stop-VMGraceful`.

## [2026-03-20]

### Added

- Six TPM-WMI event IDs per KB5085046 to `$assessGuestScript` and `$verifyScript`:
  1036 (DB updated), 1043 (KEK applied), 1044 (Option ROM DB updated), 1045 (UEFI CA
  DB updated), 1797 (boot manager update failed), 1799 (boot manager updated).
  `-MaxEvents` increased from 50 to 100.
- `UEFICA2023ErrorEvent` registry value read, appended to VM Notes when present.

### Fixed

- VMName column showing `System.String[]` in CSV output and `{VMName}` in
  Format-Table console output. Root cause was a variable scope collision between the
  `[string[]]$VMName` parameter and the `$vmName` loop variable (PowerShell variable
  names are case-insensitive, so both resolved to the same variable and the
  `[string[]]` constraint coerced all assignments back to a string array). Fixed by
  renaming the loop variable to `$currentVMName` across all 25 usages.
- Regression where a multiline `$evts` hashtable in `$assessGuestScript` caused the
  guest script to return empty output. Reverted to single-line format (multiline
  hashtable declarations are not safe in the `Invoke-VMScript` transport context).
- Silent data loss in PowerShell 7 when the guest script returns empty output:
  `ConvertFrom-Json` returns `$null` in PS7 instead of throwing. Added an explicit
  null check after parse so the catch block fires correctly.

## [2026-03-16]

### Added

- `-Assess` switch: read-only assessment mode that makes no changes. Collects
  hardware version, ESXi host/version, firmware type, Secure Boot state, and
  `.nvram_old`/snapshot presence at the hypervisor layer. With `-GuestCredential`
  also collects KEK/DB/PK cert status, registry deployment signals, TPM-WMI event
  IDs, and BitLocker state in a single call. Derives a per-VM `ActionNeeded` column.
  Exports to `SecureBoot_Assess_<timestamp>.csv`. Mutually exclusive with all action
  modes.
- `-UpgradeHardware` standalone mode (powers off, snapshots, upgrades to latest
  supported HW version, powers on. Combined with `-GuestCredential` inserts as step
  2b) and `Invoke-VMHardwareUpgrade` helper. `-CleanupHWSnapshots` switch to remove
  `Pre-HWUpgrade*` snapshots.
- Smart step detection pre-check at the start of each VM's loop, setting an entry
  point (full, skipNvram, skipToStep6, certDone, allDone) to skip already-completed
  steps.
- Step 7b automatic extra reboot when Event 1801 or 1800 is present and 1808 is
  absent. Re-verifies and diagnoses persistent 1801 in priority order (1802, 1795,
  registry error, stuck AvailableUpdates).
- `-InterVMDelay` parameter (default 0) for co-dependent VM pairs, not applied after
  the last VM.
- Datastore space check wired into assess and main pre-confirm: per-VM snapshot size
  estimate from `LayoutEx.File` delta sizes (or committed bytes as an upper bound,
  or a fixed fallback), with a 16 MB per-disk baseline floor. Adds `Datastore`,
  `DSFreeGB`, `DSCapacityGB`, `SnapshotEstimateGB`, `DSSpaceOK` columns and
  warnings. `Format-Bytes` and `Get-VMDatastoreSpaceInfo` helpers added.
- `Remove-SnapshotsParallel` and `Remove-NvramFilesParallel` helpers. Snapshot
  removal groups by datastore and fires one async task per datastore group in
  parallel (sequential within a group to avoid competing I/O). NVRAM file deletion
  fires all tasks simultaneously since it is a metadata operation.

### Changed

- Removed mutual exclusion between `-CleanupSnapshots`, `-CleanupHWSnapshots`, and
  `-CleanupNvram`. All three can be combined in a single run with a safe internal
  order (SecureBoot-Fix snapshots, then HWUpgrade snapshots, then `.nvram_old`
  files) and a single confirmation prompt and combined CSV. Added non-managed child
  snapshot detection that skips a parent snapshot with a warning when unmanaged
  children exist.
- `Resolve-TargetVMs` and CSV name collection preserve input order via a
  seen-hashtable dedup instead of `Sort-Object`/`Select-Object -Unique`.

### Fixed

- Verify script rewritten from JSON to `VERIFY_START`/`VERIFY_END` bracketed
  KEY=VALUE output to avoid JSON serialization that caused ExitCode 1 with empty
  output under `Invoke-VMScript`.
- `UEFICA2023Error` read uses `Get-ItemProperty` plus a member check to avoid a
  non-terminating error when the property is absent.
- `Copy-VMGuestFile` calls for PK and KEK DER use `-Force` to avoid failure when the
  file exists from a previous run.
- `Resolve-TargetVMs` named-VM path no longer applies an OS filter, which was
  silently dropping explicitly named VMs whose guest info was stale after a snapshot
  revert or slow boot.
- Step `[9/9]` console color corrected from Yellow to Cyan to match other step
  headers.

## [2026-03-13]

### Added

- TPM-WMI event log query in the verify script (events 1795, 1800, 1801, 1802,
  1803, 1808), returned in the JSON payload, with corresponding CSV columns,
  inline console status, and Notes entries for error events. Event 1808 absence
  intentionally does not block `$certGood`. Registry signals and cert checks remain
  the primary pass/fail gate.
- `UEFICA2023Error` read from `HKLM:\...\SecureBoot\Servicing` returned in the JSON
  result, with a CSV column. `$certGood` is gated on the error key being absent so
  VMs with the key present are no longer reported as successful.
- `-IgnoreCertificateWarnings` switch and help block. The unconditional
  `Set-PowerCLIConfiguration -InvalidCertificateAction Ignore` was replaced with a
  conditional `-Scope Session` block that only fires when the switch is passed and
  emits warnings so the operator sees what they are opting into.

### Changed

- Step 9 comment block and ESXi 7.x warning updated to reflect KB 423919 (March
  2026), which documents a single `allowAuthBypass` + FAT32 disk method for all ESXi
  versions. SetupMode is clarified as an automatable alternative. Stale
  `PK_SigListContent.bin` reference removed from the help block.

## [2026-03-10]

### Added

- Windows 10 and 11 to the guest OS filtering so Windows 10/11 VMs are supported in
  addition to Windows Server.

## [2026-03-06]

### Fixed

- Scoped the datacenter lookup to the target VM in all datastore operations.
  `Get-VMDatastoreContext` and the `-CleanupNvram` block both resolved the
  datacenter via `Get-Datacenter | Select-Object -First 1`, which returns an
  arbitrary datacenter in multi-datacenter vCenter environments. Datastore file
  operations require the MoRef of the datacenter the target VM actually belongs to.
  `Get-VMDatastoreContext` now uses `Get-Datacenter -VM $VMObj`, and the
  `-CleanupNvram` block resolves `$dcRef` per VM. No behavioral change in
  single-datacenter environments. Identified by @smiszewski (PR #1).

## [2026-03-05] - PK enrollment

This release predates the `$ScriptVersion` banner introduced in v1.5.

### Changed

- `-PKBinPath` renamed to `-PKDerPath` (now accepts `WindowsOEMDevicesPK.der`, a
  DER-encoded X.509 certificate, instead of the nonexistent `PK_SigListContent.bin`).
  `-KEKBinPath` renamed to `-KEKDerPath`.

### Fixed

- `Valid_Other` PK now correctly triggers enrollment. VMs whose NVRAM was
  regenerated by ESXi < 9.0 receive an ESXi-generated placeholder PK (`Valid_Other`)
  which previously passed the validity check and skipped step 9. Per Broadcom KB
  423919, ESXi versions earlier than 9.0 do not install a proper Platform Key.
  `Valid_Other` is now treated identically to `Invalid_NULL` and triggers PK
  enrollment when `-PKDerPath` is provided.
- PK enrollment uses the correct file format. The previous implementation passed a
  `.bin` file to `Set-SecureBootUEFI -ContentFilePath`, which expects an EFI
  Signature List. The correct approach uses
  `Format-SecureBootUEFI -CertificateFilePath -FormatWithCert` to convert the DER
  certificate to ESL format piped directly to `Set-SecureBootUEFI`. No intermediate
  `.bin` file is required.

### Added

- ESXi host version check in step 9: emits a detailed warning and skips the
  automated path on ESXi 7.x hosts (where SetupMode is unavailable) rather than
  failing silently.
- BitLocker re-suspension at step 9: re-checks BitLocker before the SetupMode reboot
  and, if active, performs a second key backup and re-suspends with `RebootCount 2`.
  If BitLocker is active but no `-BitLockerBackupShare` was provided, PK remediation
  is skipped rather than risking a lockout.
- `PKEnrolled` CSV column. Four-bucket PK summary output (already valid, placeholder,
  enrolled, enroll failed, still invalid). A separate NOTES block after the summary
  table so long notes are not truncated. A `Valid_Other` warning at step 8, and a
  corrected fallback manual enrollment command
  (`Format-SecureBootUEFI | Set-SecureBootUEFI`).

## [2026-03-04]

### Fixed

- Added additional BitLocker verification methods for cases where
  `Get-BitLockerVolume` is unavailable (typically when the BitLocker feature is not
  installed), which previously caused a parsing error.

## [2026-03-03]

### Added

- Initial upload of FixSecureBootBulk.ps1.
