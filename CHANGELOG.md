# Changelog

All notable changes to FixSecureBootBulk.ps1 and its companion documentation,
through v1.7.7.

This file documents the project history up to and including v1.7.7.

The project began before a version banner was introduced. Entries dated earlier
than v1.5 (the first version to carry a `$ScriptVersion` string) are labeled by
date only, matching how they were actually published. From v1.5 onward, entries
are labeled by the version string the script reported at release.

## Documentation (post-v1.7.7, doc-only)

After v1.7.7, the documentation on the default branch received P09-related updates
with no change to the v1.7.7 script. These notes are included in this frozen
package because they describe how ESXi 8.0 P09 affects use of the v1.7.7 script:

- Added an "Important notice regarding support status" to the README, the DC guide,
  and the no-script manual guide. It records that Broadcom's prior NVRAM guidance
  (KB 421593) was removed and replaced by KB 423919 "to avoid suggestions of
  deleting NVRAM, as that behavior can lead to unexpected corruptions of the
  associated VM," that a Broadcom employee stated in the community forums that
  renaming or deleting the NVRAM file is not endorsed by VMware engineering, and
  that ESXi 8.0 P09 (released May 27, 2026 as part of 8.0 Update 3j) now provides
  an officially supported PK remediation path: a guest OS reboot for vTPM-disabled
  VMs. Broadcom documents the `uefi.secureBoot.PK.resetOnce` VMX method for
  Linux/non-Windows vTPM-enabled VMs, while vTPM-enabled Windows VMs should wait
  for the planned capsule-based automated solution per KB 423893.
- The notice explains that on P09+ hosts, when guest credentials are supplied, the
  script's smart pre-check can verify the 2023 KEK is already present in NVRAM and
  skips the rename for that VM, so there is no unnecessary rename on VMs already
  remediated via the official path. In no-credential hypervisor-only mode (which
  v1.7.7 made possible by making `-GuestCredential` optional) the script cannot
  inspect guest certificate state, so `-SkipNVRAMRename` should be used for any VM
  already remediated through the official P09 path. The notice also reiterates the
  rollback options (`-Rollback`, `-RetainSnapshots`, `-SkipNVRAMRename`) for using
  the script with judgment and at your own risk.

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
