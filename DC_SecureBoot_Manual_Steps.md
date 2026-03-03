# Domain Controller Secure Boot 2023 Certificate Remediation
## Manual Procedure for Domain Controllers

---

## Overview

Domain controllers require manual handling due to UAC restrictions that prevent
`Invoke-VMScript` from running elevated commands. The process is identical for
both DCs but must be performed **sequentially** — complete and verify DC1
entirely before touching DC2 (the PDC Emulator holder).

**Order of operations:**
1. **DC1** (secondary / no FSMO roles) — lower risk, process first
2. **DC2** (PDC Emulator holder) — after DC1 is confirmed healthy, transfer PDC Emulator role first

**Time required per DC:** Approximately 30–45 minutes including reboots.

> Substitute your actual DC hostnames for `DC1` and `DC2` throughout this guide.

**Prerequisites:**
- ESXi host must be on **8.0.2 or later** — earlier versions will not regenerate NVRAM with 2023 certificates
- VM hardware version must be **13 or later** — required for EFI/Secure Boot support
- **VMware Tools must be installed and running** on the DC — required for `Invoke-VMScript` to verify NVRAM cert presence after power-on. Check status in vSphere Client or with PowerCLI:
  ```powershell
  (Get-VM "DC1").Guest.ExtensionData.ToolsStatus  # Expected: toolsOk
  ```

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

## Phase 1 — DC1 (Secondary DC / No FSMO Roles)

### Step 1 — Take snapshot

Run from your admin workstation PowerCLI session:

```powershell
$vm = Get-VM -Name "DC1"
New-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix" `
    -Description "Pre Secure Boot 2023 cert fix - manual" `
    -Memory:$false -Quiesce:$false -Confirm:$false
```

Verify the snapshot appears in vSphere before continuing.

### Step 2 — Rename NVRAM file

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

$ds        = Get-Datastore -Name $dsName
$dsBrowser = Get-View $ds.ExtensionData.Browser
$spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$spec.MatchPattern = "*.nvram"
$results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)
$nvramFile = $results.File | Where-Object { $_.Path -notmatch "_old" } | Select-Object -First 1

$oldPath = "[$dsName] $vmDir/$($nvramFile.Path)"
$newPath = "[$dsName] $vmDir/$($nvramFile.Path -replace '\.nvram$', '.nvram_old')"

$dcRef = (Get-Datacenter | Select-Object -First 1 | Get-View).MoRef
$fm    = Get-View (Get-View ServiceInstance).Content.FileManager
$task  = $fm.MoveDatastoreFile_Task($oldPath, $dcRef, $newPath, $dcRef, $true)

# Wait for task to complete
do { Start-Sleep -Seconds 2; $t = Get-View $task } while ($t.Info.State -notin @("success","error"))

if ($t.Info.State -eq "success") { Write-Host "NVRAM renamed successfully." -ForegroundColor Green }
else { Write-Warning "NVRAM rename failed: $($t.Info.Error.LocalizedMessage)" }
```

**Stop here if NVRAM rename failed.** Do not power on until it succeeds.

### Step 3 — Power on and verify 2023 certs in new NVRAM

```powershell
Start-VM -VM $vm
```

Wait 2–3 minutes for the DC to fully boot and AD services to start, then verify:

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
- Stop — do not proceed with registry changes
- Check whether the NVRAM rename was successful on the datastore
- Verify the ESXi host version supports NVRAM regeneration (requires ESXi 8.0.2 or later)
- Revert to the snapshot and investigate before retrying

### Step 4 — Apply registry fix directly on DC1

RDP or console into **DC1**. Open PowerShell **as Administrator**
(right-click → Run as Administrator). Run the following:

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

# Clear any stale state from previous failed attempts
if (Test-Path $svcPath) {
    Remove-Item -Path $svcPath -Recurse -Force
    Write-Host "Stale Servicing subkey cleared."
}

# Set AvailableUpdates
Set-ItemProperty -Path $regPath -Name "AvailableUpdates" -Value 0x5944 -Type DWord -Force
Write-Host "AvailableUpdates set: 0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates"))"

# Trigger update task immediately rather than waiting up to 12 hours
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

# Report state after task runs
$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
# Expected value at this point: 0x4100 (certs applied, boot manager reboot pending)
# or 0x4000 (fully complete if boot manager was already updated)
```

### Step 5 — Reboot DC1

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

### Step 6 — Run task again after reboot

Log back into DC1 via RDP or console, elevated PowerShell:

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates: 0x$("{0:X4}" -f $val)"
# Expected: 0x4000 (fully complete)
```

### Step 7 — Verify success on DC1

Still in the elevated PowerShell session on DC1:

```powershell
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
Write-Host "Servicing Status : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
Write-Host "KEK 2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023')"
Write-Host "DB  2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023')"
```

**Expected output:**
```
Servicing Status : Updated
KEK 2023 present : True
DB  2023 present : True
```

If status shows `InProgress` rather than `Updated`, allow 30 minutes and check
again. The task runs every 12 hours — trigger it manually if needed.

### Step 8 — Verify DC health after reboot

From admin workstation:

```powershell
repadmin /replsummary
dcdiag /test:replications
```

Confirm replication is healthy before proceeding to DC2.

### Step 9 — Retain snapshot for validation period

Leave the snapshot in place for several days while monitoring DC1. When
satisfied there are no issues, remove it from your admin workstation:

```powershell
$snap = Get-Snapshot -VM (Get-VM "DC1") -Name "Pre-SecureBoot-Fix"
Remove-Snapshot -Snapshot $snap -Confirm:$false
```

---

## Phase 2 — DC2 (PDC Emulator Holder)

**Do not start Phase 2 until DC1 is confirmed healthy and replication is clean.**

### Step 1 — Transfer PDC Emulator role to DC1

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

### Step 2 — Take snapshot

```powershell
$vm = Get-VM -Name "DC2"
New-Snapshot -VM $vm -Name "Pre-SecureBoot-Fix" `
    -Description "Pre Secure Boot 2023 cert fix - manual" `
    -Memory:$false -Quiesce:$false -Confirm:$false
```

### Step 3 — Rename NVRAM file

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

$ds        = Get-Datastore -Name $dsName
$dsBrowser = Get-View $ds.ExtensionData.Browser
$spec      = New-Object VMware.Vim.HostDatastoreBrowserSearchSpec
$spec.MatchPattern = "*.nvram"
$results   = $dsBrowser.SearchDatastoreSubFolders("[$dsName] $vmDir", $spec)
$nvramFile = $results.File | Where-Object { $_.Path -notmatch "_old" } | Select-Object -First 1

$oldPath = "[$dsName] $vmDir/$($nvramFile.Path)"
$newPath = "[$dsName] $vmDir/$($nvramFile.Path -replace '\.nvram$', '.nvram_old')"

$dcRef = (Get-Datacenter | Select-Object -First 1 | Get-View).MoRef
$fm    = Get-View (Get-View ServiceInstance).Content.FileManager
$task  = $fm.MoveDatastoreFile_Task($oldPath, $dcRef, $newPath, $dcRef, $true)

do { Start-Sleep -Seconds 2; $t = Get-View $task } while ($t.Info.State -notin @("success","error"))

if ($t.Info.State -eq "success") { Write-Host "NVRAM renamed successfully." -ForegroundColor Green }
else { Write-Warning "NVRAM rename failed: $($t.Info.Error.LocalizedMessage)" }
```

### Step 4 — Power on and verify 2023 certs in new NVRAM

```powershell
Start-VM -VM $vm
```

Wait 2–3 minutes, then verify:

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

### Step 5 — Apply registry fix on DC2

RDP or console into **DC2**, elevated PowerShell:

```powershell
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
$svcPath = "$regPath\Servicing"

if (Test-Path $svcPath) {
    Remove-Item -Path $svcPath -Recurse -Force
    Write-Host "Stale Servicing subkey cleared."
}

Set-ItemProperty -Path $regPath -Name "AvailableUpdates" -Value 0x5944 -Type DWord -Force
Write-Host "AvailableUpdates set: 0x$("{0:X4}" -f (Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates"))"

Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Write-Host "Task triggered - waiting 30 seconds..."
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue -Path $regPath -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates after task: 0x$("{0:X4}" -f $val)"
```

### Step 6 — Reboot DC2

```powershell
Restart-Computer -Force
```

### Step 7 — Run task again after reboot

Log back into DC2, elevated PowerShell:

```powershell
Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
Start-Sleep -Seconds 30

$val = Get-ItemPropertyValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" `
    -Name "AvailableUpdates" -EA SilentlyContinue
Write-Host "AvailableUpdates: 0x$("{0:X4}" -f $val)"
```

### Step 8 — Verify success on DC2

```powershell
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
Write-Host "Servicing Status : $((Get-ItemPropertyValue -Path $svcPath -Name 'UEFICA2023Status' -EA SilentlyContinue))"
Write-Host "KEK 2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes) -match 'Microsoft Corporation KEK 2K CA 2023')"
Write-Host "DB  2023 present : $([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)  -match 'Windows UEFI CA 2023')"
```

Expected:
```
Servicing Status : Updated
KEK 2023 present : True
DB  2023 present : True
```

### Step 9 — Transfer PDC Emulator back to DC2

```powershell
Move-ADDirectoryServerOperationMasterRole -Identity "DC2" `
    -OperationMasterRole PDCEmulator -Confirm:$false

# Verify
$pdcHolder = (Get-ADDomain).PDCEmulator
Write-Host "PDC Emulator returned to: $pdcHolder"
# Expected: DC2.yourdomain.com
```

### Step 10 — Final replication health check

```powershell
repadmin /replsummary
dcdiag /test:replications
```

### Step 11 — Retain snapshot for validation period

Leave the snapshot in place for several days, then remove when satisfied:

```powershell
$snap = Get-Snapshot -VM (Get-VM "DC2") -Name "Pre-SecureBoot-Fix"
Remove-Snapshot -Snapshot $snap -Confirm:$false
```

---

## Rollback Procedure

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
- [ ] Snapshot taken: Pre-SecureBoot-Fix
- [ ] NVRAM renamed on datastore
- [ ] Powered on — KEK 2023: True, DB 2023: True
- [ ] Registry fix applied (elevated PS directly on DC)
- [ ] First reboot completed
- [ ] Task triggered post-reboot
- [ ] Servicing Status: Updated, KEK: True, DB: True
- [ ] Replication health re-verified
- [ ] Snapshot removed after validation period

### DC2 (PDC Emulator Holder)
- [ ] DC1 confirmed healthy first
- [ ] Replication clean
- [ ] PDC Emulator transferred to DC1
- [ ] Snapshot taken: Pre-SecureBoot-Fix
- [ ] NVRAM renamed on datastore
- [ ] Powered on — KEK 2023: True, DB 2023: True
- [ ] Registry fix applied (elevated PS directly on DC)
- [ ] First reboot completed
- [ ] Task triggered post-reboot
- [ ] Servicing Status: Updated, KEK: True, DB: True
- [ ] PDC Emulator transferred back to DC2
- [ ] Replication health re-verified
- [ ] Snapshot removed after validation period
