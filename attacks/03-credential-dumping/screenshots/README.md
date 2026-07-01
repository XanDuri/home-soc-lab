# Screenshots for Scenario 03 — Credential Dumping (LSASS)

| File | What to capture |
| --- | --- |
| `01-lsass-dump.png` | WS01 PowerShell — rundll32/comsvcs MiniDump command + the 60 MB lsass.dmp file (dir output) |
| `02-sysmon-event10-raw.png` | Raw Sysmon Event 10 — SourceImage rundll32, TargetImage lsass, GrantedAccess 0x1FFFFF, comsvcs.dll in call trace |
| `03-wazuh-alert-100101.png` | Wazuh alert (rule 100101, level 12) showing rundll32.exe accessed LSASS memory |
| `04-rule-tuning.png` | (optional) Before/after tuning — the alert list showing FPs (VBoxService/svchost) before the baseline exclusion was added |
