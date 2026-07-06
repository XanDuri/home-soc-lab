# Screenshots for Scenario 06 — Scheduled Task Persistence

| File | What to capture |
| --- | --- |
| `01-schtasks-create.png` | WS01 PowerShell — schtasks /create command + schtasks /query showing task Ready |
| `02-event-4698-raw.png` | Raw Event 4698 — the task XML (BootTrigger, powershell.exe, SYSTEM S-1-5-18) |
| `03-wazuh-builtin-level4.png` | Wazuh built-in alert 60228 firing at level 4 |
| `04-custom-rule-100104.png` | The custom rule 100104 in local_rules.xml |
| `05-wazuh-alert-100104.png` | The custom alert 100104 (level 12) for the suspicious task |
