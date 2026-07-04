# Screenshots for Scenario 05 — Event Log Clearing

| File | What to capture |
| --- | --- |
| `01-clear-logs-commands.png` | WS01 PowerShell — wevtutil cl Security and wevtutil cl System commands |
| `02-event-1102-104-raw.png` | Raw Event 1102 / 104 detail — the "log was cleared" record with the account |
| `03-wazuh-builtin-level5.png` | Wazuh built-in alerts 63103 + 63104 firing at level 5 |
| `04-custom-rule-100103.png` | The custom rule 100103 in local_rules.xml |
| `05-wazuh-alert-100103.png` | The custom alert 100103 (level 12) firing after re-clearing the logs |
