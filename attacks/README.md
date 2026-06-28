# Attack & Detection Scenarios

Each scenario is documented the same way, so the repo reads like a SOC analyst's
casebook. Copy [`_TEMPLATE.md`](./_TEMPLATE.md) into a new folder for each one.

## Scenario index

| # | Scenario | MITRE ATT&CK | Folder |
| --- | --- | --- | --- |
| 01 | RDP / SMB brute force | T1110 | `01-brute-force/` |
| 02 | Kerberoasting | T1558.003 | `02-kerberoasting/` |
| 03 | Credential dumping (Mimikatz) | T1003 | `03-credential-dumping/` |
| 04 | Defender tampering | T1562.001 | `04-defender-tampering/` |
| 05 | Event log clearing | T1070.001 | `05-log-clearing/` |
| 06 | Scheduled task persistence | T1053.005 | `06-scheduled-task/` |
