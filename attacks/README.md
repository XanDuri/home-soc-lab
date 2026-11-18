# Attack & Detection Scenarios

Each scenario is documented the same way, so the repo reads like a SOC analyst's
casebook. Copy [`_TEMPLATE.md`](./_TEMPLATE.md) into a new folder for each one.

## Scenario index

| # | Scenario | MITRE ATT&CK | Folder |
| --- | --- | --- | --- |
| 01 | RDP brute force | T1110.001 | [`01-brute-force/`](./01-brute-force) |
| 02 | Kerberoasting | T1558.003 | [`02-kerberoasting/`](./02-kerberoasting) |
| 03 | Credential dumping (LSASS via comsvcs.dll) | T1003.001 | [`03-credential-dumping/`](./03-credential-dumping) |
| 04 | Defender tampering | T1562.001 | [`04-defender-tampering/`](./04-defender-tampering) |
| 05 | Event log clearing | T1070.001 | [`05-log-clearing/`](./05-log-clearing) |
| 06 | Scheduled task persistence | T1053.005 | [`06-scheduled-task/`](./06-scheduled-task) |

The custom detection rules for all scenarios live in [`/wazuh-rules/local_rules.xml`](../wazuh-rules/local_rules.xml).
