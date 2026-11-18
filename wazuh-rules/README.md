# Custom Wazuh rules

`local_rules.xml` contains the five custom detection rules written for this lab.

**Deploy:** copy to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager,
test with `/var/ossec/bin/wazuh-logtest`, then `sudo systemctl restart wazuh-manager`.

| Rule | Level | Parent | Detects | MITRE | Scenario |
| --- | --- | --- | --- | --- | --- |
| 100100 | 12 | `if_sid` 60103 | Event 4769 with RC4 (0x17) — Kerberoasting | T1558.003 | [02](../attacks/02-kerberoasting) |
| 100101 | 12 | `if_group` sysmon_event_10 | Unexpected process accessing `lsass.exe` | T1003.001 | [03](../attacks/03-credential-dumping) |
| 100102 | 12 | `if_sid` 62154 | Defender protection disabled / exclusion added | T1562.001 | [04](../attacks/04-defender-tampering) |
| 100103 | 12 | `if_sid` 63103, 63104 | Security / System event log cleared | T1070.001 | [05](../attacks/05-log-clearing) |
| 100104 | 12 | `if_sid` 60228 | Scheduled task with script host / SYSTEM / boot trigger | T1053.005 | [06](../attacks/06-scheduled-task) |

Scenario 01 (RDP brute force) is detected by built-in rules 60122, 60204 and 92657.

## Known limitations and next improvements

These rules were validated in a small lab. Before production use I would:

- **100100** — exclude `krbtgt` and computer accounts (`serviceName` ending in `$`)
  to cut noise from legacy RC4 clients; add a frequency rule (one user requesting
  many different SPNs) and a honeypot SPN account, since an attacker who requests
  AES tickets bypasses the RC4 condition.
- **100101** — match the **full path** of excluded processes
  (e.g. `C:\Windows\System32\svchost.exe`), not just the file name, so a renamed
  tool in another folder can't hide behind the exclusion; also check
  `GrantedAccess` values typical of dumping (e.g. `0x1FFFFF`, `0x1010`).
- **100104** — `S-1-5-18` alone matches many legitimate updater tasks; require a
  **combination** of hallmarks (e.g. SYSTEM + script host) or exclude known tasks.
- **Brute force** — add a password-spraying rule: many *different* accounts
  failing from one source IP, plus account lockouts (Event 4740).
