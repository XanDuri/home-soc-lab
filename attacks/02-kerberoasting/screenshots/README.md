# Screenshots for Scenario 02 — Kerberoasting

| File | What to capture |
| --- | --- |
| `01-getuserspns-attack.png` | Kali — impacket-GetUserSPNs returning svc_sql SPN + the $krb5tgs$ hash |
| `02-john-crack.png` | Kali — John the Ripper cracking the hash, showing `SummerSql2024` |
| `03-hashcat-crack-1.png` | Kali — hashcat cracking (part 1 of the long output) |
| `04-hashcat-crack-2.png` | Kali — hashcat cracking (part 2), ending with `Status: Cracked` |
| `05-event-4769-raw.png` | Raw Event 4769 (DC01 Event Viewer or Wazuh detail) — ServiceName svc_sql, EncryptionType 0x17, source 192.168.56.100 |
| `06-wazuh-custom-alert.png` | Wazuh alert list — level 12 hits from custom rule 100100 |
