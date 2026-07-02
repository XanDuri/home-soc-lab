# Screenshots for Scenario 04 — Defender Tampering

| File | What to capture |
| --- | --- |
| `01-tampering-commands.png` | WS01 PowerShell — Set-MpPreference -Disable... and Add-MpPreference -ExclusionPath commands |
| `02-defender-5007-raw.png` | Raw Event 5007 in Defender Operational log — exclusion path added, "unexpected event... may be malware" warning |
| `03-wazuh-alert-100102.png` | Wazuh alert (custom rule 100102, level 12) — Defender tampering |
| `04-custom-rules.png` | (optional) local_rules.xml showing all three custom rules (100100, 100101, 100102) |
