# Screenshots for Scenario 01

Drop the following PNG files here:

| File | What to capture |
| --- | --- |
| `01-hydra-attack.png` | Kali terminal — full hydra run showing the 8 attempts and the `login: jan.kowalski password: Password123` line |
| `02-wazuh-failed-logons.png` | Wazuh Threat Hunting — list of rule 60122 + 60204 events on WS01 |
| `03-wazuh-successful-logon.png` | Wazuh alert for rule 92657 (successful remote logon / possible pass-the-hash) |
| `04-wazuh-alert-detail.png` | Expanded 60204 alert showing raw event detail (eventID 4625, user, source IP) |
