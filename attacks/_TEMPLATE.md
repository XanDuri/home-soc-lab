# Scenario NN — <Attack name>

> **MITRE ATT&CK:** Txxxx — <technique name>
> **Tactic:** <e.g. Credential Access>
> **Target:** <e.g. DC01 / WS01>
> **Attacker:** KALI (192.168.56.100)

---

## 1. Summary

One or two sentences: what the attack does and why a SOC cares about it.

## 2. Attack (from Kali)

What the adversary runs, with the exact commands.

```bash
# example
hydra -l jan.kowalski -P wordlist.txt rdp://192.168.56.20
```

## 3. What it looks like in the logs

Which Windows Event IDs / Sysmon events / Wazuh alerts are generated.

- Event ID xxxx — <description>
- Wazuh rule xxxxx — <description>

*(Add screenshots of the Wazuh dashboard in `/screenshots`.)*

## 4. Detection logic

How the activity is detected. Include the custom Wazuh rule if one was written
(store the XML in `/wazuh-rules`).

```xml
<!-- example custom rule -->
<rule id="100001" level="10">
  <if_sid>...</if_sid>
  <description>Possible ... attack</description>
  <mitre><id>Txxxx</id></mitre>
</rule>
```

## 5. Incident report (SOC L1 view)

| Field | Value |
| --- | --- |
| **Severity** | Low / Medium / High |
| **Detection time** | YYYY-MM-DD HH:MM UTC |
| **Affected asset** | <hostname> |
| **Indicators (IoCs)** | <IPs, accounts, hashes...> |

**Recommended actions**

1. ...
2. ...

## 6. Lessons learned

What a defender should harden to prevent or reduce this attack.
