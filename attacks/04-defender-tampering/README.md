# Scenario 04 — Defender Tampering (Impair Defenses) → Custom Detection Rule

> **MITRE ATT&CK:** [T1562.001 — Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
> **Tactic:** Defense Evasion
> **Target:** WS01 (192.168.56.20) — Windows 10 Pro
> **Detection stack:** Windows Defender Operational log + Wazuh custom rule

---

## 1. Summary

Before (or after) running their real payload, attackers frequently **disable
security tooling** — turning off the antivirus, adding folder exclusions so their
malware isn't scanned, or disabling real-time protection. This is "Impair
Defenses", and it's a high-signal event: **there is almost no legitimate reason**
for a normal user or process to disable Windows Defender's protections.

This scenario performs several Defender-tampering actions and detects them. It
also demonstrates a key SIEM lesson: the relevant log channel had to be
**explicitly added to the Wazuh agent**, and while Wazuh has a built-in low-level
rule for Defender config changes, a **custom rule** raises the severity for the
specifically suspicious changes.

---

## 2. Attack (from WS01, as local admin)

Several common tampering techniques, each of which changes a Defender security
setting:

```powershell
# Disable real-time protection
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable behaviour monitoring
Set-MpPreference -DisableBehaviorMonitoring $true

# Add a folder exclusion (so malware placed there is never scanned)
Add-MpPreference -ExclusionPath "C:\Temp"
```

Each of these is a classic adversary move — the **folder exclusion** in particular
is a favourite: drop the payload in an excluded path and Defender ignores it.

> 📸 **SCREENSHOT 1 — `screenshots/01-tampering-commands.png`**
> WS01 PowerShell — the `Set-MpPreference -Disable...` and
> `Add-MpPreference -ExclusionPath` commands.

---

## 3. What it looks like in the logs

Every change is recorded in the **Windows Defender Operational log** as
**Event ID 5007** ("Antimalware platform configuration changed"). Windows itself
flags these as suspicious — the event text literally says the change is
*"unexpected and should be reviewed, as it may have been caused by malware."*

Example (adding the exclusion):

```
Event ID 5007 — Defender configuration changed
  Old value:
  New value: HKLM\...\Windows Defender\Exclusions\Paths\C:\Temp = 0x0
```

And disabling real-time protection / tamper protection produces further 5007 (and
5001) entries.

> 📸 **SCREENSHOT 2 — `screenshots/02-defender-5007-raw.png`**
> The raw Event 5007 in the Defender Operational log, showing the exclusion path
> added and the "unexpected event... may be malware" warning.

### Telemetry lesson — the channel had to be added to the agent

By default the Wazuh agent does **not** collect the Windows Defender channel, so
these events never reached the SIEM at first. The channel had to be added to the
agent's `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

After restarting the agent, the 5007 events started arriving. This is the same
lesson as the Sysmon scenario: **a SIEM only sees the log sources you tell the
agent to collect.**

---

## 4. Detection logic — custom Wazuh rule

Wazuh has a **built-in** rule (62154) that catches Defender config changes, but at
**level 5** (informational) — it fires on every change, including benign startup
noise. A custom rule raises the severity to **level 12** for the specifically
dangerous changes (disabling protection or adding an exclusion), and maps them to
MITRE. Stored in [`/wazuh-rules/local_rules.xml`](../../wazuh-rules/local_rules.xml):

```xml
<rule id="100102" level="12">
  <if_sid>62154</if_sid>
  <field name="win.system.message">Exclusions\\Paths|DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableAntiSpyware|TamperProtection</field>
  <description>Possible Defender tampering: a security setting was disabled or an exclusion was added</description>
  <mitre>
    <id>T1562.001</id>
  </mitre>
</rule>
```

It inherits from the built-in rule 62154 (`if_sid`) and only escalates when the
message contains a genuinely suspicious keyword — separating real tampering from
Defender's normal startup chatter.

The rule fired on the attack:

```
Rule 100102 (level 12):
Possible Defender tampering: a security setting was disabled or an exclusion was added
```

> 📸 **SCREENSHOT 3 — `screenshots/03-wazuh-alert-100102.png`**
> The Wazuh alert (custom rule 100102, level 12) for Defender tampering.

> 📸 **SCREENSHOT 4 — `screenshots/04-custom-rules.png`** *(optional)*
> The `local_rules.xml` file showing all three custom rules (100100 Kerberoasting,
> 100101 credential dumping, 100102 Defender tampering).

---

## 5. Incident report (SOC L1 view)

| Field | Value |
| --- | --- |
| **Incident ID** | INC-2026-004 |
| **Severity** | High |
| **Detection time** | 2026-07-02 ~07:36 UTC |
| **Affected asset** | WS01 (192.168.56.20) |
| **Actor** | CORP\Administrator (local admin session) |
| **Actions** | Real-time protection disabled; behaviour monitoring disabled; folder exclusion `C:\Temp` added |
| **Triggered rules** | 100102 (custom, level 12), 62154 (built-in, level 5) |
| **Indicators (IoCs)** | Event 5007; exclusion path `C:\Temp`; `DisableRealtimeMonitoring`; TamperProtection change |

**What happened:** Windows Defender protections were disabled and a folder
exclusion was added on WS01. There is no routine reason for this — it strongly
suggests an attacker preparing the host to run malware undetected.

**Recommended actions (L1 → L2):**

1. **Re-enable Defender** and remove the unauthorized exclusion immediately.
2. **Scan `C:\Temp`** (the excluded path) — it may contain a dropped payload.
3. Isolate WS01 and correlate with other activity on the host (this rarely happens
   alone — check for credential dumping, new processes, persistence).
4. Investigate how the actor gained the admin rights used to change Defender.
5. Consider enforcing **Tamper Protection via Intune/GPO** so it can't be toggled locally.

---

## 6. Lessons learned (defender's view)

- **Disabling AV is high-signal.** Alert on it aggressively — legitimate admins
  almost never disable Defender in day-to-day work.
- **Watch exclusions especially.** Adding a folder exclusion is a quiet, classic
  precursor to dropping malware; treat new exclusions as suspicious by default.
- **Enforce Tamper Protection centrally** (Intune / GPO) so it survives local
  admin attempts to turn it off.
- **Collect the right channel.** The Defender Operational log isn't collected by
  default — without adding it to the agent, this attack is invisible to the SIEM.
- **Tune severity, not just detection.** The built-in rule fired at level 5 and
  buried the signal in noise; the custom rule promotes the genuinely dangerous
  changes to level 12.

---

<p align="center"><sub>Part of <a href="../../README.md">home-soc-lab</a> — attack &amp; detection scenarios.</sub></p>
