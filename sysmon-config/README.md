# Sysmon configuration

`sysmon-lsass-processaccess.xml` is the fragment that makes **Sysmon Event ID 10
(ProcessAccess)** visible for `lsass.exe` — required for
[Scenario 03](../attacks/03-credential-dumping).

The Wazuh agent on WS01 collects the Sysmon channel via `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
