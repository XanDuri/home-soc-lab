# Network Architecture

## Design goals

1. **Isolation** — the lab must never touch the internet, so attacks can be run
   safely and traffic stays clean for analysis.
2. **Realism** — the topology mirrors a small corporate network (a domain
   controller, a workstation, and a security monitoring server).
3. **Reachability for the analyst** — the SIEM dashboard must be usable from the
   host, without giving the lab machines internet access.

## Two networks

| Network | VirtualBox type | Subnet | Purpose |
| --- | --- | --- | --- |
| `lab-net` | Internal Network | `192.168.56.0/24` | All lab traffic (attacks + logs). No internet. |
| host-only | Host-Only Adapter | `192.168.57.0/24` | Dashboard access from the host only. |

The **lab network** (`192.168.56.0/24`) is a VirtualBox *Internal Network*. Machines
on it can talk to each other but have **no route to the host or the internet** —
ideal for detonating attacks.

The **host-only network** (`192.168.57.0/24`) exists solely so the analyst can
open the Wazuh dashboard in a browser on the host. Only the Wazuh server has a
second interface on this network.

## IP addressing plan

Static addressing is used throughout (no DHCP) so detection rules can rely on
stable IPs and the topology is predictable — as it would be in an enterprise.

| Host | lab-net (`56.x`) | host-only (`57.x`) |
| --- | --- | --- |
| DC01 | `192.168.56.10` | — |
| WAZUH | `192.168.56.11` | `192.168.57.11` |
| WS01 | `192.168.56.20` | — |
| KALI | `192.168.56.100` | — |
| Host (Windows 11) | — | `192.168.57.1` |

## DNS

DC01 is the authoritative DNS server for `corp.lab`. Every domain member
(WS01) points its DNS at `192.168.56.10` so it can locate domain services. This
is what allows WS01 to join and authenticate against the domain.

## Isolation summary

- Lab machines: **Internal Network only** → no internet, no host access.
- Wazuh: Internal Network **+** host-only (dashboard) → still no internet.
- Kali: Internal Network only → fully contained attacker.
- Internet is enabled **temporarily** on a machine only when installing software
  (e.g. an agent), then disabled again.
