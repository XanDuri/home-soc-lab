# Lab Setup

High-level record of how each machine in the lab was built. Detailed
step-by-step notes and screenshots live alongside each section.

## 1. DC01 — Domain Controller

- Installed **Windows Server 2022 Standard (Desktop Experience)** from the
  evaluation ISO.
- Set a static IP (`192.168.56.10`) on the internal adapter, with DNS pointing
  to itself.
- Renamed the machine to `DC01`.
- Installed the **Active Directory Domain Services** role and promoted the server
  to a Domain Controller, creating a new forest: **`corp.lab`** (NetBIOS `CORP`).
- Created test accounts:
  - `jan.kowalski` — standard user
  - `svc_sql` — service account with an SPN registered (target for Kerberoasting)
  - `admin.test` — member of Domain Admins (high-value target)

## 2. WAZUH — SIEM

- Imported the official **Wazuh 4.14.5 OVA**.
- Configured two interfaces:
  - `eth0` → host-only (`192.168.57.11`) for dashboard access
  - `eth1` → internal lab-net (`192.168.56.11`) for log collection
- Made the network configuration persistent and verified the dashboard
  auto-starts after reboot at `https://192.168.57.11`.

## 3. WS01 — Workstation

- Installed **Windows 10 Pro 22H2** (Pro is required to join a domain).
- Created a local account during OOBE, then set a static IP (`192.168.56.20`)
  with DNS pointing at DC01 (`192.168.56.10`).
- **Joined the machine to the `corp.lab` domain** and confirmed domain logon
  with `CORP\jan.kowalski`.

## 4. KALI — Attacker

- Imported the official **Kali Linux 2026.1** VirtualBox image.
- Connected to the internal lab-net only (no internet) with a static IP
  (`192.168.56.100`).
- Verified offensive tooling: `nmap`, `hydra`, `netexec`, `impacket`,
  `bloodhound`.

## Snapshots

A clean snapshot was taken of every machine after its baseline configuration, so
any scenario that damages a host can be rolled back in seconds:

- `dc01-baseline-with-users`
- `wazuh-configured`
- `ws01-domain-joined`
- `kali-configured`
