# OPNsense Checkmk agent

Personal fork of [bashclub/checkmk-opnsense-agent](https://github.com/bashclub/checkmk-opnsense-agent).

## How to install

SSH into your OPNsense:

```sh
fetch -o /usr/local/etc/rc.syshook.d/start/99-checkmk_agent https://raw.githubusercontent.com/bboeckling/checkmk-opnsense-agent/main/opnsense_checkmk_agent.py
chmod +x /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```

Ensure you create a packet filter rule to allow connections from your checkmk server to the firewall on port 6556.

The original installation steps are retained; the download URL points to this fork.

## Features

| From the original agent | Coverage |
| --- | --- |
| System and hardware | CPU, RAM, uptime, processes, kernel, network interfaces/counters, TCP, NTP, SSH, filesystems, ZFS, temperatures, SMART, IPMI and APC UPS |
| OPNsense | Firmware, business licence, services, package audit, gateways and CARP |
| VPN and services | OpenVPN, IPsec, WireGuard, ISC DHCP, Unbound, Squid, Nginx, HAProxy and ACME certificates |
| Agent and extensions | Inventory, labels, local checks, plugins, spool files, caching, piggyback, Nmap/domain/blocklist tasks, Zabbix output, IP allowlist, encryption and tenants |

**Added or improved in this fork:**

- **Kea DHCPv4/v6:** service and HA status, address/prefix pool utilization (WARN 80%, CRIT 90%), excluding reservations outside the pools. Missing or inconsistent counters trigger a bounded, paged lease lookup; failed lookups produce UNKNOWN.
- **FRR BGP:** neighbor state, prefix counters and policy warnings; automatically respects FRR's CARP failover setting. Intentional standby is OK; takeover has a configurable grace period.
- **WireGuard with CARP:** peers and interfaces recognize intentional standby; takeover requires an active interface and a new handshake. Traffic counters are separated per peer/interface.
- **Compatibility and reliability:** OpenVPN instances, IPsec Connections, and fixes for inventory, audit results, tasks, certificates, timeouts, restarts and updates.

The built-in `--update` still downloads upstream code and can overwrite these additions.

## CARP-aware monitoring

FRR uses the OPNsense plugin's CARP setting automatically. With that setting off,
BGP remains monitored on both nodes. Mixed or unknown CARP roles produce UNKNOWN.
For a custom script that stops FRR on standby, declare its dependency in
`/usr/local/etc/checkmk.conf`: `bgp_carp_depend_on: all` (all CARP VIPs), or a
specific VIP address/UUID. `off` explicitly disables this behavior.
`bgp_failover_grace` and `wireguard_failover_grace` default to 120 seconds, starting
when the running agent observes takeover; failures during startup produce WARN.

CARP-dependent WireGuard interfaces now have local services named
`WireGuard Interface: <name> (wgN)` instead of standard interface services.
After updating, run Checkmk service discovery, accept the replacements, and
remove the vanished old services. Review other interface assignments during
discovery because statgrab interface indexes can shift. The new services record
their own traffic history; the actual interface state remains visible even on
BACKUP. WireGuard instances without CARP dependencies keep their standard checks.
These checks only observe status and do not start/stop FRR or change interfaces.

## Disclaimer

This is a personal, AI-assisted development based on the original project, not an official release by its authors. Changes have automated regression tests but still require validation on your own OPNsense systems, including real failover tests. Use at your own risk.
