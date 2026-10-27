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

- **Kea DHCPv4/v6:** service and HA status, address/prefix pool utilization (WARN 80%, CRIT 90%).
- **FRR BGP:** neighbor state, prefix counters and policy warnings, checked independently on both firewalls.
- **WireGuard with CARP:** intentional standby is OK; takeover requires a new handshake after a configurable grace period (default 120 seconds). Traffic counters are separated per peer.
- **Compatibility and reliability:** OpenVPN instances, IPsec Connections, and fixes for inventory, audit results, tasks, certificates, timeouts, restarts and updates.

The built-in `--update` still downloads upstream code and can overwrite these additions.

## Disclaimer

This is a personal, AI-assisted development based on the original project, not an official release by its authors. Changes have automated regression tests but still require validation on your own OPNsense systems, including real failover tests. Use at your own risk.
