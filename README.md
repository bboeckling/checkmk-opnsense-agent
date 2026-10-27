# OPNsense Checkmk agent

This working version adds CARP-aware WireGuard monitoring, Kea DHCP and FRR BGP monitoring,
and regression fixes to the upstream 1.2.16 agent. Local version: **1.2.17**.
It has portable regression tests; installation and a real failover still require
validation on OPNsense. The monitoring checks do not change VPN/DHCP settings.

## WireGuard with CARP

The agent reads enabled WireGuard instances and their assigned enabled peers
from `/conf/config.xml`. Each instance's `carp_depend_on` is resolved to the
specific virtual IP and its live **interface + VHID** from `ifconfig -v`.
Both current UUID references and older VIP-address references are supported.
A different VIP being MASTER does not suppress a tunnel failure.

| Situation | Checkmk state |
| --- | --- |
| Dependent VIP is BACKUP | OK: tunnel intentionally inactive |
| VIP becomes MASTER; waiting for a new handshake | WARN during the configurable grace period |
| MASTER with a fresh handshake | OK |
| MASTER without a new handshake after the grace period | CRIT |
| Missing/unresolvable VIP or CARP INIT | UNKNOWN |
| Instance without a CARP dependency | Normal handshake monitoring |

The same service remains visible on both cluster members, including while a
tunnel is intentionally inactive. Its default name remains `WireGuard Client:
<peer name>`. If a peer belongs to multiple enabled instances, the instance name
is added to distinguish their services. Byte rates are tracked per interface/peer.

Optional settings in `/usr/local/etc/checkmk.conf`, in seconds:

```text
wireguard_handshake_max_age: 300
wireguard_failover_grace: 120
```

The grace period starts when the running agent **observes** a transition to
MASTER. It requires a handshake timestamp at or after that transition; a recent
handshake from before takeover is insufficient. Transition memory lives in the
agent process. A restart or separate `--debug` invocation cannot reconstruct an
earlier takeover: on first observing MASTER, normal handshake validation applies
immediately. A role change entirely between polls cannot be reconstructed.

WireGuard handshakes require traffic or persistent keepalives. For continuously
monitored site-to-site tunnels, configure appropriate keepalives in OPNsense.
The agent sends no probes and changes no tunnel settings. A fresh handshake
confirms a peer handshake, not reachability of every network behind it.

## Kea DHCP

Enabled Kea DHCPv4/v6 services are detected from the OPNsense configuration.
The agent uses `/var/run/kea/kea4-ctrl-socket` and
`/var/run/kea/kea6-ctrl-socket`, with the read-only commands `status-get`,
`statistic-get-all`, and `config-get`. No additional listening port is required.

Discover these new local services in Checkmk after installation:

- `Kea DHCPv4` / `Kea DHCPv6`: runtime, DHCP socket state, HA role/state.
  A healthy HA standby is OK. Transitional states or an unreachable HA partner
  produce WARN; terminated HA or failed DHCP sockets produce CRIT.
  Missing configured HA status produces UNKNOWN.
- `Kea DHCPv4 Pool ...`: combined address pool utilization per subnet.
- `Kea DHCPv6 Pool ...`: separate subnet totals for addresses and delegated prefixes.
- `Kea DHCPv4 Statistics` / `Kea DHCPv6 Statistics`: collection status.
  Failed queries produce UNKNOWN instead of invented zero counts.

Pool utilization warns at **80%** and becomes critical at **90%**. Metrics include
`used`, `total`, `declined`, and `usage`. Kea includes declined addresses in its
assigned count, so they are not counted twice. These are runtime statistics,
rather than a second interpretation of CSV lease files. Multiple ranges within
a subnet are aggregated. Individual client leases and host-reservation capacity
adjustments are not provided.

ISC DHCP monitoring is retained. Dnsmasq lease monitoring is not included.
Kea HA is evaluated using Kea's own state, independently of CARP.

## FRR BGP

When FRR and BGP are enabled in the OPNsense configuration, the agent reads
`vtysh -c 'show bgp vrf all summary json'` with a five-second timeout. It never
modifies routing configuration. BGP is checked on **both** cluster nodes,
independently of CARP or WireGuard's standby handling.

The `BGP FRR` service summarizes session health. Each neighbor/address-family/VRF
has a separate `BGP <vrf> <family> <neighbor>` service:

- Established: OK, including sessions with zero received prefixes.
- Idle, Active, or other non-established states: CRIT, including administrative shutdown.
- Configured enabled neighbors missing from the runtime summary: CRIT.
- Established with FRR's missing eBGP policy indication: WARN.
- Query timeout or invalid JSON/schema: UNKNOWN; known/configured peer services remain visible.
- Failed vtysh command or missing executable: CRIT.

Metrics include received/sent prefixes and messages, session uptime, and dropped
connections where FRR reports them. Disabled OPNsense neighbors are omitted.
The default VRF's expected IPv4/IPv6 unicast neighbors are checked against XML
configuration, including a missing address family. Runtime neighbors in other
VRFs/address families are discovered, but manually configured missing neighbors
outside the OPNsense XML model cannot be inferred. Route reachability, BFD, and
per-neighbor minimum-prefix policies are not checked in this version.

## Fork workflow

The maintained fork is `bboeckling/checkmk-opnsense-agent`; `origin` points to it.
`upstream` points to the original `bashclub/checkmk-opnsense-agent` repository.
Development is on `codex/ha-monitoring-fixes`. Run the regression tests and validate
on OPNsense before merging it into the fork's default branch or tagging a release.
The original author's BSD license header is retained.

```sh
git fetch upstream
git push -u origin codex/ha-monitoring-fixes
```

## Install this local version

Copy the modified file from this checkout to each OPNsense, for example:

```sh
scp opnsense_checkmk_agent.py root@FIREWALL:/tmp/opnsense_checkmk_agent.py
```

On OPNsense, back up an existing installation and install:

```sh
test ! -f /usr/local/etc/rc.syshook.d/start/99-checkmk_agent || cp -p /usr/local/etc/rc.syshook.d/start/99-checkmk_agent /root/checkmk_agent.previous
install -m 0755 /tmp/opnsense_checkmk_agent.py /usr/local/etc/rc.syshook.d/start/99-checkmk_agent
```

Example `/usr/local/etc/checkmk.conf` (protect with permissions `0600`):

```text
onlyfrom: 192.0.2.10
encrypt: REPLACE_WITH_A_LONG_RANDOM_SECRET
wireguard_handshake_max_age: 300
wireguard_failover_grace: 120
```

Allow TCP port 6556 only from the Checkmk server in the firewall. IPv4-mapped
IPv6 addresses are normalized for `onlyfrom` and tenant matching. Encryption
uses the existing legacy Checkmk agent format; configure the corresponding mode
on the Checkmk server. It does not provide mutual TLS. Without `encrypt`, output
is plaintext. Help output masks secrets; `--configdebug` dumps the firewall
configuration and should not be shared.

The agent targets OPNsense/FreeBSD. Runtime dependencies are `requests`, `urllib3`,
`cryptography` (42+ for UTC certificate properties), `pyOpenSSL`, and Python
`unbound` bindings; `packaging` is used by `--update`. Use the OPNsense
package-managed Python environment. Portable tests require only Python's standard
library and do not validate the installed runtime dependencies.

Check output before starting or restarting:

```sh
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --debug
/usr/local/etc/rc.syshook.d/start/99-checkmk_agent --restart
```

Debug mode runs normal checks, including package-audit database refresh and
configured plugins. The built-in `--update` downloads upstream code: do not use
it for this modified checkout until these changes exist upstream, or it may
replace the CARP/Kea implementation. Updates validate syntax, keep a `.bak`, and
replace the file atomically, but do not merge local modifications.

## Validate on both firewalls

1. Capture debug output on MASTER and BACKUP. Confirm the expected Kea services
   and assigned WireGuard peers appear.
2. Discover services in Checkmk on both hosts. BACKUP WireGuard services should
   show the explicit standby message.
3. During an approved maintenance window, change the relevant CARP VIP's role.
   The old MASTER should report standby; the new MASTER should show WARN until a
   new handshake arrives, then OK. Service names should remain stable.
4. In a controlled test, leave a peer unavailable after takeover. It must become
   CRIT after the grace period. Restore it and confirm recovery.
5. Verify another CARP VIP being MASTER does not affect a BACKUP-dependent tunnel.
   Compare Kea pool totals and HA state with the UI.

No deployment or real failover is performed by the local tests.

## Regression tests

```sh
python -m unittest discover -s tests -v
```

Tests execute production definitions with mocked OS input without importing
FreeBSD libraries or running firewall commands. They cover CARP transitions,
handshake freshness, multiple peers, Kea v4/v6 and HA, control responses, inventory,
audit errors, tasks, restarts, updates, OpenVPN/IPsec configuration variants,
and BGP sessions, VRFs, address families, policy errors, and failed queries.

## Other fixes

- Inventory expiry, numeric configuration, and spool-file age limits.
- Audit/update information failures no longer produce false OK results.
- ACME expiry and renewal intervals use days consistently.
- OpenVPN single entries and MVC instances; IPsec Swanctl connections alongside legacy tunnels.
- Task changes, disabled/deleted tasks, errors, and short execution intervals.
- Query timeouts, cached worker cleanup, and PKCS#7 decryption padding.
- Restart without a PID cannot signal the process group; help masks secrets.

## References

- [OPNsense WireGuard instance model](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Wireguard/Server.xml)
- [OPNsense CARP-dependent WireGuard control](https://github.com/opnsense/core/blob/master/src/opnsense/scripts/wireguard/wg-service-control.php)
- [OPNsense Kea control socket](https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.php)
- [Kea management API](https://kea.readthedocs.io/en/latest/arm/ctrl-channel.html)
- [Kea allocation counters](https://kea.readthedocs.io/en/latest/umls.html)
- [OPNsense FRR BGP model](https://github.com/opnsense/plugins/blob/master/net/frr/src/opnsense/mvc/app/models/OPNsense/Quagga/BGP.xml)
- [FRR BGP commands](https://docs.frrouting.org/en/stable-10.5/bgp.html)
