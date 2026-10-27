"""Portable regression tests: compile production definitions without platform imports.

The agent imports FreeBSD-only libraries and creates system directories at import
time. These tests execute the actual definitions via AST, with OS input mocked.
Run with: python -m unittest discover -s tests -v
"""
import ast
import copy
import glob
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
from socketserver import TCPServer, StreamRequestHandler
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from collections import Counter, defaultdict
from unittest.mock import Mock, patch
from xml.etree import ElementTree


SOURCE = Path(__file__).resolve().parents[1] / "opnsense_checkmk_agent.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
NAMES = {"as_list", "normalize_ip", "replace_agent", "etree_to_dict", "object_dict", "checkmk_checker",
         "checkmk_task", "checkmk_taskrunner", "checkmk_cached_process", "checkmk_server", "checkmk_handler"}
NS = dict(globals(), ELementTree=ElementTree, __VERSION__="test", LOCALDIR="/local",
          PLUGINSDIR="/plugins", SPOOLDIR="/spool", MK_CONFDIR="/etc", TASKDIR="/tasks",
          CHECKMK_CONFIG="/etc/checkmk.conf", MAX_SIMULATAN_THREADS=4, log=Mock())
NS["TASKFILE_REGEX"] = re.compile(r"^(service|type|interval|disabled|piggyback|tenant):\s*(.*?)(?:\s+#|$)", re.M)
exec(compile(ast.Module(body=[node for node in TREE.body if getattr(node, "name", "") in NAMES], type_ignores=[]), str(SOURCE), "exec"), NS)
Checker = NS["checkmk_checker"]


def checker(config=None):
    obj = Checker()
    obj._datastore = NS["object_dict"]()
    obj._ipaccess_log = {}
    obj._config_reader = lambda: copy.deepcopy(config or {})
    return obj


def wg_config():
    # XML fixture also exercises the single-item conversion used on OPNsense.
    root = ElementTree.fromstring('''<opnsense>
      <interfaces><wan><if>igb0</if></wan><lan><if>igb1</if></lan></interfaces>
      <virtualip><vip uuid="vip-wan"><interface>wan</interface><mode>carp</mode>
      <subnet>192.0.2.1</subnet><vhid>1</vhid></vip></virtualip>
      <OPNsense><wireguard><general><enabled>1</enabled></general>
        <client><clients><client uuid="peer-a"><enabled>1</enabled><name>Office</name>
          <pubkey>key-a</pubkey><tunneladdress>10.0.0.0/24</tunneladdress></client></clients></client>
        <server><servers><server uuid="server-a"><enabled>1</enabled><name>VPN</name>
          <instance>0</instance><carp_depend_on>vip-wan</carp_depend_on><peers>peer-a</peers>
        </server></servers></server>
      </wireguard></OPNsense></opnsense>''')
    return NS["etree_to_dict"](root)["opnsense"]


class WireGuardTests(unittest.TestCase):
    def setUp(self):
        self.config = wg_config()
        self.obj = checker(self.config)
        self.state = "BACKUP"
        self.handshake = 0
        self.clock = patch.object(time, "time", return_value=1000)
        self.now = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.obj._run_prog = self.run_prog

    def run_prog(self, command, **kwargs):
        if command[0] == "ifconfig":
            # Reusing VHID 1 on another interface must not select its MASTER.
            return ('igb0: flags=8843<UP,BROADCAST,RUNNING>\n'
                    f'\tcarp: {self.state} vhid 1 advbase 1 advskew 100\n'
                    'igb1: flags=8843<UP,BROADCAST,RUNNING>\n'
                    '\tcarp: MASTER vhid 1 advbase 1 advskew 0\n')
        return f'wg0\tkey-a\t(none)\t192.0.2.2:51820\t10.0.0.0/24\t{self.handshake}\t100\t200\t25\n'

    def output(self):
        return self.obj.checklocal_wireguard()[0]

    def test_backup_is_ok_with_stable_service_name(self):
        self.assertTrue(self.output().startswith('0 "WireGuard Client: Office"'))
        self.assertIn("intentionally inactive", self.output())

    def test_master_without_handshake_is_critical_on_first_observation(self):
        self.state = "MASTER"
        self.assertTrue(self.output().startswith("2 "))

    def test_failover_warns_then_requires_new_handshake(self):
        self.output()
        self.state = "MASTER"
        self.now.return_value = 1010
        self.handshake = 1005  # recent, but from BEFORE takeover
        self.assertTrue(self.output().startswith("1 "))
        self.now.return_value = 1131
        self.assertTrue(self.output().startswith("2 "))
        self.handshake = 1130
        self.assertTrue(self.output().startswith("0 "))

    def test_stale_handshake_is_critical(self):
        self.state, self.handshake = "MASTER", 699
        self.assertTrue(self.output().startswith("2 "))

    def test_unknown_or_init_carp_is_not_silently_ok(self):
        self.state = "INIT"
        self.assertTrue(self.output().startswith("3 "))
        self.config["virtualip"]["vip"]["@uuid"] = "missing"
        self.assertTrue(self.output().startswith("3 "))

    def test_legacy_vip_address_reference(self):
        self.config["OPNsense"]["wireguard"]["server"]["servers"]["server"]["carp_depend_on"] = "192.0.2.1"
        self.assertTrue(self.output().startswith("0 "))

    def test_disabled_server_or_peer_is_omitted(self):
        self.config["OPNsense"]["wireguard"]["server"]["servers"]["server"]["enabled"] = "0"
        self.assertEqual([], self.obj.checklocal_wireguard())
        self.config["OPNsense"]["wireguard"]["server"]["servers"]["server"]["enabled"] = "1"
        self.config["OPNsense"]["wireguard"]["client"]["clients"]["client"]["enabled"] = "0"
        self.assertEqual([], self.obj.checklocal_wireguard())

    def test_tunnel_without_carp_still_monitored(self):
        self.config["OPNsense"]["wireguard"]["server"]["servers"]["server"]["carp_depend_on"] = ""
        self.assertTrue(self.output().startswith("2 "))
        self.handshake = 999
        self.assertTrue(self.output().startswith("0 "))

    def test_second_failover_gets_new_grace_window(self):
        self.output()
        self.state = "MASTER"
        self.assertTrue(self.output().startswith("1 "))
        self.state = "BACKUP"
        self.output()
        self.now.return_value = 2000
        self.state = "MASTER"
        self.assertIn("120s remaining", self.output())

    def test_counters_are_separate_for_two_peers_on_one_interface(self):
        clients = self.config["OPNsense"]["wireguard"]["client"]["clients"]
        second = dict(clients["client"], **{"@uuid": "peer-b", "pubkey": "key-b", "name": "Other"})
        clients["client"] = [clients["client"], second]
        self.config["OPNsense"]["wireguard"]["server"]["servers"]["server"]["peers"] += ",peer-b"
        self.obj._get_traffic = Mock(return_value=(0, 0))
        self.obj.checklocal_wireguard()
        keys = [call.args[1] for call in self.obj._get_traffic.call_args_list]
        self.assertEqual([("wg0", "key-a"), ("wg0", "key-b")], keys)


class KeaTests(unittest.TestCase):
    def setUp(self):
        self.config = {"OPNsense": {"Kea": {"dhcp4": {"general": {"enabled": "1"}}}}}
        self.obj = checker(self.config)
        self.status = {"uptime": 123, "sockets": {"status": "ready"}}
        self.stats = {"subnet[7].total-addresses": [[100, "now"]],
                      "subnet[7].assigned-addresses": [[40, "now"]],
                      "subnet[7].declined-addresses": [[5, "now"]],
                      "subnet[7].pool[0].total-addresses": [[100, "now"]],
                      "subnet[7].pool[0].assigned-addresses": [[40, "now"]],
                      "subnet[7].pool[0].declined-addresses": [[5, "now"]]}
        self.live = {"Dhcp4": {"subnet4": [{"id": 7, "subnet": "192.0.2.0/24", "pools": [{"pool": "192.0.2.10-192.0.2.109"}]}]}}
        self.obj._kea_command = lambda path, cmd: {"status-get": self.status,
            "statistic-get-all": self.stats, "config-get": self.live}[cmd]

    def output(self):
        return self.obj.checklocal_kea()

    def test_enabled_service_and_pool(self):
        output = self.output()
        self.assertTrue(output[0].startswith('0 "Kea DHCPv4"'))
        self.assertIn("usage=40.00", output[1])  # declined is already included
        self.assertTrue(output[-1].startswith('0 "Kea DHCPv4 Statistics"'))

    def test_disabled_service_is_omitted(self):
        self.config["OPNsense"]["Kea"]["dhcp4"]["general"]["enabled"] = "0"
        self.assertEqual([], self.output())

    def test_thresholds(self):
        for assigned, state in ((79, 0), (80, 1), (90, 2), (100, 2)):
            with self.subTest(assigned=assigned):
                self.stats["subnet[7].pool[0].assigned-addresses"] = [[assigned, "now"]]
                self.assertTrue(self.output()[1].startswith(str(state) + " "))

    def test_unavailable_socket_is_critical(self):
        self.obj._kea_command = Mock(side_effect=TimeoutError)
        self.assertTrue(self.output()[0].startswith("2 "))

    def test_invalid_statistics_are_unknown(self):
        self.stats.clear()
        self.assertTrue(self.output()[1].startswith('3 "Kea DHCPv4 Pool'))
        self.assertTrue(self.output()[-1].startswith('3 "Kea DHCPv4 Statistics"'))

    def test_out_of_pool_reservations_do_not_inflate_utilization(self):
        # Reported production case: 58 subnet leases, only 15 pool addresses.
        self.stats.update({"subnet[7].total-addresses": [[15]],
                           "subnet[7].assigned-addresses": [[58]],
                           "subnet[7].pool[0].total-addresses": [[15]],
                           "subnet[7].pool[0].assigned-addresses": [[3]],
                           "subnet[7].pool[0].declined-addresses": [[0]]})
        output = self.output()[1]
        self.assertTrue(output.startswith("0 "))
        self.assertIn("used=3|total=15", output)
        self.assertIn("usage=20.00", output)
        self.assertNotIn("386.7", output)

    def test_reservation_only_subnet_is_not_reported_as_pool(self):
        self.live["Dhcp4"]["subnet4"][0]["pools"] = []
        self.assertFalse(any('"Kea DHCPv4 Pool ' in line for line in self.output()))

    def test_subnet_counters_are_not_used_when_pool_counters_missing(self):
        self.stats = {key: value for key, value in self.stats.items() if ".pool[" not in key}
        output = self.output()[1]
        self.assertTrue(output.startswith("3 "))
        self.assertNotIn("usage=", output)

    def test_multiple_ranges_with_same_default_id_counted_once(self):
        self.live["Dhcp4"]["subnet4"][0]["pools"].append({"pool": "192.0.2.150-192.0.2.199"})
        self.assertIn("used=40|total=100", self.output()[1])

    def test_distinct_pool_ids_are_aggregated(self):
        self.live["Dhcp4"]["subnet4"][0]["pools"].append({"pool": "192.0.2.150-192.0.2.199", "pool-id": 5})
        self.stats.update({"subnet[7].pool[5].total-addresses": [[50]],
                           "subnet[7].pool[5].assigned-addresses": [[20]],
                           "subnet[7].pool[5].declined-addresses": [[2]]})
        self.assertIn("used=60|total=150|declined=7", self.output()[1])

    def test_partial_pool_statistics_do_not_report_partial_total(self):
        self.live["Dhcp4"]["subnet4"][0]["pools"].append({"pool": "192.0.2.150-192.0.2.199", "pool-id": 5})
        self.assertTrue(self.output()[1].startswith("3 "))

    def test_inconsistent_pool_counters_are_unknown_not_clamped(self):
        for assigned, declined in ((101, 0), (-1, 0), (3, 5)):
            with self.subTest(assigned=assigned, declined=declined):
                self.stats["subnet[7].pool[0].assigned-addresses"] = [[assigned]]
                self.stats["subnet[7].pool[0].declined-addresses"] = [[declined]]
                output = self.output()[1]
                self.assertTrue(output.startswith("3 "))
                self.assertNotIn("usage=", output)

    def test_healthy_ha_standby_is_ok(self):
        self.status["high-availability"] = [{"ha-servers": {
            "local": {"role": "standby", "state": "hot-standby", "scopes": []},
            "remote": {"in-touch": True, "communication-interrupted": False}}}]
        self.assertTrue(self.output()[0].startswith("0 "))
        self.assertIn("standby/hot-standby", self.output()[0])
        self.status["high-availability"][0]["ha-servers"]["remote"]["communication-interrupted"] = True
        self.assertTrue(self.output()[0].startswith("1 "))

    def test_missing_configured_ha_is_unknown(self):
        self.config["OPNsense"]["Kea"]["dhcp4"]["ha"] = {"enabled": "1"}
        self.assertTrue(self.output()[0].startswith("3 "))

    def test_disabled_active_ha_service_is_critical(self):
        self.status["dhcp-state"] = {"globally-disabled": True}
        self.status["high-availability"] = [{"ha-servers": {
            "local": {"role": "primary", "state": "hot-standby", "scopes": ["primary"]}}}]
        self.assertTrue(self.output()[0].startswith("2 "))
        local = self.status["high-availability"][0]["ha-servers"]["local"]
        local.update(role="standby", scopes=[])
        self.assertTrue(self.output()[0].startswith("0 "))

    def test_failed_dhcp_sockets_are_critical(self):
        self.status["sockets"]["status"] = "failed"
        self.assertTrue(self.output()[0].startswith("2 "))

    def test_ipv6_address_and_prefix_pools(self):
        self.config["OPNsense"]["Kea"] = {"dhcp6": {"general": {"enabled": "1"}}}
        self.live = {"Dhcp6": {"subnet6": [{"id": 7, "subnet": "2001:db8::/64", "pools": [{}], "pd-pools": [{}]}]}}
        self.stats = {"subnet[7].total-nas": [[100]], "subnet[7].assigned-nas": [[30]],
                      "subnet[7].total-pds": [[10]], "subnet[7].assigned-pds": [[9]],
                      "subnet[7].pool[0].total-nas": [[100]], "subnet[7].pool[0].assigned-nas": [[30]],
                      "subnet[7].pd-pool[0].total-pds": [[10]], "subnet[7].pd-pool[0].assigned-pds": [[9]]}
        output = self.output()
        self.assertIn("usage=30.00", output[1])
        self.assertTrue(output[2].startswith("2 "))
        self.assertIn("pds", output[2])

    def test_control_channel_fragmented_json(self):
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        sock.recv.side_effect = [b'{"result":0,', b'"arguments":{"uptime":42}}']
        with patch.object(socket, "socket", return_value=sock), patch.object(socket, "AF_UNIX", 1, create=True):
            self.assertEqual({"uptime": 42}, Checker._kea_command("test", "status-get"))
        sock.sendall.assert_called_once_with(b'{"command": "status-get"}')

    def test_control_channel_rejects_failed_or_truncated_response(self):
        for chunks in ([b'{"result":1,"text":"failed"}'], [b'{"result":0', b'']):
            sock = Mock()
            sock.__enter__ = Mock(return_value=sock)
            sock.__exit__ = Mock(return_value=False)
            sock.recv.side_effect = chunks
            with patch.object(socket, "socket", return_value=sock), patch.object(socket, "AF_UNIX", 1, create=True):
                with self.assertRaises((ValueError, ConnectionError)):
                    Checker._kea_command("test", "status-get")


class BGPTests(unittest.TestCase):
    def setUp(self):
        self.neighbor = {"enabled": "1", "address": "192.0.2.2", "family": "ipv4", "description": "Transit"}
        self.config = {"OPNsense": {"quagga": {"general": {"enabled": "1"}, "bgp": {
            "enabled": "1", "neighbors": {"neighbor": self.neighbor}}}}}
        self.peer = {"state": "Established", "peerState": "OK", "remoteAs": 65002,
                     "pfxRcd": 10, "pfxSnt": 4, "msgRcvd": 100, "msgSent": 90,
                     "peerUptimeMsec": 123000, "connectionsDropped": 2}
        self.summary = {"default": {"ipv4Unicast": {"peers": {"192.0.2.2": self.peer}}}}
        self.obj = checker(self.config)
        self.command = patch.object(subprocess, "check_output", side_effect=lambda *args, **kwargs: json.dumps(self.summary))
        self.run_command = self.command.start()
        self.addCleanup(self.command.stop)

    def output(self):
        return self.obj.checklocal_bgp()

    def test_established_session_and_metrics(self):
        output = self.output()
        self.assertTrue(output[0].startswith('0 "BGP FRR"'))
        self.assertTrue(output[1].startswith('0 "BGP default ipv4Unicast 192.0.2.2"'))
        self.assertIn("prefixes_received=10", output[1])
        self.assertIn("uptime=123.0", output[1])
        self.assertIn("remote AS 65002", output[1])
        self.run_command.assert_called_with(["/usr/local/bin/vtysh", "-c", "show bgp vrf all summary json"],
            encoding="utf-8", stderr=subprocess.DEVNULL, timeout=5)

    def test_disabled_bgp_does_not_run_commands(self):
        self.config["OPNsense"]["quagga"]["bgp"]["enabled"] = "0"
        self.assertEqual([], self.output())
        self.run_command.assert_not_called()

    def test_down_session_is_critical_even_on_carp_backup(self):
        self.obj._read_carp_states = Mock(side_effect=AssertionError("BGP must not depend on CARP"))
        self.peer["state"] = "Active"
        output = self.output()
        self.assertTrue(output[0].startswith("2 "))
        self.assertTrue(output[1].startswith("2 "))
        self.obj._read_carp_states.assert_not_called()

    def test_zero_prefixes_are_not_automatically_failure(self):
        self.peer["pfxRcd"] = 0
        self.assertTrue(self.output()[1].startswith("0 "))

    def test_policy_problem_warns_despite_established_session(self):
        self.peer["peerState"] = "Policy"
        self.assertTrue(self.output()[1].startswith("1 "))
        self.assertIn("missing inbound/outbound policy", self.output()[1])

    def test_disabled_neighbor_is_omitted(self):
        self.neighbor["enabled"] = "0"
        self.assertEqual(1, len(self.output()))

    def test_missing_configured_neighbor_is_critical(self):
        self.summary = {}
        self.assertTrue(self.output()[1].startswith("2 "))
        self.assertIn("missing from FRR", self.output()[1])

    def test_missing_second_family_is_critical(self):
        self.neighbor["family"] = "ipv4,ipv6"
        output = self.output()
        self.assertEqual(3, len(output))
        self.assertTrue(output[1].startswith("0 "))
        self.assertTrue(output[2].startswith('2 "BGP default ipv6Unicast'))

    def test_multiple_vrfs_remain_separate(self):
        self.summary["blue"] = {"ipv4Unicast": {"peers": {"192.0.2.2": dict(self.peer, state="Idle")}}}
        output = self.output()
        self.assertEqual(3, len(output))
        self.assertTrue(output[1].startswith('2 "BGP blue '))
        self.assertTrue(output[2].startswith('0 "BGP default '))

    def test_ipv6_and_flat_default_summary(self):
        self.neighbor.update(address="2001:db8::2", family="ipv6")
        self.summary = {"ipv6Unicast": {"peers": {"2001:db8:0:0::2": self.peer}}}
        output = self.output()
        self.assertEqual(2, len(output))
        self.assertTrue(output[1].startswith('0 "BGP default ipv6Unicast 2001:db8::2"'))

    def test_failed_command_is_critical(self):
        self.run_command.side_effect = subprocess.CalledProcessError(1, "vtysh")
        self.assertTrue(self.output()[0].startswith("2 "))
        self.assertTrue(self.output()[1].startswith("2 "))

    def test_query_timeout_is_unknown(self):
        self.run_command.side_effect = subprocess.TimeoutExpired("vtysh", 5)
        self.assertTrue(self.output()[0].startswith("3 "))
        self.assertTrue(self.output()[1].startswith("3 "))

    def test_invalid_schema_is_unknown(self):
        for data in ([], {"warning": "BGP not running"}, {"default": {"ipv4Unicast": {"peers": []}}}):
            with self.subTest(data=data):
                self.summary = data
                self.assertTrue(self.output()[0].startswith("3 "))

    def test_invalid_json_is_unknown(self):
        self.run_command.side_effect = None
        self.run_command.return_value = "not-json"
        self.assertTrue(self.output()[0].startswith("3 "))

    def test_previously_discovered_runtime_peers_survive_query_error(self):
        self.config["OPNsense"]["quagga"]["bgp"]["neighbors"] = {}
        self.assertEqual(2, len(self.output()))
        self.run_command.side_effect = subprocess.TimeoutExpired("vtysh", 5)
        self.assertTrue(self.output()[1].startswith('3 "BGP default ipv4Unicast 192.0.2.2"'))


class RegressionTests(unittest.TestCase):
    def test_ipv4_mapped_allowlist_and_numeric_configuration(self):
        Server = NS["checkmk_server"]
        with patch.object(Server, "_run_prog", return_value=""), patch.object(TCPServer, "__init__", return_value=None), patch.dict(NS, pwd=types.SimpleNamespace(getpwnam=lambda name: (name, "", 0, 0, "", "", ""))):
            obj = Server(6556, "unused", onlyfrom=" 192.0.2.10 ", expire_inventory="14400",
                         wireguard_failover_grace="90", tenants="192.0.2.11#secret")
        self.assertEqual(14400, obj.expire_inventory)
        self.assertEqual(90, obj.wireguard_failover_grace)
        self.assertTrue(obj.verify_request(None, ("::ffff:192.0.2.10", 1000)))
        self.assertTrue(obj.verify_request(None, ("::ffff:192.0.2.11", 1000)))
        self.assertFalse(obj.verify_request(None, ("192.0.2.12", 1000)))

    def test_expired_spool_data_is_not_emitted(self):
        class MinimalChecker(Checker):
            def __dir__(self):
                return []
        obj = MinimalChecker()
        obj._getosinfo = lambda: None
        obj._info = {"os": "OPNsense", "hostname": "test"}
        obj.tenants, obj.onlyfrom, obj.encrypt = {}, None, None
        obj._ipaccess_log, obj.expire_inventory = {}, 100
        obj.do_inventory = lambda: []
        obj.taskrunner = types.SimpleNamespace(get_data=lambda: [])
        with tempfile.TemporaryDirectory() as directory, patch.dict(NS, SPOOLDIR=directory, LOCALDIR="/nonexistent/local", PLUGINSDIR="/nonexistent/plugins"):
            old = Path(directory, "60_old")
            new = Path(directory, "60_new")
            old.write_text("EXPIRED-DATA")
            new.write_text("CURRENT-DATA")
            os.utime(old, (100, 100))
            os.utime(new, (990, 990))
            with patch.object(time, "time", return_value=1000):
                output = obj.do_checks().decode()
            self.assertNotIn("EXPIRED-DATA", output)
            self.assertIn("CURRENT-DATA", output)

    def test_acme_expiry_and_renewal_use_days(self):
        cert = {"enabled": "1", "description": "Example", "certRefId": "cert", "statusCode": "200", "lastUpdate": "1000000", "renewInterval": "60"}
        obj = checker({"OPNsense": {"AcmeClient": {"certificates": {"certificate": cert}}}})
        with patch.object(time, "time", return_value=10000000):
            for remaining, age, expected in ((5, 1, 2), (40, 1, 0), (40, 61, 1)):
                with self.subTest(remaining=remaining, age=age):
                    obj._get_certificate = Mock(return_value={"not_valid_after": 10000000 + remaining * 86400, "not_valid_before": 10000000 - age * 86400})
                    self.assertTrue(obj.checklocal_acmeclient()[0].startswith(str(expected) + " "))

    def test_decrypt_removes_padding_without_stripping_payload(self):
        payload = "  agent output\n".encode()
        padding = 16 - len(payload) % 16
        decryptor = Mock()
        decryptor.update.return_value = payload + bytes([padding]) * padding
        decryptor.finalize.return_value = b""
        crypto_mocks = dict(crypto_default_backend=lambda: None, PBKDF2HMAC=Mock(),
                            hashes=Mock(), algorithms=Mock(), modes=Mock(),
                            Cipher=Mock(return_value=types.SimpleNamespace(decryptor=lambda: decryptor)))
        crypto_mocks["PBKDF2HMAC"].return_value.derive.return_value = b"x" * 48
        with patch.dict(NS, **crypto_mocks):
            self.assertEqual(payload.decode(), checker().decrypt_msg(b"x" * 34, "secret"))
            decryptor.update.return_value = b"bad padding\x00"
            self.assertEqual("invalid key", checker().decrypt_msg(b"x" * 34, "secret"))

    def test_missing_cached_executable_does_not_stick_worker(self):
        process = NS["checkmk_cached_process"](["/missing-executable"])
        process._thread = object()
        with patch.object(subprocess, "check_output", side_effect=FileNotFoundError):
            process._runner(5)
        self.assertIsNone(process._thread)
        self.assertEqual("", process._data[1])

    def test_inventory_expiry(self):
        obj = checker()
        obj.expire_inventory = 10
        obj._ipaccess_log = {"old": 0, "other": 0}
        with patch.object(time, "time", return_value=100):
            self.assertTrue(obj._expired_lastaccesed("client"))
            self.assertFalse(obj._expired_lastaccesed("client"))
        self.assertEqual({"client": 100}, obj._ipaccess_log)

    def test_audit_errors_are_not_ok(self):
        obj = checker()
        for data in ("", "invalid-json", "{}"):
            obj._run_cache_prog = Mock(return_value=data)
            self.assertTrue(obj.checklocal_pkgaudit()[0].startswith("3 "))
        obj._run_cache_prog = Mock(return_value='{"pkg_count":0}')
        self.assertTrue(obj.checklocal_pkgaudit()[0].startswith("0 "))
        obj._run_cache_prog = Mock(return_value='{"pkg_count":1,"packages":{"example":{}}}')
        self.assertTrue(obj.checklocal_pkgaudit()[0].startswith("1 "))

    def test_tasks_reload_disable_and_delete(self):
        runner = NS["checkmk_taskrunner"](None)
        with tempfile.TemporaryDirectory() as directory, patch.dict(NS, TASKDIR=directory):
            path = Path(directory, "example.task")
            path.write_text("type: dummy\ninterval: 10\n")
            runner.check_taskdir()
            self.assertEqual(10, runner._queue[0].interval)
            path.write_text("type: cmk\ninterval: 20\n")
            stamp = path.stat().st_mtime + 2
            os.utime(path, (stamp, stamp))
            runner.check_taskdir()
            self.assertEqual(20, runner._queue[0].interval)
            self.assertEqual("cmk", runner._queue[0].type)
            path.write_text("type: cmk\ndisabled: 1\n")
            os.utime(path, (stamp + 2, stamp + 2))
            runner.check_taskdir()
            self.assertEqual([], runner._queue)
            for name in ("one.task", "two.task"):
                Path(directory, name).write_text("type: dummy\n")
            runner.check_taskdir()
            self.assertEqual(2, len(runner._queue))
            Path(directory, "one.task").unlink()
            Path(directory, "two.task").unlink()
            runner.check_taskdir()
            self.assertEqual([], runner._queue)

    def test_task_exception_is_reported(self):
        task = NS["checkmk_task"]("broken.task", {"type": "not-implemented"})
        task._run()
        self.assertIsNotNone(task.error)
        self.assertEqual("", str(task))
        task = NS["checkmk_task"]("empty.task", {"type": "ssh"})
        task._run()
        self.assertIn("no agent output", task.error)
        self.assertEqual("", str(task))
        with self.assertRaises(ValueError):
            NS["checkmk_task"]("bad.task", {"interval": "0"})

    def test_scheduler_waits_for_short_interval(self):
        runner = NS["checkmk_taskrunner"](None)
        task = NS["checkmk_task"]("short.task", {"interval": "10", "type": "dummy"})
        task.nextrun = 1010
        runner._queue = [task]
        runner.check_taskdir = Mock()
        runner._run_task = Mock(side_effect=AssertionError("Task ran early"))
        runner._event = Mock()
        runner._event.wait.side_effect = lambda delay: setattr(runner, "isrunning", False)
        with patch.object(time, "time", return_value=1000):
            runner._run_forever()
        runner._event.wait.assert_called_once_with(10)

    def test_restart_without_pid_never_signals_group(self):
        branch = next(node for node in ast.walk(TREE) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == "args.stop or args.restart")
        fake_os = Mock()
        env = dict(NS, args=types.SimpleNamespace(stop=False, restart=True), _pid=0,
                   _server=Mock(), os=fake_os, time=Mock(), sys=Mock())
        exec(compile(ast.Module(body=branch.body, type_ignores=[]), str(SOURCE), "exec"), env)
        fake_os.kill.assert_not_called()
        env["_server"].daemonize.assert_called_once()

    def test_atomic_update_preserves_backup_and_rejects_invalid_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "agent.py")
            path.write_text("old = 1\n")
            with self.assertRaises(SyntaxError):
                NS["replace_agent"](str(path), "not valid python !!!")
            self.assertEqual("old = 1\n", path.read_text())
            NS["replace_agent"](str(path), "new = 2\n")
            self.assertEqual("new = 2\n", path.read_text())
            self.assertEqual("old = 1\n", Path(str(path) + ".bak").read_text())

    def test_openvpn_instances_and_single_legacy_entry_are_checked(self):
        for config in (
            {"OPNsense": {"OpenVPN": {"Instances": {"Instance": {"@uuid": "vpn", "role": "server", "proto": "udp", "port": "1194", "server": "10.8.0.0/24", "description": "VPN"}}}}},
            {"openvpn": {"openvpn-server": {"vpnid": "1", "local_port": "1194", "protocol": "udp", "tunnel_network": "10.8.0.0/24", "description": "VPN"}}}
        ):
            obj = checker(config)
            obj._get_certificate = Mock(return_value={})
            obj._read_from_openvpnsocket = Mock(side_effect=TimeoutError)
            self.assertTrue(obj.checklocal_openvpn()[0].startswith('2 "OpenVPN Server: VPN"'))

    def test_ipsec_connections_and_disabled_connections(self):
        connection = {"@uuid": "conn-uuid", "description": "Branch", "enabled": "1"}
        config = {"OPNsense": {"Swanctl": {"Connections": {"Connection": connection}}}}
        obj = checker(config)
        obj._run_prog = Mock(return_value=json.dumps({"conn-uuid": {"sas": [{"state": "ESTABLISHED", "child-sas": {"child": {"state": "INSTALLED"}}}]}}))
        self.assertTrue(obj.checklocal_ipsec()[0].startswith('0 "IPsec Tunnel: Branch"'))
        connection["enabled"] = "0"
        self.assertEqual([], obj.checklocal_ipsec())


if __name__ == "__main__":
    unittest.main()
