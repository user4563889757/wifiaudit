"""Parser and audit tests for wifiaudit (no Wi-Fi hardware required)."""

import json
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import wifiaudit  # noqa: E402


NMCLI_FIXTURE = r""" :OpenCafe:AA\:BB\:CC\:DD\:EE\:01:Infra:6:88:--
 :Shop\:Guest:AA\:BB\:CC\:DD\:EE\:02:Infra:11:70:WEP
*:HomeNet:AA\:BB\:CC\:DD\:EE\:03:Infra:1:92:WPA1 WPA2
 :Corp:AA\:BB\:CC\:DD\:EE\:04:Infra:36:80:WPA2 802.1X
 ::AA\:BB\:CC\:DD\:EE\:05:Infra:44:60:WPA2 WPA3
"""

IW_FIXTURE = """BSS aa:bb:cc:dd:ee:01(on wlp0s20f3)
\tfreq: 2437
\tSSID: OpenCafe
\tcapability: ESS Privacy (0x0011)
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 2 (Configured)

BSS aa:bb:cc:dd:ee:03(on wlp0s20f3)
\tfreq: 2412
\tSSID: HomeNet
\tRSN:\t * Version: 1
\t\t * Group cipher: TKIP
\t\t * Pairwise ciphers: CCMP

BSS aa:bb:cc:dd:ee:05(on wlp0s20f3)
\tfreq: 5180
\tSSID: Hidden
\tWPS:\t * Version: 1.0
\t\t * Wi-Fi Protected Setup State: 1 (Not Configured)
"""


class TerseParsingTests(unittest.TestCase):
    def test_escaped_colons_are_not_delimiters(self):
        line = r" :My\:Network:66\:BF\:6B\:8B\:12\:1C:Infra:11:100:WPA2"
        fields = wifiaudit.split_terse(line)
        self.assertEqual(fields[1], "My:Network")
        self.assertEqual(fields[2], "66:BF:6B:8B:12:1C")
        self.assertEqual(fields[6], "WPA2")

    def test_escaped_backslash(self):
        self.assertEqual(wifiaudit.split_terse(r"a\\b:c"), [r"a\b", "c"])

    def test_split_key_value_keeps_colons_in_value(self):
        key, value = wifiaudit.split_key_value(
            r"IP4.ADDRESS[1]:192.168.1.5/24"
        )
        self.assertEqual(key, "IP4.ADDRESS[1]")
        self.assertEqual(value, "192.168.1.5/24")

    def test_parse_nmcli_output(self):
        networks = wifiaudit.parse_nmcli_output(NMCLI_FIXTURE)
        self.assertEqual(len(networks), 5)
        by_bssid = {network.bssid: network for network in networks}

        open_net = by_bssid["AA:BB:CC:DD:EE:01"]
        self.assertEqual(open_net.ssid, "OpenCafe")
        self.assertEqual(open_net.channel, 6)
        self.assertEqual(open_net.signal, 88)
        self.assertFalse(open_net.in_use)

        guest = by_bssid["AA:BB:CC:DD:EE:02"]
        self.assertEqual(guest.ssid, "Shop:Guest")

        home = by_bssid["AA:BB:CC:DD:EE:03"]
        self.assertTrue(home.in_use)
        self.assertEqual(home.security_raw, "WPA1 WPA2")

        hidden = by_bssid["AA:BB:CC:DD:EE:05"]
        self.assertTrue(hidden.hidden)
        self.assertEqual(hidden.display_ssid, "<hidden>")

    def test_parse_nmcli_output_deduplicates_bssid(self):
        fixture = "\n".join(
            [
                r" :Same:AA\:BB\:CC\:DD\:EE\:01:Infra:1:20:WPA2",
                r" :Same:AA\:BB\:CC\:DD\:EE\:01:Infra:1:80:WPA2",
            ]
        )
        networks = wifiaudit.parse_nmcli_output(fixture)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0].signal, 80)

    def test_bad_numeric_fields_become_none(self):
        fixture = r" :Odd:AA\:BB\:CC\:DD\:EE\:06:Infra:xx:n/a:WPA2"
        network = wifiaudit.parse_nmcli_output(fixture)[0]
        self.assertIsNone(network.channel)
        self.assertIsNone(network.signal)


class SecurityClassificationTests(unittest.TestCase):
    def test_open(self):
        for raw in ("", "--", None):
            self.assertTrue(wifiaudit.classify_security(raw)["open"])

    def test_wep(self):
        flags = wifiaudit.classify_security("WEP")
        self.assertTrue(flags["wep"])
        self.assertFalse(flags["wpa2"])

    def test_wpa1_only(self):
        flags = wifiaudit.classify_security("WPA1")
        self.assertTrue(flags["wpa1"])
        self.assertFalse(flags["wpa2"])

    def test_wpa2_wpa3(self):
        flags = wifiaudit.classify_security("WPA2 WPA3")
        self.assertTrue(flags["wpa2"])
        self.assertTrue(flags["wpa3"])

    def test_enterprise(self):
        self.assertTrue(wifiaudit.classify_security("WPA2 802.1X")["enterprise"])
        self.assertTrue(wifiaudit.classify_security("WPA2-Enterprise")["enterprise"])

    def test_tkip_token(self):
        self.assertTrue(wifiaudit.classify_security("WPA2 TKIP")["tkip"])

    def test_unknown(self):
        self.assertTrue(wifiaudit.classify_security("SOMETHING-NEW")["unknown"])


class IwParsingTests(unittest.TestCase):
    def test_wps_frequency_and_tkip(self):
        parsed = wifiaudit.parse_iw_scan(IW_FIXTURE)

        open_net = parsed["AA:BB:CC:DD:EE:01"]
        self.assertEqual(open_net["freq"], 2437)
        self.assertTrue(open_net["wps"])
        self.assertEqual(open_net["wps_state"], "configured")

        home = parsed["AA:BB:CC:DD:EE:03"]
        self.assertEqual(home["freq"], 2412)
        self.assertFalse(home["wps"])
        self.assertTrue(home["tkip"])

        hidden = parsed["AA:BB:CC:DD:EE:05"]
        self.assertTrue(hidden["wps"])
        self.assertEqual(hidden["wps_state"], "not configured")

    def test_missing_wps_element_means_false(self):
        parsed = wifiaudit.parse_iw_scan(
            "BSS aa:bb:cc:dd:ee:09(on wlan0)\n\tfreq: 2412\n"
        )
        self.assertFalse(parsed["AA:BB:CC:DD:EE:09"]["wps"])


class FindingTests(unittest.TestCase):
    def test_open_network_is_high(self):
        network = wifiaudit.Network(ssid="Cafe", bssid="AA:BB:CC:DD:EE:01")
        findings = wifiaudit.audit_network(network)
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["code"], "open-network")

    def test_wep_is_high(self):
        network = wifiaudit.Network(
            ssid="Old", bssid="AA:BB:CC:DD:EE:02", security_raw="WEP"
        )
        codes = {finding["code"] for finding in wifiaudit.audit_network(network)}
        self.assertIn("wep", codes)
        self.assertEqual(
            wifiaudit.network_risk(wifiaudit.audit_network(network)), "high"
        )

    def test_wpa1_enabled_alongside_wpa2_is_low(self):
        network = wifiaudit.Network(
            ssid="Mixed",
            bssid="AA:BB:CC:DD:EE:03",
            security_raw="WPA1 WPA2",
        )
        codes = {finding["code"] for finding in wifiaudit.audit_network(network)}
        self.assertIn("wpa1-enabled", codes)
        self.assertNotIn("wpa1-only", codes)

    def test_wps_and_hidden(self):
        network = wifiaudit.Network(
            ssid="",
            bssid="AA:BB:CC:DD:EE:04",
            security_raw="WPA2",
            wps=True,
            wps_state="configured",
        )
        findings = wifiaudit.audit_network(network)
        codes = {finding["code"] for finding in findings}
        self.assertIn("wps-enabled", codes)
        self.assertIn("hidden-ssid", codes)
        self.assertEqual(wifiaudit.network_risk(findings), "medium")

    def test_info_does_not_set_risk(self):
        network = wifiaudit.Network(
            ssid="Fine", bssid="AA:BB:CC:DD:EE:05", security_raw="WPA2"
        )
        findings = wifiaudit.audit_network(network)
        self.assertEqual(findings[0]["severity"], "info")
        self.assertEqual(wifiaudit.network_risk(findings), "ok")


class ActiveConnectionTests(unittest.TestCase):
    @staticmethod
    def _proc(stdout="", returncode=0, stderr=""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_parse_dev_show_collects_indexed_values(self):
        text = "\n".join(
            [
                "GENERAL.CONNECTION:Home",
                "GENERAL.STATE:100 (connected)",
                "IP4.ADDRESS[1]:192.168.1.5/24",
                "IP4.ADDRESS[2]:10.0.0.5/24",
                "IP4.DNS[1]:192.168.1.1",
                "IP4.GATEWAY:192.168.1.1",
            ]
        )
        data = wifiaudit.parse_dev_show(text)
        self.assertEqual(data["GENERAL.CONNECTION"], "Home")
        self.assertEqual(data["IP4.ADDRESS"], ["192.168.1.5/24", "10.0.0.5/24"])
        self.assertEqual(data["IP4.DNS"], ["192.168.1.1"])

    def test_open_active_connection_is_high(self):
        active = {
            "name": "Cafe",
            "security": {
                "key-mgmt": "",
                "pairwise": "",
                "group": "",
                "proto": "",
            },
        }
        findings = wifiaudit.audit_active(active)
        self.assertEqual(findings[0]["code"], "active-open")
        self.assertEqual(findings[0]["severity"], "high")

    def test_wep_active_connection_is_not_reported_as_open(self):
        active = {
            "name": "Old",
            "security": {
                "key-mgmt": "none",
                "pairwise": "",
                "group": "",
                "proto": "",
                "wep-key-type": "1",
            },
        }
        findings = wifiaudit.audit_active(active)
        codes = {finding["code"] for finding in findings}
        self.assertIn("active-wep", codes)
        self.assertNotIn("active-open", codes)

    def test_wpa1_active_connection_flagged(self):
        active = {
            "name": "Old",
            "security": {
                "key-mgmt": "wpa-psk",
                "pairwise": "TKIP",
                "group": "TKIP",
                "proto": "wpa",
            },
        }
        codes = {finding["code"] for finding in wifiaudit.audit_active(active)}
        self.assertIn("active-wpa1", codes)
        self.assertIn("active-tkip", codes)

    def test_unknown_active_security_is_not_flagged(self):
        self.assertEqual(wifiaudit.audit_active({"name": "X", "security": None}), [])

    def test_read_active_connection_parses_security(self):
        device_output = "\n".join(
            [
                "GENERAL.CONNECTION:Home",
                "GENERAL.STATE:100 (connected)",
                "IP4.ADDRESS[1]:192.168.1.5/24",
                "IP4.GATEWAY:192.168.1.1",
                "IP4.DNS[1]:192.168.1.1",
            ]
        )
        security_output = "\n".join(
            [
                "802-11-wireless-security.key-mgmt:wpa-psk",
                "802-11-wireless-security.pairwise:ccmp",
                "802-11-wireless-security.group:ccmp",
                "802-11-wireless-security.proto:rsn",
            ]
        )
        warnings = []
        with mock.patch.object(
            wifiaudit,
            "run_command",
            side_effect=[
                self._proc(device_output),
                self._proc(security_output),
            ],
        ) as runner:
            active = wifiaudit.read_active_connection("wlan0", warnings)

        self.assertEqual(active["name"], "Home")
        self.assertEqual(active["state"], "connected")
        self.assertEqual(active["security"]["key-mgmt"], "wpa-psk")
        self.assertEqual(active["security"]["proto"], "rsn")
        self.assertEqual(active["ip4_addresses"], ["192.168.1.5/24"])
        self.assertFalse(warnings)

        requested_fields = " ".join(runner.call_args_list[1].args[0]).lower()
        self.assertIn("802-11-wireless-security.key-mgmt", requested_fields)
        self.assertNotIn("security.psk", requested_fields)

    def test_read_active_connection_returns_none_when_disconnected(self):
        device_output = "GENERAL.CONNECTION:--\nGENERAL.STATE:30 (disconnected)\n"
        with mock.patch.object(
            wifiaudit, "run_command", return_value=self._proc(device_output)
        ):
            self.assertIsNone(wifiaudit.read_active_connection("wlan0", []))

    def test_read_active_connection_does_not_flag_missing_security_data(self):
        device_output = "GENERAL.CONNECTION:Home\nGENERAL.STATE:100 (connected)\n"
        warnings = []
        with mock.patch.object(
            wifiaudit,
            "run_command",
            side_effect=[
                self._proc(device_output),
                self._proc(""),
            ],
        ):
            active = wifiaudit.read_active_connection("wlan0", warnings)
        self.assertIsNone(active["security"])
        self.assertTrue(warnings)


class ReportTests(unittest.TestCase):
    def test_report_is_json_serializable_and_sorted(self):
        networks = wifiaudit.parse_nmcli_output(NMCLI_FIXTURE)
        report = wifiaudit.build_report("wlp0s20f3", networks, None, [])
        encoded = json.dumps(report)
        self.assertIn("open-network", encoded)

        self.assertTrue(report["read_only"])
        self.assertEqual(report["summary"]["networks"], 5)
        self.assertGreaterEqual(report["summary"]["high"], 1)

        risk_values = [network["risk"] for network in report["networks"]]
        self.assertEqual(risk_values[0], "high")
        self.assertIn("ok", risk_values)

    def test_report_keeps_info_findings_in_json(self):
        networks = wifiaudit.parse_nmcli_output(
            r" :Good:AA\:BB\:CC\:DD\:EE\:07:Infra:1:90:WPA2"
        )
        report = wifiaudit.build_report("wlan0", networks, None, [])
        self.assertEqual(report["networks"][0]["risk"], "ok")
        self.assertTrue(
            any(finding["severity"] == "info" for finding in report["findings"])
        )


if __name__ == "__main__":
    unittest.main()
