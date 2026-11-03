#!/usr/bin/env python3
"""wifiaudit - an ultra-lightweight, read-only Wi-Fi security auditor.

Scans visible access points with NetworkManager's ``nmcli`` (and optionally
``iw``) and reports configuration weaknesses. It never captures handshakes,
injects packets, deauthenticates clients, or attempts to recover passwords.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

TOOL = "wifiaudit"
__version__ = "1.0.0"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
RISK_ORDER = {"ok": 0, "info": 1, "low": 2, "medium": 3, "high": 4}

SEVERITY_COLORS = {
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[2;37m",
    "ok": "\033[1;32m",
}
RESET = "\033[0m"

BSSID_RE = re.compile(r"^\s*BSS\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
INDEXED_KEY_RE = re.compile(r"\[\d+\]$")

NMCLI_FIELDS = "IN-USE,SSID,BSSID,MODE,CHAN,SIGNAL,SECURITY"
ACTIVE_FIELDS = (
    "802-11-wireless-security.key-mgmt,"
    "802-11-wireless-security.pairwise,"
    "802-11-wireless-security.group,"
    "802-11-wireless-security.proto"
)
DEVICE_FIELDS = (
    "GENERAL.CONNECTION,GENERAL.STATE,IP4.ADDRESS,IP4.GATEWAY,IP4.DNS,"
    "IP6.ADDRESS,IP6.GATEWAY"
)


class WifiAuditError(RuntimeError):
    """A user-facing error that should not produce a traceback."""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def split_terse(line: str) -> list[str]:
    """Split one line of ``nmcli --terse`` output.

    nmcli escapes literal colons and backslashes in values (``\\:`` and
    ``\\\\``), so a plain ``str.split(":")`` would corrupt BSSIDs and SSIDs.
    """

    fields: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line) and line[i + 1] in (":", "\\"):
            current.append(line[i + 1])
            i += 2
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    fields.append("".join(current))
    return fields


def split_key_value(line: str) -> tuple[str, str]:
    """Split an nmcli terse line into its first key and the remaining value."""

    fields = split_terse(line)
    if not fields:
        return "", ""
    if len(fields) == 1:
        return fields[0], ""
    return fields[0], ":".join(fields[1:])


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def classify_security(raw: str | None) -> dict[str, bool]:
    """Turn an nmcli security string into a set of boolean flags."""

    text = (raw or "").strip().upper()
    flags = {
        "open": False,
        "wep": False,
        "wpa1": False,
        "wpa2": False,
        "wpa3": False,
        "enterprise": False,
        "tkip": False,
        "wps": False,
        "unknown": False,
    }

    if text in ("", "--", "-", "NONE", "OPEN"):
        flags["open"] = True
        return flags

    compact = re.sub(r"[^A-Z0-9.]+", " ", text)
    tokens = compact.split()
    for token in tokens:
        if token == "WEP":
            flags["wep"] = True
        elif token in ("WPA", "WPA1", "WPA-1"):
            flags["wpa1"] = True
        elif token.startswith("WPA2"):
            flags["wpa2"] = True
        elif token.startswith("WPA3"):
            flags["wpa3"] = True
        elif token == "TKIP":
            flags["tkip"] = True
        elif token == "WPS":
            flags["wps"] = True
        elif token in ("ENTERPRISE", "EAP", "802.1X"):
            flags["enterprise"] = True

    if "TKIP" in text:
        flags["tkip"] = True
    if "802.1X" in text or "ENTERPRISE" in text or "EAP" in tokens:
        flags["enterprise"] = True

    if not any((flags["wep"], flags["wpa1"], flags["wpa2"], flags["wpa3"])):
        flags["unknown"] = True
    return flags


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass
class Network:
    ssid: str
    bssid: str
    mode: str = ""
    channel: int | None = None
    signal: int | None = None
    security_raw: str = ""
    in_use: bool = False
    frequency_mhz: int | None = None
    wps: bool | None = None
    wps_state: str | None = None
    tkip: bool = False

    @property
    def hidden(self) -> bool:
        return not self.ssid.strip()

    @property
    def display_ssid(self) -> str:
        return self.ssid if not self.hidden else "<hidden>"

    def as_dict(self) -> dict[str, Any]:
        flags = classify_security(self.security_raw)
        security = self.security_raw.strip()
        if security in ("", "--", "-"):
            security = "OPEN"
        return {
            "ssid": self.ssid,
            "display_ssid": self.display_ssid,
            "bssid": self.bssid,
            "hidden": self.hidden,
            "mode": self.mode,
            "channel": self.channel,
            "signal": self.signal,
            "security": security,
            "wpa1": flags["wpa1"],
            "wpa2": flags["wpa2"],
            "wpa3": flags["wpa3"],
            "wep": flags["wep"],
            "enterprise": flags["enterprise"],
            "tkip": flags["tkip"] or self.tkip,
            "wps": self.wps,
            "wps_state": self.wps_state,
            "frequency_mhz": self.frequency_mhz,
            "in_use": self.in_use,
        }


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------


def run_command(args: Sequence[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise WifiAuditError(f"{args[0]} not found; please install it first") from exc
    except subprocess.TimeoutExpired as exc:
        raise WifiAuditError(f"{args[0]} timed out after {timeout}s") from exc


# ---------------------------------------------------------------------------
# Discovery and scanning
# ---------------------------------------------------------------------------


def detect_interface() -> str:
    proc = run_command(
        ["nmcli", "--terse", "--fields", "DEVICE,TYPE,STATE", "device", "status"],
        timeout=10,
    )
    if proc.returncode != 0:
        raise WifiAuditError(proc.stderr.strip() or "nmcli could not list devices")

    candidates: list[tuple[str, str]] = []
    for line in proc.stdout.splitlines():
        fields = split_terse(line)
        if len(fields) >= 3 and fields[1].strip() == "wifi":
            candidates.append((fields[0].strip(), fields[2].strip()))

    for name, state in candidates:
        if state.startswith("connected"):
            return name
    if candidates:
        return candidates[0][0]
    raise WifiAuditError("no Wi-Fi interface found; use --interface")


def parse_nmcli_output(text: str) -> list[Network]:
    networks: dict[str, Network] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = split_terse(line)
        if len(fields) < 7:
            continue

        in_use, ssid, bssid, mode, channel, signal, security = fields[:7]
        network = Network(
            ssid=ssid,
            bssid=bssid.strip().upper(),
            mode=mode.strip(),
            channel=_to_int(channel),
            signal=_to_int(signal),
            security_raw=security.strip(),
            in_use=in_use.strip() == "*",
        )
        key = network.bssid or f"{network.ssid}|{network.channel}"
        existing = networks.get(key)
        if existing is None:
            networks[key] = network
            continue

        # Keep one row per BSSID, preferring the strongest report while
        # preserving flags that only one duplicate carried.
        existing.in_use = existing.in_use or network.in_use
        if network.security_raw and not existing.security_raw:
            existing.security_raw = network.security_raw
        if (network.signal or -1) > (existing.signal or -1):
            network.in_use = network.in_use or existing.in_use
            network.security_raw = network.security_raw or existing.security_raw
            networks[key] = network
    return list(networks.values())


def scan_networks(interface: str, rescan: bool = False) -> list[Network]:
    proc = run_command(
        [
            "nmcli",
            "--terse",
            "--fields",
            NMCLI_FIELDS,
            "device",
            "wifi",
            "list",
            "ifname",
            interface,
            "--rescan",
            "yes" if rescan else "no",
        ],
        timeout=30,
    )
    if proc.returncode != 0:
        raise WifiAuditError(proc.stderr.strip() or "nmcli scan failed")
    return parse_nmcli_output(proc.stdout)


def parse_iw_scan(text: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    current: dict[str, Any] | None = None

    for line in text.splitlines():
        match = BSSID_RE.match(line)
        if match:
            current = {
                "bssid": match.group(1).upper(),
                "freq": None,
                "wps": None,
                "wps_state": None,
                "tkip": False,
            }
            result[current["bssid"]] = current
            continue
        if current is None:
            continue

        stripped = line.strip()
        if stripped.startswith("freq:"):
            current["freq"] = _to_int(stripped.split(":", 1)[1])
        elif stripped.startswith("WPS:"):
            current["wps"] = True
        elif "Wi-Fi Protected Setup State:" in stripped:
            current["wps"] = True
            if "Not Configured" in stripped:
                current["wps_state"] = "not configured"
            elif "Configured" in stripped:
                current["wps_state"] = "configured"
        elif "WPS State:" in stripped:
            current["wps"] = True
            if "Not Configured" in stripped:
                current["wps_state"] = "not configured"
            elif "Configured" in stripped:
                current["wps_state"] = "configured"

        if "cipher:" in stripped.lower() and "TKIP" in stripped.upper():
            current["tkip"] = True

    # A complete iw scan tells us that a BSS without a WPS element does not
    # advertise WPS at all (rather than leaving it unknown).
    for entry in result.values():
        if entry["wps"] is None:
            entry["wps"] = False
    return result


def enrich_with_iw(
    networks: list[Network], interface: str, warnings: list[str]
) -> None:
    if not networks:
        return
    if shutil.which("iw") is None:
        warnings.append(
            "iw not found; WPS/TKIP enrichment skipped (install 'iw' to enable it)"
        )
        return

    try:
        proc = run_command(["iw", "dev", interface, "scan"], timeout=26)
    except WifiAuditError as exc:
        warnings.append(f"iw scan failed: {exc}")
        return
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "iw scan failed"
        warnings.append(f"iw scan failed: {detail}")
        return

    enrichment = parse_iw_scan(proc.stdout)
    for network in networks:
        extra = enrichment.get(network.bssid)
        if extra is None:
            continue
        network.frequency_mhz = extra.get("freq")
        network.wps = extra.get("wps")
        network.wps_state = extra.get("wps_state")
        if extra.get("tkip"):
            network.tkip = True


# ---------------------------------------------------------------------------
# Active connection
# ---------------------------------------------------------------------------


def parse_dev_show(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for line in text.splitlines():
        key, value = split_key_value(line)
        if not key:
            continue
        base = INDEXED_KEY_RE.sub("", key)
        if base != key or base.endswith("ADDRESS") or base.endswith(".DNS"):
            data.setdefault(base, []).append(value)
        else:
            data[base] = value
    return data


def read_active_connection(
    interface: str, warnings: list[str] | None = None
) -> dict[str, Any] | None:
    if warnings is None:
        warnings = []

    proc = run_command(
        [
            "nmcli",
            "--terse",
            "--fields",
            DEVICE_FIELDS,
            "device",
            "show",
            interface,
        ],
        timeout=10,
    )
    if proc.returncode != 0:
        warnings.append("unable to read active connection state from nmcli")
        return None

    data = parse_dev_show(proc.stdout)
    name = str(data.get("GENERAL.CONNECTION", "")).strip()
    if not name or name == "--":
        return None

    raw_state = str(data.get("GENERAL.STATE", "")).strip()
    state_match = re.search(r"\(([^)]+)\)", raw_state)
    state = state_match.group(1) if state_match else raw_state

    active: dict[str, Any] = {
        "name": name,
        "state": state,
        "ip4_addresses": data.get("IP4.ADDRESS", []),
        "ip4_gateway": data.get("IP4.GATEWAY"),
        "ip4_dns": data.get("IP4.DNS", []),
        "ip6_addresses": data.get("IP6.ADDRESS", []),
        "ip6_gateway": data.get("IP6.GATEWAY"),
        "security": None,
    }

    # Query only non-secret security settings from the active profile.
    security_proc = run_command(
        [
            "nmcli",
            "--terse",
            "--fields",
            ACTIVE_FIELDS,
            "connection",
            "show",
            name,
        ],
        timeout=10,
    )
    if security_proc.returncode == 0:
        values: dict[str, str] = {}
        for line in security_proc.stdout.splitlines():
            key, value = split_key_value(line)
            values[key] = value
        security = {
            key: values.get(f"802-11-wireless-security.{key}")
            for key in ("key-mgmt", "pairwise", "group", "proto")
        }
        if all(value is None for value in security.values()):
            warnings.append("active connection security settings are unavailable")
        else:
            active["security"] = security
    else:
        warnings.append("unable to read active connection security settings")

    return active


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def audit_network(network: Network) -> list[dict[str, str]]:
    flags = classify_security(network.security_raw)
    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, message: str) -> None:
        findings.append({"severity": severity, "code": code, "message": message})

    if flags["open"]:
        add("high", "open-network", "Open network with no encryption.")
    if flags["wep"]:
        add("high", "wep", "WEP encryption is broken and should not be used.")
    if flags["wpa1"] and not (flags["wpa2"] or flags["wpa3"]):
        add("medium", "wpa1-only", "WPA1 only; upgrade the access point to WPA2/WPA3.")
    elif flags["wpa1"]:
        add("low", "wpa1-enabled", "WPA1 is still enabled alongside a newer standard.")
    if flags["tkip"] or network.tkip:
        add("medium", "tkip", "TKIP cipher in use; prefer AES/CCMP.")
    if flags["wps"] or network.wps is True:
        suffix = f" ({network.wps_state})" if network.wps_state else ""
        add("medium", "wps-enabled", f"WPS is enabled{suffix}; disable it if not needed.")
    if network.hidden:
        add(
            "low",
            "hidden-ssid",
            "Hidden SSID; this is not a security control and can disrupt roaming.",
        )
    if flags["enterprise"]:
        add(
            "info",
            "enterprise",
            "WPA-Enterprise; verify clients validate the RADIUS certificate.",
        )
    if flags["unknown"]:
        add(
            "info",
            "unknown-security",
            f"Unrecognized security string: {network.security_raw!r}.",
        )
    if (
        flags["wpa2"]
        and not flags["wpa3"]
        and not flags["wpa1"]
        and not flags["wep"]
        and not flags["open"]
        and not flags["enterprise"]
    ):
        add("info", "wpa2-only", "WPA2 only; enable WPA3 where clients support it.")
    return findings


def audit_active(active: dict[str, Any] | None) -> list[dict[str, str]]:
    if not active:
        return []
    security = active.get("security")
    if not security:
        return []

    findings: list[dict[str, str]] = []

    def add(severity: str, code: str, message: str) -> None:
        findings.append({"severity": severity, "code": code, "message": message})

    key_mgmt = (security.get("key-mgmt") or "").strip().lower()
    if not key_mgmt or key_mgmt == "none":
        add("high", "active-open", "Active connection has no wireless encryption.")
    elif key_mgmt == "wep":
        add("high", "active-wep", "Active connection uses broken WEP encryption.")

    proto = (security.get("proto") or "").lower()
    if "wpa" in proto and "rsn" not in proto and key_mgmt not in ("", "none", "wep"):
        add(
            "medium",
            "active-wpa1",
            "Active connection uses WPA1 only; reconfigure it for WPA2/WPA3.",
        )

    cipher = " ".join(
        filter(None, [security.get("pairwise"), security.get("group")])
    ).lower()
    if "tkip" in cipher:
        add("medium", "active-tkip", "Active connection uses the TKIP cipher.")

    if key_mgmt == "wpa-eap":
        add(
            "info",
            "active-enterprise",
            "Active connection uses WPA-Enterprise; confirm certificate validation.",
        )
    return findings


def network_risk(findings: Sequence[dict[str, str]]) -> str:
    risks = [
        finding["severity"]
        for finding in findings
        if finding["severity"] in SEVERITY_ORDER and finding["severity"] != "info"
    ]
    if not risks:
        return "ok"
    return max(risks, key=lambda severity: SEVERITY_ORDER[severity])


def build_report(
    interface: str,
    networks: list[Network],
    active: dict[str, Any] | None,
    warnings: list[str],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    network_findings: dict[str, list[dict[str, str]]] = {}

    for network in networks:
        for finding in audit_network(network):
            enriched = {
                **finding,
                "scope": "network",
                "ssid": network.ssid,
                "bssid": network.bssid,
            }
            findings.append(enriched)
            network_findings.setdefault(network.bssid, []).append(finding)

    for finding in audit_active(active):
        findings.append(
            {
                **finding,
                "scope": "active",
                "ssid": active.get("name") if active else None,
                "bssid": None,
            }
        )

    findings.sort(
        key=lambda finding: (
            -SEVERITY_ORDER[finding["severity"]],
            finding.get("ssid") or "",
            finding.get("code") or "",
        )
    )

    entries: list[dict[str, Any]] = []
    for network in networks:
        entry = network.as_dict()
        entry["risk"] = network_risk(network_findings.get(network.bssid, []))
        entries.append(entry)

    entries.sort(
        key=lambda entry: (
            -RISK_ORDER[entry["risk"]],
            -(entry["signal"] if entry["signal"] is not None else -1),
            entry["display_ssid"].lower(),
        )
    )

    summary = {
        "networks": len(entries),
        "high": sum(1 for finding in findings if finding["severity"] == "high"),
        "medium": sum(1 for finding in findings if finding["severity"] == "medium"),
        "low": sum(1 for finding in findings if finding["severity"] == "low"),
        "info": sum(1 for finding in findings if finding["severity"] == "info"),
        "wps_checked": any(network.wps is not None for network in networks),
        "wps_enabled": sum(1 for network in networks if network.wps is True),
    }

    return {
        "tool": TOOL,
        "version": __version__,
        "read_only": True,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "interface": interface,
        "networks": entries,
        "active_connection": active,
        "findings": findings,
        "summary": summary,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def color_enabled(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def paint(text: str, severity: str, enabled: bool) -> str:
    if not enabled or severity not in SEVERITY_COLORS:
        return text
    return f"{SEVERITY_COLORS[severity]}{text}{RESET}"


def _truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


def print_human(report: dict[str, Any], verbose: bool, color: bool) -> None:
    summary = report["summary"]
    print(f"{TOOL} {report['version']} - Wi-Fi security audit")
    print(f"Interface : {report['interface']}")
    print(f"Scanned at: {report['scanned_at']}")
    print("Mode      : read-only scan (no capture, injection, or association)")

    networks = report["networks"]
    if networks:
        rows: list[list[str]] = []
        for network in networks:
            rows.append(
                [
                    _truncate(network["display_ssid"], 30),
                    network["bssid"] or "-",
                    str(network["channel"]) if network["channel"] is not None else "-",
                    str(network["signal"]) if network["signal"] is not None else "-",
                    network["security"],
                    network["risk"],
                ]
            )
        headers = ["SSID", "BSSID", "CH", "SIG", "SECURITY", "RISK"]
        widths = [
            max(len(headers[index]), *(len(row[index]) for row in rows))
            for index in range(len(headers))
        ]

        def render(values: list[str], risk: str | None = None) -> str:
            cells = []
            for index, value in enumerate(values):
                padded = value.ljust(widths[index])
                if index == len(values) - 1 and risk is not None:
                    padded = paint(padded, risk, color)
                cells.append(padded)
            return "  ".join(cells).rstrip()

        print()
        print(render(headers))
        print(render(["-" * width for width in widths]))
        for network, row in zip(networks, rows):
            print(render(row, network["risk"]))
    else:
        print()
        print("No networks found.")

    print()
    summary_line = (
        f"{summary['networks']} networks: "
        f"{summary['high']} high, {summary['medium']} medium, {summary['low']} low"
    )
    if verbose:
        summary_line += f", {summary['info']} info"
    print(summary_line)
    if summary["wps_checked"]:
        print(f"WPS enabled: {summary['wps_enabled']} network(s)")
    print()

    visible_findings = [
        finding
        for finding in report["findings"]
        if verbose or finding["severity"] != "info"
    ]
    if visible_findings:
        print("Findings:")
        for finding in visible_findings:
            if finding["scope"] == "active":
                target = f"active connection {finding['ssid']!r}"
            else:
                target = finding["ssid"] or "<hidden>"
                if finding["bssid"]:
                    target += f" ({finding['bssid']})"
            label = paint(finding["severity"].upper().ljust(6), finding["severity"], color)
            print(f"  {label} {target}: {finding['message']}")
    else:
        print("No high, medium, or low findings.")

    active = report["active_connection"]
    print()
    if active:
        addresses = active.get("ip4_addresses") or active.get("ip6_addresses") or []
        detail = f"{active['name']} ({active.get('state') or 'unknown state'})"
        if addresses:
            detail += f" [{', '.join(str(address) for address in addresses)}]"
        print(f"Active connection: {detail}")
    else:
        print("Active connection: none")

    if verbose and report["warnings"]:
        print()
        for warning in report["warnings"]:
            print(f"note: {warning}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=TOOL,
        description=(
            "Read-only Wi-Fi security auditor. Scans visible access points and "
            "reports weak configurations. Only test networks you own or have "
            "written permission to assess."
        ),
    )
    parser.add_argument(
        "-i",
        "--interface",
        metavar="IFACE",
        help="wireless interface to scan (default: auto-detect)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors"
    )
    parser.add_argument(
        "--rescan",
        action="store_true",
        help="force a fresh scan instead of using NetworkManager's cache",
    )
    parser.add_argument(
        "--no-wps",
        action="store_true",
        help="skip optional iw-based WPS/TKIP enrichment",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show info-level findings and notes",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL} {__version__}"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    warnings: list[str] = []

    try:
        interface = args.interface or detect_interface()
        networks = scan_networks(interface, rescan=args.rescan)
        if not networks:
            warnings.append("no networks found; try again with --rescan")
        if not args.no_wps:
            enrich_with_iw(networks, interface, warnings)
        active = read_active_connection(interface, warnings)
        report = build_report(interface, networks, active, warnings)
    except WifiAuditError as exc:
        print(f"{TOOL}: error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human(report, verbose=args.verbose, color=color_enabled(args.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
