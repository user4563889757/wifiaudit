# wifiaudit

An ultra-lightweight, read-only Wi-Fi security auditor for Linux.

`wifiaudit` scans the access points your wireless card can already see and reports
weak configurations: open networks, WEP, WPA1, TKIP, WPS, and hidden SSIDs. It also
audits the security settings of the connection you are currently using.

It is a single Python file with **no third-party dependencies**. It uses the
NetworkManager CLI (`nmcli`) that is already installed on most Linux desktops, plus
`iw` when available for WPS and cipher details.

```console
$ python3 wifiaudit.py
wifiaudit 1.0.0 - Wi-Fi security audit
Interface : wlp0s20f3
Scanned at: 2026-11-03T11:45:12+00:00
Mode      : read-only scan (no capture, injection, or association)

SSID                            BSSID              CH  SIG  SECURITY  RISK
------------------------------  -----------------  --  ---  --------  ------
IdoomFibre_ATMvhHv4z            66:BF:6B:8B:12:1C  11  100  WPA2      ok
OpenCafe                        AA:BB:CC:DD:EE:01  6   88   OPEN      high
...

2 networks: 1 high, 0 medium, 0 low

Findings:
  HIGH   OpenCafe (AA:BB:CC:DD:EE:01): Open network with no encryption.

Active connection: HomeNet (connected) [192.168.1.5/24]
```

## What it does

- Lists visible access points with SSID, BSSID, channel, signal, and security.
- Flags:
  - open networks (high)
  - WEP (high)
  - WPA1-only (medium) or WPA1 still enabled (low)
  - TKIP (medium)
  - WPS enabled (medium)
  - hidden SSID (low)
- Reports WPA2-only and enterprise networks as informational notes, with a
  recommendation to enable WPA3 or verify RADIUS certificate validation.
- Audits the active connection's key-management, protocol, and cipher settings.
- Emits a stable JSON report for scripting and CI.
- Works without root for the basic `nmcli` audit.

## What it deliberately does **not** do

This tool is defensive only. It does **not** contain, and will not add:

- handshake or PMKID capture
- deauthentication or disassociation
- packet injection or rogue access points
- dictionary, brute-force, or offline password attacks
- PIN or WPS attack tooling
- any password recovery or network-cracking feature

It only reads scan results and connection metadata that NetworkManager already
exposes. It never associates with a network to test it.

## Requirements

- Linux with NetworkManager (`nmcli`)
- Python 3.9 or newer
- Optional: `iw` for WPS and TKIP enrichment (`sudo apt install iw` on Debian/Ubuntu).
  Without `iw`, those fields remain `null` and the audit still works.
- Optional: root / `CAP_NET_ADMIN` for `iw` to perform a scan. `nmcli` works as a
  normal desktop user.

Check what is available:

```console
$ command -v nmcli iw
$ nmcli device status
```

## Usage

```bash
# Audit using the cached scan results (fast, no extra radio traffic)
python3 wifiaudit.py

# Force a fresh scan
python3 wifiaudit.py --rescan

# Choose an interface
python3 wifiaudit.py --interface wlp0s20f3

# JSON output
python3 wifiaudit.py --json

# Include info-level findings and notes
python3 wifiaudit.py --verbose

# Skip the optional iw scan
python3 wifiaudit.py --no-wps
```

### Options

| Option | Description |
| --- | --- |
| `-i`, `--interface IFACE` | Wireless interface to scan. Auto-detected by default. |
| `--json` | Emit a JSON report instead of the table. |
| `--no-color` | Disable ANSI colors. Colors are also disabled when stdout is not a TTY or `NO_COLOR` is set. |
| `--rescan` | Ask NetworkManager for a fresh scan instead of using its cache. |
| `--no-wps` | Skip `iw`-based WPS/TKIP enrichment. |
| `-v`, `--verbose` | Show info-level findings, WPS notes, and warnings. |
| `--version` | Print the version. |

Exit status is `0` after a successful audit and `1` if `nmcli` is missing, no
wireless interface is found, or the scan fails.

## JSON output

The JSON object is designed to be easy to consume and contains no secrets:

```json
{
  "tool": "wifiaudit",
  "version": "1.0.0",
  "read_only": true,
  "scanned_at": "2026-11-03T11:45:12+00:00",
  "interface": "wlp0s20f3",
  "networks": [
    {
      "ssid": "Cafe",
      "display_ssid": "Cafe",
      "bssid": "AA:BB:CC:DD:EE:01",
      "hidden": false,
      "mode": "Infra",
      "channel": 6,
      "signal": 88,
      "security": "OPEN",
      "wpa1": false,
      "wpa2": false,
      "wpa3": false,
      "wep": false,
      "enterprise": false,
      "tkip": false,
      "wps": null,
      "wps_state": null,
      "frequency_mhz": null,
      "in_use": false,
      "risk": "high"
    }
  ],
  "active_connection": null,
  "findings": [
    {
      "severity": "high",
      "code": "open-network",
      "message": "Open network with no encryption.",
      "scope": "network",
      "ssid": "Cafe",
      "bssid": "AA:BB:CC:DD:EE:01"
    }
  ],
  "summary": {
    "networks": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0,
    "wps_checked": false,
    "wps_enabled": 0
  },
  "warnings": []
}
```

`wps` is `true`, `false`, or `null`. `null` means `iw` was unavailable, not that
WPS is absent. `risk` is the highest non-informational severity for that network,
or `ok` when there are only informational findings.

## Severity model

| Severity | Meaning |
| --- | --- |
| `high` | Open or WEP-protected network; traffic is not meaningfully protected. |
| `medium` | WPA1-only, TKIP, or WPS enabled; known weak or deprecated configuration. |
| `low` | WPA1 still enabled alongside WPA2/WPA3, or hidden SSID (not a real control). |
| `info` | WPA2-only, WPA-Enterprise, or unrecognized security string; advisory only. |

Hidden SSIDs are reported because people often ask about them, but hiding an SSID
is not a security control. It can make roaming and diagnosis worse.

## Limitations

- Results depend on the scan cache and the radio's capabilities. Use `--rescan`
  for a current view.
- `nmcli dev wifi list` reports the security modes, not every cipher detail.
  TKIP detection therefore benefits from `iw`, and may be absent when `iw` is not
  installed or cannot scan.
- WPS information comes from the AP's beacon/probe-response information element.
  It cannot verify whether WPS is actually usable.
- Signal strength is a rough percentage from NetworkManager, not a calibrated
  measurement.
- The active-connection check reads only `key-mgmt`, `pairwise`, `group`,
  `proto`, and the non-secret WEP key type; it never reads the pre-shared key.
- This is not a replacement for a full wireless assessment or a site survey.

## Tests

The test suite uses synthetic `nmcli` and `iw` output, so no Wi-Fi hardware is
required:

```bash
python3 -m unittest discover -s tests -v
```

## Legal and ethical use

Use `wifiaudit` only on networks you own or have explicit written permission to
assess. Scanning radio spectrum is regulated differently in different places;
you are responsible for complying with local law. The authors accept no liability
for misuse.

## License

MIT. See [LICENSE](LICENSE).
