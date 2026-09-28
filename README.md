# HAIBOX WireGuard

WireGuard and port forwarding for a HAIBOX behind a VPS with a public IPv4 address. The VPS provides the public endpoint; the HAIBOX router keeps the tunnel open from its own network.

## Install v6.6

On a Debian or Ubuntu VPS, run as root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/main/install.sh)
```

The installer downloads the latest Golden release, checks its SHA-256 file and starts the setup menu. Choose **INSTALL + WEB UI**, then open `https://VPS_PUBLIC_IP:65000`. WireGuard uses UDP `443` by default. The first login is `admin` / `password`; you must change that password before setup continues.

[v6.6 script](https://github.com/simonemessina92/haibox-wireguard/releases/download/v6.6/haibox-wireguard_v6.6.sh) · [SHA-256](https://github.com/simonemessina92/haibox-wireguard/releases/download/v6.6/haibox-wireguard_v6.6.sh.sha256) · [Release notes](releases/v6.6.md)

## First setup

The wizard asks for the router LAN address and subnet, applies the VPS configuration and shows the WireGuard profile for the HAIBOX router. Copy or download the `.conf`, or use its QR code. A separate tab offers a Remote VPN Client profile for a phone or computer. Once the router tunnel is reachable, finish the wizard to open Overview.

If the browser closes during setup, log back in and continue with the saved network configuration and keys. An existing installation with an applied configuration goes straight to the control panel.

## What v6.6 includes

- **Overview:** active WireGuard peers, HAIBOX LAN device status, public service links and a four-minute RX/TX graph. The VPS keeps only the current four-minute window in memory while a Web UI session is active; returning to the browser restores that window.
- **Configuration:** core network values, extra port forwards, DMZ and an optional **Domain** for Public Services links. The domain changes Web UI links only; DNS is configured separately. DMZ receives ports left free by built-in mappings, extra rules and VPS services.
- **VPN Profiles:** router and Remote VPN Client configurations with copy, download and QR actions.
- **Apply and persistence:** a healthy, unchanged WireGuard interface is kept running; configuration changes still use the normal apply path. Saved rules and services survive a VPS reboot.

The router provides full-tunnel Internet access through the VPS. Published HAIBOX services use public DNAT and WireGuard-side hairpin rules. The Remote VPN Client reaches the HAIBOX LAN without using the VPS as its general Internet gateway.

## Default addresses

| Component | Address |
|---|---|
| Router LAN | `192.168.10.1/24` |
| StreamHub | `192.168.10.101` |
| HSG/HMG | `192.168.10.102` |
| Makito X4E | `192.168.10.103` |
| Windows | `192.168.10.104` |
| Proxmox | `192.168.10.250` |
| VPS WireGuard | `10.66.66.1` |
| Router WireGuard | `10.66.66.2` |
| Remote VPN Client | `10.66.66.3` |

LAN values can be changed during setup or later in Configuration. The VPS must have a public IPv4 address, root access, UDP `443` available for WireGuard and TCP `65000` available for the Web UI unless you change those ports.

## Versions

`main` contains the latest Golden release. Approved assets and checksums for v6.4, v6.5 and v6.6 remain in [GitHub Releases](https://github.com/simonemessina92/haibox-wireguard/releases); v6.3 and earlier assets remain there without checksums where none were published. `develop` contains the next build under test.

Use a separate test VPS for development builds:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/simonemessina92/haibox-wireguard/develop/install-dev.sh)
```

[Changelog](CHANGELOG.md) · [Development baseline](DEVELOPMENT_BASELINE.md) · [Release notes](releases/)

Maintained by Simone Messina.
