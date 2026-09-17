# HAIBOX WireGuard

HAIBOX WireGuard is a deployment and management tool designed to create a complete WireGuard-based remote access environment for HAIBOX systems using a public VPS.

The goal is simple:

> Start from a clean VPS, run a single command, follow the guided setup, and deploy the HAIBOX VPN environment.

## Features

- Automated WireGuard server configuration on the VPS
- HAIBOX router WireGuard configuration
- Full-tunnel Internet access through the VPS public IPv4
- Remote access to the HAIBOX local network
- Port forwarding for HAIBOX services
- Persistent routing and firewall configuration
- Optional HTTPS Web UI
- Downloadable WireGuard configuration for the HAIBOX router
- Optional additional Remote VPN Client
- Downloadable Remote VPN Client configuration
- Automatic configuration validation
- Interactive setup and management

## Typical Network Architecture

```text
                    INTERNET
                        |
                  Public IPv4
                        |
                       VPS
                  WireGuard Server
                    10.66.66.1
                        |
                   WireGuard VPN
                        |
                  HAIBOX Router
                    10.66.66.2
                        |
                 192.168.10.0/24
                        |
        +---------------+---------------+
        |               |               |
    StreamHub         HSG          Makito X4E
  192.168.10.101  192.168.10.102  192.168.10.103
                        |
               Windows Orchestrator
                 192.168.10.104
```

An optional Remote VPN Client can also connect directly to the VPS:

```text
Remote PC
10.66.66.3
     |
 WireGuard
     |
    VPS
     |
 WireGuard
     |
HAIBOX Router
     |
192.168.10.0/24
```

This allows the remote computer to directly access HAIBOX devices using their local IP addresses.

## Requirements

- Debian or Ubuntu VPS
- Root access
- Public IPv4 address
- Internet connectivity
- WireGuard-compatible router on the HAIBOX side

Required packages are installed automatically by the setup tool.

## Default Network

| Device | Default Address |
|---|---|
| HAIBOX Router | `192.168.10.1` |
| StreamHub | `192.168.10.101` |
| HSG | `192.168.10.102` |
| Makito X4E | `192.168.10.103` |
| Windows Orchestrator | `192.168.10.104` |
| Proxmox | `192.168.10.250` |
| VPS WireGuard | `10.66.66.1` |
| HAIBOX Router WireGuard | `10.66.66.2` |
| Remote VPN Client | `10.66.66.3` |

These values can be changed during configuration.

## Web UI

HAIBOX WireGuard includes an optional HTTPS Web UI for monitoring and managing the deployment.

The Web UI provides access to:

- HAIBOX VPN status
- Router WireGuard configuration
- Router configuration download
- Remote VPN Client management
- Remote VPN Client configuration download
- Current network configuration

## Remote VPN Client

An additional WireGuard peer can be generated for a remote Windows, macOS, Linux, Android or iOS device.

Once connected, the remote client can directly reach devices inside the HAIBOX LAN using their local `192.168.10.x` addresses.

## Installation

A one-line installation procedure for clean VPS deployments will be provided here.

## Security

WireGuard provides authenticated encrypted VPN communication between the VPS, HAIBOX router and optional remote clients.

The default HAIBOX deployment uses UDP port `443` for the WireGuard transport. This value can be changed during configuration.

The optional Web UI uses HTTPS and authentication.

## Project

Designed and developed by **Simone Messina**.

Built for portable HAIBOX deployments, demonstrations, remote access and field operation.

## License and Usage

Usage of this software is subject to the licensing and usage terms presented by the installer.

The software is provided as-is, without warranty.
