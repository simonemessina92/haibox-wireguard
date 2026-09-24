# HAIBOX WireGuard — Development Baseline

## 1. Purpose and authority

This document is the engineering baseline for HAIBOX WireGuard development.

- **Current Golden source:** `haibox-wireguard_v6.5.sh`
- **Golden status:** tested on the real HAIBOX environment and working
- **Development rule:** released Golden assets are immutable. Every new development cycle starts from the current Golden.
- **Conflict rule:** if previous chats, notes, memories, or older scripts disagree with the Golden file, the Golden file wins.
- **Promotion rule:** a development build becomes a new Golden only after the mandatory regression checklist in this document passes.

The current Golden release has:

- Version header: `6.5`
- SHA-256: `5cfce2477f9bb1af119fe00502055ad21507203a604c017e3205596d85b9c21a`

The checksum identifies the exact analyzed artifact. A file with a different checksum is not this Golden, even if its filename or version header says v6.3.

## 2. Supported platform and operating model

The script is a VPS-side deployment and management utility for Debian/Ubuntu with `systemd`. It must run as root.

It installs and uses:

- WireGuard and `wg-quick`
- `iptables` and `iptables-save`/`iptables-restore`
- `iproute2`, `ping`, `curl`, CA certificates, OpenSSL, Python 3, and `flock`
- a self-contained Python HTTPS management application generated from the Bash script

The script owns the HAIBOX-specific WireGuard, routing, NAT, forwarding, persistence, and Web UI configuration on the VPS. If UFW is active during apply, the script disables it and records that state so `REMOVE ALL` can restore it.

## 3. Reference architecture

### Default networks and peers

| Component | Default address | Role |
|---|---:|---|
| HAIBOX LAN | `192.168.10.0/24` | Remote LAN routed through the HAIBOX router |
| HAIBOX router LAN | `192.168.10.1` | LAN gateway/device management |
| Proxmox | `192.168.10.250` | Public GUI mapping on TCP 8006 |
| StreamHub | `192.168.10.101` | Main broadcast service target |
| HSG/HMG | `192.168.10.102` | Gateway/manager target |
| Makito X4E | `192.168.10.103` | Encoder target |
| Windows Orchestrator | `192.168.10.104` | Inventory/dashboard target; no default public DNAT |
| WireGuard tunnel | `10.66.66.0/24` | VPN transport network |
| VPS WireGuard | `10.66.66.1` | WireGuard server and routed/NAT endpoint |
| HAIBOX router WireGuard | `10.66.66.2` | Site peer advertising the HAIBOX LAN |
| Remote VPN client | `10.66.66.3` | Optional direct administrative client |

WireGuard listens on UDP `443` by default. The router peer uses a full tunnel (`AllowedIPs = 0.0.0.0/0`), DNS `1.1.1.1`, MTU `1420`, and `PersistentKeepalive = 25`. The optional remote client routes only the HAIBOX LAN and VPS WireGuard address through the VPN.

### Traffic model

1. HAIBOX LAN Internet traffic crosses `wg0` and exits the VPS public interface using MASQUERADE.
2. Incoming public service traffic is DNATed to the appropriate HAIBOX LAN device.
3. The same public service mappings work from inside the WireGuard tunnel through hairpin DNAT, restricted to traffic addressed to the VPS public IP.
4. Traffic forwarded toward the HAIBOX LAN is SNATed to the VPS WireGuard IP to guarantee a stable return path.
5. Forwarding explicitly permits established/related traffic, WireGuard-to-public, public-to-WireGuard, and WireGuard-to-WireGuard traffic.

## 4. Golden files and runtime state

| Path | Purpose |
|---|---|
| `/root/haibox_wg_state.conf` | Desired persistent configuration |
| `/root/haibox_wg_applied.conf` | Last successfully applied network state, used to clean old rules |
| `/etc/wireguard/wg0.conf` | VPS WireGuard configuration |
| `/root/haibox_router_wg.conf` | Generated HAIBOX router configuration |
| `/root/haibox_remote_client_wg.conf` | Generated optional remote-client configuration |
| `/etc/sysctl.d/99-haibox-wg.conf` | IPv4 forwarding and reverse-path-filter settings |
| `/etc/haibox-wg-rules.v4` | Persisted firewall snapshot |
| `/etc/systemd/system/haibox-wg-rules.service` | Firewall restore service |
| `/usr/local/sbin/haibox-wireguard` | Installed self-copy used by the Web UI |
| `/opt/haibox-webui/haibox_webui.py` | Generated Python Web UI |
| `/opt/haibox-webui/haibox_webui.crt` | Web UI TLS certificate |
| `/opt/haibox-webui/haibox_webui.key` | Web UI TLS private key |
| `/root/haibox_webui_auth.conf` | Web UI username and PBKDF2 password verifier |
| `/etc/systemd/system/haibox-webui.service` | Web UI service |

Private material and state files are written with restrictive permissions. WireGuard keys are reused if already present; applying a configuration must not silently rotate them.

## 5. Golden firewall and NAT behavior

The script creates dedicated chains:

- NAT: `HAIBOX_NAT`, reached from `PREROUTING`
- Forwarding: `HAIBOX_FWD`, reached from `FORWARD`

It also adds:

- INPUT allow for the configured WireGuard UDP port
- INPUT allow for the enabled Web UI TCP port, tagged `HAIBOX_WEBUI`
- MASQUERADE for both HAIBOX LAN and WireGuard tunnel traffic leaving the public interface
- SNAT to the VPS WireGuard IP for traffic sent to the HAIBOX LAN over `wg0`

Every standard DNAT mapping must exist twice:

- Internet path: input interface is the VPS public interface
- Hairpin path: input interface is `wg0` and destination is the VPS public IP

### Default public mappings

| Target | Public protocol/port | Internal destination |
|---|---|---|
| Router admin | TCP `8080` | Router `:8080` |
| Router LuCI | TCP `8081` | Router `:8081` |
| Proxmox GUI | TCP `8006` | Proxmox `:8006`, always published |
| Makito GUI | TCP `10443` | Makito `:443` |
| Makito encoder | UDP `30000-30004` | Same ports on Makito |
| HSG/HMG GUI | TCP `10444` | HSG/HMG `:443` |
| HSG/HMG SSH | TCP `2222` | HSG/HMG `:22` |
| HSG/HMG RTMP | TCP `1936` | HSG/HMG `:1935` |
| HSG/HMG SRT | UDP `9000-9100` | Same ports on HSG/HMG |
| StreamHub | TCP `7900`, `7901-7940` | Same ports on StreamHub |
| StreamHub web/services | TCP `443`, `8444`, `8888`, `8891`, `8893`, `8896`, `8884`, `8885`, `5322`, `1935` | Same ports on StreamHub |
| StreamHub FTP | TCP `20`, `21`, `12000-12009` | Same ports on StreamHub |
| StreamHub media/services | UDP `7900-7940`, `5010-5026`, `5353`, `5959-5960`, `5961-5999`, `6960-6999`, `7960-7999`, `20000-20100`, `20400-20499` | Same ports on StreamHub |

User-defined extra TCP/UDP port-forward rules are validated, stored in `EXTRA_PF_RULES`, applied to both public and hairpin paths, and checked for conflicts with reserved standard mappings.

## 6. WireGuard configuration invariants

The VPS configuration must retain these routing semantics:

- VPS interface address is derived from `WG_VPS_IP` and the prefix of `WG_TUN_CIDR`.
- HAIBOX router peer `AllowedIPs` contains exactly its tunnel `/32` plus `LAN_CIDR`.
- Remote-client peer, when created, has its own tunnel `/32` on the VPS.
- Router configuration remains a full-tunnel client with persistent keepalive.
- Remote-client configuration keeps `AllowedIPs = LAN_CIDR, WG_VPS_IP/32`; it is not converted into an Internet full tunnel.
- Creating the remote client adds/reuses its key pair, rewrites the server/router/client configurations, and restarts active WireGuard without breaking the HAIBOX peer.

## 7. Web UI Golden behavior

The Web UI is part of the current Golden, not an experimental add-on.

- HTTPS, bound by default to `0.0.0.0:65000`
- Self-signed RSA certificate, valid for ten years, reused when already present
- Fresh installations use `admin` / `password` and require immediate replacement before dashboard access
- Replacement and subsequent Web UI passwords must be at least 10 characters
- Existing credentials are preserved during upgrades
- PBKDF2-HMAC-SHA256 password storage with a random salt and 200,000 iterations
- Secure, HttpOnly, SameSite=Strict session cookie
- In-memory expiring sessions and authenticated routes
- Configuration editor with server-side validation
- Standard-port and extra-rule collision validation
- Apply + persistence operation via the installed script
- Test and System Health actions
- Router and remote-client `.conf` downloads when available
- Live dashboard and network statistics endpoints
- Compact Overview, Configuration and VPN Profiles workspaces
- Per-device RX/TX traffic accounting from the HAIBOX perspective
- POST/Redirect/GET prevents browser refresh from replaying state-changing actions
- Transient action messages dismiss automatically after 10 seconds

The live dashboard polls only while its tab is active and the page is visible. It reports:

- WireGuard peer state using current interface information and handshake data
- configured HAIBOX LAN device reachability using ICMP and selected TCP service probes
- latency when available

A device responding to ICMP is Online even if an optional monitored service is closed. A device with blocked ICMP but a reachable monitored service is reported as Service Online.

## 8. Apply safety and transaction behavior

Configuration apply is serialized with `/run/haibox-apply.lock`.

Before changing runtime networking, the script:

1. validates the complete configuration through the embedded Python validation logic;
2. verifies that the chosen public interface exists;
3. records service enable/active states and UFW state;
4. backs up WireGuard, sysctl, firewall persistence files, current iptables rules, and relevant sysctl values;
5. cleans rules associated with the last applied state.

On failure or interruption, it restores the prior files, services, firewall rules, and sysctl values. On success it copies desired state to the applied-state file. This rollback behavior is a Golden invariant and must not be weakened by later development.

## 9. Persistence and lifecycle behavior

- `wg-quick@wg0` is enabled when a WireGuard configuration exists.
- `haibox-wg-rules.service` restores the tested `iptables-save` snapshot after network-online and WireGuard startup.
- The rules snapshot is checked with `iptables-restore --test` before replacement.
- Web UI and firewall input rules follow the saved enabled state and selected port.
- `REMOVE ALL` requires the literal confirmation `YES`.
- Removal stops/disables HAIBOX services, removes owned rules/files/keys, reloads sysctl, purges WireGuard packages, and re-enables UFW only if the script had disabled it.
- Python 3 is purged only if the script recorded that it installed Python itself.

## 10. Health semantics

`SYSTEM HEALTH` returns:

- `0`: healthy
- `1`: warning only
- `2`: one or more errors

The health check verifies the WireGuard interface/service/address, router peer, active router reachability, IPv4 forwarding, LAN route, firewall chains and jumps, NAT, persistent files/services, and enabled Web UI listener.

Critical Golden rule: an old WireGuard handshake is diagnostic history only. The HAIBOX router is declared online only when the active reachability check succeeds. A recent or historical handshake alone must never produce an online result.

## 11. Supported entry points

### Interactive menu

1. Install + Web UI
2. Apply (terminal fallback)
3. Test
4. System Health
5. Make Persistent
6. Remove All
7. Show current config
8. Show Web UI access
9. Reset Web UI credentials

### Non-interactive flags

- `--web-apply`
- `--web-test`
- `--health`
- `--create-remote-client`
- `--ensure-webui-input`
- `--print-webui-access`
- `--reset-webui-credentials`

Unknown flags must fail rather than being silently ignored.

## 12. Change-control rules for v6.5+

1. Never edit or overwrite a published Golden release asset.
2. Start from the current Golden, update the version consistently, and work only on `develop`.
3. Keep the project as a single deployable script unless a deliberate architecture change is approved.
4. Do not reconstruct code from chat memory or an older release.
5. Do not remove or rename a state key, path, CLI flag, Web UI endpoint, or mapping without an explicit migration plan.
6. Preserve existing keys, state, service names, and generated client configurations across an in-place upgrade.
7. New firewall rules must use the owned chains or explicit HAIBOX comments and must be idempotent.
8. New configurable ports must participate in validation and collision detection.
9. Never expose Windows Orchestrator publicly by default.
10. Any change to routing, NAT, DNAT, SNAT, WireGuard `AllowedIPs`, or rollback behavior requires the full real-environment regression suite.
11. A successful syntax check or installation is not sufficient to declare a new Golden.
12. Record each approved release checksum and the physical regression-test result in this document or its successor.
13. After a Golden is approved and published on `main`, merge that exact `main` state into `develop` before starting another development cycle. Resolve older development changes in favor of the approved Golden; keep the branch history. Verify that the resulting `develop` tree matches `main` before making new changes.
14. Start the next development build from the synchronized Golden source. Give it a `-dev.1` version only when implementing the first new change; do not label the unmodified Golden as a development build.

## 13. Mandatory regression checklist

### A. Artifact and static checks

- [ ] Development started from the exact current Golden checksum recorded above.
- [ ] Version is updated consistently in Bash header, menu, health output, and Web UI-visible text.
- [ ] `bash -n` passes.
- [ ] Embedded Python is extracted and `python3 -m py_compile` passes.
- [ ] No accidental CRLF conversion, truncation, or broken heredoc delimiters exists.
- [ ] ShellCheck findings are reviewed; any accepted exceptions are documented.
- [ ] All Golden state keys and runtime paths remain present or have an explicit migration.
- [ ] Standard mappings and both DNAT paths are still generated.
- [ ] No secret/private key/password hash is printed to normal output or logs.

### B. Clean VPS installation

- [ ] Run as root on a supported clean Debian/Ubuntu VPS.
- [ ] EULA appears once, rejects `N`, and records acceptance after `Y`.
- [ ] Required packages install successfully.
- [ ] Installed self-copy exists and is executable at `/usr/local/sbin/haibox-wireguard`.
- [ ] Web UI starts automatically on TCP 65000 with `admin` / `password` on a fresh installation.
- [ ] First login forces a new password of at least 10 characters before dashboard access.
- [ ] HTTPS Web UI starts and is reachable externally.
- [ ] Login succeeds with the configured credentials; bad credentials fail.
- [ ] Logout invalidates the session.
- [ ] TLS key, auth file, WireGuard keys, and state files have restrictive permissions.

### C. Configuration validation

- [ ] Default configuration is accepted.
- [ ] Invalid IP, CIDR, interface, and port values are rejected without changing runtime networking.
- [ ] Invalid or overlapping extra port-forward rules are rejected with a useful error.
- [ ] A valid single-port extra rule applies correctly.
- [ ] A valid range rule with identical public/target range applies correctly.
- [ ] A valid translated range applies correctly.
- [ ] Proxmox TCP `8006` is always included in the standard public mappings.
- [ ] Windows Orchestrator has no default public DNAT.

### D. WireGuard core

- [ ] `wg0` starts on the configured UDP port.
- [ ] HAIBOX router establishes a current handshake.
- [ ] VPS can actively reach the router tunnel IP.
- [ ] Route to `LAN_CIDR` uses `wg0`.
- [ ] VPS can reach the configured HAIBOX LAN devices.
- [ ] Router config download matches the saved state and keeps full-tunnel semantics.
- [ ] Remote-client creation/download succeeds.
- [ ] Remote client reaches the HAIBOX LAN and VPS WireGuard IP.
- [ ] Remote client does not unexpectedly become a full Internet tunnel.
- [ ] Adding/recreating the remote client does not rotate existing VPS/router keys or break the HAIBOX peer.

### E. Internet breakout and forwarding

- [ ] A HAIBOX LAN device reaches the Internet through the VPS.
- [ ] Public source IP observed from the HAIBOX is the VPS public IPv4.
- [ ] Internet breakout works with the router's IP masquerading enabled.
- [ ] Internet breakout works in the previously supported router masquerading mode(s).
- [ ] Existing/related flows continue correctly through the forwarding chain.
- [ ] Repeated Apply does not duplicate owned jumps or POSTROUTING rules.

### F. Public DNAT services

- [ ] Router admin TCP `8080` reaches internal `8080`.
- [ ] Router LuCI TCP `8081` reaches internal `8081`.
- [ ] Makito GUI TCP `10443` reaches internal `443`.
- [ ] Makito UDP `30000-30004` passes bidirectional application traffic.
- [ ] HSG/HMG GUI TCP `10444`, SSH `2222`, RTMP `1936`, and SRT UDP range work.
- [ ] StreamHub HTTPS `443` and alternate web `8444` work.
- [ ] StreamHub TCP `7900-7940` and all listed service/FTP mappings are present and application-tested where equipment permits.
- [ ] StreamHub UDP `7900-7940` and all listed UDP ranges are present and application-tested where equipment permits.
- [ ] Proxmox TCP `8006` reaches internal `8006` through both public and hairpin mappings.
- [ ] At least one configured extra TCP rule and one configured extra UDP rule are tested end to end.

### G. Hairpin behavior

- [ ] From a WireGuard-side client, the VPS public IP and every critical published GUI resolve through the same public port mapping.
- [ ] Hairpin StreamHub media traffic is tested on representative TCP and UDP ports.
- [ ] Hairpin rules match `-i wg0 -d VPS_PUBLIC_IP`; they do not indiscriminately capture other destinations.
- [ ] Return traffic follows the stable SNAT path via the VPS WireGuard IP.

### H. Web UI and live dashboard

- [ ] Saved settings survive Web UI service restart and VPS reboot.
- [ ] Apply from Web UI performs apply + persistence and returns useful output.
- [ ] Router and remote-client downloads require authentication.
- [ ] Dashboard endpoint requires authentication and does not cache stale results.
- [ ] Router shows online only after an active successful check.
- [ ] A stale handshake plus failed active check shows router offline.
- [ ] Configured LAN devices show online/offline according to ICMP reachability.
- [ ] Dashboard polling stops when its tab/page is not active and resumes when visible.
- [ ] Network statistics update without breaking the configuration form.

### I. Persistence and reboot

- [ ] `iptables-restore --test` accepts the saved rules file.
- [ ] `wg-quick@wg0`, `haibox-wg-rules.service`, and enabled Web UI service have the correct enable/active state.
- [ ] Reboot the VPS.
- [ ] WireGuard peer reconnects without manual intervention.
- [ ] Internet breakout still works after reboot.
- [ ] Public DNAT and hairpin DNAT still work after reboot.
- [ ] Web UI and dashboard work after reboot.
- [ ] System Health returns the correct exit code and summary.

### J. Failure and rollback

- [ ] Force a safe validation failure: runtime and persisted configuration remain unchanged.
- [ ] Force a controlled apply failure after backup creation: prior WireGuard, firewall, sysctl, and service states are restored.
- [ ] Interrupt a controlled apply with SIGINT/SIGTERM: rollback completes.
- [ ] A concurrent apply attempt is rejected by the lock.
- [ ] Failed apply does not replace `haibox_wg_applied.conf` with uncommitted state.
- [ ] Rollback preserves access to the VPS.

### K. Remove All

- [ ] Any response other than literal `YES` cancels removal.
- [ ] Confirmed removal disables/stops owned services and removes owned rules, files, generated configs, and keys.
- [ ] Unrelated firewall rules remain intact.
- [ ] UFW is re-enabled only if it had been active before HAIBOX disabled it.
- [ ] Pre-existing Python 3 is not purged.
- [ ] A fresh reinstall after removal succeeds.

## 14. Release acceptance record

Complete this table only after physical regression testing. “Static pass” or “code reviewed” is not equivalent to Golden.

| Version | SHA-256 | Test date | VPS OS | HAIBOX/router build | Tester | Result | Notes |
|---|---|---|---|---|---|---|---|
| v6.3 | `aa01be1c788310fd10675a437cf6efe442387e1a3dad21b8147b92bd783e35d2` | Previously completed | Recorded in project history | Recorded in project history | Simone Messina | **GOLDEN** | Immutable source baseline |
| v6.4 | `058801a6ff50e49933cc58e38c2e1320e8262e19251daf58a6fbc30dc892143a` | 2026-09-18 | Debian 13 | HAIBOX physical test environment | Simone Messina | **GOLDEN** | Validated first on Amsterdam test VPS, then installed on Italy production VPS |

## 15. Definition of done for the next Golden

A release can replace the current active Golden only when:

1. its exact source file and SHA-256 are archived;
2. all applicable checklist items pass on the real VPS + HAIBOX setup;
3. failures, intentional deviations, and equipment-limited tests are explicitly recorded;
4. upgrade from the existing Golden preserves configuration and access;
5. rollback has been exercised, not merely code-reviewed;
6. Simone explicitly confirms the tested release as Golden.
7. `README.md` is reviewed and updated where needed: current Golden version, highlighted features, installation command, direct release/download/checksum links, and architecture diagram.
