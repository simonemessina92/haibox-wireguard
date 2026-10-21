# CLAUDE.md — HAIBOX WireGuard

Guidance for Claude Code sessions working in this repository. This is the
maintainer's most important project and it runs on production VPSs that carry
live broadcast traffic. Correctness and safety matter more than speed.

Read this file together with [`DEVELOPMENT_BASELINE.md`](DEVELOPMENT_BASELINE.md).
The baseline is the engineering authority (invariants, regression checklist,
release acceptance record). If this file and the baseline disagree, the
baseline wins; if the baseline and the current Golden script disagree, the
Golden script wins.

## 1. What the project is

A single Bash script, `haibox-wireguard.sh`, run as root on a Debian/Ubuntu VPS
(systemd) with a public IPv4 address. It turns the VPS into the public endpoint
for a HAIBOX: a GL.iNet router (GL-AXT1800) and a LAN of broadcast equipment
(Haivision StreamHub, HSG/HMG, Makito X4E, Windows Orchestrator, Proxmox).

The script:

- installs WireGuard, iptables, Python 3 and helpers;
- writes `wg0` (VPS server), the router peer profile (full tunnel) and an
  optional Remote VPN Client profile (LAN-only split tunnel);
- builds NAT/forwarding in owned chains `HAIBOX_NAT` and `HAIBOX_FWD`: Internet
  breakout (MASQUERADE), public DNAT to LAN devices, WireGuard-side hairpin
  DNAT, SNAT to the VPS WireGuard IP, extra port-forward rules and optional DMZ;
- persists everything (`haibox-wg-rules.service`, `wg-quick@wg0`, sysctl);
- generates and runs an HTTPS Web UI (Python, port 65000) with login,
  first-run wizard, dashboard, configuration editor, VPN profiles/QR codes and
  Remove All.

Default addresses, port mappings, runtime files and the traffic model are in
`DEVELOPMENT_BASELINE.md` §3–§5 and `README.md`.

## 2. Repository layout

| Path | Purpose |
|---|---|
| `haibox-wireguard.sh` | The whole product (~7,200 lines). Bash + an embedded Python Web UI. |
| `install.sh` | Production installer: downloads the **latest GitHub Release** asset, verifies its `.sha256`, runs `bash -n`, installs to `/root/haibox-wireguard.sh`, executes it. |
| `install-dev.sh` | Development installer: downloads `haibox-wireguard.sh` from the **`develop` branch** (no checksum), installs to `/root/haibox-wireguard-dev.sh`. For test VPSs only. |
| `DEVELOPMENT_BASELINE.md` | Engineering baseline, Golden checksum, invariants, mandatory regression checklist, release acceptance record. |
| `CHANGELOG.md` | Release history (`[Unreleased]` on top). |
| `releases/vX.Y.md` | GitHub Release notes, one file per Golden. |
| `releases/README.md` | Short release procedure. |
| `.github/release-request.json` | **Release trigger** (see §6). |
| `.github/release-request.example.json` | Template; `NEXT_VERSION` is intentionally invalid. |
| `.github/workflows/release.yml` | Publishes a release when `release-request.json` changes on `main`. |
| `.github/workflows/release-notes.yml` | Updates notes of the current release when `releases/*.md` changes on `main`. |

There is no build step, package manager, or test suite. The script is the
deliverable.

## 3. Structure of `haibox-wireguard.sh`

- Lines 1–480: header (`# Version X.Y` on line 5 — the release workflow checks
  it with `grep -Fqx`), path/name constants, helpers, EULA, state load/save,
  `init_defaults`, interactive prompts, dependency install, self-copy, Web UI
  auth/cert writers.
- `write_webui_app()` (starts ~line 479): writes `/opt/haibox-webui/haibox_webui.py`
  from the quoted heredoc `<<'PYEOF'` … `PYEOF` (~5,670 lines of Python:
  `SCRIPT_VERSION`, `RELEASE_CHANNEL`, `DEFAULTS`, validation, HTML/JS, the
  `Handler` with `do_GET`/`do_POST`, network sampler, `main()`).
- After the heredoc: service writer, key generation (`gen_keys`, keys are
  reused, never rotated), `write_wg_configs`, `create_remote_client`, sysctl,
  firewall (`dnat_both`, `dnat_range_both`, `apply_extra_pf_rules`, DMZ via
  `<<'PYDMZ'`, `iptables_apply_rules`), `make_persistent`, `do_test`,
  `system_health`, `remove_all`, `validate_config` (`<<'PYVALIDATE'`),
  `apply_runtime` (lock + backup + rollback), `install_workflow`,
  `run_noninteractive_command`, `menu`, and the entry point at the end.

Critical coupling — do not break:

- `validate_config` re-reads the installed script and extracts the Web UI
  source by splitting on the first `<<'PYEOF'\n` and the next `\nPYEOF`. The
  delimiter name, its quoting, and the fact that it is the first `PYEOF`
  heredoc must stay as they are. Bash and the Web UI share one validator.
- The Web UI calls the installed self-copy `/usr/local/sbin/haibox-wireguard`
  with flags (`--web-apply`, `--web-test`, `--health`, `--create-remote-client`,
  `--ensure-webui-input`, `--print-webui-access`, `--web-remove`).
- Non-interactive flags exist in **two** places: the `case` in
  `run_noninteractive_command` and the allow-list `case` at the very end of the
  file. A new flag must be added to both; unknown flags must fail.
- The version string appears in several places that must change together:
  line 5 `# Version X.Y`, `SCRIPT_VERSION`, `RELEASE_CHANNEL`
  (`"GOLDEN"` or `"DEVELOPMENT"`), `server_version = "HAIBOX-WebUI/X.Y"`, the
  System Health banner and the menu banner (`vX.Y (GOLDEN)` /
  `vX.Y-dev.N (DEVELOPMENT)`). Header line 5 must stay exactly
  `# Version X.Y` for a release. Find them with
  `grep -n '6\.7\|SCRIPT_VERSION\|RELEASE_CHANNEL' haibox-wireguard.sh`
  (replace `6.7` with the current version).

Fixed in v6.8-dev.1: `--reset-webui-credentials` was missing from the final
allow-list (since v6.4) and failed with "Unknown option"; `--web-remove` is
now listed in baseline §11.

## 4. Checks you can run here (static only)

Nothing in this repository can be exercised for real outside a VPS with a
HAIBOX router. Never run `haibox-wireguard.sh`, `install.sh` or
`install-dev.sh` in a Claude session: they require root and rewrite
WireGuard, iptables, sysctl, systemd units and packages on the host.

Safe static checks (all pass on v6.7):

```bash
# Bash syntax and line endings
bash -n haibox-wireguard.sh install.sh install-dev.sh
grep -c $'\r' haibox-wireguard.sh            # must print 0

# Embedded Python compiles (extract the Web UI heredoc to a temp file)
tmp="$(mktemp -d)"
sed -n "/<<'PYEOF'$/,/^PYEOF$/p" haibox-wireguard.sh | sed '1d;$d' > "$tmp/webui.py"
python3 -m py_compile "$tmp/webui.py"
# PYDMZ and PYVALIDATE heredocs can be checked the same way.

# ShellCheck (pip install shellcheck-py if missing). v6.7 baseline at -S warning:
# SC2034 EXPOSE_PROXMOX_GUI, SC2034 label, SC1090 non-constant source. Accepted.
shellcheck -S warning haibox-wireguard.sh install.sh install-dev.sh

# Exact artifact identity
sha256sum haibox-wireguard.sh                # compare with DEVELOPMENT_BASELINE.md §1
```

Offline validator smoke test (reads no host state, changes nothing):

```bash
python3 -I - haibox-wireguard.sh <<'EOF'
import sys
from pathlib import Path
src = Path(sys.argv[1]).read_text(encoding="utf-8")
app = src.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
ns = {"__name__": "haibox_validation"}
exec(compile(app, "haibox_webui.py", "exec"), ns)
st = dict(ns["DEFAULTS"], PUB_IP="203.0.113.10", PUB_IFACE="eth0")
_, errors, _ = ns["apply_form_values"]({k: [v] for k, v in st.items()}, st)
print("errors:", errors)                     # expected: []
EOF
```

Static checks are necessary but never sufficient: a Golden is declared only
after the physical regression checklist (baseline §13) passes on the real
VPS + HAIBOX and the maintainer confirms it.

## 5. Branches and workflow

- `main` — the current Golden only. Its `haibox-wireguard.sh` must be
  byte-identical to the latest release asset (v6.7: SHA-256
  `cc2ca8071d426d2d4e6711b48e7766c5ee2b682c66d5a8bf11de5ad7d53b78b6`, commit
  `30299be`, tag `v6.7`).
- `develop` — development. All work happens here or on a feature branch with a
  PR into `develop`. Test VPSs install it with `install-dev.sh`.
- `claude/backup-pre-claude-migration` — snapshot of `main` at `30299be` taken
  before the Codex → Claude migration. Do not delete or move it.
- `chore/repository-workflow` — old branch from PR #1 (already merged). Not
  used.

Working agreement with the maintainer (Simone):

1. Claude develops and pushes to `develop` on its own (feature branch + PR
   into `develop`, merged by Claude).
2. Simone installs the `develop` build on the test VPS and tests it.
3. Only when Simone writes **"golden"** for that build does Claude bring it to
   `main` and publish the release (§6). Never push to `main` or create a
   release without that explicit word for that specific build.
4. After the release, align `develop` with `main` (baseline §12 rule 13).

Commit messages: short imperative English (`fix: …`, `feat: …`, `docs: …`
are common in history). All repository text is in English. Talk to Simone in
Italian.

Development versioning (baseline §12): the first change after a Golden bumps
to the next minor with a `-dev.N` suffix (e.g. `6.8-dev.1`), incrementing `N`
for each test build, with `RELEASE_CHANNEL = "DEVELOPMENT"`. Do not label an
unmodified Golden as a development build. Record each dev build under
`[Unreleased]` in `CHANGELOG.md`.

## 6. Release pipeline (what triggers what)

Both workflows run **only on pushes to `main`**, filtered by path:

| Change pushed to `main` | Effect |
|---|---|
| `.github/release-request.json` | `release.yml`: validates version format, `bash -n`, that line `# Version X.Y` matches; refuses if tag `vX.Y` exists; creates tag `vX.Y` at that commit and a GitHub Release with `haibox-wireguard_vX.Y.sh` + `.sha256`, notes from `notes_file`. The new release becomes "latest", so **every production `install.sh` run immediately installs it.** |
| `releases/*.md` (without `release-request.json` in the same commit) | `release-notes.yml`: edits the notes of the release named in `release-request.json`, only if that version's notes file changed. |
| Anything else (README, CLAUDE.md, CHANGELOG, baseline, script) | No workflow runs. |

`release-request.json` also supports `repair_existing`, hard-restricted to
v6.6 (a one-off repair that replaced assets and moved the tag). Never use or
extend it without explicit approval: published Golden assets are immutable.

Promotion procedure after Simone says "golden" (baseline §15, releases/README):

1. On `develop`: set the final version (`X.Y`, `RELEASE_CHANNEL = "GOLDEN"`)
   everywhere listed in §3; update `README.md`, `CHANGELOG.md`,
   `releases/vX.Y.md`, and the baseline (current Golden, SHA-256, acceptance
   record row from Simone's test results).
2. Merge `develop` into `main` with a PR.
3. As the last step, change `.github/release-request.json` on `main` to the new
   version, title `HAIBOX WireGuard vX.Y — Golden` and notes file.
4. Verify: Actions run green, release assets exist, downloaded asset's
   `sha256sum -c` passes and is byte-identical to `main`'s
   `haibox-wireguard.sh`, and the SHA-256 matches the baseline.
5. Merge `main` back into `develop` and confirm the trees match.

Docs-only changes to `main` (like this file) must not touch
`.github/release-request.json` or `releases/*.md`, so they cannot trigger a
release.

## 7. Safety rules (non-negotiable)

- **Secrets.** Never print, log, commit, paste or upload WireGuard private or
  preshared keys, generated `.conf` profiles, `/root/haibox_webui_auth.conf`,
  the Web UI TLS key, password hashes, VPS public IPs or support bundles. If a
  user shares one, do not repeat it. The repository was scanned on 2026-10-21
  (all branches and history): no keys or credentials are committed; the only
  credential in code is the documented first-login default `admin` /
  `password`, which must be changed at first login.
- Never modify or replace a published release asset or move a tag.
- Never weaken the Golden invariants in baseline §5–§10, in particular:
  apply serialization (`/run/haibox-apply.lock`), backup + rollback on failure
  or signal, key reuse (no silent rotation), both DNAT paths (public and
  `-i wg0 -d PUB_IP` hairpin), router online only after an active reachability
  check (never from a handshake alone), Windows Orchestrator never published by
  default, idempotent rules in owned chains or with HAIBOX comments.
- Keep it a single deployable script; no new files the VPS would need to fetch.
- Do not rename/remove state keys, runtime paths, service names, CLI flags,
  Web UI endpoints or port mappings without a migration plan approved by Simone.
- Upgrades in place must keep configuration, keys, profiles and Web UI
  credentials.
- Any change to routing, NAT/DNAT/SNAT, `AllowedIPs` or rollback needs the full
  real-environment regression suite (baseline §13) before it can be Golden.
- Do not "clean up" or reformat the script beyond the task; large diffs make
  physical regression review harder.

## 8. Before you open a PR into `develop`

- Static checks in §4 pass; no new ShellCheck warnings.
- Version bumped consistently (§3, §5); `CHANGELOG.md` `[Unreleased]` updated.
- Diff reviewed for secrets and for accidental changes to invariants.
- PR description says what Simone must test on the VPS (pick the relevant
  items from baseline §13).
