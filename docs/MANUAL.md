# Serket Operator's Manual

**Active Directory attack-path mapping — AraizCorp LLC**
Version 2.1 · For authorized security assessments only

---

## 1. What Serket is (and is not)

Serket collects Active Directory metadata over **LDAP only**, builds a directed
relationship graph (users, groups, computers, ACLs, GPOs, trusts, AD CS), and
computes attack paths to Tier 0. Results are saved locally as JSON bundles and
explored in a local web workbench.

- It is **not** BloodHound: no Neo4j, no SMB session enumeration, no agents.
- It is **not** "undetectable": it is *low-profile by design* — one LDAP
  session, paged searches, rate-limit + random jitter, and a measured
  footprint you can compare against SIEM/DC telemetry.
- It **never** executes validation commands and the workbench never reconnects
  to the directory.

---

## 2. Installation

### 2.1 Native (venv) — Linux / macOS

```bash
git clone <your Serket source> && cd Serket
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
serket --help
```

### 2.2 Native (venv) — Windows PowerShell

```powershell
git clone <your Serket source> && Set-Location Serket
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
serket --help
```

### 2.3 pipx (recommended for daily use)

```bash
pipx install /path/to/Serket
pipx ensurepath        # open a new terminal afterwards
serket --help
```

### 2.4 Docker (viewer only, or full CLI)

```bash
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/araizcorp/serket:latest
```

See `DOCKER.md` for the hardened read-only invocation and serving a real
result bundle from a mounted volume.

> After installing, always invoke `serket`, not `python serket.py`.

---

## 3. Quick start without a domain

The repo ships a synthetic bundle (`demo/`) that never contacts a DC:

```bash
serket --serve demo/serket-demo.json
```

Open <http://127.0.0.1:8080>, accept the legal notice, and explore the five
views (Overview, Paths, Explorer, Exposure, Detection).

To validate a **real** collection, use the disposable lab in `lab/`
(Samba AD DC in Docker):

```bash
cd lab && docker compose up --build
serket -dc 127.0.0.1 -d lab.serket.local -u administrator \
  -p 'SerketLab123!' --rate-limit 0.01 -o results/lab
docker compose down -v     # deletes the lab completely
```

---

## 4. CLI reference

```
serket [-h] [-dc HOST] [-d DOMAIN] [-u USER] [-p PASS] [--hashes LM:NT]
       [-k] [--auth MODE] [--ldaps] [--rate-limit SEC] [--jitter 0-1] [--max-paths N]
       [--no-acls] [--no-adcs] [--sysvol-root PATH]
       [--include-external-surface] [-o PATH] [--load PATH] [--serve PATH]
       [--input PATH] [--bridge PATH] [--port PORT] [--quiet]
       [{server,enrich,external-enrich}]
```

| Flag | Meaning |
|---|---|
| `-dc HOST` | DC hostname/IP. Omit to auto-discover via AD DNS SRV records. |
| `-d DOMAIN` | Domain FQDN (e.g. `corp.local`). |
| `-u USER` | Username (SAM or UPN). |
| `-p PASS` | Password. **Omit** to be prompted (keeps it out of shell history). |
| `--hashes LM:NT` | NTLM hash auth — pass-the-hash (`:NT` alone is fine). |
| `-k` | Kerberos; uses the ccache in `$KRB5CCNAME`. |
| `--auth MODE` | Explicit auth mode: `ntlm` (default), `kerberos` (same as `-k`), or `simple`. Overrides `-k`/`--hashes` when given. `simple` is a compatibility fallback for servers that reject ldap3's NTLM exchange (e.g. Samba AD DCs): it binds with `user@domain` via an LDAP simple bind. **OPSEC warning:** the DC logs a plain "simple bind", a different auth telemetry signature than NTLM — use only when NTLM/Kerberos are not an option. |
| `--ldaps` | LDAPS on 636 (encrypts queries on the wire). |
| `--rate-limit SEC` | Seconds to sleep between LDAP pages (default `0.08`). |
| `--jitter 0-1` | Random ±jitter applied to each sleep (default `0.5`). `0` = perfectly regular cadence (easier to fingerprint). |
| `--max-paths N` | Attack paths to compute (default `20`). |
| `--no-acls` | Skip ACL collection (fewer edges, faster, less data). |
| `--no-adcs` | Skip AD CS template enumeration. |
| `--sysvol-root PATH` | Parse an explicitly supplied local/mounted SYSVOL copy (Registry.pol, scripts, Local Users and Groups). No share discovery. |
| `--include-external-surface` | Run standalone Portico from PATH and consume its sanitized bridge. |
| `-o PATH` | Output directory (default `~/.serket/results`). |
| `--load PATH` | Load a saved bundle/manifest for offline console analysis. |
| `--serve PATH` | Launch the web workbench from a saved bundle. |
| `--input PATH` | Input `.serket` package for `enrich`. |
| `--bridge PATH` | Keyring/Portico bridge JSON for enrichment. |
| `--port PORT` | Workbench port (default `8080`, binds `127.0.0.1` only). |
| `--quiet` | Suppress progress output. |

Subcommands:

| Command | Purpose |
|---|---|
| `serket server [-d DOMAIN]` | Open the **latest** saved result in the workbench. |
| `serket --load PATH` | Console analysis of a saved bundle (no browser). |
| `serket --serve PATH` | Workbench from an explicit bundle file. |
| `serket enrich` | Apply a Keyring bridge and emit a new portable package. |
| `serket external-enrich` | Consume a Portico external-surface bridge. |

---

## 5. Collection workflows

### 5.1 Password authentication (interactive)

```bash
serket -d corp.local -u auditor --ldaps
```

`-p` omitted → hidden prompt. DC auto-discovered via AD DNS.

### 5.2 Kerberos (ccache)

```bash
export KRB5CCNAME=/tmp/auditor.ccache
serket -d corp.local -u auditor -k --ldaps
```

Best OPSEC option: no new NTLM authentication is created if you already hold
a ticket.

### 5.3 Pass-the-hash

```bash
serket -d corp.local -u auditor --hashes :aad3b435b51404eeaad3b435b51404ee --ldaps
```

Only use credential material explicitly covered by the engagement's
authorization.

### 5.4 Offline SYSVOL evidence

```bash
serket -d corp.local -u auditor -k --sysvol-root /evidence/SYSVOL
```

Reads Registry.pol, script inventory and Group Policy preferences from a copy
you already possess. Serket never mounts or browses SYSVOL itself.

### 5.5 Collection profiles (OPSEC)

| Profile | Command | Use when |
|---|---|---|
| Standard | default (`--rate-limit 0.08 --jitter 0.5`) | Most internal assessments |
| Low-and-slow | `--rate-limit 0.4 --jitter 0.7 --ldaps` | Sensitive environments, mature SOC |
| Fast lab/test | `--rate-limit 0.01` | Docker lab, CTF, tight windows |
| Minimal | `--no-acls` | When only identity/group paths are needed |

Every run records its footprint in `collection.telemetry` of the manifest
(searches, pages, entries, rate-limit, jitter, duration). Use it in the
purple-team debrief to compare expected vs. observed telemetry.

---

## 6. What a run produces

A result bundle in `-o PATH`:

```
serket-results.json     # combined result consumed by --load / --serve
manifest.json           # collection metadata + telemetry footprint
identities.json         # users and groups
systems.json            # computers with classification
permissions.json        # ACLs, owners, delegation
directory.json          # OUs, containers, GPOs, domain policy
adcs.json               # CAs and templates (ESC1 classification)
analysis.json           # paths, attack surface, stats
graph.json              # serialized directed multigraph
report.txt              # human-readable summary
```

The workbench reads the saved bundle only. Interactive path queries run
against the saved graph — **never** against the directory.

---

## 7. The workbench

Start it with `serket --serve <bundle.json>` (or `serket server` for the
latest). It binds `127.0.0.1` only and opens your browser.

| View | What it shows |
|---|---|
| **Overview (OV)** | Posture metrics, Tier 0 targets, priority paths, findings by category, domain policy. |
| **Paths (PA)** | Query builder: pick source identity and target/Tier 0, filter by hops and relationship type; path graph with MITRE ATT&CK technique chain. |
| **Explorer (EX)** | Scoped subgraph browsing with the floating inspector. |
| **Exposure (SR)** | Findings grouped by family (ACL-based control, SPNs, replication, AD CS, delegation…). |
| **Detection (DT)** | Expected telemetry and detection guidance per finding. |

Global features:

- **Universal search** (top bar): name, SID, UPN, DN, DNS name, `sAMAccountName`.
- **Inspector** (right pane): Evidence / Impact / Validation / Telemetry tabs
  for any selected node or relationship, with remediation context.
- Language toggle ES/EN in the top bar.

---

## 8. Offline analysis and re-use

```bash
# Console summary of a bundle (no browser)
serket --load results/serket_corp_20260101_120000

# Workbench from the same bundle
serket --serve results/serket_corp_20260101_120000

# Latest bundle for a domain
serket server -d corp.local
```

Loading reconstructs the graph from the saved data and re-runs pathfinding
locally; nothing queries AD again.

---

## 9. Enrichment

```bash
# Merge a Keyring metadata bridge into a .serket package
serket enrich --input run.serket --bridge keyring-bridge.json -o enriched.serket

# Fold a Portico external-surface bridge into a collection
serket -d corp.local -u auditor --include-external-surface
```

See `docs/KEYRING_INTEGRATION.md` and `docs/SERKET_FORMAT.md` for the bundle
and bridge formats.

---

## 10. Using Serket from RedHarpoon

RedHarpoon (AraizCorp's offensive CLI) ships a native wrapper:

```
RedHarpoon → Active Directory → Serket
```

It offers three flows — **collect** (asks DC, domain, user, auth method,
LDAPS, rate-limit, SYSVOL), **load saved results**, and **serve the
workbench** — and records every run in the RedHarpoon memory (queriable from
*Custom Native Tools → Memory / History*). The wrapper finds Serket on `PATH`
or via the `SERKET_PATH` environment variable.

---

## 11. Security, privacy and data handling

- The native server binds `127.0.0.1`; the interface uses no CDN or external
  analytics and never phones home.
- Results contain confidential directory data: encrypt, scope and delete them
  per the engagement's rules.
- Serket does not replace written authorization, a collection plan or change
  control.

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| `Cannot start web UI: No module named 'fastapi'` | `pip install fastapi uvicorn` (included in normal installs). |
| Workbench shows nothing / "no results" | Confirm the `--serve` path points at the **bundle JSON file**, not the directory. |
| Bind fails on 389/445 in the lab | Another Samba/DC process is listening; stop it or change the host port mapping in `lab/docker-compose.yml`. |
| Collection hangs at "Connecting" | Check `-dc`, firewall, and that the account can bind. Try LDAPS off, then on. |
| No ACL edges in results | The assessment account needs read access to `nTSecurityDescriptor` (typically Domain Admins or delegated rights). |
| Kerberos fails | Verify `KRB5CCNAME`, clock skew (< 5 min) and SPN of the account. |
| `LDAPSessionTerminatedByServerError` right after bind (Samba AD DC) | Samba terminates ldap3's NTLM (Sicily) exchange. Re-run with `--auth simple`, or use Kerberos (`-k`), the recommended path. Windows AD is unaffected. |
| Old bundle will not serve | Bundles from v2.0 with binary SIDs are repaired in memory on load; a fresh collection is needed for full ACL data. |

---

*Serket is dual-use software. The operator is responsible for written
authorization, scope, rules of engagement and legal compliance. MIT license
covers the code; AraizCorp names and visual identity are protected brand
assets.*
