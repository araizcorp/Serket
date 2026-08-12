<p align="center">
  <img src="serket/ui/assets/brand/serket-logo-primary-red-v3.png" alt="Serket by AraizCorp" width="520">
</p>

<h1 align="center">Serket</h1>

<p align="center">
  Active Directory relationship intelligence and attack-path analysis.<br>
  A local-first, dual-use security tool by <strong>AraizCorp LLC</strong>.
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.es.md">Español</a> ·
  <a href="LEGAL.md">Legal notice</a> · <a href="DOCKER.md">Container guide</a>
</p>

> [!WARNING]
> **Development status:** Serket is an active pre-release project. Core collection, graph construction, saved-result analysis, universal search and interactive path exploration work, but coverage is not yet complete. Do not treat the current output as an exhaustive assessment or use it as the sole basis for a production security decision.

Serket collects authorized Active Directory metadata over LDAP, converts identities and permissions into a directed graph, and presents the result in an original investigation workbench. It is designed for defenders, auditors, red teams and purple teams working under an explicit authorization and rules of engagement.

Serket is not presented as “undetectable.” Its controlled collection profile reduces unnecessary queries, measures the collection footprint and helps an assessment team compare expected activity with DC, SIEM, EDR and NDR telemetry.

![Serket Workbench](docs/media/serket-workbench-preview-02.png)

## Current capabilities

| Capability | Status | Notes |
|---|---:|---|
| LDAP collection | Available | Users, groups, computers, domain policy, GPOs, trusts, selected ACLs and AD CS data |
| Authentication | Available | Password prompt, NTLM hash, Kerberos cache and optional LDAPS |
| Relationship graph | Available | Directed graph with transitive group membership and permission/delegation edges |
| Global path analysis | Available | OPSEC-weighted Dijkstra paths to high-value nodes |
| Interactive path query | Available | Choose a loaded source and target/Tier 0; computation uses the saved graph and does not query AD again |
| Universal search | Available | Name, SID, UPN, DN, DNS name and `sAMAccountName` |
| Node and relationship inspector | Available | Controls, controlled by, memberships, paths, evidence, impact and remediation context |
| Local web workbench | Available | Overview, Paths, Explorer, Exposure and Detection views; English default, Spanish optional |
| Docker packaging | Prepared | Hardened image, Compose file and multi-architecture GHCR workflow are included |
| AD CS classification | Partial | Automated ESC1 classification only |
| Trust analysis | Partial | Trust objects are enumerated; advanced abuse conclusions are not inferred yet |
| Detection validation | Partial | Guidance and expected telemetry are shown; live SIEM/EDR evidence import is not implemented yet |
| `.serket` portable package | Planned | Current result format is JSON plus a text report |

## How it works

```mermaid
flowchart LR
    A["Authorized LDAP session"] --> B["Collector"]
    B --> C["Directed relationship graph"]
    C --> D["Path and exposure analysis"]
    D --> E["JSON result + text report"]
    E --> F["Local read-only API"]
    F --> G["Serket Workbench"]
```

The browser interface reads the saved result. It never executes validation commands and an interactive path query never reconnects to the directory.

## Requirements

- Python 3.10 or later
- Network access from the collector host to the authorized domain controller
- A domain account with enough read access for the selected collection scope
- Docker or Podman only if the container workflow is used

ACL, LAPS, gMSA and AD CS visibility depends on the permissions granted to the assessment account and on the configuration of the target environment.

## Try the synthetic demo

The included demo contains fictional `LAB.SERKET.LOCAL` identities and does not contact a domain controller.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
serket --serve demo/serket-demo.json
```

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
serket --serve demo/serket-demo.json
```

Open <http://127.0.0.1:8080>. Native mode binds only to loopback and normally opens the default browser automatically.

## Install for native collection

Serket requires Python 3.10 or later. The installation creates the `serket` command; do not run the tool with `python serket.py` after installing it.

### Kali Linux, Linux and macOS

```bash
git clone https://github.com/araizcorp/Serket.git
cd Serket
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
hash -r
serket --help
```

On Kali or any other Linux distribution, **do not use `py -m pip install .`**. `py` is the Windows Python launcher and may be an unrelated command on Linux. Once the virtual environment is active, use `python -m pip install .` as shown above.

The `serket` command works from any directory while the virtual environment is active. To use it in a later terminal, activate the same environment again:

```bash
source /path/to/Serket/.venv/bin/activate
serket --help
```

If `pipx` is already installed and you want `serket` on your user `PATH` without activating a virtual environment each time, run this from the cloned repository:

```bash
pipx install .
pipx ensurepath
```

Open a new terminal after `pipx ensurepath`, then verify the command with `serket --help`.

### Windows PowerShell

```powershell
git clone https://github.com/araizcorp/Serket.git
Set-Location Serket
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
serket --help
```

`py` is used only to create the environment on Windows. If the launcher is unavailable, replace that first `py` with `python`. After activation, use `python -m pip` so the package and the `serket` command are installed in the active environment.

## Collect an authorized domain

### Password authentication

Omit `-p` to enter the password through the hidden prompt instead of storing it in shell history:

```bash
serket \
  -d corp.local \
  -u auditor \
  --ldaps
```

Serket discovers a domain controller automatically through the Active Directory DNS SRV records for the supplied domain. Use `-dc HOST` only to override discovery, select a specific controller or work around unavailable AD DNS.

### Kerberos

```bash
export KRB5CCNAME=/tmp/auditor.ccache
serket -d corp.local -u auditor -k
```

PowerShell equivalent:

```powershell
$env:KRB5CCNAME = "C:\path\to\auditor.ccache"
serket -d corp.local -u auditor -k
```

### NTLM hash

```bash
serket \
  -d corp.local \
  -u auditor \
  --hashes :NT_HASH
```

Only use credential material that is explicitly covered by the authorization for the assessment. Prefer LDAPS when the environment supports it.

### Collection controls

```bash
serket \
  -d corp.local \
  -u auditor \
  --rate-limit 0.20 \
  --max-paths 50 \
  --no-adcs
```

| Option | Purpose |
|---|---|
| `-dc HOST` | Override automatic AD DNS discovery and use a specific controller |
| `--rate-limit SEC` | Delay between LDAP result pages; default `0.08` seconds |
| `--max-paths N` | Maximum global paths saved; default `20` |
| `--no-acls` | Skip DACL-only ACL collection; faster but removes important permission edges |
| `--no-adcs` | Skip certificate-template enumeration |
| `--ldaps` | Use LDAP over TLS on port 636 |
| `-o DIR` | Select the output directory |
| `--quiet` | Suppress progress output for machine-oriented execution |

ACL and ADCS descriptor queries automatically request only the DACL through the Microsoft LDAP security-descriptor control. No additional flag or dependency is required.

Run `serket --help` for the complete CLI reference. The legacy `python serket.py` entry point remains available from a source checkout.

## Results

By default Serket writes to `~/.serket/results/`:

```text
serket_corp_local_YYYYMMDD_HHMMSS.json
serket_corp_local_YYYYMMDD_HHMMSS_report.txt
```

The JSON contains metadata, collection telemetry, graph nodes and edges, derived exposure summaries and calculated paths. Treat it as sensitive assessment evidence even when it does not contain passwords.

### Open the latest result in the Workbench

After a collection finishes, start the web interface without locating the JSON manually:

```bash
serket server
```

This opens the newest result in `~/.serket/results/`. To select the newest result for a particular domain:

```bash
serket server -d corp.local
```

Use `--port 9090` to select another local port or `--output DIR` if the collection was saved outside the default directory. The Workbench listens only on `127.0.0.1`.

### Read a saved result in the terminal

```bash
serket --load ~/.serket/results/serket_corp_local_YYYYMMDD_HHMMSS.json
```

### Open a specific JSON in the Workbench

```bash
serket \
  --serve ~/.serket/results/serket_corp_local_YYYYMMDD_HHMMSS.json \
  --port 8080
```

## Using the Workbench

1. **Overview** shows domain, graph and collection metrics plus the highest-priority calculated paths.
2. **Search** accepts a partial name, SID, UPN, distinguished name, DNS name or `sAMAccountName`.
3. **Paths** lets you select a source identity and a destination or all Tier 0 targets, filter the relationship type and constrain hop count.
4. **Focused graph** displays the selected route as an interactive directed subgraph. Drag the diamond nodes to rearrange it; curves, arrows and labels follow automatically.
5. **Inspector** opens when a node or edge is selected. Node tabs show controls, incoming control, memberships and saved paths. Relationship tabs show evidence, impact, validation, telemetry and remediation guidance.
6. **Explorer** presents a focused graph around the selected object instead of trying to render the entire directory at once.
7. **Exposure** groups Kerberos, delegation, ACL, AD CS, SID history, LAPS, gMSA and trust observations.
8. **Detection** distinguishes documented expectations from unknown validation state. “Unknown” means that no detection evidence was imported; it does not mean the activity is invisible.

Use the `EN / ES` selector to change language. The interface stores only the language preference in the browser.

## Local API

The Workbench uses a small read-only API that can also support local integrations:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/search?q=aria` | Universal node search |
| `GET` | `/api/nodes/{node_id}` | Node details and relationship directions |
| `GET` | `/api/graph` | Normalized saved graph |
| `GET` | `/api/paths` | Precomputed global paths |
| `POST` | `/api/query-paths` | On-demand path calculation over the loaded graph |
| `GET` | `/api/surface` | Derived exposure summary |
| `GET` | `/healthz` | Local health check |

Example query body:

```json
{
  "source": "S-1-5-21-...-1101",
  "target": "tier0",
  "max_hops": 6,
  "include_edge": "all",
  "limit": 25
}
```

The response explicitly reports `"queried_directory": false` because the calculation uses only the graph already loaded in memory.

## Relationship and exposure coverage

Current graph construction includes, where supported by collected evidence:

- Direct and transitive `MemberOf` relationships
- `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner` and `AllExtendedRights`
- `ForceChangePassword`, `AddMember`, `AddSelf` and `ShadowCredentials`
- `DCSync`
- Unconstrained delegation, constrained delegation and RBCD
- Kerberoastable and AS-REP roastable identities
- AD CS ESC1 enrollment paths
- SID history and heuristic password-in-description indicators
- Legacy Microsoft LAPS and modern Windows LAPS visibility indicators
- gMSA readability indicators without persisting the managed-password blob
- Domain trusts and selected GPO metadata

These are relationship and exposure observations, not proof that an exploitation action occurred or will succeed. Validate every path in the target environment and within the agreed rules of engagement.

## Docker

### Build the current source locally

```bash
docker build --tag serket:dev .
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  serket:dev
```

### Compose

```bash
docker compose up --build
```

### Published image

The release workflow is prepared for `ghcr.io/araizcorp/serket`, but this project is still under development. The public pull command becomes valid after the first tagged image is published:

```bash
docker pull ghcr.io/araizcorp/serket:latest
```

See [DOCKER.md](DOCKER.md) for read-only result mounts, Compose usage and publication details.

## Security and privacy model

- Native serving binds to `127.0.0.1`; documented container publishing also uses host loopback.
- The frontend has no CDN, Neo4j or external analytics dependency.
- Result data is not transmitted to AraizCorp or another service by the application.
- The API disables caching and adds restrictive browser security headers.
- The Workbench is read-only and never executes a suggested validation command.
- The collector records query/page/entry and stage telemetry for later review.

Serket does not replace authorization, a collection plan or change control. Store result files as sensitive client evidence and remove them according to the engagement retention policy.

## Known limitations and roadmap

The following items are not complete in this release:

- ESC2–ESC8 automated AD CS analysis
- Advanced trust conclusions such as SID-filtering and quarantine abuse analysis
- Live SIEM/EDR evidence import and verified detection status
- Resumable interrupted collection
- Portable, integrity-checked `.serket` assessment packages
- Large-domain performance validation and broader graph-query presets
- Web-based PDF, Markdown and CSV export hub

Roadmap items are not security claims. Track implementation and tests in repository releases and issues.

## Development and verification

```bash
python -B -m unittest discover -s tests -v
python -m py_compile serket.py serket/cli.py serket/server/api.py
node --check serket/ui/workbench.js
docker build --tag serket:dev .
```

The current automated suite covers API security headers, graph normalization, collection invariants, internationalization, universal search, node relationship directions and arbitrary-source path queries. A successful unit test run does not replace validation against an authorized lab domain.

## Project layout

```text
pyproject.toml             package metadata and `serket` console entry point
serket.py                  source-checkout compatibility wrapper
serket/cli.py              CLI and orchestration
serket/collector/          LDAP collection and ACL parsing
serket/graph/              graph construction and path analysis
serket/output/             persistence and terminal reporting
serket/server/             local read-only FastAPI application
serket/ui/                 Workbench, localization and brand assets
demo/                      synthetic evaluation dataset
tests/                     automated regression tests
.github/workflows/         test and GHCR publication workflow
```

## Responsible use, license and ownership

Use Serket only on systems you own or are explicitly authorized in writing to assess. The operator is responsible for scope, timing, rules of engagement, legal compliance and secure handling of results.

Copyright © 2026 **AraizCorp LLC**. Source code is provided under the [MIT License](LICENSE). The license does not grant rights to the Serket or AraizCorp names, logos or visual identity. Read the full [legal and responsibility notice](LEGAL.md) before use; a [Spanish translation](LEGAL.es.md) is also available.
