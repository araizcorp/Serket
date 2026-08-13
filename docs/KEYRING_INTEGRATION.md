# Keyring credential enrichment

Serket consumes Keyring's `serket-bridge` as metadata injection. The bridge never contains passwords,
hashes, tokens, API keys, or encrypted secret payloads.

## Persistent offline workflow

```bash
keyring export --input analysis.reliquary --format serket-bridge --domain corp.local --output bridge.json
serket enrich --input audit.serket --bridge bridge.json --output audit-enriched.serket
serket --serve audit-enriched.serket
```

The input package is never overwritten. Serket validates bridge version, types, counts, list bounds, and
prohibited sensitive field names before writing the enriched package.

## Local session API

An already-running Workbench can apply the same JSON to memory:

```http
POST /api/enrich
Content-Type: application/json
```

The endpoint is subject to an 8 MiB body limit. It changes only the current local process; use the CLI
workflow above when an enriched `.serket` artifact must be retained.

## Matching

Serket prefers an exact SID or graph identifier. If Keyring only has `username@domain` or
`DOMAIN\\username` from an offline Windows artifact, Serket falls back to the account name only when that
name resolves to exactly one graph node. Ambiguous matches are reported and never applied.

## UI attributes

Enriched nodes may show:

- `REUSE (N)`: the identity shares credential material with N other identities.
- `CLOUD`: the reuse cluster includes a cloud identity.
- `LAPS REUSE`: a LAPS-specific reuse finding.
- `POLICY FAIL`: available password age evidence exceeds the collected domain maximum age.

The inspector stores only aggregate names, counts, severity, and policy context.
