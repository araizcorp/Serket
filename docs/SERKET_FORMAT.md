# Serket assessment package v1

A `.serket` file is a ZIP-compatible, read-only assessment artifact created
next to every native result directory.

## Contract

- `manifest.json` declares schema version 1, component names and SHA-256 hashes.
- Every component is a top-level JSON file; nested and parent-relative archive
  paths are rejected.
- Loaders verify hashes before composing the in-memory result.
- `interchange.json` uses `araizcorp-identity-bridge/v1` and exposes stable
  identity IDs to Reliquary without including passwords, hashes, LAPS values,
  gMSA blobs or other credential material.
- Existing schema-1 result directories without hashes remain readable for
  backwards compatibility but are not considered integrity-verified.

## Risk inference extension

Pack 3 snapshots add optional fields to `analysis.json` without changing the
package schema version:

- `snapshot_id`: stable identifier reused when the same snapshot is reanalysed.
- `findings`: `finding://serket/v1` records with evidence, certainty, paths,
  MITRE context and explainable `serket-risk/v1` components. `id` identifies
  the observation inside one snapshot; `correlation_id` is stable across
  snapshots and is the comparison key intended for Ledger.
- `risk_summary`: aggregate score, severity counts and category scores intended
  for posture comparison. Consumers must also retain `risk_model`.
- `sensitivity`: node sensitivity derived from Tier-0 identity, containment,
  group membership and GPO links.

`GPO_TIER0_LINK` findings use `coverage: ldap_only`. They describe an enabled
LDAP link to a sensitive container, including order, enforced state and block
inheritance context; they do not claim that uncollected SYSVOL content is
malicious.

Older schema-1 packages may omit these fields. Consumers must interpret their
absence as `not_assessed`, never as an empty or healthy posture.

`GET /api/findings` supports `badge`, `severity`, `tier0_reachable`,
`object_id`, `offset` and `limit`. Pages are capped at 2,000 records.

Treat the complete package as sensitive assessment evidence.
