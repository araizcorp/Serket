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

Treat the complete package as sensitive assessment evidence.
