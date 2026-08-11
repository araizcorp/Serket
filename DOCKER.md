# Serket container guide

The container is a local, read-only viewer by default. It starts with a synthetic dataset so the Workbench can be evaluated without connecting to a directory.

## Run the published image

```bash
docker run --rm \
  --name serket-workbench \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/araizcorp/serket:latest
```

Open <http://127.0.0.1:8080>.

Publishing on `127.0.0.1` is intentional: saved directory data can be sensitive and must not be exposed to the LAN by default.

## Open a real result file

Linux/macOS:

```bash
docker run --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 \
  -v "$PWD/results:/data:ro" \
  ghcr.io/araizcorp/serket:latest \
  --serve /data/serket-results.json --port 8080 --quiet
```

PowerShell:

```powershell
docker run --rm `
  --read-only `
  --tmpfs /tmp:rw,noexec,nosuid,size=64m `
  --cap-drop ALL `
  --security-opt no-new-privileges `
  -p 127.0.0.1:8080:8080 `
  -v "${PWD}/results:/data:ro" `
  ghcr.io/araizcorp/serket:latest `
  --serve /data/serket-results.json --port 8080 --quiet
```

With Compose, change the `command` path in `docker-compose.yml`, then run:

```bash
docker compose up --build
```

## Build locally

```bash
docker build --tag serket:local .
docker run --rm -p 127.0.0.1:8080:8080 serket:local
```

## Publish manually

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/araizcorp/serket:latest \
  --tag ghcr.io/araizcorp/serket:2.0.0 \
  --push .
```

Use a classic personal access token with `write:packages` for a manual push. The included GitHub Actions workflow uses the repository `GITHUB_TOKEN` instead.

## Scope and data handling

Serket is dual-use security software for authorized work. The operator remains responsible for written authorization, scope, rules of engagement, legal compliance and secure handling of collected data. The MIT license covers source code; AraizCorp names and visual identity remain protected brand assets.
