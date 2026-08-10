# BFSIboard — self-hosted PII & credential monitoring

Open-source scanner for the BFSI sector. Scans code, config and cloud files for
exposed personal data (PII) and secrets — then shows it on a local dashboard.

- **Zero runtime dependencies** (pure Node, no databases, no telemetry)
- **Nothing leaves your machine** — all findings stay local
- MIT licensed

## Quick start (Docker)

```bash
docker run -d -p 8080:8080 \
  -v "$PWD:/data:ro" \
  -e BFSIBOARD_SCAN_PATH=/data \
  ghcr.io/bfsiboard/bfsiboard:latest
```

Open **http://localhost:8080** — the dashboard shows scan status and masked findings.

Or with docker compose (mounts `./repos` into the container):

```bash
docker compose up -d
```

## CLI

```bash
npm install -g @bfsiboard/cli
bfsiboard scan .          # scan current directory
bfsiboard scan ./src --json
bfsiboard rules           # list detection rules
bfsiboard init            # write a sample config
```

Exit code is `1` when a `high` (or configured) finding is present, so it works in CI:

```bash
bfsiboard scan . && echo "clean" || echo "secrets found"
```

## Configuration

`bfsiboard.config.json`:

```json
{
  "scan": {
    "paths": ["./"],
    "exclude": [".git", "node_modules"],
    "include": [],
    "maxFindings": 1000
  },
  "report": {
    "failOn": "high",
    "output": "bfsiboard-findings.json"
  }
}
```

## Dashboard environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `BFSIBOARD_PORT` | `8080` | HTTP port |
| `BFSIBOARD_SCAN_PATH` | `/data` (in container) | Directory to scan |
| `BFSIBOARD_SCAN_INTERVAL` | `900` | Seconds between scans |

## Detection

Secrets: AWS keys, GitHub/GitLab tokens, Slack, Stripe, npm, Google, Twilio,
SendGrid, private key blocks, JWTs, database connection strings, generic
credential assignments. PII: Aadhaar, PAN, credit cards (Luhn-validated),
Indian mobile numbers, emails, IPs. Findings are **masked** by default.

## Publishing (maintainers)

```bash
# npm package
npm publish --access public            # needs npm token + @bfsiboard org access

# container image
docker buildx build --platform linux/amd64,linux/arm64 \
  --push -t ghcr.io/bfsiboard/bfsiboard:latest .
```

## Development

```bash
npm install
npm test                 # scans sample/ fixture, verifies masking
npm run scan             # scan current directory
npm start                # run dashboard server
```
