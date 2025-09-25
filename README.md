# Plopsec Core Graph API

A Fastify API server using arangojs and Yarn. Provides endpoints for CVE and CWE data with pagination and filtering.

## Project Structure
- `app.js`: Fastify server setup and route registration
- `config.js`: Loads config from environment variables or fallback config file
- `/routes/cve.js`, `/routes/cwe.js`: API endpoints
- `/services/arango.js`: ArangoDB connection

## Setup
1. Install dependencies: `yarn install`
2. Configure environment variables as needed (see `config.js`)
3. Start the server: `node app.js`

## Configuration
Environment variables (or values from `config.default.json` if unset):
- `ARANGO_URL` ArangoDB endpoint URL
- `ARANGO_DB` Database name
- `ARANGO_USER` Database user
- `ARANGO_PASSWORD` Database password
- `PORT` Listening port (default 3000)

## Docker
A minimal multi-stage `Dockerfile` (alpine) is provided.

### Build single architecture (current machine)
```bash
docker build -t plopsec/core-graph:local .
```

### Run container
```bash
docker run --rm -p 3000:3000 \
  -e ARANGO_URL=http://host.docker.internal:8529/ \
  -e ARANGO_DB=cvemate \
  -e ARANGO_USER=cvemate_reader \
  -e ARANGO_PASSWORD=change_me \
  --name core-graph plopsec/core-graph:local
```

### Multi-arch build (amd64 + arm64)
Enable buildx (once):
```bash
docker buildx create --name multi --use --bootstrap 2>/dev/null || docker buildx use multi
```

Build and push (example):
```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t plopsec/core-graph:latest \
  -t plopsec/core-graph:$(date +%Y%m%d) \
  --push .
```

If you just want a local multi-arch image (no push):
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t plopsec/core-graph:multi --load .
```

### Healthcheck
The image includes a basic healthcheck probing `/api/stats`. Ensure that endpoint is reachable; otherwise adjust or override.

### Development vs Production notes
The container runs with `NODE_ENV=production` and a non-root user. Logging uses `pino-pretty`; if you want pure JSON logs, modify `app.js` to remove the transport in production.

## Troubleshooting
- Connection refused to ArangoDB: ensure network access (use `host.docker.internal` on macOS/Windows or `--add-host` on Linux).
- Wrong credentials: verify env values; the startup log prints a masked config table.
- Healthcheck failing: inspect container logs `docker logs core-graph`.
