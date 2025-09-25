#!/usr/bin/env bash
set -euo pipefail


# Simple helper to run the plopsec/core-graph container in the foreground so logs stream immediately.
# You can override defaults via environment variables before calling the script, e.g.:
#   IMAGE=plopsec/core-graph:local NAME=plopsec-core-graph ./run_docker.sh --help

IMAGE="${IMAGE:-plopsec/core-graph:local}"
NAME="${NAME:-plopsec-core-graph}"
ENV_FILE="${ENV_FILE:-src/.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[warn] Env file '$ENV_FILE' not found (continuing without --env-file)." >&2
  USE_ENV_FILE=false
else
  USE_ENV_FILE=true
fi


# Remove any existing container with the same name so we can start fresh.
if docker ps -a --format '{{.Names}}' | grep -Eq "^${NAME}$"; then
  echo "[info] Removing existing container '$NAME'..." >&2
  docker rm -f "$NAME" >/dev/null
fi

# Export PORT from env file if present, else default to 3000
if $USE_ENV_FILE && grep -q '^PORT=' "$ENV_FILE"; then
  export PORT=$(grep '^PORT=' "$ENV_FILE" | head -n1 | cut -d'=' -f2-)
else
  export PORT=3000
fi

echo "[info] Running image '$IMAGE' as container '$NAME' (interactive, port $PORT)..." >&2

RUN_ARGS=(
  --name "$NAME"
  --pull=missing          # only pull if image not found locally
  --rm                    # auto remove when it exits
  -it                     # interactive + TTY so logs stream and you can Ctrl+C
  -p "$PORT:$PORT"
)

if $USE_ENV_FILE; then
  RUN_ARGS+=(--env-file "$ENV_FILE")
fi

# Pass any extra arguments given to this script after the image to the container entrypoint.
# Example: ./run_docker.sh --help
exec docker run "${RUN_ARGS[@]}" "$IMAGE" "$@"