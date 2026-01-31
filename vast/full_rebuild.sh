#!/usr/bin/env bash
#
# Full rebuild: tear down everything, reset data, rebuild all images
# from scratch, and bring the stack back up.
#
# Usage: ./vast/full_rebuild.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== Full Rebuild ==="
echo ""

# --- 1. Tear down all containers and volumes ---
echo "--- Stopping containers and removing volumes ---"
docker compose down -v

# --- 2. Reset VastDB tables and Kafka topics (ephemeral containers, no services needed) ---
echo ""
echo "--- Running data reset ---"
./vast/reset_data.sh

# --- 3. Rebuild all images with no cache ---
echo ""
echo "--- Building images (--no-cache) ---"
docker compose build --no-cache

# --- 4. Bring everything up ---
echo ""
echo "--- Starting all services ---"
docker compose up -d

echo ""
echo "=== Full rebuild complete. Services are starting up. ==="
echo "    Run 'docker compose logs -f' to follow logs."
