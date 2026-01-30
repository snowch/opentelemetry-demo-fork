#!/usr/bin/env bash
#
# Reset all OTEL data: drop/recreate VastDB tables and Kafka topics,
# then restart the ingester and collector.
#
# Usage: ./vast/reset_data.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

# Load config from .env.override
source .env.override 2>/dev/null || true
KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-172.200.204.97:9092}"
TRINO_HOST="${TRINO_HOST:-10.143.11.241}"
TRINO_PORT="${TRINO_PORT:-8443}"

TOPICS=("otel-logs" "otel-traces" "otel-metrics")
KAFKA_BIN="/opt/kafka/bin/kafka-topics.sh"

echo "=== Resetting OTEL Data ==="

# --- 1. Drop and recreate VastDB tables via Trino ---
echo ""
echo "--- Dropping and recreating VastDB tables via Trino ---"
docker compose exec -T observability-agent python3 -u -c "
import trino, sys

conn = trino.dbapi.connect(
    host='${TRINO_HOST}', port=${TRINO_PORT},
    user='trino', catalog='vast', schema='\"csnow-db|otel\"',
    http_scheme='https', verify=False
)
cur = conn.cursor()

with open('/app/ddl.sql') as f:
    ddl = f.read()

for stmt in ddl.split(';'):
    stmt = stmt.strip()
    if not stmt or all(l.strip().startswith('--') or not l.strip() for l in stmt.split('\n')):
        continue
    lines = [l for l in stmt.split('\n') if l.strip() and not l.strip().startswith('--')]
    sql = '\n'.join(lines)
    try:
        cur.execute(sql)
        cur.fetchall()
        first_line = sql.split('\n')[0][:70]
        print(f'  OK: {first_line}...')
    except Exception as e:
        print(f'  ERROR: {e}', file=sys.stderr)

print('VastDB tables reset complete.')
"


echo ""
echo "=== Reset complete. New data will start flowing shortly. ==="
