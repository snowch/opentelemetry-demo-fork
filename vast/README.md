# VAST Observability Agent

VAST Data observability integration for the [OpenTelemetry Demo](https://github.com/open-telemetry/opentelemetry-demo). Adds a web dashboard with diagnostic chat, predictive alerts, and automated root cause analysis backed by VastDB and Trino.

## Architecture

```
otel-demo services → otel-collector → Kafka (3 topics)
                                         ↓
                              observability-ingester
                                         ↓
                                      VastDB
                                         ↓
                                   Trino (queries)
                                         ↓
                              observability-agent (web UI)
```

## Prerequisites

- VAST Kafka broker with three topics: `otel-logs`, `otel-traces`, `otel-metrics`
- VAST DB bucket/schema with access credentials
- Trino connected to VAST DB
- Anthropic API key (for diagnostic chat and automated investigations)

## Quick Start

### 1. Configure environment variables

Copy the template and fill in your credentials:

```bash
cp vast/.env-template .env.override
# Edit .env.override with your VAST, Trino, Kafka, and Anthropic credentials
```

The following variables must be set in `.env.override` (they are not in `.env` since they contain deployment-specific credentials):

| Variable | Description |
|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | Kafka broker address (e.g. `172.200.204.97:9092`) |
| `VASTDB_ENDPOINT` | VastDB HTTP endpoint |
| `VASTDB_ACCESS_KEY` | VastDB access key |
| `VASTDB_SECRET_KEY` | VastDB secret key |
| `VASTDB_BUCKET` | VastDB bucket name |
| `VASTDB_SCHEMA` | VastDB schema name |
| `TRINO_HOST` | Trino server hostname |
| `TRINO_PORT` | Trino server port |
| `TRINO_USER` | Trino username |
| `TRINO_CATALOG` | Trino catalog (e.g. `vast`) |
| `TRINO_SCHEMA` | Trino schema (e.g. `csnow-db\|otel`) |
| `TRINO_VERIFY` | TLS verification (`true`/`false`) |
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM features |

### 2. Build and start

```bash
# Build the VAST observability containers
docker compose build observability-agent observability-ingester

# Start everything
docker compose up -d
```

### 3. Access the dashboard

Open http://localhost:5001 in your browser.

## Services

This integration adds three services to the docker compose stack:

| Service | Description | Port |
|---------|-------------|------|
| `observability-agent` | Web UI + predictive alerts + diagnostic chat | 5001 |
| `observability-ingester` | Kafka consumer that writes OTEL data to VastDB | - |
| `pg-latency-proxy` | PostgreSQL fault injection proxy (profile: `fault-injection`) | - |

## Diagnostic Chat

An interactive LLM-powered chat interface for support engineers to diagnose issues by querying observability data via Trino.

### Features

- Natural language queries like "ad service is slow" or "show me errors in checkout"
- Iterative diagnosis - the LLM runs multiple queries to find root causes
- Correlates logs, metrics, and traces automatically
- Full SQL support via Trino (JOINs, GROUP BY, aggregations, etc.)

### Example Queries

| Query | What it does |
|-------|--------------|
| "ad service is slow" | Investigates latency in the ad service |
| "what errors occurred in the last hour?" | Finds recent errors across all services |
| "show me failed checkouts" | Finds checkout failures with traces |
| "trace request abc123" | Shows full trace for a specific request |
| "why is the frontend timing out?" | Diagnoses timeout issues |

## Predictive Maintenance Alerts

An automated service that monitors telemetry data and generates predictive alerts for potential issues before they become critical failures.

### Features

- **Fully automated** - no user input required, runs continuously in the background
- **Self-learning baselines** - computes statistical baselines from historical data
- **Multiple detection methods**:
  - Z-score anomaly detection for error rates, latency, throughput
  - Service down detection (no telemetry for 1+ hour)
  - Configurable thresholds for warning/critical severity
- **Auto-resolution** - alerts automatically resolve when conditions normalize
- **Web UI integration** - alerts panel in sidebar, click to investigate

### Alert Types

| Alert Type | Description |
|------------|-------------|
| `error_spike` | Error rate exceeds baseline or threshold |
| `latency_degradation` | P95 latency significantly above baseline |
| `throughput_drop` | Request volume dropped significantly |
| `service_down` | No telemetry received for extended period |

### Setup

The service requires the same Trino and Anthropic credentials as the diagnostic chat. These are configured in `.env.override` (see [Quick Start](#1-configure-environment-variables)). The predictive alerts service runs automatically inside the `observability-agent` container — no separate process is needed.

### Configuration

All settings are configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DETECTION_INTERVAL` | 60 | Seconds between anomaly detection runs |
| `BASELINE_INTERVAL` | 3600 | Seconds between baseline recomputation |
| `BASELINE_WINDOW_HOURS` | 24 | Hours of historical data for baselines |
| `ANOMALY_THRESHOLD` | 3.0 | Z-score threshold for anomaly detection |
| `ERROR_RATE_WARNING` | 0.05 | Error rate (5%) that triggers warning |
| `ERROR_RATE_CRITICAL` | 0.20 | Error rate (20%) that triggers critical |
| `MIN_SAMPLES_FOR_BASELINE` | 10 | Minimum data points required for baseline |
| `ALERT_COOLDOWN_MINUTES` | 15 | Cooldown after resolution before re-alerting |

### Automated Root Cause Analysis

When alerts are created, the service can automatically investigate using an LLM to find the root cause. This requires an Anthropic API key.

**Additional environment variables for investigations:**

| Variable | Default | Description |
|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | - | API key for LLM investigations (required) |
| `INVESTIGATION_MODEL` | claude-3-5-haiku-20241022 | Model to use (Haiku recommended for cost) |
| `INVESTIGATION_MAX_TOKENS` | 1000 | Max response tokens per investigation |
| `MAX_INVESTIGATIONS_PER_HOUR` | 5 | Rate limit for API cost control |
| `INVESTIGATION_SERVICE_COOLDOWN_MINUTES` | 30 | Cooldown per service between investigations |
| `INVESTIGATE_CRITICAL_ONLY` | false | Only investigate critical severity alerts |

**How it works:**
1. When a new alert is created, the investigator checks rate limits
2. If within limits, it queries recent traces/logs/errors for the service
3. The LLM analyzes the data and identifies the root cause
4. Results are stored in `alert_investigations` table
5. Web UI displays the root cause summary with the alert

### Database Tables

The service creates/uses four tables for storing state:

- `service_baselines` - Computed statistical baselines per service/metric
- `anomaly_scores` - Historical anomaly detection results
- `alerts` - Active and resolved alerts
- `alert_investigations` - LLM-generated root cause analysis

Create tables using the DDL in `ddl.sql`.

### Web UI Integration

When running, alerts appear in the sidebar:
- Badge shows count of active alerts (color indicates severity)
- Click any alert to automatically investigate via diagnostic chat
- Alerts auto-refresh with the rest of the dashboard

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/alerts` | GET | List alerts (filter by status, severity, service) |
| `/api/alerts/<id>/acknowledge` | POST | Acknowledge an alert |
| `/api/alerts/<id>/resolve` | POST | Manually resolve an alert |
| `/api/alerts/history` | GET | Historical alert trends |
| `/api/baselines` | GET | Current service baselines |
| `/api/anomalies` | GET | Recent anomaly scores |

## Testing with Simulated Failures

To test the diagnostic capabilities, you can simulate infrastructure failures using the provided script. Run from the repo root:

```bash
# Actions: block, unblock, degrade, restore, inject, status
# Targets: postgres, redis, kafka, or any docker compose service name
vast/scripts/simulate_failure.sh <action> <target> [options]
```

### Examples

```bash
# Degrade PostgreSQL with latency proxy (uses docker compose fault-injection profile)
vast/scripts/simulate_failure.sh degrade postgres slow

# Check status (shows proxy state and measures query latency)
vast/scripts/simulate_failure.sh status postgres

# Restore PostgreSQL to normal
vast/scripts/simulate_failure.sh restore postgres

# Block PostgreSQL connections (hard failure)
vast/scripts/simulate_failure.sh block postgres
vast/scripts/simulate_failure.sh unblock postgres

# Pause Redis (simulates timeout/hang)
vast/scripts/simulate_failure.sh block redis

# Inject application failures via otel-demo API
vast/scripts/simulate_failure.sh inject payment-failure 50%
vast/scripts/simulate_failure.sh inject slow-images 5sec
vast/scripts/simulate_failure.sh inject memory-leak 100x
vast/scripts/simulate_failure.sh inject payment-failure off
```

### What to Look For

After simulating a failure, wait 30-60 seconds for effects to propagate, then ask the diagnostic chat:
- "Show me errors in the last 5 minutes"
- "What's wrong with the system?"
- "Diagnose the frontend issues"

The AI should follow the SysAdmin diagnostic process:
1. Check infrastructure health first (databases, hosts, services)
2. Look for connection errors, timeouts, and missing telemetry
3. Trace errors through the dependency chain
4. Identify the root cause component
