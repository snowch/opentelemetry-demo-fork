# Testing the Failure Simulator

The failure simulator orchestrates realistic failure scenarios to demonstrate predictive alerting. All scenarios are managed via REST API and visible in the web UI at `http://localhost:5000`.

## Prerequisites

```bash
# Ensure services are running
docker compose up -d

# Verify the observability agent is healthy
curl -s http://localhost:5000/api/simulation/scenarios | python3 -m json.tool
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/simulation/scenarios` | List available scenarios |
| POST | `/api/simulation/start` | Start a scenario |
| GET | `/api/simulation/status` | Poll running simulation status |
| POST | `/api/simulation/stop` | Stop and cleanup |
| GET | `/api/simulation/results/<run_id>` | Get results for a completed run |

---

## UI Overview

Before running any scenario, familiarize yourself with the key UI areas that will change during failures.

### Sidebar

The left sidebar shows three entity sections that update every 15 seconds:

- **Services** — Each service shows a status badge:
  - **Green "OK"** — healthy, no errors
  - **Yellow "N% err"** — warning, 1-10% error rate
  - **Red "N% err"** — error, >10% error rate
  - **Yellow "no data"** — no telemetry received

- **Databases** — Each database shows a span count badge (green).

- **Hosts** — Each host shows three color-coded resource metrics:
  - **CPU** — green <60%, yellow 60-80%, red >80%
  - **MEM** — green <70%, yellow 70-85%, red >85%
  - **DISK** — green <75%, yellow 75-90%, red >90%

### Main Panel (right side)

- **Recent Errors card** — Shows total error count and affected services in the last 5 minutes. Green with "0 errors" when healthy; red with expandable error list when errors exist. Clicking it expands a list of failing services and operations.

- **Predictive Alerts panel** — Shows alerts with severity badges:
  - **CRITICAL** — red left border, red text
  - **WARNING** — orange left border, orange text
  - **INFO** — cyan left border, cyan text
  - Each alert shows a category tag (ROOT CAUSE or SYMPTOM) and relative timestamp.

- **Alert Activity feed** — Time-ordered list of alert events (created, auto-resolved, investigation started, root cause found) over the last 60 minutes.

- **Predictions panel** — Resource exhaustion predictions with confidence badges:
  - **HIGH** — red badge
  - **MEDIUM** — orange badge
  - **LOW** — blue badge
  - Each shows: resource icon, current usage, threshold, hours until exhaustion, trend slope, R² value.

### Entity Drill-Down Modal

Click any service, database, or host in the sidebar to open a modal with tabs:

- **Charts** — Line/bar charts for latency, error rate, and throughput over time.
- **Traces** — Table with Time, Operation, Duration, Status columns. Error rows have red background and red "ERROR" text. Filter by time window, status, min duration.
- **Logs** — Table with Time, Severity, Message columns. Severity is color-coded: ERROR=red, WARN=orange, INFO=cyan, DEBUG=gray. Error rows have red background.
- **Metrics** — Raw metric data table.
- **Dependencies / Topology** — Service relationship graphs.

---

## Scenario 1: PostgreSQL Degradation

Progressively worsens PostgreSQL performance via `ALTER SYSTEM SET` config changes over 12 minutes.

| Time | Setting Changes |
|------|----------------|
| 0:00 | `work_mem=256kB`, `random_page_cost=20` |
| 3:00 | `work_mem=64kB`, `effective_cache_size=32MB` |
| 6:00 | `random_page_cost=100`, `effective_cache_size=1MB` |
| 9:00 | `statement_timeout=200ms` |

**Start:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "postgres_degradation"}'
```

**Verify settings changed:**
```bash
docker compose exec -T postgresql psql -U root -d otel -c "SHOW work_mem; SHOW random_page_cost; SHOW effective_cache_size;"
```

**Monitor status:**
```bash
curl -s http://localhost:5000/api/simulation/status | python3 -m json.tool
```

### Expected UI Changes

**Sidebar — Databases:**
- The `postgresql` database span count in the sidebar may decrease as queries slow down or time out.

**Sidebar — Services:**
- Services that query PostgreSQL (`product-catalog`, `product-reviews`, `checkout`) may shift from green "OK" badges to yellow/red error badges as queries start failing (especially after the `statement_timeout=200ms` step at 9:00).

**Entity Modal — Database drill-down (click `postgresql` in sidebar):**
- **Charts tab:**
  - *Avg Latency* line (purple) trends upward as `work_mem` and `effective_cache_size` shrink, forcing disk-based sorts and bad query plans.
  - *Max Latency* line (red) spikes, especially after step 3 (`random_page_cost=100`).
  - *Error Rate* line (red) rises after step 4 when `statement_timeout=200ms` causes queries to abort.
  - *Slowest Queries* table shows increasing latency values per operation. Rows with >5% error rate appear in red text.
- **Traces tab:** After step 4, rows with status "ERROR" (red background, red text) appear as queries exceed the 200ms timeout. Filter by "ERROR" status to isolate them.
- **Logs tab:** ERROR-severity log entries (red text, red row background) appear for timed-out or failed queries.

**Main Panel — Recent Errors:**
- Error count card turns red with a non-zero count. Expanding it shows `product-reviews`, `checkout`, or other DB-dependent services with their failing operations.

**Main Panel — Predictive Alerts:**
- `dependency_anomaly` or `latency_degradation` alerts may appear with CRITICAL or WARNING severity, showing the affected database and services.

**Main Panel — Predictions:**
- If the trend analysis detects sustained degradation, a prediction may appear for database-related resources with hours-until-exhaustion and confidence metrics.

**Stop and cleanup (resets all PG settings to defaults):**
```bash
curl -s -X POST http://localhost:5000/api/simulation/stop
```

**Verify cleanup:**
```bash
docker compose exec -T postgresql psql -U root -d otel -c "SHOW work_mem; SHOW random_page_cost;"
# Should show: work_mem=4MB, random_page_cost=4
```

**After stopping:** All sidebar badges should return to green "OK" within 1-2 refresh cycles (15-30 seconds). Error charts flatten back to baseline. Error count card returns to green "0 errors".

---

## Scenario 2: Cascading Payment Failure

Escalates payment service failure rate from 10% to 75% via feature flags.

| Time | Failure Rate |
|------|-------------|
| 0:00 | 10% |
| 3:00 | 25% |
| 6:00 | 50% |
| 9:00 | 75% |

**Start:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "cascading_payment"}'
```

**Verify flag changed:**
```bash
curl -s http://localhost:8080/feature/api/read | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data['flags']['paymentFailure']['defaultVariant'])"
```

### Expected UI Changes

**Sidebar — Services:**
- `payment` service badge changes from green "OK" to yellow "~10% err" immediately, then progressively to red "25% err", "50% err", "75% err" at each 3-minute step.
- `checkout` service badge turns yellow/red as payment failures cascade upstream — checkout calls payment, so its error rate rises too.
- `frontend` service may also show error badges as checkout failures propagate to user-facing requests.

**Entity Modal — Service drill-down (click `payment` in sidebar):**
- **Charts tab:**
  - *Error Rate* chart (red line with light red fill) climbs in a staircase pattern matching the 10% -> 25% -> 50% -> 75% steps.
  - *Latency* chart (cyan line) may show increasing avg latency as retries and error handling add overhead.
  - *Throughput* bar chart (cyan bars) stays roughly constant — the load generator continues sending requests.
  - *Top Operations* table: the `/charge` or payment-related operation shows a rising Error % column (red text when >5%).
- **Traces tab:** Increasing number of rows with red "ERROR" status and red row background. At 75% failure rate, roughly 3 out of 4 traces show errors. Use the status filter dropdown to select "ERROR" and see only failed traces.
- **Logs tab:** ERROR-severity entries (red text) accumulate, showing payment charge failures.

**Entity Modal — Cascade to checkout (click `checkout` in sidebar):**
- Same pattern but delayed — errors appear after payment starts failing.
- Traces show `checkout` spans that call `payment` and inherit the error status.

**Main Panel — Recent Errors:**
- Error card turns red. Expanding shows `payment`, `checkout`, and possibly `frontend` with their failing operations.

**Main Panel — Predictive Alerts:**
- `error_spike` alert appears with CRITICAL severity for the `payment` service.
- `dependency_anomaly` alert may appear identifying the cascade from `payment` to `checkout`.

**Main Panel — Alert Activity:**
- Timeline shows "Created: payment error_spike" events, and if auto-investigation is enabled, "Investigation started" and "Root cause found" entries.

**Stop:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/stop
```

**After stopping:** `paymentFailure` flag resets to `off`. Service error badges return to green "OK" within 15-30 seconds. Error rate charts drop back to zero.

---

## Scenario 3: Memory Leak Simulation

Enables recommendation service cache failure to simulate memory growth.

**Start:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "memory_leak"}'
```

**Verify flag changed:**
```bash
curl -s http://localhost:8080/feature/api/read | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data['flags']['recommendationCacheFailure']['defaultVariant'])"
# Should show: on
```

### Expected UI Changes

**Sidebar — Services:**
- `recommendation` service badge may shift to yellow/red as the service becomes slower or starts failing under memory pressure.

**Sidebar — Hosts:**
- The host running the `recommendation` container shows **MEM** metric climbing:
  - Green -> yellow (at 70%) -> red (at 85%)
  - The numeric percentage increases over time.

**Entity Modal — Host drill-down (click the affected host):**
- **Overview tab:** Memory utilization chart trends upward over the 15-minute scenario.
- **Services tab:** Shows `recommendation` as a service running on this host.

**Entity Modal — Service drill-down (click `recommendation`):**
- **Charts tab:** Latency may increase as the service struggles with memory pressure. Error rate may rise if the service starts OOMing.
- **Traces tab:** Traces may show increasing duration. If the service crashes and restarts, gaps in trace data appear.
- **Logs tab:** WARN or ERROR entries related to memory or cache failures.

**Main Panel — Predictions:**
- A memory prediction may appear: "MEM - hostname — Currently 78% -> 90% threshold in ~2.5h (slope: 0.0048/h, R²=0.892)" with a HIGH confidence red badge.

**Main Panel — Predictive Alerts:**
- `anomaly` or `trend` alerts may fire for the `recommendation` service or its host.

**Stop:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/stop
```

**After stopping:** `recommendationCacheFailure` flag resets to `off`. Memory usage stabilizes and gradually decreases. Host MEM metric returns to green.

---

## Scenario 4: Disk Fill Simulation

Writes 4.5GB temp files into the postgresql container every 2 minutes (27GB total over 12 minutes).

| Time | Cumulative Disk Written |
|------|------------------------|
| 0:00 | 4.5GB |
| 2:00 | 9.0GB |
| 4:00 | 13.5GB |
| 6:00 | 18.0GB |
| 8:00 | 22.5GB |
| 10:00 | 27.0GB |

**Start:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "disk_fill"}'
```

**Note:** This scenario uses `docker exec` inside the container, which requires the Docker socket to be mounted (via `/var/run/docker.sock`). If step 0 reports `success: false`, check that the Docker socket volume and CLI binary are available in the observability-agent container.

### Expected UI Changes

**Sidebar — Hosts:**
- The host running the `postgresql` container shows **DISK** metric climbing:
  - Green -> yellow (at 75%) -> red (at 90%)
  - The numeric percentage increases in ~4.5GB jumps every 2 minutes.

**Entity Modal — Host drill-down (click the affected host):**
- **Overview tab:** Disk utilization chart shows a clear upward staircase pattern with ~~4% jumps per step.

**Main Panel — Predictions:**
- A disk prediction appears: "DISK - hostname — Currently N% -> 90% threshold in ~Xh" with trend slope showing the fill rate. Confidence increases as more data points confirm the linear trend.

**Main Panel — Predictive Alerts:**
- `trend` alert fires when the system detects sustained disk growth heading toward the threshold.

**Stop:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/stop
```

**After stopping:** Cleanup removes all `/tmp/sim_fill_*.dat` files. DISK metric drops back to pre-simulation levels.

**Manual cleanup** (if the simulation was interrupted or cleanup didn't run):
```bash
docker exec postgresql rm -f /tmp/sim_fill_*.dat
docker exec postgresql df -h /tmp   # verify disk usage dropped
```

---

## Scenario 5: Kafka Saturation

Enables Kafka queue problems via feature flag, causing consumer lag spikes and message backlog.

**Start:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "kafka_saturation"}'
```

**Verify flag changed:**
```bash
curl -s http://localhost:8080/feature/api/read | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data['flags']['kafkaQueueProblems']['defaultVariant'])"
# Should show: on
```

### Expected UI Changes

**Sidebar — Services:**
- `fraud-detection` and `accounting` services (Kafka consumers) may show yellow/red error badges as they fall behind on processing or time out.

**Entity Modal — Service drill-down (click `fraud-detection` or `accounting`):**
- **Charts tab:** Latency charts show increasing processing times as consumer lag grows.
- **Traces tab:** Traces may show longer durations or ERROR status for message processing operations.
- **Logs tab:** WARN entries (orange text) about consumer lag or processing delays. ERROR entries (red text) if messages start failing.
- **Metrics tab:** Kafka-related metrics (consumer lag, partition offsets) show diverging values.

**Main Panel — Predictive Alerts:**
- `anomaly` alert may fire detecting unusual consumer lag patterns.
- `trend` alert may fire if lag grows steadily.

**Main Panel — Alert Activity:**
- Timeline entries for Kafka-related alerts with timestamps.

**Stop:**
```bash
curl -s -X POST http://localhost:5000/api/simulation/stop
```

**After stopping:** `kafkaQueueProblems` flag resets to `off`. Consumer lag clears as consumers catch up. Service badges return to green.

---

## General Testing Workflow

```bash
# 1. List scenarios
curl -s http://localhost:5000/api/simulation/scenarios | python3 -m json.tool

# 2. Start a scenario
curl -s -X POST http://localhost:5000/api/simulation/start \
  -H 'Content-Type: application/json' \
  -d '{"scenario": "SCENARIO_ID"}'

# 3. Poll status (repeat every 10-30s)
curl -s http://localhost:5000/api/simulation/status | python3 -m json.tool

# 4. Watch for step completions — each step shows success: true/false
#    Steps execute at the delay_seconds intervals defined in the scenario

# 5. Open the UI at http://localhost:5000 and observe:
#    - Sidebar: service/database/host status badges change color
#    - Main panel: error card turns red, alerts appear, predictions populate
#    - Click an entity to open drill-down modal with charts, traces, logs

# 6. Stop early if needed (cleanup runs automatically)
curl -s -X POST http://localhost:5000/api/simulation/stop

# 7. Get results for a completed run
curl -s http://localhost:5000/api/simulation/results/RUN_ID | python3 -m json.tool
```

### Results Endpoint

After a scenario completes (or is stopped), the results endpoint returns:

```json
{
  "run_id": "a223914a",
  "scenario_name": "postgres_degradation",
  "status": "completed",
  "started_at": "2026-01-30T12:09:00Z",
  "ended_at": "2026-01-30T12:21:00Z",
  "steps_completed": [
    {"index": 0, "label": "Reduce work_mem to 256kB", "success": true, "executed_at": "..."},
    {"index": 1, "label": "Reduce work_mem to 64kB", "success": true, "executed_at": "..."}
  ],
  "fired_alerts": [
    {"alert_id": "...", "service_name": "product-reviews", "alert_type": "dependency_anomaly", "severity": "critical"}
  ],
  "fired_predictions": [
    {"host_name": "...", "resource_type": "disk", "hours_until_exhaustion": 2.5, "confidence": "high"}
  ]
}
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `success: false` on all steps | Container can't reach target service | Check `docker compose ps` for healthy services |
| Feature flag steps fail | flagd-ui API unreachable | Verify `curl http://localhost:8080/feature/api/read` returns JSON |
| PG degradation steps fail | psycopg2 can't connect | Check `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_PASSWORD` env vars |
| Disk fill steps fail | Docker CLI not in container | `disk_fill` requires Docker socket — run simulator on host instead |
| Simulation stuck at "running" | Waiting for next step delay | Steps fire at `delay_seconds` intervals (typically 120-180s apart) |
| Can't start new simulation | Previous run still active | `POST /api/simulation/stop` first |
| Sidebar not updating | Auto-refresh interval | Sidebar refreshes every 15 seconds; wait or manually reload |
| No alerts appearing | Alert engine lag or thresholds not met | Alerts require sustained anomalies; wait for multiple steps to fire |
| Charts look flat | Time window too wide | Use the time selector in the modal to narrow to 1m or 5m |
