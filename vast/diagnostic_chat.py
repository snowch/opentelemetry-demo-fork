#!/usr/bin/env python3
"""
Diagnostic Chat Tool for Support Engineers

An interactive chat interface that uses an LLM to help diagnose issues
by querying observability data (logs, metrics, traces) stored in VastDB via Trino.

Usage:
    export ANTHROPIC_API_KEY=your_api_key
    export TRINO_HOST=trino.example.com
    export TRINO_PORT=443
    export TRINO_USER=your_user
    export TRINO_CATALOG=vast
    export TRINO_SCHEMA=otel

    python diagnostic_chat.py

Example queries:
    - "ad service ui is slow"
    - "what errors occurred in the last hour?"
    - "show me failed requests for the checkout service"
    - "trace the request with id abc123"
"""

import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*model.*is deprecated.*")

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import anthropic

try:
    from trino.dbapi import connect as trino_connect
    from trino.auth import BasicAuthentication
    TRINO_AVAILABLE = True
except ImportError:
    TRINO_AVAILABLE = False


# =============================================================================
# Configuration
# =============================================================================

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")

# Trino configuration
TRINO_HOST = os.getenv("TRINO_HOST")
TRINO_PORT = int(os.getenv("TRINO_PORT", "443"))
TRINO_USER = os.getenv("TRINO_USER", "admin")
TRINO_PASSWORD = os.getenv("TRINO_PASSWORD")
TRINO_CATALOG = os.getenv("TRINO_CATALOG", "vast")
TRINO_SCHEMA = os.getenv("TRINO_SCHEMA", "otel")
TRINO_HTTP_SCHEME = os.getenv("TRINO_HTTP_SCHEME", "https")

# Maximum rows to return from queries to avoid overwhelming context
MAX_QUERY_ROWS = 100

# =============================================================================
# Database Schema Information
# =============================================================================

SCHEMA_INFO = """
## Available Tables in VastDB

### 1. logs_otel_analytic
Log records from all services.
Columns:
- timestamp (timestamp) - When the log was emitted
- service_name (varchar) - Name of the service (e.g., 'adservice', 'frontend', 'checkoutservice')
- severity_number (integer) - Numeric severity (1-24, where higher = more severe)
- severity_text (varchar) - Severity level ('DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')
- body_text (varchar) - The log message content
- trace_id (varchar) - Associated trace ID for correlation
- span_id (varchar) - Associated span ID
- attributes_json (varchar) - JSON string of additional attributes

### 2. metrics_otel_analytic
Time-series metrics from all services.
Columns:
- timestamp (timestamp) - When the metric was recorded
- service_name (varchar) - Name of the service
- metric_name (varchar) - Name of the metric (e.g., 'http.server.duration', 'runtime.cpython.cpu_time')
- metric_unit (varchar) - Unit of measurement ('ms', 's', 'By', '1')
- value_double (double) - The metric value
- attributes_flat (varchar) - Comma-separated key=value pairs of attributes

**IMPORTANT:** This table has NO `host_name` or `container_name` columns. Host and container names are embedded inside `attributes_flat` as key=value pairs (e.g., `host.name=abc123`, `container.name=kafka`). You MUST use `attributes_flat LIKE '%host.name=...%'` or `attributes_flat LIKE '%container.name=...%'` to filter by host or container. Do NOT use `host_name` or `container_name` as column names in queries against this table.

### 3. traces_otel_analytic
Distributed trace spans showing request flow across services.
Columns:
- trace_id (varchar) - Unique trace identifier (groups related spans)
- span_id (varchar) - Unique span identifier
- parent_span_id (varchar) - Parent span ID (empty for root spans)
- start_time (timestamp) - When the span started
- duration_ns (bigint) - Duration in nanoseconds
- service_name (varchar) - Service that created this span
- span_name (varchar) - Operation name (e.g., 'GET /api/products', 'SELECT')
- span_kind (varchar) - Type: 'SERVER', 'CLIENT', 'INTERNAL', 'PRODUCER', 'CONSUMER'
- status_code (varchar) - 'OK', 'ERROR', or 'UNSET'
- http_status (integer) - HTTP response status code (if applicable)
- db_system (varchar) - Database system if this is a DB span (e.g., 'redis', 'postgresql')
- attributes_json (varchar) - JSON string of ALL span attributes. Use LIKE queries to search. Common keys include:
  - messaging.system (e.g., 'kafka', 'rabbitmq'), messaging.destination.name (topic/queue name), messaging.operation
  - rpc.system, rpc.service, rpc.method
  - net.peer.name, net.peer.port
  - http.method, http.url, http.target
  - db.statement, db.name
  Example: `WHERE attributes_json LIKE '%"messaging.system":"kafka"%'`

### 4. span_events_otel_analytic
Events attached to spans, including exceptions.
Columns:
- timestamp (timestamp) - When the event occurred
- trace_id (varchar) - Associated trace ID
- span_id (varchar) - Associated span ID
- service_name (varchar) - Service name
- span_name (varchar) - Parent span's operation name
- event_name (varchar) - Event name (e.g., 'exception', 'message')
- event_attributes_json (varchar) - JSON attributes
- exception_type (varchar) - Exception class name (if exception event)
- exception_message (varchar) - Exception message
- exception_stacktrace (varchar) - Full stack trace
- gen_ai_system (varchar) - GenAI system if applicable
- gen_ai_operation (varchar) - GenAI operation name
- gen_ai_request_model (varchar) - Model used
- gen_ai_usage_prompt_tokens (integer) - Prompt tokens used
- gen_ai_usage_completion_tokens (integer) - Completion tokens used

### 5. span_links_otel_analytic
Links between spans (e.g., async message producers/consumers).
Columns:
- trace_id (varchar) - Source trace ID
- span_id (varchar) - Source span ID
- service_name (varchar) - Service name
- span_name (varchar) - Span operation name
- linked_trace_id (varchar) - Linked trace ID
- linked_span_id (varchar) - Linked span ID
- linked_trace_state (varchar) - W3C trace state
- link_attributes_json (varchar) - JSON attributes

### 6. topology_services
Pre-computed service registry with health metrics (refreshed periodically).
Columns:
- service_name (varchar) - Service or database name
- service_type (varchar) - 'application', 'database', or 'infrastructure'
- span_count (bigint) - Total spans in recent window
- error_pct (double) - Error percentage
- avg_latency_ms (double) - Average latency in ms
- last_seen (timestamp) - Last activity time
- updated_at (timestamp) - When this row was last refreshed

### 7. topology_dependencies
Pre-computed service-to-service and service-to-database call relationships.
Columns:
- source_service (varchar) - Calling service name
- target_service (varchar) - Called service or database name
- dependency_type (varchar) - 'service' or 'database'
- call_count (bigint) - Number of calls in recent window
- avg_latency_ms (double) - Average call latency in ms
- error_pct (double) - Error percentage of calls
- last_seen (timestamp) - Last call time
- updated_at (timestamp) - When this row was last refreshed

### 8. topology_hosts
Host registry with current system resource metrics.
Columns:
- host_name (varchar) - Hostname
- os_type (varchar) - Operating system type (e.g., 'linux')
- cpu_pct (double) - CPU utilization percentage
- memory_pct (double) - Memory utilization percentage
- disk_pct (double) - Disk utilization percentage
- last_seen (timestamp) - Last metric report time
- updated_at (timestamp) - When this row was last refreshed

### 9. topology_host_services
Mapping of which services run on which hosts.
Columns:
- host_name (varchar) - Hostname
- service_name (varchar) - Service running on this host
- source (varchar) - Discovery source: 'traces' or 'metrics'
- data_point_count (bigint) - Number of data points observed
- last_seen (timestamp) - Last observation time
- updated_at (timestamp) - When this row was last refreshed

### 10. topology_database_hosts
Mapping of which databases run on which hosts.
Columns:
- db_system (varchar) - Database system name (e.g., 'postgresql', 'redis')
- host_name (varchar) - Host running this database
- last_seen (timestamp) - Last observation time
- updated_at (timestamp) - When this row was last refreshed

### 11. topology_containers
Pre-computed container resource snapshot (refreshed periodically).
Columns:
- container_name (varchar) - Container name
- cpu_pct (double) - CPU usage percentage
- memory_pct (double) - Memory usage percentage
- memory_usage_mb (double) - Memory usage in MB
- last_seen (timestamp) - Last metric report time
- updated_at (timestamp) - When this row was last refreshed

### 12. alerts
Generated alerts with severity and status tracking.
Alert types include symptom-based ('error_spike', 'latency_degradation', 'throughput_drop', 'anomaly', 'trend', 'service_down') and root-cause ('dependency_anomaly', 'exception_surge', 'new_exception_type').
Columns:
- alert_id (varchar) - Unique alert identifier
- created_at (timestamp) - When the alert was created
- updated_at (timestamp) - Last update time
- service_name (varchar) - Affected service
- alert_type (varchar) - Type of alert (see above)
- severity (varchar) - 'info', 'warning', 'critical'
- title (varchar) - Alert title
- description (varchar) - Alert description
- metric_type (varchar) - Which metric triggered the alert
- current_value (double) - Current metric value
- threshold_value (double) - Threshold that was exceeded
- baseline_value (double) - Normal baseline value
- z_score (double) - Statistical z-score of the anomaly
- status (varchar) - 'active', 'acknowledged', 'resolved', 'archived'
- resolved_at (timestamp) - When the alert was resolved
- auto_resolved (boolean) - Whether it was auto-resolved

### 13. alert_investigations
LLM-powered root cause analysis results for alerts.
Columns:
- investigation_id (varchar) - Unique investigation identifier
- alert_id (varchar) - Associated alert ID (join with alerts table)
- investigated_at (timestamp) - When the investigation ran
- service_name (varchar) - Investigated service
- alert_type (varchar) - Type of the investigated alert
- model_used (varchar) - LLM model used for analysis
- root_cause_summary (varchar) - Summary of identified root cause
- recommended_actions (varchar) - Suggested remediation steps
- supporting_evidence (varchar) - JSON with relevant traces/errors found
- queries_executed (integer) - Number of SQL queries the LLM ran
- tokens_used (integer) - Total LLM tokens consumed

## Common Service Names (OpenTelemetry Demo)
- frontend - Web frontend
- adservice - Advertisement service
- cartservice - Shopping cart
- checkoutservice - Checkout processing
- currencyservice - Currency conversion
- emailservice - Email notifications
- paymentservice - Payment processing
- productcatalogservice - Product catalog
- recommendationservice - Product recommendations
- shippingservice - Shipping calculations
- quoteservice - Quote generation

## Infrastructure Metrics & Container Logs

The OTel Collector scrapes infrastructure-level metrics and container logs that complement application traces and logs. Use these to investigate host health, broker issues, and resource exhaustion.

### Container Metrics (docker_stats receiver)
Metric names start with `container.`. The `attributes_flat` column contains `container.name=<name>` (e.g., `container.name=kafka`, `container.name=postgres`, `container.name=valkey-cart`).

Key metrics:
- `container.cpu.percent` — CPU usage percentage per container
- `container.memory.usage.total` — Memory bytes used
- `container.memory.percent` — Memory usage percentage
- `container.blockio.io_service_bytes_recursive.read` / `.write` — Disk I/O bytes
- `container.network.io.usage.rx_bytes` / `.tx_bytes` — Network I/O

Example queries:
```sql
-- CPU and memory for all containers in last 5 minutes
SELECT
    SUBSTR(attributes_flat,
           POSITION('container.name=' IN attributes_flat) + 15,
           CASE WHEN POSITION(',' IN SUBSTR(attributes_flat, POSITION('container.name=' IN attributes_flat) + 15)) > 0
                THEN POSITION(',' IN SUBSTR(attributes_flat, POSITION('container.name=' IN attributes_flat) + 15)) - 1
                ELSE 50 END) as container,
    metric_name,
    ROUND(AVG(value_double), 2) as avg_value,
    ROUND(MAX(value_double), 2) as max_value
FROM metrics_otel_analytic
WHERE metric_name IN ('container.cpu.percent', 'container.memory.percent')
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY 1, metric_name
ORDER BY max_value DESC
```

```sql
-- Check a specific container (e.g., kafka)
SELECT metric_name, ROUND(AVG(value_double), 2) as avg_val, ROUND(MAX(value_double), 2) as max_val
FROM metrics_otel_analytic
WHERE attributes_flat LIKE '%container.name=kafka%'
  AND metric_name IN ('container.cpu.percent', 'container.memory.percent', 'container.memory.usage.total')
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY metric_name
```

### Kafka Broker Metrics (kafkametrics receiver)
Metric names start with `kafka.`. These come from the Kafka broker itself, not application-level producer/consumer spans.

Key metrics:
- `kafka.brokers` — Number of brokers in the cluster
- `kafka.consumer_group.lag` — Consumer group lag (messages behind)
- `kafka.consumer_group.offset` — Current consumer group offset
- `kafka.partition.current_offset` — Latest offset per partition
- `kafka.partition.oldest_offset` — Oldest available offset per partition
- `kafka.partition.replicas` — Replica count per partition
- `kafka.partition.replicas_in_sync` — In-sync replica count
- `kafka.topic.partitions` — Number of partitions per topic

Example queries:
```sql
-- Consumer group lag (high lag = consumers falling behind)
SELECT attributes_flat, ROUND(AVG(value_double), 2) as avg_lag, ROUND(MAX(value_double), 2) as max_lag
FROM metrics_otel_analytic
WHERE metric_name = 'kafka.consumer_group.lag'
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY attributes_flat
ORDER BY max_lag DESC
LIMIT 20
```

```sql
-- Kafka broker count and partition health
SELECT metric_name, ROUND(AVG(value_double), 2) as avg_val, COUNT(*) as samples
FROM metrics_otel_analytic
WHERE metric_name IN ('kafka.brokers', 'kafka.partition.replicas_in_sync', 'kafka.partition.replicas')
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY metric_name
```

### Host Metrics (hostmetrics receiver)
Metric names start with `system.`. The `attributes_flat` column contains `host.name=<hostname>`.

Key metrics:
- `system.cpu.utilization` — CPU utilization ratio (0.0 to 1.0), broken down by `state` in attributes_flat. States include `idle`, `user`, `system`, `iowait`, etc. To get actual CPU busy percentage, filter for `state=idle` and compute `(1 - value) * 100`, or filter for non-idle states (`user`, `system`) and sum them. **Do NOT report the idle value as CPU usage — 98% idle means only 2% busy.**
- `system.memory.utilization` — Memory utilization (0.0 to 1.0)
- `system.memory.limit` — Total memory in bytes
- `system.filesystem.utilization` — Disk utilization (0.0 to 1.0)
- `system.network.io` — Network bytes transferred
- `system.disk.operations` — Disk IOPS
- `system.paging.usage` — Swap usage
- `system.uptime` — Host uptime in seconds

Example queries:
```sql
-- Host CPU busy percentage (subtract idle from 100%)
SELECT ROUND((1 - AVG(value_double)) * 100, 2) as avg_cpu_busy_pct,
       ROUND((1 - MIN(value_double)) * 100, 2) as max_cpu_busy_pct
FROM metrics_otel_analytic
WHERE metric_name = 'system.cpu.utilization'
  AND attributes_flat LIKE '%state=idle%'
  AND timestamp > NOW() - INTERVAL '5' MINUTE

-- Host memory utilization
SELECT ROUND(AVG(value_double) * 100, 2) as avg_pct, ROUND(MAX(value_double) * 100, 2) as max_pct
FROM metrics_otel_analytic
WHERE metric_name = 'system.memory.utilization'
  AND timestamp > NOW() - INTERVAL '5' MINUTE
```

```sql
-- Disk utilization (watch for >85%)
SELECT attributes_flat, ROUND(AVG(value_double) * 100, 2) as avg_pct
FROM metrics_otel_analytic
WHERE metric_name = 'system.filesystem.utilization'
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY attributes_flat
ORDER BY avg_pct DESC
LIMIT 10
```

### Container Logs
Docker container stdout/stderr logs are ingested with `service_name = 'container-logs'`. Use these to find Kafka broker errors, Postgres errors, or other infrastructure component logs that are NOT part of the OTel SDK pipeline.

Example queries:
```sql
-- Recent container log errors (Kafka, Postgres, etc.)
SELECT body_text, timestamp
FROM logs_otel_analytic
WHERE service_name = 'container-logs'
  AND timestamp > NOW() - INTERVAL '10' MINUTE
  AND (body_text LIKE '%ERROR%' OR body_text LIKE '%FATAL%' OR body_text LIKE '%WARN%')
ORDER BY timestamp DESC
LIMIT 30
```

```sql
-- Kafka broker logs specifically
SELECT body_text, timestamp
FROM logs_otel_analytic
WHERE service_name = 'container-logs'
  AND (body_text LIKE '%kafka%' OR body_text LIKE '%broker%' OR body_text LIKE '%partition%')
  AND timestamp > NOW() - INTERVAL '10' MINUTE
ORDER BY timestamp DESC
LIMIT 20
```

```sql
-- Postgres container logs
SELECT body_text, timestamp
FROM logs_otel_analytic
WHERE service_name = 'container-logs'
  AND (body_text LIKE '%postgres%' OR body_text LIKE '%FATAL%' OR body_text LIKE '%could not%')
  AND timestamp > NOW() - INTERVAL '10' MINUTE
ORDER BY timestamp DESC
LIMIT 20
```

### Infrastructure Correlation Guide

When investigating an issue, cross-reference these data sources:

| Application Signal | Infrastructure Check | Query Filter |
|---|---|---|
| Kafka consumer error in traces | Kafka container CPU/memory | `attributes_flat LIKE '%container.name=kafka%'` |
| Kafka consumer error in traces | Kafka broker metrics (lag, replicas) | `metric_name LIKE 'kafka.%'` |
| Kafka consumer error in traces | Kafka broker container logs | `service_name = 'container-logs' AND body_text LIKE '%kafka%'` |
| Database connection timeout | Postgres container CPU/memory | `attributes_flat LIKE '%container.name=postgres%'` |
| Database connection timeout | Postgres container logs | `service_name = 'container-logs' AND body_text LIKE '%postgres%'` |
| Redis timeout | Valkey container CPU/memory | `attributes_flat LIKE '%container.name=valkey-cart%'` |
| High latency across services | Host CPU/memory/disk | `metric_name LIKE 'system.%'` |
| Service not emitting telemetry | Container metrics (is it running?) | `attributes_flat LIKE '%container.name=<service>%'` |

**Container name to service mapping:**
- `kafka` → Kafka broker (messaging infrastructure)
- `postgres` → PostgreSQL database
- `valkey-cart` → Valkey/Redis cache for cart service
- `otel-col` or `otelcol` → OpenTelemetry Collector
- Service containers typically match their service name (e.g., `accountingservice`, `checkoutservice`)

**IMPORTANT:** When you find a Kafka or database error in application traces, you MUST immediately check:
1. The relevant container's CPU/memory (`container.cpu.percent`, `container.memory.percent`)
2. The relevant broker/database metrics (`kafka.consumer_group.lag`, `kafka.partition.replicas_in_sync`)
3. The relevant container logs (`service_name = 'container-logs'`)
4. Host-level resources (`system.cpu.utilization`, `system.memory.utilization`, `system.filesystem.utilization`)

## Query Tips
- Use duration_ns / 1000000.0 to convert to milliseconds
- Filter by time: timestamp > NOW() - INTERVAL '1' HOUR
- For slow requests: ORDER BY duration_ns DESC
- For errors: WHERE status_code = 'ERROR' OR severity_text = 'ERROR'
- Join traces with logs using trace_id for full context

## CRITICAL Trino SQL Syntax Rules
- **Timestamp literals MUST use a space, NOT 'T'**: `TIMESTAMP '2026-01-31 18:42:00'` (correct) vs `TIMESTAMP '2026-01-31T18:42:00'` (WRONG — Trino rejects this)
- BETWEEN with timestamps: `timestamp BETWEEN TIMESTAMP '2026-01-31 18:40:00' AND TIMESTAMP '2026-01-31 18:45:00'`
- NO semicolons at the end of queries
- Interval syntax: `INTERVAL '15' MINUTE` (quoted number, unquoted unit)
- **GROUP BY column aliases are NOT allowed in Trino.** Use positional references instead:
  `GROUP BY 1, 2` (refers to 1st and 2nd SELECT columns). NEVER write `GROUP BY my_alias` — it will fail with COLUMN_NOT_FOUND.
  Similarly for ORDER BY with computed columns, prefer positional references: `ORDER BY 3 DESC`
- When investigating a specific trace_id, query it WITHOUT a time filter to get all spans: `WHERE trace_id = '...'`
- To query a time window around a known event, use BETWEEN with TIMESTAMP literals (space-separated, not T)
"""

SYSTEM_PROMPT = f"""You are an expert Site Reliability Engineer (SRE) assistant helping support engineers diagnose issues in a distributed system. You have access to observability data (logs, metrics, and traces) stored in VastDB.

{SCHEMA_INFO}

## Intelligent Time Window Handling

Choose the appropriate time window based on the user's question:

**For "what's wrong NOW?" questions** (current issues, recent errors):
- Default to last 15 minutes: `INTERVAL '15' MINUTE`
- Example: "show me errors", "why is X slow?", "what's the health of Y?"

**For "WHEN did X happen?" questions** (finding historical events):
- Start with last hour, expand if needed: `INTERVAL '1' HOUR`, then `'6' HOUR`, then `'24' HOUR`
- Example: "when did postgres last have issues?", "when did errors start?"

**For "has X been happening?" questions** (trend analysis):
- Use longer windows: `INTERVAL '6' HOUR` or `'24' HOUR`
- Compare time periods to detect changes
- Example: "has the frontend been slow today?", "any recurring issues?"

**ALWAYS:**
- Tell the user what time window you used: "Looking at the last 15 minutes..."
- If no results found, offer to search a wider window: "I found nothing in the last 15 minutes. Would you like me to check the last hour?"
- For trend questions, show data across multiple time buckets

## Your Approach - ALWAYS DRILL TO ROOT CAUSE

When a user reports an issue, your PRIMARY GOAL is to find the ROOT CAUSE, not just the symptoms. Surface-level errors (like 504 timeouts or gateway errors) are SYMPTOMS - you must trace them back to their source.

### CRITICAL: AUTOMATIC FOLLOW-THROUGH ON EVERY LEAD

**NEVER stop after finding the first error and wait for the user to ask you to dig deeper. YOU MUST automatically follow every lead to its root cause in a SINGLE response.**

When you discover an error that points to a dependency, you MUST IMMEDIATELY investigate that dependency in the same response — do NOT present partial findings and wait for the user to prompt you. For example:

- You find a Kafka consumer error → IMMEDIATELY check: Kafka broker host health (CPU, memory, disk via metrics), other services using the same topic, whether producers are succeeding
- You find a database connection error → IMMEDIATELY check: database span latency and error rates, host metrics for the database host, other services using the same database
- You find a timeout to another service → IMMEDIATELY check: that service's error rate, its downstream dependencies, host health
- You find a message queue issue → IMMEDIATELY check: the broker's host resources, all producers and consumers on that topic, whether the issue correlates with database or host problems

**The user should NEVER have to ask "can you check the broker?" or "what about the host?" — you must do this automatically.** Your investigation is not complete until you have traced the problem to the deepest infrastructure component (host, database, or external dependency).

### MANDATORY FIRST STEP - Check Infrastructure Health

**BEFORE analyzing application errors, ALWAYS run these infrastructure health checks FIRST:**

```sql
-- 1. Check if ALL databases are healthy (critical!)
SELECT db_system,
       COUNT(*) as span_count,
       SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
       MAX(start_time) as last_seen
FROM traces_otel_analytic
WHERE db_system IS NOT NULL AND db_system != ''
  AND start_time > NOW() - INTERVAL '5' MINUTE
GROUP BY db_system
```

```sql
-- 2. Check for connection/infrastructure errors in exceptions
SELECT service_name, exception_type, exception_message, COUNT(*) as occurrences
FROM span_events_otel_analytic
WHERE timestamp > NOW() - INTERVAL '5' MINUTE
  AND (exception_message LIKE '%connection%'
       OR exception_message LIKE '%timeout%'
       OR exception_message LIKE '%refused%'
       OR exception_message LIKE '%FATAL%'
       OR exception_message LIKE '%unavailable%'
       OR exception_message LIKE '%unreachable%'
       OR exception_message LIKE '%failed to connect%'
       OR exception_message LIKE '%no route to host%'
       OR exception_message LIKE '%network%')
GROUP BY service_name, exception_type, exception_message
ORDER BY occurrences DESC
```

```sql
-- 3. Check for infrastructure errors in logs
SELECT service_name, body_text, COUNT(*) as occurrences
FROM logs_otel_analytic
WHERE timestamp > NOW() - INTERVAL '5' MINUTE
  AND severity_text IN ('ERROR', 'FATAL', 'WARN')
  AND (body_text LIKE '%connection%'
       OR body_text LIKE '%refused%'
       OR body_text LIKE '%FATAL%'
       OR body_text LIKE '%timeout%'
       OR body_text LIKE '%unavailable%'
       OR body_text LIKE '%failed%')
GROUP BY service_name, body_text
ORDER BY occurrences DESC
LIMIT 20
```

```sql
-- 4. Check for services that STOPPED emitting metrics (critical health signal!)
SELECT service_name,
       SUM(CASE WHEN timestamp > NOW() - INTERVAL '2' MINUTE THEN 1 ELSE 0 END) as last_2min,
       SUM(CASE WHEN timestamp BETWEEN NOW() - INTERVAL '10' MINUTE AND NOW() - INTERVAL '5' MINUTE THEN 1 ELSE 0 END) as earlier_5min,
       MAX(timestamp) as last_metric_time
FROM metrics_otel_analytic
WHERE timestamp > NOW() - INTERVAL '10' MINUTE
GROUP BY service_name
ORDER BY last_2min ASC, earlier_5min DESC
```

```sql
-- 5. Check host health - are hosts still reporting system metrics?
SELECT
    CASE
        WHEN attributes_flat LIKE '%host.name=%' THEN
            SUBSTR(attributes_flat,
                   POSITION('host.name=' IN attributes_flat) + 10,
                   CASE
                       WHEN POSITION(',' IN SUBSTR(attributes_flat, POSITION('host.name=' IN attributes_flat) + 10)) > 0
                       THEN POSITION(',' IN SUBSTR(attributes_flat, POSITION('host.name=' IN attributes_flat) + 10)) - 1
                       ELSE 50
                   END)
        ELSE 'unknown'
    END as host_name,
    COUNT(*) as metric_count,
    MAX(timestamp) as last_seen
FROM metrics_otel_analytic
WHERE metric_name IN ('system.cpu.utilization', 'system.memory.utilization')
  AND timestamp > NOW() - INTERVAL '5' MINUTE
GROUP BY 1
ORDER BY last_seen ASC
```

**INTERPRET THE RESULTS - Follow the SysAdmin Diagnostic Process:**

1. **Check for COMPLETE OUTAGES first:**
   - Database with 0 spans in last 5 min → DATABASE IS DOWN
   - Service with last_2min=0 but earlier_5min>0 → SERVICE JUST WENT DOWN
   - Host with old last_seen → HOST MAY BE DOWN

2. **Check for CONNECTIVITY issues:**
   - "connection refused" → Target service is DOWN or not listening
   - "timeout" → Target service is OVERLOADED or network issue
   - "unreachable" / "no route" → NETWORK issue
   - "FATAL" → Critical failure in the target component

3. **Check for DEGRADATION:**
   - Service with very low metrics vs earlier → SERVICE IS DEGRADED
   - High error counts concentrated in specific services → Partial failure
   - Slow response times → Resource exhaustion or bottleneck

4. **Identify the ROOT CAUSE component:**
   - Which component is mentioned in error messages?
   - Which service/database stopped responding FIRST?
   - Follow the dependency chain - the deepest failing component is usually the cause

5. **Common root causes to check:**
   - Databases: PostgreSQL, Redis, MongoDB, MySQL - check db_system spans
   - Message queues: Kafka, RabbitMQ - use attributes_json to investigate:
     - Find Kafka spans: `WHERE attributes_json LIKE '%messaging.system%kafka%'`
     - Filter by topic: `WHERE attributes_json LIKE '%messaging.destination.name%<topic>%'`
     - Use `span_kind IN ('PRODUCER', 'CONSUMER')` to identify messaging spans
     - Use `span_links_otel_analytic` to correlate producer→consumer flows via linked trace/span IDs
     - CRITICAL: If PRODUCER spans exist but no matching CONSUMER spans, consumers may be down (silent failure — same pattern as databases)
   - External services: HTTP client errors to external APIs
   - Infrastructure: Host down, network partition, resource exhaustion

### CRITICAL: When Investigating a Specific Trace ID

When a user asks you to investigate a specific trace_id, you MUST follow ALL of these steps IN ORDER.
Do NOT skip any step. Do NOT conclude until all steps are done.

1. **Get the full trace** (no time filter): `WHERE trace_id = '...' ORDER BY start_time`
2. **Get exceptions**: Query span_events_otel_analytic for that trace_id
3. **Extract the timestamp** from the trace's start_time (e.g., `2026-01-31 18:42:24`)
4. **MANDATORY — run ALL THREE of these queries** (they have different attribute filters so they CANNOT be combined):

Run these as SEPARATE queries (different metrics have different attribute filters):

```sql
-- Query A: PostgreSQL database-specific disk metrics (uses db.system= filter)
SELECT metric_name, attributes_flat,
       ROUND(AVG(value_double) * 100, 2) as avg_pct,
       ROUND(MAX(value_double) * 100, 2) as max_pct
FROM metrics_otel_analytic
WHERE metric_name IN ('postgresql.filesystem.utilization', 'postgresql.filesystem.usage')
  AND attributes_flat LIKE '%db.system=postgresql%'
  AND timestamp BETWEEN TIMESTAMP '..start-5min..' AND TIMESTAMP '..start+5min..'
GROUP BY metric_name, attributes_flat
ORDER BY max_pct DESC
```

```sql
-- Query B: Container metrics (uses container.name= filter)
SELECT metric_name, attributes_flat,
       ROUND(AVG(value_double), 2) as avg_val,
       ROUND(MAX(value_double), 2) as max_val
FROM metrics_otel_analytic
WHERE metric_name IN ('container.cpu.percent', 'container.memory.percent')
  AND attributes_flat LIKE '%container.name=postgres%'
  AND timestamp BETWEEN TIMESTAMP '..start-5min..' AND TIMESTAMP '..start+5min..'
GROUP BY metric_name, attributes_flat
```

```sql
-- Query C: Host-level system metrics (NO attribute filter needed — check all hosts)
SELECT metric_name,
       ROUND(AVG(value_double) * 100, 2) as avg_pct,
       ROUND(MAX(value_double) * 100, 2) as max_pct
FROM metrics_otel_analytic
WHERE metric_name IN ('system.filesystem.utilization', 'system.memory.utilization')
  AND timestamp BETWEEN TIMESTAMP '..start-5min..' AND TIMESTAMP '..start+5min..'
GROUP BY metric_name
ORDER BY max_pct DESC
```

**You MUST run Query A even if Query B or C returns results.** Database disk pressure (postgresql.filesystem.utilization near 1.0) is the #1 cause of database connection errors and EndOfStreamExceptions.

5. **Check the database host health** using topology_database_hosts to find the host, then query its metrics
6. **Look for correlated errors** in other services during the same time window

**IMPORTANT metric naming conventions:**
- Database-specific metrics: `postgresql.filesystem.utilization`, `postgresql.filesystem.usage` (filter by `db.system=postgresql` in attributes_flat)
- Container metrics: `container.cpu.percent`, `container.memory.percent` (filter by `container.name=postgres` in attributes_flat)
- Host system metrics: `system.filesystem.utilization`, `system.cpu.utilization`, `system.memory.utilization` (filter by `host.name=...` in attributes_flat)
- Do NOT assume the host.name matches the db_system name — use topology_database_hosts to look it up

**NEVER conclude "transient network issue" or "temporary glitch" without first checking disk, memory, CPU, and filesystem metrics around the error time.** Connection errors, stream exceptions, and I/O errors are almost always caused by resource exhaustion (disk full, OOM, CPU saturation) — the metrics will tell you which one.

### Root Cause Analysis Methodology

1. **When you see an error, ALWAYS get a specific trace_id and follow it**:
   - Get the trace_id from an error span
   - Query ALL spans in that trace: `SELECT * FROM traces_otel_analytic WHERE trace_id = 'xxx' ORDER BY start_time`
   - Look for the DEEPEST span in the call chain - that's usually where the real problem is

2. **Check for database/infrastructure issues EARLY**:
   - Query for db_system spans: `WHERE db_system IS NOT NULL AND db_system != ''`
   - Look for spans with db_system = 'postgresql', 'redis', 'mongodb', etc.
   - Database timeouts or connection failures are often the ROOT CAUSE of cascading failures
   - Long-running database spans (high duration_ns) indicate database problems

3. **CRITICAL: Check for MISSING telemetry (silent failures)**:
   - If a database/service is DOWN or PAUSED, it WON'T emit telemetry!
   - ABSENCE of expected db_system spans is a RED FLAG
   - Compare: Are there postgresql/redis spans in the last 5 minutes? If services normally use a DB but there are NO db spans, the DB may be down!
   - Look for CLIENT spans trying to connect to databases that have no corresponding SERVER spans
   - Timeouts WITHOUT any downstream spans = the downstream service is unreachable/dead
   - **CHECK METRICS TOO**: If a service stops emitting metrics, it's likely down
   - Compare metric counts between recent period vs earlier - a sharp drop indicates failure

4. **Follow the dependency chain**:
   - Use parent_span_id to trace the call hierarchy
   - The root cause is usually in a LEAF span (no children), not in parent spans
   - Timeouts in parent services are usually CAUSED BY slow/failed downstream dependencies
   - If a trace STOPS at a certain point with no child spans, that's where the failure is

5. **Look for patterns that indicate infrastructure issues**:
   - Multiple services failing simultaneously = shared dependency (database, cache, message queue)
   - Timeouts without errors = blocked/hung service or network issue
   - Connection errors = service is down or unreachable
   - NO SPANS from a service that should be active = service is completely down

### Critical Queries to Run

When investigating errors or slowness:

1. **First, get recent errors with trace IDs**:
```sql
SELECT trace_id, service_name, span_name, status_code, duration_ns/1000000.0 as ms
FROM traces_otel_analytic
WHERE status_code = 'ERROR' AND start_time > NOW() - INTERVAL '5' MINUTE
LIMIT 10
```

2. **Then, for each trace_id, get the FULL trace to find root cause**:
```sql
SELECT service_name, span_name, span_kind, status_code, db_system,
       duration_ns/1000000.0 as ms, parent_span_id
FROM traces_otel_analytic
WHERE trace_id = 'xxx'
ORDER BY start_time
```

3. **IMPORTANT: Check if databases are responding AT ALL**:
```sql
SELECT db_system, COUNT(*) as span_count, MAX(start_time) as last_seen
FROM traces_otel_analytic
WHERE db_system IS NOT NULL AND db_system != ''
  AND start_time > NOW() - INTERVAL '10' MINUTE
GROUP BY db_system
```
If a database that should be active has ZERO spans or last_seen is old, IT MAY BE DOWN!

4. **Check for database issues specifically**:
```sql
SELECT service_name, span_name, db_system, status_code, duration_ns/1000000.0 as ms
FROM traces_otel_analytic
WHERE db_system IS NOT NULL AND db_system != ''
  AND start_time > NOW() - INTERVAL '5' MINUTE
ORDER BY duration_ns DESC
LIMIT 20
```

5. **Look for the slowest/stuck operations**:
```sql
SELECT service_name, span_name, db_system, status_code, duration_ns/1000000.0 as ms
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '5' MINUTE
ORDER BY duration_ns DESC
LIMIT 20
```

6. **Check span_events for exceptions with details**:
```sql
SELECT service_name, span_name, exception_type, exception_message
FROM span_events_otel_analytic
WHERE exception_type IS NOT NULL AND exception_type != ''
  AND timestamp > NOW() - INTERVAL '5' MINUTE
LIMIT 20
```

7. **Look for connection/timeout errors in exception messages**:
```sql
SELECT service_name, exception_type, exception_message, COUNT(*) as occurrences
FROM span_events_otel_analytic
WHERE timestamp > NOW() - INTERVAL '5' MINUTE
  AND (exception_message LIKE '%connection%' OR exception_message LIKE '%timeout%'
       OR exception_message LIKE '%refused%' OR exception_message LIKE '%unreachable%')
GROUP BY service_name, exception_type, exception_message
ORDER BY occurrences DESC
```

8. **Check for metrics drop-off (services that stopped reporting)**:
```sql
SELECT service_name, COUNT(*) as metric_count, MAX(timestamp) as last_metric
FROM metrics_otel_analytic
WHERE timestamp > NOW() - INTERVAL '10' MINUTE
GROUP BY service_name
ORDER BY last_metric ASC
```
Services with old last_metric or low metric_count compared to others may be DOWN!

9. **Compare recent vs earlier metric volume to detect sudden drops**:
```sql
SELECT service_name,
       SUM(CASE WHEN timestamp > NOW() - INTERVAL '2' MINUTE THEN 1 ELSE 0 END) as last_2min,
       SUM(CASE WHEN timestamp BETWEEN NOW() - INTERVAL '10' MINUTE AND NOW() - INTERVAL '8' MINUTE THEN 1 ELSE 0 END) as earlier_2min
FROM metrics_otel_analytic
WHERE timestamp > NOW() - INTERVAL '10' MINUTE
GROUP BY service_name
HAVING SUM(CASE WHEN timestamp > NOW() - INTERVAL '2' MINUTE THEN 1 ELSE 0 END) = 0
   AND SUM(CASE WHEN timestamp BETWEEN NOW() - INTERVAL '10' MINUTE AND NOW() - INTERVAL '8' MINUTE THEN 1 ELSE 0 END) > 0
```
This finds services that WERE reporting metrics but have STOPPED - strong indicator of failure!

### DO NOT STOP AT THE FIRST ERROR YOU FIND

When investigating ANY service, even if you find one clear error (e.g. a Kafka topic issue),
you MUST STILL check the broader infrastructure before concluding. The first error you find
may be a symptom of something deeper.

**MANDATORY: After finding errors in the target service, ALWAYS also run:**

1. **Check ALL databases** — are any degraded, slow, or down?
```sql
SELECT db_system,
       COUNT(*) as span_count,
       SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
       ROUND(AVG(duration_ns / 1000000.0), 2) as avg_ms,
       ROUND(MAX(duration_ns / 1000000.0), 2) as max_ms,
       MAX(start_time) as last_seen
FROM traces_otel_analytic
WHERE db_system IS NOT NULL AND db_system != ''
  AND start_time > NOW() - INTERVAL '5' MINUTE
GROUP BY db_system
```

2. **Check ALL services for errors** — is this an isolated issue or part of a broader failure?
```sql
SELECT service_name,
       COUNT(*) as total,
       SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
       ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct,
       ROUND(AVG(duration_ns / 1000000.0), 2) as avg_ms
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '5' MINUTE
GROUP BY service_name
HAVING SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) > 0
ORDER BY error_pct DESC
```

3. **Follow the trace** — get a trace_id from the error and query ALL spans in that trace to find the deepest failure.

**The root cause is often NOT in the service the user asked about.** A database degradation can cause
Kafka consumer timeouts, which cause accounting errors, which cause checkout failures.
Always trace the full dependency chain.

### DO NOT STOP AT SURFACE ERRORS

- 504 Gateway Timeout → Find WHICH downstream service timed out
- Connection refused → Find WHICH service is down
- High latency → Find WHICH database/service is slow
- "Service unavailable" → Find the ACTUAL unavailable component
- No database spans → DATABASE MAY BE DOWN (can't report if it's dead!)
- Kafka/messaging errors → Check if the underlying DATABASE or HOST is degraded

### Detecting Silent Failures (Down Services)

A service that is DOWN or PAUSED cannot emit telemetry. Look for:
1. Services that normally emit spans but now have NONE
2. CLIENT spans with no corresponding responses
3. Traces that stop abruptly at a service boundary
4. Connection timeout exceptions pointing to a specific host/service
5. **METRICS DROP-OFF**: Services that were emitting metrics but suddenly stopped
6. Compare metric volume between now vs 5-10 minutes ago - a cliff drop = failure

### Detecting Long-Standing Issues (Chronic Problems)

Issues that have been happening for a long time won't show as "changes" - they're the new normal. Use ABSOLUTE THRESHOLDS:

1. **Error rate thresholds** - Any service with >5% error rate is unhealthy:
```sql
SELECT service_name,
       COUNT(*) as total,
       SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
       ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '1' HOUR
GROUP BY service_name
HAVING SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) > 0
ORDER BY error_pct DESC
```

2. **Latency thresholds** - Operations taking >5 seconds are problematic:
```sql
SELECT service_name, span_name, db_system,
       COUNT(*) as slow_count,
       AVG(duration_ns/1000000.0) as avg_ms,
       MAX(duration_ns/1000000.0) as max_ms
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '1' HOUR
  AND duration_ns > 5000000000  -- > 5 seconds
GROUP BY service_name, span_name, db_system
ORDER BY slow_count DESC
```

3. **Compare to longer historical baseline** - Look back hours or days:
```sql
SELECT service_name,
       SUM(CASE WHEN start_time > NOW() - INTERVAL '1' HOUR THEN 1 ELSE 0 END) as last_hour,
       SUM(CASE WHEN start_time BETWEEN NOW() - INTERVAL '24' HOUR AND NOW() - INTERVAL '23' HOUR THEN 1 ELSE 0 END) as yesterday_same_hour
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '24' HOUR
GROUP BY service_name
```

4. **Cross-service comparison** - If similar services have different error rates, investigate:
```sql
SELECT service_name,
       ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '1' HOUR
GROUP BY service_name
ORDER BY error_pct DESC
```

5. **Check for persistent exceptions** - Same error repeatedly = chronic issue:
```sql
SELECT service_name, exception_type, exception_message, COUNT(*) as occurrences
FROM span_events_otel_analytic
WHERE timestamp > NOW() - INTERVAL '1' HOUR
  AND exception_type IS NOT NULL AND exception_type != ''
GROUP BY service_name, exception_type, exception_message
ORDER BY occurrences DESC
LIMIT 20
```

Use these when the user reports an ongoing issue or when recent comparisons show no anomalies but the system is clearly unhealthy.

### Example Root Cause Chain

User sees: "Frontend is slow"
↓ Query frontend traces, find high latency
↓ Follow trace_id, see checkout-service taking 30s
↓ Follow trace deeper, see postgres query taking 30s
↓ ROOT CAUSE: PostgreSQL is slow/down

OR (silent failure):
User sees: "Frontend is slow"
↓ Query frontend traces, find 15s timeouts
↓ Follow trace_id, trace STOPS at a service trying to reach postgres
↓ Check db_system spans - ZERO postgres spans in last 5 minutes!
↓ ROOT CAUSE: PostgreSQL is DOWN (no telemetry = can't respond)

ALWAYS trace to the leaf of the dependency tree!

## Query Guidelines

- Always limit queries (use LIMIT) to avoid overwhelming results
- Use appropriate time filters to focus on relevant data
- When looking for slow operations, sort by duration descending
- When investigating errors, filter by status_code = 'ERROR' or severity_text = 'ERROR'
- For the current time, use NOW() or CURRENT_TIMESTAMP
- ALWAYS check db_system column when investigating slowness or timeouts
- Check for ABSENCE of spans, not just presence of errors

## Service Name Discovery (CRITICAL)

Service names in the database may NOT match what users say. Users might say "ad service" but the actual service_name could be "ad", "adservice", "ad-service", or "oteldemo-adservice".

**ALWAYS discover the exact service name FIRST before querying for a specific service:**

```sql
SELECT DISTINCT service_name
FROM traces_otel_analytic
WHERE service_name LIKE '%ad%'
  AND start_time > NOW() - INTERVAL '1' HOUR
LIMIT 20
```

Or list all services to find the right one:
```sql
SELECT DISTINCT service_name, COUNT(*) as span_count
FROM traces_otel_analytic
WHERE start_time > NOW() - INTERVAL '1' HOUR
GROUP BY service_name
ORDER BY span_count DESC
```

**Common patterns:**
- User says "ad service" → Look for: `WHERE service_name LIKE '%ad%'`
- User says "checkout" → Look for: `WHERE service_name LIKE '%checkout%'`
- User says "frontend" → Look for: `WHERE service_name LIKE '%frontend%'`

**NEVER assume the exact service name.** If a query returns no results, check if you have the right service_name by listing available services first.

## Service Health Reporting

When summarizing service health status, use these EXPLICIT guidelines:

### Terminology
- Report **Error Rate** directly (e.g., "5.9% error rate"), NOT inverted metrics like "94.1% positive"
- "Error Rate" = percentage of spans with status_code = 'ERROR'
- Be specific: "Error Rate: 5.9%" is clearer than "Success Rate: 94.1%"

### Health Classification Thresholds
Use these thresholds consistently when classifying services:

- **Healthy** (green): Error rate < 1%
- **Warning** (yellow): Error rate 1-5%
- **Degraded** (orange): Error rate 5-20%
- **Critical** (red): Error rate > 20%

### Output Formatting
When presenting service status summaries, use consistent formatting:

```
Service Health Summary:

CRITICAL (>20% error rate):
- payment-service: 25.4% error rate (investigate immediately)

DEGRADED (5-20% error rate):
- checkout-service: 8.2% error rate
- cart-service: 6.1% error rate

WARNING (1-5% error rate):
- frontend: 3.2% error rate
- ad-service: 2.1% error rate

HEALTHY (<1% error rate):
- email-service: 0.1% error rate
- currency-service: 0% error rate
```

Do NOT indent sections inconsistently. Keep all category headers at the same level.

## Chart Generation Guidelines

When asked to visualize data, use these guidelines:

### Chart Type Selection
- **Line chart**: For time-series data (latency over time, error rates over time, throughput over time)
- **Bar chart**: For comparing categories (errors by service, latency by operation)
- **Doughnut chart**: For showing proportions (request distribution by service)

### Latency Visualization (IMPORTANT)
When asked for "latency graph" or "latency over time":
1. Query data with time buckets:
```sql
SELECT date_trunc('minute', start_time) as time_bucket,
       ROUND(AVG(duration_ns/1000000.0), 2) as avg_latency_ms,
       ROUND(MAX(duration_ns/1000000.0), 2) as max_latency_ms
FROM traces_otel_analytic
WHERE service_name = 'xxx' AND start_time > NOW() - INTERVAL '1' HOUR
GROUP BY date_trunc('minute', start_time)
ORDER BY time_bucket
```
2. Use a **LINE chart** with time buckets as x-axis labels
3. Create datasets for avg_latency_ms and/or max_latency_ms
4. Labels should be timestamps (e.g., "12:30", "12:31", "12:32")

**WRONG**: Bar chart with "Average Latency" and "Max Latency" as x-axis labels
**RIGHT**: Line chart with time points as x-axis, multiple data series for avg/max

### Example Chart Data Structure
For latency over time:
- chart_type: "line"
- title: "Checkout Service Latency Over Time"
- labels: ["12:30", "12:31", "12:32", "12:33", ...]
- datasets: array with objects containing label, data, and color fields
  - First dataset: label="Avg Latency (ms)", data=[45.2, 52.1, 48.3, ...], color="#00d9ff"
  - Second dataset: label="Max Latency (ms)", data=[120.5, 165.2, 98.1, ...], color="#ff5252"

## STRICT ANTI-HALLUCINATION RULES

You MUST follow these rules at all times. Violations undermine trust with support engineers.

### Ground Every Claim in Data
- **NEVER state a fact, metric value, error message, service name, or status unless it came from a query result in THIS conversation.**
- If you haven't queried for it yet, say "Let me check" and run the query — do NOT guess.
- When presenting findings, cite the actual values returned: row counts, error percentages, specific timestamps, exact exception messages. Do NOT paraphrase exception messages or error text — quote them verbatim from query results.
- If a query returns 0 rows, say "No results found" — do NOT invent what the results "might" show.

### Distinguish Facts from Hypotheses
- **CONFIRMED (from query data):** State directly: "The checkout service has a 12.3% error rate in the last 15 minutes."
- **HYPOTHESIS (needs verification):** Always flag: "This COULD indicate a database connection issue — let me query to confirm."
- **NEVER present a hypothesis as a confirmed finding.** If you haven't run the query, it's a hypothesis.

### When You Don't Know, Say So
- "I don't see data for that in the current time window."
- "The query returned no results — this could mean [X] or [Y]. Let me widen the search."
- "I don't have enough information to determine the root cause yet. Let me run additional queries."
- NEVER say "the service is healthy" or "everything looks fine" unless you have query results showing low error rates, normal latency, and active span counts.

### No Fabrication
- Do NOT invent service names, metric names, error messages, trace IDs, or numerical values.
- Do NOT describe query results you haven't actually received.
- Do NOT extrapolate trends from a single data point.
- If the tool returns an error, report the error honestly — do NOT pretend the query succeeded.

### When Summarizing
- Only summarize data you actually queried and received.
- If your summary covers multiple services, you must have queried each one.
- If you say "all services are healthy," you must have checked all of them.
- Clearly state what time window your analysis covers.

## Important Notes

- Be conversational but focused on finding ROOT CAUSE
- Show your reasoning as you investigate
- Don't stop at the first error you find - TRACE IT DEEPER
- Always explain what you're looking for with each query
- When you find the root cause, clearly state it with evidence from query results
- Remember: NO DATA from a service can mean the service is DOWN

You have access to a tool called `execute_sql` that runs SQL queries against the VastDB database via Trino. Use it to investigate issues.
"""


# =============================================================================
# Trino Query Executor
# =============================================================================

class TrinoQueryExecutor:
    """Executes SQL queries against VastDB via Trino."""

    def __init__(self):
        if not TRINO_AVAILABLE:
            raise ImportError("trino package not installed. Run: pip install trino")

        auth = None
        if TRINO_PASSWORD:
            auth = BasicAuthentication(TRINO_USER, TRINO_PASSWORD)

        self.conn = trino_connect(
            host=TRINO_HOST,
            port=TRINO_PORT,
            user=TRINO_USER,
            catalog=TRINO_CATALOG,
            schema=TRINO_SCHEMA,
            http_scheme=TRINO_HTTP_SCHEME,
            auth=auth,
            verify=False,
        )

    def get_backend_name(self) -> str:
        return f"Trino ({TRINO_HOST}:{TRINO_PORT})"

    @staticmethod
    def _fix_group_by_aliases(sql: str) -> str:
        """Rewrite GROUP BY / ORDER BY column aliases to positional references.

        Trino (unlike MySQL/PostgreSQL) does not allow column aliases in
        GROUP BY or ORDER BY — e.g. ``GROUP BY container_name`` fails with
        COLUMN_NOT_FOUND when ``container_name`` is a SELECT alias.

        LLM-generated SQL (from alert investigations and diagnostic chat)
        frequently produces this pattern despite prompt instructions to use
        positional refs.  Rather than relying solely on prompt engineering,
        we intercept the SQL here and rewrite alias references to ordinals
        (e.g. ``GROUP BY 1, 2``) so queries succeed reliably.
        """
        select_match = re.search(r'\bSELECT\b(.*?)\bFROM\b', sql, re.IGNORECASE | re.DOTALL)
        if not select_match:
            return sql

        select_body = select_match.group(1)
        aliases: list[str] = []
        depth = 0
        current_expr_start = 0
        for i, ch in enumerate(select_body):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            elif ch == ',' and depth == 0:
                fragment = select_body[current_expr_start:i]
                alias_m = re.search(r'\bAS\s+(\w+)\s*$', fragment, re.IGNORECASE)
                aliases.append(alias_m.group(1) if alias_m else '')
                current_expr_start = i + 1
        fragment = select_body[current_expr_start:]
        alias_m = re.search(r'\bAS\s+(\w+)\s*$', fragment, re.IGNORECASE)
        aliases.append(alias_m.group(1) if alias_m else '')

        alias_map = {}
        for idx, alias in enumerate(aliases, 1):
            if alias:
                alias_map[alias.lower()] = str(idx)

        if not alias_map:
            return sql

        def _replace_refs(clause_match: re.Match) -> str:
            keyword = clause_match.group(1)
            body = clause_match.group(2)
            parts = body.split(',')
            new_parts = []
            for part in parts:
                stripped = part.strip()
                token_m = re.match(r'^(\w+)(\s+(?:ASC|DESC))?\s*$', stripped, re.IGNORECASE)
                if token_m and token_m.group(1).lower() in alias_map:
                    replacement = alias_map[token_m.group(1).lower()]
                    suffix = token_m.group(2) or ''
                    new_parts.append(f' {replacement}{suffix}')
                else:
                    new_parts.append(part)
            # Preserve trailing whitespace so we don't merge with the next keyword
            # (e.g. "DESC\nLIMIT" becoming "DESCLIMIT")
            result = f'{keyword}{",".join(new_parts)}'
            if body and body[-1] in (' ', '\n', '\t', '\r'):
                result += '\n'
            return result

        sql = re.sub(
            r'(GROUP\s+BY|ORDER\s+BY)\b(.*?)(?=\bHAVING\b|\bORDER\b|\bLIMIT\b|\bUNION\b|\)|\;|$)',
            _replace_refs,
            sql,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return sql

    def execute_query(self, sql: str) -> Dict[str, Any]:
        """Execute a SQL query via Trino."""
        sql = sql.strip()

        # Allow CTEs (WITH ... AS SELECT) — they are read-only queries
        if not sql.lower().startswith(("select", "with")):
            return {
                "success": False,
                "error": "Only SELECT queries are supported",
                "rows": [],
                "columns": []
            }

        # Fix LLM-generated GROUP BY alias references (Trino rejects these)
        sql = self._fix_group_by_aliases(sql)

        # Enforce limit
        sql_lower = sql.lower()
        if "limit" not in sql_lower:
            sql = sql.rstrip(";") + f" LIMIT {MAX_QUERY_ROWS}"
        else:
            match = re.search(r'\blimit\s+(\d+)', sql_lower)
            if match and int(match.group(1)) > MAX_QUERY_ROWS:
                sql = re.sub(r'\blimit\s+\d+', f'LIMIT {MAX_QUERY_ROWS}', sql, flags=re.IGNORECASE)

        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)

            # Get column names
            columns = [desc[0] for desc in cursor.description] if cursor.description else []

            # Fetch results
            raw_rows = cursor.fetchall()

            # Convert to list of dicts
            rows = []
            for raw_row in raw_rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    val = raw_row[i]
                    # Convert timestamps to strings
                    if hasattr(val, 'isoformat'):
                        val = val.isoformat()
                    row_dict[col] = val
                rows.append(row_dict)

            return {
                "success": True,
                "message": "Query executed successfully",
                "rows": rows,
                "columns": columns,
                "row_count": len(rows)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"{type(e).__name__}: {str(e)}",
                "rows": [],
                "columns": []
            }


# =============================================================================
# Claude Chat Interface
# =============================================================================

class DiagnosticChat:
    """Interactive chat interface using Claude for diagnosis."""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.query_executor = TrinoQueryExecutor()
        self.conversation_history: List[Dict] = []

        # Define the SQL execution tool
        self.tools = [
            {
                "name": "execute_sql",
                "description": """Execute a SQL query against the VastDB observability database via Trino.

Use this tool to query logs, metrics, traces, span events, and span links.

Available tables:
- logs_otel_analytic: Log records with timestamp, service_name, severity_number, severity_text, body_text, trace_id, span_id, attributes_json
- metrics_otel_analytic: Metrics with timestamp, service_name, metric_name, metric_unit, value_double, attributes_flat
- traces_otel_analytic: Trace spans with trace_id, span_id, parent_span_id, start_time, duration_ns, service_name, span_name, span_kind, status_code, http_status, db_system, attributes_json
- span_events_otel_analytic: Span events including exceptions with timestamp, trace_id, span_id, service_name, span_name, event_name, event_attributes_json, exception_type, exception_message, exception_stacktrace
- span_links_otel_analytic: Links between spans with trace_id, span_id, service_name, span_name, linked_trace_id, linked_span_id
- topology_services: service_name, service_type, span_count, error_pct, avg_latency_ms, last_seen
- topology_dependencies: source_service, target_service, dependency_type, call_count, avg_latency_ms, error_pct
- topology_hosts: host_name, display_name, os_type, cpu_pct, memory_pct, disk_pct, last_seen
- topology_containers: container_name, cpu_pct, memory_pct, memory_usage_mb, last_seen
- topology_database_hosts: db_system, host_name, last_seen
- topology_host_services: host_name, service_name, source, data_point_count, last_seen
- service_metrics_1m: time_bucket, service_name, avg_latency_ms, max_latency_ms, p95_latency_ms, request_count, error_count, error_pct
- db_metrics_1m: time_bucket, db_system, avg_latency_ms, max_latency_ms, query_count, error_count, error_pct
- operation_metrics_5m: time_bucket, service_name, span_name, call_count, avg_latency_ms, error_count, error_pct
- alerts: alert_id, created_at, updated_at, service_name, alert_type, severity, title, description, metric_type, current_value, baseline_value, z_score, status, resolved_at, auto_resolved
- alert_investigations: investigation_id, alert_id, investigated_at, service_name, alert_type, model_used, root_cause_summary, recommended_actions, supporting_evidence, queries_executed, tokens_used

CRITICAL: No semicolons. GROUP BY aliases not allowed in Trino — use positional refs (GROUP BY 1, 2).
Always include a LIMIT clause to avoid returning too many results.
Results are limited to 100 rows maximum.""",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "sql": {
                            "type": "string",
                            "description": "The SQL SELECT query to execute"
                        }
                    },
                    "required": ["sql"]
                }
            }
        ]

    def chat(self, user_message: str) -> str:
        """Send a message and get a response, potentially with tool use."""

        # Add user message to history
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        # Keep conversation history manageable
        if len(self.conversation_history) > 20:
            self.conversation_history = self.conversation_history[-20:]

        # Initial API call
        response = self._call_api()

        # Handle tool use loop
        while response.stop_reason == "tool_use":
            # Process tool calls
            tool_results = self._process_tool_calls(response)

            # Add assistant response and tool results to history
            self.conversation_history.append({
                "role": "assistant",
                "content": response.content
            })
            self.conversation_history.append({
                "role": "user",
                "content": tool_results
            })

            # Continue the conversation
            response = self._call_api()

        # Extract final text response
        final_response = self._extract_text(response)

        # Add to history
        self.conversation_history.append({
            "role": "assistant",
            "content": final_response
        })

        return final_response

    def _call_api(self):
        """Make an API call to Claude."""
        return self.client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=self.tools,
            messages=self.conversation_history
        )

    def _process_tool_calls(self, response) -> List[Dict]:
        """Process tool calls from the response."""
        tool_results = []

        for content_block in response.content:
            if content_block.type == "tool_use":
                tool_name = content_block.name
                tool_input = content_block.input
                tool_use_id = content_block.id

                if tool_name == "execute_sql":
                    sql = tool_input.get("sql", "")
                    print(f"\n[Executing SQL]\n{sql}\n")

                    result = self.query_executor.execute_query(sql)

                    # Format result for display
                    if result["success"]:
                        print(f"[Query returned {result['row_count']} rows]")
                        if result["rows"]:
                            # Show preview of first few rows
                            preview_count = min(3, len(result["rows"]))
                            for i, row in enumerate(result["rows"][:preview_count]):
                                print(f"  Row {i+1}: {self._format_row_preview(row)}")
                            if len(result["rows"]) > preview_count:
                                print(f"  ... and {len(result['rows']) - preview_count} more rows")
                    else:
                        print(f"[Query Error: {result['error']}]")

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps(result, default=str)
                    })
                else:
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": json.dumps({"error": f"Unknown tool: {tool_name}"})
                    })

        return tool_results

    def _format_row_preview(self, row: Dict) -> str:
        """Format a row for preview display."""
        parts = []
        for k, v in list(row.items())[:4]:  # Show first 4 columns
            v_str = str(v)[:50]  # Truncate long values
            parts.append(f"{k}={v_str}")
        return ", ".join(parts)

    def _extract_text(self, response) -> str:
        """Extract text content from response."""
        text_parts = []
        for content_block in response.content:
            if hasattr(content_block, 'text'):
                text_parts.append(content_block.text)
        return "\n".join(text_parts)

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []
        print("Conversation history cleared.")


# =============================================================================
# Main CLI Interface
# =============================================================================

def print_banner():
    """Print welcome banner."""
    print("=" * 70)
    print("  Observability Diagnostic Chat")
    print("  Powered by Claude + Trino + VastDB")
    print("=" * 70)
    print()
    print("Describe your issue and I'll help diagnose it by querying")
    print("logs, metrics, and traces from your observability data.")
    print()
    print("Example queries:")
    print("  - 'ad service is slow'")
    print("  - 'what errors occurred in the last hour?'")
    print("  - 'show me failed checkouts'")
    print("  - 'trace request abc123'")
    print()
    print("Commands:")
    print("  /clear  - Clear conversation history")
    print("  /help   - Show this help message")
    print("  /quit   - Exit the chat")
    print()
    print("-" * 70)


def validate_config():
    """Validate required configuration."""
    errors = []

    if not ANTHROPIC_API_KEY:
        errors.append("ANTHROPIC_API_KEY is required")

    if not TRINO_HOST:
        errors.append("TRINO_HOST is required")

    if not TRINO_AVAILABLE:
        errors.append("trino package not installed. Run: pip install trino")

    if errors:
        print("Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        print()
        return False

    return True


def main():
    """Main entry point."""
    print_banner()

    if not validate_config():
        return 1

    try:
        print("Initializing...")
        chat = DiagnosticChat()
        print(f"Connected to: {chat.query_executor.get_backend_name()}")
        print(f"Using model: {ANTHROPIC_MODEL}")
        print()
    except Exception as e:
        print(f"Error initializing: {type(e).__name__}: {e}")
        return 1

    print("Ready! Type your question or describe the issue.\n")

    while True:
        try:
            # Get user input
            user_input = input("You: ").strip()

            if not user_input:
                continue

            # Handle commands
            if user_input.lower() == "/quit":
                print("Goodbye!")
                break
            elif user_input.lower() == "/clear":
                chat.clear_history()
                continue
            elif user_input.lower() == "/help":
                print_banner()
                continue

            # Get response from Claude
            print()
            response = chat.chat(user_input)
            print(f"\nAssistant: {response}\n")
            print("-" * 70)
            print()

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"\nError: {type(e).__name__}: {e}\n")
            continue

    return 0


if __name__ == "__main__":
    sys.exit(main())
