#!/usr/bin/env python3
"""
Metric Aggregator Service

Background service that pre-computes 1-minute and 5-minute rollup tables
from raw traces. The web UI reads from these small tables instead of
scanning the full traces_otel_analytic table on every drill-down refresh.

Usage:
    export TRINO_HOST=trino.example.com
    export TRINO_PASSWORD=your_password
    python metric_aggregator.py

Environment Variables:
    TRINO_HOST                  - Trino server hostname
    TRINO_PORT                  - Trino server port (default: 443)
    TRINO_USER                  - Trino username (default: admin)
    TRINO_PASSWORD              - Trino password
    TRINO_CATALOG               - Trino catalog (default: vast)
    TRINO_SCHEMA                - Trino schema (default: otel)

    AGGREGATION_INTERVAL        - Seconds between cycles (default: 60)
    RETENTION_HOURS             - Hours of rollup data to keep (default: 48)
"""

import os
import sys
import time
import json
import signal
import warnings
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Any

warnings.filterwarnings("ignore")

from otel_init import init_telemetry, traced, traced_cursor

try:
    from trino.dbapi import connect as trino_connect
    from trino.auth import BasicAuthentication
except ImportError:
    print("[ERROR] trino package not installed. Run: pip install trino")
    sys.exit(1)


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Configuration for metric aggregator service."""

    # Trino connection
    trino_host: str = field(default_factory=lambda: os.getenv("TRINO_HOST"))
    trino_port: int = field(default_factory=lambda: int(os.getenv("TRINO_PORT", "443")))
    trino_user: str = field(default_factory=lambda: os.getenv("TRINO_USER", "admin"))
    trino_password: str = field(default_factory=lambda: os.getenv("TRINO_PASSWORD"))
    trino_catalog: str = field(default_factory=lambda: os.getenv("TRINO_CATALOG", "vast"))
    trino_schema: str = field(default_factory=lambda: os.getenv("TRINO_SCHEMA", "otel"))
    trino_http_scheme: str = field(default_factory=lambda: os.getenv("TRINO_HTTP_SCHEME", "https"))

    # Aggregation settings
    aggregation_interval: int = field(
        default_factory=lambda: int(os.getenv("AGGREGATION_INTERVAL", "60"))
    )
    retention_hours: int = field(
        default_factory=lambda: int(os.getenv("RETENTION_HOURS", "48"))
    )
    warmup_minutes: int = field(
        default_factory=lambda: int(os.getenv("WARMUP_MINUTES", "5"))
    )
    overlap_minutes: int = field(
        default_factory=lambda: int(os.getenv("OVERLAP_MINUTES", "10"))
    )

    def validate(self):
        """Validate required configuration."""
        if not self.trino_host:
            raise ValueError("TRINO_HOST environment variable is required")


# =============================================================================
# Trino Executor (same pattern as topology_inference.py)
# =============================================================================

class TrinoExecutor:
    """Executes SQL queries against VastDB via Trino."""

    def __init__(self, config: Config):
        self.config = config
        self._conn = None
        self._connect()

    def _connect(self):
        """Establish connection to Trino."""
        auth = None
        if self.config.trino_password:
            auth = BasicAuthentication(self.config.trino_user, self.config.trino_password)

        self._conn = trino_connect(
            host=self.config.trino_host,
            port=self.config.trino_port,
            user=self.config.trino_user,
            catalog=self.config.trino_catalog,
            schema=self.config.trino_schema,
            http_scheme=self.config.trino_http_scheme,
            auth=auth,
            verify=False,
        )
        print(f"[Trino] Connected to {self.config.trino_host}")

    def execute(self, sql: str) -> List[Dict[str, Any]]:
        """Execute a query and return results as list of dicts."""
        try:
            cursor = self._conn.cursor()
            with traced_cursor(cursor, sql) as cur:
                cur.execute(sql)
                if cur.description:
                    columns = [desc[0] for desc in cur.description]
                    rows = cur.fetchall()
                    return [dict(zip(columns, row)) for row in rows]
            return []
        except Exception as e:
            error_msg = str(e)
            print(f"[Trino] Query error: {error_msg}")
            if "connection" in error_msg.lower():
                self._connect()
            return []

    def execute_write(self, sql: str) -> bool:
        """Execute a write query (INSERT/UPDATE/DELETE)."""
        try:
            cursor = self._conn.cursor()
            with traced_cursor(cursor, sql) as cur:
                cur.execute(sql)
            return True
        except Exception as e:
            print(f"[Trino] Write error: {e}")
            return False


# =============================================================================
# Metric Aggregator Service
# =============================================================================

class MetricAggregatorService:
    """Pre-computes rollup tables for drill-down charts."""

    JOB_NAME = 'metric_aggregator'

    def __init__(self, config: Config):
        self.config = config
        self.executor = TrinoExecutor(config)
        self.running = True

        # Cached warmup cutoff (stable after initial ingestion)
        self._warmup_earliest = None
        self._warmup_earliest_ts = 0

        # Track row counts per table for job status details
        self._last_table_rows = {}

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[Service] Shutting down...")
        self.running = False

    def _ensure_tables(self):
        """Check that rollup tables exist."""
        tables = [
            "service_metrics_1m",
            "db_metrics_1m",
            "operation_metrics_5m",
        ]
        for table in tables:
            try:
                self.executor.execute(f"SELECT 1 FROM {table} LIMIT 1")
            except Exception as e:
                if "does not exist" in str(e).lower():
                    print(f"[Service] Table {table} does not exist. Please create it using ddl.sql")
                    return False
        return True

    # -------------------------------------------------------------------------
    # Aggregation Steps
    # -------------------------------------------------------------------------


    def _warmup_cutoff(self):
        """Return SQL clause that excludes the first N minutes of trace data.

        This filters out transient startup errors (e.g. Kafka topic not yet
        available) that occur before all services are fully initialized.
        The MIN(start_time) result is cached for 10 minutes since it's
        effectively static after initial ingestion.
        """
        warmup = self.config.warmup_minutes
        now = time.time()
        if self._warmup_earliest is None or (now - self._warmup_earliest_ts) > 600:
            rows = self.executor.execute("SELECT MIN(start_time) as earliest FROM traces_otel_analytic")
            self._warmup_earliest = rows[0]['earliest'] if rows and rows[0]['earliest'] else None
            self._warmup_earliest_ts = now
        if self._warmup_earliest:
            return f"start_time > TIMESTAMP '{self._warmup_earliest}' + INTERVAL '{warmup}' MINUTE"
        return None

    @traced
    def _aggregate_service_metrics_1m(self):
        """Recompute recent 1-minute service metric buckets.

        Deletes and reinserts the most recent overlap window to capture
        late-arriving spans, then inserts any older buckets not yet computed.
        """
        overlap = self.config.overlap_minutes
        print(f"[Aggregator] Aggregating service metrics (1m buckets, {overlap}m overlap)...")

        # Delete recent buckets so we can recompute with any late-arriving spans
        self.executor.execute_write(
            f"DELETE FROM service_metrics_1m WHERE time_bucket >= NOW() - INTERVAL '{overlap}' MINUTE"
        )

        # Find latest remaining bucket after the delete
        rows = self.executor.execute("SELECT MAX(time_bucket) as last_bucket FROM service_metrics_1m")
        last_bucket = rows[0]['last_bucket'] if rows and rows[0]['last_bucket'] else None

        if last_bucket:
            since_clause = f"start_time > TIMESTAMP '{last_bucket}'"
        else:
            since_clause = f"start_time > NOW() - INTERVAL '{self.config.retention_hours}' HOUR"

        warmup = self._warmup_cutoff()
        warmup_clause = f"AND {warmup}" if warmup else ""

        sql = f"""
        INSERT INTO service_metrics_1m
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            service_name,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(MAX(duration_ns / 1000000.0), 2) as max_latency_ms,
            ROUND(APPROX_PERCENTILE(duration_ns / 1000000.0, 0.95), 2) as p95_latency_ms,
            COUNT(*) as request_count,
            SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as error_count,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
        FROM traces_otel_analytic
        WHERE {since_clause}
          AND service_name IS NOT NULL AND service_name != ''
          {warmup_clause}
        GROUP BY date_trunc('minute', start_time), service_name
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute(
                "SELECT COUNT(*) as cnt FROM service_metrics_1m"
            )
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['service_metrics_1m'] = count
            print(f"[Aggregator]   -> {count} total service-minute rows")
        else:
            print("[Aggregator]   -> FAILED to aggregate service metrics")

    @traced
    def _aggregate_db_metrics_1m(self):
        """Recompute recent 1-minute database metric buckets."""
        overlap = self.config.overlap_minutes
        print(f"[Aggregator] Aggregating database metrics (1m buckets, {overlap}m overlap)...")

        self.executor.execute_write(
            f"DELETE FROM db_metrics_1m WHERE time_bucket >= NOW() - INTERVAL '{overlap}' MINUTE"
        )

        rows = self.executor.execute("SELECT MAX(time_bucket) as last_bucket FROM db_metrics_1m")
        last_bucket = rows[0]['last_bucket'] if rows and rows[0]['last_bucket'] else None

        if last_bucket:
            since_clause = f"start_time > TIMESTAMP '{last_bucket}'"
        else:
            since_clause = f"start_time > NOW() - INTERVAL '{self.config.retention_hours}' HOUR"

        warmup = self._warmup_cutoff()
        warmup_clause = f"AND {warmup}" if warmup else ""

        sql = f"""
        INSERT INTO db_metrics_1m
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            db_system,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(MAX(duration_ns / 1000000.0), 2) as max_latency_ms,
            COUNT(*) as query_count,
            SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as error_count,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
        FROM traces_otel_analytic
        WHERE {since_clause}
          AND db_system IS NOT NULL AND db_system != ''
          {warmup_clause}
        GROUP BY date_trunc('minute', start_time), db_system
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute(
                "SELECT COUNT(*) as cnt FROM db_metrics_1m"
            )
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['db_metrics_1m'] = count
            print(f"[Aggregator]   -> {count} total db-minute rows")
        else:
            print("[Aggregator]   -> FAILED to aggregate database metrics")

    @traced
    def _aggregate_operations_5m(self):
        """Recompute recent 5-minute per-service, per-operation rollups."""
        overlap = self.config.overlap_minutes
        print(f"[Aggregator] Aggregating operation metrics (5m buckets, {overlap}m overlap)...")

        self.executor.execute_write(
            f"DELETE FROM operation_metrics_5m WHERE time_bucket >= NOW() - INTERVAL '{overlap}' MINUTE"
        )

        rows = self.executor.execute("SELECT MAX(time_bucket) as last_bucket FROM operation_metrics_5m")
        last_bucket = rows[0]['last_bucket'] if rows and rows[0]['last_bucket'] else None

        if last_bucket:
            since_clause = f"start_time > TIMESTAMP '{last_bucket}'"
        else:
            since_clause = f"start_time > NOW() - INTERVAL '{self.config.retention_hours}' HOUR"

        warmup = self._warmup_cutoff()
        warmup_clause = f"AND {warmup}" if warmup else ""

        sql = f"""
        INSERT INTO operation_metrics_5m
        SELECT
            date_trunc('hour', start_time) + INTERVAL '5' MINUTE * FLOOR(EXTRACT(MINUTE FROM start_time) / 5) as time_bucket,
            service_name,
            span_name,
            COUNT(*) as call_count,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as error_count,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
        FROM traces_otel_analytic
        WHERE {since_clause}
          AND service_name IS NOT NULL AND service_name != ''
          AND span_name IS NOT NULL AND span_name != ''
          {warmup_clause}
        GROUP BY
            date_trunc('hour', start_time) + INTERVAL '5' MINUTE * FLOOR(EXTRACT(MINUTE FROM start_time) / 5),
            service_name,
            span_name
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute(
                "SELECT COUNT(*) as cnt FROM operation_metrics_5m"
            )
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['operation_metrics_5m'] = count
            print(f"[Aggregator]   -> {count} total operation-5m rows")
        else:
            print("[Aggregator]   -> FAILED to aggregate operation metrics")

    @traced
    def _purge_old_data(self):
        """Delete rows older than retention period from all rollup tables."""
        retention = self.config.retention_hours
        print(f"[Aggregator] Purging data older than {retention}h...")

        for table in ["service_metrics_1m", "db_metrics_1m", "operation_metrics_5m"]:
            sql = f"DELETE FROM {table} WHERE time_bucket < NOW() - INTERVAL '{retention}' HOUR"
            if self.executor.execute_write(sql):
                print(f"[Aggregator]   -> Purged old rows from {table}")
            else:
                print(f"[Aggregator]   -> FAILED to purge {table}")

    # -------------------------------------------------------------------------
    # Main Loop
    # -------------------------------------------------------------------------

    def run(self):
        """Main service loop."""
        print("=" * 60)
        print("Metric Aggregator Service")
        print("=" * 60)
        print(f"\nConfiguration:")
        print(f"  Aggregation interval: {self.config.aggregation_interval}s")
        print(f"  Retention: {self.config.retention_hours}h")
        print(f"  Warmup skip: {self.config.warmup_minutes}m")
        print(f"  Overlap recompute: {self.config.overlap_minutes}m")
        print()

        print(f"[Service] Starting aggregation loop (interval: {self.config.aggregation_interval}s)...\n")

        while self.running:
            try:
                loop_start = time.time()

                print(f"[Service] Starting aggregation cycle at {datetime.now(timezone.utc).isoformat()}")

                self._aggregate_service_metrics_1m()
                self._aggregate_db_metrics_1m()
                self._aggregate_operations_5m()
                self._purge_old_data()

                elapsed = time.time() - loop_start
                print(f"[Service] Cycle complete in {elapsed:.1f}s\n")

                details = {
                    "interval_seconds": self.config.aggregation_interval,
                    "retention_hours": self.config.retention_hours,
                    "overlap_minutes": self.config.overlap_minutes,
                    "cycle_duration_s": round(elapsed, 1),
                    "steps": ["service_metrics_1m", "db_metrics_1m", "operation_metrics_5m", "purge"],
                    "tables": dict(self._last_table_rows),
                }
                self._write_job_status(elapsed, details=details)

                sleep_time = max(0, self.config.aggregation_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[Service] Error in aggregation loop: {e}")
                self._write_job_status(0, status='error', details={"error": str(e)[:200]})
                time.sleep(5)

        print("[Service] Stopped")

    def _write_job_status(self, cycle_duration_s: float, status: str = 'ok', details: dict = None):
        """Write job status to the job_status table."""
        try:
            details_str = json.dumps(details or {}).replace("'", "''")
            self.executor.execute_write(
                f"DELETE FROM job_status WHERE job_name = '{self.JOB_NAME}'"
            )
            self.executor.execute_write(
                f"INSERT INTO job_status VALUES ("
                f"'{self.JOB_NAME}', NOW(), {int(cycle_duration_s * 1000)}, "
                f"'{status}', '{details_str}', NOW())"
            )
        except Exception as e:
            print(f"[Service] Failed to write job status: {e}")


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    config = Config()

    try:
        config.validate()
    except ValueError as e:
        print(f"[Error] {e}")
        return 1

    init_telemetry('observability-aggregator')

    service = MetricAggregatorService(config)
    service.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
