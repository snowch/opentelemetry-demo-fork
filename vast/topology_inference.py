#!/usr/bin/env python3
"""
Topology Inference Service

Background service that periodically materializes service topology,
dependencies, and host mappings into dedicated Trino tables. The web UI
reads from these pre-computed tables instead of running expensive ad-hoc
queries on every request.

Usage:
    export TRINO_HOST=trino.example.com
    export TRINO_PASSWORD=your_password
    python topology_inference.py

Environment Variables:
    TRINO_HOST                       - Trino server hostname
    TRINO_PORT                       - Trino server port (default: 443)
    TRINO_USER                       - Trino username (default: admin)
    TRINO_PASSWORD                   - Trino password
    TRINO_CATALOG                    - Trino catalog (default: vast)
    TRINO_SCHEMA                     - Trino schema (default: otel)

    TOPOLOGY_INFERENCE_INTERVAL      - Seconds between cycles (default: 60)
    TOPOLOGY_SERVICES_LOOKBACK_HOURS - Service discovery window (default: 1)
    TOPOLOGY_DEPS_LOOKBACK_MINUTES   - Dependency join window (default: 15)
    TOPOLOGY_HOSTS_LOOKBACK_MINUTES  - Host metrics window (default: 5)
"""

import os
import sys
import json
import time
import signal
import warnings
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Any

warnings.filterwarnings("ignore")

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
    """Configuration for topology inference service."""

    # Trino connection
    trino_host: str = field(default_factory=lambda: os.getenv("TRINO_HOST"))
    trino_port: int = field(default_factory=lambda: int(os.getenv("TRINO_PORT", "443")))
    trino_user: str = field(default_factory=lambda: os.getenv("TRINO_USER", "admin"))
    trino_password: str = field(default_factory=lambda: os.getenv("TRINO_PASSWORD"))
    trino_catalog: str = field(default_factory=lambda: os.getenv("TRINO_CATALOG", "vast"))
    trino_schema: str = field(default_factory=lambda: os.getenv("TRINO_SCHEMA", "otel"))
    trino_http_scheme: str = field(default_factory=lambda: os.getenv("TRINO_HTTP_SCHEME", "https"))

    # Topology settings
    inference_interval: int = field(
        default_factory=lambda: int(os.getenv("TOPOLOGY_INFERENCE_INTERVAL", "60"))
    )
    services_lookback_hours: int = field(
        default_factory=lambda: int(os.getenv("TOPOLOGY_SERVICES_LOOKBACK_HOURS", "1"))
    )
    deps_lookback_minutes: int = field(
        default_factory=lambda: int(os.getenv("TOPOLOGY_DEPS_LOOKBACK_MINUTES", "15"))
    )
    hosts_lookback_minutes: int = field(
        default_factory=lambda: int(os.getenv("TOPOLOGY_HOSTS_LOOKBACK_MINUTES", "5"))
    )
    warmup_minutes: int = field(
        default_factory=lambda: int(os.getenv("WARMUP_MINUTES", "5"))
    )

    def validate(self):
        """Validate required configuration."""
        if not self.trino_host:
            raise ValueError("TRINO_HOST environment variable is required")


# =============================================================================
# Trino Executor (reused pattern from predictive_alerts.py)
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
            cursor.execute(sql)
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
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
            cursor.execute(sql)
            return True
        except Exception as e:
            print(f"[Trino] Write error: {e}")
            return False


# =============================================================================
# Topology Inference Service
# =============================================================================

class TopologyInferenceService:
    """Materializes service topology into pre-computed tables."""

    JOB_NAME = 'topology_inference'

    def __init__(self, config: Config):
        self.config = config
        self.executor = TrinoExecutor(config)
        self.running = True

        # Track entity counts per table for job status details
        self._last_table_rows = {}

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[Service] Shutting down...")
        self.running = False

    def _ensure_tables(self):
        """Check that topology tables exist."""
        tables = [
            "topology_services",
            "topology_dependencies",
            "topology_host_services",
            "topology_hosts",
            "topology_database_hosts",
            "topology_containers",
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
    # Materialization Steps
    # -------------------------------------------------------------------------

    def _warmup_cutoff(self):
        """Return SQL clause that excludes the first N minutes of trace data.

        Filters out transient startup errors (e.g. Kafka topic not yet
        available) that occur before all services are fully initialized.
        """
        warmup = self.config.warmup_minutes
        rows = self.executor.execute("SELECT MIN(start_time) as earliest FROM traces_otel_analytic")
        earliest = rows[0]['earliest'] if rows and rows[0]['earliest'] else None
        if earliest:
            return f"start_time > TIMESTAMP '{earliest}' + INTERVAL '{warmup}' MINUTE"
        return None

    def _materialize_services(self):
        """Materialize active services from traces."""
        lookback = self.config.services_lookback_hours
        print(f"[Topology] Materializing services (lookback: {lookback}h)...")

        self.executor.execute_write("DELETE FROM topology_services WHERE 1=1")

        warmup = self._warmup_cutoff()
        warmup_clause = f"AND {warmup}" if warmup else ""

        sql = f"""
        INSERT INTO topology_services
        SELECT
            service_name,
            'application' as service_type,
            COUNT(*) as span_count,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            MAX(start_time) as last_seen,
            NOW() as updated_at
        FROM traces_otel_analytic
        WHERE start_time > NOW() - INTERVAL '{lookback}' HOUR
          AND service_name IS NOT NULL AND service_name != ''
          {warmup_clause}
        GROUP BY service_name
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_services")
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['topology_services'] = count
            print(f"[Topology]   -> {count} services materialized")
        else:
            print("[Topology]   -> FAILED to materialize services")

    def _materialize_dependencies(self):
        """Materialize service-to-service and service-to-database dependencies."""
        lookback = self.config.deps_lookback_minutes
        print(f"[Topology] Materializing dependencies (lookback: {lookback}m)...")

        self.executor.execute_write("DELETE FROM topology_dependencies WHERE 1=1")

        warmup = self._warmup_cutoff()
        warmup_clause = f"AND {warmup}" if warmup else ""

        # Service-to-service dependencies via parent/child span join
        svc_sql = f"""
        INSERT INTO topology_dependencies
        SELECT
            parent.service_name as source_service,
            child.service_name as target_service,
            'service' as dependency_type,
            COUNT(*) as call_count,
            ROUND(AVG(child.duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct,
            MAX(child.start_time) as last_seen,
            NOW() as updated_at
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child
            ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE parent.start_time > NOW() - INTERVAL '{lookback}' MINUTE
          AND child.service_name != parent.service_name
          AND child.db_system IS NULL
          {warmup_clause}
        GROUP BY parent.service_name, child.service_name
        """
        self.executor.execute_write(svc_sql)

        # Service-to-database dependencies
        db_sql = f"""
        INSERT INTO topology_dependencies
        SELECT
            service_name as source_service,
            db_system as target_service,
            'database' as dependency_type,
            COUNT(*) as call_count,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct,
            MAX(start_time) as last_seen,
            NOW() as updated_at
        FROM traces_otel_analytic
        WHERE start_time > NOW() - INTERVAL '{lookback}' MINUTE
          AND db_system IS NOT NULL AND db_system != ''
          {warmup_clause}
        GROUP BY service_name, db_system
        """
        self.executor.execute_write(db_sql)

        rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_dependencies")
        count = rows[0]['cnt'] if rows else 0
        self._last_table_rows['topology_dependencies'] = count
        print(f"[Topology]   -> {count} dependencies materialized")

    def _materialize_host_services(self):
        """Materialize host-to-service mappings from metrics."""
        lookback = self.config.deps_lookback_minutes
        print(f"[Topology] Materializing host-services (lookback: {lookback}m)...")

        self.executor.execute_write("DELETE FROM topology_host_services WHERE 1=1")

        # From metrics with host.name attribute - metric-prefix inference for known services
        metrics_sql = f"""
        INSERT INTO topology_host_services
        SELECT
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) as host_name,
            SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1) as service_name,
            'metrics' as source,
            COUNT(*) as data_point_count,
            MAX(timestamp) as last_seen,
            NOW() as updated_at
        FROM metrics_otel_analytic
        WHERE timestamp > NOW() - INTERVAL '{lookback}' MINUTE
          AND attributes_flat LIKE '%host.name=%'
          AND (metric_name LIKE 'postgresql.%'
            OR metric_name LIKE 'redis.%'
            OR metric_name LIKE 'nginx.%'
            OR metric_name LIKE 'kafka.%'
            OR metric_name LIKE 'docker.%')
        GROUP BY
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1),
            SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1)
        HAVING REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) IS NOT NULL
        """
        self.executor.execute_write(metrics_sql)

        rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_host_services")
        count = rows[0]['cnt'] if rows else 0
        self._last_table_rows['topology_host_services'] = count
        print(f"[Topology]   -> {count} host-service mappings materialized")

    def _materialize_hosts(self):
        """Materialize host registry with system metrics."""
        lookback = self.config.hosts_lookback_minutes
        print(f"[Topology] Materializing hosts (lookback: {lookback}m)...")

        self.executor.execute_write("DELETE FROM topology_hosts WHERE 1=1")

        sql = f"""
        INSERT INTO topology_hosts
            (host_name, display_name, os_type, cpu_pct, memory_pct, disk_pct, last_seen, updated_at)
        SELECT
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) as host_name,
            CAST(NULL AS varchar) as display_name,
            MAX(CASE
                WHEN attributes_flat LIKE '%os.type=linux%' THEN 'linux'
                WHEN attributes_flat LIKE '%os.type=windows%' THEN 'windows'
                WHEN attributes_flat LIKE '%os.type=darwin%' THEN 'darwin'
                ELSE 'unknown'
            END) as os_type,
            MAX(CASE WHEN metric_name = 'system.cpu.utilization' AND value_double <= 1
                THEN ROUND(value_double * 100, 1) END) as cpu_pct,
            MAX(CASE WHEN metric_name = 'system.memory.utilization'
                AND attributes_flat LIKE '%state=used%' AND value_double <= 1
                THEN ROUND(value_double * 100, 1) END) as memory_pct,
            MAX(CASE WHEN metric_name = 'system.filesystem.utilization' AND value_double <= 1
                THEN ROUND(value_double * 100, 1) END) as disk_pct,
            MAX(timestamp) as last_seen,
            CAST(NOW() AS timestamp(9)) as updated_at
        FROM metrics_otel_analytic
        WHERE metric_name IN ('system.cpu.utilization', 'system.memory.utilization', 'system.filesystem.utilization')
          AND timestamp > NOW() - INTERVAL '{lookback}' MINUTE
          AND attributes_flat LIKE '%host.name=%'
        GROUP BY REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1)
        HAVING REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) IS NOT NULL
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_hosts")
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['topology_hosts'] = count
            print(f"[Topology]   -> {count} hosts materialized")
            self._resolve_host_display_names()
        else:
            print("[Topology]   -> FAILED to materialize hosts")

    def _resolve_host_display_names(self):
        """Set display_name on topology_hosts from the top service in topology_host_services."""
        rows = self.executor.execute(
            "SELECT host_name, service_name FROM topology_host_services ORDER BY data_point_count DESC"
        )
        if not rows:
            return
        # Pick first (highest data_point_count) service per host
        best = {}
        for r in rows:
            h = r.get("host_name")
            if h and h not in best:
                best[h] = r.get("service_name", "")
        updated = 0
        for host_name, svc in best.items():
            if not svc:
                continue
            safe_svc = svc.replace("'", "''")
            safe_host = host_name.replace("'", "''")
            ok = self.executor.execute_write(
                f"UPDATE topology_hosts SET display_name = '{safe_svc}' WHERE host_name = '{safe_host}'"
            )
            if ok:
                updated += 1
        if updated:
            print(f"[Topology]   -> {updated} host display names resolved")

    def _materialize_database_hosts(self):
        """Materialize database-to-host mappings from metric attributes."""
        lookback = self.config.deps_lookback_minutes
        print(f"[Topology] Materializing database-hosts (lookback: {lookback}m)...")

        self.executor.execute_write("DELETE FROM topology_database_hosts WHERE 1=1")

        sql = f"""
        INSERT INTO topology_database_hosts
        SELECT
            SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1) as db_system,
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) as host_name,
            MAX(timestamp) as last_seen,
            NOW() as updated_at
        FROM metrics_otel_analytic
        WHERE timestamp > NOW() - INTERVAL '{lookback}' MINUTE
          AND attributes_flat LIKE '%host.name=%'
          AND (metric_name LIKE 'postgresql.%'
            OR metric_name LIKE 'redis.%'
            OR metric_name LIKE 'kafka.%')
        GROUP BY
            SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1),
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1)
        HAVING REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) IS NOT NULL
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_database_hosts")
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['topology_database_hosts'] = count
            print(f"[Topology]   -> {count} database-host mappings materialized")
        else:
            print("[Topology]   -> FAILED to materialize database-hosts")

    def _materialize_containers(self):
        """Materialize container registry with resource metrics from docker_stats."""
        lookback = self.config.hosts_lookback_minutes
        print(f"[Topology] Materializing containers (lookback: {lookback}m)...")

        self.executor.execute_write("DELETE FROM topology_containers WHERE 1=1")

        sql = f"""
        INSERT INTO topology_containers
        SELECT
            REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1) as container_name,
            MAX(CASE WHEN metric_name = 'container.cpu.percent' THEN ROUND(value_double, 1) END) as cpu_pct,
            MAX(CASE WHEN metric_name = 'container.memory.percent' THEN ROUND(value_double, 1) END) as memory_pct,
            MAX(CASE WHEN metric_name = 'container.memory.usage.total' THEN ROUND(value_double / 1048576.0, 1) END) as memory_usage_mb,
            MAX(timestamp) as last_seen,
            NOW() as updated_at
        FROM metrics_otel_analytic
        WHERE metric_name IN ('container.cpu.percent', 'container.memory.percent', 'container.memory.usage.total')
          AND timestamp > NOW() - INTERVAL '{lookback}' MINUTE
          AND attributes_flat LIKE '%container.name=%'
        GROUP BY REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1)
        HAVING REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1) IS NOT NULL
        """
        if self.executor.execute_write(sql):
            rows = self.executor.execute("SELECT COUNT(*) as cnt FROM topology_containers")
            count = rows[0]['cnt'] if rows else 0
            self._last_table_rows['topology_containers'] = count
            print(f"[Topology]   -> {count} containers materialized")
        else:
            print("[Topology]   -> FAILED to materialize containers")

    # -------------------------------------------------------------------------
    # Main Loop
    # -------------------------------------------------------------------------

    def run(self):
        """Main service loop."""
        print("=" * 60)
        print("Topology Inference Service")
        print("=" * 60)
        print(f"\nConfiguration:")
        print(f"  Inference interval: {self.config.inference_interval}s")
        print(f"  Services lookback: {self.config.services_lookback_hours}h")
        print(f"  Dependencies lookback: {self.config.deps_lookback_minutes}m")
        print(f"  Hosts lookback: {self.config.hosts_lookback_minutes}m")
        print()

        print(f"[Service] Starting materialization loop (interval: {self.config.inference_interval}s)...\n")

        while self.running:
            try:
                loop_start = time.time()

                print(f"[Service] Starting materialization cycle at {datetime.now(timezone.utc).isoformat()}")

                self._materialize_services()
                self._materialize_dependencies()
                self._materialize_host_services()
                self._materialize_hosts()
                self._materialize_database_hosts()
                self._materialize_containers()

                elapsed = time.time() - loop_start
                print(f"[Service] Cycle complete in {elapsed:.1f}s\n")

                details = {
                    "interval_seconds": self.config.inference_interval,
                    "cycle_duration_s": round(elapsed, 1),
                    "steps": ["services", "dependencies", "host_services", "hosts", "database_hosts", "containers"],
                    "tables": dict(self._last_table_rows),
                }
                self._write_job_status(elapsed, details=details)

                sleep_time = max(0, self.config.inference_interval - elapsed)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[Service] Error in materialization loop: {e}")
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

    service = TopologyInferenceService(config)
    service.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
