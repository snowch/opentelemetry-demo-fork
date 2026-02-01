#!/usr/bin/env python3
"""
Predictive Maintenance Alerts Service

Automated service that monitors telemetry data and generates predictive alerts
for potential issues before they become critical failures.

Features:
- Self-learning baselines from historical data
- Multiple anomaly detection methods (Z-score, IQR, Isolation Forest)
- Trend detection for gradual degradation
- Automatic alert generation and resolution
- No user input required - fully automated

Usage:
    export TRINO_HOST=trino.example.com
    export TRINO_PASSWORD=your_password
    python predictive_alerts.py

Environment Variables:
    TRINO_HOST          - Trino server hostname
    TRINO_PORT          - Trino server port (default: 443)
    TRINO_USER          - Trino username (default: admin)
    TRINO_PASSWORD      - Trino password
    TRINO_CATALOG       - Trino catalog (default: vast)
    TRINO_SCHEMA        - Trino schema (default: otel)

    DETECTION_INTERVAL  - Seconds between detection runs (default: 60)
    BASELINE_INTERVAL   - Seconds between baseline updates (default: 3600)
    BASELINE_WINDOW_HOURS - Hours of data for baseline computation (default: 24)
    ANOMALY_THRESHOLD   - Z-score threshold for anomaly (default: 3.0)
"""

import os
import sys
import time
import uuid
import signal
import warnings
import json
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from collections import deque
import statistics
import math
import hashlib

# Suppress warnings
warnings.filterwarnings("ignore")

# Optional: Anthropic for LLM-powered investigations
try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("[INFO] anthropic not available - LLM investigations disabled")

try:
    from trino.dbapi import connect as trino_connect
    from trino.auth import BasicAuthentication
    TRINO_AVAILABLE = True
except ImportError:
    TRINO_AVAILABLE = False
    print("[ERROR] trino package not installed. Run: pip install trino")
    sys.exit(1)

# Optional: sklearn for advanced anomaly detection
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[INFO] sklearn not available - using statistical methods only")


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class Config:
    """Configuration for predictive alerts service."""

    # Trino connection
    trino_host: str = field(default_factory=lambda: os.getenv("TRINO_HOST"))
    trino_port: int = field(default_factory=lambda: int(os.getenv("TRINO_PORT", "443")))
    trino_user: str = field(default_factory=lambda: os.getenv("TRINO_USER", "admin"))
    trino_password: str = field(default_factory=lambda: os.getenv("TRINO_PASSWORD"))
    trino_catalog: str = field(default_factory=lambda: os.getenv("TRINO_CATALOG", "vast"))
    trino_schema: str = field(default_factory=lambda: os.getenv("TRINO_SCHEMA", "otel"))
    trino_http_scheme: str = field(default_factory=lambda: os.getenv("TRINO_HTTP_SCHEME", "https"))

    # Detection settings
    detection_interval: int = field(
        default_factory=lambda: int(os.getenv("DETECTION_INTERVAL", "60"))
    )
    baseline_interval: int = field(
        default_factory=lambda: int(os.getenv("BASELINE_INTERVAL", "3600"))
    )
    baseline_window_hours: int = field(
        default_factory=lambda: int(os.getenv("BASELINE_WINDOW_HOURS", "24"))
    )

    # Anomaly thresholds
    zscore_threshold: float = field(
        default_factory=lambda: float(os.getenv("ANOMALY_THRESHOLD", "3.0"))
    )
    error_rate_warning: float = field(
        default_factory=lambda: float(os.getenv("ERROR_RATE_WARNING", "0.05"))
    )
    error_rate_critical: float = field(
        default_factory=lambda: float(os.getenv("ERROR_RATE_CRITICAL", "0.20"))
    )

    # Alert settings
    min_samples_for_baseline: int = field(
        default_factory=lambda: int(os.getenv("MIN_SAMPLES_FOR_BASELINE", "10"))
    )
    alert_cooldown_minutes: int = field(
        default_factory=lambda: int(os.getenv("ALERT_COOLDOWN_MINUTES", "15"))
    )
    auto_resolve_minutes: int = field(
        default_factory=lambda: int(os.getenv("AUTO_RESOLVE_MINUTES", "30"))
    )

    # Root cause detection settings (flexible/learnable)
    root_cause_enabled: bool = field(
        default_factory=lambda: os.getenv("ROOT_CAUSE_ENABLED", "true").lower() == "true"
    )
    # Comma-separated list of root cause types to enable (empty = all enabled)
    # Options: db_latency, db_error, dependency_latency, dependency_error, exception_surge, new_exception
    root_cause_types: str = field(
        default_factory=lambda: os.getenv("ROOT_CAUSE_TYPES", "")
    )
    # Per-type threshold multipliers (relative to base zscore_threshold)
    # Format: "db_latency:0.8,db_error:0.6,dependency:1.0,exception:1.2"
    root_cause_threshold_multipliers: str = field(
        default_factory=lambda: os.getenv("ROOT_CAUSE_THRESHOLDS", "db_error:0.8,dependency_error:0.9")
    )
    # Adaptive learning: adjust thresholds based on alert resolution patterns
    adaptive_thresholds_enabled: bool = field(
        default_factory=lambda: os.getenv("ADAPTIVE_THRESHOLDS", "true").lower() == "true"
    )
    # How much to adjust threshold when alerts are frequently auto-resolved (likely false positives)
    adaptive_threshold_adjustment: float = field(
        default_factory=lambda: float(os.getenv("ADAPTIVE_THRESHOLD_ADJUSTMENT", "0.1"))
    )

    # LLM Investigation settings
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY")
    )
    investigation_model: str = field(
        default_factory=lambda: os.getenv("INVESTIGATION_MODEL", "claude-3-5-haiku-20241022")
    )
    investigation_max_tokens: int = field(
        default_factory=lambda: int(os.getenv("INVESTIGATION_MAX_TOKENS", "1000"))
    )
    max_investigations_per_hour: int = field(
        default_factory=lambda: int(os.getenv("MAX_INVESTIGATIONS_PER_HOUR", "5"))
    )
    investigation_service_cooldown_minutes: int = field(
        default_factory=lambda: int(os.getenv("INVESTIGATION_SERVICE_COOLDOWN_MINUTES", "30"))
    )
    investigate_critical_only: bool = field(
        default_factory=lambda: os.getenv("INVESTIGATE_CRITICAL_ONLY", "false").lower() == "true"
    )

    def validate(self):
        """Validate required configuration."""
        if not self.trino_host:
            raise ValueError("TRINO_HOST environment variable is required")


class Severity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertType(Enum):
    # Symptom-based alerts (existing)
    ERROR_SPIKE = "error_spike"
    LATENCY_DEGRADATION = "latency_degradation"
    THROUGHPUT_DROP = "throughput_drop"
    ANOMALY = "anomaly"
    TREND = "trend"
    SERVICE_DOWN = "service_down"

    # Root cause alerts (new) - proactive detection of underlying issues
    DB_CONNECTION_FAILURE = "db_connection_failure"    # Database connection issues
    DB_SLOW_QUERIES = "db_slow_queries"                # Database query performance degradation
    DEPENDENCY_FAILURE = "dependency_failure"          # Downstream service failures
    DEPENDENCY_LATENCY = "dependency_latency"          # Downstream service slow responses
    EXCEPTION_SURGE = "exception_surge"                # Unusual increase in exceptions
    NEW_EXCEPTION_TYPE = "new_exception_type"          # Previously unseen exception type


class AlertStatus(Enum):
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


# =============================================================================
# Adaptive Threshold Manager
# =============================================================================

class AdaptiveThresholdManager:
    """
    Manages learned thresholds that adapt based on alert patterns.

    Learning logic:
    - If alerts for a metric type are frequently auto-resolved quickly -> increase threshold (reduce sensitivity)
    - If alerts lead to investigations with confirmed root causes -> decrease threshold (increase sensitivity)
    """

    def __init__(self, config: Config):
        self.config = config
        self.base_threshold = config.zscore_threshold

        # Parse configured threshold multipliers
        self.multipliers: Dict[str, float] = self._parse_multipliers(config.root_cause_threshold_multipliers)

        # Learned adjustments (loaded from DB, modified over time)
        self.learned_adjustments: Dict[str, float] = {}

        # Manual overrides: (service_name, category) -> absolute z-score value
        self.manual_overrides: Dict[Tuple[str, str], float] = {}

        # Parse enabled root cause types
        self.enabled_types: set = self._parse_enabled_types(config.root_cause_types)

    def _parse_multipliers(self, multiplier_str: str) -> Dict[str, float]:
        """Parse threshold multipliers from config string."""
        multipliers = {}
        if not multiplier_str:
            return multipliers

        for pair in multiplier_str.split(","):
            if ":" in pair:
                key, value = pair.strip().split(":", 1)
                try:
                    multipliers[key.strip()] = float(value.strip())
                except ValueError:
                    pass
        return multipliers

    def _parse_enabled_types(self, types_str: str) -> set:
        """Parse enabled root cause types from config string."""
        if not types_str:
            return set()  # Empty means all enabled
        return {t.strip() for t in types_str.split(",") if t.strip()}

    def is_root_cause_enabled(self, root_cause_type: str) -> bool:
        """Check if a specific root cause type is enabled."""
        if not self.config.root_cause_enabled:
            return False
        if not self.enabled_types:
            return True  # Empty set means all enabled
        return root_cause_type in self.enabled_types

    def get_threshold(self, metric_category: str, service_name: str = None) -> float:
        """
        Get the effective threshold for a metric category.

        If a manual override exists for (service_name, category), return it directly.
        Otherwise fall through to base * multiplier + learned logic.

        Categories: db_latency, db_error, dependency_latency, dependency_error, exception_surge, new_exception
        """
        # Check manual override first
        if service_name:
            key = (service_name, metric_category)
            if key in self.manual_overrides:
                return max(1.0, self.manual_overrides[key])

        # Start with base threshold
        threshold = self.base_threshold

        # Apply configured multiplier if exists
        if metric_category in self.multipliers:
            threshold *= self.multipliers[metric_category]
        # Also check partial matches (e.g., "db" matches "db_latency")
        else:
            for key, mult in self.multipliers.items():
                if metric_category.startswith(key) or key in metric_category:
                    threshold *= mult
                    break

        # Apply learned adjustment
        if self.config.adaptive_thresholds_enabled and metric_category in self.learned_adjustments:
            threshold += self.learned_adjustments[metric_category]

        return max(1.0, threshold)  # Never go below 1.0

    def learn_from_alert_history(self, executor: 'TrinoExecutor'):
        """
        Analyze alert history to adjust thresholds.

        - High auto-resolve rate + short duration -> likely false positives -> increase threshold
        - Alerts with investigations showing confirmed issues -> keep or lower threshold
        """
        if not self.config.adaptive_thresholds_enabled:
            return

        # Analyze alerts from last 7 days
        sql = """
            SELECT
                alert_type,
                metric_type,
                COUNT(*) as total_alerts,
                SUM(CASE WHEN auto_resolved = true THEN 1 ELSE 0 END) as auto_resolved_count
            FROM alerts
            WHERE created_at > current_timestamp - interval '7' day
            GROUP BY alert_type, metric_type
            HAVING COUNT(*) >= 5
        """
        try:
            results = executor.execute(sql)
        except Exception as e:
            print(f"[Adaptive] Could not analyze alert history: {e}")
            return

        for row in results:
            alert_type = row.get("alert_type", "")
            metric_type = row.get("metric_type", "")
            total = row.get("total_alerts", 0)
            auto_resolved = row.get("auto_resolved_count", 0)

            if total < 5:
                continue

            auto_resolve_rate = auto_resolved / total if total > 0 else 0

            # Determine the metric category
            category = self._get_metric_category(alert_type, metric_type)
            if not category:
                continue

            # High auto-resolve rate (>70%) suggests false positives - increase threshold
            if auto_resolve_rate > 0.7:
                adjustment = self.config.adaptive_threshold_adjustment
                self.learned_adjustments[category] = self.learned_adjustments.get(category, 0) + adjustment
                print(f"[Adaptive] Increasing threshold for {category} (auto-resolve rate: {auto_resolve_rate:.0%})")

            # Low auto-resolve rate (<30%) with many alerts - might be too sensitive
            elif auto_resolve_rate < 0.3 and total > 20:
                # Check if these led to investigations with findings
                inv_sql = f"""
                    SELECT COUNT(*) as investigated
                    FROM alert_investigations
                    WHERE alert_type = '{alert_type}'
                    AND investigated_at > current_timestamp - interval '7' day
                    AND root_cause_summary IS NOT NULL AND root_cause_summary != ''
                """
                inv_result = executor.execute(inv_sql)
                investigated = inv_result[0].get("investigated", 0) if inv_result else 0

                # If most alerts weren't investigated or had findings, they're valuable
                if investigated > total * 0.3:
                    # Keep threshold as is or slightly lower
                    adjustment = -self.config.adaptive_threshold_adjustment * 0.5
                    self.learned_adjustments[category] = self.learned_adjustments.get(category, 0) + adjustment
                    print(f"[Adaptive] Decreasing threshold for {category} (valuable alerts)")

        # Cap adjustments to prevent runaway
        for category in self.learned_adjustments:
            self.learned_adjustments[category] = max(-1.0, min(1.0, self.learned_adjustments[category]))

        # Persist learned adjustments to DB
        self.save_learned_adjustments(executor)

    def load_overrides_from_db(self, executor):
        """Load learned adjustments and manual overrides from threshold_overrides table."""
        sql = """
            SELECT service_name, metric_category, override_type, threshold_value
            FROM threshold_overrides
        """
        try:
            results = executor.execute(sql)
        except Exception as e:
            print(f"[Adaptive] Could not load overrides from DB: {e}")
            return

        for row in results:
            svc = row.get("service_name", "*")
            cat = row.get("metric_category", "")
            otype = row.get("override_type", "")
            val = row.get("threshold_value")
            if val is None:
                continue
            val = float(val)
            if otype == "learned" and svc == "*":
                self.learned_adjustments[cat] = val
            elif otype == "manual":
                self.manual_overrides[(svc, cat)] = val

        print(f"[Adaptive] Loaded {len(self.learned_adjustments)} learned adjustments, {len(self.manual_overrides)} manual overrides from DB")

    def save_learned_adjustments(self, executor):
        """Persist current learned adjustments to threshold_overrides table."""
        try:
            executor.execute("DELETE FROM threshold_overrides WHERE override_type = 'learned' AND service_name = '*'")
        except Exception as e:
            print(f"[Adaptive] Could not clear old learned adjustments: {e}")
            return

        now_str = "CURRENT_TIMESTAMP"
        for category, value in self.learned_adjustments.items():
            sql = f"""
                INSERT INTO threshold_overrides
                    (service_name, metric_category, override_type, threshold_value, created_by, created_at, updated_at)
                VALUES ('*', '{category}', 'learned', {value}, 'system', {now_str}, {now_str})
            """
            try:
                executor.execute(sql)
            except Exception as e:
                print(f"[Adaptive] Could not save learned adjustment for {category}: {e}")

    def set_manual_override(self, executor, service_name: str, category: str, value: float):
        """Set a manual threshold override for a service+category."""
        try:
            executor.execute(
                f"DELETE FROM threshold_overrides WHERE service_name = '{service_name}' "
                f"AND metric_category = '{category}' AND override_type = 'manual'"
            )
        except Exception:
            pass
        now_str = "CURRENT_TIMESTAMP"
        sql = f"""
            INSERT INTO threshold_overrides
                (service_name, metric_category, override_type, threshold_value, created_by, created_at, updated_at)
            VALUES ('{service_name}', '{category}', 'manual', {value}, 'user', {now_str}, {now_str})
        """
        executor.execute(sql)
        self.manual_overrides[(service_name, category)] = value

    def delete_manual_override(self, executor, service_name: str, category: str):
        """Remove a manual threshold override."""
        executor.execute(
            f"DELETE FROM threshold_overrides WHERE service_name = '{service_name}' "
            f"AND metric_category = '{category}' AND override_type = 'manual'"
        )
        self.manual_overrides.pop((service_name, category), None)

    def get_all_effective(self, service_name: str = None) -> Dict[str, Dict]:
        """Return effective thresholds for all categories with full breakdown."""
        all_categories = [
            "error_rate", "latency", "throughput",
            "db_latency", "db_error",
            "dependency_latency", "dependency_error",
            "exception_surge", "new_exception",
        ]
        result = {}
        for cat in all_categories:
            # Compute base * multiplier
            base = self.base_threshold
            mult = 1.0
            if cat in self.multipliers:
                mult = self.multipliers[cat]
            else:
                for key, m in self.multipliers.items():
                    if cat.startswith(key) or key in cat:
                        mult = m
                        break
            computed = base * mult
            learned_adj = self.learned_adjustments.get(cat, 0.0)
            manual_ov = None
            if service_name:
                manual_ov = self.manual_overrides.get((service_name, cat))

            if manual_ov is not None:
                effective = max(1.0, manual_ov)
                source = "manual"
            elif learned_adj != 0.0:
                effective = max(1.0, computed + learned_adj)
                source = "learned"
            else:
                effective = max(1.0, computed)
                source = "default"

            result[cat] = {
                "base": round(base, 2),
                "multiplier": round(mult, 2),
                "learned_adjustment": round(learned_adj, 2),
                "manual_override": round(manual_ov, 2) if manual_ov is not None else None,
                "effective": round(effective, 2),
                "source": source,
            }
        return result

    def _get_metric_category(self, alert_type: str, metric_type: str) -> str:
        """Map alert/metric type to a threshold category."""
        if "db_" in alert_type.lower() or metric_type.startswith("db_"):
            if "latency" in metric_type.lower():
                return "db_latency"
            elif "error" in metric_type.lower():
                return "db_error"
        elif "dependency" in alert_type.lower() or metric_type.startswith("dep_"):
            if "latency" in metric_type.lower():
                return "dependency_latency"
            elif "error" in metric_type.lower() or "rate" in metric_type.lower():
                return "dependency_error"
        elif "exception" in alert_type.lower():
            if "new_exception" in alert_type.lower():
                return "new_exception"
            return "exception_surge"
        return ""


# =============================================================================
# Trino Query Executor
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

    def execute(self, sql: str, return_error: bool = False) -> List[Dict[str, Any]]:
        """Execute a query and return results as list of dicts.

        If return_error=True, returns [{"error": "message"}] on failure instead of [].
        """
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
            # Try to reconnect on connection errors
            if "connection" in error_msg.lower():
                self._connect()
            if return_error:
                return [{"error": error_msg}]
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
# Baseline Computer
# =============================================================================

class BaselineComputer:
    """Computes statistical baselines from historical data."""

    def __init__(self, executor: TrinoExecutor, config: Config):
        self.executor = executor
        self.config = config
        self.baselines: Dict[str, Dict[str, Dict]] = {}  # service -> metric_type -> baseline

    def compute_all_baselines(self) -> Dict[str, Dict[str, Dict]]:
        """Compute baselines for all services and metrics."""
        print("[Baseline] Computing baselines...")

        # Get list of active services
        services = self._get_active_services()
        print(f"[Baseline] Found {len(services)} active services")

        for service in services:
            self.baselines[service] = {}

            # Compute error rate baseline
            error_baseline = self._compute_error_rate_baseline(service)
            if error_baseline:
                self.baselines[service]["error_rate"] = error_baseline
                self._store_baseline(service, "error_rate", error_baseline)

            # Compute latency baselines
            for percentile in ["p50", "p95", "p99"]:
                latency_baseline = self._compute_latency_baseline(service, percentile)
                if latency_baseline:
                    metric_type = f"latency_{percentile}"
                    self.baselines[service][metric_type] = latency_baseline
                    self._store_baseline(service, metric_type, latency_baseline)

            # Compute throughput baseline
            throughput_baseline = self._compute_throughput_baseline(service)
            if throughput_baseline:
                self.baselines[service]["throughput"] = throughput_baseline
                self._store_baseline(service, "throughput", throughput_baseline)

            # === ROOT CAUSE BASELINES ===

            # Compute database query baselines for this service
            db_baselines = self._compute_db_query_baselines(service)
            for db_metric, baseline in db_baselines.items():
                self.baselines[service][db_metric] = baseline
                self._store_baseline(service, db_metric, baseline)

            # Compute exception rate baseline
            exception_baseline = self._compute_exception_rate_baseline(service)
            if exception_baseline:
                self.baselines[service]["exception_rate"] = exception_baseline
                self._store_baseline(service, "exception_rate", exception_baseline)

            # Compute dependency latency baselines
            dep_baselines = self._compute_dependency_baselines(service)
            for dep_metric, baseline in dep_baselines.items():
                self.baselines[service][dep_metric] = baseline
                self._store_baseline(service, dep_metric, baseline)

        # Store known exception types across all services
        self._compute_known_exception_types()

        print(f"[Baseline] Computed baselines for {len(self.baselines)} services")
        return self.baselines

    def _get_active_services(self) -> List[str]:
        """Get list of services that have recent data."""
        sql = f"""
            SELECT DISTINCT service_name
            FROM traces_otel_analytic
            WHERE start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            AND service_name IS NOT NULL
            AND service_name != ''
        """
        results = self.executor.execute(sql)
        return [r["service_name"] for r in results]

    def _compute_error_rate_baseline(self, service: str) -> Optional[Dict]:
        """Compute error rate baseline for a service."""
        sql = f"""
            SELECT
                date_trunc('hour', start_time) as hour,
                COUNT(*) as total,
                SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                CAST(SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as error_rate
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            GROUP BY date_trunc('hour', start_time)
            HAVING COUNT(*) >= 10
            ORDER BY hour
        """
        results = self.executor.execute(sql)

        if len(results) < self.config.min_samples_for_baseline:
            return None

        error_rates = [r["error_rate"] for r in results if r["error_rate"] is not None]
        return self._compute_stats(error_rates)

    def _compute_latency_baseline(self, service: str, percentile: str) -> Optional[Dict]:
        """Compute latency baseline for a service."""
        pct_value = {"p50": 0.5, "p95": 0.95, "p99": 0.99}[percentile]

        sql = f"""
            SELECT
                date_trunc('hour', start_time) as hour,
                approx_percentile(duration_ns / 1e6, {pct_value}) as latency_ms
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            AND duration_ns > 0
            GROUP BY date_trunc('hour', start_time)
            HAVING COUNT(*) >= 10
            ORDER BY hour
        """
        results = self.executor.execute(sql)

        if len(results) < self.config.min_samples_for_baseline:
            return None

        latencies = [r["latency_ms"] for r in results if r["latency_ms"] is not None]
        return self._compute_stats(latencies)

    def _compute_throughput_baseline(self, service: str) -> Optional[Dict]:
        """Compute throughput (requests per minute) baseline."""
        sql = f"""
            SELECT
                date_trunc('minute', start_time) as minute,
                COUNT(*) as requests
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            AND span_kind = 'SERVER'
            GROUP BY date_trunc('minute', start_time)
            ORDER BY minute
        """
        results = self.executor.execute(sql)

        if len(results) < self.config.min_samples_for_baseline:
            return None

        throughputs = [r["requests"] for r in results if r["requests"] is not None]
        return self._compute_stats(throughputs)

    def _compute_stats(self, values: List[float]) -> Optional[Dict]:
        """Compute statistical measures from a list of values."""
        if not values or len(values) < 2:
            return None

        sorted_values = sorted(values)
        n = len(sorted_values)

        mean = statistics.mean(values)
        stddev = statistics.stdev(values) if len(values) > 1 else 0

        return {
            "mean": mean,
            "stddev": stddev,
            "min": min(values),
            "max": max(values),
            "p50": sorted_values[int(n * 0.5)],
            "p95": sorted_values[int(n * 0.95)] if n > 20 else sorted_values[-1],
            "p99": sorted_values[int(n * 0.99)] if n > 100 else sorted_values[-1],
            "sample_count": n,
        }

    def _store_baseline(self, service: str, metric_type: str, baseline: Dict):
        """Store baseline in database."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        sql = f"""
            INSERT INTO service_baselines (
                computed_at, service_name, metric_type,
                baseline_mean, baseline_stddev, baseline_min, baseline_max,
                baseline_p50, baseline_p95, baseline_p99,
                sample_count, window_hours
            ) VALUES (
                TIMESTAMP '{now}', '{service}', '{metric_type}',
                {baseline['mean']}, {baseline['stddev']}, {baseline['min']}, {baseline['max']},
                {baseline['p50']}, {baseline['p95']}, {baseline['p99']},
                {baseline['sample_count']}, {self.config.baseline_window_hours}
            )
        """
        self.executor.execute_write(sql)

    def get_baseline(self, service: str, metric_type: str) -> Optional[Dict]:
        """Get baseline for a service/metric, computing if needed."""
        if service in self.baselines and metric_type in self.baselines[service]:
            return self.baselines[service][metric_type]
        return None

    # =========================================================================
    # ROOT CAUSE BASELINE METHODS
    # =========================================================================

    def _compute_db_query_baselines(self, service: str) -> Dict[str, Dict]:
        """Compute database query latency and error rate baselines per db_system."""
        baselines = {}

        # Get database systems this service uses
        db_systems_sql = f"""
            SELECT DISTINCT db_system
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND db_system IS NOT NULL AND db_system != ''
            AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
        """
        db_systems = self.executor.execute(db_systems_sql)

        for row in db_systems:
            db_system = row["db_system"]

            # Database query latency baseline
            latency_sql = f"""
                SELECT
                    date_trunc('hour', start_time) as hour,
                    approx_percentile(duration_ns / 1e6, 0.95) as latency_p95
                FROM traces_otel_analytic
                WHERE service_name = '{service}'
                AND db_system = '{db_system}'
                AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
                AND duration_ns > 0
                GROUP BY date_trunc('hour', start_time)
                HAVING COUNT(*) >= 5
                ORDER BY hour
            """
            latency_results = self.executor.execute(latency_sql)

            if len(latency_results) >= self.config.min_samples_for_baseline:
                latencies = [r["latency_p95"] for r in latency_results if r["latency_p95"] is not None]
                if latencies:
                    stats = self._compute_stats(latencies)
                    if stats:
                        baselines[f"db_{db_system}_latency"] = stats

            # Database error rate baseline
            error_sql = f"""
                SELECT
                    date_trunc('hour', start_time) as hour,
                    COUNT(*) as total,
                    SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                    CAST(SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as error_rate
                FROM traces_otel_analytic
                WHERE service_name = '{service}'
                AND db_system = '{db_system}'
                AND start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
                GROUP BY date_trunc('hour', start_time)
                HAVING COUNT(*) >= 5
                ORDER BY hour
            """
            error_results = self.executor.execute(error_sql)

            if len(error_results) >= self.config.min_samples_for_baseline:
                error_rates = [r["error_rate"] for r in error_results if r["error_rate"] is not None]
                if error_rates:
                    stats = self._compute_stats(error_rates)
                    if stats:
                        baselines[f"db_{db_system}_error_rate"] = stats

        return baselines

    def _compute_exception_rate_baseline(self, service: str) -> Optional[Dict]:
        """Compute exception rate baseline from span events."""
        sql = f"""
            SELECT
                date_trunc('hour', timestamp) as hour,
                COUNT(*) as exception_count
            FROM span_events_otel_analytic
            WHERE service_name = '{service}'
            AND exception_type IS NOT NULL AND exception_type != ''
            AND timestamp > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            GROUP BY date_trunc('hour', timestamp)
            ORDER BY hour
        """
        results = self.executor.execute(sql)

        if len(results) < self.config.min_samples_for_baseline:
            return None

        counts = [r["exception_count"] for r in results if r["exception_count"] is not None]
        return self._compute_stats(counts) if counts else None

    def _compute_dependency_baselines(self, service: str) -> Dict[str, Dict]:
        """Compute latency and error rate baselines for downstream dependencies."""
        baselines = {}

        # Find downstream services this service calls
        deps_sql = f"""
            SELECT DISTINCT child.service_name as dependency
            FROM traces_otel_analytic parent
            JOIN traces_otel_analytic child
                ON parent.span_id = child.parent_span_id
                AND parent.trace_id = child.trace_id
            WHERE parent.service_name = '{service}'
            AND child.service_name != '{service}'
            AND child.service_name IS NOT NULL
            AND child.db_system IS NULL
            AND parent.start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
        """
        deps = self.executor.execute(deps_sql)

        for row in deps:
            dep_service = row["dependency"]

            # Dependency call latency baseline
            latency_sql = f"""
                SELECT
                    date_trunc('hour', child.start_time) as hour,
                    approx_percentile(child.duration_ns / 1e6, 0.95) as latency_p95
                FROM traces_otel_analytic parent
                JOIN traces_otel_analytic child
                    ON parent.span_id = child.parent_span_id
                    AND parent.trace_id = child.trace_id
                WHERE parent.service_name = '{service}'
                AND child.service_name = '{dep_service}'
                AND parent.start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
                AND child.duration_ns > 0
                GROUP BY date_trunc('hour', child.start_time)
                HAVING COUNT(*) >= 5
                ORDER BY hour
            """
            latency_results = self.executor.execute(latency_sql)

            if len(latency_results) >= self.config.min_samples_for_baseline:
                latencies = [r["latency_p95"] for r in latency_results if r["latency_p95"] is not None]
                if latencies:
                    stats = self._compute_stats(latencies)
                    if stats:
                        baselines[f"dep_{dep_service}_latency"] = stats

            # Dependency error rate baseline
            error_sql = f"""
                SELECT
                    date_trunc('hour', child.start_time) as hour,
                    COUNT(*) as total,
                    SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                    CAST(SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) / COUNT(*) as error_rate
                FROM traces_otel_analytic parent
                JOIN traces_otel_analytic child
                    ON parent.span_id = child.parent_span_id
                    AND parent.trace_id = child.trace_id
                WHERE parent.service_name = '{service}'
                AND child.service_name = '{dep_service}'
                AND parent.start_time > current_timestamp - interval '{self.config.baseline_window_hours}' hour
                GROUP BY date_trunc('hour', child.start_time)
                HAVING COUNT(*) >= 5
                ORDER BY hour
            """
            error_results = self.executor.execute(error_sql)

            if len(error_results) >= self.config.min_samples_for_baseline:
                error_rates = [r["error_rate"] for r in error_results if r["error_rate"] is not None]
                if error_rates:
                    stats = self._compute_stats(error_rates)
                    if stats:
                        baselines[f"dep_{dep_service}_error_rate"] = stats

        return baselines

    def _compute_known_exception_types(self):
        """Track known exception types per service for new exception detection."""
        sql = f"""
            SELECT service_name, exception_type, COUNT(*) as count
            FROM span_events_otel_analytic
            WHERE exception_type IS NOT NULL AND exception_type != ''
            AND timestamp > current_timestamp - interval '{self.config.baseline_window_hours}' hour
            GROUP BY service_name, exception_type
            HAVING COUNT(*) >= 3
        """
        results = self.executor.execute(sql)

        # Store known exception types per service
        self.known_exception_types: Dict[str, set] = {}
        for row in results:
            service = row["service_name"]
            exc_type = row["exception_type"]
            if service not in self.known_exception_types:
                self.known_exception_types[service] = set()
            self.known_exception_types[service].add(exc_type)

        total_types = sum(len(v) for v in self.known_exception_types.values())
        print(f"[Baseline] Tracked {total_types} known exception types across {len(self.known_exception_types)} services")

    def get_known_exception_types(self, service: str) -> set:
        """Get known exception types for a service."""
        return getattr(self, 'known_exception_types', {}).get(service, set())


# =============================================================================
# Anomaly Detector
# =============================================================================

class AnomalyDetector:
    """Detects anomalies using multiple methods."""

    def __init__(self, executor: TrinoExecutor, config: Config, baseline_computer: BaselineComputer):
        self.executor = executor
        self.config = config
        self.baseline_computer = baseline_computer

        # Adaptive threshold manager for root cause detection
        self.threshold_manager = AdaptiveThresholdManager(config)

        # Isolation Forest model (if sklearn available)
        self.isolation_forest = None
        if SKLEARN_AVAILABLE:
            self.isolation_forest = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )

    def learn_thresholds(self):
        """Learn adaptive thresholds from alert history."""
        self.threshold_manager.learn_from_alert_history(self.executor)

    def detect_all(self) -> List[Dict]:
        """Run all anomaly detection methods and return detected anomalies."""
        anomalies = []

        # Get current metrics for all services
        services = list(self.baseline_computer.baselines.keys())

        for service in services:
            # === SYMPTOM-BASED DETECTION (existing) ===

            # Check error rate
            error_anomaly = self._detect_error_rate_anomaly(service)
            if error_anomaly:
                anomalies.append(error_anomaly)

            # Check latency
            latency_anomaly = self._detect_latency_anomaly(service)
            if latency_anomaly:
                anomalies.append(latency_anomaly)

            # Check throughput drop
            throughput_anomaly = self._detect_throughput_anomaly(service)
            if throughput_anomaly:
                anomalies.append(throughput_anomaly)

            # Check for service down
            down_anomaly = self._detect_service_down(service)
            if down_anomaly:
                anomalies.append(down_anomaly)

            # === ROOT CAUSE DETECTION (new - configurable) ===
            if self.config.root_cause_enabled:
                # Check database health issues
                if self.threshold_manager.is_root_cause_enabled("db_latency") or \
                   self.threshold_manager.is_root_cause_enabled("db_error"):
                    db_anomalies = self._detect_database_issues(service)
                    anomalies.extend(db_anomalies)

                # Check dependency health issues
                if self.threshold_manager.is_root_cause_enabled("dependency_latency") or \
                   self.threshold_manager.is_root_cause_enabled("dependency_error"):
                    dep_anomalies = self._detect_dependency_issues(service)
                    anomalies.extend(dep_anomalies)

                # Check exception patterns
                if self.threshold_manager.is_root_cause_enabled("exception_surge") or \
                   self.threshold_manager.is_root_cause_enabled("new_exception"):
                    exc_anomalies = self._detect_exception_issues(service)
                    anomalies.extend(exc_anomalies)

        return anomalies

    def _detect_error_rate_anomaly(self, service: str) -> Optional[Dict]:
        """Detect error rate spikes."""
        # Get current error rate (last 5 minutes)
        sql = f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                CAST(SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) /
                    NULLIF(COUNT(*), 0) as error_rate
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '5' minute
        """
        results = self.executor.execute(sql)

        if not results or results[0]["total"] < 5:
            return None

        current_rate = results[0]["error_rate"] or 0
        baseline = self.baseline_computer.get_baseline(service, "error_rate")

        # Determine severity based on absolute thresholds and Z-score
        severity = None
        z_score = 0

        if baseline and baseline["stddev"] > 0:
            z_score = (current_rate - baseline["mean"]) / baseline["stddev"]

            if z_score > self.config.zscore_threshold:
                severity = Severity.WARNING
            if z_score > self.config.zscore_threshold * 1.5:
                severity = Severity.CRITICAL

        # Also check absolute thresholds
        if current_rate >= self.config.error_rate_critical:
            severity = Severity.CRITICAL
        elif current_rate >= self.config.error_rate_warning and severity is None:
            severity = Severity.WARNING

        if severity:
            self._store_anomaly_score(
                service, "error_rate", current_rate,
                baseline["mean"] if baseline else 0,
                baseline["mean"] if baseline else 0,
                baseline["stddev"] if baseline else 0,
                z_score, True, "zscore"
            )

            return {
                "service": service,
                "metric_type": "error_rate",
                "alert_type": AlertType.ERROR_SPIKE,
                "severity": severity,
                "current_value": current_rate,
                "baseline_value": baseline["mean"] if baseline else 0,
                "z_score": z_score,
                "message": f"Error rate {current_rate:.1%} exceeds baseline {baseline['mean']:.1%}" if baseline
                          else f"Error rate {current_rate:.1%} exceeds threshold"
            }

        return None

    def _detect_latency_anomaly(self, service: str) -> Optional[Dict]:
        """Detect latency degradation."""
        # Get current P95 latency
        sql = f"""
            SELECT
                approx_percentile(duration_ns / 1e6, 0.95) as latency_p95
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '5' minute
            AND duration_ns > 0
            HAVING COUNT(*) >= 5
        """
        results = self.executor.execute(sql)

        if not results or results[0]["latency_p95"] is None:
            return None

        current_latency = results[0]["latency_p95"]
        baseline = self.baseline_computer.get_baseline(service, "latency_p95")

        if not baseline or baseline["stddev"] == 0:
            return None

        z_score = (current_latency - baseline["mean"]) / baseline["stddev"]

        if z_score > self.config.zscore_threshold:
            severity = Severity.WARNING if z_score < self.config.zscore_threshold * 1.5 else Severity.CRITICAL

            self._store_anomaly_score(
                service, "latency_p95", current_latency,
                baseline["mean"], baseline["mean"], baseline["stddev"],
                z_score, True, "zscore"
            )

            return {
                "service": service,
                "metric_type": "latency_p95",
                "alert_type": AlertType.LATENCY_DEGRADATION,
                "severity": severity,
                "current_value": current_latency,
                "baseline_value": baseline["mean"],
                "z_score": z_score,
                "message": f"P95 latency {current_latency:.0f}ms exceeds baseline {baseline['mean']:.0f}ms (z={z_score:.1f})"
            }

        return None

    def _detect_throughput_anomaly(self, service: str) -> Optional[Dict]:
        """Detect throughput drops (potential upstream issues)."""
        # Get current throughput (requests per minute)
        sql = f"""
            SELECT COUNT(*) as requests
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '5' minute
            AND span_kind = 'SERVER'
        """
        results = self.executor.execute(sql)

        if not results:
            return None

        # Normalize to per-minute
        current_throughput = results[0]["requests"] / 5.0
        baseline = self.baseline_computer.get_baseline(service, "throughput")

        if not baseline or baseline["stddev"] == 0 or baseline["mean"] < 1:
            return None

        # For throughput, we care about drops (negative z-score)
        z_score = (current_throughput - baseline["mean"]) / baseline["stddev"]

        # Throughput drop is concerning when significantly below baseline
        if z_score < -self.config.zscore_threshold:
            severity = Severity.WARNING if z_score > -self.config.zscore_threshold * 1.5 else Severity.CRITICAL

            self._store_anomaly_score(
                service, "throughput", current_throughput,
                baseline["mean"], baseline["mean"], baseline["stddev"],
                z_score, True, "zscore"
            )

            pct_drop = (baseline["mean"] - current_throughput) / baseline["mean"] * 100

            return {
                "service": service,
                "metric_type": "throughput",
                "alert_type": AlertType.THROUGHPUT_DROP,
                "severity": severity,
                "current_value": current_throughput,
                "baseline_value": baseline["mean"],
                "z_score": z_score,
                "message": f"Throughput dropped {pct_drop:.0f}% ({current_throughput:.0f}/min vs {baseline['mean']:.0f}/min baseline)"
            }

        return None

    def _detect_service_down(self, service: str) -> Optional[Dict]:
        """Detect if a service has stopped sending data.

        Includes a data-age guard: if the oldest trace in the DB is less than
        1 hour old (e.g. after a database reset), we don't have enough history
        to reliably claim a service is down, so we skip the check.
        """
        # Guard: ensure we have at least 1 hour of data before firing this alert.
        # After a DB reset the oldest row will be very recent, making "no data in
        # the last hour" meaningless — every service would trigger.
        age_sql = """
            SELECT MIN(start_time) as oldest
            FROM traces_otel_analytic
        """
        age_results = self.executor.execute(age_sql)
        if age_results and age_results[0]["oldest"] is not None:
            oldest = age_results[0]["oldest"]
            try:
                from datetime import datetime, timezone, timedelta
                now_utc = datetime.now(timezone.utc)
                one_hour_ago = now_utc - timedelta(hours=1)

                if isinstance(oldest, datetime):
                    # Normalize to UTC-aware for comparison
                    if oldest.tzinfo is None:
                        oldest = oldest.replace(tzinfo=timezone.utc)
                    if oldest > one_hour_ago:
                        return None  # Not enough history yet
                elif isinstance(oldest, str):
                    oldest_dt = datetime.fromisoformat(oldest.replace('Z', '+00:00'))
                    if oldest_dt.tzinfo is None:
                        oldest_dt = oldest_dt.replace(tzinfo=timezone.utc)
                    if oldest_dt > one_hour_ago:
                        return None
            except (ValueError, TypeError):
                pass  # If we can't parse, proceed with normal detection

        sql = f"""
            SELECT
                MAX(start_time) as last_seen,
                current_timestamp - MAX(start_time) as time_since
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
            AND start_time > current_timestamp - interval '1' hour
        """
        results = self.executor.execute(sql)

        if not results or results[0]["last_seen"] is None:
            # No data in the last hour - service may be down
            return {
                "service": service,
                "metric_type": "availability",
                "alert_type": AlertType.SERVICE_DOWN,
                "severity": Severity.CRITICAL,
                "current_value": 0,
                "baseline_value": 1,
                "z_score": 0,
                "message": f"Service {service} has not sent telemetry in over 1 hour"
            }

        return None

    def _store_anomaly_score(
        self, service: str, metric_type: str, current_value: float,
        expected_value: float, baseline_mean: float, baseline_stddev: float,
        z_score: float, is_anomaly: bool, detection_method: str
    ):
        """Store anomaly score in database."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        anomaly_score = min(1.0, abs(z_score) / 5.0)  # Normalize z-score to 0-1

        sql = f"""
            INSERT INTO anomaly_scores (
                timestamp, service_name, metric_type,
                current_value, expected_value, baseline_mean, baseline_stddev,
                z_score, anomaly_score, is_anomaly, detection_method
            ) VALUES (
                TIMESTAMP '{now}', '{service}', '{metric_type}',
                {current_value}, {expected_value}, {baseline_mean}, {baseline_stddev},
                {z_score}, {anomaly_score}, {str(is_anomaly).lower()}, '{detection_method}'
            )
        """
        self.executor.execute_write(sql)

    # =========================================================================
    # ROOT CAUSE DETECTION METHODS
    # =========================================================================

    def _detect_database_issues(self, service: str) -> List[Dict]:
        """Detect database-related root causes: slow queries, connection failures."""
        anomalies = []

        # Get all database baselines for this service
        service_baselines = self.baseline_computer.baselines.get(service, {})
        db_metrics = [k for k in service_baselines.keys() if k.startswith("db_")]

        for metric in db_metrics:
            # Parse db_system from metric name (e.g., "db_postgresql_latency" -> "postgresql")
            parts = metric.split("_")
            if len(parts) < 3:
                continue

            db_system = parts[1]
            metric_type_suffix = parts[2]  # "latency" or "error_rate"

            baseline = service_baselines[metric]

            if metric_type_suffix == "latency":
                # Check database query latency
                sql = f"""
                    SELECT approx_percentile(duration_ns / 1e6, 0.95) as latency_p95
                    FROM traces_otel_analytic
                    WHERE service_name = '{service}'
                    AND db_system = '{db_system}'
                    AND start_time > current_timestamp - interval '5' minute
                    AND duration_ns > 0
                    HAVING COUNT(*) >= 3
                """
                results = self.executor.execute(sql)

                if results and results[0].get("latency_p95") is not None:
                    current_latency = results[0]["latency_p95"]

                    if baseline["stddev"] > 0:
                        z_score = (current_latency - baseline["mean"]) / baseline["stddev"]
                        threshold = self.threshold_manager.get_threshold("db_latency")

                        if z_score > threshold:
                            severity = Severity.WARNING if z_score < threshold * 1.5 else Severity.CRITICAL

                            self._store_anomaly_score(
                                service, metric, current_latency,
                                baseline["mean"], baseline["mean"], baseline["stddev"],
                                z_score, True, "zscore"
                            )

                            anomalies.append({
                                "service": service,
                                "metric_type": metric,
                                "alert_type": AlertType.DB_SLOW_QUERIES,
                                "severity": severity,
                                "current_value": current_latency,
                                "baseline_value": baseline["mean"],
                                "z_score": z_score,
                                "message": f"Database {db_system} queries slow: {current_latency:.0f}ms P95 (baseline: {baseline['mean']:.0f}ms, z={z_score:.1f})"
                            })

            elif metric_type_suffix == "error" or metric.endswith("_error_rate"):
                # Check database error rate (connection failures, query errors)
                sql = f"""
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                        CAST(SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) /
                            NULLIF(COUNT(*), 0) as error_rate
                    FROM traces_otel_analytic
                    WHERE service_name = '{service}'
                    AND db_system = '{db_system}'
                    AND start_time > current_timestamp - interval '5' minute
                """
                results = self.executor.execute(sql)

                if results and results[0].get("total", 0) >= 3:
                    current_rate = results[0].get("error_rate") or 0

                    if baseline["stddev"] > 0:
                        z_score = (current_rate - baseline["mean"]) / baseline["stddev"]
                        threshold = self.threshold_manager.get_threshold("db_error")

                        # Database errors use adaptive threshold
                        if z_score > threshold or current_rate > 0.1:
                            severity = Severity.CRITICAL if current_rate > 0.2 or z_score > threshold * 1.5 else Severity.WARNING

                            self._store_anomaly_score(
                                service, metric, current_rate,
                                baseline["mean"], baseline["mean"], baseline["stddev"],
                                z_score, True, "zscore"
                            )

                            anomalies.append({
                                "service": service,
                                "metric_type": metric,
                                "alert_type": AlertType.DB_CONNECTION_FAILURE,
                                "severity": severity,
                                "current_value": current_rate,
                                "baseline_value": baseline["mean"],
                                "z_score": z_score,
                                "message": f"Database {db_system} errors: {current_rate:.1%} error rate (baseline: {baseline['mean']:.1%})"
                            })

        return anomalies

    def _detect_dependency_issues(self, service: str) -> List[Dict]:
        """Detect dependency-related root causes: downstream service failures, latency."""
        anomalies = []

        # Get all dependency baselines for this service
        service_baselines = self.baseline_computer.baselines.get(service, {})
        dep_metrics = [k for k in service_baselines.keys() if k.startswith("dep_")]

        for metric in dep_metrics:
            # Parse dependency service from metric name (e.g., "dep_auth-service_latency")
            parts = metric.split("_")
            if len(parts) < 3:
                continue

            # Handle service names with underscores
            dep_service = "_".join(parts[1:-1])
            metric_type_suffix = parts[-1]  # "latency" or "error_rate"

            baseline = service_baselines[metric]

            if metric_type_suffix == "latency":
                # Check dependency call latency
                sql = f"""
                    SELECT approx_percentile(child.duration_ns / 1e6, 0.95) as latency_p95
                    FROM traces_otel_analytic parent
                    JOIN traces_otel_analytic child
                        ON parent.span_id = child.parent_span_id
                        AND parent.trace_id = child.trace_id
                    WHERE parent.service_name = '{service}'
                    AND child.service_name = '{dep_service}'
                    AND parent.start_time > current_timestamp - interval '5' minute
                    AND child.duration_ns > 0
                    HAVING COUNT(*) >= 3
                """
                results = self.executor.execute(sql)

                if results and results[0].get("latency_p95") is not None:
                    current_latency = results[0]["latency_p95"]

                    if baseline["stddev"] > 0:
                        z_score = (current_latency - baseline["mean"]) / baseline["stddev"]
                        threshold = self.threshold_manager.get_threshold("dependency_latency")

                        if z_score > threshold:
                            severity = Severity.WARNING if z_score < threshold * 1.5 else Severity.CRITICAL

                            self._store_anomaly_score(
                                service, metric, current_latency,
                                baseline["mean"], baseline["mean"], baseline["stddev"],
                                z_score, True, "zscore"
                            )

                            anomalies.append({
                                "service": service,
                                "metric_type": metric,
                                "alert_type": AlertType.DEPENDENCY_LATENCY,
                                "severity": severity,
                                "current_value": current_latency,
                                "baseline_value": baseline["mean"],
                                "z_score": z_score,
                                "message": f"Dependency {dep_service} slow: {current_latency:.0f}ms P95 (baseline: {baseline['mean']:.0f}ms, z={z_score:.1f})"
                            })

            elif metric_type_suffix == "rate":  # error_rate
                # Check dependency error rate
                sql = f"""
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
                        CAST(SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) AS DOUBLE) /
                            NULLIF(COUNT(*), 0) as error_rate
                    FROM traces_otel_analytic parent
                    JOIN traces_otel_analytic child
                        ON parent.span_id = child.parent_span_id
                        AND parent.trace_id = child.trace_id
                    WHERE parent.service_name = '{service}'
                    AND child.service_name = '{dep_service}'
                    AND parent.start_time > current_timestamp - interval '5' minute
                """
                results = self.executor.execute(sql)

                if results and results[0].get("total", 0) >= 3:
                    current_rate = results[0].get("error_rate") or 0

                    if baseline["stddev"] > 0:
                        z_score = (current_rate - baseline["mean"]) / baseline["stddev"]
                        threshold = self.threshold_manager.get_threshold("dependency_error")

                        if z_score > threshold or current_rate > 0.15:
                            severity = Severity.CRITICAL if current_rate > 0.25 or z_score > threshold * 1.5 else Severity.WARNING

                            self._store_anomaly_score(
                                service, metric, current_rate,
                                baseline["mean"], baseline["mean"], baseline["stddev"],
                                z_score, True, "zscore"
                            )

                            anomalies.append({
                                "service": service,
                                "metric_type": metric,
                                "alert_type": AlertType.DEPENDENCY_FAILURE,
                                "severity": severity,
                                "current_value": current_rate,
                                "baseline_value": baseline["mean"],
                                "z_score": z_score,
                                "message": f"Dependency {dep_service} failing: {current_rate:.1%} error rate (baseline: {baseline['mean']:.1%})"
                            })

        return anomalies

    def _detect_exception_issues(self, service: str) -> List[Dict]:
        """Detect exception-related root causes: surges and new exception types."""
        anomalies = []

        # Check exception rate surge
        baseline = self.baseline_computer.get_baseline(service, "exception_rate")
        if baseline:
            sql = f"""
                SELECT COUNT(*) as exception_count
                FROM span_events_otel_analytic
                WHERE service_name = '{service}'
                AND exception_type IS NOT NULL AND exception_type != ''
                AND timestamp > current_timestamp - interval '5' minute
            """
            results = self.executor.execute(sql)

            if results:
                # Normalize to hourly rate for comparison (5 min -> 1 hour = multiply by 12)
                current_count = results[0].get("exception_count", 0)
                current_hourly_rate = current_count * 12

                # Require minimum 3 exceptions in 5 min to avoid noise from single events
                # and hourly rate must be at least 2x baseline mean
                min_count = 3
                min_rate_multiplier = 2.0
                if (baseline["stddev"] > 0 and current_count >= min_count
                        and current_hourly_rate > baseline["mean"] * min_rate_multiplier):
                    z_score = (current_hourly_rate - baseline["mean"]) / baseline["stddev"]
                    threshold = self.threshold_manager.get_threshold("exception_surge")

                    if z_score > threshold:
                        severity = Severity.WARNING if z_score < threshold * 1.5 else Severity.CRITICAL

                        self._store_anomaly_score(
                            service, "exception_rate", current_hourly_rate,
                            baseline["mean"], baseline["mean"], baseline["stddev"],
                            z_score, True, "zscore"
                        )

                        anomalies.append({
                            "service": service,
                            "metric_type": "exception_rate",
                            "alert_type": AlertType.EXCEPTION_SURGE,
                            "severity": severity,
                            "current_value": current_hourly_rate,
                            "baseline_value": baseline["mean"],
                            "z_score": z_score,
                            "message": f"Exception surge: {current_count} exceptions in 5 min (~{current_hourly_rate:.0f}/hour, baseline: {baseline['mean']:.0f}/hour)"
                        })

        # Check for new/unknown exception types
        known_types = self.baseline_computer.get_known_exception_types(service)
        if known_types:  # Only check if we have baseline exception types
            sql = f"""
                SELECT DISTINCT exception_type, COUNT(*) as count
                FROM span_events_otel_analytic
                WHERE service_name = '{service}'
                AND exception_type IS NOT NULL AND exception_type != ''
                AND timestamp > current_timestamp - interval '15' minute
                GROUP BY exception_type
                HAVING COUNT(*) >= 2
            """
            results = self.executor.execute(sql)

            for row in results:
                exc_type = row["exception_type"]
                exc_count = row["count"]

                if exc_type not in known_types:
                    # New exception type detected
                    anomalies.append({
                        "service": service,
                        "metric_type": f"new_exception:{exc_type[:50]}",
                        "alert_type": AlertType.NEW_EXCEPTION_TYPE,
                        "severity": Severity.WARNING,
                        "current_value": exc_count,
                        "baseline_value": 0,
                        "z_score": 0,
                        "message": f"New exception type detected: {exc_type} ({exc_count} occurrences in 15 min)"
                    })

        return anomalies


# =============================================================================
# Alert Manager
# =============================================================================

class AlertManager:
    """Manages alert lifecycle: creation, deduplication, and resolution."""

    def __init__(self, executor: TrinoExecutor, config: Config, context_capture: 'IncidentContextCapture' = None):
        self.executor = executor
        self.config = config
        self.context_capture = context_capture
        self.active_alerts: Dict[str, Dict] = {}  # key -> alert
        self._load_active_alerts()

    def _load_active_alerts(self):
        """Load active alerts from database."""
        sql = """
            SELECT
                alert_id, service_name, alert_type, metric_type,
                created_at, severity, current_value
            FROM alerts
            WHERE status = 'active'
        """
        results = self.executor.execute(sql)

        for alert in results:
            key = self._alert_key(alert["service_name"], alert["alert_type"], alert["metric_type"])
            self.active_alerts[key] = alert

        print(f"[Alerts] Loaded {len(self.active_alerts)} active alerts")

    def _alert_key(self, service: str, alert_type: str, metric_type: str) -> str:
        """Generate unique key for alert deduplication."""
        return f"{service}:{alert_type}:{metric_type}"

    def process_anomalies(self, anomalies: List[Dict]) -> Tuple[int, int, List[Dict]]:
        """Process detected anomalies and create/update alerts. Returns (created, updated, new_alerts)."""
        created = 0
        updated = 0
        new_alerts = []

        seen_keys = set()

        for anomaly in anomalies:
            service = anomaly["service"]
            alert_type = anomaly["alert_type"].value
            metric_type = anomaly["metric_type"]
            key = self._alert_key(service, alert_type, metric_type)
            seen_keys.add(key)

            if key in self.active_alerts:
                # Update existing alert
                self._update_alert(key, anomaly)
                updated += 1
            else:
                # Check cooldown
                if not self._in_cooldown(service, alert_type, metric_type):
                    # Create new alert
                    alert_info = self._create_alert(anomaly)
                    if alert_info:
                        new_alerts.append(alert_info)
                    created += 1

        # Auto-resolve alerts that are no longer anomalous
        resolved = self._auto_resolve(seen_keys)

        if created or updated or resolved:
            print(f"[Alerts] Created: {created}, Updated: {updated}, Auto-resolved: {resolved}")

        return created, updated, new_alerts

    def _in_cooldown(self, service: str, alert_type: str, metric_type: str) -> bool:
        """Check if alert is in cooldown period after resolution."""
        sql = f"""
            SELECT created_at
            FROM alerts
            WHERE service_name = '{service}'
            AND alert_type = '{alert_type}'
            AND metric_type = '{metric_type}'
            AND status = 'resolved'
            AND resolved_at > current_timestamp - interval '{self.config.alert_cooldown_minutes}' minute
            ORDER BY resolved_at DESC
            LIMIT 1
        """
        results = self.executor.execute(sql)
        return len(results) > 0

    def _create_alert(self, anomaly: Dict) -> Optional[Dict]:
        """Create a new alert and return alert info for investigation."""
        alert_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        service = anomaly["service"]
        alert_type = anomaly["alert_type"].value
        severity = anomaly["severity"].value
        metric_type = anomaly["metric_type"]

        title = f"{alert_type.replace('_', ' ').title()} - {service}"
        description = anomaly["message"]

        sql = f"""
            INSERT INTO alerts (
                alert_id, created_at, updated_at, service_name,
                alert_type, severity, title, description,
                metric_type, current_value, threshold_value, baseline_value,
                z_score, status, auto_resolved
            ) VALUES (
                '{alert_id}', TIMESTAMP '{now}', TIMESTAMP '{now}', '{service}',
                '{alert_type}', '{severity}', '{title}', '{description}',
                '{metric_type}', {anomaly['current_value']}, 0, {anomaly['baseline_value']},
                {anomaly['z_score']}, 'active', false
            )
        """

        if self.executor.execute_write(sql):
            key = self._alert_key(service, alert_type, metric_type)
            alert_info = {
                "alert_id": alert_id,
                "service_name": service,
                "alert_type": alert_type,
                "metric_type": metric_type,
                "severity": severity,
                "description": description,
            }
            self.active_alerts[key] = alert_info
            print(f"[Alert] CREATED [{severity.upper()}] {title}: {description}")

            # Capture incident context
            if self.context_capture:
                try:
                    anomaly_scores_data = {
                        metric_type: {
                            "current_value": anomaly["current_value"],
                            "z_score": anomaly["z_score"],
                            "baseline_value": anomaly["baseline_value"],
                        }
                    }
                    baselines_data = {
                        metric_type: {
                            "mean": anomaly["baseline_value"],
                        }
                    }
                    self.context_capture.capture_context(
                        alert_id, service, alert_type, severity,
                        anomaly_scores=anomaly_scores_data,
                        baselines=baselines_data
                    )
                except Exception as e:
                    print(f"[Alert] Context capture failed: {e}")

            return alert_info
        return None

    def _update_alert(self, key: str, anomaly: Dict):
        """Update an existing alert with new values."""
        alert = self.active_alerts[key]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        sql = f"""
            UPDATE alerts
            SET updated_at = TIMESTAMP '{now}',
                current_value = {anomaly['current_value']},
                z_score = {anomaly['z_score']},
                severity = '{anomaly['severity'].value}'
            WHERE alert_id = '{alert['alert_id']}'
        """
        self.executor.execute_write(sql)

    def _auto_resolve(self, seen_keys: set) -> int:
        """Auto-resolve alerts that are no longer anomalous."""
        resolved = 0
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        keys_to_remove = []

        for key, alert in self.active_alerts.items():
            if key not in seen_keys:
                # Alert condition no longer present
                sql = f"""
                    UPDATE alerts
                    SET status = 'resolved',
                        resolved_at = TIMESTAMP '{now}',
                        auto_resolved = true
                    WHERE alert_id = '{alert['alert_id']}'
                """
                if self.executor.execute_write(sql):
                    keys_to_remove.append(key)
                    resolved += 1
                    print(f"[Alert] AUTO-RESOLVED: {alert['service_name']} - {alert['alert_type']}")

        for key in keys_to_remove:
            del self.active_alerts[key]

        return resolved


# =============================================================================
# Incident Context Capture
# =============================================================================

class IncidentContextCapture:
    """Captures a snapshot of surrounding telemetry when an alert fires."""

    def __init__(self, executor: TrinoExecutor):
        self.executor = executor

    def capture_context(
        self, alert_id: str, service: str, alert_type: str, severity: str,
        anomaly_scores: Optional[Dict] = None, baselines: Optional[Dict] = None
    ) -> Optional[str]:
        """Capture full incident context and store it. Returns context_id."""
        context_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        metrics_snapshot = self._capture_metrics_window(service)
        error_traces = self._capture_error_traces(service)
        log_snapshot = self._capture_logs(service)
        topology_snapshot = self._capture_topology(service)

        # Determine metric types for fingerprint
        metric_types = []
        if anomaly_scores:
            metric_types = list(anomaly_scores.keys()) if isinstance(anomaly_scores, dict) else []
        fingerprint = self._compute_fingerprint(service, alert_type, metric_types)

        baselines_json = json.dumps(baselines or {}).replace("'", "''")
        anomaly_json = json.dumps(anomaly_scores or {}).replace("'", "''")

        sql = f"""
            INSERT INTO incident_context (
                context_id, alert_id, captured_at, service_name, alert_type,
                severity, fingerprint, metrics_snapshot, error_traces,
                log_snapshot, topology_snapshot, baseline_values, anomaly_scores
            ) VALUES (
                '{context_id}', '{alert_id}', TIMESTAMP '{now_str}', '{service}',
                '{alert_type}', '{severity}', '{fingerprint}',
                '{metrics_snapshot}', '{error_traces}', '{log_snapshot}',
                '{topology_snapshot}', '{baselines_json}', '{anomaly_json}'
            )
        """

        if self.executor.execute_write(sql):
            print(f"[Context] Captured incident context {context_id} for alert {alert_id}")
            return context_id
        return None

    def _capture_metrics_window(self, service: str) -> str:
        """Query last 10 min of metrics for the service."""
        rows = self.executor.execute(f"""
            SELECT metric_name,
                   COUNT(*) as data_points,
                   AVG(value_double) as avg_val,
                   MIN(value_double) as min_val,
                   MAX(value_double) as max_val
            FROM metrics_otel_analytic
            WHERE service_name = '{service}'
              AND timestamp > current_timestamp - INTERVAL '10' MINUTE
            GROUP BY metric_name
            ORDER BY metric_name
            LIMIT 50
        """)
        result = []
        for r in rows:
            result.append({
                "metric": r.get("metric_name", ""),
                "data_points": r.get("data_points", 0),
                "avg": round(r.get("avg_val", 0) or 0, 6),
                "min": round(r.get("min_val", 0) or 0, 6),
                "max": round(r.get("max_val", 0) or 0, 6),
            })
        return json.dumps(result).replace("'", "''")

    def _capture_error_traces(self, service: str) -> str:
        """Query last 10 min of error traces."""
        rows = self.executor.execute(f"""
            SELECT trace_id, span_id, span_name, duration_ns, start_time
            FROM traces_otel_analytic
            WHERE service_name = '{service}'
              AND status_code = 'ERROR'
              AND start_time > current_timestamp - INTERVAL '10' MINUTE
            ORDER BY start_time DESC
            LIMIT 20
        """)
        result = []
        for r in rows:
            result.append({
                "trace_id": r.get("trace_id", ""),
                "span_name": r.get("span_name", ""),
                "duration_ms": round((r.get("duration_ns", 0) or 0) / 1e6, 2),
            })
        return json.dumps(result).replace("'", "''")

    def _capture_logs(self, service: str) -> str:
        """Query last 10 min of WARN/ERROR logs."""
        rows = self.executor.execute(f"""
            SELECT severity_text, body_text, timestamp
            FROM logs_otel_analytic
            WHERE service_name = '{service}'
              AND severity_number >= 9
              AND timestamp > current_timestamp - INTERVAL '10' MINUTE
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        result = []
        for r in rows:
            body = r.get("body_text", "") or ""
            result.append({
                "severity": r.get("severity_text", ""),
                "message": body[:500],
            })
        return json.dumps(result).replace("'", "''")

    def _capture_topology(self, service: str) -> str:
        """Query topology dependencies for the service."""
        rows = self.executor.execute(f"""
            SELECT target_service, dependency_type, call_count, avg_latency_ms, error_pct
            FROM topology_dependencies
            WHERE source_service = '{service}'
            LIMIT 20
        """)
        result = []
        for r in rows:
            result.append({
                "target": r.get("target_service", ""),
                "type": r.get("dependency_type", ""),
                "calls": r.get("call_count", 0),
                "latency_ms": round(r.get("avg_latency_ms", 0) or 0, 2),
                "error_pct": round(r.get("error_pct", 0) or 0, 4),
            })
        return json.dumps(result).replace("'", "''")

    def _compute_fingerprint(self, service: str, alert_type: str, metric_types: List[str]) -> str:
        """SHA256 hash for pattern matching."""
        key = f"{service}|{alert_type}|{','.join(sorted(metric_types))}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# =============================================================================
# Resource Trend Predictor
# =============================================================================

class ResourceTrendPredictor:
    """Linear regression predictor for resource exhaustion."""

    # Resource metric mappings and thresholds
    RESOURCE_METRICS = {
        "disk": {"metric": "system.filesystem.utilization", "threshold": 0.95},
        "memory": {"metric": "system.memory.utilization", "threshold": 0.95},
        "cpu": {"metric": "system.cpu.utilization", "threshold": 0.95},
    }

    def __init__(self, executor: TrinoExecutor):
        self.executor = executor

    def predict_all(self) -> List[Dict]:
        """Run predictions for all known hosts. Returns list of prediction dicts."""
        # Expire stale predictions first
        self._expire_stale_predictions()

        # Get known hosts
        hosts = self.executor.execute("""
            SELECT DISTINCT host_name FROM topology_hosts
            WHERE last_seen > current_timestamp - INTERVAL '1' HOUR
            LIMIT 50
        """)

        predictions = []
        for h in hosts:
            host_name = h.get("host_name", "")
            if not host_name:
                continue
            preds = self._predict_host_resources(host_name)
            predictions.extend(preds)

        return predictions

    def _predict_host_resources(self, host: str) -> List[Dict]:
        """Check all resource types for a given host."""
        predictions = []

        for resource_type, info in self.RESOURCE_METRICS.items():
            metric_name = info["metric"]
            threshold = info["threshold"]

            ts = self._query_resource_timeseries(host, metric_name, hours=2)
            if len(ts) < 5:
                continue

            x = [p[0] for p in ts]  # timestamps as hours from first point
            y = [p[1] for p in ts]  # values

            slope, intercept, r_squared = self._linear_regression(x, y)

            # Only predict if trending up with decent fit and exhaustion within 24h
            if slope <= 0 or r_squared < 0.7:
                continue

            current_value = y[-1]
            if current_value >= threshold:
                continue  # Already exhausted

            hours_to_threshold = (threshold - current_value) / slope
            if hours_to_threshold > 24 or hours_to_threshold <= 0:
                continue

            # Confidence based on R²
            if r_squared > 0.9:
                confidence = "high"
            elif r_squared > 0.7:
                confidence = "medium"
            else:
                confidence = "low"

            now = datetime.now(timezone.utc)
            exhaustion_at = now + timedelta(hours=hours_to_threshold)

            prediction = {
                "host_name": host,
                "resource_type": resource_type,
                "service_name": None,
                "current_value": round(current_value, 4),
                "trend_slope": round(slope, 6),
                "trend_r_squared": round(r_squared, 4),
                "predicted_exhaustion_at": exhaustion_at,
                "threshold_value": threshold,
                "hours_until_exhaustion": round(hours_to_threshold, 2),
                "confidence": confidence,
            }

            self._store_prediction(prediction)
            predictions.append(prediction)
            print(f"[Predictor] {resource_type} on {host}: {current_value:.1%} → {threshold:.0%} in {hours_to_threshold:.1f}h (r²={r_squared:.3f})")

        return predictions

    def _query_resource_timeseries(self, host: str, metric_name: str, hours: int = 2) -> List[Tuple[float, float]]:
        """Get time-series from metrics_otel_analytic. Returns [(hours_offset, value), ...]."""
        rows = self.executor.execute(f"""
            SELECT timestamp, value_double
            FROM metrics_otel_analytic
            WHERE attributes_flat LIKE '%{host}%'
              AND metric_name = '{metric_name}'
              AND timestamp > current_timestamp - INTERVAL '{hours}' HOUR
            ORDER BY timestamp
            LIMIT 500
        """)

        if not rows:
            return []

        points = []
        first_ts = None
        for r in rows:
            ts = r.get("timestamp")
            val = r.get("value_double")
            if ts is None or val is None:
                continue
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if first_ts is None:
                first_ts = ts
            hours_offset = (ts - first_ts).total_seconds() / 3600.0
            points.append((hours_offset, float(val)))

        return points

    @staticmethod
    def _linear_regression(x: List[float], y: List[float]) -> Tuple[float, float, float]:
        """Pure Python linear regression. Returns (slope, intercept, r_squared)."""
        n = len(x)
        if n < 2:
            return 0.0, 0.0, 0.0

        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        sum_y2 = sum(yi * yi for yi in y)

        denom = n * sum_x2 - sum_x * sum_x
        if abs(denom) < 1e-12:
            return 0.0, sum_y / n if n else 0.0, 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n

        # R-squared
        ss_res = sum((yi - (slope * xi + intercept)) ** 2 for xi, yi in zip(x, y))
        mean_y = sum_y / n
        ss_tot = sum((yi - mean_y) ** 2 for yi in y)

        if abs(ss_tot) < 1e-12:
            r_squared = 0.0
        else:
            r_squared = 1.0 - ss_res / ss_tot

        return slope, intercept, max(0.0, r_squared)

    def _store_prediction(self, prediction: Dict):
        """INSERT into resource_predictions."""
        prediction_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        exhaustion_str = prediction["predicted_exhaustion_at"]
        if isinstance(exhaustion_str, datetime):
            exhaustion_str = exhaustion_str.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        service_val = f"'{prediction['service_name']}'" if prediction.get("service_name") else "NULL"

        sql = f"""
            INSERT INTO resource_predictions (
                prediction_id, created_at, host_name, resource_type, service_name,
                current_value, trend_slope, trend_r_squared, predicted_exhaustion_at,
                threshold_value, hours_until_exhaustion, confidence, status
            ) VALUES (
                '{prediction_id}', TIMESTAMP '{now}', '{prediction["host_name"]}',
                '{prediction["resource_type"]}', {service_val},
                {prediction["current_value"]}, {prediction["trend_slope"]},
                {prediction["trend_r_squared"]}, TIMESTAMP '{exhaustion_str}',
                {prediction["threshold_value"]}, {prediction["hours_until_exhaustion"]},
                '{prediction["confidence"]}', 'active'
            )
        """
        self.executor.execute_write(sql)

    def _expire_stale_predictions(self):
        """Mark old predictions as 'expired'."""
        self.executor.execute_write("""
            UPDATE resource_predictions
            SET status = 'expired'
            WHERE status = 'active'
              AND predicted_exhaustion_at < current_timestamp
        """)


# =============================================================================
# Pattern Matcher
# =============================================================================

class PatternMatcher:
    """Identifies recurring incident fingerprints from incident_context data."""

    def __init__(self, executor: TrinoExecutor):
        self.executor = executor

    def match_pattern(self, fingerprint: str, service: str, alert_type: str) -> Optional[Dict]:
        """Check if this fingerprint matches a known pattern."""
        rows = self.executor.execute(f"""
            SELECT pattern_id, occurrence_count, first_seen, last_seen,
                   avg_duration_minutes, common_root_cause, precursor_signals
            FROM incident_patterns
            WHERE fingerprint = '{fingerprint}'
            LIMIT 1
        """)
        if rows:
            r = rows[0]
            precursors = r.get("precursor_signals")
            if precursors:
                try:
                    precursors = json.loads(precursors)
                except (json.JSONDecodeError, TypeError):
                    pass
            return {
                "pattern_id": r.get("pattern_id"),
                "occurrence_count": r.get("occurrence_count", 0),
                "first_seen": str(r.get("first_seen", "")),
                "last_seen": str(r.get("last_seen", "")),
                "avg_duration_minutes": r.get("avg_duration_minutes"),
                "common_root_cause": r.get("common_root_cause"),
                "precursor_signals": precursors,
            }
        return None

    def update_patterns(self):
        """Aggregate incident_context data into incident_patterns."""
        print("[PatternMatcher] Updating patterns from incident context data...")

        # Group by fingerprint in incident_context
        rows = self.executor.execute("""
            SELECT fingerprint, service_name, alert_type,
                   COUNT(*) as occurrence_count,
                   MIN(captured_at) as first_seen,
                   MAX(captured_at) as last_seen
            FROM incident_context
            GROUP BY fingerprint, service_name, alert_type
            HAVING COUNT(*) >= 2
            LIMIT 100
        """)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        updated = 0

        for r in rows:
            fingerprint = r.get("fingerprint", "")
            service = r.get("service_name", "")
            alert_type = r.get("alert_type", "")
            occ_count = r.get("occurrence_count", 0)
            first_seen = r.get("first_seen")
            last_seen = r.get("last_seen")

            if isinstance(first_seen, datetime):
                first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                first_seen_str = str(first_seen)[:23] if first_seen else now

            if isinstance(last_seen, datetime):
                last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            else:
                last_seen_str = str(last_seen)[:23] if last_seen else now

            # Compute average duration from resolved alerts with matching fingerprint
            avg_duration = self._compute_avg_duration(fingerprint)

            # Get common root cause from investigations
            common_root_cause = self._get_common_root_cause(service, alert_type)

            # Compute precursor signals
            precursors = self._compute_precursors(service, alert_type)
            precursors_json = json.dumps(precursors).replace("'", "''")

            # Check if pattern already exists
            existing = self.executor.execute(
                f"SELECT pattern_id FROM incident_patterns WHERE fingerprint = '{fingerprint}' LIMIT 1"
            )

            if existing:
                # Update existing pattern
                pattern_id = existing[0].get("pattern_id", "")
                root_cause_escaped = (common_root_cause or "").replace("'", "''")[:2000]
                sql = f"""
                    UPDATE incident_patterns
                    SET occurrence_count = {occ_count},
                        last_seen = TIMESTAMP '{last_seen_str}',
                        avg_duration_minutes = {avg_duration},
                        common_root_cause = '{root_cause_escaped}',
                        precursor_signals = '{precursors_json}',
                        updated_at = TIMESTAMP '{now}'
                    WHERE pattern_id = '{pattern_id}'
                """
            else:
                # Insert new pattern
                pattern_id = str(uuid.uuid4())[:8]
                root_cause_escaped = (common_root_cause or "").replace("'", "''")[:2000]
                sql = f"""
                    INSERT INTO incident_patterns (
                        pattern_id, fingerprint, service_name, alert_type,
                        occurrence_count, first_seen, last_seen,
                        avg_duration_minutes, common_root_cause,
                        precursor_signals, updated_at
                    ) VALUES (
                        '{pattern_id}', '{fingerprint}', '{service}', '{alert_type}',
                        {occ_count}, TIMESTAMP '{first_seen_str}', TIMESTAMP '{last_seen_str}',
                        {avg_duration}, '{root_cause_escaped}',
                        '{precursors_json}', TIMESTAMP '{now}'
                    )
                """

            if self.executor.execute_write(sql):
                updated += 1

        print(f"[PatternMatcher] Updated {updated} patterns")

    def predict_cascade(self, service: str) -> List[Dict]:
        """Use topology to find downstream services that may be affected."""
        deps = self.executor.execute(f"""
            SELECT target_service, dependency_type
            FROM topology_dependencies
            WHERE source_service = '{service}'
            LIMIT 20
        """)

        at_risk = []
        for dep in deps:
            target = dep.get("target_service", "")
            if not target:
                continue

            # Check if historical incidents on this service correlated with
            # downstream incidents within 15 min
            correlated = self.executor.execute(f"""
                SELECT COUNT(*) as cnt
                FROM incident_context ic1
                JOIN incident_context ic2
                  ON ic2.captured_at BETWEEN ic1.captured_at AND ic1.captured_at + INTERVAL '15' MINUTE
                WHERE ic1.service_name = '{service}'
                  AND ic2.service_name = '{target}'
                LIMIT 1
            """)

            count = correlated[0].get("cnt", 0) if correlated else 0
            if count > 0:
                at_risk.append({
                    "service": target,
                    "dependency_type": dep.get("dependency_type", ""),
                    "historical_cascades": count,
                })

        return at_risk

    def _compute_avg_duration(self, fingerprint: str) -> float:
        """Compute average alert duration for alerts matching this fingerprint."""
        rows = self.executor.execute(f"""
            SELECT AVG(
                CAST(
                    date_diff('second', a.created_at, a.resolved_at) AS double
                ) / 60.0
            ) as avg_mins
            FROM alerts a
            JOIN incident_context ic ON a.alert_id = ic.alert_id
            WHERE ic.fingerprint = '{fingerprint}'
              AND a.resolved_at IS NOT NULL
            LIMIT 1
        """)
        if rows and rows[0].get("avg_mins"):
            return round(rows[0]["avg_mins"], 2)
        return 0.0

    def _get_common_root_cause(self, service: str, alert_type: str) -> str:
        """Get the most common root cause summary from investigations."""
        rows = self.executor.execute(f"""
            SELECT root_cause_summary, COUNT(*) as cnt
            FROM alert_investigations
            WHERE service_name = '{service}'
              AND alert_type = '{alert_type}'
              AND root_cause_summary IS NOT NULL
            GROUP BY root_cause_summary
            ORDER BY cnt DESC
            LIMIT 1
        """)
        if rows:
            return rows[0].get("root_cause_summary", "") or ""
        return ""

    def _compute_precursors(self, service: str, alert_type: str) -> List[Dict]:
        """Find metrics that degraded before incidents of this type."""
        rows = self.executor.execute(f"""
            SELECT metric_type, AVG(z_score) as avg_zscore, COUNT(*) as cnt
            FROM anomaly_scores asc2
            WHERE service_name = '{service}'
              AND is_anomaly = true
              AND timestamp > current_timestamp - INTERVAL '24' HOUR
            GROUP BY metric_type
            ORDER BY avg_zscore DESC
            LIMIT 5
        """)
        result = []
        for r in rows:
            result.append({
                "metric": r.get("metric_type", ""),
                "avg_zscore": round(r.get("avg_zscore", 0) or 0, 2),
                "count": r.get("cnt", 0),
            })
        return result


# =============================================================================
# Alert Investigator (LLM-powered root cause analysis)
# =============================================================================

INVESTIGATION_SYSTEM_PROMPT = """You are an expert SRE assistant performing automated root cause analysis for alerts.
You have access to observability data via SQL queries (Trino/Presto dialect). Analyze the alert and determine the root cause.

Available tables and their EXACT columns (use ONLY these columns):

traces_otel_analytic (time column: start_time):
  start_time, trace_id, span_id, parent_span_id, service_name, span_name,
  span_kind, status_code, http_status, duration_ns, db_system

logs_otel_analytic (time column: timestamp):
  timestamp, service_name, severity_number, severity_text, body_text, trace_id, span_id

span_events_otel_analytic (time column: timestamp):
  timestamp, trace_id, span_id, service_name, span_name, event_name,
  exception_type, exception_message, exception_stacktrace

metrics_otel_analytic (time column: timestamp):
  timestamp, service_name, metric_name, metric_unit, value_double

CRITICAL SQL RULES:
- For traces: WHERE start_time > current_timestamp - INTERVAL '15' MINUTE
- For logs/events/metrics: WHERE timestamp > current_timestamp - INTERVAL '15' MINUTE
- There is NO 'attributes' column - do not use it
- NO semicolons at end of queries
- NO square brackets [] anywhere
- Interval format: INTERVAL '15' MINUTE (number in quotes)

STRICT ANTI-HALLUCINATION RULES:
- ONLY state facts that came from query results in THIS investigation.
- NEVER fabricate error messages, metric values, service names, or trace IDs.
- If a query returns 0 rows, say "no data found" — do NOT invent results.
- Quote exception messages and error text VERBATIM from query results.
- If you cannot determine the root cause from the data, say so explicitly.
- Every claim in EVIDENCE must reference actual query output.
- Do NOT describe what a query "would show" — only describe what it DID show.
- If the execute_sql tool returns an error, report the failure honestly.

Your analysis should be CONCISE (under 500 words). Output format:
ROOT CAUSE: <one sentence summary based on evidence>
EVIDENCE:
- <key finding 1 with actual values from queries>
- <key finding 2 with actual values from queries>
RECOMMENDED ACTIONS:
1. <action 1>
2. <action 2>
"""

class AlertInvestigator:
    """LLM-powered automatic investigation of alerts."""

    def __init__(self, executor: 'TrinoExecutor', config: Config):
        self.executor = executor
        self.config = config
        self.client = None
        self.enabled = False

        # Rate limiting: track investigation timestamps
        self.investigation_times: deque = deque(maxlen=100)
        # Per-service cooldown: service -> last investigation time
        self.service_last_investigated: Dict[str, datetime] = {}

        if ANTHROPIC_AVAILABLE and config.anthropic_api_key:
            self.client = anthropic.Anthropic(api_key=config.anthropic_api_key)
            self.enabled = True
            print(f"[Investigator] Enabled (model: {config.investigation_model}, max {config.max_investigations_per_hour}/hour)")
        else:
            print("[Investigator] Disabled (no ANTHROPIC_API_KEY)")

        self.tools = [{
            "name": "execute_sql",
            "description": "Execute a SQL query against the observability database",
            "input_schema": {
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "The SQL query to execute"
                    }
                },
                "required": ["sql"]
            }
        }]

    def should_investigate(self, alert: Dict) -> bool:
        """Check if we should investigate this alert (rate limits, cooldowns)."""
        if not self.enabled:
            return False

        service = alert.get("service_name", "")
        severity = alert.get("severity", "")

        # Check if critical-only mode
        if self.config.investigate_critical_only and severity != "critical":
            return False

        # Check hourly rate limit
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)

        # Remove old timestamps
        while self.investigation_times and self.investigation_times[0] < hour_ago:
            self.investigation_times.popleft()

        if len(self.investigation_times) >= self.config.max_investigations_per_hour:
            print(f"[Investigator] Rate limit reached ({self.config.max_investigations_per_hour}/hour)")
            return False

        # Check per-service cooldown
        if service in self.service_last_investigated:
            cooldown_until = self.service_last_investigated[service] + timedelta(
                minutes=self.config.investigation_service_cooldown_minutes
            )
            if now < cooldown_until:
                remaining = (cooldown_until - now).seconds // 60
                print(f"[Investigator] Service {service} in cooldown ({remaining}m remaining)")
                return False

        return True

    def investigate(self, alert: Dict) -> Optional[Dict]:
        """Investigate an alert and return findings."""
        if not self.should_investigate(alert):
            return None

        service = alert.get("service_name", "")
        alert_type = alert.get("alert_type", "")
        alert_id = alert.get("alert_id", "")
        description = alert.get("description", "")

        print(f"[Investigator] Starting investigation for {service} - {alert_type}")

        # Record investigation attempt
        now = datetime.now(timezone.utc)
        self.investigation_times.append(now)
        self.service_last_investigated[service] = now

        # Build investigation prompt
        user_prompt = f"""Investigate this alert:

Service: {service}
Alert Type: {alert_type}
Description: {description}

Find the root cause by querying the observability data. Focus on the last 15 minutes.
Start by checking for errors, exceptions, and anomalies in this service and its dependencies."""

        try:
            # Run investigation with tool use
            messages = [{"role": "user", "content": user_prompt}]
            queries_executed = 0
            total_tokens = 0

            for _ in range(5):  # Max 5 iterations
                response = self.client.messages.create(
                    model=self.config.investigation_model,
                    max_tokens=self.config.investigation_max_tokens,
                    system=INVESTIGATION_SYSTEM_PROMPT,
                    tools=self.tools,
                    messages=messages
                )

                total_tokens += response.usage.input_tokens + response.usage.output_tokens

                # Check for tool use
                tool_calls = [b for b in response.content if b.type == "tool_use"]

                if not tool_calls:
                    # No more tool calls, extract final response
                    break

                # Process tool calls
                messages.append({"role": "assistant", "content": response.content})

                tool_results = []
                for tool_call in tool_calls:
                    if tool_call.name == "execute_sql":
                        sql = tool_call.input.get("sql", "")
                        # Strip semicolons - Trino doesn't accept them
                        sql = sql.strip().rstrip(';')
                        queries_executed += 1

                        # Execute query with error reporting
                        result = self.executor.execute(sql, return_error=True)
                        result_str = json.dumps(result[:20] if len(result) > 20 else result, default=str)

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_call.id,
                            "content": result_str
                        })
                    else:
                        # Unknown tool - still need to respond
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_call.id,
                            "content": "Unknown tool",
                            "is_error": True
                        })

                messages.append({"role": "user", "content": tool_results})

            # Handle the conversation state before requesting final summary
            if response.stop_reason == "end_turn":
                # Last response was natural completion, add it and request summary
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": """Based on your investigation, provide your final analysis in this EXACT format:

ROOT CAUSE: <one sentence describing the root cause>

EVIDENCE:
- <finding 1>
- <finding 2>

RECOMMENDED ACTIONS:
1. <action 1>
2. <action 2>"""
                })
            else:
                # Last response had tool calls - need to get a natural completion first
                # The tool_results are already in messages, so just request completion
                summary_response = self.client.messages.create(
                    model=self.config.investigation_model,
                    max_tokens=self.config.investigation_max_tokens,
                    system=INVESTIGATION_SYSTEM_PROMPT,
                    tools=self.tools,
                    messages=messages
                )
                total_tokens += summary_response.usage.input_tokens + summary_response.usage.output_tokens
                messages.append({"role": "assistant", "content": summary_response.content})
                messages.append({
                    "role": "user",
                    "content": """Based on your investigation, provide your final analysis in this EXACT format:

ROOT CAUSE: <one sentence describing the root cause>

EVIDENCE:
- <finding 1>
- <finding 2>

RECOMMENDED ACTIONS:
1. <action 1>
2. <action 2>"""
                })

            # Get structured response (no tools)
            final_response = self.client.messages.create(
                model=self.config.investigation_model,
                max_tokens=self.config.investigation_max_tokens,
                system=INVESTIGATION_SYSTEM_PROMPT,
                messages=messages
            )
            total_tokens += final_response.usage.input_tokens + final_response.usage.output_tokens

            # Extract final analysis
            analysis = self._extract_text(final_response)

            # Parse into structured format
            root_cause, actions, evidence = self._parse_analysis(analysis)

            # Store investigation
            investigation_id = str(uuid.uuid4())[:8]
            self._store_investigation(
                investigation_id=investigation_id,
                alert_id=alert_id,
                service=service,
                alert_type=alert_type,
                root_cause=root_cause,
                actions=actions,
                evidence=evidence,
                queries_executed=queries_executed,
                tokens_used=total_tokens
            )

            print(f"[Investigator] Completed: {root_cause[:80]}...")

            return {
                "investigation_id": investigation_id,
                "root_cause_summary": root_cause,
                "recommended_actions": actions,
                "supporting_evidence": evidence,
                "queries_executed": queries_executed,
                "tokens_used": total_tokens
            }

        except Exception as e:
            print(f"[Investigator] Error: {e}")
            return None

    def _extract_text(self, response) -> str:
        """Extract text content from response."""
        text_parts = []
        for block in response.content:
            if hasattr(block, 'text'):
                text_parts.append(block.text)
        return "\n".join(text_parts)

    def _parse_analysis(self, analysis: str) -> Tuple[str, str, str]:
        """Parse the analysis into structured components."""
        root_cause = ""
        actions = ""
        evidence = ""

        lines = analysis.split("\n")
        current_section = None

        for line in lines:
            line_upper = line.upper().strip()
            if line_upper.startswith("ROOT CAUSE:"):
                current_section = "root_cause"
                root_cause = line.split(":", 1)[1].strip() if ":" in line else ""
            elif line_upper.startswith("EVIDENCE:") or line_upper.startswith("SUPPORTING EVIDENCE:"):
                current_section = "evidence"
            elif line_upper.startswith("RECOMMENDED ACTIONS:") or line_upper.startswith("ACTIONS:"):
                current_section = "actions"
            elif current_section == "root_cause" and line.strip() and not root_cause:
                root_cause = line.strip()
            elif current_section == "evidence":
                evidence += line + "\n"
            elif current_section == "actions":
                actions += line + "\n"

        # Fallback: use first sentence as root cause if not parsed
        if not root_cause and analysis:
            root_cause = analysis.split(".")[0][:200]

        return root_cause.strip(), actions.strip(), evidence.strip()

    def _store_investigation(
        self, investigation_id: str, alert_id: str, service: str, alert_type: str,
        root_cause: str, actions: str, evidence: str, queries_executed: int, tokens_used: int
    ):
        """Store investigation results in database."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # Escape single quotes for SQL
        root_cause_escaped = root_cause.replace("'", "''")[:2000]
        actions_escaped = actions.replace("'", "''")[:2000]
        evidence_escaped = evidence.replace("'", "''")[:4000]

        sql = f"""
            INSERT INTO alert_investigations (
                investigation_id, alert_id, investigated_at, service_name, alert_type,
                model_used, root_cause_summary, recommended_actions, supporting_evidence,
                queries_executed, tokens_used
            ) VALUES (
                '{investigation_id}', '{alert_id}', TIMESTAMP '{now}', '{service}', '{alert_type}',
                '{self.config.investigation_model}', '{root_cause_escaped}', '{actions_escaped}', '{evidence_escaped}',
                {queries_executed}, {tokens_used}
            )
        """
        self.executor.execute_write(sql)


# =============================================================================
# Main Service
# =============================================================================

class PredictiveAlertsService:
    """Main service that orchestrates all components."""

    JOB_NAME = 'predictive_alerts'

    def __init__(self, config: Config):
        self.config = config
        self.executor = TrinoExecutor(config)
        self.baseline_computer = BaselineComputer(self.executor, config)
        self.anomaly_detector = AnomalyDetector(self.executor, config, self.baseline_computer)
        self.context_capture = IncidentContextCapture(self.executor)
        self.alert_manager = AlertManager(self.executor, config, context_capture=self.context_capture)
        self.investigator = AlertInvestigator(self.executor, config)
        self.trend_predictor = ResourceTrendPredictor(self.executor)
        self.pattern_matcher = PatternMatcher(self.executor)

        self.running = True
        self.last_baseline_update = 0
        self.last_trend_prediction = 0
        self.last_pattern_update = 0

        # Setup graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print("\n[Service] Shutting down...")
        self.running = False

    def _ensure_tables(self):
        """Ensure required tables exist (creates them if not)."""
        # Check if tables exist by querying
        tables = ["service_baselines", "anomaly_scores", "alerts",
                  "incident_context", "resource_predictions", "incident_patterns", "simulation_runs"]

        for table in tables:
            sql = f"SELECT 1 FROM {table} LIMIT 1"
            try:
                self.executor.execute(sql)
            except Exception as e:
                if "does not exist" in str(e).lower():
                    print(f"[Service] Table {table} does not exist. Please create it using ddl.sql")
                    return False

        return True

    def run(self):
        """Main service loop."""
        print("=" * 60)
        print("Predictive Maintenance Alerts Service")
        print("=" * 60)
        print(f"\nConfiguration:")
        print(f"  Detection interval: {self.config.detection_interval}s")
        print(f"  Baseline interval: {self.config.baseline_interval}s")
        print(f"  Baseline window: {self.config.baseline_window_hours}h")
        print(f"  Z-score threshold: {self.config.zscore_threshold}")
        print(f"  Error rate warning: {self.config.error_rate_warning:.0%}")
        print(f"  Error rate critical: {self.config.error_rate_critical:.0%}")
        print(f"  sklearn available: {SKLEARN_AVAILABLE}")
        print(f"\nRoot cause detection:")
        print(f"  Enabled: {self.config.root_cause_enabled}")
        if self.config.root_cause_enabled:
            if self.config.root_cause_types:
                print(f"  Types: {self.config.root_cause_types}")
            else:
                print(f"  Types: all (auto-discovered)")
            print(f"  Adaptive thresholds: {self.config.adaptive_thresholds_enabled}")
            if self.anomaly_detector.threshold_manager.multipliers:
                print(f"  Threshold multipliers: {self.anomaly_detector.threshold_manager.multipliers}")
        print(f"\nInvestigation settings:")
        print(f"  LLM investigations: {'enabled' if self.investigator.enabled else 'disabled'}")
        if self.investigator.enabled:
            print(f"  Model: {self.config.investigation_model}")
            print(f"  Max per hour: {self.config.max_investigations_per_hour}")
            print(f"  Service cooldown: {self.config.investigation_service_cooldown_minutes}m")
            print(f"  Critical only: {self.config.investigate_critical_only}")
        print()

        # Initial baseline computation
        print("[Service] Computing initial baselines...")
        self.baseline_computer.compute_all_baselines()
        self.last_baseline_update = time.time()

        # Load persisted threshold overrides from DB
        print("[Service] Loading threshold overrides from DB...")
        self.anomaly_detector.threshold_manager.load_overrides_from_db(self.executor)

        # Learn adaptive thresholds from alert history
        if self.config.adaptive_thresholds_enabled:
            print("[Service] Learning adaptive thresholds from alert history...")
            self.anomaly_detector.learn_thresholds()

        print(f"\n[Service] Starting detection loop (interval: {self.config.detection_interval}s)...")

        while self.running:
            try:
                loop_start = time.time()

                # Update baselines periodically
                if time.time() - self.last_baseline_update > self.config.baseline_interval:
                    print("[Service] Updating baselines...")
                    self.baseline_computer.compute_all_baselines()
                    self.last_baseline_update = time.time()

                    # Re-learn adaptive thresholds
                    if self.config.adaptive_thresholds_enabled:
                        self.anomaly_detector.learn_thresholds()

                # Run anomaly detection
                anomalies = self.anomaly_detector.detect_all()

                # Process anomalies and manage alerts
                created, updated, new_alerts = self.alert_manager.process_anomalies(
                    anomalies if anomalies else []
                )

                # Investigate new alerts (with rate limiting)
                for alert in new_alerts:
                    self.investigator.investigate(alert)

                # Resource trend predictions (every 5 minutes)
                if time.time() - self.last_trend_prediction > 300:
                    try:
                        predictions = self.trend_predictor.predict_all()
                        if predictions:
                            print(f"[Service] Generated {len(predictions)} resource prediction(s)")
                    except Exception as e:
                        print(f"[Service] Trend prediction error: {e}")
                    self.last_trend_prediction = time.time()

                # Pattern matching (every 30 minutes)
                if time.time() - self.last_pattern_update > 1800:
                    try:
                        self.pattern_matcher.update_patterns()
                    except Exception as e:
                        print(f"[Service] Pattern update error: {e}")
                    self.last_pattern_update = time.time()

                # Sleep for remaining interval time
                elapsed = time.time() - loop_start

                # Build details for job status
                details = {"interval_seconds": self.config.detection_interval}
                if self.last_baseline_update > 0:
                    details["last_baseline_minutes_ago"] = round((time.time() - self.last_baseline_update) / 60, 1)
                if self.last_trend_prediction > 0:
                    details["last_trend_minutes_ago"] = round((time.time() - self.last_trend_prediction) / 60, 1)
                details["active_alerts"] = len(self.alert_manager.active_alerts)
                self._write_job_status(elapsed, details=details)

                sleep_time = max(0, self.config.detection_interval - elapsed)

                if sleep_time > 0:
                    time.sleep(sleep_time)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[Service] Error in detection loop: {e}")
                self._write_job_status(0, status='error', details={"error": str(e)[:200]})
                time.sleep(5)  # Brief pause before retrying

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

    service = PredictiveAlertsService(config)
    service.run()

    return 0


if __name__ == "__main__":
    sys.exit(main())
