#!/usr/bin/env python3
"""
Failure Simulator — Orchestrates realistic failure scenarios for predictive maintenance demos.

Provides 5 built-in multi-step scenarios that can be triggered from the web UI
to demonstrate predictive alerting capabilities.

Scenarios:
  - postgres_degradation: Gradual latency increase via tc netem
  - cascading_payment: Escalating payment failures via feature flags
  - memory_leak: Memory growth via recommendation cache failure flag
  - disk_fill: Create temp files in postgres container
  - kafka_saturation: Enable Kafka queue problems flag
"""

import os
import json
import time
import uuid
import subprocess
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any


OTEL_DEMO_HOST = os.getenv("OTEL_DEMO_HOST", "localhost")
OTEL_DEMO_PORT = os.getenv("OTEL_DEMO_PORT", "8080")
FLAGD_UI_URL = f"http://{OTEL_DEMO_HOST}:{OTEL_DEMO_PORT}/feature/api"

POSTGRES_HOST = os.getenv("POSTGRES_HOST", "postgresql")
POSTGRES_PORT = int(os.getenv("POSTGRES_PORT", "5432"))
POSTGRES_DB = os.getenv("POSTGRES_DB", "otel")
POSTGRES_USER = os.getenv("POSTGRES_USER", "root")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "otel")


# =============================================================================
# Scenario Definitions
# =============================================================================

SCENARIOS = {
    "postgres_degradation": {
        "name": "PostgreSQL Degradation",
        "description": "Progressively degrades PostgreSQL performance by adjusting configuration settings (work_mem, random_page_cost, effective_cache_size) over 12 minutes.",
        "predicted_alerts": ["db_slow_queries", "latency_degradation"],
        "duration_minutes": 12,
        "steps": [
            {"delay_seconds": 0, "action": "pg_config_degrade", "params": {"settings": {"work_mem": "'256kB'", "random_page_cost": "20"}}, "label": "Reduce work_mem to 256kB, raise random_page_cost"},
            {"delay_seconds": 180, "action": "pg_config_degrade", "params": {"settings": {"work_mem": "'64kB'", "effective_cache_size": "'32MB'"}}, "label": "Reduce work_mem to 64kB, cache to 32MB"},
            {"delay_seconds": 360, "action": "pg_config_degrade", "params": {"settings": {"work_mem": "'64kB'", "random_page_cost": "100", "effective_cache_size": "'1MB'"}}, "label": "Extreme: random_page_cost=100, cache=1MB"},
            {"delay_seconds": 540, "action": "pg_config_degrade", "params": {"settings": {"work_mem": "'64kB'", "random_page_cost": "100", "effective_cache_size": "'1MB'", "statement_timeout": "'200ms'"}}, "label": "Add 200ms statement timeout"},
        ],
        "cleanup": {"action": "pg_config_reset"},
    },
    "cascading_payment": {
        "name": "Cascading Payment Failure",
        "description": "Escalates payment service failure rate from 10% to 75% over 12 minutes, causing cascading errors to checkout and frontend.",
        "predicted_alerts": ["error_spike", "dependency_failure"],
        "duration_minutes": 12,
        "steps": [
            {"delay_seconds": 0, "action": "feature_flag", "params": {"flag": "paymentFailure", "variant": "10%"}, "label": "10% payment failures"},
            {"delay_seconds": 180, "action": "feature_flag", "params": {"flag": "paymentFailure", "variant": "25%"}, "label": "25% payment failures"},
            {"delay_seconds": 360, "action": "feature_flag", "params": {"flag": "paymentFailure", "variant": "50%"}, "label": "50% payment failures"},
            {"delay_seconds": 540, "action": "feature_flag", "params": {"flag": "paymentFailure", "variant": "75%"}, "label": "75% payment failures"},
        ],
        "cleanup": {"action": "feature_flag", "params": {"flag": "paymentFailure", "variant": "off"}},
    },
    "memory_leak": {
        "name": "Memory Leak Simulation",
        "description": "Simulates a memory leak in the recommendation service by enabling cache failure.",
        "predicted_alerts": ["anomaly", "trend"],
        "duration_minutes": 15,
        "steps": [
            {"delay_seconds": 0, "action": "feature_flag", "params": {"flag": "recommendationCacheFailure", "variant": "on"}, "label": "Enable cache failure"},
        ],
        "cleanup": {"action": "feature_flag", "params": {"flag": "recommendationCacheFailure", "variant": "off"}},
    },
    "disk_fill": {
        "name": "Disk Fill Simulation",
        "description": "Creates temporary files in the postgres data directory every 2 minutes to simulate disk exhaustion. PGDATA is a 250MB tmpfs.",
        "predicted_alerts": ["trend"],
        "duration_minutes": 12,
        "steps": [
            {"delay_seconds": 0, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 1}, "label": "Write 30MB (1/6)"},
            {"delay_seconds": 120, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 2}, "label": "Write 30MB (2/6)"},
            {"delay_seconds": 240, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 3}, "label": "Write 30MB (3/6)"},
            {"delay_seconds": 360, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 4}, "label": "Write 30MB (4/6)"},
            {"delay_seconds": 480, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 5}, "label": "Write 30MB (5/6)"},
            {"delay_seconds": 600, "action": "disk_fill_step", "params": {"size_mb": 30, "file_index": 6}, "label": "Write 30MB (6/6)"},
        ],
        "cleanup": {"action": "disk_fill_cleanup"},
    },
    "kafka_saturation": {
        "name": "Kafka Saturation",
        "description": "Enables Kafka queue problems to simulate consumer lag growth and message backlog.",
        "predicted_alerts": ["anomaly", "trend"],
        "duration_minutes": 10,
        "steps": [
            {"delay_seconds": 0, "action": "feature_flag", "params": {"flag": "kafkaQueueProblems", "variant": "on"}, "label": "Enable queue problems"},
        ],
        "cleanup": {"action": "feature_flag", "params": {"flag": "kafkaQueueProblems", "variant": "off"}},
    },
}


# =============================================================================
# Action Executors
# =============================================================================

def _run_docker_exec(container: str, command: List[str], timeout: int = 30) -> bool:
    """Run a command inside a docker container."""
    try:
        result = subprocess.run(
            ["docker", "exec", container] + command,
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            print(f"[Simulator] Docker exec failed: {result.stderr}")
            return False
        return True
    except subprocess.TimeoutExpired:
        print(f"[Simulator] Docker exec timed out for {container}")
        return False
    except FileNotFoundError:
        print("[Simulator] docker command not found")
        return False


def _run_pg_sql(statements: List[str]) -> bool:
    """Execute SQL statements directly against PostgreSQL using psycopg2."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=POSTGRES_HOST, port=POSTGRES_PORT,
            dbname=POSTGRES_DB, user=POSTGRES_USER, password=POSTGRES_PASSWORD
        )
        conn.autocommit = True
        cur = conn.cursor()
        for stmt in statements:
            print(f"[Simulator] PG exec: {stmt}")
            cur.execute(stmt)
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"[Simulator] PostgreSQL error: {e}")
        return False


def _call_feature_flag(flag_name: str, variant: str) -> bool:
    """Set a feature flag's defaultVariant via the flagd-ui API.

    Reads the full flag config, changes the target flag's defaultVariant,
    and writes the full config back.
    """
    import urllib.request
    import urllib.error

    try:
        # Read current flags
        with urllib.request.urlopen(f"{FLAGD_UI_URL}/read", timeout=10) as resp:
            data = json.loads(resp.read().decode())

        flags = data.get("flags", data.get("data", {}).get("flags", {}))
        if flag_name not in flags:
            print(f"[Simulator] Flag '{flag_name}' not found. Available: {list(flags.keys())}")
            return False

        if variant not in flags[flag_name].get("variants", {}):
            print(f"[Simulator] Variant '{variant}' not found for flag '{flag_name}'. Available: {list(flags[flag_name]['variants'].keys())}")
            return False

        # Update the default variant
        flags[flag_name]["defaultVariant"] = variant
        print(f"[Simulator] Setting {flag_name} defaultVariant = {variant}")

        # Write back
        payload = json.dumps({"data": {"flags": flags}}).encode()
        req = urllib.request.Request(f"{FLAGD_UI_URL}/write", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 204)

    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        print(f"[Simulator] Feature flag API error: {e}")
        return False


def execute_action(action: str, params: Dict) -> bool:
    """Execute a single simulation action."""
    if action == "feature_flag":
        return _call_feature_flag(params["flag"], params["variant"])

    elif action == "pg_config_degrade":
        settings = params.get("settings", {})
        stmts = [f"ALTER SYSTEM SET {k} = {v}" for k, v in settings.items()]
        stmts.append("SELECT pg_reload_conf()")
        return _run_pg_sql(stmts)

    elif action == "pg_config_reset":
        return _run_pg_sql(["ALTER SYSTEM RESET ALL", "SELECT pg_reload_conf()"])

    elif action == "disk_fill_step":
        size_mb = params["size_mb"]
        file_index = params["file_index"]
        return _run_docker_exec(
            "postgresql",
            ["dd", "if=/dev/zero", f"of=/var/lib/postgresql/data/sim_fill_{file_index}.dat", "bs=1M", f"count={size_mb}"],
            timeout=300
        )

    elif action == "disk_fill_cleanup":
        return _run_docker_exec("postgresql", ["sh", "-c", "rm -f /var/lib/postgresql/data/sim_fill_*.dat"], timeout=10)

    else:
        print(f"[Simulator] Unknown action: {action}")
        return False


# =============================================================================
# SimulationManager
# =============================================================================

class SimulationManager:
    """Manages running simulation scenarios with background threads."""

    def __init__(self, executor=None):
        self.executor = executor
        self._active_run: Optional[Dict] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def list_scenarios(self) -> List[Dict]:
        """Return available scenarios with descriptions."""
        return [
            {
                "id": sid,
                "name": s["name"],
                "description": s["description"],
                "duration_minutes": s["duration_minutes"],
                "steps": len(s["steps"]),
                "predicted_alerts": s["predicted_alerts"],
                "has_cleanup": "cleanup" in s,
            }
            for sid, s in SCENARIOS.items()
        ]

    def run_cleanup(self, scenario_id: str) -> bool:
        """Run the cleanup action for a scenario. Safe to call at any time."""
        scenario = SCENARIOS.get(scenario_id)
        if not scenario or "cleanup" not in scenario:
            return False
        cleanup = scenario["cleanup"]
        return execute_action(cleanup["action"], cleanup.get("params", {}))

    def start_scenario(self, scenario_name: str, config: Optional[Dict] = None) -> Optional[str]:
        """Start a scenario. Returns run_id or None if already running."""
        with self._lock:
            if self._active_run and self._active_run["status"] == "running":
                return None

            if scenario_name not in SCENARIOS:
                return None

            run_id = str(uuid.uuid4())[:8]
            now = datetime.now(timezone.utc)

            self._active_run = {
                "run_id": run_id,
                "scenario_name": scenario_name,
                "started_at": now.isoformat(),
                "ended_at": None,
                "status": "running",
                "config": config or {},
                "steps_completed": [],
                "current_step_index": 0,
                "total_steps": len(SCENARIOS[scenario_name]["steps"]),
            }

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_scenario,
                args=(run_id, scenario_name),
                daemon=True,
                name=f"sim-{run_id}"
            )
            self._thread.start()

            # Store in DB if executor available
            self._store_run(self._active_run)

            return run_id

    def stop_scenario(self, run_id: Optional[str] = None) -> bool:
        """Stop the running scenario and execute cleanup."""
        with self._lock:
            if not self._active_run or self._active_run["status"] != "running":
                return False
            if run_id and self._active_run["run_id"] != run_id:
                return False

        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=15)

        return True

    def get_status(self) -> Optional[Dict]:
        """Get current simulation status."""
        with self._lock:
            if not self._active_run:
                return None
            run = dict(self._active_run)

        if run["status"] == "running" and run["started_at"]:
            started = datetime.fromisoformat(run["started_at"])
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
            scenario = SCENARIOS.get(run["scenario_name"], {})
            total_duration = scenario.get("duration_minutes", 10) * 60
            run["elapsed_seconds"] = int(elapsed)
            run["progress_pct"] = min(100, int(elapsed / total_duration * 100)) if total_duration > 0 else 0

        return run

    def get_results(self, run_id: str) -> Optional[Dict]:
        """Get results for a completed simulation run."""
        if not self.executor:
            with self._lock:
                if self._active_run and self._active_run["run_id"] == run_id:
                    return dict(self._active_run)
            return None

        rows = self.executor.execute(
            f"SELECT * FROM simulation_runs WHERE run_id = '{run_id}' LIMIT 1"
        )
        if not rows:
            return None

        row = rows[0]
        result = dict(row)

        # Parse JSON fields
        for field in ("scenario_config", "steps_completed", "predicted_alerts", "actual_alerts"):
            if result.get(field):
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    pass

        # Query alerts that fired during the simulation window
        if result.get("started_at") and result.get("ended_at"):
            started = result["started_at"]
            ended = result["ended_at"]
            if isinstance(started, datetime):
                started = started.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            if isinstance(ended, datetime):
                ended = ended.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            alerts = self.executor.execute(f"""
                SELECT alert_id, service_name, alert_type, severity, title, created_at
                FROM alerts
                WHERE created_at BETWEEN TIMESTAMP '{started}' AND TIMESTAMP '{ended}'
                ORDER BY created_at
                LIMIT 50
            """)
            result["fired_alerts"] = alerts

            predictions = self.executor.execute(f"""
                SELECT prediction_id, host_name, resource_type, service_name,
                       hours_until_exhaustion, confidence, created_at
                FROM resource_predictions
                WHERE created_at BETWEEN TIMESTAMP '{started}' AND TIMESTAMP '{ended}'
                ORDER BY created_at
                LIMIT 50
            """)
            result["fired_predictions"] = predictions

        return result

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _run_scenario(self, run_id: str, scenario_name: str):
        """Background thread that executes scenario steps."""
        scenario = SCENARIOS[scenario_name]
        steps = scenario["steps"]
        start_time = time.time()

        print(f"[Simulator] Starting scenario: {scenario['name']} (run_id={run_id})")

        try:
            for i, step in enumerate(steps):
                # Wait until the step's scheduled time
                target_time = start_time + step["delay_seconds"]
                while time.time() < target_time:
                    if self._stop_event.is_set():
                        print(f"[Simulator] Scenario stopped at step {i}")
                        self._finish_run("aborted", scenario)
                        return
                    time.sleep(1)

                if self._stop_event.is_set():
                    self._finish_run("aborted", scenario)
                    return

                # Execute the step
                print(f"[Simulator] Step {i+1}/{len(steps)}: {step['label']}")
                success = execute_action(step["action"], step.get("params", {}))

                with self._lock:
                    if self._active_run:
                        self._active_run["current_step_index"] = i + 1
                        self._active_run["steps_completed"].append({
                            "index": i,
                            "label": step["label"],
                            "success": success,
                            "executed_at": datetime.now(timezone.utc).isoformat(),
                        })

            # All steps completed — wait for remaining scenario duration
            total_duration = scenario["duration_minutes"] * 60
            remaining = total_duration - (time.time() - start_time)
            if remaining > 0:
                print(f"[Simulator] All steps done, waiting {int(remaining)}s for scenario to complete")
                end_time = time.time() + remaining
                while time.time() < end_time:
                    if self._stop_event.is_set():
                        break
                    time.sleep(1)

            self._finish_run("completed", scenario)

        except Exception as e:
            print(f"[Simulator] Error in scenario: {e}")
            self._finish_run("aborted", scenario)

    def _finish_run(self, status: str, scenario: Dict):
        """Cleanup and finalize the run."""
        # Execute cleanup action
        cleanup = scenario.get("cleanup")
        if cleanup:
            print(f"[Simulator] Running cleanup: {cleanup['action']}")
            execute_action(cleanup["action"], cleanup.get("params", {}))

        with self._lock:
            if self._active_run:
                self._active_run["status"] = status
                self._active_run["ended_at"] = datetime.now(timezone.utc).isoformat()
                self._update_run_in_db(self._active_run)

        print(f"[Simulator] Scenario {status}")

    def _store_run(self, run: Dict):
        """Store a new simulation run in the database."""
        if not self.executor:
            return
        now = run["started_at"]
        if isinstance(now, str):
            now_str = now.replace("T", " ").replace("+00:00", "")[:23]
        else:
            now_str = now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        config_json = json.dumps(run.get("config", {})).replace("'", "''")
        predicted = json.dumps(SCENARIOS.get(run["scenario_name"], {}).get("predicted_alerts", [])).replace("'", "''")

        sql = f"""
            INSERT INTO simulation_runs (
                run_id, started_at, scenario_name, scenario_config,
                status, steps_completed, predicted_alerts, actual_alerts
            ) VALUES (
                '{run["run_id"]}', TIMESTAMP '{now_str}', '{run["scenario_name"]}',
                '{config_json}', 'running', '[]', '{predicted}', '[]'
            )
        """
        self.executor.execute_write(sql)

    def _update_run_in_db(self, run: Dict):
        """Update a simulation run in the database."""
        if not self.executor:
            return

        ended = run.get("ended_at", "")
        if isinstance(ended, str) and ended:
            ended_str = ended.replace("T", " ").replace("+00:00", "")[:23]
        elif isinstance(ended, datetime):
            ended_str = ended.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        else:
            ended_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        steps_json = json.dumps(run.get("steps_completed", [])).replace("'", "''")

        # Collect actual alerts during the window
        actual_alerts_json = "[]"
        if run.get("started_at"):
            started = run["started_at"]
            if isinstance(started, str):
                started_str = started.replace("T", " ").replace("+00:00", "")[:23]
            else:
                started_str = started.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

            alerts = self.executor.execute(f"""
                SELECT alert_id, alert_type, service_name, severity
                FROM alerts
                WHERE created_at >= TIMESTAMP '{started_str}'
                ORDER BY created_at
                LIMIT 50
            """)
            if alerts:
                actual_alerts_json = json.dumps(alerts).replace("'", "''")

        sql = f"""
            UPDATE simulation_runs
            SET ended_at = TIMESTAMP '{ended_str}',
                status = '{run["status"]}',
                steps_completed = '{steps_json}',
                actual_alerts = '{actual_alerts_json}'
            WHERE run_id = '{run["run_id"]}'
        """
        self.executor.execute_write(sql)
