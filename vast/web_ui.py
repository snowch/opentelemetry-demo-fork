#!/usr/bin/env python3
"""
Web UI for Observability Diagnostic Chat

A web-based interface for support engineers to diagnose issues
and monitor system status.

Usage:
    export ANTHROPIC_API_KEY=your_api_key
    export TRINO_HOST=trino.example.com
    python web_ui.py

Then open http://localhost:5000 in your browser.
"""

import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message=".*model.*is deprecated.*")

import json
import os
import re
import time
import threading
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, render_template, request, jsonify, Response
import anthropic

from otel_init import init_telemetry, traced_cursor

try:
    from opentelemetry.instrumentation.flask import FlaskInstrumentor
    _FLASK_INSTRUMENTOR_AVAILABLE = True
except ImportError:
    _FLASK_INSTRUMENTOR_AVAILABLE = False

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

# Investigation config (mirrors predictive_alerts.py settings)
INVESTIGATE_CRITICAL_ONLY = os.getenv("INVESTIGATE_CRITICAL_ONLY", "false").lower() == "true"

TRINO_HOST = os.getenv("TRINO_HOST")
TRINO_PORT = int(os.getenv("TRINO_PORT", "443"))
TRINO_USER = os.getenv("TRINO_USER", "admin")
TRINO_PASSWORD = os.getenv("TRINO_PASSWORD")
TRINO_CATALOG = os.getenv("TRINO_CATALOG", "vast")
TRINO_SCHEMA = os.getenv("TRINO_SCHEMA", "otel")
TRINO_HTTP_SCHEME = os.getenv("TRINO_HTTP_SCHEME", "https")

MAX_QUERY_ROWS = 100

app = Flask(__name__)

# Initialize OpenTelemetry tracing
init_telemetry('observability-agent')
if _FLASK_INSTRUMENTOR_AVAILABLE:
    FlaskInstrumentor().instrument_app(app)

# =============================================================================
# Response Cache
# =============================================================================
#
# Simple TTL cache for read-heavy API endpoints that hit Trino.  Each Trino
# round-trip takes 300-1000ms over the network, and most data is written by
# background jobs running on 60s+ cycles.  Serving slightly-stale responses
# from memory eliminates redundant queries and dramatically improves UI
# responsiveness — especially when the browser fires 7+ concurrent requests
# on page load or when opening the alert modal.
#
# Cache keys are the full request URL (including query string) so that
# different time windows (e.g. ?time=5m vs ?time=1h) are cached separately.
#
# Write endpoints (POST) bypass the cache entirely.  The cache can also be
# explicitly invalidated after mutations (e.g. after an investigation
# completes) by calling _invalidate_cache() with a prefix.

class TTLCache:
    """Thread-safe in-memory cache with per-key TTL."""

    def __init__(self):
        self._store: Dict[str, tuple] = {}  # key -> (value, expiry_timestamp)
        self._lock = threading.Lock()

    def get(self, key: str):
        """Return cached value if present and not expired, else None."""
        with self._lock:
            entry = self._store.get(key)
            if entry and entry[1] > time.monotonic():
                return entry[0]
            # Expired — remove it
            self._store.pop(key, None)
            return None

    def set(self, key: str, value, ttl_seconds: float):
        """Store a value with the given TTL (in seconds)."""
        with self._lock:
            self._store[key] = (value, time.monotonic() + ttl_seconds)

    def invalidate(self, prefix: str = ""):
        """Remove all entries whose key starts with *prefix*.
        Call with no arguments to flush the entire cache."""
        with self._lock:
            if not prefix:
                self._store.clear()
            else:
                keys = [k for k in self._store if k.startswith(prefix)]
                for k in keys:
                    del self._store[k]


_cache = TTLCache()

# TTL values (seconds) — tuned to match background-job intervals so we never
# serve data older than one job cycle.
CACHE_TTL_STATUS = 30        # /api/status — topology/aggregator run every 60s
CACHE_TTL_ALERTS = 15        # /api/alerts — alert changes need quicker visibility
CACHE_TTL_ALERTS_ACTIVITY = 15
CACHE_TTL_PREDICTIONS = 30   # /api/predictions — predictive job runs every 60s
CACHE_TTL_JOBS = 30          # /api/jobs/status
CACHE_TTL_SIMULATION = 30    # /api/simulation/*
CACHE_TTL_INCIDENTS = 60     # /api/incidents/context/<id> — context rarely changes


def _cached_response(cache_key: str, ttl: float, fn):
    """Return a cached JSON response, or call *fn* to produce one and cache it.

    *fn* must return a Flask response (typically from jsonify()).
    """
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached
    result = fn()
    _cache.set(cache_key, result, ttl)
    return result


def _invalidate_cache(prefix: str = ""):
    """Invalidate cached responses.  Called after mutations so the next read
    picks up fresh data.  Pass a URL prefix (e.g. '/api/alerts') to
    selectively flush, or omit for a full flush."""
    _cache.invalidate(prefix)


# =============================================================================
# Entity Type Registry
# =============================================================================

ENTITY_TYPES = {
    'service': {
        'display_name': 'Services',
        'name_field': 'service_name',
        'traces_table': 'traces_otel_analytic',
        'traces_time_field': 'start_time',
        'traces_filter': "service_name = '{name}'",
        'logs_filter': "service_name = '{name}'",
        'logs_join': None,
        'metrics_filter': "service_name = '{name}'",
        'has_latency_charts': True,
        'has_error_charts': True,
        'extra_charts': ['top_operations'],
    },
    'database': {
        'display_name': 'Databases',
        'name_field': 'db_system',
        'traces_table': 'traces_otel_analytic',
        'traces_time_field': 'start_time',
        'traces_filter': "db_system = '{name}'",
        'logs_filter': None,
        'logs_join': "l.service_name IN (SELECT DISTINCT service_name FROM traces_otel_analytic WHERE db_system = '{name}' AND start_time > NOW() - INTERVAL {interval})",
        'metrics_filter': "metric_name LIKE '{name}.%'",
        'has_latency_charts': True,
        'has_error_charts': True,
        'extra_charts': ['slow_queries', 'deadlocks', 'db_size'],
    },
    'host': {
        'display_name': 'Hosts',
        'name_field': 'host_name',
        'traces_table': 'traces_otel_analytic',
        'traces_time_field': 'start_time',
        'traces_filter': "attributes_flat LIKE '%host.name={name}%'",
        'logs_filter': None,
        'logs_join': "l.service_name IN (SELECT DISTINCT service_name FROM traces_otel_analytic WHERE attributes_flat LIKE '%host.name={name}%' AND start_time > NOW() - INTERVAL {interval} AND service_name IS NOT NULL AND service_name != '')",
        'metrics_filter': "attributes_flat LIKE '%host.name={name}%'",
        'has_latency_charts': False,
        'has_error_charts': False,
        'extra_charts': [],
    },
    'container': {
        'display_name': 'Containers',
        'name_field': 'container_name',
        'traces_table': 'traces_otel_analytic',
        'traces_time_field': 'start_time',
        'traces_filter': None,
        'logs_filter': None,
        'logs_join': None,
        'metrics_filter': "attributes_flat LIKE '%container.name={name}%'",
        'has_latency_charts': False,
        'has_error_charts': False,
        'extra_charts': [],
    },
}


def parse_time_interval(time_param, default="'5' MINUTE"):
    """Parse time parameter like '5m' into SQL interval string."""
    try:
        time_value = int(time_param[:-1])
        time_unit = time_param[-1]
    except (ValueError, IndexError):
        return default

    if time_unit == 's':
        return f"'{time_value}' SECOND"
    elif time_unit == 'm':
        return f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        return f"'{time_value}' HOUR"
    return default


def parse_time_range(req, default_preset='5m'):
    """Parse start/end or time query params into a time range dict.

    Returns dict with either:
      {'mode': 'absolute', 'start': "TIMESTAMP '...'", 'end': "TIMESTAMP '...'"}
      {'mode': 'relative', 'interval': "<sql interval>"}
    """
    start = req.args.get('start', '').strip()
    end = req.args.get('end', '').strip()
    if start and end:
        # datetime-local format: YYYY-MM-DDTHH:MM -> Trino TIMESTAMP
        start_ts = start.replace('T', ' ')
        end_ts = end.replace('T', ' ')
        if len(start_ts) == 16:  # YYYY-MM-DD HH:MM
            start_ts += ':00'
        if len(end_ts) == 16:
            end_ts += ':00'
        return {
            'mode': 'absolute',
            'start': f"TIMESTAMP '{start_ts}'",
            'end': f"TIMESTAMP '{end_ts}'",
        }
    interval = parse_time_interval(req.args.get('time', default_preset))
    return {'mode': 'relative', 'interval': interval}


def time_filter_sql(tr, field):
    """Generate a SQL WHERE fragment for the given time range dict and field name."""
    if tr['mode'] == 'absolute':
        return f"{field} BETWEEN {tr['start']} AND {tr['end']}"
    return f"{field} > NOW() - INTERVAL {tr['interval']}"


def time_range_to_interval(tr):
    """Return the raw SQL interval string from a time range (for filters that embed interval)."""
    if tr['mode'] == 'absolute':
        return tr['interval'] if 'interval' in tr else "'1' HOUR"
    return tr['interval']


def build_trace_filters(req):
    """Build extra WHERE clause fragments from request params for trace queries."""
    extra = ''
    status_filter = req.args.get('status', '')
    search_filter = req.args.get('search', '')
    min_duration = req.args.get('min_duration', '')
    if status_filter:
        extra += f" AND status_code = '{status_filter}'"
    if search_filter:
        extra += f" AND LOWER(span_name) LIKE LOWER('%{search_filter}%')"
    if min_duration:
        extra += f" AND duration_ns / 1000000.0 >= {float(min_duration)}"
    return extra


def build_log_filters(req, table_alias=''):
    """Build extra WHERE clause fragments from request params for log queries."""
    prefix = f"{table_alias}." if table_alias else ''
    extra = ''
    severity_filter = req.args.get('severity', '')
    search_filter = req.args.get('search', '')
    if severity_filter:
        extra += f" AND {prefix}severity_text = '{severity_filter}'"
    if search_filter:
        extra += f" AND LOWER({prefix}body) LIKE LOWER('%{search_filter}%')"
    return extra


# Import the system prompt from diagnostic_chat
from diagnostic_chat import SYSTEM_PROMPT

# =============================================================================
# Trino Query Executor
# =============================================================================

class TrinoQueryExecutor:
    """Executes SQL queries against VastDB via Trino."""

    def __init__(self):
        if not TRINO_AVAILABLE:
            raise ImportError("trino package not installed")

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
        # Extract aliases from the outermost SELECT clause
        select_match = re.search(r'\bSELECT\b(.*?)\bFROM\b', sql, re.IGNORECASE | re.DOTALL)
        if not select_match:
            return sql

        select_body = select_match.group(1)

        # Parse aliases: look for  "AS alias" patterns, respecting parentheses depth
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
        # last column
        fragment = select_body[current_expr_start:]
        alias_m = re.search(r'\bAS\s+(\w+)\s*$', fragment, re.IGNORECASE)
        aliases.append(alias_m.group(1) if alias_m else '')

        if not any(aliases):
            return sql

        # Build alias -> position map (1-indexed)
        alias_map = {}
        for idx, alias in enumerate(aliases, 1):
            if alias:
                alias_map[alias.lower()] = str(idx)

        if not alias_map:
            return sql

        def _replace_refs(clause_match: re.Match) -> str:
            keyword = clause_match.group(1)  # GROUP BY or ORDER BY
            body = clause_match.group(2)
            # Split on commas (top-level only)
            parts = body.split(',')
            new_parts = []
            for part in parts:
                stripped = part.strip()
                # Check if the whole token (ignoring trailing ASC/DESC) is an alias
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

        # Replace GROUP BY and ORDER BY references
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
            return {"success": False, "error": "Only SELECT queries are supported", "rows": [], "columns": []}

        # Fix LLM-generated GROUP BY alias references (Trino rejects these)
        sql = self._fix_group_by_aliases(sql)

        sql_lower = sql.lower()
        if "limit" not in sql_lower:
            sql = sql.rstrip(";") + f" LIMIT {MAX_QUERY_ROWS}"
        else:
            match = re.search(r'\blimit\s+(\d+)', sql_lower)
            if match and int(match.group(1)) > MAX_QUERY_ROWS:
                sql = re.sub(r'\blimit\s+\d+', f'LIMIT {MAX_QUERY_ROWS}', sql, flags=re.IGNORECASE)

        try:
            cursor = self.conn.cursor()
            with traced_cursor(cursor, sql) as cur:
                cur.execute(sql)
                columns = [desc[0] for desc in cur.description] if cur.description else []
                raw_rows = cur.fetchall()

            rows = []
            for raw_row in raw_rows:
                row_dict = {}
                for i, col in enumerate(columns):
                    val = raw_row[i]
                    if hasattr(val, 'isoformat'):
                        val = val.isoformat()
                    row_dict[col] = val
                rows.append(row_dict)

            return {"success": True, "rows": rows, "columns": columns, "row_count": len(rows)}

        except Exception as e:
            return {"success": False, "error": f"{type(e).__name__}: {str(e)}", "rows": [], "columns": []}

    def execute_write(self, sql: str) -> Dict[str, Any]:
        """Execute a write SQL statement (INSERT, DELETE, etc.) via Trino."""
        sql = sql.strip().rstrip(";")
        try:
            cursor = self.conn.cursor()
            with traced_cursor(cursor, sql) as cur:
                cur.execute(sql)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": f"{type(e).__name__}: {str(e)}"}


# Global instances
query_executor = None
anthropic_client = None

def get_query_executor():
    global query_executor
    if query_executor is None:
        query_executor = TrinoQueryExecutor()
    return query_executor

def get_anthropic_client():
    global anthropic_client
    if anthropic_client is None:
        anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return anthropic_client


# =============================================================================
# Chat Session Management
# =============================================================================

chat_sessions = {}  # session_id -> (last_access_time, history)
_SESSION_TTL = 3600  # 1 hour

def get_or_create_session(session_id: str) -> List[Dict]:
    now = time.time()
    # Evict stale sessions
    stale = [sid for sid, (ts, _) in chat_sessions.items() if now - ts > _SESSION_TTL]
    for sid in stale:
        del chat_sessions[sid]
    if session_id not in chat_sessions:
        chat_sessions[session_id] = (now, [])
    else:
        chat_sessions[session_id] = (now, chat_sessions[session_id][1])
    return chat_sessions[session_id][1]


# =============================================================================
# Routes
# =============================================================================

@app.route('/')
def index():
    return render_template('index.html')


def get_chat_tools():
    """Return the tools definition for the chat endpoint."""
    return [{
        "name": "execute_sql",
        "description": "Execute a SQL query against the observability database",
        "input_schema": {
            "type": "object",
            "properties": {"sql": {"type": "string", "description": "The SQL SELECT query"}},
            "required": ["sql"]
        }
    }, {
        "name": "generate_chart",
        "description": """Generate a chart/graph to visualize data. Use this when the user asks for visualizations, trends, or graphs.

CRITICAL - Choose the correct chart type:
- **line**: ONLY for TIME SERIES data where X-axis is timestamps/time buckets (e.g., "latency over time", "errors per hour")
- **bar**: For CATEGORICAL comparisons where X-axis is categories like services, endpoints, operations (e.g., "latency by endpoint", "errors by service")
- **doughnut**: For showing proportions/percentages of a whole (e.g., "request distribution")

WRONG: Using line chart for "latency by endpoint" (endpoints are categories, not time)
RIGHT: Using bar chart for "latency by endpoint"
RIGHT: Using line chart for "latency over the last hour" (time series)

IMPORTANT: Always provide data sorted appropriately - by time for line charts, by value (desc) for bar charts.""",
        "input_schema": {
            "type": "object",
            "properties": {
                "chart_type": {
                    "type": "string",
                    "enum": ["line", "bar", "doughnut"],
                    "description": "Type of chart: 'line' for time series, 'bar' for categorical comparisons, 'doughnut' for proportions"
                },
                "title": {
                    "type": "string",
                    "description": "Chart title"
                },
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "X-axis labels (categories or time points)"
                },
                "datasets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "label": {"type": "string", "description": "Dataset name (shown in legend)"},
                            "data": {"type": "array", "items": {"type": "number"}, "description": "Data values"},
                            "color": {"type": "string", "description": "Color (optional, e.g., '#00d9ff' or 'red')"}
                        },
                        "required": ["label", "data"]
                    },
                    "description": "One or more data series to plot"
                }
            },
            "required": ["chart_type", "title", "labels", "datasets"]
        }
    }, {
        "name": "generate_topology",
        "description": """Generate a service topology/dependency graph visualization. Use this when the user asks about:
- Service dependencies or topology
- What depends on a service/database
- What a service/database depends on
- Architecture or call flow visualization

The topology will be rendered as an interactive network graph. Nodes represent services or databases, edges represent call relationships.

To find dependencies, query traces_otel_analytic:
- For service-to-service calls: Look at parent_span_id relationships where services differ
- For database dependencies: Look at db_system field to find which services call which databases

Example query to find service dependencies:
SELECT DISTINCT
    parent.service_name as caller,
    child.service_name as callee
FROM traces_otel_analytic child
JOIN traces_otel_analytic parent ON child.parent_span_id = parent.span_id AND child.trace_id = parent.trace_id
WHERE child.service_name != parent.service_name
  AND child.start_time > NOW() - INTERVAL '10' MINUTE

Example query to find database dependencies:
SELECT DISTINCT service_name, db_system
FROM traces_otel_analytic
WHERE db_system IS NOT NULL AND db_system != ''
  AND start_time > NOW() - INTERVAL '10' MINUTE""",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Title for the topology graph"
                },
                "nodes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "description": "Unique node identifier"},
                            "label": {"type": "string", "description": "Display label for the node"},
                            "type": {"type": "string", "enum": ["service", "database", "external"], "description": "Node type for styling"},
                            "status": {"type": "string", "enum": ["healthy", "warning", "error"], "description": "Health status (optional)"}
                        },
                        "required": ["id", "label", "type"]
                    },
                    "description": "List of nodes (services, databases, external systems)"
                },
                "edges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from": {"type": "string", "description": "Source node ID"},
                            "to": {"type": "string", "description": "Target node ID"},
                            "label": {"type": "string", "description": "Edge label (optional, e.g., call count)"}
                        },
                        "required": ["from", "to"]
                    },
                    "description": "List of edges (call relationships between nodes)"
                }
            },
            "required": ["title", "nodes", "edges"]
        }
    }]


def _prefetch_trace_context(executor, user_message):
    """If the user message references a trace ID, pre-fetch trace + infrastructure context."""
    import re as _re
    match = _re.search(r'\b([a-f0-9]{32})\b', user_message)
    if not match:
        return None

    trace_id = match.group(1)
    context_parts = [f"[Pre-fetched context for trace {trace_id}]"]

    # 1. Get all spans
    spans = executor.execute_query(
        f"SELECT service_name, span_name, span_kind, status_code, db_system, "
        f"duration_ns/1000000.0 as duration_ms, start_time, attributes_json "
        f"FROM traces_otel_analytic WHERE trace_id = '{trace_id}' ORDER BY start_time"
    )
    if spans['success'] and spans['rows']:
        context_parts.append(f"Trace spans ({len(spans['rows'])} spans):")
        for s in spans['rows']:
            context_parts.append(f"  {s.get('start_time')} | {s.get('service_name')} | {s.get('span_name')} | "
                                 f"{s.get('span_kind')} | status={s.get('status_code')} | {s.get('duration_ms')}ms | "
                                 f"db_system={s.get('db_system', '')} | attrs={str(s.get('attributes_json', ''))[:200]}")

        # Extract timestamp for infrastructure queries
        first_time = spans['rows'][0].get('start_time', '')
        if first_time:
            try:
                if isinstance(first_time, str):
                    ts = datetime.fromisoformat(first_time.replace('Z', ''))
                else:
                    ts = first_time
                from datetime import timedelta
                t_start = (ts - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
                t_end = (ts + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

                # 2. Get exceptions
                events = executor.execute_query(
                    f"SELECT service_name, exception_type, exception_message "
                    f"FROM span_events_otel_analytic WHERE trace_id = '{trace_id}' LIMIT 10"
                )
                if events['success'] and events['rows']:
                    context_parts.append(f"\nExceptions:")
                    for e in events['rows']:
                        context_parts.append(f"  {e.get('exception_type')}: {str(e.get('exception_message', ''))[:200]}")

                # 3. PostgreSQL filesystem metrics (the key one LLMs keep missing)
                pg_fs = executor.execute_query(
                    f"SELECT metric_name, attributes_flat, "
                    f"ROUND(AVG(value_double) * 100, 2) as avg_pct, "
                    f"ROUND(MAX(value_double) * 100, 2) as max_pct "
                    f"FROM metrics_otel_analytic "
                    f"WHERE metric_name IN ('postgresql.filesystem.utilization', 'postgresql.filesystem.usage') "
                    f"AND attributes_flat LIKE '%db.system=postgresql%' "
                    f"AND timestamp BETWEEN TIMESTAMP '{t_start}' AND TIMESTAMP '{t_end}' "
                    f"GROUP BY metric_name, attributes_flat ORDER BY max_pct DESC"
                )
                if pg_fs['success'] and pg_fs['rows']:
                    context_parts.append(f"\nPostgreSQL filesystem metrics ({t_start} to {t_end}):")
                    for r in pg_fs['rows']:
                        context_parts.append(f"  {r.get('metric_name')}: avg={r.get('avg_pct')}%, max={r.get('max_pct')}% | {str(r.get('attributes_flat', ''))[:150]}")

                # 4. Host-level system metrics
                sys_metrics = executor.execute_query(
                    f"SELECT metric_name, "
                    f"ROUND(AVG(value_double) * 100, 2) as avg_pct, "
                    f"ROUND(MAX(value_double) * 100, 2) as max_pct "
                    f"FROM metrics_otel_analytic "
                    f"WHERE metric_name IN ('system.filesystem.utilization', 'system.memory.utilization') "
                    f"AND timestamp BETWEEN TIMESTAMP '{t_start}' AND TIMESTAMP '{t_end}' "
                    f"GROUP BY metric_name ORDER BY max_pct DESC"
                )
                if sys_metrics['success'] and sys_metrics['rows']:
                    context_parts.append(f"\nHost system metrics ({t_start} to {t_end}):")
                    for r in sys_metrics['rows']:
                        context_parts.append(f"  {r.get('metric_name')}: avg={r.get('avg_pct')}%, max={r.get('max_pct')}%")

                # 5. Container metrics
                container_metrics = executor.execute_query(
                    f"SELECT metric_name, attributes_flat, "
                    f"ROUND(AVG(value_double), 2) as avg_val, "
                    f"ROUND(MAX(value_double), 2) as max_val "
                    f"FROM metrics_otel_analytic "
                    f"WHERE metric_name IN ('container.cpu.percent', 'container.memory.percent') "
                    f"AND attributes_flat LIKE '%container.name=postgres%' "
                    f"AND timestamp BETWEEN TIMESTAMP '{t_start}' AND TIMESTAMP '{t_end}' "
                    f"GROUP BY metric_name, attributes_flat"
                )
                if container_metrics['success'] and container_metrics['rows']:
                    context_parts.append(f"\nPostgreSQL container metrics ({t_start} to {t_end}):")
                    for r in container_metrics['rows']:
                        context_parts.append(f"  {r.get('metric_name')}: avg={r.get('avg_val')}, max={r.get('max_val')}")

            except Exception as e:
                context_parts.append(f"\n[Error fetching infrastructure context: {e}]")

    return "\n".join(context_parts) if len(context_parts) > 1 else None


@app.route('/api/chat/stream', methods=['POST'])
def chat_stream():
    """Handle chat messages with streaming progress updates via SSE."""
    data = request.json
    user_message = data.get('message', '')
    session_id = data.get('session_id', 'default')

    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    def generate():
        conversation_history = get_or_create_session(session_id)

        executor = get_query_executor()
        # Pre-fetch trace context if user references a trace ID
        trace_context = _prefetch_trace_context(executor, user_message)
        enriched_message = user_message
        if trace_context:
            enriched_message = f"{user_message}\n\n{trace_context}"
        conversation_history.append({"role": "user", "content": enriched_message})

        # Keep history manageable
        if len(conversation_history) > 20:
            conversation_history = conversation_history[-20:]
            chat_sessions[session_id] = conversation_history

        client = get_anthropic_client()
        tools = get_chat_tools()

        executed_queries = []
        generated_charts = []
        generated_topologies = []
        iteration = 0
        max_iterations = 10  # Safety limit

        try:
            # Send initial status
            yield f"data: {json.dumps({'type': 'status', 'message': 'Analyzing your question...', 'step': 1})}\n\n"

            response = client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=conversation_history
            )

            # Handle tool use loop
            while response.stop_reason == "tool_use" and iteration < max_iterations:
                iteration += 1
                tool_results = []

                # Count tools to execute
                tool_count = sum(1 for cb in response.content if cb.type == "tool_use")
                tool_index = 0

                for content_block in response.content:
                    if content_block.type == "tool_use":
                        tool_index += 1

                        if content_block.name == "execute_sql":
                            sql = content_block.input.get("sql", "")
                            # Send query status
                            yield f"data: {json.dumps({'type': 'status', 'message': f'Executing query {tool_index}/{tool_count}...', 'step': iteration + 1, 'detail': sql[:80] + '...' if len(sql) > 80 else sql})}\n\n"

                            result = executor.execute_query(sql)
                            executed_queries.append({"sql": sql, "result": result})

                            row_count = result.get('row_count', 0) if result.get('success') else 0
                            yield f"data: {json.dumps({'type': 'query_result', 'query_index': len(executed_queries) - 1, 'row_count': row_count, 'success': result.get('success', False)})}\n\n"

                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": content_block.id,
                                "content": json.dumps(result, default=str)
                            })

                        elif content_block.name == "generate_chart":
                            chart_title = content_block.input.get("title", "Chart")
                            yield f"data: {json.dumps({'type': 'status', 'message': f'Generating chart: {chart_title}...', 'step': iteration + 1})}\n\n"

                            chart_data = {
                                "chart_type": content_block.input.get("chart_type", "line"),
                                "title": content_block.input.get("title", "Chart"),
                                "labels": content_block.input.get("labels", []),
                                "datasets": content_block.input.get("datasets", [])
                            }
                            generated_charts.append(chart_data)
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": content_block.id,
                                "content": json.dumps({"success": True, "message": "Chart generated successfully"})
                            })

                        elif content_block.name == "generate_topology":
                            topo_title = content_block.input.get("title", "Topology")
                            yield f"data: {json.dumps({'type': 'status', 'message': f'Generating topology: {topo_title}...', 'step': iteration + 1})}\n\n"

                            topology_data = {
                                "title": topo_title,
                                "nodes": content_block.input.get("nodes", []),
                                "edges": content_block.input.get("edges", [])
                            }
                            generated_topologies.append(topology_data)
                            tool_results.append({
                                "type": "tool_result",
                                "tool_use_id": content_block.id,
                                "content": json.dumps({"success": True, "message": "Topology generated successfully"})
                            })

                conversation_history.append({"role": "assistant", "content": response.content})
                conversation_history.append({"role": "user", "content": tool_results})

                # Send analyzing status before next API call
                yield f"data: {json.dumps({'type': 'status', 'message': 'Analyzing results...', 'step': iteration + 1})}\n\n"

                response = client.messages.create(
                    model=ANTHROPIC_MODEL,
                    max_tokens=4096,
                    system=SYSTEM_PROMPT,
                    tools=tools,
                    messages=conversation_history
                )

            # Extract final response
            yield f"data: {json.dumps({'type': 'status', 'message': 'Preparing response...', 'step': iteration + 2})}\n\n"

            final_response = ""
            for content_block in response.content:
                if hasattr(content_block, 'text'):
                    final_response += content_block.text

            conversation_history.append({"role": "assistant", "content": final_response})

            # Send final result (use default=str to handle Decimal types from Trino)
            yield f"data: {json.dumps({'type': 'complete', 'response': final_response, 'queries': executed_queries, 'charts': generated_charts, 'topologies': generated_topologies}, default=str)}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })


@app.route('/api/chat', methods=['POST'])
def chat():
    """Handle chat messages (non-streaming fallback)."""
    data = request.json
    user_message = data.get('message', '')
    session_id = data.get('session_id', 'default')

    if not user_message:
        return jsonify({'error': 'No message provided'}), 400

    conversation_history = get_or_create_session(session_id)

    executor = get_query_executor()
    # Pre-fetch trace context if user references a trace ID
    trace_context = _prefetch_trace_context(executor, user_message)
    enriched_message = user_message
    if trace_context:
        enriched_message = f"{user_message}\n\n{trace_context}"
    conversation_history.append({"role": "user", "content": enriched_message})

    # Keep history manageable
    if len(conversation_history) > 20:
        conversation_history = conversation_history[-20:]
        chat_sessions[session_id] = conversation_history

    client = get_anthropic_client()
    tools = get_chat_tools()

    executed_queries = []
    generated_charts = []
    generated_topologies = []

    try:
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=conversation_history
        )

        # Handle tool use loop
        iteration = 0
        max_iterations = 10  # Safety limit matching streaming endpoint
        while response.stop_reason == "tool_use" and iteration < max_iterations:
            iteration += 1
            tool_results = []

            for content_block in response.content:
                if content_block.type == "tool_use":
                    if content_block.name == "execute_sql":
                        sql = content_block.input.get("sql", "")
                        result = executor.execute_query(sql)
                        executed_queries.append({"sql": sql, "result": result})
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": content_block.id,
                            "content": json.dumps(result, default=str)
                        })
                    elif content_block.name == "generate_chart":
                        chart_data = {
                            "chart_type": content_block.input.get("chart_type", "line"),
                            "title": content_block.input.get("title", "Chart"),
                            "labels": content_block.input.get("labels", []),
                            "datasets": content_block.input.get("datasets", [])
                        }
                        generated_charts.append(chart_data)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": content_block.id,
                            "content": json.dumps({"success": True, "message": "Chart generated successfully"})
                        })
                    elif content_block.name == "generate_topology":
                        topology_data = {
                            "title": content_block.input.get("title", "Topology"),
                            "nodes": content_block.input.get("nodes", []),
                            "edges": content_block.input.get("edges", [])
                        }
                        generated_topologies.append(topology_data)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": content_block.id,
                            "content": json.dumps({"success": True, "message": "Topology generated successfully"})
                        })

            conversation_history.append({"role": "assistant", "content": response.content})
            conversation_history.append({"role": "user", "content": tool_results})

            response = client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=tools,
                messages=conversation_history
            )

        # Extract final response
        final_response = ""
        for content_block in response.content:
            if hasattr(content_block, 'text'):
                final_response += content_block.text

        conversation_history.append({"role": "assistant", "content": final_response})

        return jsonify({
            'response': final_response,
            'queries': executed_queries,
            'charts': generated_charts,
            'topologies': generated_topologies
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear', methods=['POST'])
def clear_session():
    """Clear chat session."""
    data = request.json
    session_id = data.get('session_id', 'default')
    chat_sessions[session_id] = []
    return jsonify({'status': 'cleared'})


@app.route('/api/status', methods=['GET'])
def system_status():
    """Get current system status.  Cached for CACHE_TTL_STATUS seconds."""
    cache_key = f"/api/status?time={request.args.get('time', '5m')}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()
    time_param = request.args.get('time', '5m')

    # Parse time parameter
    time_value = int(time_param[:-1])
    time_unit = time_param[-1]

    if time_unit == 's':
        interval = f"'{time_value}' SECOND"
    elif time_unit == 'm':
        interval = f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        interval = f"'{time_value}' HOUR"
    else:
        interval = "'5' MINUTE"

    status = {
        'services': [],
        'databases': [],
        'hosts': [],
        'recent_errors': [],
        'error_summary': {},
        'timestamp': datetime.utcnow().isoformat()
    }

    # Load all suppressions to exclude from error counts/lists
    suppression_not_expr = ""  # for use inside CASE WHEN (same as suppression_where)
    suppression_where = ""     # for use in WHERE clauses
    try:
        sup_result = executor.execute_query(
            "SELECT service_name, suppression_type, exception_type FROM alert_suppressions"
        )
        if sup_result.get('success') and sup_result.get('rows'):
            op_clauses = []       # error_operation: filter by span_name
            exc_types = set()     # exception_type: filter via NOT EXISTS on span_events

            for row in sup_result['rows']:
                svc = row['service_name']
                val = row['exception_type']
                stype = row.get('suppression_type', 'exception_type')

                if stype == 'error_operation':
                    if svc == '*':
                        op_clauses.append(f"span_name = '{val}'")
                    else:
                        op_clauses.append(f"(service_name = '{svc}' AND span_name = '{val}')")
                elif stype == 'exception_type':
                    exc_types.add(val)

            # suppression_op_expr: safe for use inside CASE WHEN (no subqueries)
            # suppression_where: full filter for WHERE clauses (can include NOT EXISTS)
            op_filter = f"AND NOT ({' OR '.join(op_clauses)})" if op_clauses else ""
            exc_filter = ""
            if exc_types:
                escaped = "', '".join(exc_types)
                exc_filter = (
                    f"AND NOT EXISTS (SELECT 1 FROM span_events_otel_analytic se "
                    f"WHERE se.trace_id = traces_otel_analytic.trace_id "
                    f"AND se.span_id = traces_otel_analytic.span_id "
                    f"AND se.exception_type IN ('{escaped}'))"
                )
            suppression_not_expr = op_filter  # safe for CASE WHEN (operations only)
            suppression_where = f"{op_filter} {exc_filter}".strip()  # full filter for WHERE
    except Exception:
        pass

    # Get service health - use pre-computed topology table only for the
    # default 1h window (topology_services uses a 1h lookback).
    # For shorter windows, query raw traces so the dropdown actually works.
    topology_svc_result = None
    if time_param == '1h':
        topology_svc_result = executor.execute_query("""
        SELECT service_name,
               span_count as total_spans,
               CAST(ROUND(error_pct / 100.0 * span_count, 0) AS BIGINT) as errors,
               error_pct,
               avg_latency_ms
        FROM topology_services
        ORDER BY span_count DESC
        """)
    if topology_svc_result and topology_svc_result['success'] and topology_svc_result['rows']:
        status['services'] = topology_svc_result['rows']
    else:
        # Fallback: discover from 1 hour, calculate stats for selected window
        all_services_query = """
        SELECT DISTINCT service_name
        FROM traces_otel_analytic
        WHERE start_time > NOW() - INTERVAL '1' HOUR
        """
        all_services = set()
        result = executor.execute_query(all_services_query)
        if result['success']:
            all_services = {row['service_name'] for row in result['rows']}

        stats_query = f"""
        SELECT service_name,
               COUNT(*) as total_spans,
               SUM(CASE WHEN status_code = 'ERROR' AND (http_status IS NULL OR http_status < 200 OR http_status >= 300) {suppression_not_expr} THEN 1 ELSE 0 END) as errors,
               ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' AND (http_status IS NULL OR http_status < 200 OR http_status >= 300) {suppression_not_expr} THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct,
               ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms
        FROM traces_otel_analytic
        WHERE start_time > NOW() - INTERVAL {interval}
        GROUP BY service_name
        ORDER BY total_spans DESC
        """
        stats_by_service = {}
        result = executor.execute_query(stats_query)
        if result['success']:
            for row in result['rows']:
                stats_by_service[row['service_name']] = row

        services_list = []
        for svc in all_services:
            if svc in stats_by_service:
                services_list.append(stats_by_service[svc])
            else:
                services_list.append({
                    'service_name': svc,
                    'total_spans': 0,
                    'errors': 0,
                    'error_pct': None,
                    'avg_latency_ms': None
                })

        services_list.sort(key=lambda x: x['total_spans'], reverse=True)
        status['services'] = services_list

    # Get database status
    db_query = """
    SELECT db_system,
           COUNT(*) as span_count,
           MAX(start_time) as last_seen,
           ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms
    FROM traces_otel_analytic
    WHERE db_system IS NOT NULL AND db_system != ''
      AND start_time > NOW() - INTERVAL '10' MINUTE
    GROUP BY db_system
    """
    result = executor.execute_query(db_query)
    if result['success']:
        status['databases'] = result['rows']

    # Get error summary stats
    error_summary_query = f"""
    SELECT
        COUNT(*) as total_errors,
        COUNT(DISTINCT service_name) as affected_services
    FROM traces_otel_analytic
    WHERE status_code = 'ERROR'
      AND (http_status IS NULL OR http_status < 200 OR http_status >= 300)
      AND start_time > NOW() - INTERVAL {interval}
      {suppression_where}
    """
    result = executor.execute_query(error_summary_query)
    if result['success'] and result['rows']:
        status['error_summary'] = result['rows'][0]

    # Get recent errors with trace_id and span_id for drill-down
    error_query = f"""
    SELECT trace_id, span_id, service_name, span_name, status_code,
           duration_ns / 1000000.0 as duration_ms,
           start_time
    FROM traces_otel_analytic
    WHERE status_code = 'ERROR'
      AND (http_status IS NULL OR http_status < 200 OR http_status >= 300)
      AND start_time > NOW() - INTERVAL {interval}
      {suppression_where}
    ORDER BY start_time DESC
    LIMIT 10
    """
    result = executor.execute_query(error_query)
    if result['success']:
        status['recent_errors'] = result['rows']

    # Get host metrics - try topology table first, fall back to inline query
    topology_host_result = executor.execute_query("""
    SELECT host_name, display_name, os_type, cpu_pct, memory_pct, disk_pct, last_seen
    FROM topology_hosts
    """)
    if topology_host_result['success'] and topology_host_result['rows']:
        status['hosts'] = topology_host_result['rows']
    else:
        # Fallback: expensive SUBSTR/POSITION chain on attributes_flat
        host_query = """
        SELECT
            SUBSTR(attributes_flat,
                   POSITION('host.name=' IN attributes_flat) + 10,
                   POSITION(',' IN SUBSTR(attributes_flat, POSITION('host.name=' IN attributes_flat) + 10)) - 1
            ) as host_name,
            MAX(CASE WHEN metric_name = 'system.cpu.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as cpu_pct,
            MAX(CASE WHEN metric_name = 'system.memory.utilization' AND attributes_flat LIKE '%state=used%' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as memory_pct,
            MAX(CASE WHEN metric_name = 'system.filesystem.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as disk_pct,
            MAX(timestamp) as last_seen
        FROM metrics_otel_analytic
        WHERE metric_name IN ('system.cpu.utilization', 'system.memory.utilization', 'system.filesystem.utilization')
          AND timestamp > NOW() - INTERVAL '5' MINUTE
          AND attributes_flat LIKE '%host.name=%'
        GROUP BY SUBSTR(attributes_flat,
                   POSITION('host.name=' IN attributes_flat) + 10,
                   POSITION(',' IN SUBSTR(attributes_flat, POSITION('host.name=' IN attributes_flat) + 10)) - 1
            )
        HAVING SUBSTR(attributes_flat,
                   POSITION('host.name=' IN attributes_flat) + 10,
                   POSITION(',' IN SUBSTR(attributes_flat, POSITION('host.name=' IN attributes_flat) + 10)) - 1
            ) IS NOT NULL
        """
        result = executor.execute_query(host_query)
        if result['success']:
            status['hosts'] = result['rows']

    # Get container status
    container_result = executor.execute_query("""
    SELECT container_name, cpu_pct, memory_pct, memory_usage_mb, last_seen
    FROM topology_containers
    ORDER BY container_name
    """)
    if container_result['success'] and container_result['rows']:
        status['containers'] = container_result['rows']
    else:
        # Fallback: query metrics directly
        container_query = """
        SELECT
            REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1) as container_name,
            MAX(CASE WHEN metric_name = 'container.cpu.percent' THEN ROUND(value_double, 1) END) as cpu_pct,
            MAX(CASE WHEN metric_name = 'container.memory.percent' THEN ROUND(value_double, 1) END) as memory_pct,
            MAX(CASE WHEN metric_name = 'container.memory.usage.total' THEN ROUND(value_double / 1048576.0, 1) END) as memory_usage_mb,
            MAX(timestamp) as last_seen
        FROM metrics_otel_analytic
        WHERE metric_name IN ('container.cpu.percent', 'container.memory.percent', 'container.memory.usage.total')
          AND timestamp > NOW() - INTERVAL '5' MINUTE
          AND attributes_flat LIKE '%container.name=%'
        GROUP BY REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1)
        HAVING REGEXP_EXTRACT(attributes_flat, 'container\\.name=([^,]+)', 1) IS NOT NULL
        ORDER BY 1
        """
        result = executor.execute_query(container_query)
        if result['success']:
            status['containers'] = result['rows']

    # Build entity_categories for generic UI
    status['entity_categories'] = [
        {
            'type': 'service',
            'display_name': 'Services',
            'name_field': 'service_name',
            'entities': status['services'],
        },
        {
            'type': 'database',
            'display_name': 'Databases',
            'name_field': 'db_system',
            'entities': status['databases'],
        },
        {
            'type': 'host',
            'display_name': 'Hosts',
            'name_field': 'host_name',
            'entities': status['hosts'],
        },
        {
            'type': 'container',
            'display_name': 'Containers',
            'name_field': 'container_name',
            'entities': status.get('containers', []),
        },
    ]

    response = jsonify(status)
    _cache.set(cache_key, response, CACHE_TTL_STATUS)
    return response


@app.route('/api/query', methods=['POST'])
def execute_query():
    """Execute a custom SQL query."""
    data = request.json
    sql = data.get('sql', '')

    if not sql:
        return jsonify({'error': 'No SQL provided'}), 400

    executor = get_query_executor()
    result = executor.execute_query(sql)
    return jsonify(result)


@app.route('/api/service/<service_name>', methods=['GET'])
def service_details(service_name):
    """Get detailed metrics for a specific service.

    Reads from pre-aggregated service_metrics_1m table when available,
    falling back to raw traces_otel_analytic queries if the rollup table
    is empty or missing.
    """
    executor = get_query_executor()
    tr = parse_time_range(request, default_preset='1h')
    time_cond_bucket = time_filter_sql(tr, 'time_bucket')
    time_cond_start = time_filter_sql(tr, 'start_time')

    data = {
        'service_name': service_name,
        'latency_history': [],
        'error_history': [],
        'throughput_history': [],
        'recent_errors': [],
        'top_operations': []
    }

    # Try pre-aggregated rollup table first
    rollup_query = f"""
    SELECT time_bucket, avg_latency_ms, max_latency_ms, p95_latency_ms,
           request_count, error_count, error_pct
    FROM service_metrics_1m
    WHERE service_name = '{service_name}'
      AND {time_cond_bucket}
    ORDER BY time_bucket
    """
    result = executor.execute_query(rollup_query)
    use_rollup = result['success'] and len(result.get('rows', [])) > 0

    if use_rollup:
        rows = result['rows']
        # Latency history from rollup
        data['latency_history'] = [
            {'time_bucket': r['time_bucket'], 'avg_latency_ms': r['avg_latency_ms'],
             'max_latency_ms': r['max_latency_ms'], 'request_count': r['request_count']}
            for r in rows
        ]
        # Error history from rollup
        data['error_history'] = [
            {'time_bucket': r['time_bucket'], 'total': r['request_count'],
             'errors': r['error_count'], 'error_pct': r['error_pct']}
            for r in rows
        ]
    else:
        # Fallback: raw queries on traces_otel_analytic
        latency_query = f"""
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(MAX(duration_ns / 1000000.0), 2) as max_latency_ms,
            COUNT(*) as request_count
        FROM traces_otel_analytic
        WHERE service_name = '{service_name}'
          AND {time_cond_start}
        GROUP BY date_trunc('minute', start_time)
        ORDER BY time_bucket
        """
        result = executor.execute_query(latency_query)
        if result['success']:
            data['latency_history'] = result['rows']

        error_query = f"""
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            COUNT(*) as total,
            SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct
        FROM traces_otel_analytic
        WHERE service_name = '{service_name}'
          AND {time_cond_start}
        GROUP BY date_trunc('minute', start_time)
        ORDER BY time_bucket
        """
        result = executor.execute_query(error_query)
        if result['success']:
            data['error_history'] = result['rows']

    # Recent errors (always from raw traces — need individual span detail)
    recent_errors_query = f"""
    SELECT span_name, status_code, start_time,
           duration_ns / 1000000.0 as duration_ms
    FROM traces_otel_analytic
    WHERE service_name = '{service_name}'
      AND status_code = 'ERROR'
      AND {time_cond_start}
    ORDER BY start_time DESC
    LIMIT 10
    """
    result = executor.execute_query(recent_errors_query)
    if result['success']:
        data['recent_errors'] = result['rows']

    # Top operations by volume
    top_ops_query = f"""
    SELECT span_name,
           COUNT(*) as call_count,
           ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
           ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct
    FROM traces_otel_analytic
    WHERE service_name = '{service_name}'
      AND {time_cond_start}
    GROUP BY span_name
    ORDER BY call_count DESC
    LIMIT 10
    """
    result = executor.execute_query(top_ops_query)
    if result['success']:
        data['top_operations'] = result['rows']

    return jsonify(data)


@app.route('/api/error/<trace_id>/<span_id>', methods=['GET'])
def error_details(trace_id, span_id):
    """Get detailed information about a specific error."""
    executor = get_query_executor()

    data = {
        'error_info': None,
        'exception': None,
        'trace': [],
        'attributes': {},
        'similar_errors': None,
        'related_alerts': [],
        'service_health': []
    }

    # Get error span info
    error_query = f"""
    SELECT service_name, span_name, span_kind, status_code,
           duration_ns / 1000000.0 as duration_ms,
           start_time, db_system
    FROM traces_otel_analytic
    WHERE trace_id = '{trace_id}' AND span_id = '{span_id}'
    LIMIT 1
    """
    result = executor.execute_query(error_query)
    if result['success'] and result['rows']:
        data['error_info'] = result['rows'][0]

    # Get exception details from span_events
    exception_query = f"""
    SELECT exception_type, exception_message, exception_stacktrace
    FROM span_events_otel_analytic
    WHERE trace_id = '{trace_id}' AND span_id = '{span_id}'
      AND exception_type IS NOT NULL AND exception_type != ''
    LIMIT 1
    """
    result = executor.execute_query(exception_query)
    if result['success'] and result['rows']:
        data['exception'] = result['rows'][0]

    # Get span attributes for diagnostic context
    attrs_query = f"""
    SELECT attributes_json FROM traces_otel_analytic
    WHERE trace_id = '{trace_id}' AND span_id = '{span_id}' LIMIT 1
    """
    result = executor.execute_query(attrs_query)
    if result['success'] and result['rows']:
        raw = result['rows'][0].get('attributes_json', '')
        if raw:
            try:
                all_attrs = json.loads(raw) if isinstance(raw, str) else raw
                diag_prefixes = ('db.', 'http.', 'messaging.', 'rpc.', 'net.')
                data['attributes'] = {k: v for k, v in all_attrs.items()
                                      if any(k.startswith(p) for p in diag_prefixes)}
            except (json.JSONDecodeError, AttributeError):
                pass

    # Similar errors frequency (only if we have exception info)
    if data['exception'] and data['exception'].get('exception_type'):
        exc_type = data['exception']['exception_type'].replace("'", "''")
        svc = (data['error_info'] or {}).get('service_name', '').replace("'", "''")
        if svc:
            similar_query = f"""
            SELECT
              COUNT(*) FILTER (WHERE timestamp > NOW() - INTERVAL '1' HOUR) as count_1h,
              COUNT(*) as count_24h,
              MIN(timestamp) as first_seen
            FROM span_events_otel_analytic
            WHERE exception_type = '{exc_type}' AND service_name = '{svc}'
              AND timestamp > NOW() - INTERVAL '24' HOUR
            """
            result = executor.execute_query(similar_query)
            if result['success'] and result['rows']:
                row = result['rows'][0]
                data['similar_errors'] = {
                    'count_1h': row.get('count_1h', 0) or 0,
                    'count_24h': row.get('count_24h', 0) or 0,
                    'first_seen': str(row.get('first_seen', '')) if row.get('first_seen') else None
                }

    # Related alerts within ±5 minutes
    error_time = (data['error_info'] or {}).get('start_time')
    svc = (data['error_info'] or {}).get('service_name', '').replace("'", "''")
    if error_time and svc:
        # Trino requires space-separated timestamp, not ISO 'T' separator
        error_time_sql = str(error_time).replace('T', ' ')
        alerts_query = f"""
        SELECT alert_id, alert_type, severity, title, created_at
        FROM alerts
        WHERE service_name = '{svc}'
          AND created_at BETWEEN TIMESTAMP '{error_time_sql}' - INTERVAL '5' MINUTE
                             AND TIMESTAMP '{error_time_sql}' + INTERVAL '5' MINUTE
        ORDER BY created_at DESC LIMIT 5
        """
        result = executor.execute_query(alerts_query)
        if result['success'] and result['rows']:
            data['related_alerts'] = result['rows']

    # Service health anomalies in last 10 minutes
    if svc:
        health_query = f"""
        SELECT metric_type, current_value, expected_value, z_score, timestamp
        FROM anomaly_scores
        WHERE service_name = '{svc}'
          AND timestamp > NOW() - INTERVAL '10' MINUTE AND is_anomaly = true
        ORDER BY z_score DESC LIMIT 5
        """
        result = executor.execute_query(health_query)
        if result['success'] and result['rows']:
            data['service_health'] = result['rows']

    # Get full trace for context
    trace_query = f"""
    SELECT service_name, span_name, span_kind, status_code,
           duration_ns / 1000000.0 as duration_ms,
           start_time, parent_span_id
    FROM traces_otel_analytic
    WHERE trace_id = '{trace_id}'
    ORDER BY start_time
    """
    result = executor.execute_query(trace_query)
    if result['success']:
        data['trace'] = result['rows']

    return jsonify(data)




@app.route('/api/service/<service_name>/dependencies', methods=['GET'])
def service_dependencies(service_name):
    """Get upstream and downstream dependencies for a service."""
    executor = get_query_executor()
    time_param = request.args.get('time', '15m')

    # Parse time parameter
    time_value = int(time_param[:-1])
    time_unit = time_param[-1]
    if time_unit == 's':
        interval = f"'{time_value}' SECOND"
    elif time_unit == 'm':
        interval = f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        interval = f"'{time_value}' HOUR"
    else:
        interval = "'15' MINUTE"

    data = {'upstream': [], 'downstream': []}

    # Try topology table first
    topo_down = executor.execute_query(f"""
    SELECT target_service as dependency, dependency_type as dep_type, call_count
    FROM topology_dependencies
    WHERE source_service = '{service_name}'
    ORDER BY call_count DESC
    LIMIT 20
    """)
    topo_up = executor.execute_query(f"""
    SELECT source_service as dependent, 'service' as dep_type, call_count
    FROM topology_dependencies
    WHERE target_service = '{service_name}'
    ORDER BY call_count DESC
    LIMIT 20
    """)

    if (topo_down['success'] and topo_down['rows']) or (topo_up['success'] and topo_up['rows']):
        if topo_down['success']:
            data['downstream'] = topo_down['rows']
        if topo_up['success']:
            data['upstream'] = topo_up['rows']
    else:
        # Fallback: expensive self-JOIN on traces
        downstream_query = f"""
        SELECT DISTINCT
            COALESCE(NULLIF(child.db_system, ''), child.service_name) as dependency,
            CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END as dep_type,
            COUNT(*) as call_count
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE parent.service_name = '{service_name}'
          AND (child.service_name != '{service_name}' OR child.db_system IS NOT NULL)
          AND parent.start_time > NOW() - INTERVAL {interval}
        GROUP BY COALESCE(NULLIF(child.db_system, ''), child.service_name),
                 CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END
        ORDER BY call_count DESC
        LIMIT 20
        """

        upstream_query = f"""
        SELECT DISTINCT
            parent.service_name as dependent,
            'service' as dep_type,
            COUNT(*) as call_count
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE child.service_name = '{service_name}'
          AND parent.service_name != '{service_name}'
          AND child.start_time > NOW() - INTERVAL {interval}
        GROUP BY parent.service_name
        ORDER BY call_count DESC
        LIMIT 20
        """

        result = executor.execute_query(downstream_query)
        if result['success']:
            data['downstream'] = result['rows']

        result = executor.execute_query(upstream_query)
        if result['success']:
            data['upstream'] = result['rows']

    return jsonify(data)


@app.route('/api/service/<service_name>/operations', methods=['GET'])
def service_operations(service_name):
    """Get top operations for a service with configurable time window.

    Reads from pre-aggregated operation_metrics_5m when the requested
    window is >= 5 minutes, falling back to raw traces otherwise.
    """
    executor = get_query_executor()
    tr = parse_time_range(request)
    time_param = request.args.get('time', '5m')

    if tr['mode'] == 'relative':
        interval = tr['interval']
        # Determine rollup eligibility from original time param
        try:
            time_value = int(time_param[:-1])
            time_unit = time_param[-1]
        except (ValueError, IndexError):
            time_value, time_unit = 5, 'm'
        use_rollup = (time_unit == 'h') or (time_unit == 'm' and time_value >= 5)
    else:
        interval = "'1' HOUR"
        use_rollup = True  # absolute ranges are always large enough

    time_cond_bucket = time_filter_sql(tr, 'time_bucket')
    time_cond_start = time_filter_sql(tr, 'start_time')

    if use_rollup:
        rollup_query = f"""
        SELECT span_name,
               CAST(SUM(call_count) AS BIGINT) as call_count,
               ROUND(SUM(avg_latency_ms * call_count) / NULLIF(SUM(call_count), 0), 2) as avg_latency_ms,
               ROUND(100.0 * SUM(error_count) / NULLIF(SUM(call_count), 0), 2) as error_pct
        FROM operation_metrics_5m
        WHERE service_name = '{service_name}'
          AND {time_cond_bucket}
        GROUP BY span_name
        ORDER BY call_count DESC
        LIMIT 10
        """
        result = executor.execute_query(rollup_query)
        if result['success'] and len(result.get('rows', [])) > 0:
            return jsonify({'operations': result['rows']})

    # Fallback: raw traces
    top_ops_query = f"""
    SELECT span_name,
           COUNT(*) as call_count,
           ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
           ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
    FROM traces_otel_analytic
    WHERE service_name = '{service_name}'
      AND {time_cond_start}
    GROUP BY span_name
    ORDER BY call_count DESC
    LIMIT 10
    """
    result = executor.execute_query(top_ops_query)

    if result['success']:
        return jsonify({'operations': result['rows']})
    else:
        return jsonify({'operations': [], 'error': result.get('error')})


@app.route('/api/database/<db_system>', methods=['GET'])
def database_details(db_system):
    """Get detailed metrics for a specific database system.

    Reads from pre-aggregated db_metrics_1m table when available,
    falling back to raw traces_otel_analytic queries if the rollup
    table is empty or missing.
    """
    executor = get_query_executor()
    tr = parse_time_range(request, default_preset='1h')
    time_cond_bucket = time_filter_sql(tr, 'time_bucket')
    time_cond_start = time_filter_sql(tr, 'start_time')
    time_cond_ts = time_filter_sql(tr, 'timestamp')

    data = {
        'db_system': db_system,
        'latency_history': [],
        'error_history': [],
        'slow_queries': [],
        'deadlock_history': [],
        'size_history': []
    }

    # Try pre-aggregated rollup table first
    rollup_query = f"""
    SELECT time_bucket, avg_latency_ms, max_latency_ms,
           query_count, error_count, error_pct
    FROM db_metrics_1m
    WHERE db_system = '{db_system}'
      AND {time_cond_bucket}
    ORDER BY time_bucket
    """
    result = executor.execute_query(rollup_query)
    use_rollup = result['success'] and len(result.get('rows', [])) > 0

    if use_rollup:
        rows = result['rows']
        # Latency history from rollup
        data['latency_history'] = [
            {'time_bucket': r['time_bucket'], 'avg_latency_ms': r['avg_latency_ms'],
             'max_latency_ms': r['max_latency_ms'], 'query_count': r['query_count']}
            for r in rows
        ]
        # Error history from rollup
        data['error_history'] = [
            {'time_bucket': r['time_bucket'], 'total': r['query_count'],
             'errors': r['error_count'], 'error_pct': r['error_pct']}
            for r in rows
        ]
    else:
        # Fallback: raw queries on traces_otel_analytic
        latency_query = f"""
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(MAX(duration_ns / 1000000.0), 2) as max_latency_ms,
            COUNT(*) as query_count
        FROM traces_otel_analytic
        WHERE db_system = '{db_system}'
          AND {time_cond_start}
        GROUP BY date_trunc('minute', start_time)
        ORDER BY time_bucket
        """
        result = executor.execute_query(latency_query)
        if result['success']:
            data['latency_history'] = result['rows']

        error_query = f"""
        SELECT
            date_trunc('minute', start_time) as time_bucket,
            COUNT(*) as total,
            SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
        FROM traces_otel_analytic
        WHERE db_system = '{db_system}'
          AND {time_cond_start}
        GROUP BY date_trunc('minute', start_time)
        ORDER BY time_bucket
        """
        result = executor.execute_query(error_query)
        if result['success']:
            data['error_history'] = result['rows']

    # Slowest queries by service/operation (always raw — need per-operation detail)
    slow_queries_query = f"""
    SELECT service_name, span_name,
           COUNT(*) as call_count,
           ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
           ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct
    FROM traces_otel_analytic
    WHERE db_system = '{db_system}'
      AND {time_cond_start}
    GROUP BY service_name, span_name
    ORDER BY avg_latency_ms DESC
    LIMIT 10
    """
    result = executor.execute_query(slow_queries_query)
    if result['success']:
        data['slow_queries'] = result['rows']

    # Deadlocks over time
    deadlock_query = f"""
    SELECT
        date_trunc('minute', timestamp) as time_bucket,
        MAX(value_double) as deadlock_count
    FROM metrics_otel_analytic
    WHERE metric_name = '{db_system}.deadlocks'
      AND {time_cond_ts}
    GROUP BY date_trunc('minute', timestamp)
    ORDER BY time_bucket
    """
    result = executor.execute_query(deadlock_query)
    if result['success']:
        data['deadlock_history'] = result['rows']

    # Database size over time
    size_query = f"""
    SELECT
        date_trunc('minute', timestamp) as time_bucket,
        ROUND(MAX(value_double) / 1048576.0, 2) as size_mb
    FROM metrics_otel_analytic
    WHERE metric_name = '{db_system}.db_size'
      AND {time_cond_ts}
    GROUP BY date_trunc('minute', timestamp)
    ORDER BY time_bucket
    """
    result = executor.execute_query(size_query)
    if result['success']:
        data['size_history'] = result['rows']

    return jsonify(data)


@app.route('/api/database/<db_system>/dependencies', methods=['GET'])
def database_dependencies(db_system):
    """Get services that depend on this database."""
    executor = get_query_executor()
    time_param = request.args.get('time', '15m')

    # Parse time parameter
    time_value = int(time_param[:-1])
    time_unit = time_param[-1]
    if time_unit == 's':
        interval = f"'{time_value}' SECOND"
    elif time_unit == 'm':
        interval = f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        interval = f"'{time_value}' HOUR"
    else:
        interval = "'15' MINUTE"

    data = {'upstream': [], 'downstream': [], 'host': None}

    # Try topology tables first
    topo_up = executor.execute_query(f"""
    SELECT source_service as dependent, 'service' as dep_type,
           call_count, avg_latency_ms, error_pct
    FROM topology_dependencies
    WHERE target_service = '{db_system}' AND dependency_type = 'database'
    ORDER BY call_count DESC
    LIMIT 20
    """)
    topo_host = executor.execute_query(f"""
    SELECT host_name FROM topology_database_hosts
    WHERE db_system = '{db_system}'
    LIMIT 1
    """)

    if topo_up['success'] and topo_up['rows']:
        data['upstream'] = topo_up['rows']
        if topo_host['success'] and topo_host['rows']:
            data['host'] = topo_host['rows'][0].get('host_name')
    else:
        # Fallback: expensive inline queries
        dependents_query = f"""
        SELECT DISTINCT
            service_name as dependent,
            'service' as dep_type,
            COUNT(*) as call_count,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 2) as error_pct
        FROM traces_otel_analytic
        WHERE db_system = '{db_system}'
          AND start_time > NOW() - INTERVAL {interval}
        GROUP BY service_name
        ORDER BY call_count DESC
        LIMIT 20
        """

        downstream_query = f"""
        SELECT DISTINCT
            COALESCE(NULLIF(child.db_system, ''), child.service_name) as dependency,
            CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END as dep_type,
            COUNT(*) as call_count
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE parent.db_system = '{db_system}'
          AND child.db_system IS NULL
          AND child.service_name IS NOT NULL
          AND parent.start_time > NOW() - INTERVAL {interval}
        GROUP BY COALESCE(NULLIF(child.db_system, ''), child.service_name),
                 CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END
        ORDER BY call_count DESC
        LIMIT 20
        """

        host_query = f"""
        SELECT DISTINCT
            REGEXP_EXTRACT(attributes_flat, 'host\\.name=([^,]+)', 1) as host_name
        FROM metrics_otel_analytic
        WHERE metric_name LIKE '{db_system}.%'
          AND timestamp > NOW() - INTERVAL {interval}
          AND attributes_flat LIKE '%host.name=%'
        LIMIT 1
        """

        result = executor.execute_query(dependents_query)
        if result['success']:
            data['upstream'] = result['rows']

        result = executor.execute_query(downstream_query)
        if result['success']:
            data['downstream'] = result['rows']

        result = executor.execute_query(host_query)
        if result['success'] and result['rows']:
            data['host'] = result['rows'][0].get('host_name')

    return jsonify(data)




@app.route('/api/host/<host_name>/services', methods=['GET'])
def host_services(host_name):
    """Get services/metrics running on this host."""
    executor = get_query_executor()
    time_param = request.args.get('time', '15m')

    # Parse time parameter
    time_value = int(time_param[:-1])
    time_unit = time_param[-1]
    if time_unit == 's':
        interval = f"'{time_value}' SECOND"
    elif time_unit == 'm':
        interval = f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        interval = f"'{time_value}' HOUR"
    else:
        interval = "'15' MINUTE"

    data = {'services': [], 'current_metrics': None, 'host_info': None}

    # Try topology tables first
    topo_svc = executor.execute_query(f"""
    SELECT service_name, data_point_count as span_count, 0.0 as error_pct
    FROM topology_host_services
    WHERE host_name = '{host_name}'
    ORDER BY data_point_count DESC
    """)
    topo_host = executor.execute_query(f"""
    SELECT os_type, cpu_pct, memory_pct, disk_pct, last_seen
    FROM topology_hosts
    WHERE host_name = '{host_name}'
    LIMIT 1
    """)

    if topo_svc['success'] and topo_svc['rows']:
        data['services'] = topo_svc['rows']
        if topo_host['success'] and topo_host['rows']:
            row = topo_host['rows'][0]
            data['host_info'] = {
                'last_seen': row.get('last_seen'),
                'os_type': row.get('os_type', 'unknown')
            }
    else:
        # Fallback: discover services from traces
        services_query = f"""
        SELECT
            service_name,
            COUNT(*) as span_count,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 1) as error_pct
        FROM traces_otel_analytic
        WHERE attributes_flat LIKE '%host.name={host_name}%'
          AND start_time > NOW() - INTERVAL {interval}
          AND service_name IS NOT NULL AND service_name != '' AND service_name != 'unknown'
        GROUP BY service_name
        ORDER BY span_count DESC
        """

        result = executor.execute_query(services_query)
        if result['success']:
            data['services'] = result['rows']

        # Fallback: discover services from metrics if no trace-based services found
        if not data['services']:
            metrics_services_query = f"""
            SELECT
                SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1) as service_name,
                COUNT(*) as span_count,
                0.0 as error_pct
            FROM metrics_otel_analytic
            WHERE attributes_flat LIKE '%host.name={host_name}%'
              AND timestamp > NOW() - INTERVAL {interval}
              AND (metric_name LIKE 'postgresql.%'
                OR metric_name LIKE 'redis.%'
                OR metric_name LIKE 'nginx.%'
                OR metric_name LIKE 'kafka.%'
                OR metric_name LIKE 'docker.%')
            GROUP BY SUBSTR(metric_name, 1, POSITION('.' IN metric_name) - 1)
            ORDER BY span_count DESC
            """
            result = executor.execute_query(metrics_services_query)
            if result['success']:
                data['services'] = result['rows']

        # Get current host metrics
        host_metrics_query = f"""
        SELECT
            MAX(CASE WHEN metric_name = 'system.cpu.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as cpu_pct,
            MAX(CASE WHEN metric_name = 'system.memory.utilization' AND attributes_flat LIKE '%state=used%' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as memory_pct,
            MAX(CASE WHEN metric_name = 'system.filesystem.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as disk_pct,
            MAX(timestamp) as last_seen
        FROM metrics_otel_analytic
        WHERE attributes_flat LIKE '%host.name={host_name}%'
          AND metric_name IN ('system.cpu.utilization', 'system.memory.utilization', 'system.filesystem.utilization')
          AND timestamp > NOW() - INTERVAL '5' MINUTE
        """

        result = executor.execute_query(host_metrics_query)
        if result['success'] and result['rows']:
            row = result['rows'][0]
            data['current_metrics'] = {
                'cpu_pct': row.get('cpu_pct'),
                'memory_pct': row.get('memory_pct'),
                'disk_pct': row.get('disk_pct')
            }
            data['host_info'] = {
                'last_seen': row.get('last_seen')
            }

        # Get OS type from metrics attributes
        os_query = f"""
        SELECT DISTINCT
            CASE
                WHEN attributes_flat LIKE '%os.type=linux%' THEN 'linux'
                WHEN attributes_flat LIKE '%os.type=windows%' THEN 'windows'
                WHEN attributes_flat LIKE '%os.type=darwin%' THEN 'darwin'
                ELSE 'unknown'
            END as os_type
        FROM metrics_otel_analytic
        WHERE attributes_flat LIKE '%host.name={host_name}%'
          AND timestamp > NOW() - INTERVAL '5' MINUTE
        LIMIT 1
        """

        result = executor.execute_query(os_query)
        if result['success'] and result['rows']:
            if data['host_info'] is None:
                data['host_info'] = {}
            data['host_info']['os_type'] = result['rows'][0].get('os_type', 'unknown')

    # Always fetch current metrics from live data (topology_hosts can be stale)
    live_metrics_query = f"""
    SELECT
        MAX(CASE WHEN metric_name = 'system.cpu.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as cpu_pct,
        MAX(CASE WHEN metric_name = 'system.memory.utilization' AND attributes_flat LIKE '%state=used%' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as memory_pct,
        MAX(CASE WHEN metric_name = 'system.filesystem.utilization' AND value_double <= 1 THEN ROUND(value_double * 100, 1) END) as disk_pct,
        MAX(timestamp) as last_seen
    FROM metrics_otel_analytic
    WHERE attributes_flat LIKE '%host.name={host_name}%'
      AND metric_name IN ('system.cpu.utilization', 'system.memory.utilization', 'system.filesystem.utilization')
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    """
    live_result = executor.execute_query(live_metrics_query)
    if live_result['success'] and live_result['rows']:
        row = live_result['rows'][0]
        if row.get('cpu_pct') is not None or row.get('memory_pct') is not None:
            data['current_metrics'] = {
                'cpu_pct': row.get('cpu_pct'),
                'memory_pct': row.get('memory_pct'),
                'disk_pct': row.get('disk_pct')
            }
            if data['host_info'] is None:
                data['host_info'] = {}
            data['host_info']['last_seen'] = row.get('last_seen')

    # Fetch resource attributes from attributes_flat
    res_attr_query = f"""
    SELECT attributes_flat
    FROM metrics_otel_analytic
    WHERE attributes_flat LIKE '%host.name={host_name}%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 1
    """
    result = executor.execute_query(res_attr_query)
    if result['success'] and result['rows'] and result['rows'][0].get('attributes_flat'):
        attrs_flat = result['rows'][0]['attributes_flat']
        resource_attrs = _parse_resource_attributes(attrs_flat, HOST_RESOURCE_ATTR_KEYS)
        if resource_attrs:
            if data['host_info'] is None:
                data['host_info'] = {}
            data['host_info']['resource_attributes'] = resource_attrs

    return jsonify(data)


def _parse_resource_attributes(attrs_flat, wanted_keys):
    """Parse an attributes_flat string into a dict of wanted resource attributes."""
    result = {}
    if not attrs_flat:
        return result
    for pair in attrs_flat.split(','):
        if '=' not in pair:
            continue
        key, _, value = pair.partition('=')
        key = key.strip()
        if key in wanted_keys:
            result[key] = value.strip()
    return result


HOST_RESOURCE_ATTR_KEYS = {
    'host.arch', 'os.type', 'os.description',
    'service.version', 'service.namespace',
    'telemetry.sdk.name', 'telemetry.sdk.version',
    'telemetry.sdk.language', 'process.runtime.name', 'process.runtime.version',
}

CONTAINER_RESOURCE_ATTR_KEYS = {
    'container.id', 'container.hostname', 'container.image.name',
    'container.image.tag', 'container.runtime', 'os.type', 'host.name',
    'service.name', 'service.namespace', 'service.version',
}


@app.route('/api/container/<container_name>/info', methods=['GET'])
def container_info(container_name):
    """Get resource attributes for a container."""
    executor = get_query_executor()
    query = f"""
    SELECT attributes_flat
    FROM metrics_otel_analytic
    WHERE attributes_flat LIKE '%container.name={container_name}%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 1
    """
    result = executor.execute_query(query)
    resource_attributes = {}
    if result['success'] and result['rows'] and result['rows'][0].get('attributes_flat'):
        resource_attributes = _parse_resource_attributes(
            result['rows'][0]['attributes_flat'], CONTAINER_RESOURCE_ATTR_KEYS
        )
    return jsonify({'resource_attributes': resource_attributes})


# --- Relationship resolution strategies keyed by (source_type, target_type) ---
# Each returns a list of entity names given (executor, source_name).
_RELATED_RESOLVERS = {}


def _related(source_type, target_type):
    """Decorator to register a related-entity resolver."""
    def decorator(fn):
        _RELATED_RESOLVERS[(source_type, target_type)] = fn
        return fn
    return decorator


def _attrs_from_metrics(executor, like_filter, wanted_keys, limit=1, require=None):
    """Helper: fetch attributes_flat rows matching a LIKE filter and parse wanted keys.

    Args:
        require: Optional dict of {key: value} that must exactly match in the parsed
                 attributes (Python-side verification since DB LIKE can return false positives).
    """
    all_keys = set(wanted_keys)
    if require:
        all_keys.update(require.keys())
    r = executor.execute_query(f"""
    SELECT attributes_flat FROM metrics_otel_analytic
    WHERE {like_filter}
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT {limit}
    """)
    results = []
    for row in (r['rows'] if r['success'] else []):
        attrs = _parse_resource_attributes(row.get('attributes_flat', ''), all_keys)
        if require and not all(attrs.get(k) == v for k, v in require.items()):
            continue
        # Only return the wanted_keys subset
        filtered = {k: attrs[k] for k in wanted_keys if k in attrs}
        if filtered:
            results.append(filtered)
    return results


def _container_id_name_map(executor):
    """Build container.id → container.name mapping from container metrics.

    LIKE on long hex container IDs is unreliable due to predicate pushdown,
    so we scan all containers (typically <50) and match in Python.
    """
    r = executor.execute_query("""
    SELECT DISTINCT attributes_flat FROM metrics_otel_analytic
    WHERE metric_name = 'container.cpu.utilization'
      AND attributes_flat LIKE '%container.name=%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 200
    """)
    mapping = {}
    for row in (r['rows'] if r['success'] else []):
        attrs = _parse_resource_attributes(
            row.get('attributes_flat', ''), {'container.name', 'container.id'})
        cid = attrs.get('container.id')
        cname = attrs.get('container.name')
        if cid and cname:
            mapping[cid] = cname
    return mapping


def _service_id_map(executor):
    """Build container.id → service.name mapping from service metrics.

    Scans distinct service metric rows to map container.id to service.name.
    LIKE may return false positives; we verify in Python with exact key parsing.
    """
    r = executor.execute_query("""
    SELECT DISTINCT attributes_flat FROM metrics_otel_analytic
    WHERE metric_name NOT LIKE 'container.%'
      AND attributes_flat LIKE '%,service.name=%'
      AND attributes_flat LIKE '%container.id=%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 5000
    """)
    mapping = {}
    for row in (r['rows'] if r['success'] else []):
        attrs = _parse_resource_attributes(
            row.get('attributes_flat', ''), {'service.name', 'container.id'})
        cid = attrs.get('container.id')
        sname = attrs.get('service.name')
        if cid and sname:
            mapping[cid] = sname
    return mapping


@_related('service', 'host')
def _service_hosts(executor, name):
    # Try topology table first, fall back to metrics
    r = executor.execute_query(f"""
    SELECT DISTINCT host_name FROM topology_host_services
    WHERE service_name = '{name}' ORDER BY host_name
    """)
    hosts = [row['host_name'] for row in (r['rows'] if r['success'] else [])]
    if hosts:
        return hosts
    rows = _attrs_from_metrics(executor,
        f"attributes_flat LIKE '%service.name={name}%'", {'host.name'},
        require={'service.name': name})
    return list({a['host.name'] for a in rows if a.get('host.name')})


@_related('service', 'container')
def _service_containers(executor, name):
    # Get container.id from service metrics, then resolve to name via scan
    rows = _attrs_from_metrics(executor,
        f"attributes_flat LIKE '%service.name={name}%'", {'container.id'},
        require={'service.name': name})
    cids = {a['container.id'] for a in rows if a.get('container.id')}
    if not cids:
        return []
    cid_to_name = _container_id_name_map(executor)
    return sorted({cid_to_name[cid] for cid in cids if cid in cid_to_name})


@_related('container', 'host')
def _container_hosts(executor, name):
    rows = _attrs_from_metrics(executor,
        f"attributes_flat LIKE '%container.name={name}%'", {'host.name'},
        require={'container.name': name})
    return list({a['host.name'] for a in rows if a.get('host.name')})


@_related('container', 'service')
def _container_services(executor, name):
    # Get container.id from container metrics, then resolve to service via scan
    rows = _attrs_from_metrics(executor,
        f"attributes_flat LIKE '%container.name={name}%'", {'container.id'},
        require={'container.name': name})
    cids = {a['container.id'] for a in rows if a.get('container.id')}
    if not cids:
        return []
    cid_to_svc = _service_id_map(executor)
    return sorted({cid_to_svc[cid] for cid in cids if cid in cid_to_svc})


@_related('host', 'service')
def _host_services_related(executor, name):
    r = executor.execute_query(f"""
    SELECT DISTINCT service_name FROM topology_host_services
    WHERE host_name = '{name}' ORDER BY service_name
    """)
    topo = [row['service_name'] for row in (r['rows'] if r['success'] else [])]
    # Also discover app services from metrics on this host
    mr = executor.execute_query(f"""
    SELECT DISTINCT attributes_flat FROM metrics_otel_analytic
    WHERE attributes_flat LIKE '%host.name={name}%'
      AND attributes_flat LIKE '%service.name=%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 2000
    """)
    svc_set = set(topo)
    for row in (mr['rows'] if mr['success'] else []):
        attrs = _parse_resource_attributes(row.get('attributes_flat', ''),
                                           {'service.name', 'host.name'})
        if attrs.get('host.name') == name and attrs.get('service.name'):
            svc_set.add(attrs['service.name'])
    return sorted(svc_set)


@_related('host', 'container')
def _host_containers(executor, name):
    r = executor.execute_query(f"""
    SELECT DISTINCT attributes_flat FROM metrics_otel_analytic
    WHERE attributes_flat LIKE '%host.name={name}%'
      AND attributes_flat LIKE '%container.name=%'
      AND timestamp > NOW() - INTERVAL '5' MINUTE
    LIMIT 2000
    """)
    containers = set()
    for row in (r['rows'] if r['success'] else []):
        attrs = _parse_resource_attributes(row.get('attributes_flat', ''),
                                           {'container.name', 'host.name'})
        if attrs.get('host.name') == name and attrs.get('container.name'):
            containers.add(attrs['container.name'])
    return sorted(containers)


@_related('database', 'host')
def _database_hosts(executor, name):
    r = executor.execute_query(f"""
    SELECT host_name FROM topology_database_hosts
    WHERE db_system = '{name}' LIMIT 1
    """)
    return [row['host_name'] for row in (r['rows'] if r['success'] else []) if row.get('host_name')]


@app.route('/api/entity/<entity_type>/<name>/related', methods=['GET'])
def entity_related(entity_type, name):
    """Get related entities for cross-navigation. Data-driven via _RELATED_RESOLVERS."""
    executor = get_query_executor()
    related = {}
    for (src, tgt), resolver in _RELATED_RESOLVERS.items():
        if src == entity_type:
            try:
                values = resolver(executor, name)
                if values:
                    related[tgt] = values
            except Exception as e:
                app.logger.warning(f"Related resolver {src}->{tgt} failed for {name}: {e}")
    return jsonify(related)


@app.route('/api/host/<host_name>/resource-history', methods=['GET'])
def host_resource_history(host_name):
    """Get 1-minute bucketed CPU, memory, disk utilization."""
    executor = get_query_executor()
    tr = parse_time_range(request, default_preset='1h')
    time_cond = time_filter_sql(tr, 'timestamp')

    query = f"""
    SELECT date_trunc('minute', timestamp) as time_bucket,
        MAX(CASE WHEN metric_name='system.cpu.utilization' AND value_double<=1
            THEN ROUND(value_double*100,1) END) as cpu_pct,
        MAX(CASE WHEN metric_name='system.memory.utilization'
            AND attributes_flat LIKE '%state=used%' AND value_double<=1
            THEN ROUND(value_double*100,1) END) as memory_pct,
        MAX(CASE WHEN metric_name='system.filesystem.utilization' AND value_double<=1
            THEN ROUND(value_double*100,1) END) as disk_pct
    FROM metrics_otel_analytic
    WHERE metric_name IN ('system.cpu.utilization','system.memory.utilization','system.filesystem.utilization')
      AND {time_cond}
      AND attributes_flat LIKE '%host.name={host_name}%'
    GROUP BY date_trunc('minute', timestamp)
    ORDER BY time_bucket
    """

    result = executor.execute_query(query)
    rows = []
    if result['success'] and result['rows']:
        for row in result['rows']:
            rows.append({
                'time_bucket': str(row.get('time_bucket', '')),
                'cpu_pct': row.get('cpu_pct'),
                'memory_pct': row.get('memory_pct'),
                'disk_pct': row.get('disk_pct')
            })

    return jsonify({'history': rows})


@app.route('/api/container/<container_name>/resource-history', methods=['GET'])
def container_resource_history(container_name):
    """Get 1-minute bucketed CPU, memory utilization for a container."""
    executor = get_query_executor()
    tr = parse_time_range(request, default_preset='1h')
    time_cond = time_filter_sql(tr, 'timestamp')

    query = f"""
    SELECT date_trunc('minute', timestamp) as time_bucket,
        MAX(CASE WHEN metric_name='container.cpu.percent' THEN ROUND(value_double,1) END) as cpu_pct,
        MAX(CASE WHEN metric_name='container.memory.percent' THEN ROUND(value_double,1) END) as memory_pct,
        MAX(CASE WHEN metric_name='container.memory.usage.total' THEN ROUND(value_double/1048576.0,1) END) as memory_mb
    FROM metrics_otel_analytic
    WHERE metric_name IN ('container.cpu.percent','container.memory.percent','container.memory.usage.total')
      AND {time_cond}
      AND attributes_flat LIKE '%container.name={container_name}%'
    GROUP BY date_trunc('minute', timestamp)
    ORDER BY time_bucket
    """

    result = executor.execute_query(query)
    rows = []
    if result['success'] and result['rows']:
        for row in result['rows']:
            rows.append({
                'time_bucket': str(row.get('time_bucket', '')),
                'cpu_pct': row.get('cpu_pct'),
                'memory_pct': row.get('memory_pct'),
                'memory_mb': row.get('memory_mb'),
            })

    return jsonify({'history': rows})


# =============================================================================
# Topology API
# =============================================================================

@app.route('/api/topology/<entity_name>', methods=['GET'])
def topology_graph(entity_name):
    """Get N-level dependency graph centered on an entity (service or database).
    Uses live trace data (parent-child span joins) for reliable edge discovery,
    with topology tables as metadata supplement.
    """
    executor = get_query_executor()
    depth = min(int(request.args.get('depth', '2')), 5)

    visited_edges = set()
    visited_nodes = {entity_name}
    frontier = {entity_name}
    nodes = {}
    edges = []
    is_host = False

    # Determine entity type from topology tables
    svc_result = executor.execute_query(f"""
    SELECT service_name, service_type, span_count, error_pct, avg_latency_ms
    FROM topology_services
    WHERE service_name = '{entity_name}'
    LIMIT 1
    """)
    if svc_result['success'] and svc_result['rows']:
        row = svc_result['rows'][0]
        nodes[entity_name] = {
            'id': entity_name, 'label': entity_name,
            'type': row.get('service_type', 'application'),
            'error_pct': row.get('error_pct', 0),
            'span_count': row.get('span_count', 0),
            'avg_latency_ms': row.get('avg_latency_ms', 0),
            'root': True
        }

    # Check if it's a host
    host_result = executor.execute_query(f"""
    SELECT host_name, os_type, cpu_pct, memory_pct, disk_pct
    FROM topology_hosts
    WHERE host_name = '{entity_name}'
    LIMIT 1
    """)
    if host_result['success'] and host_result['rows']:
        is_host = True
        row = host_result['rows'][0]
        nodes[entity_name] = {
            'id': entity_name, 'label': entity_name, 'type': 'host',
            'os_type': row.get('os_type'),
            'cpu_pct': row.get('cpu_pct'),
            'memory_pct': row.get('memory_pct'),
            'root': True
        }
        # Seed frontier with services on this host (from topology or live spans)
        host_svc = executor.execute_query(f"""
        SELECT service_name, data_point_count
        FROM topology_host_services
        WHERE host_name = '{entity_name}'
        """)
        if host_svc['success'] and host_svc['rows']:
            for r in host_svc['rows']:
                svc = r['service_name']
                if svc not in visited_nodes:
                    visited_nodes.add(svc)
                    frontier.add(svc)
                ek = (entity_name, svc, 'hosts')
                if ek not in visited_edges:
                    visited_edges.add(ek)
                    edges.append({'from': entity_name, 'to': svc, 'label': 'hosts', 'call_count': r.get('data_point_count', 0)})
        else:
            # Fallback: discover services from spans
            live_svc = executor.execute_query(f"""
            SELECT DISTINCT service_name, COUNT(*) as cnt
            FROM traces_otel_analytic
            WHERE attributes_flat LIKE '%host.name={entity_name}%'
              AND start_time > NOW() - INTERVAL '1' HOUR
              AND service_name IS NOT NULL AND service_name != ''
            GROUP BY service_name
            """)
            if live_svc['success']:
                for r in live_svc['rows']:
                    svc = r['service_name']
                    if svc not in visited_nodes:
                        visited_nodes.add(svc)
                        frontier.add(svc)
                    ek = (entity_name, svc, 'hosts')
                    if ek not in visited_edges:
                        visited_edges.add(ek)
                        edges.append({'from': entity_name, 'to': svc, 'label': 'hosts', 'call_count': r.get('cnt', 0)})
        # Database hosts
        db_host = executor.execute_query(f"""
        SELECT db_system FROM topology_database_hosts WHERE host_name = '{entity_name}'
        """)
        if db_host['success']:
            for r in db_host['rows']:
                db = r['db_system']
                if db not in visited_nodes:
                    visited_nodes.add(db)
                    frontier.add(db)
                ek = (entity_name, db, 'hosts')
                if ek not in visited_edges:
                    visited_edges.add(ek)
                    edges.append({'from': entity_name, 'to': db, 'label': 'hosts', 'call_count': 0})

    # Default node if nothing found yet
    if entity_name not in nodes:
        nodes[entity_name] = {'id': entity_name, 'label': entity_name, 'type': 'application', 'root': True}

    def get_edges_for_services(service_list):
        """Get downstream edges from live trace data using parent-child span join."""
        svc_in = "', '".join(service_list)
        result = executor.execute_query(f"""
        SELECT
            parent.service_name as source_service,
            COALESCE(NULLIF(child.db_system, ''), child.service_name) as target_service,
            CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END as dependency_type,
            COUNT(*) as call_count,
            ROUND(AVG(child.duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 1) as error_pct
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child
            ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE parent.service_name IN ('{svc_in}')
          AND (child.service_name != parent.service_name OR (child.db_system IS NOT NULL AND child.db_system != ''))
          AND parent.start_time > NOW() - INTERVAL '1' HOUR
        GROUP BY parent.service_name,
                 COALESCE(NULLIF(child.db_system, ''), child.service_name),
                 CASE WHEN child.db_system IS NOT NULL AND child.db_system != '' THEN 'database' ELSE 'service' END
        ORDER BY call_count DESC
        """)
        return result

    def get_upstream_for_services(service_list):
        """Get upstream edges from live trace data."""
        svc_in = "', '".join(service_list)
        result = executor.execute_query(f"""
        SELECT
            parent.service_name as source_service,
            child.service_name as target_service,
            'service' as dependency_type,
            COUNT(*) as call_count,
            ROUND(AVG(child.duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN child.status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 1) as error_pct
        FROM traces_otel_analytic parent
        JOIN traces_otel_analytic child
            ON parent.span_id = child.parent_span_id
            AND parent.trace_id = child.trace_id
        WHERE child.service_name IN ('{svc_in}')
          AND parent.service_name != child.service_name
          AND child.start_time > NOW() - INTERVAL '1' HOUR
        GROUP BY parent.service_name, child.service_name
        ORDER BY call_count DESC
        """)
        return result

    # Also handle database entities: find services that call this db_system
    def get_upstream_for_databases(db_list):
        """Get services that call these databases."""
        db_in = "', '".join(db_list)
        result = executor.execute_query(f"""
        SELECT
            service_name as source_service,
            db_system as target_service,
            'database' as dependency_type,
            COUNT(*) as call_count,
            ROUND(AVG(duration_ns / 1000000.0), 2) as avg_latency_ms,
            ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / COUNT(*), 1) as error_pct
        FROM traces_otel_analytic
        WHERE db_system IN ('{db_in}')
          AND start_time > NOW() - INTERVAL '1' HOUR
        GROUP BY service_name, db_system
        ORDER BY call_count DESC
        """)
        return result

    def process_edges(result, frontier_set):
        """Process query result into edges and return new nodes to explore."""
        new_nodes = set()
        if not result['success']:
            return new_nodes
        for row in result['rows']:
            src = row['source_service']
            tgt = row['target_service']
            if not src or not tgt:
                continue
            dep_type = row.get('dependency_type', 'service')
            ek = (src, tgt, dep_type)
            if ek not in visited_edges:
                visited_edges.add(ek)
                cc = row.get('call_count', 0)
                edges.append({
                    'from': src, 'to': tgt,
                    'label': f"{cc} calls",
                    'call_count': cc,
                    'avg_latency_ms': row.get('avg_latency_ms'),
                    'error_pct': row.get('error_pct')
                })
            # Track database type for targets
            if dep_type == 'database' and tgt not in nodes:
                nodes[tgt] = {'id': tgt, 'label': tgt, 'type': 'database'}
            for name in (src, tgt):
                if name not in visited_nodes:
                    visited_nodes.add(name)
                    new_nodes.add(name)
        return new_nodes

    for level in range(depth):
        if not frontier:
            break
        next_frontier = set()

        # Separate services from databases in frontier
        service_frontier = []
        db_frontier = []
        for name in frontier:
            node = nodes.get(name, {})
            if node.get('type') == 'database':
                db_frontier.append(name)
            elif node.get('type') != 'host':
                service_frontier.append(name)

        # Get downstream edges (services calling other services/databases)
        if service_frontier:
            result = get_edges_for_services(service_frontier)
            next_frontier |= process_edges(result, frontier)

            # Get upstream edges (who calls these services)
            result = get_upstream_for_services(service_frontier)
            next_frontier |= process_edges(result, frontier)

        # Get upstream edges for databases (who calls these databases)
        if db_frontier:
            result = get_upstream_for_databases(db_frontier)
            next_frontier |= process_edges(result, frontier)

        frontier = next_frontier

    # Fetch node metadata for discovered nodes
    missing = [n for n in visited_nodes if n not in nodes]
    if missing:
        missing_list = "', '".join(missing)
        svc_result = executor.execute_query(f"""
        SELECT service_name, service_type, span_count, error_pct, avg_latency_ms
        FROM topology_services
        WHERE service_name IN ('{missing_list}')
        """)
        if svc_result['success']:
            for row in svc_result['rows']:
                name = row['service_name']
                nodes[name] = {
                    'id': name, 'label': name,
                    'type': row.get('service_type', 'application'),
                    'error_pct': row.get('error_pct', 0),
                    'span_count': row.get('span_count', 0),
                    'avg_latency_ms': row.get('avg_latency_ms', 0)
                }
        for name in missing:
            if name not in nodes:
                nodes[name] = {'id': name, 'label': name, 'type': 'application'}

    return jsonify({
        'nodes': list(nodes.values()),
        'edges': edges,
        'root': entity_name,
        'depth': depth
    })


# =============================================================================
# Generic Entity API
# =============================================================================

@app.route('/api/entity/<entity_type>/<name>', methods=['GET'])
def entity_details(entity_type, name):
    """Get detailed metrics for any entity type."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    config = ENTITY_TYPES[entity_type]
    executor = get_query_executor()
    time_range = request.args.get('range', '1')

    if entity_type == 'service':
        return service_details(name)
    elif entity_type == 'database':
        return database_details(name)
    elif entity_type == 'host':
        return host_services(name)
    return jsonify({'error': 'Not implemented'}), 501


@app.route('/api/entity/<entity_type>/<name>/traces', methods=['GET'])
def entity_traces(entity_type, name):
    """Get traces for any entity type."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    config = ENTITY_TYPES[entity_type]
    executor = get_query_executor()
    limit = min(int(request.args.get('limit', '50')), 1000)
    tr = parse_time_range(request)
    interval = tr['interval'] if tr['mode'] == 'relative' else "'1' HOUR"
    extra_where = build_trace_filters(request)

    traces_filter = config['traces_filter'].format(name=name, interval=interval)
    table = config['traces_table']
    time_field = config['traces_time_field']
    time_cond = time_filter_sql(tr, time_field)

    # For service, we don't need service_name in SELECT since it's the filter
    if entity_type == 'service':
        traces_query = f"""
        SELECT trace_id, span_id, span_name, span_kind, status_code,
               ROUND(duration_ns / 1000000.0, 2) as duration_ms,
               start_time, db_system
        FROM {table}
        WHERE {traces_filter}
          AND {time_cond}
          {extra_where}
        ORDER BY {time_field} DESC
        LIMIT {limit}
        """
    else:
        traces_query = f"""
        SELECT trace_id, span_id, service_name, span_name, span_kind, status_code,
               ROUND(duration_ns / 1000000.0, 2) as duration_ms,
               {time_field} as start_time
        FROM {table}
        WHERE {traces_filter}
          AND {time_cond}
          {extra_where}
        ORDER BY {time_field} DESC
        LIMIT {limit}
        """

    result = executor.execute_query(traces_query)
    if result['success']:
        return jsonify({'traces': result['rows']})
    return jsonify({'traces': [], 'error': result.get('error')})


@app.route('/api/entity/<entity_type>/<name>/logs', methods=['GET'])
def entity_logs(entity_type, name):
    """Get logs for any entity type."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    config = ENTITY_TYPES[entity_type]
    executor = get_query_executor()
    limit = min(int(request.args.get('limit', '50')), 1000)
    tr = parse_time_range(request)
    interval = tr['interval'] if tr['mode'] == 'relative' else "'1' HOUR"

    if config['logs_filter']:
        # Direct filter (service)
        extra_where = build_log_filters(request)
        logs_filter = config['logs_filter'].format(name=name, interval=interval)
        time_cond = time_filter_sql(tr, 'timestamp')
        logs_query = f"""
        SELECT timestamp, severity_text, body, trace_id, span_id
        FROM logs_otel_analytic
        WHERE {logs_filter}
          AND {time_cond}
          {extra_where}
        ORDER BY timestamp DESC
        LIMIT {limit}
        """
    elif config['logs_join']:
        # Subquery join (database, host)
        extra_where = build_log_filters(request, 'l')
        join_filter = config['logs_join'].format(name=name, interval=interval)
        time_cond = time_filter_sql(tr, 'l.timestamp')
        logs_query = f"""
        SELECT l.timestamp, l.service_name, l.severity_text, l.body, l.trace_id, l.span_id
        FROM logs_otel_analytic l
        WHERE {join_filter}
          AND {time_cond}
          {extra_where}
        ORDER BY l.timestamp DESC
        LIMIT {limit}
        """
    else:
        return jsonify({'logs': []})

    result = executor.execute_query(logs_query)
    if result['success']:
        return jsonify({'logs': result['rows']})
    return jsonify({'logs': [], 'error': result.get('error')})


@app.route('/api/entity/<entity_type>/<name>/metrics', methods=['GET'])
def entity_metrics(entity_type, name):
    """Get metrics for any entity type."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    config = ENTITY_TYPES[entity_type]
    executor = get_query_executor()
    limit = min(int(request.args.get('limit', '50')), 1000)
    tr = parse_time_range(request)
    interval = tr['interval'] if tr['mode'] == 'relative' else "'1' HOUR"

    extra_where = ''
    search_filter = request.args.get('search', '')
    if search_filter:
        extra_where += f" AND LOWER(metric_name) LIKE LOWER('%{search_filter}%')"

    metrics_filter = config['metrics_filter'].format(name=name, interval=interval)
    time_cond = time_filter_sql(tr, 'timestamp')

    metrics_query = f"""
    SELECT metric_name,
           COUNT(*) as data_points,
           ROUND(AVG(value_double), 4) as avg_value,
           ROUND(MIN(value_double), 4) as min_value,
           ROUND(MAX(value_double), 4) as max_value,
           MAX(timestamp) as last_seen
    FROM metrics_otel_analytic
    WHERE {metrics_filter}
      AND {time_cond}
      {extra_where}
    GROUP BY metric_name
    ORDER BY data_points DESC
    LIMIT {limit}
    """

    result = executor.execute_query(metrics_query)
    if result['success']:
        return jsonify({'metrics': result['rows']})
    return jsonify({'metrics': [], 'error': result.get('error')})


# Attribute keys that are always noise in per-entity chart legends
def _deduplicate_series_labels(series_list):
    """Remove key=value pairs that are identical across all series labels."""
    if len(series_list) <= 1:
        return
    # Parse each label into a set of key=value parts
    parsed = []
    for s in series_list:
        parts = {p.strip() for p in s['label'].split(',') if p.strip()}
        parsed.append(parts)
    # Find parts common to every series
    common = parsed[0].copy()
    for p in parsed[1:]:
        common &= p
    if not common:
        return
    # Rebuild labels without common parts
    for i, s in enumerate(series_list):
        unique = [p for p in s['label'].split(',') if p.strip() and p.strip() not in common]
        s['label'] = ', '.join(p.strip() for p in unique) if unique else s['label']


_NOISE_ATTR_PREFIXES = (
    'host.name=', 'os.type=', 'service.namespace=', 'service.version=',
    'service.name=', 'telemetry.sdk.', 'container.name=', 'container.id=',
    'process.pid=', 'process.executable.', 'net.host.',
)


def _simplify_attrs_label(attrs_flat, entity_type, entity_name):
    """Build a concise chart legend label from attributes_flat.

    Strips noisy / redundant attributes so legend labels only show the
    dimensions that actually differentiate the series.
    """
    if not attrs_flat:
        return ''
    parts = [p.strip() for p in attrs_flat.split(',') if p.strip()]
    parts = [p for p in parts if not any(p.startswith(n) for n in _NOISE_ATTR_PREFIXES)]
    # Shorten remaining keys: drop common prefixes like "postgresql."
    shortened = []
    for p in parts:
        key, _, val = p.partition('=')
        # e.g. "postgresql.table.name=foo" -> "table.name=foo"
        segments = key.split('.')
        if len(segments) > 2:
            key = '.'.join(segments[-2:])
        shortened.append(f'{key}={val}')
    return ', '.join(shortened)


@app.route('/api/entity/<entity_type>/<name>/metric-history', methods=['GET'])
def entity_metric_history(entity_type, name):
    """Return 1-minute-bucketed time series for a single metric inside an entity."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    metric = request.args.get('metric')
    if not metric:
        return jsonify({'error': 'metric parameter required'}), 400

    config = ENTITY_TYPES[entity_type]
    executor = get_query_executor()
    tr = parse_time_range(request)
    interval = tr['interval'] if tr['mode'] == 'relative' else "'1' HOUR"
    metrics_filter = config['metrics_filter'].format(name=name, interval=interval)
    time_cond = time_filter_sql(tr, 'timestamp')

    # First, find top 10 attribute combos by data-point count
    top_attrs_query = f"""
    SELECT attributes_flat, COUNT(*) AS cnt
    FROM metrics_otel_analytic
    WHERE {metrics_filter}
      AND metric_name = '{metric}'
      AND {time_cond}
    GROUP BY attributes_flat
    ORDER BY cnt DESC
    LIMIT 10
    """
    top_result = executor.execute_query(top_attrs_query)
    if not top_result['success'] or not top_result['rows']:
        return jsonify({'series': [], 'metric_name': metric})

    attr_values = [row['attributes_flat'] for row in top_result['rows']]
    # Build IN clause — use empty string for NULL/empty
    in_list = ', '.join(f"'{v.replace(chr(39), chr(39)+chr(39))}'" for v in attr_values)

    query = f"""
    SELECT date_trunc('minute', timestamp) AS bucket,
           attributes_flat,
           ROUND(AVG(value_double), 6) AS avg_value
    FROM metrics_otel_analytic
    WHERE {metrics_filter}
      AND metric_name = '{metric}'
      AND {time_cond}
      AND attributes_flat IN ({in_list})
    GROUP BY date_trunc('minute', timestamp), attributes_flat
    ORDER BY bucket
    """

    result = executor.execute_query(query)
    if not result['success']:
        return jsonify({'series': [], 'error': result.get('error')})

    # Group rows by attributes_flat into separate series
    series_map = {}
    for row in result['rows']:
        key = row.get('attributes_flat', '')
        if key not in series_map:
            label = _simplify_attrs_label(key, entity_type, name)
            series_map[key] = {'label': label or metric, 'data': []}
        series_map[key]['data'].append({
            'time': row['bucket'],
            'value': row['avg_value'],
        })

    series_list = list(series_map.values())
    _deduplicate_series_labels(series_list)
    return jsonify({
        'series': series_list,
        'metric_name': metric,
    })


@app.route('/api/entity/<entity_type>/<name>/pinned-charts', methods=['GET'])
def get_pinned_charts(entity_type, name):
    """Return pinned charts for an entity."""
    executor = get_query_executor()
    sql = f"""
    SELECT pin_id, metric_name, display_name, created_at
    FROM pinned_charts
    WHERE entity_type = '{entity_type}'
      AND entity_name = '{name}'
    ORDER BY created_at
    """
    result = executor.execute_query(sql)
    if not result['success']:
        return jsonify({'pins': [], 'error': result.get('error')}), 500
    return jsonify({'pins': result.get('rows', [])})


@app.route('/api/entity/<entity_type>/<name>/pinned-charts', methods=['POST'])
def create_pinned_chart(entity_type, name):
    """Pin a metric chart to an entity's Charts tab."""
    import uuid
    body = request.get_json(force=True)
    metric_name = body.get('metric_name', '')
    if not metric_name:
        return jsonify({'error': 'metric_name required'}), 400

    executor = get_query_executor()

    # Dedup check
    check_sql = f"""
    SELECT pin_id FROM pinned_charts
    WHERE entity_type = '{entity_type}'
      AND entity_name = '{name}'
      AND metric_name = '{metric_name}'
    LIMIT 1
    """
    check = executor.execute_query(check_sql)
    if check['success'] and check.get('rows'):
        return jsonify({'pin_id': check['rows'][0]['pin_id'], 'already_existed': True})

    pin_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    display_name = metric_name

    insert_sql = f"""
    INSERT INTO pinned_charts (pin_id, entity_type, entity_name, metric_name, display_name, created_at)
    VALUES ('{pin_id}', '{entity_type}', '{name}', '{metric_name}', '{display_name}', TIMESTAMP '{now}')
    """
    try:
        cursor = executor.conn.cursor()
        cursor.execute(insert_sql)
        return jsonify({'pin_id': pin_id, 'already_existed': False})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/entity/<entity_type>/<name>/pinned-charts/<pin_id>', methods=['DELETE'])
def delete_pinned_chart(entity_type, name, pin_id):
    """Unpin a chart from an entity."""
    executor = get_query_executor()
    sql = f"""
    DELETE FROM pinned_charts
    WHERE pin_id = '{pin_id}'
      AND entity_type = '{entity_type}'
      AND entity_name = '{name}'
    """
    try:
        cursor = executor.conn.cursor()
        cursor.execute(sql)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/entity/<entity_type>/<name>/dependencies', methods=['GET'])
def entity_dependencies(entity_type, name):
    """Get dependencies for any entity type."""
    if entity_type not in ENTITY_TYPES:
        return jsonify({'error': f'Unknown entity type: {entity_type}'}), 400

    if entity_type == 'service':
        return service_dependencies(name)
    elif entity_type == 'database':
        return database_dependencies(name)
    elif entity_type == 'host':
        return host_services(name)
    return jsonify({'error': 'Not implemented'}), 501


# Legacy aliases - keep old routes working
@app.route('/api/service/<name>/traces')
def service_traces_legacy(name):
    return entity_traces('service', name)

@app.route('/api/service/<name>/logs')
def service_logs_legacy(name):
    return entity_logs('service', name)

@app.route('/api/service/<name>/metrics')
def service_metrics_legacy(name):
    return entity_metrics('service', name)

@app.route('/api/database/<name>/traces')
def database_traces_legacy(name):
    return entity_traces('database', name)

@app.route('/api/database/<name>/logs')
def database_logs_legacy(name):
    return entity_logs('database', name)

@app.route('/api/database/<name>/metrics')
def database_metrics_legacy(name):
    return entity_metrics('database', name)

@app.route('/api/host/<name>/traces')
def host_traces_legacy(name):
    return entity_traces('host', name)

@app.route('/api/host/<name>/logs')
def host_logs_legacy(name):
    return entity_logs('host', name)

@app.route('/api/host/<name>/metrics')
def host_metrics_legacy(name):
    return entity_metrics('host', name)


# =============================================================================
# Trace Viewer API
# =============================================================================

@app.route('/api/trace/<trace_id>', methods=['GET'])
def trace_detail(trace_id):
    """Get all spans and events for a trace, for the waterfall viewer."""
    executor = get_query_executor()
    safe_tid = trace_id.replace("'", "''")

    spans_query = f"""
    SELECT span_id, parent_span_id, service_name, span_name, span_kind,
           start_time, duration_ns, status_code,
           attributes_json
    FROM traces_otel_analytic
    WHERE trace_id = '{safe_tid}'
    ORDER BY start_time
    """
    result = executor.execute_query(spans_query)
    spans = result['rows'] if result['success'] else []

    # Collect span events (exceptions, logs)
    events_map = {}
    if spans:
        events_query = f"""
        SELECT span_id, event_name, timestamp,
               exception_type, exception_message, exception_stacktrace
        FROM span_events_otel_analytic
        WHERE trace_id = '{safe_tid}'
        ORDER BY timestamp
        """
        ev_result = executor.execute_query(events_query)
        if ev_result['success']:
            for ev in ev_result['rows']:
                sid = ev.get('span_id', '')
                if sid not in events_map:
                    events_map[sid] = []
                events_map[sid].append(ev)

    # Compute summary
    services = list(set(s.get('service_name', '') for s in spans if s.get('service_name')))
    return jsonify({
        'trace_id': trace_id,
        'spans': spans,
        'events': events_map,
        'service_count': len(services),
        'total_spans': len(spans)
    })


@app.route('/api/traces/search', methods=['GET'])
def traces_search():
    """Search/list traces for the trace explorer sidebar."""
    executor = get_query_executor()
    service = request.args.get('service', '')
    lookback = request.args.get('time', '1h')
    limit = min(int(request.args.get('limit', '20')), 100)
    min_duration_ms = request.args.get('min_duration_ms', '')
    error_only = request.args.get('error_only', '') == '1'

    # Parse lookback
    lookback_map = {'5m': '5', '15m': '15', '1h': '60', '6h': '360', '24h': '1440'}
    minutes = lookback_map.get(lookback, '60')
    interval = f"'{minutes}' MINUTE"

    where_clauses = [f"start_time > NOW() - INTERVAL {interval}"]
    if service:
        safe_svc = service.replace("'", "''")
        where_clauses.append(f"service_name = '{safe_svc}'")
    if min_duration_ms:
        try:
            min_ns = int(min_duration_ms) * 1000000
            where_clauses.append(f"duration_ns >= {min_ns}")
        except ValueError:
            pass
    if error_only:
        where_clauses.append("status_code = 'ERROR'")

    where_sql = " AND ".join(where_clauses)

    query = f"""
    SELECT trace_id,
           MIN(start_time) as trace_start,
           MAX(CAST(duration_ns AS BIGINT)) as max_duration_ns,
           COUNT(*) as span_count,
           COUNT(DISTINCT service_name) as service_count,
           ARRAY_AGG(DISTINCT service_name) as services,
           MAX(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as has_error
    FROM traces_otel_analytic
    WHERE {where_sql}
    GROUP BY trace_id
    ORDER BY MIN(start_time) DESC
    LIMIT {limit}
    """
    result = executor.execute_query(query)
    traces = []
    if result['success']:
        for row in result['rows']:
            dur_ns = row.get('max_duration_ns', 0) or 0
            traces.append({
                'trace_id': row.get('trace_id', ''),
                'start_time': str(row.get('trace_start', '')),
                'duration_ms': round(dur_ns / 1000000.0, 2) if dur_ns else 0,
                'span_count': row.get('span_count', 0),
                'service_count': row.get('service_count', 0),
                'services': row.get('services', []),
                'has_error': bool(row.get('has_error', 0))
            })
    return jsonify({'traces': traces})


# =============================================================================
# Alerts API
# =============================================================================

@app.route('/api/alerts/config', methods=['GET'])
def get_alerts_config():
    """Get investigation configuration for display in UI."""
    return jsonify({
        'investigate_critical_only': INVESTIGATE_CRITICAL_ONLY
    })


@app.route('/api/alerts/thresholds', methods=['GET'])
def get_alert_thresholds():
    """Return current alert detection thresholds and configuration."""
    zscore = float(os.getenv("ANOMALY_THRESHOLD", "3.0"))
    multiplier_str = os.getenv("ROOT_CAUSE_THRESHOLDS", "db_error:0.8,dependency_error:0.9")
    multipliers = {}
    for pair in multiplier_str.split(","):
        if ":" in pair:
            k, v = pair.strip().split(":", 1)
            try:
                multipliers[k.strip()] = float(v.strip())
            except ValueError:
                pass

    service_name = request.args.get('service', '').strip()

    # Load overrides from DB
    learned_map = {}  # category -> delta
    manual_map = {}   # (service, category) -> value
    executor = get_query_executor()
    if executor:
        try:
            result = executor.execute_query(
                "SELECT service_name, metric_category, override_type, threshold_value "
                "FROM threshold_overrides LIMIT 500"
            )
            for row in result.get("rows", []):
                svc = row.get("service_name", "*")
                cat = row.get("metric_category", "")
                otype = row.get("override_type", "")
                val = row.get("threshold_value")
                if val is None:
                    continue
                val = float(val)
                if otype == "learned" and svc == "*":
                    learned_map[cat] = val
                elif otype == "manual":
                    manual_map[(svc, cat)] = val
        except Exception:
            pass

    # Build effective thresholds per category
    categories = {
        "error_rate": {"description": "Service error rate spike", "base": zscore},
        "latency": {"description": "Service latency degradation", "base": zscore},
        "throughput": {"description": "Service throughput drop", "base": zscore},
        "dependency_latency": {"description": "Dependency latency anomaly", "base": zscore},
        "dependency_error": {"description": "Dependency error rate anomaly", "base": zscore},
        "exception_surge": {"description": "Exception rate surge", "base": zscore},
        "new_exception": {"description": "Previously unseen exception type", "base": zscore},
    }
    for cat, info in categories.items():
        mult = 1.0
        for key, m in multipliers.items():
            if cat.startswith(key) or key in cat:
                mult = m
                break
        info["multiplier"] = mult

        learned_adj = learned_map.get(cat, 0.0)
        info["learned_adjustment"] = round(learned_adj, 2)

        manual_ov = manual_map.get((service_name, cat)) if service_name else None
        info["manual_override"] = round(manual_ov, 2) if manual_ov is not None else None

        if manual_ov is not None:
            info["effective"] = round(max(1.0, manual_ov), 2)
            info["source"] = "manual"
        elif learned_adj != 0.0:
            info["effective"] = round(max(1.0, zscore * mult + learned_adj), 2)
            info["source"] = "learned"
        else:
            info["effective"] = round(max(1.0, zscore * mult), 2)
            info["source"] = "default"

    return jsonify({
        "detection": {
            "zscore_threshold": zscore,
            "error_rate_warning": float(os.getenv("ERROR_RATE_WARNING", "0.05")),
            "error_rate_critical": float(os.getenv("ERROR_RATE_CRITICAL", "0.20")),
            "detection_interval_seconds": int(os.getenv("DETECTION_INTERVAL", "60")),
        },
        "baselines": {
            "window_hours": int(os.getenv("BASELINE_WINDOW_HOURS", "24")),
            "recompute_interval_seconds": int(os.getenv("BASELINE_INTERVAL", "3600")),
            "min_samples": int(os.getenv("MIN_SAMPLES_FOR_BASELINE", "10")),
        },
        "alert_behavior": {
            "cooldown_minutes": int(os.getenv("ALERT_COOLDOWN_MINUTES", "15")),
            "auto_resolve_minutes": int(os.getenv("AUTO_RESOLVE_MINUTES", "30")),
        },
        "root_cause": {
            "enabled": os.getenv("ROOT_CAUSE_ENABLED", "true").lower() == "true",
            "adaptive_thresholds": os.getenv("ADAPTIVE_THRESHOLDS", "true").lower() == "true",
            "categories": categories,
        },
        "investigation": {
            "model": os.getenv("INVESTIGATION_MODEL", "claude-3-5-haiku-20241022"),
            "critical_only": INVESTIGATE_CRITICAL_ONLY,
            "max_per_hour": int(os.getenv("MAX_INVESTIGATIONS_PER_HOUR", "5")),
            "service_cooldown_minutes": int(os.getenv("INVESTIGATION_SERVICE_COOLDOWN_MINUTES", "30")),
        },
        "resource_predictions": {
            "disk_threshold": 0.95,
            "memory_threshold": 0.95,
            "cpu_threshold": 0.95,
            "trend_window_hours": 2,
            "min_r_squared": 0.7,
            "max_forecast_hours": 24,
        },
    })


@app.route('/api/entity/<entity_type>/<entity_name>/baselines', methods=['GET'])
def get_entity_baselines(entity_type, entity_name):
    """Return computed baselines for a specific entity (service/database)."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"baselines": [], "error": "No database connection"})

    # For databases, baselines are stored under the services that use them
    # with metric_type like db_<system>_latency, db_<system>_error_rate
    if entity_type == 'database':
        like_pattern = f"db_{entity_name}_%"
        sql = f"""
            SELECT service_name, metric_type, baseline_mean, baseline_stddev,
                   baseline_min, baseline_max, baseline_p50, baseline_p95, baseline_p99,
                   sample_count, computed_at
            FROM service_baselines
            WHERE metric_type LIKE '{like_pattern}'
            AND computed_at > NOW() - INTERVAL '24' HOUR
            ORDER BY computed_at DESC
        """
    else:
        sql = f"""
            SELECT service_name, metric_type, baseline_mean, baseline_stddev,
                   baseline_min, baseline_max, baseline_p50, baseline_p95, baseline_p99,
                   sample_count, computed_at
            FROM service_baselines
            WHERE service_name = '{entity_name}'
            AND computed_at > NOW() - INTERVAL '24' HOUR
            ORDER BY computed_at DESC
        """

    try:
        result = executor.execute_query(sql)
        if not result.get("success"):
            return jsonify({"baselines": [], "error": result.get("error", "Query failed")})

        # Deduplicate: keep only the latest baseline per metric_type
        seen = {}
        for row in result.get("rows", []):
            key = f"{row.get('service_name', '')}:{row.get('metric_type', '')}"
            if key not in seen:
                def safe_float(v):
                    try:
                        return round(float(v), 4) if v is not None else None
                    except (ValueError, TypeError):
                        return None
                seen[key] = {
                    "service_name": row.get("service_name"),
                    "metric_type": row.get("metric_type"),
                    "mean": safe_float(row.get("baseline_mean")),
                    "stddev": safe_float(row.get("baseline_stddev")),
                    "min": safe_float(row.get("baseline_min")),
                    "max": safe_float(row.get("baseline_max")),
                    "p50": safe_float(row.get("baseline_p50")),
                    "p95": safe_float(row.get("baseline_p95")),
                    "p99": safe_float(row.get("baseline_p99")),
                    "sample_count": int(row.get("sample_count", 0) or 0),
                    "computed_at": str(row.get("computed_at")) if row.get("computed_at") else None,
                }
        return jsonify({"baselines": list(seen.values())})
    except Exception as e:
        return jsonify({"baselines": [], "error": str(e)})


@app.route('/api/entity/<entity_type>/<entity_name>/threshold-overrides', methods=['GET'])
def get_entity_threshold_overrides(entity_type, entity_name):
    """Return manual overrides, global learned adjustments, 24h alert counts, and 7d auto-resolve rates."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    manual_overrides = {}
    learned_adjustments = {}
    alert_counts = {}
    auto_resolve_rates = {}

    # Load manual overrides for this entity
    try:
        result = executor.execute_query(
            f"SELECT metric_category, threshold_value, updated_at "
            f"FROM threshold_overrides "
            f"WHERE service_name = '{entity_name}' AND override_type = 'manual' LIMIT 100"
        )
        for row in result.get("rows", []):
            cat = row.get("metric_category", "")
            manual_overrides[cat] = {
                "value": float(row.get("threshold_value", 0)),
                "updated_at": str(row.get("updated_at")) if row.get("updated_at") else None,
            }
    except Exception:
        pass

    # Load global learned adjustments
    try:
        result = executor.execute_query(
            "SELECT metric_category, threshold_value "
            "FROM threshold_overrides "
            "WHERE service_name = '*' AND override_type = 'learned' LIMIT 100"
        )
        for row in result.get("rows", []):
            cat = row.get("metric_category", "")
            learned_adjustments[cat] = round(float(row.get("threshold_value", 0)), 2)
    except Exception:
        pass

    # 24h alert counts per category
    try:
        result = executor.execute_query(
            f"SELECT alert_type, COUNT(*) as cnt "
            f"FROM alerts "
            f"WHERE service_name = '{entity_name}' "
            f"AND created_at > NOW() - INTERVAL '24' HOUR "
            f"GROUP BY alert_type LIMIT 50"
        )
        for row in result.get("rows", []):
            alert_counts[row.get("alert_type", "")] = int(row.get("cnt", 0))
    except Exception:
        pass

    # 7d auto-resolve rates per category
    try:
        result = executor.execute_query(
            f"SELECT alert_type, "
            f"COUNT(*) as total, "
            f"SUM(CASE WHEN auto_resolved = true THEN 1 ELSE 0 END) as auto_cnt "
            f"FROM alerts "
            f"WHERE service_name = '{entity_name}' "
            f"AND created_at > NOW() - INTERVAL '7' DAY "
            f"GROUP BY alert_type "
            f"HAVING COUNT(*) >= 1 LIMIT 50"
        )
        for row in result.get("rows", []):
            total = int(row.get("total", 0))
            auto_cnt = int(row.get("auto_cnt", 0))
            auto_resolve_rates[row.get("alert_type", "")] = round(auto_cnt / total, 2) if total > 0 else 0
    except Exception:
        pass

    return jsonify({
        "manual_overrides": manual_overrides,
        "learned_adjustments": learned_adjustments,
        "alert_counts_24h": alert_counts,
        "auto_resolve_rates_7d": auto_resolve_rates,
    })


@app.route('/api/entity/<entity_type>/<entity_name>/threshold-override', methods=['PUT'])
def set_entity_threshold_override(entity_type, entity_name):
    """Set a manual threshold override for this entity."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    data = request.json or {}
    category = data.get("metric_category", "").strip()
    value = data.get("threshold_value")

    valid_categories = {
        "error_rate", "latency", "throughput",
        "dependency_latency", "dependency_error",
        "exception_surge", "new_exception",
        "resource_pressure",
    }
    if category not in valid_categories:
        return jsonify({"error": f"Invalid category: {category}"}), 400

    try:
        value = float(value)
    except (TypeError, ValueError):
        return jsonify({"error": "threshold_value must be a number"}), 400
    if value < 1.0:
        return jsonify({"error": "threshold_value must be >= 1.0"}), 400

    # DELETE + INSERT
    try:
        executor.execute_write(
            f"DELETE FROM threshold_overrides "
            f"WHERE service_name = '{entity_name}' "
            f"AND metric_category = '{category}' "
            f"AND override_type = 'manual'"
        )
        executor.execute_write(
            f"INSERT INTO threshold_overrides "
            f"(service_name, metric_category, override_type, threshold_value, created_by, created_at, updated_at) "
            f"VALUES ('{entity_name}', '{category}', 'manual', {value}, 'user', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"success": True, "effective_threshold": round(value, 2)})


@app.route('/api/entity/<entity_type>/<entity_name>/threshold-override', methods=['DELETE'])
def delete_entity_threshold_override(entity_type, entity_name):
    """Remove a manual threshold override, reverting to computed threshold."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    data = request.json or {}
    category = data.get("metric_category", "").strip()
    if not category:
        return jsonify({"error": "metric_category is required"}), 400

    try:
        executor.execute_write(
            f"DELETE FROM threshold_overrides "
            f"WHERE service_name = '{entity_name}' "
            f"AND metric_category = '{category}' "
            f"AND override_type = 'manual'"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Compute new effective threshold
    zscore = float(os.getenv("ANOMALY_THRESHOLD", "3.0"))
    multiplier_str = os.getenv("ROOT_CAUSE_THRESHOLDS", "db_error:0.8,dependency_error:0.9")
    mult = 1.0
    for pair in multiplier_str.split(","):
        if ":" in pair:
            k, v = pair.strip().split(":", 1)
            try:
                if category.startswith(k.strip()) or k.strip() in category:
                    mult = float(v.strip())
                    break
            except ValueError:
                pass

    # Check for learned adjustment
    learned_adj = 0.0
    try:
        result = executor.execute_query(
            f"SELECT threshold_value FROM threshold_overrides "
            f"WHERE service_name = '*' AND metric_category = '{category}' "
            f"AND override_type = 'learned' LIMIT 1"
        )
        rows = result.get("rows", [])
        if rows:
            learned_adj = float(rows[0].get("threshold_value", 0))
    except Exception:
        pass

    effective = round(max(1.0, zscore * mult + learned_adj), 2)
    return jsonify({"success": True, "effective_threshold": effective})


@app.route('/api/alert-suppressions', methods=['GET'])
def get_alert_suppressions():
    """List alert suppressions for a service (includes global '*' entries)."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    service = request.args.get('service', '*')
    suppression_type = request.args.get('type', '')
    type_filter = f"AND suppression_type = '{suppression_type}' " if suppression_type else ""
    sql = (
        f"SELECT service_name, suppression_type, exception_type, reason, created_by, created_at "
        f"FROM alert_suppressions "
        f"WHERE service_name IN ('{service}', '*') "
        f"{type_filter}"
        f"ORDER BY created_at DESC"
    )
    try:
        result = executor.execute_query(sql)
        return jsonify({"suppressions": result.get("rows", [])})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/alert-suppressions', methods=['PUT'])
def put_alert_suppression():
    """Create or update an alert suppression (DELETE + INSERT upsert)."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    data = request.json or {}
    service_name = data.get("service_name", "").strip()
    exception_type = data.get("exception_type", "").strip()
    suppression_type = data.get("suppression_type", "exception_type").strip()
    reason = data.get("reason", "").strip() or "User suppressed"

    if not service_name or not exception_type:
        return jsonify({"error": "service_name and exception_type are required"}), 400

    try:
        executor.execute_write(
            f"DELETE FROM alert_suppressions "
            f"WHERE service_name = '{service_name}' "
            f"AND suppression_type = '{suppression_type}' "
            f"AND exception_type = '{exception_type}'"
        )
        executor.execute_write(
            f"INSERT INTO alert_suppressions "
            f"(service_name, suppression_type, exception_type, reason, created_by, created_at) "
            f"VALUES ('{service_name}', '{suppression_type}', '{exception_type}', '{reason}', 'user', CURRENT_TIMESTAMP)"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    _cache.invalidate("/api/status")
    return jsonify({"success": True})


@app.route('/api/alert-suppressions', methods=['DELETE'])
def delete_alert_suppression():
    """Remove an alert suppression."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"error": "No database connection"}), 503

    data = request.json or {}
    service_name = data.get("service_name", "").strip()
    exception_type = data.get("exception_type", "").strip()
    suppression_type = data.get("suppression_type", "exception_type").strip()

    if not service_name or not exception_type:
        return jsonify({"error": "service_name and exception_type are required"}), 400

    try:
        executor.execute_write(
            f"DELETE FROM alert_suppressions "
            f"WHERE service_name = '{service_name}' "
            f"AND suppression_type = '{suppression_type}' "
            f"AND exception_type = '{exception_type}'"
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    _cache.invalidate("/api/status")
    return jsonify({"success": True})


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with optional filtering.  Cached for CACHE_TTL_ALERTS seconds."""
    cache_key = request.full_path  # includes query string
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()

    status = request.args.get('status', 'active')  # active, resolved, all
    severity = request.args.get('severity')  # info, warning, critical
    service = request.args.get('service')
    limit = min(int(request.args.get('limit', 50)), 100)

    data = {
        'alerts': [],
        'summary': {
            'active': 0,
            'critical': 0,
            'warning': 0,
            'info': 0
        }
    }

    # Build query with filters
    conditions = []

    if status == 'active':
        conditions.append("status = 'active'")
    elif status == 'resolved':
        conditions.append("status = 'resolved'")
    # 'all' has no status filter

    if severity:
        conditions.append(f"severity = '{severity}'")

    if service:
        conditions.append(f"service_name = '{service}'")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    # Get alerts with investigations
    alerts_query = f"""
    SELECT
        a.alert_id,
        a.created_at,
        a.updated_at,
        a.service_name,
        a.alert_type,
        a.severity,
        a.title,
        a.description,
        a.metric_type,
        a.current_value,
        a.baseline_value,
        a.z_score,
        a.status,
        a.resolved_at,
        a.auto_resolved,
        i.investigation_id,
        i.investigated_at,
        i.root_cause_summary,
        i.recommended_actions,
        i.supporting_evidence,
        i.queries_executed,
        i.tokens_used,
        i.model_used
    FROM alerts a
    LEFT JOIN alert_investigations i ON a.alert_id = i.alert_id
    {where_clause.replace('status', 'a.status').replace('severity', 'a.severity').replace('service_name', 'a.service_name') if where_clause else ''}
    ORDER BY
        CASE a.severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END,
        a.created_at DESC
    LIMIT {limit}
    """

    result = executor.execute_query(alerts_query)
    if result['success']:
        data['alerts'] = result['rows']

    # Get summary counts
    summary_query = """
    SELECT
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN status = 'active' AND severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN status = 'active' AND severity = 'warning' THEN 1 ELSE 0 END) as warning,
        SUM(CASE WHEN status = 'active' AND severity = 'info' THEN 1 ELSE 0 END) as info
    FROM alerts
    """
    result = executor.execute_query(summary_query)
    if result['success'] and result['rows']:
        row = result['rows'][0]
        data['summary'] = {
            'active': row.get('active') or 0,
            'critical': row.get('critical') or 0,
            'warning': row.get('warning') or 0,
            'info': row.get('info') or 0
        }

    response = jsonify(data)
    _cache.set(cache_key, response, CACHE_TTL_ALERTS)
    return response


@app.route('/api/alerts/<alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    executor = get_query_executor()

    sql = f"""
    UPDATE alerts
    SET status = 'acknowledged',
        updated_at = NOW()
    WHERE alert_id = '{alert_id}'
    """

    try:
        cursor = executor.conn.cursor()
        cursor.execute(sql)
        _invalidate_cache("/api/alerts")
        return jsonify({'success': True, 'message': f'Alert {alert_id} acknowledged'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/resolve', methods=['POST'])
def resolve_alert(alert_id):
    """Manually resolve an alert."""
    executor = get_query_executor()

    sql = f"""
    UPDATE alerts
    SET status = 'resolved',
        resolved_at = NOW(),
        updated_at = NOW(),
        auto_resolved = false
    WHERE alert_id = '{alert_id}'
    """

    try:
        cursor = executor.conn.cursor()
        cursor.execute(sql)
        _update_remediation_resolution(executor, alert_id)
        _invalidate_cache("/api/alerts")
        return jsonify({'success': True, 'message': f'Alert {alert_id} resolved'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/archive', methods=['POST'])
def archive_alert(alert_id):
    """Archive an alert (moves it out of active view but keeps history)."""
    executor = get_query_executor()

    sql = f"""
    UPDATE alerts
    SET status = 'archived',
        updated_at = NOW()
    WHERE alert_id = '{alert_id}'
    """

    try:
        cursor = executor.conn.cursor()
        cursor.execute(sql)
        _invalidate_cache("/api/alerts")
        return jsonify({'success': True, 'message': f'Alert {alert_id} archived'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/investigate', methods=['POST'])
def investigate_alert(alert_id):
    """Manually trigger investigation for an alert."""
    executor = get_query_executor()

    # Get alert details
    alert_query = f"""
    SELECT alert_id, service_name, alert_type, severity, title, description, created_at
    FROM alerts
    WHERE alert_id = '{alert_id}'
    """
    result = executor.execute_query(alert_query)
    if not result['success'] or not result['rows']:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404

    alert = result['rows'][0]

    # Check if already investigated
    inv_query = f"SELECT investigation_id FROM alert_investigations WHERE alert_id = '{alert_id}'"
    inv_result = executor.execute_query(inv_query)
    if inv_result['success'] and inv_result['rows']:
        return jsonify({'success': False, 'error': 'Alert already has investigation'}), 400

    # Run investigation
    try:
        investigation = run_alert_investigation(executor, alert)
        if investigation:
            _invalidate_cache("/api/alerts")
            _invalidate_cache("/api/incidents")
            return jsonify({'success': True, 'investigation': investigation})
        else:
            return jsonify({'success': False, 'error': 'Investigation failed'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


def run_alert_investigation(executor, alert):
    """Run LLM investigation for an alert."""
    import uuid

    service = alert.get('service_name', '')
    alert_type = alert.get('alert_type', '')
    alert_id = alert.get('alert_id', '')
    description = alert.get('description', '')
    created_at = alert.get('created_at', '')

    # Compute a time window anchored to when the alert fired, not "now".
    # Use a 10-minute window before the alert and 5 minutes after.
    if created_at:
        from datetime import timedelta
        try:
            if isinstance(created_at, str):
                # Handle ISO format from Trino
                alert_time = datetime.fromisoformat(created_at.replace('Z', '+00:00').replace('+00:00', ''))
            else:
                alert_time = created_at
            window_start = (alert_time - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
            window_end = (alert_time + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            window_start = None
            window_end = None
    else:
        window_start = None
        window_end = None

    if window_start and window_end:
        time_filter_traces = f"start_time BETWEEN TIMESTAMP '{window_start}' AND TIMESTAMP '{window_end}'"
        time_filter_logs = f"timestamp BETWEEN TIMESTAMP '{window_start}' AND TIMESTAMP '{window_end}'"
        time_context = f"Alert fired at: {created_at}\nTime window for queries: {window_start} to {window_end}"
    else:
        time_filter_traces = "start_time > current_timestamp - INTERVAL '15' MINUTE"
        time_filter_logs = "timestamp > current_timestamp - INTERVAL '15' MINUTE"
        time_context = "Time window: last 15 minutes from now"

    system_prompt = f"""You are an expert SRE assistant performing root cause analysis.
You have access to observability data via SQL queries (Trino/Presto dialect).

Available tables and their EXACT columns (use ONLY these):

traces_otel_analytic (time column: start_time):
  trace_id (varchar), span_id (varchar), parent_span_id (varchar),
  start_time (timestamp), duration_ns (bigint), service_name (varchar),
  span_name (varchar), span_kind (varchar), status_code (varchar),
  http_status (integer), db_system (varchar), attributes_json (varchar)

logs_otel_analytic (time column: timestamp):
  timestamp (timestamp), service_name (varchar), severity_number (integer),
  severity_text (varchar), body_text (varchar), trace_id (varchar),
  span_id (varchar), attributes_json (varchar)

span_events_otel_analytic (time column: timestamp):
  timestamp (timestamp), trace_id (varchar), span_id (varchar),
  service_name (varchar), span_name (varchar), event_name (varchar),
  event_attributes_json (varchar), exception_type (varchar),
  exception_message (varchar), exception_stacktrace (varchar),
  gen_ai_system (varchar), gen_ai_operation (varchar),
  gen_ai_request_model (varchar), gen_ai_usage_prompt_tokens (integer),
  gen_ai_usage_completion_tokens (integer)

span_links_otel_analytic (no time column):
  trace_id (varchar), span_id (varchar), service_name (varchar),
  span_name (varchar), linked_trace_id (varchar), linked_span_id (varchar),
  linked_trace_state (varchar), link_attributes_json (varchar)

metrics_otel_analytic (time column: timestamp):
  timestamp (timestamp), service_name (varchar), metric_name (varchar),
  metric_unit (varchar), value_double (double), attributes_flat (varchar)
  -- Contains infrastructure metrics: system.cpu.utilization, system.memory.utilization,
  --   system.disk.utilization, system.filesystem.utilization, container.cpu.percent,
  --   container.memory.percent, container.memory.usage.total, postgresql.* metrics, etc.
  -- service_name is typically the collector name; use attributes_flat to filter by host/container.
  -- attributes_flat contains comma-separated key=value pairs like host.name=..., container.name=..., etc.

topology_services (latest snapshot, no time column):
  service_name (varchar), service_type (varchar), span_count (bigint),
  error_pct (double), avg_latency_ms (double), last_seen (timestamp), updated_at (timestamp)

topology_dependencies (latest snapshot, no time column):
  source_service (varchar), target_service (varchar), dependency_type (varchar),
  call_count (bigint), avg_latency_ms (double), error_pct (double),
  last_seen (timestamp), updated_at (timestamp)

topology_hosts (latest snapshot, no time column):
  host_name (varchar), display_name (varchar), os_type (varchar),
  cpu_pct (double), memory_pct (double), disk_pct (double),
  last_seen (timestamp), updated_at (timestamp)

topology_containers (latest snapshot, no time column):
  container_name (varchar), cpu_pct (double), memory_pct (double),
  memory_usage_mb (double), last_seen (timestamp), updated_at (timestamp)

topology_database_hosts (maps db to host):
  db_system (varchar), host_name (varchar), last_seen (timestamp), updated_at (timestamp)

topology_host_services (maps host to services):
  host_name (varchar), service_name (varchar), source (varchar),
  data_point_count (bigint), last_seen (timestamp), updated_at (timestamp)

service_metrics_1m (pre-aggregated per-minute service metrics):
  time_bucket (timestamp), service_name (varchar), avg_latency_ms (double),
  max_latency_ms (double), p95_latency_ms (double), request_count (bigint),
  error_count (bigint), error_pct (double)

db_metrics_1m (pre-aggregated per-minute database metrics):
  time_bucket (timestamp), db_system (varchar), avg_latency_ms (double),
  max_latency_ms (double), query_count (bigint), error_count (bigint), error_pct (double)

CRITICAL SQL RULES:
- Time filter for traces: WHERE {time_filter_traces}
- Time filter for logs/events and metrics: WHERE {time_filter_logs}
- When you find a specific trace_id, query ALL spans for that trace WITHOUT a time filter
  to see the full request flow (e.g. WHERE trace_id = '...')
- NO 'attributes' column exists - use attributes_json for trace attributes,
  attributes_flat for metric attributes
- NO semicolons, NO square brackets
- Interval syntax: INTERVAL '15' MINUTE (quoted number)
- Timestamp literals MUST use a space, NOT 'T': TIMESTAMP '2026-01-31 18:42:00' (correct)
  TIMESTAMP '2026-01-31T18:42:00' is INVALID in Trino and will error
- GROUP BY column aliases are NOT allowed in Trino. Use positional references instead:
  GROUP BY 1, 2 (refers to 1st and 2nd SELECT columns). NEVER write GROUP BY my_alias.
  Similarly for ORDER BY with computed columns, prefer positional references: ORDER BY 3 DESC

INVESTIGATION STRATEGY:
1. First examine the error traces and exceptions to understand WHAT failed.
2. Then check infrastructure metrics around the same time window to understand WHY:
   - Was the host under CPU/memory/disk pressure?
   - Were there resource spikes on the database host or container?
   - Use topology_database_hosts to find which host runs the database,
     then check that host's metrics.
3. Check for correlated errors in other services during the same window.
4. For resource pressure alerts, use topology tables to identify affected services:
   - topology_host_services: maps host_name → service_name
   - topology_containers: container_name, cpu_pct, memory_pct
   - topology_hosts: host_name, cpu_pct, memory_pct, disk_pct
   Then drill into container-level metrics in metrics_otel_analytic (container.cpu.percent,
   container.memory.percent) to find the top resource consumer.

STRICT ANTI-HALLUCINATION RULES:
- ONLY state facts that came from query results in THIS investigation.
- NEVER fabricate error messages, metric values, service names, or trace IDs.
- If a query returns 0 rows, say "no data found" — do NOT invent results.
- Quote exception messages and error text VERBATIM from query results.
- If you cannot determine the root cause from the data, say so explicitly.
- Every claim in EVIDENCE must reference actual query output.
- Do NOT describe what a query "would show" — only describe what it DID show.

Be CONCISE. Output:
ROOT CAUSE: <one sentence based on evidence>
EVIDENCE:
- <finding 1 with actual values from queries>
RECOMMENDED ACTIONS:
1. <action 1>"""

    tools = [{
        "name": "execute_sql",
        "description": "Execute a SQL query against the observability database",
        "input_schema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string", "description": "The SQL query to execute"}
            },
            "required": ["sql"]
        }
    }]

    user_prompt = f"""Investigate this alert:
Service: {service}
Alert Type: {alert_type}
Description: {description}
{time_context}

Find the root cause by querying the data. Use the time window above for initial queries.
When you find a relevant trace_id, query its full span tree (no time filter) to understand the complete request flow."""

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages = [{"role": "user", "content": user_prompt}]
    queries_executed = 0
    total_tokens = 0

    for _ in range(8):
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=2000,
            system=system_prompt,
            tools=tools,
            messages=messages
        )
        total_tokens += response.usage.input_tokens + response.usage.output_tokens

        tool_calls = [b for b in response.content if b.type == "tool_use"]
        if not tool_calls:
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []

        for tool_call in tool_calls:
            if tool_call.name == "execute_sql":
                sql = tool_call.input.get("sql", "").strip().rstrip(';')
                queries_executed += 1
                result = executor.execute_query(sql)
                if result['success']:
                    result_str = json.dumps(result['rows'][:20], default=str)
                else:
                    result_str = json.dumps([{"error": result.get('error', 'Query failed')}])
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_call.id,
                    "content": result_str
                })

        messages.append({"role": "user", "content": tool_results})

    # Get final summary
    if response.stop_reason != "end_turn":
        messages.append({"role": "assistant", "content": response.content})

    messages.append({
        "role": "user",
        "content": "Provide your final analysis in this format:\nROOT CAUSE: <one sentence>\nEVIDENCE:\n- <finding>\nRECOMMENDED ACTIONS:\n1. <action>"
    })

    final = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=1000,
        system=system_prompt,
        messages=messages
    )
    total_tokens += final.usage.input_tokens + final.usage.output_tokens

    # Parse response
    text = "".join(b.text for b in final.content if hasattr(b, 'text'))

    root_cause = ""
    actions = ""
    evidence = ""

    if "ROOT CAUSE:" in text:
        parts = text.split("ROOT CAUSE:", 1)[1]
        if "EVIDENCE:" in parts:
            root_cause = parts.split("EVIDENCE:")[0].strip()
            parts = parts.split("EVIDENCE:", 1)[1]
            if "RECOMMENDED ACTIONS:" in parts:
                evidence = parts.split("RECOMMENDED ACTIONS:")[0].strip()
                actions = parts.split("RECOMMENDED ACTIONS:", 1)[1].strip()
            else:
                evidence = parts.strip()
        else:
            root_cause = parts.strip()

    # Store investigation
    investigation_id = str(uuid.uuid4())[:8]
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    store_sql = f"""
    INSERT INTO alert_investigations (
        investigation_id, alert_id, investigated_at, service_name, alert_type,
        model_used, root_cause_summary, recommended_actions, supporting_evidence,
        queries_executed, tokens_used
    ) VALUES (
        '{investigation_id}', '{alert_id}', TIMESTAMP '{now}', '{service}', '{alert_type}',
        '{ANTHROPIC_MODEL}', '{root_cause.replace("'", "''")}', '{actions.replace("'", "''")}',
        '{evidence.replace("'", "''")}', {queries_executed}, {total_tokens}
    )
    """

    try:
        cursor = executor.conn.cursor()
        cursor.execute(store_sql)
    except Exception as e:
        print(f"Failed to store investigation: {e}")

    return {
        "investigation_id": investigation_id,
        "root_cause_summary": root_cause,
        "recommended_actions": actions,
        "supporting_evidence": evidence,
        "queries_executed": queries_executed,
        "tokens_used": total_tokens
    }


@app.route('/api/alerts/history', methods=['GET'])
def get_alert_history():
    """Get historical alert data for trend analysis."""
    executor = get_query_executor()

    hours = min(int(request.args.get('hours', 24)), 168)  # max 1 week

    data = {
        'hourly_counts': [],
        'by_service': [],
        'by_type': []
    }

    # Hourly alert counts
    hourly_query = f"""
    SELECT
        date_trunc('hour', created_at) as hour,
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'warning' THEN 1 ELSE 0 END) as warning
    FROM alerts
    WHERE created_at > NOW() - INTERVAL '{hours}' HOUR
    GROUP BY date_trunc('hour', created_at)
    ORDER BY hour
    """
    result = executor.execute_query(hourly_query)
    if result['success']:
        data['hourly_counts'] = result['rows']

    # Alerts by service
    by_service_query = f"""
    SELECT
        service_name,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active
    FROM alerts
    WHERE created_at > NOW() - INTERVAL '{hours}' HOUR
    GROUP BY service_name
    ORDER BY total DESC
    LIMIT 10
    """
    result = executor.execute_query(by_service_query)
    if result['success']:
        data['by_service'] = result['rows']

    # Alerts by type
    by_type_query = f"""
    SELECT
        alert_type,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active
    FROM alerts
    WHERE created_at > NOW() - INTERVAL '{hours}' HOUR
    GROUP BY alert_type
    ORDER BY total DESC
    """
    result = executor.execute_query(by_type_query)
    if result['success']:
        data['by_type'] = result['rows']

    return jsonify(data)


@app.route('/api/errors/history', methods=['GET'])
def get_error_history():
    """Get historical error traces for the sidebar history tab."""
    executor = get_query_executor()
    if not executor:
        return jsonify({"errors": [], "summary": {}})

    hours = min(int(request.args.get('hours', 24)), 168)
    service = request.args.get('service', '').strip()
    limit = min(int(request.args.get('limit', 50)), 100)

    conditions = [
        "status_code = 'ERROR'",
        f"start_time > NOW() - INTERVAL '{hours}' HOUR",
        "(http_status IS NULL OR http_status < 200 OR http_status >= 300)",
    ]
    if service:
        conditions.append(f"service_name = '{service}'")
    where = " AND ".join(conditions)

    errors_query = f"""
    SELECT trace_id, span_id, service_name, span_name,
           duration_ns / 1000000.0 as duration_ms,
           start_time
    FROM traces_otel_analytic
    WHERE {where}
    ORDER BY start_time DESC
    LIMIT {limit}
    """
    errors = []
    result = executor.execute_query(errors_query)
    if result.get('success'):
        errors = result['rows']

    # Summary: count by service
    summary_query = f"""
    SELECT service_name,
           COUNT(*) as error_count
    FROM traces_otel_analytic
    WHERE {where}
    GROUP BY service_name
    ORDER BY error_count DESC
    LIMIT 20
    """
    by_service = []
    result = executor.execute_query(summary_query)
    if result.get('success'):
        by_service = result['rows']

    total = sum(s.get('error_count', 0) for s in by_service)

    # Error patterns: group by service + operation to identify recurring patterns
    patterns_query = f"""
    SELECT service_name, span_name,
           COUNT(*) as count,
           ROUND(AVG(duration_ns / 1000000.0), 1) as avg_duration_ms,
           MIN(start_time) as first_seen,
           MAX(start_time) as last_seen
    FROM traces_otel_analytic
    WHERE {where}
    GROUP BY service_name, span_name
    ORDER BY count DESC
    LIMIT 10
    """
    error_patterns = []
    result = executor.execute_query(patterns_query)
    if result.get('success'):
        error_patterns = result['rows']

    # Exception types breakdown (only when filtering by service)
    exception_types = []
    if service:
        exception_query = f"""
        SELECT exception_type, COUNT(*) as count,
               MAX(timestamp) as last_seen
        FROM span_events_otel_analytic
        WHERE service_name = '{service}'
          AND exception_type IS NOT NULL AND exception_type != ''
          AND timestamp > NOW() - INTERVAL '{hours}' HOUR
        GROUP BY exception_type
        ORDER BY count DESC
        LIMIT 20
        """
        result = executor.execute_query(exception_query)
        if result.get('success'):
            exception_types = result['rows']

        # Enrich with suppression status
        if exception_types:
            sup_query = (
                f"SELECT exception_type FROM alert_suppressions "
                f"WHERE service_name IN ('{service}', '*') "
                f"AND suppression_type = 'exception_type'"
            )
            sup_result = executor.execute_query(sup_query)
            suppressed_set = set()
            if sup_result.get('success'):
                suppressed_set = {r['exception_type'] for r in sup_result.get('rows', [])}
            for et in exception_types:
                et['suppressed'] = et.get('exception_type', '') in suppressed_set

    # Enrich error patterns with suppression status
    if service and error_patterns:
        op_sup_query = (
            f"SELECT exception_type FROM alert_suppressions "
            f"WHERE service_name IN ('{service}', '*') "
            f"AND suppression_type = 'error_operation'"
        )
        op_sup_result = executor.execute_query(op_sup_query)
        suppressed_ops = set()
        if op_sup_result.get('success'):
            suppressed_ops = {r['exception_type'] for r in op_sup_result.get('rows', [])}
        for ep in error_patterns:
            ep['suppressed'] = ep.get('span_name', '') in suppressed_ops

    return jsonify({
        "errors": errors,
        "by_service": by_service,
        "error_patterns": error_patterns,
        "exception_types": exception_types,
        "total": total,
        "hours": hours,
    })


@app.route('/api/baselines', methods=['GET'])
def get_baselines():
    """Get current baselines for monitoring."""
    executor = get_query_executor()

    service = request.args.get('service')

    data = {
        'baselines': []
    }

    conditions = ["1=1"]
    if service:
        conditions.append(f"service_name = '{service}'")

    where_clause = " AND ".join(conditions)

    # Get latest baselines for each service/metric combination
    baselines_query = f"""
    SELECT
        b.service_name,
        b.metric_type,
        b.baseline_mean,
        b.baseline_stddev,
        b.baseline_p50,
        b.baseline_p95,
        b.baseline_p99,
        b.sample_count,
        b.window_hours,
        b.computed_at
    FROM service_baselines b
    INNER JOIN (
        SELECT service_name, metric_type, MAX(computed_at) as max_computed
        FROM service_baselines
        WHERE {where_clause}
        GROUP BY service_name, metric_type
    ) latest ON b.service_name = latest.service_name
        AND b.metric_type = latest.metric_type
        AND b.computed_at = latest.max_computed
    ORDER BY b.service_name, b.metric_type
    """

    result = executor.execute_query(baselines_query)
    if result['success']:
        data['baselines'] = result['rows']

    return jsonify(data)


@app.route('/api/anomalies', methods=['GET'])
def get_anomalies():
    """Get recent anomaly scores."""
    executor = get_query_executor()

    minutes = min(int(request.args.get('minutes', 60)), 1440)  # max 24 hours
    service = request.args.get('service')
    only_anomalies = request.args.get('only_anomalies', 'true').lower() == 'true'

    data = {
        'anomalies': []
    }

    conditions = [f"timestamp > NOW() - INTERVAL '{minutes}' MINUTE"]

    if service:
        conditions.append(f"service_name = '{service}'")

    if only_anomalies:
        conditions.append("is_anomaly = true")

    where_clause = " AND ".join(conditions)

    anomalies_query = f"""
    SELECT
        timestamp,
        service_name,
        metric_type,
        current_value,
        expected_value,
        baseline_mean,
        baseline_stddev,
        z_score,
        anomaly_score,
        is_anomaly,
        detection_method
    FROM anomaly_scores
    WHERE {where_clause}
    ORDER BY timestamp DESC
    LIMIT 100
    """

    result = executor.execute_query(anomalies_query)
    if result['success']:
        data['anomalies'] = result['rows']

    return jsonify(data)


@app.route('/api/alerts/activity', methods=['GET'])
def get_alert_activity():
    """Get recent alert activity (created, resolved, auto-resolved).  Cached."""
    cache_key = request.full_path
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()

    minutes = min(int(request.args.get('minutes', 60)), 1440)  # max 24 hours
    limit = min(int(request.args.get('limit', 20)), 100)

    data = {
        'events': []
    }

    # Get recent alert events from alerts table
    # We construct events from created_at, resolved_at timestamps
    activity_query = f"""
    WITH alert_events AS (
        -- Created events
        SELECT
            created_at as event_time,
            'created' as event_type,
            service_name,
            alert_type,
            severity,
            title
        FROM alerts
        WHERE created_at > NOW() - INTERVAL '{minutes}' MINUTE

        UNION ALL

        -- Resolved events (auto and manual)
        SELECT
            resolved_at as event_time,
            CASE WHEN auto_resolved = true THEN 'auto_resolved' ELSE 'resolved' END as event_type,
            service_name,
            alert_type,
            severity,
            title
        FROM alerts
        WHERE resolved_at IS NOT NULL
            AND resolved_at > NOW() - INTERVAL '{minutes}' MINUTE
    )
    SELECT
        event_time,
        event_type,
        service_name,
        alert_type,
        severity,
        title
    FROM alert_events
    ORDER BY event_time DESC
    LIMIT {limit}
    """

    result = executor.execute_query(activity_query)
    if result['success']:
        data['events'] = result['rows']

    response = jsonify(data)
    _cache.set(cache_key, response, CACHE_TTL_ALERTS_ACTIVITY)
    return response


# =============================================================================
# Predictions, Incident Context, Patterns, Simulation
# =============================================================================

# Simulation manager singleton (lazy-init with executor)
_simulation_manager = None

def get_simulation_manager():
    global _simulation_manager
    if _simulation_manager is None:
        try:
            from failure_simulator import SimulationManager
            # Create a lightweight executor for the simulation manager
            from predictive_alerts import TrinoExecutor, Config
            config = Config()
            executor = TrinoExecutor(config)
            _simulation_manager = SimulationManager(executor=executor)
        except Exception as e:
            print(f"[WebUI] Could not init SimulationManager: {e}")
            from failure_simulator import SimulationManager
            _simulation_manager = SimulationManager(executor=None)
    return _simulation_manager


@app.route('/api/predictions', methods=['GET'])
def get_predictions():
    """Get active resource predictions.  Cached for CACHE_TTL_PREDICTIONS seconds."""
    cache_key = "/api/predictions"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()

    data = {'predictions': []}

    query = """
    SELECT prediction_id, created_at, host_name, resource_type, service_name,
           current_value, trend_slope, trend_r_squared, predicted_exhaustion_at,
           threshold_value, hours_until_exhaustion, confidence, status
    FROM resource_predictions
    WHERE status = 'active'
    ORDER BY hours_until_exhaustion ASC
    LIMIT 50
    """
    result = executor.execute_query(query)
    if result['success']:
        data['predictions'] = result['rows']

    response = jsonify(data)
    _cache.set(cache_key, response, CACHE_TTL_PREDICTIONS)
    return response


@app.route('/api/jobs/status', methods=['GET'])
def get_jobs_status():
    """Get status of background services.  Cached for CACHE_TTL_JOBS seconds."""
    cache_key = "/api/jobs/status"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()
    query = "SELECT job_name, last_run_at, cycle_duration_ms, status, details_json, updated_at FROM job_status ORDER BY job_name"
    result = executor.execute_query(query)
    jobs = []
    if result['success']:
        for row in result['rows']:
            job = dict(row)
            if job.get('details_json'):
                try:
                    job['details'] = json.loads(job['details_json'])
                except Exception:
                    job['details'] = {}
                del job['details_json']
            else:
                job['details'] = {}
                if 'details_json' in job:
                    del job['details_json']
            jobs.append(job)
    response = jsonify({'jobs': jobs})
    _cache.set(cache_key, response, CACHE_TTL_JOBS)
    return response


@app.route('/api/jobs/status/<job_name>', methods=['GET'])
def get_job_status(job_name):
    """Get status of a single background job.  Uses the same cache as /api/jobs/status."""
    # Reuse the all-jobs cache so we don't fire an extra Trino query
    cache_key = "/api/jobs/status"
    cached = _cache.get(cache_key)
    if cached is not None:
        all_jobs = cached.get_json().get('jobs', [])
    else:
        executor = get_query_executor()
        query = "SELECT job_name, last_run_at, cycle_duration_ms, status, details_json, updated_at FROM job_status ORDER BY job_name"
        result = executor.execute_query(query)
        jobs = []
        if result['success']:
            for row in result['rows']:
                job = dict(row)
                if job.get('details_json'):
                    try:
                        job['details'] = json.loads(job['details_json'])
                    except Exception:
                        job['details'] = {}
                    del job['details_json']
                else:
                    job['details'] = {}
                    if 'details_json' in job:
                        del job['details_json']
                jobs.append(job)
        all_response = jsonify({'jobs': jobs})
        _cache.set(cache_key, all_response, CACHE_TTL_JOBS)
        all_jobs = jobs

    # Find the requested job
    for job in all_jobs:
        if job.get('job_name') == job_name:
            return jsonify({'job': job})
    return jsonify({'error': f'Job {job_name} not found'}), 404


@app.route('/api/incidents/context/<alert_id>', methods=['GET'])
def get_incident_context(alert_id):
    """Get incident context snapshot for an alert.  Cached for CACHE_TTL_INCIDENTS seconds."""
    cache_key = f"/api/incidents/context/{alert_id}"
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    executor = get_query_executor()

    data = {'context': None, 'pattern': None, 'similar_alerts': []}

    # Sanitize alert_id
    alert_id = alert_id.replace("'", "")[:20]

    context_query = f"""
    SELECT context_id, alert_id, captured_at, service_name, alert_type,
           severity, fingerprint, metrics_snapshot, error_traces,
           log_snapshot, topology_snapshot, baseline_values, anomaly_scores
    FROM incident_context
    WHERE alert_id = '{alert_id}'
    ORDER BY captured_at DESC
    LIMIT 1
    """
    result = executor.execute_query(context_query)
    if result['success'] and result['rows']:
        ctx = result['rows'][0]
        # Parse JSON fields
        for field in ('metrics_snapshot', 'error_traces', 'log_snapshot',
                      'topology_snapshot', 'baseline_values', 'anomaly_scores'):
            if ctx.get(field):
                try:
                    ctx[field] = json.loads(ctx[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        data['context'] = ctx

        # Look up matching pattern
        fingerprint = ctx.get('fingerprint', '')
        if fingerprint:
            pattern_query = f"""
            SELECT pattern_id, occurrence_count, first_seen, last_seen,
                   avg_duration_minutes, common_root_cause, precursor_signals
            FROM incident_patterns
            WHERE fingerprint = '{fingerprint}'
            LIMIT 1
            """
            pat_result = executor.execute_query(pattern_query)
            if pat_result['success'] and pat_result['rows']:
                pat = pat_result['rows'][0]
                if pat.get('precursor_signals'):
                    try:
                        pat['precursor_signals'] = json.loads(pat['precursor_signals'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                data['pattern'] = pat

        # Get similar past alerts (same service + alert_type)
        svc = ctx.get('service_name', '').replace("'", "''")
        atype = ctx.get('alert_type', '').replace("'", "''")
        if svc and atype:
            similar_query = f"""
            SELECT alert_id, created_at, resolved_at, severity, status,
                   auto_resolved, current_value, baseline_value
            FROM alerts
            WHERE service_name = '{svc}' AND alert_type = '{atype}'
              AND alert_id != '{alert_id}'
            ORDER BY created_at DESC
            LIMIT 10
            """
            sim_result = executor.execute_query(similar_query)
            if sim_result['success']:
                data['similar_alerts'] = sim_result['rows']

    return jsonify(data)


@app.route('/api/incidents/patterns', methods=['GET'])
def get_incident_patterns():
    """Get recurring incident patterns."""
    executor = get_query_executor()

    data = {'patterns': []}

    query = """
    SELECT pattern_id, fingerprint, service_name, alert_type,
           occurrence_count, first_seen, last_seen,
           avg_duration_minutes, common_root_cause, precursor_signals, updated_at
    FROM incident_patterns
    ORDER BY occurrence_count DESC
    LIMIT 50
    """
    result = executor.execute_query(query)
    if result['success']:
        for pat in result['rows']:
            if pat.get('precursor_signals'):
                try:
                    pat['precursor_signals'] = json.loads(pat['precursor_signals'])
                except (json.JSONDecodeError, TypeError):
                    pass
        data['patterns'] = result['rows']

    response = jsonify(data)
    _cache.set(cache_key, response, CACHE_TTL_INCIDENTS)
    return response


@app.route('/api/simulation/scenarios', methods=['GET'])
def list_simulation_scenarios():
    """List available simulation scenarios."""
    mgr = get_simulation_manager()
    return jsonify({'scenarios': mgr.list_scenarios()})


@app.route('/api/simulation/start', methods=['POST'])
def start_simulation():
    """Start a simulation scenario."""
    mgr = get_simulation_manager()
    body = request.get_json(silent=True) or {}
    scenario = body.get('scenario', '')
    config = body.get('config', {})

    if not scenario:
        return jsonify({'success': False, 'error': 'Missing scenario name'}), 400

    run_id = mgr.start_scenario(scenario, config)
    if run_id is None:
        return jsonify({'success': False, 'error': 'Scenario already running or invalid name'}), 409

    return jsonify({'success': True, 'run_id': run_id})


@app.route('/api/simulation/stop', methods=['POST'])
def stop_simulation():
    """Stop the running simulation."""
    mgr = get_simulation_manager()
    body = request.get_json(silent=True) or {}
    run_id = body.get('run_id')

    success = mgr.stop_scenario(run_id)
    return jsonify({'success': success})


@app.route('/api/simulation/cleanup', methods=['POST'])
def simulation_cleanup():
    """Run cleanup/undo for a scenario, even when no simulation is running."""
    mgr = get_simulation_manager()
    body = request.get_json(silent=True) or {}
    scenario = body.get('scenario', '')

    if not scenario:
        return jsonify({'success': False, 'error': 'Missing scenario name'}), 400

    success = mgr.run_cleanup(scenario)
    if not success:
        return jsonify({'success': False, 'error': 'Cleanup failed or scenario not found'}), 400

    return jsonify({'success': True})


@app.route('/api/simulation/status', methods=['GET'])
def simulation_status():
    """Get current simulation status."""
    mgr = get_simulation_manager()
    status = mgr.get_status()
    return jsonify({'status': status})


@app.route('/api/simulation/results/<run_id>', methods=['GET'])
def simulation_results(run_id):
    """Get results for a completed simulation run."""
    mgr = get_simulation_manager()
    run_id = run_id.replace("'", "")[:20]
    results = mgr.get_results(run_id)
    if results is None:
        return jsonify({'success': False, 'error': 'Run not found'}), 404
    return jsonify({'success': True, 'results': results})


# =============================================================================
# Remediation Playbooks
# =============================================================================

import uuid as _uuid

_REMEDIATION_PLAYBOOKS_SEED = [
    {"alert_type": "dependency_anomaly",  "action_name": "Reset PostgreSQL Config",              "action_type": "pg_config_reset",  "action_params": "{}", "description": "Resets all PostgreSQL config parameters to defaults",                        "risk_level": "medium"},
    {"alert_type": "error_spike",         "action_name": "Disable Payment Failure Flag",         "action_type": "feature_flag",     "action_params": '{"flag":"paymentFailure","variant":"off"}', "description": "Disables the payment failure feature flag to stop injected errors",     "risk_level": "low"},
    {"alert_type": "dependency_anomaly",  "action_name": "Disable Payment Failure Flag",         "action_type": "feature_flag",     "action_params": '{"flag":"paymentFailure","variant":"off"}', "description": "Disables the payment failure feature flag to stop injected errors",     "risk_level": "low"},
    {"alert_type": "anomaly",            "action_name": "Disable Recommendation Cache Failure",  "action_type": "feature_flag",     "action_params": '{"flag":"recommendationCacheFailure","variant":"off"}', "description": "Disables the recommendation cache failure flag to restore normal memory usage", "risk_level": "low"},
    {"alert_type": "anomaly",            "action_name": "Disable Kafka Queue Problems",          "action_type": "feature_flag",     "action_params": '{"flag":"kafkaQueueProblems","variant":"off"}', "description": "Disables the Kafka queue problems flag to restore normal throughput",          "risk_level": "low"},
    {"alert_type": "trend",              "action_name": "Clean Disk Fill Temp Files",             "action_type": "disk_fill_cleanup","action_params": "{}", "description": "Removes temporary simulation files from the PostgreSQL data directory",         "risk_level": "low"},
    {"alert_type": "trend",              "action_name": "Clean Disk Fill Temp Files (resource)",  "action_type": "disk_fill_cleanup","action_params": "{}", "description": "Removes temporary simulation files to free disk space",                        "risk_level": "low"},
]


def _seed_remediation_playbooks():
    """Seed the remediation_playbooks table if empty. Called once at startup."""
    try:
        executor = get_query_executor()
        result = executor.execute_query("SELECT COUNT(*) as cnt FROM remediation_playbooks LIMIT 1")
        if result['success'] and result['rows'] and result['rows'][0].get('cnt', 0) > 0:
            print("[WebUI] Remediation playbooks already seeded")
            return

        now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        for pb in _REMEDIATION_PLAYBOOKS_SEED:
            pid = str(_uuid.uuid4())[:8]
            params_escaped = pb['action_params'].replace("'", "''")
            desc_escaped = pb['description'].replace("'", "''")
            sql = f"""
                INSERT INTO remediation_playbooks (
                    playbook_id, alert_type, action_name, action_type,
                    action_params, description, risk_level, created_at
                ) VALUES (
                    '{pid}', '{pb["alert_type"]}', '{pb["action_name"]}', '{pb["action_type"]}',
                    '{params_escaped}', '{desc_escaped}', '{pb["risk_level"]}',
                    TIMESTAMP '{now_str}'
                )
            """
            executor.execute_write(sql)
        print(f"[WebUI] Seeded {len(_REMEDIATION_PLAYBOOKS_SEED)} remediation playbooks")
    except Exception as e:
        print(f"[WebUI] Failed to seed remediation playbooks: {e}")


def _update_remediation_resolution(executor, alert_id):
    """When an alert resolves, update any pending remediation_log entries with resolution time."""
    try:
        update_sql = f"""
            UPDATE remediation_log
            SET alert_resolved_within_minutes = (
                EXTRACT(EPOCH FROM (NOW() - executed_at)) / 60.0
            )
            WHERE alert_id = '{alert_id}'
              AND alert_resolved_within_minutes IS NULL
        """
        executor.execute_write(update_sql)
    except Exception as e:
        print(f"[WebUI] Failed to update remediation resolution: {e}")


@app.route('/api/alerts/<alert_id>/remediations', methods=['GET'])
def get_alert_remediations(alert_id):
    """Get available remediation actions for an alert."""
    executor = get_query_executor()

    # Look up the alert to get its type
    alert_result = executor.execute_query(
        f"SELECT alert_type, service_name FROM alerts WHERE alert_id = '{alert_id}' LIMIT 1"
    )
    if not alert_result['success'] or not alert_result['rows']:
        return jsonify({'remediations': []})

    alert_type = alert_result['rows'][0].get('alert_type', '')

    # Get matching playbooks
    playbooks_result = executor.execute_query(f"""
        SELECT playbook_id, action_name, action_type, action_params,
               description, risk_level
        FROM remediation_playbooks
        WHERE alert_type = '{alert_type}'
    """)
    if not playbooks_result['success']:
        return jsonify({'remediations': []})

    remediations = []
    for pb in playbooks_result['rows']:
        pid = pb['playbook_id']
        # Get success rate for this playbook
        stats_result = executor.execute_query(f"""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successes
            FROM remediation_log
            WHERE playbook_id = '{pid}'
        """)
        total = 0
        successes = 0
        if stats_result['success'] and stats_result['rows']:
            total = stats_result['rows'][0].get('total', 0) or 0
            successes = stats_result['rows'][0].get('successes', 0) or 0

        success_rate = round(successes / total * 100) if total > 0 else None

        remediations.append({
            'playbook_id': pid,
            'action_name': pb.get('action_name'),
            'action_type': pb.get('action_type'),
            'description': pb.get('description'),
            'risk_level': pb.get('risk_level'),
            'success_rate': success_rate,
            'times_executed': total,
        })

    return jsonify({'remediations': remediations})


@app.route('/api/alerts/<alert_id>/remediate', methods=['POST'])
def remediate_alert(alert_id):
    """Execute a remediation action for an alert."""
    data = request.json or {}
    playbook_id = data.get('playbook_id', '')
    if not playbook_id:
        return jsonify({'success': False, 'error': 'playbook_id is required'}), 400

    executor = get_query_executor()

    # Look up playbook
    pb_result = executor.execute_query(
        f"SELECT action_name, action_type, action_params, risk_level FROM remediation_playbooks WHERE playbook_id = '{playbook_id}' LIMIT 1"
    )
    if not pb_result['success'] or not pb_result['rows']:
        return jsonify({'success': False, 'error': 'Playbook not found'}), 404
    pb = pb_result['rows'][0]

    # Look up alert
    alert_result = executor.execute_query(
        f"SELECT alert_id, service_name, alert_type FROM alerts WHERE alert_id = '{alert_id}' LIMIT 1"
    )
    if not alert_result['success'] or not alert_result['rows']:
        return jsonify({'success': False, 'error': 'Alert not found'}), 404
    alert = alert_result['rows'][0]

    # Parse action_params
    try:
        params = json.loads(pb.get('action_params', '{}'))
    except (json.JSONDecodeError, TypeError):
        params = {}

    # Execute remediation
    from failure_simulator import execute_remediation
    result = execute_remediation(pb['action_type'], params)

    # Log the execution
    exec_id = str(_uuid.uuid4())[:8]
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    status = 'success' if result.get('success') else 'failed'
    msg_escaped = result.get('message', '').replace("'", "''")
    params_escaped = pb.get('action_params', '{}').replace("'", "''")

    log_sql = f"""
        INSERT INTO remediation_log (
            execution_id, playbook_id, alert_id, service_name, alert_type,
            action_name, action_type, action_params, executed_at,
            executed_by, status, result_message
        ) VALUES (
            '{exec_id}', '{playbook_id}', '{alert_id}', '{alert.get("service_name", "")}',
            '{alert.get("alert_type", "")}', '{pb.get("action_name", "")}',
            '{pb.get("action_type", "")}', '{params_escaped}',
            TIMESTAMP '{now_str}', 'user', '{status}', '{msg_escaped}'
        )
    """
    executor.execute_write(log_sql)

    return jsonify({
        'success': result.get('success', False),
        'message': result.get('message', ''),
        'execution_id': exec_id,
    })


@app.route('/api/remediations/log', methods=['GET'])
def get_remediation_log():
    """Get recent remediation executions."""
    executor = get_query_executor()
    service = request.args.get('service', '')
    limit = min(int(request.args.get('limit', 50)), 100)

    conditions = []
    if service:
        conditions.append(f"service_name = '{service}'")

    where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""

    result = executor.execute_query(f"""
        SELECT execution_id, playbook_id, alert_id, service_name, alert_type,
               action_name, action_type, executed_at, executed_by,
               status, result_message, alert_resolved_within_minutes
        FROM remediation_log
        {where_clause}
        ORDER BY executed_at DESC
        LIMIT {limit}
    """)

    if result['success']:
        return jsonify({'log': result['rows']})
    return jsonify({'log': []})


# =============================================================================
# Main
# =============================================================================

if __name__ == '__main__':
    # Validate config
    errors = []
    if not ANTHROPIC_API_KEY:
        errors.append("ANTHROPIC_API_KEY is required")
    if not TRINO_HOST:
        errors.append("TRINO_HOST is required")
    if not TRINO_AVAILABLE:
        errors.append("trino package not installed")

    if errors:
        print("Configuration errors:")
        for e in errors:
            print(f"  - {e}")
        exit(1)

    print("Starting Observability Diagnostic Web UI...")
    print(f"Trino: {TRINO_HOST}:{TRINO_PORT}")
    print(f"Model: {ANTHROPIC_MODEL}")

    # Seed remediation playbooks on startup
    try:
        _seed_remediation_playbooks()
    except Exception as e:
        print(f"[WebUI] Remediation seed skipped: {e}")

    print("\nOpen http://localhost:5000 in your browser\n")

    # threaded=True allows concurrent request handling so the browser's
    # parallel API calls don't queue behind each other (each Trino round-trip
    # takes 300-1000ms; without threading, 7 concurrent requests = 3.5s serial).
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
