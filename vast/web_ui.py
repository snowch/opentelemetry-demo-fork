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
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, render_template, request, jsonify, Response
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
        'traces_table': 'spans_otel_analytic',
        'traces_time_field': 'timestamp',
        'traces_filter': "attributes_flat LIKE '%host.name={name}%'",
        'logs_filter': None,
        'logs_join': "l.service_name IN (SELECT DISTINCT service_name FROM spans_otel_analytic WHERE attributes_flat LIKE '%host.name={name}%' AND timestamp > NOW() - INTERVAL {interval} AND service_name IS NOT NULL AND service_name != '')",
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

    def execute_query(self, sql: str) -> Dict[str, Any]:
        """Execute a SQL query via Trino."""
        sql = sql.strip()

        if not sql.lower().startswith("select"):
            return {"success": False, "error": "Only SELECT queries are supported", "rows": [], "columns": []}

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
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            raw_rows = cursor.fetchall()

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

chat_sessions = {}

def get_or_create_session(session_id: str) -> List[Dict]:
    if session_id not in chat_sessions:
        chat_sessions[session_id] = []
    return chat_sessions[session_id]


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
        conversation_history.append({"role": "user", "content": user_message})

        # Keep history manageable
        if len(conversation_history) > 20:
            conversation_history = conversation_history[-20:]
            chat_sessions[session_id] = conversation_history

        client = get_anthropic_client()
        executor = get_query_executor()
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
    conversation_history.append({"role": "user", "content": user_message})

    # Keep history manageable
    if len(conversation_history) > 20:
        conversation_history = conversation_history[-20:]
        chat_sessions[session_id] = conversation_history

    client = get_anthropic_client()
    executor = get_query_executor()
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
        while response.stop_reason == "tool_use":
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
    """Get current system status."""
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
               SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) as errors,
               ROUND(100.0 * SUM(CASE WHEN status_code = 'ERROR' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 2) as error_pct,
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
    error_summary_query = """
    SELECT
        COUNT(*) as total_errors,
        COUNT(DISTINCT service_name) as affected_services
    FROM traces_otel_analytic
    WHERE status_code = 'ERROR'
      AND start_time > NOW() - INTERVAL '5' MINUTE
    """
    result = executor.execute_query(error_summary_query)
    if result['success'] and result['rows']:
        status['error_summary'] = result['rows'][0]

    # Get recent errors with trace_id and span_id for drill-down
    error_query = """
    SELECT trace_id, span_id, service_name, span_name, status_code,
           duration_ns / 1000000.0 as duration_ms,
           start_time
    FROM traces_otel_analytic
    WHERE status_code = 'ERROR'
      AND start_time > NOW() - INTERVAL '5' MINUTE
    ORDER BY start_time DESC
    LIMIT 10
    """
    result = executor.execute_query(error_query)
    if result['success']:
        status['recent_errors'] = result['rows']

    # Get host metrics - try topology table first, fall back to inline query
    topology_host_result = executor.execute_query("""
    SELECT host_name, os_type, cpu_pct, memory_pct, disk_pct, last_seen
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

    return jsonify(status)


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
    time_range = request.args.get('range', '1')  # hours

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
      AND time_bucket > NOW() - INTERVAL '{time_range}' HOUR
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
          AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
          AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
      AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
      AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
        'trace': []
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
    SELECT exception_type, exception_message
    FROM span_events_otel_analytic
    WHERE trace_id = '{trace_id}' AND span_id = '{span_id}'
      AND exception_type IS NOT NULL AND exception_type != ''
    LIMIT 1
    """
    result = executor.execute_query(exception_query)
    if result['success'] and result['rows']:
        data['exception'] = result['rows'][0]

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
    time_param = request.args.get('time', '5m')

    # Parse time parameter (e.g., "10s", "1m", "5m", "1h")
    time_value = int(time_param[:-1])
    time_unit = time_param[-1]

    if time_unit == 's':
        interval = f"'{time_value}' SECOND"
    elif time_unit == 'm':
        interval = f"'{time_value}' MINUTE"
    elif time_unit == 'h':
        interval = f"'{time_value}' HOUR"
    else:
        interval = "'5' MINUTE"  # default

    # Use rollup table for windows >= 5 minutes
    use_rollup = (time_unit == 'h') or (time_unit == 'm' and time_value >= 5)
    if use_rollup:
        rollup_query = f"""
        SELECT span_name,
               CAST(SUM(call_count) AS BIGINT) as call_count,
               ROUND(SUM(avg_latency_ms * call_count) / NULLIF(SUM(call_count), 0), 2) as avg_latency_ms,
               ROUND(100.0 * SUM(error_count) / NULLIF(SUM(call_count), 0), 2) as error_pct
        FROM operation_metrics_5m
        WHERE service_name = '{service_name}'
          AND time_bucket > NOW() - INTERVAL {interval}
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
      AND start_time > NOW() - INTERVAL {interval}
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
    time_range = request.args.get('range', '1')  # hours

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
      AND time_bucket > NOW() - INTERVAL '{time_range}' HOUR
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
          AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
          AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
      AND start_time > NOW() - INTERVAL '{time_range}' HOUR
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
      AND timestamp > NOW() - INTERVAL '{time_range}' HOUR
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
      AND timestamp > NOW() - INTERVAL '{time_range}' HOUR
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
            data['current_metrics'] = {
                'cpu_pct': row.get('cpu_pct'),
                'memory_pct': row.get('memory_pct'),
                'disk_pct': row.get('disk_pct')
            }
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
        FROM spans_otel_analytic
        WHERE attributes_flat LIKE '%host.name={host_name}%'
          AND timestamp > NOW() - INTERVAL {interval}
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

    return jsonify(data)


@app.route('/api/host/<host_name>/resource-history', methods=['GET'])
def host_resource_history(host_name):
    """Get 1-minute bucketed CPU, memory, disk utilization over the last hour."""
    executor = get_query_executor()

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
      AND timestamp > NOW() - INTERVAL '1' HOUR
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
            FROM spans_otel_analytic
            WHERE attributes_flat LIKE '%host.name={entity_name}%'
              AND timestamp > NOW() - INTERVAL '1' HOUR
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
    interval = parse_time_interval(request.args.get('time', '5m'))
    extra_where = build_trace_filters(request)

    traces_filter = config['traces_filter'].format(name=name, interval=interval)
    table = config['traces_table']
    time_field = config['traces_time_field']

    # For service, we don't need service_name in SELECT since it's the filter
    if entity_type == 'service':
        traces_query = f"""
        SELECT trace_id, span_id, span_name, span_kind, status_code,
               ROUND(duration_ns / 1000000.0, 2) as duration_ms,
               start_time, db_system
        FROM {table}
        WHERE {traces_filter}
          AND {time_field} > NOW() - INTERVAL {interval}
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
          AND {time_field} > NOW() - INTERVAL {interval}
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
    interval = parse_time_interval(request.args.get('time', '5m'))

    if config['logs_filter']:
        # Direct filter (service)
        extra_where = build_log_filters(request)
        logs_filter = config['logs_filter'].format(name=name, interval=interval)
        logs_query = f"""
        SELECT timestamp, severity_text, body, trace_id, span_id
        FROM logs_otel_analytic
        WHERE {logs_filter}
          AND timestamp > NOW() - INTERVAL {interval}
          {extra_where}
        ORDER BY timestamp DESC
        LIMIT {limit}
        """
    elif config['logs_join']:
        # Subquery join (database, host)
        extra_where = build_log_filters(request, 'l')
        join_filter = config['logs_join'].format(name=name, interval=interval)
        logs_query = f"""
        SELECT l.timestamp, l.service_name, l.severity_text, l.body, l.trace_id, l.span_id
        FROM logs_otel_analytic l
        WHERE {join_filter}
          AND l.timestamp > NOW() - INTERVAL {interval}
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
    interval = parse_time_interval(request.args.get('time', '5m'))

    extra_where = ''
    search_filter = request.args.get('search', '')
    if search_filter:
        extra_where += f" AND LOWER(metric_name) LIKE LOWER('%{search_filter}%')"

    metrics_filter = config['metrics_filter'].format(name=name, interval=interval)

    metrics_query = f"""
    SELECT metric_name,
           COUNT(*) as data_points,
           ROUND(AVG(value_double), 4) as avg_value,
           ROUND(MIN(value_double), 4) as min_value,
           ROUND(MAX(value_double), 4) as max_value,
           MAX(timestamp) as last_seen
    FROM metrics_otel_analytic
    WHERE {metrics_filter}
      AND timestamp > NOW() - INTERVAL {interval}
      {extra_where}
    GROUP BY metric_name
    ORDER BY data_points DESC
    LIMIT {limit}
    """

    result = executor.execute_query(metrics_query)
    if result['success']:
        return jsonify({'metrics': result['rows']})
    return jsonify({'metrics': [], 'error': result.get('error')})


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
# Alerts API
# =============================================================================

@app.route('/api/alerts/config', methods=['GET'])
def get_alerts_config():
    """Get investigation configuration for display in UI."""
    return jsonify({
        'investigate_critical_only': INVESTIGATE_CRITICAL_ONLY
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get alerts with optional filtering."""
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

    return jsonify(data)


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
        return jsonify({'success': True, 'message': f'Alert {alert_id} archived'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/alerts/<alert_id>/investigate', methods=['POST'])
def investigate_alert(alert_id):
    """Manually trigger investigation for an alert."""
    executor = get_query_executor()

    # Get alert details
    alert_query = f"""
    SELECT alert_id, service_name, alert_type, severity, title, description
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

    system_prompt = """You are an expert SRE assistant performing root cause analysis.
You have access to observability data via SQL queries (Trino/Presto dialect).

Available tables and their EXACT columns (use ONLY these):

traces_otel_analytic (time column: start_time):
  start_time, trace_id, span_id, parent_span_id, service_name, span_name,
  span_kind, status_code, http_status, duration_ns, db_system

logs_otel_analytic (time column: timestamp):
  timestamp, service_name, severity_number, severity_text, body_text, trace_id, span_id

span_events_otel_analytic (time column: timestamp):
  timestamp, trace_id, span_id, service_name, span_name, event_name,
  exception_type, exception_message, exception_stacktrace

CRITICAL SQL RULES:
- For traces: WHERE start_time > current_timestamp - INTERVAL '15' MINUTE
- For logs/events: WHERE timestamp > current_timestamp - INTERVAL '15' MINUTE
- NO 'attributes' column exists - do not use it
- NO semicolons, NO square brackets
- Interval: INTERVAL '15' MINUTE (quoted number)

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

Find the root cause by querying the data. Focus on the last 15 minutes."""

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages = [{"role": "user", "content": user_prompt}]
    queries_executed = 0
    total_tokens = 0

    for _ in range(5):
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
    """Get recent alert activity (created, resolved, auto-resolved)."""
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

    return jsonify(data)


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
    """Get active resource predictions."""
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

    return jsonify(data)


@app.route('/api/jobs/status', methods=['GET'])
def get_jobs_status():
    """Get status of background services."""
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
    return jsonify({'jobs': jobs})


@app.route('/api/incidents/context/<alert_id>', methods=['GET'])
def get_incident_context(alert_id):
    """Get incident context snapshot for an alert."""
    executor = get_query_executor()

    data = {'context': None, 'pattern': None}

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

    return jsonify(data)


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
    print("\nOpen http://localhost:5000 in your browser\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
