-- =============================================================================
-- Drop Existing Tables (Fresh Install)
-- =============================================================================
DROP TABLE IF EXISTS vast."csnow-db|otel".logs_otel_analytic;
DROP TABLE IF EXISTS vast."csnow-db|otel".metrics_otel_analytic;
DROP TABLE IF EXISTS vast."csnow-db|otel".span_events_otel_analytic;
DROP TABLE IF EXISTS vast."csnow-db|otel".span_links_otel_analytic;
DROP TABLE IF EXISTS vast."csnow-db|otel".traces_otel_analytic;
DROP TABLE IF EXISTS vast."csnow-db|otel".service_baselines;
DROP TABLE IF EXISTS vast."csnow-db|otel".anomaly_scores;
DROP TABLE IF EXISTS vast."csnow-db|otel".alerts;
DROP TABLE IF EXISTS vast."csnow-db|otel".alert_investigations;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_services;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_dependencies;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_host_services;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_hosts;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_database_hosts;
DROP TABLE IF EXISTS vast."csnow-db|otel".topology_containers;
DROP TABLE IF EXISTS vast."csnow-db|otel".incident_context;
DROP TABLE IF EXISTS vast."csnow-db|otel".resource_predictions;
DROP TABLE IF EXISTS vast."csnow-db|otel".incident_patterns;
DROP TABLE IF EXISTS vast."csnow-db|otel".simulation_runs;

-- vast."csnow-db|otel".logs_otel_analytic definition

CREATE TABLE vast."csnow-db|otel".logs_otel_analytic (
   timestamp timestamp(9),
   service_name varchar,
   severity_number integer,
   severity_text varchar,
   body_text varchar,
   trace_id varchar,
   span_id varchar,
   attributes_json varchar
);

-- vast."csnow-db|otel".metrics_otel_analytic definition

CREATE TABLE vast."csnow-db|otel".metrics_otel_analytic (
   timestamp timestamp(9),
   service_name varchar,
   metric_name varchar,
   metric_unit varchar,
   value_double double,
   attributes_flat varchar
);

-- vast."csnow-db|otel".span_events_otel_analytic definition

CREATE TABLE vast."csnow-db|otel".span_events_otel_analytic (
   timestamp timestamp(9),
   trace_id varchar,
   span_id varchar,
   service_name varchar,
   span_name varchar,
   event_name varchar,
   event_attributes_json varchar,
   exception_type varchar,
   exception_message varchar,
   exception_stacktrace varchar,
   gen_ai_system varchar,
   gen_ai_operation varchar,
   gen_ai_request_model varchar,
   gen_ai_usage_prompt_tokens integer,
   gen_ai_usage_completion_tokens integer
);

-- vast."csnow-db|otel".span_links_otel_analytic definition

CREATE TABLE vast."csnow-db|otel".span_links_otel_analytic (
   trace_id varchar,
   span_id varchar,
   service_name varchar,
   span_name varchar,
   linked_trace_id varchar,
   linked_span_id varchar,
   linked_trace_state varchar,
   link_attributes_json varchar
);

-- vast."csnow-db|otel".traces_otel_analytic definition

CREATE TABLE vast."csnow-db|otel".traces_otel_analytic (
   trace_id varchar,
   span_id varchar,
   parent_span_id varchar,
   start_time timestamp(9),
   duration_ns bigint,
   service_name varchar,
   span_name varchar,
   span_kind varchar,
   status_code varchar,
   http_status integer,
   db_system varchar,
   attributes_json varchar
);

-- =============================================================================
-- Predictive Maintenance Tables
-- =============================================================================

-- Service baselines: stores computed statistical baselines per service/metric
CREATE TABLE vast."csnow-db|otel".service_baselines (
   computed_at timestamp(9),
   service_name varchar,
   metric_type varchar,           -- 'error_rate', 'latency_p50', 'latency_p95', 'latency_p99', 'throughput'
   baseline_mean double,
   baseline_stddev double,
   baseline_min double,
   baseline_max double,
   baseline_p50 double,
   baseline_p95 double,
   baseline_p99 double,
   sample_count bigint,
   window_hours integer           -- how many hours of data used to compute baseline
);

-- Anomaly scores: stores ML model predictions and anomaly detection results
CREATE TABLE vast."csnow-db|otel".anomaly_scores (
   timestamp timestamp(9),
   service_name varchar,
   metric_type varchar,
   current_value double,
   expected_value double,
   baseline_mean double,
   baseline_stddev double,
   z_score double,
   anomaly_score double,          -- 0.0 to 1.0, higher = more anomalous
   is_anomaly boolean,
   detection_method varchar       -- 'zscore', 'isolation_forest', 'trend', 'threshold'
);

-- Alerts: stores generated alerts with severity and status
-- Alert types include:
--   Symptom-based: 'error_spike', 'latency_degradation', 'throughput_drop', 'anomaly', 'trend', 'service_down'
--   Root cause: 'db_connection_failure', 'db_slow_queries', 'dependency_failure',
--               'dependency_latency', 'exception_surge', 'new_exception_type'
CREATE TABLE vast."csnow-db|otel".alerts (
   alert_id varchar,
   created_at timestamp(9),
   updated_at timestamp(9),
   service_name varchar,
   alert_type varchar,            -- See alert types above
   severity varchar,              -- 'info', 'warning', 'critical'
   title varchar,
   description varchar,
   metric_type varchar,
   current_value double,
   threshold_value double,
   baseline_value double,
   z_score double,
   status varchar,                -- 'active', 'acknowledged', 'resolved', 'archived'
   resolved_at timestamp(9),
   auto_resolved boolean
);

-- Alert investigations: LLM-powered root cause analysis
CREATE TABLE vast."csnow-db|otel".alert_investigations (
   investigation_id varchar,
   alert_id varchar,
   investigated_at timestamp(9),
   service_name varchar,
   alert_type varchar,
   model_used varchar,              -- 'claude-3-5-haiku-20241022'
   root_cause_summary varchar,
   recommended_actions varchar,
   supporting_evidence varchar,     -- JSON with relevant traces/errors found
   queries_executed integer,
   tokens_used integer
);

-- =============================================================================
-- Topology Inference Tables
-- =============================================================================

-- Active services registry (materialized from traces)
CREATE TABLE vast."csnow-db|otel".topology_services (
   service_name varchar,
   service_type varchar,             -- 'application', 'database', 'infrastructure'
   span_count bigint,
   error_pct double,
   avg_latency_ms double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Service-to-service and service-to-database dependencies
CREATE TABLE vast."csnow-db|otel".topology_dependencies (
   source_service varchar,
   target_service varchar,
   dependency_type varchar,          -- 'service', 'database'
   call_count bigint,
   avg_latency_ms double,
   error_pct double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Host-to-service mappings
CREATE TABLE vast."csnow-db|otel".topology_host_services (
   host_name varchar,
   service_name varchar,
   source varchar,                   -- 'traces', 'metrics'
   data_point_count bigint,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Host registry with system metrics
CREATE TABLE vast."csnow-db|otel".topology_hosts (
   host_name varchar,
   os_type varchar,
   cpu_pct double,
   memory_pct double,
   disk_pct double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Database-to-host mappings (from metric attributes)
CREATE TABLE vast."csnow-db|otel".topology_database_hosts (
   db_system varchar,
   host_name varchar,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Container registry with resource metrics
CREATE TABLE vast."csnow-db|otel".topology_containers (
   container_name varchar,
   cpu_pct double,
   memory_pct double,
   memory_usage_mb double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- =============================================================================
-- Predictive Alerts: Incident Context, Predictions, Patterns, Simulations
-- =============================================================================

-- Incident context: snapshot of surrounding telemetry when an alert fires
CREATE TABLE vast."csnow-db|otel".incident_context (
   context_id varchar,
   alert_id varchar,
   captured_at timestamp(9),
   service_name varchar,
   alert_type varchar,
   severity varchar,
   fingerprint varchar,
   metrics_snapshot varchar,
   error_traces varchar,
   log_snapshot varchar,
   topology_snapshot varchar,
   baseline_values varchar,
   anomaly_scores varchar
);

-- Resource predictions: linear regression predictions for resource exhaustion
CREATE TABLE vast."csnow-db|otel".resource_predictions (
   prediction_id varchar,
   created_at timestamp(9),
   host_name varchar,
   resource_type varchar,
   service_name varchar,
   current_value double,
   trend_slope double,
   trend_r_squared double,
   predicted_exhaustion_at timestamp(9),
   threshold_value double,
   hours_until_exhaustion double,
   confidence varchar,
   status varchar
);

-- Incident patterns: aggregated patterns from recurring incidents
CREATE TABLE vast."csnow-db|otel".incident_patterns (
   pattern_id varchar,
   fingerprint varchar,
   service_name varchar,
   alert_type varchar,
   occurrence_count integer,
   first_seen timestamp(9),
   last_seen timestamp(9),
   avg_duration_minutes double,
   common_root_cause varchar,
   precursor_signals varchar,
   updated_at timestamp(9)
);

-- Simulation runs: tracks simulation scenarios for correlation with predictions
CREATE TABLE vast."csnow-db|otel".simulation_runs (
   run_id varchar,
   started_at timestamp(9),
   ended_at timestamp(9),
   scenario_name varchar,
   scenario_config varchar,
   status varchar,
   steps_completed varchar,
   predicted_alerts varchar,
   actual_alerts varchar
);

