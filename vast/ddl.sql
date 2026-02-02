-- =============================================================================
-- Drop Existing Tables (Fresh Install)
-- =============================================================================
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".logs_otel_analytic;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".metrics_otel_analytic;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".span_events_otel_analytic;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".span_links_otel_analytic;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".traces_otel_analytic;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".service_baselines;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".anomaly_scores;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".alerts;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".alert_investigations;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_services;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_dependencies;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_host_services;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_hosts;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_database_hosts;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".topology_containers;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".incident_context;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".resource_predictions;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".incident_patterns;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".simulation_runs;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".service_metrics_1m;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".db_metrics_1m;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".operation_metrics_5m;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".job_status;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".pinned_charts;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".threshold_overrides;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".remediation_playbooks;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".remediation_log;
DROP TABLE IF EXISTS ${CATALOG}."${SCHEMA}".entity_resource_baselines;

-- ${CATALOG}."${SCHEMA}".logs_otel_analytic definition

CREATE TABLE ${CATALOG}."${SCHEMA}".logs_otel_analytic (
   timestamp timestamp(9),
   service_name varchar,
   severity_number integer,
   severity_text varchar,
   body_text varchar,
   trace_id varchar,
   span_id varchar,
   attributes_json varchar
);

-- ${CATALOG}."${SCHEMA}".metrics_otel_analytic definition

CREATE TABLE ${CATALOG}."${SCHEMA}".metrics_otel_analytic (
   timestamp timestamp(9),
   service_name varchar,
   metric_name varchar,
   metric_unit varchar,
   value_double double,
   attributes_flat varchar
);

-- ${CATALOG}."${SCHEMA}".span_events_otel_analytic definition

CREATE TABLE ${CATALOG}."${SCHEMA}".span_events_otel_analytic (
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

-- ${CATALOG}."${SCHEMA}".span_links_otel_analytic definition

CREATE TABLE ${CATALOG}."${SCHEMA}".span_links_otel_analytic (
   trace_id varchar,
   span_id varchar,
   service_name varchar,
   span_name varchar,
   linked_trace_id varchar,
   linked_span_id varchar,
   linked_trace_state varchar,
   link_attributes_json varchar
);

-- ${CATALOG}."${SCHEMA}".traces_otel_analytic definition

CREATE TABLE ${CATALOG}."${SCHEMA}".traces_otel_analytic (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".service_baselines (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".anomaly_scores (
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
--   Root cause: 'dependency_anomaly', 'exception_surge', 'new_exception_type'
CREATE TABLE ${CATALOG}."${SCHEMA}".alerts (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".alert_investigations (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_services (
   service_name varchar,
   service_type varchar,             -- 'application', 'database', 'infrastructure'
   span_count bigint,
   error_pct double,
   avg_latency_ms double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Service-to-service and service-to-database dependencies
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_dependencies (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_host_services (
   host_name varchar,
   service_name varchar,
   source varchar,                   -- 'traces', 'metrics'
   data_point_count bigint,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Host registry with system metrics
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_hosts (
   host_name varchar,
   os_type varchar,
   cpu_pct double,
   memory_pct double,
   disk_pct double,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Database-to-host mappings (from metric attributes)
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_database_hosts (
   db_system varchar,
   host_name varchar,
   last_seen timestamp(9),
   updated_at timestamp(9)
);

-- Container registry with resource metrics
CREATE TABLE ${CATALOG}."${SCHEMA}".topology_containers (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".incident_context (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".resource_predictions (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".incident_patterns (
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
CREATE TABLE ${CATALOG}."${SCHEMA}".simulation_runs (
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

-- =============================================================================
-- Metric Aggregation Rollup Tables
-- =============================================================================

-- Pre-aggregated service metrics (1-minute buckets)
CREATE TABLE ${CATALOG}."${SCHEMA}".service_metrics_1m (
   time_bucket   timestamp(9),
   service_name  varchar,
   avg_latency_ms   double,
   max_latency_ms   double,
   p95_latency_ms   double,
   request_count    bigint,
   error_count      bigint,
   error_pct        double
);

-- Pre-aggregated database metrics (1-minute buckets)
CREATE TABLE ${CATALOG}."${SCHEMA}".db_metrics_1m (
   time_bucket   timestamp(9),
   db_system     varchar,
   avg_latency_ms   double,
   max_latency_ms   double,
   query_count      bigint,
   error_count      bigint,
   error_pct        double
);

-- Pre-aggregated operation metrics (5-minute buckets)
CREATE TABLE ${CATALOG}."${SCHEMA}".operation_metrics_5m (
   time_bucket   timestamp(9),
   service_name  varchar,
   span_name     varchar,
   call_count    bigint,
   avg_latency_ms   double,
   error_count      bigint,
   error_pct        double
);

-- Background job status tracking
CREATE TABLE ${CATALOG}."${SCHEMA}".job_status (
    job_name      varchar,
    last_run_at   timestamp(9),
    cycle_duration_ms bigint,
    status        varchar,
    details_json  varchar,
    updated_at    timestamp(9)
);

-- Threshold overrides: manual and learned threshold adjustments
-- service_name: '*' = global (learned adjustments), otherwise entity name (manual)
-- override_type: 'manual' (absolute z-score) or 'learned' (additive delta)
-- created_by: 'system' or 'user'
CREATE TABLE ${CATALOG}."${SCHEMA}".threshold_overrides (
   service_name    varchar,
   metric_category varchar,
   override_type   varchar,
   threshold_value double,
   created_by      varchar,
   created_at      timestamp(9),
   updated_at      timestamp(9)
);

-- Pinned metric charts per entity
CREATE TABLE ${CATALOG}."${SCHEMA}".pinned_charts (
   pin_id        varchar,
   entity_type   varchar,
   entity_name   varchar,
   metric_name   varchar,
   display_name  varchar,
   created_at    timestamp(9)
);

-- =============================================================================
-- Remediation Playbooks
-- =============================================================================

-- Pre-defined catalog of fix actions mapped to alert types
CREATE TABLE ${CATALOG}."${SCHEMA}".remediation_playbooks (
    playbook_id     varchar,
    alert_type      varchar,
    action_name     varchar,
    action_type     varchar,
    action_params   varchar,
    description     varchar,
    risk_level      varchar,
    created_at      timestamp(9)
);

-- Tracks every execution of a playbook action with outcome
CREATE TABLE ${CATALOG}."${SCHEMA}".remediation_log (
    execution_id    varchar,
    playbook_id     varchar,
    alert_id        varchar,
    service_name    varchar,
    alert_type      varchar,
    action_name     varchar,
    action_type     varchar,
    action_params   varchar,
    executed_at     timestamp(9),
    executed_by     varchar,
    status          varchar,
    result_message  varchar,
    alert_resolved_within_minutes double
);

-- Entity resource baselines: rolling snapshots for z-score anomaly detection
CREATE TABLE ${CATALOG}."${SCHEMA}".entity_resource_baselines (
   entity_type   varchar,
   entity_name   varchar,
   metric_name   varchar,
   sample_value  double,
   sampled_at    timestamp(9)
);

