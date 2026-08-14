CREATE TABLE retention_guard (
    singleton INTEGER PRIMARY KEY CHECK (singleton=1),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1))
);
INSERT INTO retention_guard VALUES (1,0);

CREATE TABLE retention_authorizations (
    authorization_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    system_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    authorized_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at>authorized_at),
    selected_count INTEGER NOT NULL CHECK (selected_count>=0),
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    UNIQUE(plan_id,plan_digest),
    FOREIGN KEY(decision_id,system_id) REFERENCES user_decisions(decision_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_retention_authorizations_plan
ON retention_authorizations(plan_id,plan_digest,expires_at,authorization_id);

CREATE TABLE retention_executions (
    execution_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    authorization_id TEXT NOT NULL REFERENCES retention_authorizations(authorization_id) ON DELETE RESTRICT,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    selected_counts_json TEXT NOT NULL,
    deleted_counts_json TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCEEDED','FAILED')),
    failure_code TEXT,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    CHECK ((outcome='SUCCEEDED' AND failure_code IS NULL) OR
           (outcome='FAILED' AND failure_code IS NOT NULL))
);
CREATE INDEX idx_retention_executions_time
ON retention_executions(completed_at,execution_id);

DROP TRIGGER trg_exception_no_delete;
CREATE TRIGGER trg_exception_no_delete BEFORE DELETE ON exceptions
WHEN (SELECT enabled FROM retention_guard WHERE singleton=1)!=1
BEGIN SELECT RAISE(ABORT,'exception history deletion requires retention authorization'); END;

DROP TRIGGER trg_investigation_no_delete;
CREATE TRIGGER trg_investigation_no_delete BEFORE DELETE ON investigations
WHEN (SELECT enabled FROM retention_guard WHERE singleton=1)!=1
BEGIN SELECT RAISE(ABORT,'investigation deletion requires retention authorization'); END;

DROP TRIGGER trg_investigation_status_event_no_delete;
CREATE TRIGGER trg_investigation_status_event_no_delete BEFORE DELETE ON investigation_status_events
WHEN (SELECT enabled FROM retention_guard WHERE singleton=1)!=1
BEGIN SELECT RAISE(ABORT,'investigation event deletion requires retention authorization'); END;

DROP TRIGGER trg_capability_event_no_delete;
CREATE TRIGGER trg_capability_event_no_delete BEFORE DELETE ON capability_execution_events
WHEN (SELECT enabled FROM retention_guard WHERE singleton=1)!=1
BEGIN SELECT RAISE(ABORT,'capability event deletion requires retention authorization'); END;

CREATE TRIGGER trg_retention_authorization_immutable BEFORE UPDATE ON retention_authorizations
BEGIN SELECT RAISE(ABORT,'retention authorization is immutable'); END;
CREATE TRIGGER trg_retention_authorization_no_delete BEFORE DELETE ON retention_authorizations
BEGIN SELECT RAISE(ABORT,'retention authorization history is append-only'); END;
CREATE TRIGGER trg_retention_execution_immutable BEFORE UPDATE ON retention_executions
BEGIN SELECT RAISE(ABORT,'retention audit is immutable'); END;
CREATE TRIGGER trg_retention_execution_no_delete BEFORE DELETE ON retention_executions
BEGIN SELECT RAISE(ABORT,'retention audit history is append-only'); END;
