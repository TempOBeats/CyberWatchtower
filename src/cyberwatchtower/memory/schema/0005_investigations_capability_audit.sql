CREATE TABLE investigations (
    investigation_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('OPEN','PAUSED','COMPLETED','CANCELLED')),
    title TEXT NOT NULL,
    actor TEXT NOT NULL,
    opened_at TEXT NOT NULL,
    closed_at TEXT,
    final_disposition TEXT,
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, system_id),
    CHECK ((status IN ('OPEN','PAUSED') AND closed_at IS NULL AND final_disposition IS NULL)
        OR (status IN ('COMPLETED','CANCELLED') AND closed_at IS NOT NULL AND final_disposition IS NOT NULL))
);
CREATE INDEX idx_investigations_open ON investigations(system_id,status,opened_at,investigation_id);

CREATE TABLE investigation_status_events (
    event_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('OPEN','PAUSED','COMPLETED','CANCELLED')),
    occurred_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_investigation_status_time ON investigation_status_events(system_id,investigation_id,occurred_at,event_id);

CREATE TABLE investigation_findings (
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    relationship TEXT NOT NULL CHECK (relationship IN ('SUBJECT','RELATED')),
    attached_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    PRIMARY KEY(investigation_id,finding_id,relationship),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT,
    FOREIGN KEY(system_id,finding_id) REFERENCES findings(system_id,finding_id) ON DELETE RESTRICT
);
CREATE INDEX idx_investigation_findings_lookup ON investigation_findings(system_id,finding_id,relationship,attached_at);

CREATE TABLE investigation_scopes (
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('SERVICE','LISTENER')),
    scope_json TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    attached_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    PRIMARY KEY(investigation_id,scope_digest),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_investigation_scopes_lookup ON investigation_scopes(system_id,scope_digest,attached_at);

CREATE TABLE investigation_evidence (
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN ('REPORT','FINDING','OCCURRENCE','LIFECYCLE_EVENT','RECOMMENDATION','CAPABILITY_RESULT','USER_DECISION')),
    source_record_id TEXT NOT NULL,
    epistemic_role TEXT NOT NULL CHECK (epistemic_role IN ('OBSERVED_FACT','DETERMINISTIC_DERIVATION','EXTERNAL_KNOWLEDGE','USER_ASSERTION','USER_DECISION','MODEL_INTERPRETATION')),
    consulted_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    PRIMARY KEY(investigation_id,evidence_id),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_investigation_evidence_time ON investigation_evidence(system_id,investigation_id,consulted_at,evidence_id);

CREATE TABLE investigation_questions (
    question_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    intent TEXT NOT NULL CHECK (intent IN ('WHY_DANGEROUS','WHAT_CHANGED','FIX_FIRST','SECURITY_BRIEFING','INVESTIGATE_FINDING','INVESTIGATE_SERVICE')),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('FINDING','SERVICE','LISTENER','REPORT','INVESTIGATION')),
    subject_id TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_investigation_questions_time ON investigation_questions(system_id,investigation_id,recorded_at,question_id);

CREATE TABLE capability_executions (
    execution_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    investigation_id TEXT,
    capability_id TEXT NOT NULL,
    permission_class TEXT NOT NULL CHECK (permission_class IN ('READ_ONLY','USER_APPROVAL_REQUIRED','PROHIBITED')),
    status TEXT NOT NULL CHECK (status IN ('PROPOSED','DENIED','APPROVAL_REQUIRED','SUCCEEDED','FAILED')),
    requested_at TEXT NOT NULL,
    authorization_decision_id TEXT,
    started_at TEXT,
    completed_at TEXT,
    parameter_summary_json TEXT NOT NULL,
    result_summary_json TEXT,
    error_code TEXT,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    UNIQUE(execution_id,system_id),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT,
    FOREIGN KEY(authorization_decision_id,system_id) REFERENCES user_decisions(decision_id,system_id) ON DELETE RESTRICT,
    CHECK (status!='SUCCEEDED' OR (started_at IS NOT NULL AND completed_at IS NOT NULL AND result_summary_json IS NOT NULL AND error_code IS NULL)),
    CHECK (status!='FAILED' OR (completed_at IS NOT NULL AND error_code IS NOT NULL AND result_summary_json IS NULL)),
    CHECK (status NOT IN ('DENIED','APPROVAL_REQUIRED') OR (started_at IS NULL AND result_summary_json IS NULL))
);
CREATE INDEX idx_capability_investigation ON capability_executions(system_id,investigation_id,requested_at,execution_id);

CREATE TABLE capability_execution_events (
    event_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PROPOSED','DENIED','APPROVAL_REQUIRED','SUCCEEDED','FAILED')),
    occurred_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    FOREIGN KEY(execution_id,system_id) REFERENCES capability_executions(execution_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_capability_event_time ON capability_execution_events(system_id,execution_id,occurred_at,event_id);

CREATE TABLE investigation_recommendations (
    investigation_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    recommendation_event_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY'),
    PRIMARY KEY(investigation_id,recommendation_event_id),
    FOREIGN KEY(investigation_id,system_id) REFERENCES investigations(investigation_id,system_id) ON DELETE RESTRICT,
    FOREIGN KEY(recommendation_event_id,system_id) REFERENCES recommendations_shown(recommendation_event_id,system_id) ON DELETE RESTRICT
);

CREATE TABLE conversation_references (
    reference_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    session_id TEXT NOT NULL,
    reference_type TEXT NOT NULL CHECK (reference_type IN ('FINDING','ACTION','INVESTIGATION','REPORT')),
    target_id TEXT NOT NULL,
    reference_state TEXT NOT NULL CHECK (reference_state IN ('FOCUSED','RECENTLY_MENTIONED')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at>created_at),
    provenance TEXT NOT NULL CHECK (provenance='DERIVED_HISTORY')
);
CREATE INDEX idx_conversation_references_active ON conversation_references(system_id,session_id,created_at,expires_at,reference_id);

CREATE TRIGGER trg_investigation_meaning_immutable
BEFORE UPDATE ON investigations
WHEN NEW.investigation_id IS NOT OLD.investigation_id OR NEW.system_id IS NOT OLD.system_id OR
 NEW.title IS NOT OLD.title OR NEW.actor IS NOT OLD.actor OR NEW.opened_at IS NOT OLD.opened_at OR
 NEW.provenance IS NOT OLD.provenance OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT,'investigation identity is immutable'); END;

CREATE TRIGGER trg_investigation_no_delete BEFORE DELETE ON investigations
BEGIN SELECT RAISE(ABORT,'investigation history is append-only'); END;

CREATE TRIGGER trg_investigation_status_event_immutable BEFORE UPDATE ON investigation_status_events
BEGIN SELECT RAISE(ABORT,'investigation status history is immutable'); END;
CREATE TRIGGER trg_investigation_status_event_no_delete BEFORE DELETE ON investigation_status_events
BEGIN SELECT RAISE(ABORT,'investigation status history is append-only'); END;

CREATE TRIGGER trg_capability_identity_immutable BEFORE UPDATE ON capability_executions
WHEN NEW.execution_id IS NOT OLD.execution_id OR NEW.system_id IS NOT OLD.system_id OR
 NEW.investigation_id IS NOT OLD.investigation_id OR NEW.capability_id IS NOT OLD.capability_id OR
 NEW.permission_class IS NOT OLD.permission_class OR NEW.requested_at IS NOT OLD.requested_at OR
 NEW.parameter_summary_json IS NOT OLD.parameter_summary_json OR NEW.provenance IS NOT OLD.provenance OR
 OLD.status IN ('DENIED','SUCCEEDED','FAILED')
BEGIN SELECT RAISE(ABORT,'capability audit identity or final outcome is immutable'); END;

CREATE TRIGGER trg_capability_event_immutable BEFORE UPDATE ON capability_execution_events
BEGIN SELECT RAISE(ABORT,'capability event history is immutable'); END;
CREATE TRIGGER trg_capability_event_no_delete BEFORE DELETE ON capability_execution_events
BEGIN SELECT RAISE(ABORT,'capability event history is append-only'); END;
