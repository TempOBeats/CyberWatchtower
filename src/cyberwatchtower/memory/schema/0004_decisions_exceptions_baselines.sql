CREATE TABLE user_decisions (
    decision_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    decision_type TEXT NOT NULL CHECK (decision_type IN ('ACCEPTED_RISK', 'REVIEWED', 'NOT_APPLICABLE', 'CUSTOM')),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('FINDING', 'LISTENER', 'SERVICE', 'APPLICATION', 'FIREWALL_STATE')),
    scope_json TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    actor TEXT NOT NULL,
    rationale TEXT,
    effective_at TEXT NOT NULL,
    expires_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
    supersedes_id TEXT,
    presentation_only INTEGER NOT NULL CHECK (presentation_only = 1),
    provenance TEXT NOT NULL CHECK (provenance = 'USER_DECISION'),
    created_at TEXT NOT NULL,
    FOREIGN KEY (supersedes_id, system_id) REFERENCES user_decisions(decision_id, system_id) ON DELETE RESTRICT,
    UNIQUE (decision_id, system_id)
);
CREATE INDEX idx_decisions_scope ON user_decisions(system_id, scope_digest, effective_at, decision_id);
CREATE TRIGGER trg_decision_meaning_immutable
BEFORE UPDATE ON user_decisions
WHEN NEW.decision_id IS NOT OLD.decision_id OR NEW.system_id IS NOT OLD.system_id OR
     NEW.decision_type IS NOT OLD.decision_type OR NEW.scope_type IS NOT OLD.scope_type OR
     NEW.scope_json IS NOT OLD.scope_json OR NEW.scope_digest IS NOT OLD.scope_digest OR
     NEW.actor IS NOT OLD.actor OR NEW.rationale IS NOT OLD.rationale OR
     NEW.effective_at IS NOT OLD.effective_at OR NEW.expires_at IS NOT OLD.expires_at OR
     NEW.supersedes_id IS NOT OLD.supersedes_id OR
     NEW.presentation_only IS NOT OLD.presentation_only OR
     NEW.provenance IS NOT OLD.provenance OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'decision meaning is immutable');
END;
CREATE TRIGGER trg_decision_no_delete
BEFORE DELETE ON user_decisions
BEGIN
    SELECT RAISE(ABORT, 'decision history is append-only');
END;

CREATE TABLE exceptions (
    exception_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('FINDING', 'LISTENER', 'SERVICE', 'APPLICATION', 'FIREWALL_STATE')),
    scope_json TEXT NOT NULL,
    scope_digest TEXT NOT NULL,
    approver TEXT NOT NULL,
    rationale TEXT,
    starts_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at > starts_at),
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'SUPERSEDED')),
    supersedes_id TEXT,
    presentation_only INTEGER NOT NULL CHECK (presentation_only = 1),
    provenance TEXT NOT NULL CHECK (provenance = 'USER_DECISION'),
    created_at TEXT NOT NULL,
    FOREIGN KEY (supersedes_id, system_id) REFERENCES exceptions(exception_id, system_id) ON DELETE RESTRICT,
    UNIQUE (exception_id, system_id)
);
CREATE INDEX idx_exceptions_active ON exceptions(system_id, status, starts_at, expires_at, exception_id);
CREATE INDEX idx_exceptions_scope ON exceptions(system_id, scope_digest, starts_at, exception_id);
CREATE TRIGGER trg_exception_meaning_immutable
BEFORE UPDATE ON exceptions
WHEN NEW.exception_id IS NOT OLD.exception_id OR NEW.system_id IS NOT OLD.system_id OR
     NEW.scope_type IS NOT OLD.scope_type OR NEW.scope_json IS NOT OLD.scope_json OR
     NEW.scope_digest IS NOT OLD.scope_digest OR NEW.approver IS NOT OLD.approver OR
     NEW.rationale IS NOT OLD.rationale OR NEW.starts_at IS NOT OLD.starts_at OR
     NEW.expires_at IS NOT OLD.expires_at OR NEW.supersedes_id IS NOT OLD.supersedes_id OR
     NEW.presentation_only IS NOT OLD.presentation_only OR
     NEW.provenance IS NOT OLD.provenance OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'exception meaning is immutable');
END;
CREATE TRIGGER trg_exception_no_delete
BEFORE DELETE ON exceptions
BEGIN
    SELECT RAISE(ABORT, 'exception history is append-only');
END;

CREATE TABLE baselines (
    baseline_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    baseline_type TEXT NOT NULL CHECK (baseline_type IN ('EXPECTED_SERVICES', 'EXPECTED_APPLICATIONS', 'EXPECTED_FIREWALL_STATE', 'APPROVED_LISTENERS', 'SYSTEM_POSTURE')),
    version INTEGER NOT NULL CHECK (version >= 1),
    state TEXT NOT NULL CHECK (state IN ('DRAFT', 'APPROVED', 'SUPERSEDED')),
    approver TEXT,
    approved_at TEXT,
    rationale TEXT,
    previous_baseline_id TEXT,
    provenance TEXT NOT NULL CHECK (provenance = 'USER_DECISION'),
    created_at TEXT NOT NULL,
    FOREIGN KEY (previous_baseline_id, system_id) REFERENCES baselines(baseline_id, system_id) ON DELETE RESTRICT,
    UNIQUE (baseline_id, system_id),
    UNIQUE (system_id, baseline_type, version),
    CHECK ((state = 'DRAFT' AND approver IS NULL AND approved_at IS NULL) OR
           (state != 'DRAFT' AND approver IS NOT NULL AND approved_at IS NOT NULL))
);
CREATE INDEX idx_baselines_history ON baselines(system_id, baseline_type, version, baseline_id);

CREATE TABLE baseline_entries (
    baseline_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    entry_key TEXT NOT NULL,
    entry_value TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    provenance TEXT NOT NULL CHECK (provenance = 'USER_DECISION'),
    PRIMARY KEY (baseline_id, entry_key),
    FOREIGN KEY (baseline_id, system_id) REFERENCES baselines(baseline_id, system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_baseline_entries_order ON baseline_entries(system_id, baseline_id, ordinal, entry_key);

CREATE TRIGGER trg_approved_baseline_immutable
BEFORE UPDATE ON baselines
WHEN OLD.state = 'APPROVED' AND (
    NEW.baseline_id IS NOT OLD.baseline_id OR NEW.system_id IS NOT OLD.system_id OR
    NEW.baseline_type IS NOT OLD.baseline_type OR NEW.version IS NOT OLD.version OR
    NEW.approver IS NOT OLD.approver OR NEW.approved_at IS NOT OLD.approved_at OR
    NEW.rationale IS NOT OLD.rationale OR
    NEW.previous_baseline_id IS NOT OLD.previous_baseline_id OR
    NEW.provenance IS NOT OLD.provenance OR NEW.created_at IS NOT OLD.created_at OR
    NEW.state NOT IN ('APPROVED', 'SUPERSEDED')
)
BEGIN
    SELECT RAISE(ABORT, 'approved baseline is immutable');
END;

CREATE TRIGGER trg_approved_baseline_entries_update
BEFORE UPDATE ON baseline_entries
WHEN EXISTS (SELECT 1 FROM baselines WHERE baseline_id=OLD.baseline_id
             AND system_id=OLD.system_id AND state IN ('APPROVED', 'SUPERSEDED'))
BEGIN
    SELECT RAISE(ABORT, 'approved baseline entries are immutable');
END;

CREATE TRIGGER trg_approved_baseline_entries_delete
BEFORE DELETE ON baseline_entries
WHEN EXISTS (SELECT 1 FROM baselines WHERE baseline_id=OLD.baseline_id
             AND system_id=OLD.system_id AND state IN ('APPROVED', 'SUPERSEDED'))
BEGIN
    SELECT RAISE(ABORT, 'approved baseline entries are immutable');
END;

CREATE TRIGGER trg_baseline_no_delete
BEFORE DELETE ON baselines
BEGIN
    SELECT RAISE(ABORT, 'baseline history is append-only');
END;

CREATE TABLE recommendations_shown (
    recommendation_event_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    finding_id TEXT,
    action_id TEXT NOT NULL,
    trusted_text_hash TEXT NOT NULL,
    shown_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance = 'DERIVED_HISTORY'),
    UNIQUE (recommendation_event_id, system_id)
);
CREATE INDEX idx_recommendations_action ON recommendations_shown(system_id, action_id, shown_at, recommendation_event_id);

CREATE TABLE action_responses (
    response_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    recommendation_event_id TEXT NOT NULL,
    action_id TEXT NOT NULL,
    response_type TEXT NOT NULL CHECK (response_type IN ('ACKNOWLEDGED', 'DEFERRED', 'DECLINED', 'COMPLETED')),
    actor TEXT NOT NULL,
    rationale TEXT,
    recorded_at TEXT NOT NULL,
    defer_until TEXT,
    provenance TEXT NOT NULL CHECK (provenance = 'USER_DECISION'),
    FOREIGN KEY (recommendation_event_id, system_id) REFERENCES recommendations_shown(recommendation_event_id, system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_action_responses_history ON action_responses(system_id, action_id, recorded_at, response_id);
