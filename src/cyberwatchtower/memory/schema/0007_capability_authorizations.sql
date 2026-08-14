CREATE INDEX idx_reports_content_digest
ON reports(content_digest,system_id,report_id);

CREATE TABLE capability_authorizations (
    authorization_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    capability_id TEXT NOT NULL,
    target_scope_type TEXT NOT NULL CHECK (
        target_scope_type IN ('FINDING','LISTENER','SERVICE','APPLICATION','FIREWALL_STATE')
    ),
    target_scope_json TEXT NOT NULL,
    target_scope_digest TEXT NOT NULL,
    parameter_digest TEXT NOT NULL CHECK (length(parameter_digest)=64),
    proposal_id TEXT NOT NULL,
    decision_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at>issued_at),
    provenance TEXT NOT NULL CHECK (provenance='USER_DECISION'),
    UNIQUE(system_id,proposal_id),
    FOREIGN KEY(decision_id,system_id)
        REFERENCES user_decisions(decision_id,system_id) ON DELETE RESTRICT
);
CREATE INDEX idx_capability_authorizations_validation
ON capability_authorizations(system_id,capability_id,proposal_id,expires_at,authorization_id);

CREATE TRIGGER trg_capability_authorization_immutable
BEFORE UPDATE ON capability_authorizations
BEGIN SELECT RAISE(ABORT,'capability authorization is immutable'); END;
CREATE TRIGGER trg_capability_authorization_no_delete
BEFORE DELETE ON capability_authorizations
BEGIN SELECT RAISE(ABORT,'capability authorization history is append-only'); END;
