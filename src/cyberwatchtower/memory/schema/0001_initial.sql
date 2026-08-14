CREATE TABLE systems (
    system_id TEXT PRIMARY KEY,
    display_hostname TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    identity_version INTEGER NOT NULL CHECK (identity_version >= 1),
    identity_confidence TEXT NOT NULL CHECK (
        identity_confidence IN ('STABLE', 'LEGACY_LINKED', 'UNRESOLVED')
    ),
    provenance TEXT NOT NULL CHECK (
        provenance IN (
            'DETERMINISTIC_OBSERVATION', 'DERIVED_HISTORY', 'USER_ASSERTION',
            'USER_DECISION', 'RETRIEVED_KNOWLEDGE', 'MODEL_INTERPRETATION'
        )
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE system_aliases (
    alias_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    alias_type TEXT NOT NULL CHECK (alias_type = 'HOSTNAME'),
    alias_value TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    provenance TEXT NOT NULL CHECK (
        provenance IN (
            'DETERMINISTIC_OBSERVATION', 'DERIVED_HISTORY', 'USER_ASSERTION',
            'USER_DECISION', 'RETRIEVED_KNOWLEDGE', 'MODEL_INTERPRETATION'
        )
    ),
    UNIQUE (system_id, alias_type, alias_value, valid_from)
);

CREATE INDEX idx_system_aliases_lookup
    ON system_aliases(alias_type, alias_value, valid_to);

CREATE TABLE reports (
    report_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    generated_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    report_schema_version TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    source_path TEXT,
    source_filename TEXT,
    provenance TEXT NOT NULL CHECK (provenance = 'DETERMINISTIC_OBSERVATION'),
    legacy_identity_state TEXT NOT NULL CHECK (
        legacy_identity_state IN (
            'NATIVE_SYSTEM_ID', 'HOSTNAME_FALLBACK', 'USER_LINKED', 'UNRESOLVED'
        )
    ),
    ingestion_status TEXT NOT NULL CHECK (ingestion_status = 'COMPLETE'),
    UNIQUE (system_id, content_digest),
    UNIQUE (report_id, system_id)
);

CREATE INDEX idx_reports_system_generated
    ON reports(system_id, generated_at, report_id);

CREATE TABLE score_history (
    report_id TEXT PRIMARY KEY,
    system_id TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    risk_level TEXT NOT NULL,
    critical_count INTEGER NOT NULL CHECK (critical_count >= 0),
    high_count INTEGER NOT NULL CHECK (high_count >= 0),
    medium_count INTEGER NOT NULL CHECK (medium_count >= 0),
    low_count INTEGER NOT NULL CHECK (low_count >= 0),
    info_count INTEGER NOT NULL CHECK (info_count >= 0),
    observed_at TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance = 'DETERMINISTIC_OBSERVATION'),
    FOREIGN KEY (report_id, system_id)
        REFERENCES reports(report_id, system_id) ON DELETE RESTRICT
);

CREATE INDEX idx_score_history_system_observed
    ON score_history(system_id, observed_at);

CREATE TABLE findings (
    finding_pk TEXT PRIMARY KEY,
    system_id TEXT NOT NULL REFERENCES systems(system_id) ON DELETE RESTRICT,
    finding_id TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    occurrence_count INTEGER NOT NULL CHECK (occurrence_count >= 1),
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    lifecycle_state TEXT NOT NULL CHECK (
        lifecycle_state IN ('ACTIVE', 'RESOLVED', 'RESOLUTION_UNCERTAIN')
    ),
    recurring INTEGER NOT NULL CHECK (recurring IN (0, 1)),
    reopened_count INTEGER NOT NULL DEFAULT 0 CHECK (reopened_count >= 0),
    last_resolved_at TEXT,
    latest_title TEXT NOT NULL,
    latest_severity TEXT NOT NULL CHECK (
        latest_severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    latest_kind TEXT NOT NULL CHECK (
        latest_kind IN ('RISK', 'COVERAGE_GAP', 'OBSERVATION')
    ),
    latest_assessment_state TEXT NOT NULL CHECK (
        latest_assessment_state IN ('CONFIRMED', 'POTENTIAL', 'INCOMPLETE', 'INFORMATIONAL')
    ),
    latest_source TEXT NOT NULL,
    metadata_inferred INTEGER NOT NULL DEFAULT 0 CHECK (metadata_inferred IN (0, 1)),
    provenance TEXT NOT NULL CHECK (provenance = 'DERIVED_HISTORY'),
    updated_at TEXT NOT NULL,
    UNIQUE (system_id, finding_id),
    UNIQUE (finding_pk, system_id)
);

CREATE INDEX idx_findings_system_active_recurring
    ON findings(system_id, active, recurring, last_seen_at);

CREATE TABLE finding_occurrences (
    occurrence_id TEXT PRIMARY KEY,
    finding_pk TEXT NOT NULL,
    report_id TEXT NOT NULL,
    system_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (
        severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    recommendation TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    technique_id TEXT,
    source TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('RISK', 'COVERAGE_GAP', 'OBSERVATION')),
    assessment_state TEXT NOT NULL CHECK (
        assessment_state IN ('CONFIRMED', 'POTENTIAL', 'INCOMPLETE', 'INFORMATIONAL')
    ),
    metadata_inferred INTEGER NOT NULL DEFAULT 0 CHECK (metadata_inferred IN (0, 1)),
    evidence_json TEXT NOT NULL,
    provenance TEXT NOT NULL CHECK (provenance = 'DETERMINISTIC_OBSERVATION'),
    FOREIGN KEY (finding_pk, system_id)
        REFERENCES findings(finding_pk, system_id) ON DELETE RESTRICT,
    FOREIGN KEY (report_id, system_id)
        REFERENCES reports(report_id, system_id) ON DELETE RESTRICT,
    UNIQUE (report_id, finding_pk)
);

CREATE INDEX idx_occurrences_finding_observed
    ON finding_occurrences(system_id, finding_pk, observed_at);

CREATE TABLE finding_lifecycle_events (
    event_id TEXT PRIMARY KEY,
    finding_pk TEXT NOT NULL,
    system_id TEXT NOT NULL,
    report_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'FIRST_SEEN', 'SEEN', 'RESOLVED', 'REOPENED',
            'SEVERITY_CHANGED', 'ASSESSMENT_STATE_CHANGED', 'KIND_CHANGED'
        )
    ),
    occurred_at TEXT NOT NULL,
    previous_value TEXT,
    current_value TEXT,
    provenance TEXT NOT NULL CHECK (provenance = 'DERIVED_HISTORY'),
    FOREIGN KEY (finding_pk, system_id)
        REFERENCES findings(finding_pk, system_id) ON DELETE RESTRICT,
    FOREIGN KEY (report_id, system_id)
        REFERENCES reports(report_id, system_id) ON DELETE RESTRICT
);

CREATE INDEX idx_lifecycle_finding_occurred
    ON finding_lifecycle_events(system_id, finding_pk, occurred_at);
