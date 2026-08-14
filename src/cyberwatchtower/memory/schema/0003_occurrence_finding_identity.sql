ALTER TABLE finding_occurrences ADD COLUMN stable_finding_id TEXT;

UPDATE finding_occurrences
SET stable_finding_id = (
    SELECT findings.finding_id
    FROM findings
    WHERE findings.finding_pk = finding_occurrences.finding_pk
      AND findings.system_id = finding_occurrences.system_id
);

CREATE TRIGGER trg_occurrence_finding_id_insert
BEFORE INSERT ON finding_occurrences
WHEN NEW.stable_finding_id IS NULL OR length(NEW.stable_finding_id) = 0
BEGIN
    SELECT RAISE(ABORT, 'finding occurrence requires finding_id');
END;

CREATE TRIGGER trg_occurrence_finding_id_update
BEFORE UPDATE OF stable_finding_id ON finding_occurrences
WHEN NEW.stable_finding_id IS NULL OR length(NEW.stable_finding_id) = 0
BEGIN
    SELECT RAISE(ABORT, 'finding occurrence requires finding_id');
END;

CREATE INDEX idx_occurrences_system_finding_observed
ON finding_occurrences(system_id, stable_finding_id, observed_at, report_id);
