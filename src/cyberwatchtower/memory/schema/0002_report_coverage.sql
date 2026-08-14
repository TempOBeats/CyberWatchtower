ALTER TABLE reports
    ADD COLUMN coverage_json TEXT NOT NULL DEFAULT '{}';
