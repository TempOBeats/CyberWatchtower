ALTER TABLE score_history
    ADD COLUMN scoring_version TEXT NOT NULL DEFAULT '1'
    CHECK (scoring_version IN ('1', '2'));
