-- Server-enforced path withholding rules for Milestone M4.

CREATE TABLE path_rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    path_glob TEXT NOT NULL
        CHECK (octet_length(path_glob) BETWEEN 1 AND 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, path_glob)
);

CREATE TABLE path_rule_groups (
    path_rule_id BIGINT NOT NULL REFERENCES path_rules (id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (path_rule_id, group_id)
);

CREATE INDEX path_rule_groups_group_id_idx ON path_rule_groups (group_id);
