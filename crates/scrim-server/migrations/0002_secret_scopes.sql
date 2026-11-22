-- Secret scopes and their authorized groups for Milestone M2.

CREATE TABLE secret_scopes (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    scope_name TEXT NOT NULL CHECK (octet_length(scope_name) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, scope_name)
);

CREATE TABLE secret_scope_groups (
    secret_scope_id BIGINT NOT NULL REFERENCES secret_scopes (id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (secret_scope_id, group_id)
);

CREATE INDEX secret_scope_groups_group_id_idx ON secret_scope_groups (group_id);
