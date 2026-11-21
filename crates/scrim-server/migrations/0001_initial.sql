-- Initial schema for Milestone M1: members and their API tokens, groups,
-- repositories, branch rules that restrict refs to groups, and an audit log.

CREATE TABLE members (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_machine BOOLEAN NOT NULL DEFAULT FALSE,
    public_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- Only the SHA-256 digest of each token is stored, never the token itself.
CREATE TABLE member_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    member_id BIGINT NOT NULL REFERENCES members (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX member_tokens_member_id_idx ON member_tokens (member_id);

CREATE TABLE groups (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE group_memberships (
    group_id BIGINT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    member_id BIGINT NOT NULL REFERENCES members (id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, member_id)
);

CREATE INDEX group_memberships_member_id_idx ON group_memberships (member_id);

-- `path` is the canonical repository key (symlinks resolved), relative to the
-- server's repository root, e.g. `team/app.git`.
CREATE TABLE repositories (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE branch_rules (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository_id BIGINT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
    -- A coarse guard only; the server fully validates every glob on load.
    ref_glob TEXT NOT NULL
        CHECK (ref_glob LIKE 'refs/_%' AND octet_length(ref_glob) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (repository_id, ref_glob)
);

-- The groups whose members may see refs matching a branch rule.
CREATE TABLE branch_rule_groups (
    branch_rule_id BIGINT NOT NULL REFERENCES branch_rules (id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (branch_rule_id, group_id)
);

CREATE INDEX branch_rule_groups_group_id_idx ON branch_rule_groups (group_id);

-- `actor_member_id` becomes NULL if the member is deleted so the entry itself
-- survives; `target_name` keeps a readable record of what was acted on.
CREATE TABLE audit_log (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_member_id BIGINT REFERENCES members (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_name TEXT NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at DESC);
