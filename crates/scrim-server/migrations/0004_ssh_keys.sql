-- SSH public keys for member Git-over-SSH authentication (Milestone M5).

CREATE TABLE member_ssh_keys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    member_id BIGINT NOT NULL REFERENCES members (id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX member_ssh_keys_member_id_idx ON member_ssh_keys (member_id);
