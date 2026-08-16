-- Artifact watchlist (ocidex-998g.3).
--
-- A watch is a user's private bookmark on an artifact, and it is deliberately
-- NOT an ownership or visibility relation. The main use case is watching a
-- public base image somebody else owns, so nothing here constrains the artifact
-- to the watcher's namespaces — the visibility check that decides whether a
-- watch may be created at all lives at the service boundary, where
-- artifact_visible() already answers it.
--
-- Both foreign keys cascade: a deleted user's watches are meaningless, and an
-- artifact that is gone cannot be watched. A watch is derived state, so losing
-- it with either side is correct rather than something to preserve.

-- +goose Up

CREATE TABLE artifact_watch (
    user_id     UUID        NOT NULL REFERENCES ocidex_user(id) ON DELETE CASCADE,
    artifact_id UUID        NOT NULL REFERENCES artifact(id)    ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, artifact_id)
);

-- The primary key covers "is this artifact watched by me" and "list my
-- watches"; this index covers the other direction, which the change feed
-- (ocidex-998g.4) needs to answer "who watches this artifact" when an event
-- lands on it.
CREATE INDEX idx_artifact_watch_artifact ON artifact_watch (artifact_id);

COMMENT ON TABLE artifact_watch IS
    'Per-user artifact bookmarks. Not an ownership or visibility relation: watching a public artifact owned by someone else is the primary use case.';

-- +goose Down

DROP TABLE IF EXISTS artifact_watch;
