-- Rename `log_sessions` to `sessions`, because that is what it has become.
--
-- 0001 created it for one job, and named it for that job: keep a failed attempt's log after the
-- process that produced it had exited. A row existed so `log_lines` had something to hang off.
--
-- It has not been that table for a while:
--
--  * 0002 hung `traffic_samples` off the same row, so it owns the byte counters.
--  * 0006 added `connected_at` and `reason` -- whether the tunnel ever came up, and why it ended.
--  * The Session History panel reads it for duration, outcome and totals, and `log_lines` is now
--    one of four things a row indexes rather than the only one.
--
-- The drift was already visible in the code: `prune_sessions`, `mark_session_connected` and
-- `list_sessions` had all quietly dropped the prefix while `start_log_session` kept it. This
-- settles it in the one place both sides read from.
--
-- Nothing about the data changes -- no columns, no rows, no semantics. SQLite (>= 3.25, and
-- `PRAGMA foreign_keys = ON`, which app/db.py sets at connect) rewrites the REFERENCES clauses
-- in `log_lines` and `traffic_samples` as part of the rename, so both ON DELETE CASCADEs survive
-- untouched. Indexes are the exception: a table rename leaves their names behind, so they are
-- dropped and recreated rather than left pointing at a table that no longer answers to that name.
ALTER TABLE log_sessions RENAME TO sessions;

DROP INDEX log_sessions_recent;
DROP INDEX log_sessions_ended;

CREATE INDEX sessions_recent ON sessions(id DESC);
CREATE INDEX sessions_ended ON sessions(ended_at);
