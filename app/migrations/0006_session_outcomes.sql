-- What a connection attempt did, rather than only that it happened.
--
-- `log_sessions` was written for one job: keep a failed attempt's log after the process that
-- produced it had gone. Reading a week of attempts back asks two more questions of every row,
-- and neither could be answered from what was stored:
--
--  * **Did it ever come up?** There was no record of it. An attempt that failed at the
--    credential prompt and one that carried traffic for nine hours were both just rows with a
--    start and an end, and "how long was I connected" had to be inferred from whether any
--    traffic samples happened to exist.
--  * **Why did it end?** `outcome` says what the *state machine* saw (`disconnected`,
--    `failed`), which cannot separate the two endings that actually matter to somebody watching
--    a flaky tunnel: you clicked Disconnect, or the concentrator cut you off. That distinction
--    already existed one layer away -- the controller computes it to choose between the
--    `down_manual` and `down_severed` notifications -- and was thrown away immediately after.
--
-- Both are recorded at the moment they are known rather than derived later, which is the same
-- reason the byte counters are stored cumulative: a derivation made at read time is only ever as
-- good as the evidence that survived, and here that evidence is exactly what does not survive.
--
-- Existing rows get NULL and '': honestly unknown. Nothing back-fills them, because there is
-- nothing left to back-fill them *from*, and a guess would be indistinguishable from a fact.
ALTER TABLE log_sessions ADD COLUMN connected_at TEXT;

ALTER TABLE log_sessions ADD COLUMN reason TEXT NOT NULL DEFAULT '';

-- Retention sweeps and the history panel both select on when a session ended.
CREATE INDEX log_sessions_ended ON log_sessions(ended_at);
