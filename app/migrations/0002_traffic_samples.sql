-- Byte-counter samples, one per connection attempt.
--
-- OpenVPN's management interface already pushes ">BYTECOUNT:in,out" every few seconds; until now
-- the controller overwrote the totals and discarded the history. These rows keep it.
--
-- Two deliberate choices:
--
--  * The counters are stored **cumulative**, exactly as OpenVPN reports them, and rates are
--    derived at read time. Storing pre-computed rates would bake a false spike into the database
--    permanently whenever a sample arrived late; differencing on read just averages over the
--    longer gap instead.
--  * `at` is epoch seconds rather than the ISO text used elsewhere, because every consumer of
--    this column does arithmetic on it. Formatting happens in the browser.
CREATE TABLE traffic_samples (
    id          INTEGER PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES log_sessions(id) ON DELETE CASCADE,
    at          REAL    NOT NULL,
    bytes_in    INTEGER NOT NULL,
    bytes_out   INTEGER NOT NULL
);

CREATE INDEX traffic_samples_session ON traffic_samples(session_id, id);
