-- DNS split-config rules: what the app writes to /etc/dnsmasq.d/vpn-connect.conf, replacing the
-- hand-maintained /etc/dnsmasq.d/examplecorp.conf. Not secret -- no encrypted columns, unlike
-- connections -- so, like settings and events, this needs no key to read or write.
--
-- Two kinds share one table because they render into the same file as one list: 'domain' rows
-- are dnsmasq's domain-scoped forwarders (`server=/DOMAIN/IP`); 'fallback' rows are the bare
-- `server=IP` lines tried for anything a domain rule does not match.
CREATE TABLE dns_rules (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL CHECK (kind IN ('domain', 'fallback')),
    domain      TEXT,     -- set only for kind='domain'
    address     TEXT    NOT NULL,  -- IPv4 or IPv6 literal, validated by dns.py before insert
    -- Only fallback rows need a position: dnsmasq tries bare server= lines in file order for a
    -- query matching no domain. Domain rows are matched by specificity regardless of file order,
    -- so they carry no position and render alphabetically.
    position    INTEGER,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    CHECK (
        (kind = 'domain'      AND domain IS NOT NULL AND position IS NULL)
        OR (kind = 'fallback' AND domain IS NULL     AND position IS NOT NULL)
    )
);

-- One forwarder per domain: dnsmasq would silently let the last-loaded line win on a duplicate,
-- worse than the app refusing/upserting it.
CREATE UNIQUE INDEX dns_rules_one_forwarder_per_domain ON dns_rules(domain) WHERE kind = 'domain';
CREATE INDEX dns_rules_fallback_order ON dns_rules(position) WHERE kind = 'fallback';
