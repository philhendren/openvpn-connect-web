-- Per-connection: refuse the DNS servers the server pushes.
--
-- OpenVPN 2.6+ hands pushed `dhcp-option DNS` straight to systemd-resolved over D-Bus, with no
-- --up script involved. When the server pushes a catch-all the tunnel claims *every* lookup and
-- the rules in dns_rules are bypassed entirely. Setting this adds
-- `pull-filter ignore "dhcp-option DNS"` to the .ovpn as it is written out, so the tunnel gets no
-- resolver of its own and everything falls back to dnsmasq.
--
-- A flag rather than an edit to the stored profile text: the profile is the operator's own
-- vendor-supplied file, and a toggle that rewrites it could not be undone. The directive is
-- appended to the derived file at write time instead, so unticking this genuinely reverts it.
ALTER TABLE connections
    ADD COLUMN ignore_pushed_dns INTEGER NOT NULL DEFAULT 0
    CHECK (ignore_pushed_dns IN (0, 1));
