-- Per-connection: does this tunnel actually ask for a second factor?
--
-- The app used to assume every connection did. The OTP box was unconditionally `required`, the
-- controller rejected an empty code before it had even looked the connection up, the credential
-- was always encoded as OpenVPN's `SCRV1:<password>:<code>` challenge response, and the root
-- helper passed `--static-challenge` on the openvpn command line for every profile alike. A
-- profile that signs in with a password alone could not be used at all.
--
-- This is derived, not chosen: the profile already declares it. `static-challenge` in the .ovpn
-- is OpenVPN's own statement that the server will ask for a second field, so it is read from the
-- profile text on save rather than offered as yet another checkbox to keep in sync with reality.
--
-- Defaults to 1 so that rows saved before this migration keep behaving exactly as they did; they
-- are re-derived the next time the connection is saved.
ALTER TABLE connections
    ADD COLUMN requires_mfa INTEGER NOT NULL DEFAULT 1
    CHECK (requires_mfa IN (0, 1));
