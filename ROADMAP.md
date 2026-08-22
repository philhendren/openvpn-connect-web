# Roadmap

Two things this panel does not do yet, and what each would actually cost.

Both have been thought through and deliberately not started — which is a different state from
"unknown", and worth writing down as such. Neither is scheduled. This file exists so that the
reasoning survives, and so that picking either one up starts from what has already been worked out
rather than from scratch.

Settled decisions do not live here. Where something was considered and deliberately left alone —
capping the `events` table, status badges, retention by age — the reasoning sits next to the thing
itself, in [README.md](README.md) or in the migration that made the change. A roadmap that also
holds the answers stops being a list of open questions.

---

## An OpenVPN 3 backend

**Status:** not started. It cannot be written honestly without a machine running `openvpn3` to
test against.

### What the problem actually is

[README.md](README.md#openvpn-3-openvpn3-is-not-supported) states the limitation and the reason:
OpenVPN 3 Linux is a separate implementation with **no management interface**. That is not a small
difference. Everything live this panel shows arrives over the management socket the classic client
opens on request:

- connection state and its transitions
- byte counters (`>BYTECOUNT`)
- the log, as it happens
- the credential and MFA prompts, answered interactively (`>PASSWORD`, `SCRV1:`)
- shutdown, via `signal SIGTERM`

None of it exists on the OpenVPN 3 side. So this is not a matter of swapping a binary name or
adding a flag — it is a **second backend**, talking to a different API, producing the same
`VpnStatus` the rest of the app already consumes.

### The shape it would take

`OpenVpnController` is already the only thing in the app that touches the tunnel; every view goes
through `snapshot()`, `connect()`, `disconnect()`, `routes()`, `pushed()`, `scope()` and
`recent_events()`. That surface is the seam. A second backend implements it and nothing above it
changes — which is the encouraging part, and it is not an accident: the controller was kept thin
for reasons that had nothing to do with OpenVPN 3.

Roughly what each command maps to:

| What the panel needs | Classic (`openvpn`) | OpenVPN 3 (`openvpn3`) |
| --- | --- | --- |
| Start a tunnel | helper runs `openvpn --daemon --management …` | `config-import`, then `session-start` |
| Is one running | pid file, then the management socket | `sessions-list` |
| Live state | `state` over the socket | `session-manage --status`, polled |
| Byte counters | `>BYTECOUNT` pushed every few seconds | `session-stats`, polled |
| The log | `log` over the socket, streamed | `log`, or the D-Bus log service |
| Credentials and MFA | `>PASSWORD` prompt, answered on the socket | interactive session auth |
| Stop | `signal SIGTERM` | `session-manage --disconnect` |

### What makes it harder than that table suggests

- **Polled, not pushed.** The classic backend is event-driven: the socket tells the app when
  something changed. OpenVPN 3 has to be *asked*. Every derived thing — the traffic graph's
  cumulative samples, the up/down events, the state transitions the notifier depends on — is built
  on the assumption that a change arrives as a change. Polling produces a different shape of data
  and a different set of races, and `traffic.py` already guards one going-backwards case that
  would need re-examining rather than reusing.
- **Interactive auth.** The MFA flow is the hard part. The classic client asks over the socket and
  the app answers over the same socket, which is why `SCRV1:<password>:<code>` works at all.
  OpenVPN 3's session auth is interactive in a different way, and the app's whole credential path —
  vault key in memory, `requires_mfa` derived from the profile, the challenge response encoded
  once — assumes the classic prompt.
- **The privilege boundary moves.** Today exactly one operation needs root: the helper starting the
  tunnel. `openvpn3` sessions are per-user by design and the root helper may become unnecessary,
  or become necessary in a *different* place. Either way `deploy/install.sh`, the sudoers rule and
  the drift banner all describe a boundary that would no longer be the boundary. That is not a
  detail to discover late.

### Why it is not started

Writing it needs a machine with `openvpn3` installed to develop against. A backend written blind
from documentation, with no way to run it even once, is not worth having — it would look finished
while being untested in exactly the places that matter. The two clients install side by side
without conflicting, so the first step is not code:

1. Install `openvpn3` alongside the classic client on a machine that can be experimented with.
2. Drive it by hand — import a config, start a session, read the stats, disconnect — and record
   what the output actually looks like, because that is what a stub has to imitate.
3. Only then decide whether the backend is worth writing.

Until step 2 has happened, everything above is a plan made from reading rather than from running,
and should be treated as such.

---

## Journey tests, for the things a person *does*

**Status:** not started. Blocked on one specific thing, described below.

### What is already covered, and what is not

The browser suite in [`uitests/`](uitests/) is seven scenarios, each defending a sentence somebody
can read in the documentation. Every one of them is an **observation**: load the page, and check
that something is true — a count, a hidden block, a field that appears for one profile and not
another.

None of them *change* anything. That is the gap: connecting, disconnecting, adding a connection
and editing DNS rules are what a person would call "using the app" rather than "looking at it",
and none of it is tested through a browser at all.

| Journey | What it would prove |
| --- | --- |
| Connect with MFA | code entered, pill goes `connecting` → `connected`, the facts populate, polling drops from 1s back to 5s |
| A rejected credential | `AUTH_FAILED` surfaces, the pill does not claim success, and the attempt lands in Session history as **Failed** |
| Disconnect | the modal appears, and confirming it produces **You disconnected** rather than **Dropped** — a distinction only the controller knows |
| Add a connection | upload, save, appears in the list *and* the dropdown, MFA box matching the profile just parsed |
| DNS rules end to end | add a forwarder, add fallbacks, reorder, delete — with the badge and the verdict tracking every change |
| Session history | search by outcome, select a row, read that attempt's log, page with **Show older sessions** |

### What blocks it

`StubController` in [`tools/screenshots.py`](tools/screenshots.py) is **frozen connected**. It
reports one unchanging status, and `connect()` and `disconnect()` raise `AssertionError` on
purpose — it exists to photograph a tunnel that is up, and refusing to pretend otherwise is
correct for that job.

Every journey above needs the opposite: a controller a test can **walk through states** —
`disconnected` → `connecting` → prompting for a credential → `connected`, and back down again by
either route — and can make fail on demand. That is the bulk of the work in this item, and it is a
real piece of engineering rather than a fixture tweak, because the state machine it imitates is
the one part of the app with genuine concurrency in it.

Whether it belongs beside `StubController` or replaces it is an open question. They want different
things — one wants to hold still for a photograph, the other wants to move — and a single class
serving both may end up serving neither.

### Two things worth deciding before starting

- **The selection rule still applies.** The existing scenarios earn their place by defending a
  sentence in the documentation. That rule is what stops `uitests/` becoming a slower duplicate of
  `tests/`, and it should not be quietly dropped because journeys are harder to trace back to a
  sentence. If a journey is worth testing and no documentation describes it, the documentation is
  what is missing.
- **Runtime.** The seven scenarios take about 17 seconds locally and 70 in CI. Journeys are slower
  by nature — state transitions have to actually happen. A suite that grows past a couple of
  minutes stops being run before a push, and a browser suite nobody runs locally is one that only
  ever fails in CI, which is the position this was meant to improve on.
