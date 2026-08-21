/* Polls /api/status, drives connect/disconnect, and saves the ntfy topic.
   No framework beyond Bootstrap's modal component. */
(() => {
  "use strict";

  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const card = document.getElementById("status-card");
  const form = document.getElementById("connect-form");
  const connectBtn = document.getElementById("connect-btn");
  const disconnectBtn = document.getElementById("disconnect-btn");
  const disconnectConfirm = document.getElementById("disconnect-confirm");
  const otpInput = document.getElementById("otp");
  const errorBox = document.getElementById("status-error");
  const logBox = document.getElementById("log");
  const logMeta = document.getElementById("log-meta");
  const eventList = document.getElementById("events");
  const notifyForm = document.getElementById("notify-form");
  const notifyInput = document.getElementById("ntfy-topic");
  const notifyFeedback = document.getElementById("notify-feedback");
  const messagesReset = document.getElementById("messages-reset");
  const notifyTest = document.getElementById("notify-test");
  const trafficChart = document.getElementById("traffic-chart");
  const scopeMode = document.getElementById("scope-mode");
  const scopeWarnings = document.getElementById("scope-warnings");
  const scopePublicNotice = document.getElementById("scope-public-notice");
  const trafficSummary = document.getElementById("traffic-summary");
  const trafficScale = document.getElementById("traffic-scale");
  const trafficSpan = document.getElementById("traffic-span");
  const trafficTotals = document.getElementById("traffic-totals");
  const connectionForm = document.getElementById("connection-form");
  const connectionFeedback = document.getElementById("connection-feedback");
  const connectionsBody = document.getElementById("connections-body");
  const profileSelect = document.getElementById("profile");
  const otpLabel = document.getElementById("otp-label");
  const otpField = document.getElementById("otp-field");
  const drift = document.getElementById("drift");
  const driftItems = document.getElementById("drift-items");
  const connectHint = document.getElementById("connect-hint");
  const themeToggle = document.getElementById("theme-toggle");
  const routesBody = document.getElementById("routes-body");
  const routesCount = document.getElementById("routes-count");
  const routesFilter = document.getElementById("routes-filter");
  const routesRefresh = document.getElementById("routes-refresh");
  const dnsCount = document.getElementById("dns-count");
  const dnsStatus = document.getElementById("dns-status");
  const dnsStatusHeadline = document.getElementById("dns-status-headline");
  const dnsStatusDetail = document.getElementById("dns-status-detail");
  const dnsStatusNotes = document.getElementById("dns-status-notes");
  const dnsStatusPushed = document.getElementById("dns-status-pushed");
  const dnsLegacy = document.getElementById("dns-legacy");
  const dnsLegacyText = document.getElementById("dns-legacy-text");
  const dnsImport = document.getElementById("dns-import");
  const dnsDomainBody = document.getElementById("dns-domain-body");
  const dnsDomainForm = document.getElementById("dns-domain-form");
  const dnsFallbackBody = document.getElementById("dns-fallback-body");
  const dnsFallbackForm = document.getElementById("dns-fallback-form");
  const dnsFeedback = document.getElementById("dns-feedback");

  const IDLE_POLL = 5000;
  const BUSY_POLL = 1000;
  let timer = null;
  let submitting = false;
  let routes = [];
  let routesDevice = "tun0";
  let routesLoaded = false;
  let routesKey = null;   // state + tunnel IP; routes are refetched when this changes
  const whoisOrgs = {};     // destination -> org string | null (looked up, no name found)
  const whoisPending = new Set();   // destinations currently being resolved
  const whoisFailed = new Set();    // destinations whose last lookup errored -- retried next time

  const text = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value === null || value === undefined || value === "" ? "—" : value;
  };

  const bytes = (n) => {
    if (!n) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${units[i]}`;
  };

  const duration = (s) => {
    if (s === null || s === undefined) return "—";
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
    return h ? `${h}h ${m}m` : m ? `${m}m ${sec}s` : `${sec}s`;
  };

  async function api(path, options = {}) {
    const response = await fetch(path, {
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json" },
      ...options,
    });
    if (response.status === 401) {
      window.location.href = "/login";
      throw new Error("Signed out");
    }
    const body = await response.json().catch(() => ({}));
    if (!response.ok && response.status !== 202) {
      throw new Error(body.error || `Request failed (${response.status})`);
    }
    return body;
  }

  function showError(message) {
    if (!errorBox) return;
    errorBox.textContent = message || "";
    errorBox.hidden = !message;
  }

  function render(status) {
    card.dataset.state = status.state;
    text("state-pill", status.state);
    text("state-detail", status.detail);
    text("fact-profile", status.profile);
    text("fact-ip", status.tun_ip);
    text("fact-remote", status.remote_ip);
    text("fact-uptime", duration(status.uptime_seconds));
    text("fact-in", bytes(status.bytes_in));
    text("fact-out", bytes(status.bytes_out));
    text("fact-pid", status.pid);
    text("fact-ovstate", status.openvpn_state);
    showError(status.error);

    const blocked = status.busy || status.connected || status.controllable === false;
    if (connectBtn) {
      connectBtn.disabled = submitting || blocked;
      /* Once connected the button is no longer an action, so it stops offering one and reports
         the state instead, in the status card's own green. */
      if (status.connected) {
        connectBtn.textContent = "Connected";
      } else {
        connectBtn.textContent = status.busy ? "Connecting…" : "Connect";
      }
      connectBtn.classList.toggle("btn-connected", Boolean(status.connected));
      connectBtn.classList.toggle("btn-brand", !status.connected);
    }
    if (disconnectBtn) {
      disconnectBtn.disabled = submitting || (!status.connected && !status.busy && !status.pid);
    }

    if (logBox && Array.isArray(status.log)) {
      const atBottom = logBox.scrollHeight - logBox.scrollTop - logBox.clientHeight < 24;
      logBox.textContent = status.log.length ? status.log.join("\n") : "No log output yet.";
      if (atBottom) logBox.scrollTop = logBox.scrollHeight;
      if (logMeta) {
        logMeta.textContent = status.log.length ? `${status.log.length} lines · live` : "idle";
      }
    }

    if (eventList && Array.isArray(status.events)) {
      const rows = status.events.length ? status.events : ["No events yet."];
      eventList.replaceChildren(
        ...rows.map((line) => {
          const li = document.createElement("li");
          li.textContent = line;
          if (!status.events.length) li.className = "text-body-secondary";
          return li;
        })
      );
    }

    syncRoutes(status);

    schedule(status.busy ? BUSY_POLL : IDLE_POLL);
  }

  // --- deployment self-check ---------------------------------------------
  // Polled slowly and separately from the status: an unreinstalled helper or an unrestarted
  // process is a state that changes when a human does something, not several times a minute.

  const DRIFT_POLL = 60000;

  async function loadDrift() {
    if (!drift || !driftItems) return;
    try {
      const report = await api("/api/deploy");
      drift.hidden = report.clean;
      if (report.clean) return;
      driftItems.replaceChildren(
        ...report.items.map((item) => {
          const li = document.createElement("li");
          const headline = document.createElement("strong");
          headline.textContent = item.headline;
          const detail = document.createElement("div");
          detail.textContent = item.detail;
          const fix = document.createElement("code");
          fix.textContent = item.fix;
          li.append(headline, detail, fix);
          return li;
        }),
      );
    } catch {
      /* the check is advice, not a feature -- a failure to fetch it must not shout */
      drift.hidden = true;
    }
  }

  // --- routes ------------------------------------------------------------
  // Fetched separately from /api/status: this list is hundreds of rows on a split tunnel, and it
  // only changes when the tunnel does, so polling it every few seconds would be waste.

  const TAGS = {
    "on-link": "on-link",
    bypass: "server",
  };

  /* A public destination -- anything that is not this VPN operator's own private address space
     -- gets its registered organisation looked up via /api/whois and shown here, so a pushed
     range like an AWS region reads as "Amazon.com, Inc." rather than an opaque CIDR. */
  function ownerCell(route) {
    const td = document.createElement("td");
    td.className = "owner";
    if (!route.public) {
      td.textContent = "—";
      td.classList.add("muted");
      return td;
    }
    if (Object.prototype.hasOwnProperty.call(whoisOrgs, route.destination)) {
      const org = whoisOrgs[route.destination];
      td.textContent = org || "No organisation on record";
      td.title = org || "";
      if (!org) td.classList.add("muted");
    } else if (whoisFailed.has(route.destination)) {
      td.textContent = "Lookup failed";
      td.classList.add("muted");
    } else {
      td.textContent = "Looking up…";
      td.classList.add("muted");
    }
    return td;
  }

  function routeRow(route) {
    const tr = document.createElement("tr");

    const dst = document.createElement("td");
    dst.className = "dst";
    dst.textContent = route.destination;
    if (TAGS[route.kind]) {
      const tag = document.createElement("span");
      tag.className = "route-tag";
      tag.textContent = TAGS[route.kind];
      tag.title = route.kind === "bypass"
        ? `Route to the VPN server itself, pinned to ${route.device} so the tunnel's own traffic does not loop.`
        : `The tunnel's own subnet, attached directly to ${route.device}.`;
      dst.append(tag);
    } else if (route.public) {
      const tag = document.createElement("span");
      tag.className = "route-tag route-tag-public";
      tag.textContent = "public";
      tag.title = "Not this VPN operator's own address space -- anything else hosted in this " +
        "range also travels through the tunnel.";
      dst.append(tag);
    }

    const via = document.createElement("td");
    via.textContent = route.gateway || route.device;
    if (!route.gateway) via.className = "muted";

    const size = document.createElement("td");
    size.className = "text-end";
    size.textContent = route.addresses === null || route.addresses === undefined
      ? "—"
      : route.addresses.toLocaleString();

    const metric = document.createElement("td");
    metric.className = "text-end muted";
    metric.textContent = route.metric === null || route.metric === undefined ? "—" : route.metric;

    tr.append(dst, via, ownerCell(route), size, metric);
    return tr;
  }

  function emptyRow(message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "text-body-secondary";
    td.textContent = message;
    tr.append(td);
    return tr;
  }

  function renderRoutes() {
    if (!routesBody) return;
    const needle = (routesFilter ? routesFilter.value : "").trim().toLowerCase();
    const shown = needle
      ? routes.filter((r) =>
          `${r.destination} ${r.gateway || ""} ${r.device}`.toLowerCase().includes(needle))
      : routes;

    if (!routesLoaded) {
      routesBody.replaceChildren(emptyRow("Loading routes…"));
    } else if (!routes.length) {
      routesBody.replaceChildren(emptyRow("No routes — the tunnel is not up."));
    } else if (!shown.length) {
      routesBody.replaceChildren(emptyRow("No routes match that filter."));
    } else {
      routesBody.replaceChildren(...shown.map(routeRow));
    }

    if (routesCount) {
      if (!routesLoaded) routesCount.textContent = "—";
      else if (!routes.length) routesCount.textContent = "0";
      else if (needle) routesCount.textContent = `${shown.length} of ${routes.length}`;
      else routesCount.textContent = `${routes.length} via ${routesDevice}`;
    }
  }

  async function loadRoutes() {
    if (!routesBody) return;
    try {
      const result = await api("/api/routes");
      routes = Array.isArray(result.routes) ? result.routes : [];
      routesDevice = result.device || routesDevice;
      routesLoaded = true;
    } catch (err) {
      routes = [];
      routesLoaded = true;
      if (routesCount) routesCount.textContent = "—";
      routesBody.replaceChildren(emptyRow(`Could not read the routing table: ${err.message}`));
      return;
    }
    renderRoutes();
    ensureWhois();
  }

  /* Looked up separately from the routes table itself, and only for what is public: whois is an
     external service with no guaranteed latency, so the table renders immediately and each row
     fills in as its lookup resolves rather than the whole panel waiting on the slowest one.
     Batched to match the server-side cap in app/services/whois.py, so a tunnel with more public
     prefixes than that still gets every one of them, just in more than one request. */
  const WHOIS_BATCH = 40;

  async function ensureWhois() {
    const seen = new Set();
    routes.forEach((route) => { if (route.public) seen.add(route.destination); });
    const need = [...seen].filter(
      (d) => !whoisPending.has(d) && !Object.prototype.hasOwnProperty.call(whoisOrgs, d)
    );
    if (!need.length) return;

    need.forEach((d) => { whoisPending.add(d); whoisFailed.delete(d); });
    renderRoutes();   // shows "Looking up…" immediately rather than after the first batch lands

    for (let i = 0; i < need.length; i += WHOIS_BATCH) {
      const batch = need.slice(i, i + WHOIS_BATCH);
      const params = new URLSearchParams();
      batch.forEach((d) => params.append("dest", d));
      try {
        const result = await api(`/api/whois?${params.toString()}`);
        (result.results || []).forEach((r) => { whoisOrgs[r.destination] = r.org; });
      } catch {
        // Left unresolved rather than shown as a wrong answer -- the row says "Lookup failed"
        // and the next routes load (a state change, or Refresh) tries again.
        batch.forEach((d) => whoisFailed.add(d));
      } finally {
        batch.forEach((d) => whoisPending.delete(d));
        renderRoutes();
      }
    }
  }

  function syncRoutes(status) {
    const key = `${status.state}|${status.tun_ip || ""}`;
    if (key === routesKey) return;
    routesKey = key;
    loadRoutes();
    loadScope();   // the verdict changes exactly when the routes behind it do
    loadDnsStatus();   // and so does who resolves what: OpenVPN configures DNS as the tunnel comes up
  }

  /* --- tunnel scope -----------------------------------------------------
     Full, split or nothing, plus whether IPv6 escapes the tunnel. Fetched on the same signal as
     the routes table, since it is derived from the same kernel state. */
  const percent = (fraction) => {
    if (fraction >= 1) return "100%";
    if (fraction <= 0) return "0%";
    const value = fraction * 100;
    /* A split tunnel can carry a ten-thousandth of the address space, so fixed decimals would
       round most real answers to "0.00%". */
    return `${value >= 0.1 ? value.toFixed(2) : value.toPrecision(2)}%`;
  };

  const familyText = (family, name) => {
    if (family.mode === "none") {
      return family.egress_device
        ? `goes direct, not through the VPN`
        : `not in use on this machine`;
    }
    if (family.mode === "full") {
      return family.redirect_pair
        ? "all of it through the VPN (via a /1 pair, not a default route)"
        : "all of it through the VPN";
    }
    return `${percent(family.coverage)} of ${name} through the VPN, the rest direct`;
  };

  /* The question this panel exists to answer, in the words someone would actually use to ask
     it: when I am connected, does my personal traffic go through this VPN or not? */
  const VERDICTS = {
    none: {
      badge: "no tunnel",
      verdict: "No tunnel is running.",
      detail:
        "Everything this machine does is going over your normal internet connection. Connect " +
        "to see what the VPN would carry.",
    },
    full: {
      badge: "all traffic",
      verdict: "Everything goes through this VPN.",
      detail:
        "All traffic from this machine — personal browsing, banking, streaming, everything — is " +
        "carried through the tunnel and leaves from the VPN's network. Nothing goes direct.",
    },
    split: {
      badge: "some traffic",
      verdict: "Only some traffic goes through this VPN.",
      detail: null,   // filled in below, because the count is part of the answer
    },
  };

  /* The verdict above is derived from IPv4 alone, so it must not claim "nothing goes direct"
     while the warning right above it says IPv6 does. */
  const detailFor = (data, copy, warned) => {
    if (data.mode === "split") {
      return (
        `Traffic to ${data.ipv4.prefixes} specific networks is carried through the tunnel. ` +
        "Everything else — personal browsing, banking, streaming — goes out over your normal " +
        "internet connection and never touches the VPN."
      );
    }
    if (data.mode === "full" && warned) {
      return (
        "All IPv4 traffic from this machine — personal browsing, banking, streaming — is " +
        "carried through the tunnel. IPv6 is not, so anything reachable over IPv6 still goes " +
        "direct."
      );
    }
    return copy.detail;
  };

  function renderScope(data) {
    const warnings = data.warnings || [];
    const copy = VERDICTS[data.mode] || VERDICTS.none;

    if (scopeMode) {
      scopeMode.dataset.mode = warnings.length ? "warn" : data.mode;
      scopeMode.textContent = warnings.length ? `${copy.badge} · ipv6 escaping` : copy.badge;
    }

    text("scope-verdict", copy.verdict);
    text("scope-detail", detailFor(data, copy, warnings.length > 0));

    text("scope-v4", familyText(data.ipv4, "IPv4"));
    text("scope-v6", familyText(data.ipv6, "IPv6"));
    text("scope-coverage", data.ipv4.mode === "none" ? "—" : percent(data.ipv4.coverage));
    text(
      "scope-prefixes",
      data.ipv4.mode === "none"
        ? "—"
        : `${data.ipv4.prefixes} routed, ${data.ipv4.blocks} after merging overlaps`
    );
    text(
      "scope-public",
      data.ipv4.mode === "none"
        ? "—"
        : data.ipv4.public_prefixes
          ? `${data.ipv4.public_prefixes} of ${data.ipv4.prefixes} (${percent(data.ipv4.public_coverage)} of the internet)`
          : "None — every routed network is private address space"
    );
    if (scopeWarnings) {
      scopeWarnings.replaceChildren();
      (data.warnings || []).forEach((warning) => {
        const box = document.createElement("div");
        box.className = "alert alert-warning py-2 mb-2";
        box.textContent = warning;
        scopeWarnings.appendChild(box);
      });
    }
    if (scopePublicNotice) {
      scopePublicNotice.replaceChildren();
      if (data.public_notice) {
        const box = document.createElement("div");
        box.className = "alert alert-info py-2 mb-2";
        box.textContent = data.public_notice;
        scopePublicNotice.appendChild(box);
      }
    }
  }

  async function loadScope() {
    try {
      renderScope(await api("/api/scope"));
    } catch {
      /* the status card already reports connectivity problems */
    }
  }

  /* --- DNS rules ----------------------------------------------------------
     Domain forwarders and fallback servers, applied to /etc/dnsmasq.d/vpn-connect.conf and
     reloaded into dnsmasq after every change -- there is no separate "Apply" step, so the
     database and the live config cannot silently drift apart. */

  const dnsFeedbackShow = (message, ok) => {
    if (!dnsFeedback) return;
    dnsFeedback.className = `small mb-0 mt-3 ${ok ? "text-body-secondary" : "text-danger"}`;
    dnsFeedback.textContent = message;
    dnsFeedback.hidden = false;
  };

  const dnsActionCell = (buttons) => {
    const td = document.createElement("td");
    td.className = "text-end";
    buttons.forEach((btn) => td.append(btn));
    return td;
  };

  const dnsButton = (label, cls, action, id) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = `btn btn-sm ${cls} ms-1`;
    btn.textContent = label;
    btn.dataset.action = action;
    btn.dataset.id = id;
    return btn;
  };

  const dnsEmptyRow = (message, colspan) => {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = colspan;
    td.className = "text-body-secondary";
    td.textContent = message;
    tr.append(td);
    return tr;
  };

  function renderDns(payload) {
    const domainRules = payload.domain_rules || [];
    const fallbackRules = payload.fallback_rules || [];

    if (dnsCount) {
      const total = domainRules.length + fallbackRules.length;
      dnsCount.textContent = total ? `${total} rule${total === 1 ? "" : "s"}` : "none";
    }

    if (dnsDomainBody) {
      if (!domainRules.length) {
        dnsDomainBody.replaceChildren(dnsEmptyRow("No domain forwarders yet.", 3));
      } else {
        dnsDomainBody.replaceChildren(
          ...domainRules.map((rule) => {
            const tr = document.createElement("tr");
            const domain = document.createElement("td");
            domain.textContent = rule.domain;
            const address = document.createElement("td");
            address.textContent = rule.address;
            tr.append(domain, address, dnsActionCell([dnsButton("Delete", "btn-outline-danger", "delete", rule.id)]));
            return tr;
          })
        );
      }
    }

    if (dnsFallbackBody) {
      if (!fallbackRules.length) {
        dnsFallbackBody.replaceChildren(dnsEmptyRow("No fallback servers yet.", 2));
      } else {
        const ordered = [...fallbackRules].sort((a, b) => (a.position ?? 0) - (b.position ?? 0));
        dnsFallbackBody.replaceChildren(
          ...ordered.map((rule, index) => {
            const tr = document.createElement("tr");
            const address = document.createElement("td");
            address.textContent = rule.address;
            const buttons = [];
            if (index > 0) buttons.push(dnsButton("↑", "btn-outline-secondary", "up", rule.id));
            if (index < ordered.length - 1) {
              buttons.push(dnsButton("↓", "btn-outline-secondary", "down", rule.id));
            }
            buttons.push(dnsButton("Delete", "btn-outline-danger", "delete", rule.id));
            tr.append(address, dnsActionCell(buttons));
            return tr;
          })
        );
      }
    }

    if (dnsLegacy) {
      if (payload.legacy) {
        const count = payload.legacy.rules.length;
        dnsLegacyText.textContent =
          `${count} rule${count === 1 ? "" : "s"} found in ${payload.legacy.path} — review and ` +
          "import to manage them here. The file is retired once you do.";
        dnsLegacy.hidden = false;
      } else {
        dnsLegacy.hidden = true;
      }
    }

    if (payload.warning) dnsFeedbackShow(payload.warning, false);

    // The verdict cross-references the rules that were just rendered, so it is refreshed from
    // here rather than from each caller -- every path that changes a rule ends up here.
    loadDnsStatus();
  }

  /* Who actually resolves what. A domain forwarder is essential on a tunnel that applies no DNS
     of its own and dead weight on one that has taken DNS over entirely, and nothing about the
     rule itself says which -- so the answer is read from systemd-resolved and shown above them. */
  function renderDnsStatus(report) {
    if (!dnsStatus) return;
    /* Red, not amber, for "all": every lookup this machine makes is going down the tunnel, so
       whoever runs the VPN sees every site you visit. The other actionable case is only that
       some rules below are doing nothing, which is untidy rather than exposing. */
    const tone =
      report.mode === "all"
        ? "alert-danger"
        : report.action_needed
          ? "alert-warning"
          : "alert-secondary";
    dnsStatus.className = `alert small mt-2 ${tone}`;
    dnsStatusHeadline.textContent = report.headline;
    dnsStatusDetail.textContent = report.detail;

    dnsStatusNotes.replaceChildren(
      ...(report.notes || []).map((note) => {
        const li = document.createElement("li");
        li.textContent = note;
        return li;
      }),
    );

    const pushed = report.pushed_servers || [];
    if (pushed.length) {
      dnsStatusPushed.textContent = `The server offered ${pushed.join(", ")}.`;
      dnsStatusPushed.hidden = false;
    } else {
      dnsStatusPushed.hidden = true;
    }
  }

  async function loadDnsStatus() {
    if (!dnsStatus) return;
    try {
      renderDnsStatus(await api("/api/dns/status"));
    } catch (err) {
      dnsStatus.className = "alert alert-secondary small mt-2";
      dnsStatusHeadline.textContent = "Could not read the resolver state.";
      dnsStatusDetail.textContent = err.message;
      dnsStatusNotes.replaceChildren();
      dnsStatusPushed.hidden = true;
    }
  }

  async function loadDns() {
    if (!dnsDomainBody) return;
    try {
      renderDns(await api("/api/dns"));
    } catch (err) {
      dnsDomainBody.replaceChildren(dnsEmptyRow(`Could not load DNS rules: ${err.message}`, 3));
      dnsFallbackBody.replaceChildren();
    }
  }

  if (dnsDomainForm) {
    dnsDomainForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = dnsDomainForm.querySelector("button[type=submit]");
      button.disabled = true;
      try {
        const payload = await api("/api/dns", {
          method: "POST",
          body: JSON.stringify({
            kind: "domain",
            domain: document.getElementById("dns-domain-name").value,
            address: document.getElementById("dns-domain-address").value,
          }),
        });
        renderDns(payload);
        dnsDomainForm.reset();
        if (!payload.warning) dnsFeedbackShow("Saved and applied.", true);
      } catch (err) {
        dnsFeedbackShow(err.message, false);
      } finally {
        button.disabled = false;
      }
    });
  }

  if (dnsFallbackForm) {
    dnsFallbackForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = dnsFallbackForm.querySelector("button[type=submit]");
      button.disabled = true;
      try {
        const payload = await api("/api/dns", {
          method: "POST",
          body: JSON.stringify({
            kind: "fallback",
            address: document.getElementById("dns-fallback-address").value,
          }),
        });
        renderDns(payload);
        dnsFallbackForm.reset();
        if (!payload.warning) dnsFeedbackShow("Saved and applied.", true);
      } catch (err) {
        dnsFeedbackShow(err.message, false);
      } finally {
        button.disabled = false;
      }
    });
  }

  const dnsRowAction = async (event, table) => {
    const button = event.target.closest("[data-action]");
    if (!button || !table.contains(button)) return;
    const { action, id } = button.dataset;
    if (action === "delete" && !window.confirm("Delete this DNS rule?")) return;
    button.disabled = true;
    try {
      const path = action === "delete" ? `/api/dns/${id}/delete` : `/api/dns/${id}/move`;
      const body = action === "delete" ? undefined : JSON.stringify({ direction: action });
      renderDns(await api(path, { method: "POST", body }));
      if (action !== "delete") return;   // the row (and its button) is gone
      dnsFeedbackShow("Applied.", true);
    } catch (err) {
      button.disabled = false;
      dnsFeedbackShow(err.message, false);
    }
  };

  if (dnsDomainBody) {
    dnsDomainBody.addEventListener("click", (e) => dnsRowAction(e, dnsDomainBody));
  }
  if (dnsFallbackBody) {
    dnsFallbackBody.addEventListener("click", (e) => dnsRowAction(e, dnsFallbackBody));
  }

  if (dnsImport) {
    dnsImport.addEventListener("click", async () => {
      dnsImport.disabled = true;
      try {
        const payload = await api("/api/dns/import", { method: "POST" });
        renderDns(payload);
        if (!payload.warning) {
          dnsFeedbackShow(`Imported ${payload.imported} rule(s) and applied.`, true);
        }
      } catch (err) {
        dnsImport.disabled = false;
        dnsFeedbackShow(err.message, false);
      }
    });
  }

  function schedule(delay) {
    clearTimeout(timer);
    timer = setTimeout(poll, delay);
  }

  async function poll() {
    try {
      render(await api("/api/status"));
    } catch (err) {
      showError(err.message);
      schedule(IDLE_POLL);
    }
  }

  if (form) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      submitting = true;
      showError("");
      connectBtn.disabled = true;
      try {
        await api("/api/connect", {
          method: "POST",
          body: JSON.stringify({
            profile: document.getElementById("profile").value,
            otp: otpInput.value,
          }),
        });
        otpInput.value = "";
      } catch (err) {
        showError(err.message);
      } finally {
        submitting = false;
        schedule(200);
      }
    });
  }

  if (disconnectConfirm) {
    disconnectConfirm.addEventListener("click", async () => {
      const modalEl = document.getElementById("disconnect-modal");
      bootstrap.Modal.getOrCreateInstance(modalEl).hide();
      submitting = true;
      showError("");
      try {
        await api("/api/disconnect", { method: "POST" });
      } catch (err) {
        showError(err.message);
      } finally {
        submitting = false;
        schedule(200);
      }
    });
  }

  /* One form saves the topic and all three message bodies together. Bodies are read straight
     off the [data-kind] blocks, so adding a kind to the template needs no change here. */
  const readBodies = () => {
    const bodies = {};
    notifyForm.querySelectorAll("[data-kind]").forEach((block) => {
      const field = block.querySelector("[data-field='body']");
      if (field) bodies[block.dataset.kind] = field.value;
    });
    return bodies;
  };

  const writeBodies = (bodies) => {
    notifyForm.querySelectorAll("[data-kind]").forEach((block) => {
      const field = block.querySelector("[data-field='body']");
      if (field && bodies[block.dataset.kind] !== undefined) {
        field.value = bodies[block.dataset.kind];
      }
    });
  };

  const saveNotify = async (bodies) => {
    const button = document.getElementById("notify-save");
    button.disabled = true;
    try {
      const result = await api("/api/notify", {
        method: "POST",
        body: JSON.stringify({ topic: notifyInput.value, bodies }),
      });
      writeBodies(result.bodies);
      notifyFeedback.className = "small mb-0 text-body-secondary";
      notifyFeedback.textContent = result.enabled
        ? `Saved. Notifications go to ${result.url} — subscribe to that topic in the ntfy app.`
        : "Saved. Notifications are off.";
    } catch (err) {
      notifyFeedback.className = "small mb-0 text-danger";
      notifyFeedback.textContent = err.message;
    } finally {
      notifyFeedback.hidden = false;
      button.disabled = false;
    }
  };

  if (notifyForm) {
    notifyForm.addEventListener("submit", (event) => {
      event.preventDefault();
      saveNotify(readBodies());
    });
  }

  if (messagesReset) {
    /* Saving blank bodies is what restores the defaults, so this needs no separate endpoint. */
    messagesReset.addEventListener("click", () => {
      notifyForm.querySelectorAll("[data-field='body']").forEach((el) => { el.value = ""; });
      saveNotify(readBodies());
    });
  }

  if (notifyTest) {
    /* Saves first: testing text the operator has edited but not saved would be misleading. */
    notifyTest.addEventListener("click", async () => {
      notifyTest.disabled = true;
      try {
        await saveNotify(readBodies());
        const result = await api("/api/notify/test", { method: "POST" });
        notifyFeedback.className = "small mb-0 text-body-secondary";
        notifyFeedback.textContent = `Test notification sent to ${result.url}.`;
      } catch (err) {
        notifyFeedback.className = "small mb-0 text-danger";
        notifyFeedback.textContent = err.message;
      } finally {
        notifyFeedback.hidden = false;
        notifyTest.disabled = false;
      }
    });
  }

  /* Connections. The form posts multipart so the .ovpn arrives as a file rather than a string
     the operator would have to paste. */
  if (connectionForm) {
    connectionForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = document.getElementById("connection-save");
      button.disabled = true;
      try {
        const response = await fetch("/api/connections", {
          method: "POST",
          credentials: "same-origin",
          headers: { "X-CSRF-Token": csrf },   // no Content-Type: the browser sets the boundary
          body: new FormData(connectionForm),
        });
        const result = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
        connectionFeedback.className = "small mb-0 text-body-secondary";
        connectionFeedback.textContent = `Saved “${result.display_name}”. Reloading…`;
        window.location.reload();
      } catch (err) {
        connectionFeedback.className = "small mb-0 text-danger";
        connectionFeedback.textContent = err.message;
      } finally {
        connectionFeedback.hidden = false;
        button.disabled = false;
      }
    });
  }

  if (connectionsBody) {
    connectionsBody.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-action]");
      if (!button) return;
      const { action, name } = button.dataset;
      if (action === "delete" && !window.confirm(`Delete the connection “${name}”?`)) return;
      button.disabled = true;
      try {
        await api(`/api/connections/${encodeURIComponent(name)}/${action}`, { method: "POST" });
        window.location.reload();
      } catch (err) {
        button.disabled = false;
        showError(err.message);
      }
    });
  }

  if (profileSelect && otpLabel) {
    /* Both the prompt text and whether a code is wanted at all are per-connection, so the field
       follows the selection. `required` has to come off with the field: a hidden required input
       blocks submission with a validation message the browser cannot show anywhere. */
    const syncChallenge = () => {
      const option = profileSelect.selectedOptions[0];
      if (!option) return;
      if (option.dataset.challenge) otpLabel.textContent = option.dataset.challenge;

      const wanted = option.dataset.mfa !== "0";
      if (otpField) otpField.hidden = !wanted;
      if (otpInput) {
        otpInput.required = wanted;
        if (!wanted) otpInput.value = "";
      }
      if (connectHint) {
        connectHint.textContent = wanted
          ? "The username and password come from the stored connection. Only the code is needed here."
          : "This profile signs in with its stored username and password alone — it asks for no authenticator code.";
      }
    };
    profileSelect.addEventListener("change", syncChallenge);
    syncChallenge();
  }

  /* --- traffic graph ----------------------------------------------------
     Hand-drawn SVG rather than a charting library: two series over time is a page of maths,
     and a vendored library would be the largest asset in the app by an order of magnitude.
     The viewBox is stretched to the panel width (preserveAspectRatio="none"), so all text is
     HTML outside the SVG -- inside it would stretch with the graph. */
  const CHART = { w: 600, h: 160, pad: 6 };
  const SVG_NS = "http://www.w3.org/2000/svg";

  const rate = (bytesPerSecond) => `${bytes(bytesPerSecond)}/s`;

  const svgEl = (name, attrs) => {
    const node = document.createElementNS(SVG_NS, name);
    Object.entries(attrs).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  };

  /* Mirrored areas: received above the centre line, sent below. It is the conventional shape
     for a network graph, and it keeps the two series from hiding each other. */
  const buildPath = (points, scale, direction) => {
    const mid = CHART.h / 2;
    const usable = mid - CHART.pad;
    const step = points.length > 1 ? CHART.w / (points.length - 1) : 0;
    const y = (value) => mid - direction * (scale > 0 ? (value / scale) * usable : 0);
    const line = points
      .map((point, index) => `${index ? "L" : "M"}${(index * step).toFixed(1)},${y(point).toFixed(1)}`)
      .join(" ");
    return { line, area: `${line} L${CHART.w},${mid} L0,${mid} Z` };
  };

  const renderTraffic = (data) => {
    if (!trafficChart) return;
    while (trafficChart.lastChild && trafficChart.lastChild.nodeName !== "title") {
      trafficChart.removeChild(trafficChart.lastChild);
    }
    const points = data.points || [];
    const mid = CHART.h / 2;
    trafficChart.appendChild(
      svgEl("line", { class: "traffic-axis", x1: 0, y1: mid, x2: CHART.w, y2: mid,
                      "vector-effect": "non-scaling-stroke" })
    );

    if (points.length < 2) {
      trafficSpan.textContent = data.session
        ? "Waiting for samples — the first rate needs two readings."
        : "No connection attempts recorded yet.";
      trafficScale.textContent = "—";
      trafficTotals.textContent = "";
      trafficChart.setAttribute("aria-label", "No traffic data yet");
      return;
    }

    /* One shared scale for both directions, so "sent" and "received" stay comparable by eye
       rather than each being normalised to its own maximum. */
    const scale = Math.max(...points.map((p) => Math.max(p.rx, p.tx)), 1);
    const rx = buildPath(points.map((p) => p.rx), scale, 1);
    const tx = buildPath(points.map((p) => p.tx), scale, -1);

    [[mid / 2, ""], [mid * 1.5, ""]].forEach(([y]) => {
      trafficChart.appendChild(
        svgEl("line", { class: "traffic-grid", x1: 0, y1: y, x2: CHART.w, y2: y,
                        "stroke-dasharray": "3 4", "vector-effect": "non-scaling-stroke" })
      );
    });
    trafficChart.appendChild(svgEl("path", { class: "traffic-rx-fill", d: rx.area }));
    trafficChart.appendChild(svgEl("path", { class: "traffic-tx-fill", d: tx.area }));
    trafficChart.appendChild(
      svgEl("path", { class: "traffic-rx-line", d: rx.line, "vector-effect": "non-scaling-stroke" })
    );
    trafficChart.appendChild(
      svgEl("path", { class: "traffic-tx-line", d: tx.line, "vector-effect": "non-scaling-stroke" })
    );

    const latest = points[points.length - 1];
    /* Both peaks, because the two series share one scale so that they stay comparable by eye.
       Without this the quieter direction reads as a flat line with no way to tell what it was. */
    trafficScale.textContent = `peak ${rate(data.peak_rx)} ↓ · ${rate(data.peak_tx)} ↑`;
    trafficSpan.textContent = `${duration(Math.round(data.span_seconds))} of this connection`;
    trafficTotals.textContent =
      `${bytes(data.bytes_in)} in · ${bytes(data.bytes_out)} out`;
    trafficChart.setAttribute(
      "aria-label",
      `Throughput: ${rate(latest.rx)} received, ${rate(latest.tx)} sent. ` +
        `Peak ${rate(data.peak_rx)} received, ${rate(data.peak_tx)} sent.`
    );
    if (trafficSummary) {
      trafficSummary.textContent = `${rate(latest.rx)} ↓ · ${rate(latest.tx)} ↑`;
    }
  };

  let trafficTimer = null;

  const loadTraffic = async () => {
    try {
      renderTraffic(await api("/api/traffic"));
    } catch {
      /* the status card already reports connectivity problems; do not double up */
    }
  };

  const trafficPanel = document.getElementById("panel-traffic");
  const scopePanel = document.getElementById("panel-scope");
  const dnsPanel = document.getElementById("panel-dns");

  const pollTraffic = (on) => {
    window.clearInterval(trafficTimer);
    trafficTimer = null;
    if (!on) return;
    loadTraffic();
    /* Only while the panel is open. Closed, this costs nothing at all -- which is why the
       series is not folded into /api/status. */
    trafficTimer = window.setInterval(loadTraffic, IDLE_POLL);
  };

  if (scopePanel) {
    scopePanel.addEventListener("shown.bs.collapse", (e) => {
      if (e.target === scopePanel) loadScope();
    });
  }

  if (trafficPanel) {
    trafficPanel.addEventListener("shown.bs.collapse", (e) => {
      if (e.target === trafficPanel) pollTraffic(true);
    });
    trafficPanel.addEventListener("hidden.bs.collapse", (e) => {
      if (e.target === trafficPanel) pollTraffic(false);
    });
  }

  if (dnsPanel) {
    dnsPanel.addEventListener("shown.bs.collapse", (e) => {
      if (e.target === dnsPanel) loadDns();
    });
  }

  /* Panels remember whether you left them open. Worth doing rather than relying on the markup
     default: saving a connection reloads the page, which would otherwise shut everything you
     had opened. A panel marked data-panel-locked keeps the server's choice -- that is the
     Connections panel on a fresh install, which must always greet you open. */
  const PANEL_KEY = "vpn-connect:panels";

  const readPanelState = () => {
    try {
      const stored = JSON.parse(window.localStorage.getItem(PANEL_KEY) || "{}");
      return stored && typeof stored === "object" ? stored : {};
    } catch {
      return {};   // private mode, or someone put junk in there
    }
  };

  const writePanelState = (state) => {
    try {
      window.localStorage.setItem(PANEL_KEY, JSON.stringify(state));
    } catch {
      /* storage unavailable: panels simply stop being remembered */
    }
  };

  const panels = document.querySelectorAll(".collapse[data-panel]");
  if (panels.length) {
    const state = readPanelState();
    panels.forEach((panel) => {
      const toggle = document.querySelector(`[data-bs-target="#${panel.id}"]`);
      const remembered = state[panel.dataset.panel];
      if (panel.dataset.panelLocked === undefined && typeof remembered === "boolean") {
        panel.classList.toggle("show", remembered);
        if (toggle) {
          toggle.classList.toggle("collapsed", !remembered);
          toggle.setAttribute("aria-expanded", String(remembered));
        }
      }
      /* A panel restored open by the code above never fires shown.bs.collapse, so it would sit
         empty until something else happened to refresh it. */
      if (panel.classList.contains("show")) {
        if (panel === trafficPanel) pollTraffic(true);
        if (panel === scopePanel) loadScope();
        if (panel === dnsPanel) loadDns();
      }
      ["shown.bs.collapse", "hidden.bs.collapse"].forEach((event) => {
        panel.addEventListener(event, (e) => {
          if (e.target !== panel) return;      // nested collapses must not write our key
          const next = readPanelState();
          next[panel.dataset.panel] = event === "shown.bs.collapse";
          writePanelState(next);
        });
      });
    });
  }

  if (routesFilter) {
    routesFilter.addEventListener("input", renderRoutes);
  }

  if (routesRefresh) {
    routesRefresh.addEventListener("click", async () => {
      routesRefresh.disabled = true;
      try {
        await loadRoutes();
      } finally {
        routesRefresh.disabled = false;
      }
    });
  }

  if (themeToggle) {
    themeToggle.addEventListener("click", () => window.vpnTheme.toggle());
  }

  poll();
  loadDrift();
  window.setInterval(loadDrift, DRIFT_POLL);
})();
