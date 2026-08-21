/* Applies the saved theme before first paint, so there is no flash of the wrong palette.
   Loaded synchronously in <head> — deliberately not deferred. */
(() => {
  "use strict";
  const KEY = "vpn-connect-theme";
  const stored = (() => {
    try { return localStorage.getItem(KEY); } catch { return null; }
  })();
  const system = () =>
    window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";

  const apply = (choice) => {
    const resolved = choice === "light" || choice === "dark" ? choice : system();
    document.documentElement.setAttribute("data-bs-theme", resolved);
    document.documentElement.dataset.themeChoice = choice || "system";
  };

  apply(stored);

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (!document.documentElement.dataset.themeChoice ||
        document.documentElement.dataset.themeChoice === "system") {
      apply(null);
    }
  });

  window.vpnTheme = {
    toggle() {
      const next =
        document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark";
      try { localStorage.setItem(KEY, next); } catch { /* private mode: session-only */ }
      apply(next);
      return next;
    },
  };
})();
