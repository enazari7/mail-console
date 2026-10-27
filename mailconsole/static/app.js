// BeastPing Mail Console: small progressive enhancements. Every feature also
// works without JavaScript (links and forms); nothing here talks to the server.
(function () {
  "use strict";

  // Dropdowns (<details data-dd>): one open at a time, close on outside click / Escape.
  const dropdowns = () => document.querySelectorAll("details[data-dd]");
  document.addEventListener("toggle", (ev) => {
    const el = ev.target;
    if (el.matches && el.matches("details[data-dd]") && el.open) {
      dropdowns().forEach((d) => { if (d !== el) d.open = false; });
      const first = el.querySelector(".dd-menu a, .dd-menu button, .dd-menu input");
      if (first && el.classList.contains("row-menu")) first.focus({ preventScroll: true });
    }
  }, true);
  document.addEventListener("click", (ev) => {
    dropdowns().forEach((d) => { if (d.open && !d.contains(ev.target)) d.open = false; });
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    dropdowns().forEach((d) => {
      if (d.open) { d.open = false; const s = d.querySelector("summary"); if (s) s.focus(); }
    });
  });

  // Debounced search: submit 450 ms after typing stops (empty, 3+ chars, or an exact short term on Enter).
  const box = document.querySelector("input[data-search]");
  if (box && box.form) {
    let timer = null;
    const initial = box.value;
    box.addEventListener("input", () => {
      clearTimeout(timer);
      const v = box.value.trim();
      if (v === initial.trim() || (v.length > 0 && v.length < 3)) return;
      timer = setTimeout(() => box.form.requestSubmit(), 450);
    });
    if (box.hasAttribute("data-refocus")) {
      box.focus({ preventScroll: true });
      const end = box.value.length;
      box.setSelectionRange(end, end);
    }
  }

  // Clickable rows: open the details page unless an interactive element was used.
  document.addEventListener("click", (ev) => {
    const row = ev.target.closest && ev.target.closest("tr[data-href]");
    if (!row || ev.target.closest("a, button, details, summary, input, label")) return;
    if (window.getSelection && String(window.getSelection()).length) return; // allow text selection
    if (ev.metaKey || ev.ctrlKey || ev.button === 1) window.open(row.dataset.href, "_blank", "noopener");
    else window.location.assign(row.dataset.href);
  });

  // Copy buttons.
  document.addEventListener("click", async (ev) => {
    const btn = ev.target.closest && ev.target.closest("[data-copy]");
    if (!btn) return;
    ev.preventDefault();
    const label = btn.querySelector("span");
    const before = label ? label.textContent : "";
    try {
      await navigator.clipboard.writeText(btn.dataset.copy);
      if (label) label.textContent = "Copied";
    } catch (e) {
      if (label) label.textContent = "Copy failed – select the value instead";
    }
    setTimeout(() => {
      if (label) label.textContent = before;
      const menu = btn.closest("details");
      if (menu) menu.open = false;
    }, 900);
  });
})();
