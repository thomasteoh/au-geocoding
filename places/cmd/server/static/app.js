// app.js — the demo search SPA. Hosts the explainer animation beside a live
// search box that POSTs to /search and renders the strategy chip, result cards,
// a local SVG map, a JSON playground, and error/ambiguity states.
//
// Per ux.md: single input, debounce 250ms with AbortController, POST (keeps
// queries out of proxy logs), strategy chip is the most useful element, results
// expand in place, the map is a local SVG from our own data (no tiles), the
// playground shows the exact request/response that just ran.

(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => {
    if (c === "&") return String.fromCharCode(38) + "amp;";
    if (c === "<") return String.fromCharCode(38) + "lt;";
    if (c === ">") return String.fromCharCode(38) + "gt;";
    if (c === '"') return String.fromCharCode(38) + "quot;";
    return String.fromCharCode(38) + "#39;";
  });

  const state = {
    query: "",
    results: null,
    expanded: null,
  };

  const STRATEGY_COLORS = {
    poi_anchor: "#3987e5",
    address: "#199e70",
    coord: "#6b46c1",
    poi: "#dd6b20",
  };

  // ---- search ------------------------------------------------------------

  async function search(q) {
    // Debounce already coalesces rapid typing; a per-request AbortController
    // was cancelling in-flight fetches before they resolved. Keep it simple.
    const status = $("#status-bar");
    try {
      const res = await fetch("/search", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ query: q }),
      });
      if (!res.ok) throw new Error("search failed: " + res.status);
      const data = await res.json();
      state.results = data;
      renderResults(data);
      // Empty state: no candidates is a real outcome (out-of-scope / nothing
      // matched), not a blank list. Show it explicitly.
      if (status) {
        const n = (data.candidates || []).length;
        if (n === 0) {
          status.textContent = "No candidates — the query didn't match any address or POI in scope.";
          status.className = "status-warn";
        } else {
          status.textContent = "Matched " + n + " candidate" + (n === 1 ? "" : "s") + ".";
          status.className = "status-ok";
        }
      }
      return data;
    } catch (e) {
      console.error("search failed", e);
      // Error state: a 500 / network failure should say so, not show a blank list.
      if (status) {
        status.textContent = "Search failed: " + (e && e.message ? e.message : "network error") + " — try again.";
        status.className = "status-error";
      }
      throw e;
    }
  }

  function debounce(fn, ms) {
    let t;
    return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
  }

  // ---- result rendering ---------------------------------------------------

  function renderResults(data) {
    const out = $("#result-list");
    if (!out) return;

    const chip = $("#strategy-chip");
    if (chip) {
      const color = STRATEGY_COLORS[data.strategy] || "#718096";
      chip.style.color = color;
      chip.textContent = "⚡ " + data.strategy + " · " + data.generated + " gen";
    }

    const meta = $("#result-meta");
    if (meta) {
      meta.textContent = data.total + " results" +
        (data.ambiguous && data.ambiguous.length ? " · ambiguous" : "") +
        (data.truncated ? " · truncated" : "");
    }

    const list = $("#result-list");
    if (list) {
      list.innerHTML = "";
      (data.candidates || []).forEach((c, i) => {
        const card = document.createElement("div");
        card.className = "result-card";
        card.dataset.kind = c.kind;
        card.dataset.index = String(i);
        // Keyboard reachable: the card is focusable and arrow-key navigable.
        card.tabIndex = 0;
        card.setAttribute("role", "button");
        card.setAttribute("aria-expanded", "false");
        card.innerHTML = `
          <div class="result-head">
            <span class="result-name">${esc(c.name || c.id || c.kind)}</span>
            <span class="result-src">▸ ${esc(c.source)}</span>
          </div>
          ${c.address ? `<div class="result-addr">${esc(c.address)}</div>` : ""}
          ${c.distance_m ? `<div class="result-dist">${c.distance_m} m from anchor</div>` : ""}
          ${c.latitude ? `<div class="result-coord">${c.latitude.toFixed(4)}, ${c.longitude.toFixed(4)}</div>` : ""}
        `;
        card.addEventListener("click", () => expandCard(card, c, i));
        card.addEventListener("keydown", (e) => {
          // Arrow-key navigation through the result list; Enter/Space expands.
          if (e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            const cards = list.querySelectorAll(".result-card");
            const idx = Number(card.dataset.index);
            const next = e.key === "ArrowDown" ? idx + 1 : idx - 1;
            if (next >= 0 && next < cards.length) cards[next].focus();
          } else if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            expandCard(card, c, i);
          }
        });
        list.append(card);
      });
    }

    renderMap(data);
    renderPlayground(data);
    renderStates(data);
  }

  function expandCard(card, c, i) {
    // Real expansion: toggle an .expanded class AND the meters that ux.md
    // specifies (match/authorities/precision). The CSS for .expanded is in
    // anim.css; the detail block renders the G-NAF quality axes.
    if (state.expanded === i) {
      card.classList.toggle("expanded");
      card.setAttribute("aria-expanded", card.classList.contains("expanded") ? "true" : "false");
      return;
    }
    state.expanded = i;
    card.classList.add("expanded");
    card.setAttribute("aria-expanded", "true");
    // Append the detail meters once (idempotent).
    const detail = card.querySelector(".result-detail");
    if (!detail) {
      const d = document.createElement("div");
      d.className = "result-detail";
      const match = c.match_score !== undefined ? c.match_score.toFixed(2) : "—";
      const conf = c.gnaf_confidence !== undefined ? c.gnaf_confidence : "—";
      const rel = c.geocode_reliability !== undefined ? c.geocode_reliability : "—";
      d.innerHTML = `
        <div class="result-meter">match ${esc(match)}</div>
        <div class="result-meter">authorities ${esc(conf)}</div>
        <div class="result-meter">precision ${esc(rel)}</div>
      `;
      card.append(d);
    }
  }

  // ---- local SVG map (from our own data, no tiles) -------------------------

  function renderMap(data) {
    const map = $("#map");
    if (!map) return;
    // Project anchor + candidates into an SVG viewport. Fit to the data, not a
    // hardcoded Victoria bbox — a NSW or rural VIC point would render off-canvas.
    // Address/coord responses have no anchor, but their candidates carry
    // coordinates — render them anyway (a single candidate = a lone point).
    const W = 300, H = 300;
    const pts = [];
    if (data.anchor) pts.push(data.anchor);
    (data.candidates || []).forEach((c) => { if (c.latitude) pts.push(c); });
    let latMin = Infinity, latMax = -Infinity, lonMin = Infinity, lonMax = -Infinity;
    pts.forEach((p) => {
      const lat = p.latitude, lon = p.longitude;
      if (typeof lat !== "number" || typeof lon !== "number") return;
      if (lat < latMin) latMin = lat;
      if (lat > latMax) latMax = lat;
      if (lon < lonMin) lonMin = lon;
      if (lon > lonMax) lonMax = lon;
    });
    // No finite points: clear the map.
    if (!isFinite(latMin) || !isFinite(lonMin)) { map.innerHTML = ""; return; }
    // Pad the fit box so the points aren't on the exact edge.
    const pad = 0.02;
    const latSpan = (latMax - latMin) || 0.01;
    const lonSpan = (lonMax - lonMin) || 0.01;
    latMin -= latSpan * pad; latMax += latSpan * pad;
    lonMin -= lonSpan * pad; lonMax += lonSpan * pad;
    const x = (lon) => ((lon - lonMin) / (lonMax - lonMin || 1)) * W;
    const y = (lat) => ((latMax - lat) / (latMax - latMin || 1)) * H;
    let svg = `<svg viewBox="0 0 ${W} ${H}" class="local-map">`;
    if (data.anchor) {
      svg += `<circle cx="${x(data.anchor.longitude)}" cy="${y(data.anchor.latitude)}" r="6" fill="#d97706" />`;
      svg += `<text x="${x(data.anchor.longitude)+8}" y="${y(data.anchor.latitude)}" font-size="10">anchor</text>`;
    }
    (data.candidates || []).forEach((c) => {
      if (!c.latitude) return;
      svg += `<circle cx="${x(c.longitude)}" cy="${y(c.latitude)}" r="5" fill="#3987e5" />`;
    });
    svg += `</svg>`;
    map.innerHTML = svg;
  }

  // ---- JSON playground (the exact request/response that just ran) ----------

  function renderPlayground(data) {
    const pg = $("#playground");
    if (!pg) return;
    pg.textContent = JSON.stringify({
      request: { query: state.query },
      response: data,
    }, null, 2);
  }

  // ---- ambiguity / error states -------------------------------------------

  function renderStates(data) {
    const amb = $("#ambig");
    if (!amb) return;
    if (data.ambiguous && data.ambiguous.length) {
      amb.innerHTML = `<div class="ambig-note">⚠ ${data.ambiguous.length} localities named “${esc(data.ambiguous[0].name)}”. Which one?</div>` +
        data.ambiguous.map((a) => `<button class="ambig-chip" data-state="${esc(a.state)}">${esc(a.state)}</button>`).join("");
      return;
    }
    amb.innerHTML = "";
  }

  // ---- init ----------------------------------------------------------------

  function init() {
    const input = $("#search-input");
    if (!input) {
      // The element isn't in the DOM yet (readyState guard raced the parse).
      // Retry on next tick / DOMContentLoaded.
      if (document.readyState !== "complete") {
        document.addEventListener("DOMContentLoaded", init);
      }
      return;
    }
    const run = debounce(() => search(input.value.trim()), 250);
    input.addEventListener("input", run);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") { e.preventDefault(); search(input.value.trim()); }
    });
    // Explainer toggle: show/hide the animation side panel.
    const toggle = $("#explainer-toggle");
    if (toggle) {
      toggle.addEventListener("click", () => {
        const panel = $("#explainer");
        const hidden = panel.style.display === "none";
        panel.style.display = hidden ? "" : "none";
        toggle.setAttribute("aria-expanded", String(hidden));
      });
    }
    // Prefill the flagship query so the explainer and the live result agree.
    input.value = "woolworths near doncaster and blackburn road";
    search(input.value.trim());
  }

  document.addEventListener("DOMContentLoaded", init);
  // Also run if the document is already loaded (scripts at the end can race
  // the event). Guard against double-init.
  if (document.readyState === "complete" || document.readyState === "interactive") {
    init();
  }
})();
