// anim.js — the JSON-driven animation engine for the geocoding explainer.
// Zero-dependency, vanilla JS, no build step. Reads scenes.json (same-origin)
// and renders each scene as a sequence of beats on a clock.
//
// Data contract (from presentations.md):
//   AnimationScene { id, title, teaches, duration, beats }
//   Beat = type 'type'|'highlight'|'split'|'probe'|'badge'|'scatter'|'window'|
//          'drawLine'|'cross'|'ring'|'note'
//
// Controls: play/pause, step fwd/back, scene chips, speed 0.5/1/2, replay.
// reduced-motion: every scene skips to its final keyframe with no tween.

(() => {
  "use strict";

  const state = {
    scenes: [],
    sceneIndex: 0,
    beatIndex: 0,
    playing: false,
    speed: 1,
    reducedMotion: false,
    timer: null,
    stage: null,
  };

  // ---- helpers ----------------------------------------------------------

  const $ = (sel) => document.querySelector(sel);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => {
    if (c === "&") return String.fromCharCode(38) + "amp;";
    if (c === "<") return String.fromCharCode(38) + "lt;";
    if (c === ">") return String.fromCharCode(38) + "gt;";
    if (c === '"') return String.fromCharCode(38) + "quot;";
    return String.fromCharCode(38) + "#39;";
  });

  const reducedMotion = () =>
    window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- rendering --------------------------------------------------------

  function buildSceneDOM(scene, stage) {
    stage.innerHTML = "";
    const header = document.createElement("div");
    header.className = "anim-header";
    header.innerHTML = `<h2>${esc(scene.title)}</h2>`;
    stage.append(header);

    const body = document.createElement("div");
    body.className = "anim-stage";
    body.dataset.scene = scene.id;
    stage.append(body);

    const caption = document.createElement("p");
    caption.className = "anim-caption";
    caption.textContent = scene.teaches || "";
    stage.append(caption);

    const controls = document.createElement("div");
    controls.className = "anim-controls";
    controls.innerHTML = `
      <button data-act="play">▶ Play</button>
      <button data-act="pause">⏸ Pause</button>
      <button data-act="step-fwd">⏭ Step</button>
      <button data-act="step-back">⏮ Back</button>
      <button data-act="replay">↻ Replay</button>
      <label>Speed
        <select data-act="speed">
          <option value="0.5">0.5×</option>
          <option value="1" selected>1×</option>
          <option value="2">2×</option>
        </select>
      </label>
    `;
    stage.append(controls);

    const progress = document.createElement("div");
    progress.className = "anim-progress";
    progress.innerHTML = `<div class="anim-progress-fill"></div>`;
    stage.append(progress);

    return { body, caption, progress };
  }

  function beatNode(beat) {
    const n = document.createElement("div");
    n.className = "anim-beat anim-beat-" + beat.type;
    switch (beat.type) {
      case "type": n.textContent = beat.text; break;
      case "highlight": n.dataset.target = beat.target; n.textContent = beat.target; break;
      case "split":
        n.innerHTML = beat.into.map((s) => `<span class="anim-frag">${esc(s)}</span>`).join(" ");
        break;
      case "probe":
        n.dataset.result = String(beat.result);
        n.textContent = beat.target + (beat.result ? " ✓" : " ✗");
        break;
      case "badge": n.textContent = beat.text; break;
      case "note": n.textContent = beat.text; break;
      case "scatter":
        n.dataset.color = beat.color || "";
        // A scatter beat may reference the heavy scene4.json payload by name
        // (e.g. {payload:"doncaster"}) or carry inline points.
        const pts = beat.points || (beat.payload && state.scene4[beat.payload]) || [];
        // Project lat/lon into the stage if the payload carries geographic
        // coordinates (scene4.json), else use inline x/y percentages.
        const geo = pts.length && (pts[0].lat !== undefined);
        const geoBounds = beat.bounds || state.scene4.window || null;
        pts.forEach((p) => {
          const d = document.createElement("div");
          d.className = "anim-point";
          if (geo && geoBounds) {
            const x = ((p.lon - geoBounds.lonMin) / (geoBounds.lonMax - geoBounds.lonMin || 1)) * 100;
            const y = ((geoBounds.latMax - p.lat) / (geoBounds.latMax - geoBounds.latMin || 1)) * 100;
            d.style.left = x + "%"; d.style.top = y + "%";
          } else {
            d.style.left = p.x + "%"; d.style.top = p.y + "%";
          }
          d.dataset.color = beat.color || "";
          n.append(d);
        });
        break;
      case "window":
        // Window bounds may be geographic (lat/lon) — project to % of the stage.
        if (beat.bounds && beat.bounds.latMin !== undefined && state.scene4.window) {
          const w = state.scene4.window;
          const x = ((beat.bounds.lonMin - w.lonMin) / (w.lonMax - w.lonMin || 1)) * 100;
          const y = ((w.latMax - beat.bounds.latMax) / (w.latMax - w.latMin || 1)) * 100;
          const xw = ((beat.bounds.lonMax - beat.bounds.lonMin) / (w.lonMax - w.lonMin || 1)) * 100;
          const yh = ((beat.bounds.latMax - beat.bounds.latMin) / (w.latMax - w.latMin || 1)) * 100;
          n.innerHTML = `<div class="anim-window" style="left:${x}%;top:${y}%;width:${xw}%;height:${yh}%"></div>`;
        } else if (beat.bounds) {
          n.innerHTML = `<div class="anim-window" style="left:${beat.bounds.x}%;top:${beat.bounds.y}%;width:${beat.bounds.w}%;height:${beat.bounds.h}%"></div>`;
        }
        break;
      case "drawLine":
        // Draw a least-squares line through a street's points. If the beat has
        // no inline points, use the scatter payload it references (e.g. the
        // DONCASTER/BLACKBURN fit in scene4.json).
        const linePts = beat.points && beat.points.length
          ? beat.points
          : (beat.payload && state.scene4[beat.payload]) || [];
        // Fit a straight line (least-squares) and draw it across the stage.
        let svg = "";
        if (linePts.length) {
          const w = state.scene4.window;
          const xs = linePts.map(p => p.lon);
          const ys = linePts.map(p => p.lat);
          const n = xs.length;
          const mx = xs.reduce((a,b)=>a+b,0)/n, my = ys.reduce((a,b)=>a+b,0)/n;
          let num=0, den=0;
          for (let i=0;i<n;i++){ num += (xs[i]-mx)*(ys[i]-my); den += (xs[i]-mx)*(xs[i]-mx); }
          const slope = den ? num/den : 0;
          const intercept = my - slope*mx;
          const x0 = w.lonMin, x1 = w.lonMax;
          const y0 = slope*x0 + intercept, y1 = slope*x1 + intercept;
          const X = (lon)=>{ const ww = state.scene4.window; return ((lon-ww.lonMin)/(ww.lonMax-ww.lonMin||1))*100; };
          const Y = (lat)=>{ const ww = state.scene4.window; return ((ww.latMax-lat)/(ww.latMax-ww.latMin||1))*100; };
          svg = `<svg class="anim-line" viewBox="0 0 100 100" preserveAspectRatio="none">` +
            `<line x1="${X(x0)}" y1="${Y(y0)}" x2="${X(x1)}" y2="${Y(y1)}" stroke="${beat.color || '#3987e5'}" stroke-width="2" />` +
            `</svg>`;
        }
        n.innerHTML = svg;
        break;
      case "cross":
        // Cross position may be geographic — project to % of the stage.
        if (beat.at && beat.at.lat !== undefined && state.scene4.window) {
          const w = state.scene4.window;
          const cx = ((beat.at.lon - w.lonMin) / (w.lonMax - w.lonMin || 1)) * 100;
          const cy = ((w.latMax - beat.at.lat) / (w.latMax - w.latMin || 1)) * 100;
          n.innerHTML = `<div class="anim-cross" style="left:${cx}%;top:${cy}%"></div>`;
        } else if (beat.at) {
          n.innerHTML = `<div class="anim-cross" style="left:${beat.at.x}%;top:${beat.at.y}%"></div>`;
        }
        break;
      case "ring":
        // Ring center may be geographic — project to % of the stage.
        if (beat.center && beat.center.lat !== undefined && state.scene4.window) {
          const w = state.scene4.window;
          const cx = ((beat.center.lon - w.lonMin) / (w.lonMax - w.lonMin || 1)) * 100;
          const cy = ((w.latMax - beat.center.lat) / (w.latMax - w.latMin || 1)) * 100;
          // radiusM → stage px: approximate with the window's diagonal scale.
          const r = (beat.radiusM / 2000) * 100;
          n.innerHTML = `<div class="anim-ring" style="left:${cx}%;top:${cy}%;width:${r*2}%;height:${r*2}%"></div>`;
        } else if (beat.center) {
          n.innerHTML = `<div class="anim-ring" style="left:${beat.center.x}%;top:${beat.center.y}%;width:${beat.w}%;height:${beat.h}%"></div>`;
        }
        break;
    }
    return n;
  }

  function renderBeat(beat, node, body) {
    body.append(node);
    if (state.reducedMotion) {
      // Jump to the final state — no tween, the teaching point is preserved.
      node.classList.add("anim-final");
      return;
    }
    node.classList.add("anim-in");
  }

  // ---- static panel rendering ----------------------------------------------

  function renderPanel(panel, body) {
    if (!panel) return;
    const el = document.createElement("div");
    el.className = "anim-panel anim-panel-" + panel.type;
    switch (panel.type) {
      case "split-diagram":
        el.innerHTML = `
          <div class="anim-panel-cols">
            <div class="anim-panel-col">
              <div class="anim-panel-head">${esc(panel.left.name)}</div>
              ${panel.left.items.map((i) => `<div class="anim-panel-item">${esc(i)}</div>`).join("")}
            </div>
            <div class="anim-panel-arrow">→</div>
            <div class="anim-panel-col">
              <div class="anim-panel-head">${esc(panel.right.name)}</div>
              ${panel.right.items.map((i) => `<div class="anim-panel-item">${esc(i)}</div>`).join("")}
            </div>
          </div>
          <div class="anim-panel-rule">${esc(panel.rule)}</div>`;
        break;
      case "data-card":
        el.innerHTML = `
          <div class="anim-panel-name">${esc(panel.name)}</div>
          <div class="anim-panel-stats">
            <span>${panel.candidates} candidates</span>
            <span>${panel.states} states</span>
            <span>${panel.percentages.base}% share a name</span>
            <span>${panel.percentages.state}% state-cut</span>
            <span>${panel.percentages.statePostcode}% state+postcode</span>
            <span>${panel.withinStateRepeats} within-state repeats</span>
          </div>
          <div class="anim-panel-note">${esc(panel.note)}</div>`;
        break;
      case "rule-card":
        el.innerHTML = `<div class="anim-panel-rule">${esc(panel.rule)}</div>`;
        break;
    }
    body.append(el);
  }

  function currentScene() {
    return state.scenes[state.sceneIndex] || null;
  }

  function totalBeats(scene) {
    return scene ? scene.beats.length : 0;
  }

  function showScene(index) {
    const scene = state.scenes[index];
    if (!scene) return;
    state.sceneIndex = index;
    state.beatIndex = 0;
    const { body, caption, progress } = buildSceneDOM(scene, state.stage);
    state.body = body;
    state.caption = caption;
    state.progress = progress;
    caption.textContent = scene.teaches || "";

    // Chips persist across scene changes — re-render them after the wipe.
    renderChips();

    // Static panels (no beats) render their content; animated scenes render beats.
    if (scene.panel) {
      renderPanel(scene.panel, body);
    }

    // Render all beats' final DOM upfront; animate them as the playhead advances.
    scene.beats.forEach((b) => body.append(renderBeat(b, beatNode(b), body)));
    state.beatIndex = 0;

    // Show only the first beat (or all if reduced-motion — jump to end).
    // Re-check live: the matchMedia change listener re-renders, but emulation
    // changes may not dispatch a change event, so trust a fresh check here.
    state.reducedMotion = reducedMotion();
    if (state.reducedMotion) {
      body.querySelectorAll(".anim-beat").forEach((n) => n.classList.add("anim-final"));
      setProgress(progress, 1);
    } else {
      setProgress(progress, 0);
    }
    updateChips();
  }

  function setProgress(progress, frac) {
    if (!progress) return;
    const fill = progress.querySelector(".anim-progress-fill");
    if (fill) fill.style.width = (frac * 100).toFixed(1) + "%";
  }

  function play() {
    if (!currentScene()) return;
    state.playing = true;
    stepBeat(0);
    startTimer();
  }

  function startTimer() {
    stopTimer();
    const scene = currentScene();
    if (!scene) return;
    const stepMs = 200 / state.speed; // 200 ms gap per beat
    state.timer = setInterval(() => {
      if (!state.playing) return;
      const beats = scene.beats;
      const b = beats[state.beatIndex];
      if (!b) { pause(); return; }
      // Advance the playhead. stepBeat toggles the anim-active class on the
      // beat nodes so they actually render — incrementing beatIndex alone only
      // moves the progress bar and never shows the beats.
      stepBeat(1);
      if (state.beatIndex >= beats.length) {
        pause();
        setProgress(state.progress, 1);
        return;
      }
    }, stepMs);
  }

  function stopTimer() {
    if (state.timer) { clearInterval(state.timer); state.timer = null; }
  }

  function pause() {
    state.playing = false;
    stopTimer();
  }

  function stepBeat(dir) {
    const scene = currentScene();
    if (!scene) return;
    const beats = scene.beats;
    if (dir < 0 && state.beatIndex === 0) return;
    if (dir > 0 && state.beatIndex >= beats.length) return;
    state.beatIndex = Math.max(0, Math.min(state.beatIndex + dir, beats.length));
    const nodes = state.body ? state.body.querySelectorAll(".anim-beat") : [];
    for (let i = 0; i < nodes.length; i++) {
      const active = i < state.beatIndex;
      nodes[i].classList.toggle("anim-active", active);
    }
    setProgress(state.progress, beats.length ? state.beatIndex / beats.length : 0);
  }

  function replay() {
    state.beatIndex = 0;
    showScene(state.sceneIndex);
    if (state.playing) { stepBeat(0); startTimer(); }
  }

  function setSpeed(s) {
    state.speed = parseFloat(s) || 1;
    if (state.playing) { stopTimer(); startTimer(); }
  }

  // ---- scene chips --------------------------------------------------------

  function renderChips() {
    // Clear any previous chips container, then rebuild (showScene calls this
    // after each scene DOM wipe, so it must not accumulate duplicates).
    if (state.chips) state.chips.remove();
    const chips = document.createElement("div");
    chips.className = "anim-chips";
    state.scenes.forEach((s, i) => {
      const b = document.createElement("button");
      b.className = "anim-chip";
      b.dataset.scene = i;
      b.textContent = s.title;
      b.addEventListener("click", () => gotoScene(i));
      chips.append(b);
    });
    state.stage.append(chips);
    state.chips = chips;
  }

  function updateChips() {
    if (!state.chips) return;
    state.chips.querySelectorAll(".anim-chip").forEach((c, i) => {
      c.classList.toggle("anim-chip-active", i === state.sceneIndex);
    });
  }

  function gotoScene(i) {
    if (!state.scenes[i]) return;
    pause();
    showScene(i);
  }

  // ---- fallback ------------------------------------------------------------

  function renderFallback() {
    state.stage.innerHTML = `<div class="anim-fallback"><p>${esc("Explainer scenes not loaded (scenes.json empty).")}</p></div>`;
  }

  // ---- boot ----------------------------------------------------------------

  async function boot() {
    state.stage = $("#explainer") || $("#app");
    if (!state.stage) {
      // Element not yet in DOM — retry when it appears.
      if (document.readyState !== "complete") {
        document.addEventListener("DOMContentLoaded", boot);
      }
      return;
    }
    state.reducedMotion = reducedMotion();

    let data = [];
    try {
      const res = await fetch("/static/data/scenes.json");
      if (res.ok) data = await res.json();
    } catch (e) {
      data = [];
    }

    // Scene 4's scatter references the heavy address-point payload (scene4.json).
    // Load it separately so the film stays lean; merge into the scene on demand.
    let scene4 = null;
    try {
      const res = await fetch("/static/data/scene4.json");
      if (res.ok) scene4 = await res.json();
    } catch (e) {
      scene4 = null;
    }
    state.scene4 = scene4 || {};

    if (!Array.isArray(data) || data.length === 0) {
      renderFallback();
      return;
    }

    // Scenes may be objects keyed by id or an array; normalise to an array.
    const scenes = Array.isArray(data) ? data : Object.values(data);
    state.scenes = scenes;
    showScene(0);

    // Controls
    state.stage.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-act]");
      if (!btn) return;
      const act = btn.dataset.act;
      switch (act) {
        case "play": play(); break;
        case "pause": pause(); break;
        case "step-fwd": stepBeat(1); break;
        case "step-back": stepBeat(-1); break;
        case "replay": replay(); break;
        case "speed": setSpeed(btn.value); break;
      }
    });

    // Keyboard: space = play/pause, arrows = step
    document.addEventListener("keydown", (e) => {
      if (e.key === " ") { e.preventDefault(); state.playing ? pause() : play(); }
      else if (e.key === "ArrowRight") stepBeat(1);
      else if (e.key === "ArrowLeft") stepBeat(-1);
    });

    // Reduced-motion changes live
    if (window.matchMedia) {
      window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", (m) => {
        state.reducedMotion = m.matches;
        if (m.matches) showScene(state.sceneIndex);
      });
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
  // Also run if the document is already loaded (scripts at the end can race
  // the event). Guard against double-boot.
  if (document.readyState === "complete" || document.readyState === "interactive") {
    boot();
  }
})();
