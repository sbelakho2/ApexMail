(function () {
  // ── Privacy-aware telemetry (widget-local, mode-gated) ──────────────
  // data-kiwi-telemetry on the container OR the widget: "off" (default) |
  // "minimal" | "full". This module is the lazy widget-telemetry.js: it
  // loads ONLY when the eager core (widget-driver.js) sees an enabled
  // telemetry mode on a widget (the core registers an "off" stub that
  // embeds the empty "{}" telemetry blob exactly like the historical
  // always-eager session), so a default page pays zero bytes for the
  // session machinery. The create() factory receives the RESOLVED mode
  // from the core (widget attribute first, container second — the same
  // precedence the historical session used internally). Listeners are
  // attached to the widget element ONLY (never document-wide) and are
  // removed when the solve finishes or fails.
  // No device-capability or screen-size signals are ever collected, and
  // scrolling/touch interactions are not tracked; navigator.webdriver is
  // only reported in "full" mode. Event timings are only recorded in
  // "full" mode, capped at 20 entries and quantized to 250 ms buckets.
  function telemetrySession(container, W, mode) {
    var mouseEvents = 0, keyEvents = 0, eventTimings = [];
    function onEvent(e) {
      if (e.type === "keydown") {
        if (e.repeat) return;
        keyEvents++;
      } else {
        mouseEvents++;
      }
      if (mode === "full" && eventTimings.length < 20) {
        eventTimings.push(Math.round(performance.now() / 250) * 250);
      }
    }
    function attach() {
      if (mode === "off") return;
      W.addEventListener("pointerdown", onEvent, {passive:true});
      W.addEventListener("keydown", onEvent, {passive:true});
      W.addEventListener("click", onEvent, {passive:true});
    }
    function stop() {
      if (mode === "off") return;
      W.removeEventListener("pointerdown", onEvent);
      W.removeEventListener("keydown", onEvent);
      W.removeEventListener("click", onEvent);
    }
    function build() {
      if (mode === "off") return {};
      var t = { v: 2, mode: mode, me: mouseEvents, ke: keyEvents };
      if (mode === "full") {
        t.wd = navigator.webdriver === true;
        t.et = eventTimings;
      }
      return t;
    }
    attach();
    return { build: build, stop: stop };
  }

  // The module registers itself with the internal core bridge the moment
  // it executes (the page loads it as a same-origin SRI-pinned script
  // asset only when telemetry is enabled); a module script that somehow
  // ran before the core is inert.
  var kiwiBridge = (typeof window !== "undefined" && window.__kiwiCaptchaCore) || null;
  if (kiwiBridge && typeof kiwiBridge.register === "function") {
    kiwiBridge.register("telemetry", {
      create: function (container, W, mode) { return telemetrySession(container, W, mode); }
    });
  }
})();
