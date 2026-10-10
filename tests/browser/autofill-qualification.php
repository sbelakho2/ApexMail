<?php

declare(strict_types=1);

/**
 * The human-openable autofill qualification page of
 * docs/autofill-qualification-protocol.md. The fixture router serves it
 * at GET /autofill-form and includes this file only for that route.
 * This file is deliberately not part of the benchmark measurement source
 * set, so editing it can never invalidate a client performance
 * recording.
 *
 * The page is the same standard markup the autofill-evidence spec
 * constructs in memory: the widget container, the hidden token input
 * and the real autocomplete-semantic fields (email, username,
 * current-password). It arms the authenticated decoy pool by default
 * (?decoy=pool; ?decoy=1 serves the unarmed emission and
 * ?decoyname=<name> pins the emitted name, like the other fixtures).
 *
 * The documented manual sequence must be completable literally.
 *
 *   Run A (negative control): save a profile/login for this URL in the
 *   surface under test, reload, and accept the native fill on the real
 *   fields. Pressing Submit serializes the form and POSTs it to
 *   /form-submit with fetch instead of navigating, so the page and its
 *   controls stay alive, exactly as the protocol document instructs.
 *   Press Check to post the serialized form to /honeypot-check: the
 *   decoy input must be empty and honeypot_hit must be false.
 *
 *   Run B (positive control): /honeypot-check consumes the verified
 *   record, so reload for a fresh challenge first. Press "Fill the
 *   authenticated decoy (positive control)": it reads the decoy name
 *   from the last seen /challenge response and fills exactly that input
 *   through the native value setter. Press Check: the proof must stay
 *   valid and honeypot_hit must be true.
 *
 * A pass row must record both controls (the matrix validator requires
 * controls.negative and controls.positive for every pass row).
 */

$assets = $repo.'/packages/kiwicaptcha-wasm/assets';
$glue = (string) file_get_contents($assets.'/kiwicaptcha-wasm.js');
$driver = (string) file_get_contents($assets.'/widget-driver.js');
$risk = (string) file_get_contents($assets.'/widget-risk.js');
// The authenticated pool is the default: the manual qualification checks
// the exact server-issued decoy name of the verified record (the unarmed
// ?decoy=1 emission carries no authenticated name, so a pass row needs
// the pool arm).
$endpoint = '/challenge?decoy='.(($_GET['decoy'] ?? '') === '1' ? '1' : 'pool');
if (($_GET['decoyname'] ?? '') !== '') {
    $endpoint .= '&decoyname='.rawurlencode((string) $_GET['decoyname']);
}
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
echo '<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>KiwiCaptcha autofill qualification page</title>
</head>
<body>
<h1>KiwiCaptcha autofill qualification</h1>
<p>This is the manual qualification page of docs/autofill-qualification-protocol.md.
Run A (negative control): save a profile/login for this URL in the surface under
test, reload, accept the native fill on the real fields, press Submit, then press
Check. The serialized form must show no non-empty value under the server-issued
decoy name (the decoy name is in the /challenge response) and honeypot_hit must be
false. Run B (positive control): the check consumes the verified record, so reload
for a fresh challenge, press the positive-control button to fill exactly the
authenticated decoy field, then press Check again: the proof must stay valid and
honeypot_hit must be true. A pass row records both controls.</p>
<form id="f" action="/form-submit" method="post">
  <div class="kiwi-container" id="kiwicaptcha-root"
    data-kiwi-endpoint="'.htmlspecialchars($endpoint, ENT_QUOTES).'" data-kiwi-scope="login">
    <input type="hidden" name="kiwi__token" data-kiwi-token value="" />
    <div class="kiwi-widget" data-kiwi-widget data-state="idle">
      <div class="kiwi-icon-wrapper"><svg></svg><div class="kiwi-glow"></div></div>
      <div class="kiwi-main">
        <div class="kiwi-top"><span class="kiwi-label" data-kiwi-label>Security Check</span><span class="kiwi-badge" data-kiwi-badge>Idle</span></div>
        <div class="kiwi-track" aria-hidden="true"><div class="kiwi-bar" data-kiwi-bar></div></div>
        <div class="kiwi-bottom"><p class="kiwi-info" data-kiwi-info>Protected</p><span class="kiwi-timer" data-kiwi-timer></span></div>
      </div>
    </div>
  </div>
  <p><label>Email <input type="email" name="email" autocomplete="email" /></label></p>
  <p><label>Username <input type="text" name="username" autocomplete="username" /></label></p>
  <p><label>Password <input type="password" name="password" autocomplete="current-password" /></label></p>
  <p><button type="submit">Submit</button> <span id="autofill-submitted"></span></p>
</form>
<p>Run A check / Run B check (fresh challenge first): <button type="button" id="autofill-check">Check serialized form and decoy evidence</button></p>
<p>Run B control: <button type="button" id="autofill-positive">Fill the authenticated decoy (positive control)</button></p>
<pre id="autofill-out"></pre>
<p>Posted form capture: <a href="/capture/form">/capture/form</a></p>
<script>
// The challenge-response watcher: records the authenticated decoy name of
// the last issued challenge without touching the driver. It wraps fetch
// before the widget scripts load, so the driver\'s own /challenge request
// is observed.
(function () {
  var nativeFetch = window.fetch.bind(window);
  window.__autofillDecoy = null;
  window.fetch = function (input, init) {
    var result = nativeFetch(input, init);
    try {
      var url = typeof input === "string" ? input : (input && input.url) || "";
      if (url.indexOf("/challenge") !== -1) {
        result.then(function (resp) {
          resp.clone().json().then(function (data) {
            if (data && typeof data.decoy_field === "string" && data.decoy_field !== "") {
              window.__autofillDecoy = data.decoy_field;
            }
          }).catch(function () {});
        }).catch(function () {});
      }
    } catch (e) {}
    return result;
  };
})();
</script>
<script>'.$glue.'</script>
<script>'.$driver.'</script>
<script>'.$risk.'</script>
<script>
(function () {
  var form = document.getElementById("f");
  var out = document.getElementById("autofill-out");
  function note(text) { out.textContent = text + "\n" + out.textContent; }
  // The documented sequence: Submit must not navigate away, so the
  // controls survive the submission. The real submit event still fires
  // (native autofill and Enter-key submission included), the form is
  // serialized exactly as a real submission would serialize it, and the
  // fixture\'s /form-submit endpoint records the same payload.
  form.addEventListener("submit", function (event) {
    event.preventDefault();
    var body = new URLSearchParams(new FormData(form));
    fetch("/form-submit", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        note("submission captured: " + JSON.stringify(data));
        document.getElementById("autofill-submitted").textContent = "submitted — the page stays open for the controls";
      })
      .catch(function (err) { note("submission failed: " + err); });
  });
  document.getElementById("autofill-check").addEventListener("click", function () {
    var body = new URLSearchParams();
    var filled = [];
    new FormData(form).forEach(function (value, key) {
      if (value !== "") filled.push(key + "=" + value);
      body.append(key, value);
    });
    fetch("/honeypot-check", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        note("non-empty fields: " + JSON.stringify(filled) + "\n" + JSON.stringify(data, null, 2));
      });
  });
  document.getElementById("autofill-positive").addEventListener("click", function () {
    var name = window.__autofillDecoy;
    if (!name) {
      note("positive control: no challenge response with a decoy field seen yet");
      return;
    }
    var input = form.querySelector("input[name=\"" + CSS.escape(name) + "\"]");
    if (!input) {
      note("positive control: the authenticated decoy input " + name + " is not rendered on this page");
      return;
    }
    var setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set;
    setter.call(input, "autofill-positive-control");
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    note("positive control: filled the authenticated decoy field " + name + " — press Check to read the evidence");
  });
})();
</script>
</body>
</html>';
