/* ApexMail API Explorer island (external file — CSP script-src 'self').
 *
 * Moved out of the inline <script nonce="static-build"> block so the
 * marketing CSP (no unsafe-inline for scripts) allows it. Configuration
 * comes from the DOM: the island root carries data-api-base.
 *
 * All server-derived values are HTML-escaped before insertion — the
 * response body is attacker-influenced JSON and must never flow into
 * innerHTML raw.
 */
(function () {
  'use strict';

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;' }[c];
    });
  }

  var root = document.querySelector('[data-api-explorer-root]');
  if (!root) return;
  var respEl = root.querySelector('[data-api-explorer-response]');
  var sandboxURL = (root.getAttribute('data-api-base') || '') + '/v1/sandbox/send';

  function buildPayload() {
    return {
      from: 'sender@example.com',
      to: 'recipient@example.com',
      subject: 'Sandbox Test ' + new Date().toISOString().slice(11, 19),
      html: '<p>This is a sandbox request sent from the API Explorer.</p>'
    };
  }

  root.querySelectorAll('button[data-api-explorer-endpoint-button]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var payload = buildPayload();
      respEl.innerHTML = '<p style="color:#a0aec0;font-family:monospace;font-size:12px">Sending sandbox request…</p>';
      var t0 = performance.now();
      fetch(sandboxURL, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
        .then(function (r) { return r.json().then(function (d) { return { status: r.status, body: d }; }); })
        .then(function (result) {
          var t1 = performance.now();
          var h = result.body || {};
          var curl = 'curl -X POST ' + sandboxURL + ' \\\n  -H "Content-Type: application/json" \\\n  -d \'' + JSON.stringify(payload) + '\'';
          var lines = [];
          lines.push('<div style="color:#68d391;margin-bottom:8px">HTTP ' + escapeHtml(result.status) + ' — ' + escapeHtml(h.status || '') + '</div>');
          lines.push('<div style="color:#a0aec0">Request ID: <span style="color:#f6e05e">' + escapeHtml(h.request_id || '—') + '</span></div>');
          lines.push('<div style="color:#a0aec0">Message ID: <span style="color:#f6e05e">' + escapeHtml(h.id || '—') + '</span></div>');
          lines.push('<div style="color:#a0aec0">Latency: <span style="color:#f6e05e">' + escapeHtml(h.latency_ms || Math.round(t1 - t0)) + 'ms</span></div>');
          if (h.sandbox) lines.push('<div style="color:#a0aec0;margin-top:4px">⚠ ' + escapeHtml(h.note || '') + '</div>');
          if (h.errors) {
            var errs = h.errors.map(function (e) { return '  • ' + escapeHtml(e.field) + ': ' + escapeHtml(e.message); }).join('<br>');
            lines.push('<div style="color:#fc8181;margin-top:8px">Validation errors:<br>' + errs + '</div>');
          }
          lines.push('<div style="margin-top:12px;padding:8px;background:#1a202c;border-radius:4px;color:#a0aec0;font-size:10px;overflow-x:auto"><pre style="white-space:pre-wrap">' + escapeHtml(curl) + '</pre></div>');
          lines.push('<div style="margin-top:8px;padding:8px;background:#1a202c;border-radius:4px;color:#a0aec0;font-size:10px;overflow-x:auto"><pre style="white-space:pre-wrap">' + escapeHtml(JSON.stringify(h, null, 2)) + '</pre></div>');
          respEl.innerHTML =
            '<div style="font-family:monospace;font-size:11px;color:#e2e8f0;line-height:1.6">' +
            lines.join('') + '</div>';
        })
        .catch(function (e) {
          respEl.innerHTML = '';
          var p = document.createElement('p');
          p.style.cssText = 'color:#fc8181;font-family:monospace;font-size:12px';
          p.textContent = 'Request failed: ' + e.message;
          respEl.appendChild(p);
        });
    });
  });

  if (respEl && respEl.textContent.indexOf('Ready for execution') !== -1) {
    respEl.innerHTML = '';
    var hint = document.createElement('p');
    hint.style.cssText = 'color:#a0aec0;font-family:monospace;font-size:12px';
    hint.textContent = 'Pick an endpoint above and press "Send sandbox request" — it POSTs to the live sandbox endpoint. No email is delivered.';
    respEl.appendChild(hint);
  }
})();
