(function () {
  var doc = JSON.parse(document.getElementById('kiwi-webauthn-options').dataset.options);
  var opts = doc.public_key;
  function buf(v) {
    var b = atob(v.replace(/-/g, '+').replace(/_/g, '/'));
    var a = new Uint8Array(b.length);
    for (var i = 0; i < b.length; i++) { a[i] = b.charCodeAt(i); }
    return a.buffer;
  }
  function b64(v) {
    var b = '';
    var u = new Uint8Array(v);
    for (var i = 0; i < u.length; i++) { b += String.fromCharCode(u[i]); }
    return btoa(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  opts.challenge = buf(opts.challenge);
  var isCreate = doc.ceremony === 'creation';
  if (isCreate) {
    if (opts.user && opts.user.id) { opts.user.id = buf(opts.user.id); }
    if (opts.excludeCredentials) {
      opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
        return { id: buf(c.id), type: c.type };
      });
    }
  } else if (opts.allowCredentials) {
    opts.allowCredentials = opts.allowCredentials.map(function (c) {
      return { id: buf(c.id), type: c.type };
    });
  }
  var call = isCreate
    ? navigator.credentials.create({ publicKey: opts })
    : navigator.credentials.get({ publicKey: opts });
  call.then(function (cred) {
    var payload = { id: cred.id, rawId: b64(cred.rawId), type: cred.type, response: {} };
    payload.response.clientDataJSON = b64(cred.response.clientDataJSON);
    if (isCreate) {
      payload.response.attestationObject = b64(cred.response.attestationObject);
    } else {
      payload.response.authenticatorData = b64(cred.response.authenticatorData);
      payload.response.signature = b64(cred.response.signature);
      payload.response.userHandle = cred.response.userHandle ? b64(cred.response.userHandle) : null;
    }
    document.getElementById('kiwi-webauthn-credential').value = JSON.stringify(payload);
    document.getElementById('kiwi-webauthn-form').submit();
  }).catch(function (e) {
    document.getElementById('kiwi-webauthn-status').textContent =
      'Security key failed: ' + (e && e.message ? e.message : String(e));
  });
})();
