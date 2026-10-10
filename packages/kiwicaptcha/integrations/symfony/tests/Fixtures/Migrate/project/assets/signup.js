// Acme signup guard: the hcaptcha widget on the registration form.
const HCAPTCHA_SITE_KEY = '10000000-ffff-ffff-ffff-000000000001';

export function renderSignupCaptcha(el) {
  return window.hcaptcha.render(el, { sitekey: HCAPTCHA_SITE_KEY });
}

export function resetSignupCaptcha() {
  window.hcaptcha.reset();
}

export async function verifyOnServer(token) {
  const res = await fetch('https://api.hcaptcha.com/siteverify', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret: window.ACME_HCAPTCHA_SECRET,
      response: token,
    }),
  });
  return res.json();
}
