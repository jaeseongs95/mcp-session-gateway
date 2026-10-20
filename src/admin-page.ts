import type { Db } from './store.ts';
import type { Scope } from './registry.ts';

// Everything shown comes from agents or admins, so every value is escaped and no stored HTML is ever rendered.
// There is no view of any token or secret: the store does not hold them in readable form.
const esc = (value: unknown): string => String(value ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const time = (ms: unknown): string => (typeof ms === 'number' ? new Date(ms).toISOString() : '');
const scopes = (json: unknown): string =>
  typeof json === 'string' ? (JSON.parse(json) as Scope[]).map((s) => `${s.mode} ${s.project}/${s.task}`).join(', ') : '';

const page = (body: string): string =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
  `<title>MCP session gateway</title><script src="/admin/app.js" defer></script></head><body><h1>MCP session gateway</h1>${body}` +
  `<p data-msg role="status"></p></body></html>`;

export function loginPage(canEnroll: boolean): string {
  const enroll = canEnroll
    ? `<form data-enroll><label>Enrollment code <input name="code" type="password" required autocomplete="off"></label> ` +
      `<button>Enroll this passkey as admin</button></form>`
    : '';
  return page(`<p><button data-login>Sign in with passkey</button></p>${enroll}`);
}

const LIST_SQL = `
SELECT r.*, g.version, g.scopes, g.expires_at, g.approved_by, g.approved_at, l.account,
  (SELECT MAX(a.at) FROM audit a WHERE a.actor = r.key_thumbprint AND a.action LIKE 'invoke:%' AND a.result = 'ok') AS last_used
FROM registrations r
LEFT JOIN grants g ON g.registration_id = r.id
LEFT JOIN account_leases l ON l.registration_id = r.id AND l.state IN ('LENDING', 'LENT')
ORDER BY r.created_at DESC`;

export function adminPage(db: Db, now: number): string {
  const rows = db.prepare(LIST_SQL).all();
  const body = rows
    .map((r) => {
      const state = r.state === 'ACTIVE' && typeof r.expires_at === 'number' && r.expires_at <= now ? 'EXPIRED' : r.state;
      const actions =
        state === 'REVOKED'
          ? ''
          : `<input data-project placeholder="project" aria-label="project"> <input data-task placeholder="task" aria-label="task"> ` +
            `<input data-minutes type="number" min="1" max="10080" value="60" aria-label="minutes"> <button data-act="grant">Grant READ</button> ` +
            `<input data-name placeholder="new name" aria-label="new name"> <button data-act="rename">Rename</button> ` +
            `<button data-act="revoke">Revoke</button>`;
      return (
        `<tr data-id="${esc(r.id)}" data-version="${esc(r.version ?? 0)}">` +
        `<td>${esc(r.display_name)}</td>` +
        `<td><code>${esc(r.session_label)}</code><br><small>registration ${esc(r.id)} · key ${esc(String(r.key_thumbprint).slice(0, 8))}</small></td>` +
        `<td>${esc(r.host_claim)} <strong>(unverified)</strong></td>` +
        `<td>${esc(scopes(r.requested_scopes))}</td>` +
        `<td>${esc(scopes(r.scopes))}${r.account ? `<br><small>account ${esc(r.account)}</small>` : ''}</td>` +
        `<td>${esc(state)}</td><td>${esc(time(r.expires_at))}</td><td>${esc(time(r.last_used))}</td>` +
        `<td>${esc(r.approved_by)} ${esc(time(r.approved_at))}</td><td>${actions}</td></tr>`
      );
    })
    .join('');
  return page(
    `<table><thead><tr><th>Session name</th><th>Session ID</th><th>Actual host</th><th>Requested</th><th>Granted</th>` +
      `<th>State</th><th>Expires</th><th>Last used</th><th>Approved</th><th>Actions</th></tr></thead><tbody>${body}</tbody></table>`,
  );
}

// Served from /admin/app.js so the page can run under a CSP without inline script. Uses the browser's own WebAuthn JSON
// helpers (PublicKeyCredential.parse*OptionsFromJSON, credential.toJSON) instead of a client library.
export const ADMIN_SCRIPT = `
const msg = (text) => { document.querySelector('[data-msg]').textContent = text; };
async function post(url, body) {
  const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(json.error || String(res.status));
  return json;
}
async function withPasskey(startUrl, startBody, finishUrl) {
  const start = await post(startUrl, startBody);
  if (start.summary && !confirm('Approve with your passkey:\\n' + start.summary)) throw new Error('cancelled');
  const credential = await navigator.credentials.get({ publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(start.options) });
  return post(finishUrl, { challengeId: start.challengeId, response: credential.toJSON() });
}
document.addEventListener('click', async (event) => {
  const button = event.target;
  if (!(button instanceof HTMLButtonElement)) return;
  try {
    if (button.hasAttribute('data-login')) {
      await withPasskey('/admin/login/options', {}, '/admin/login/verify');
      location.reload();
      return;
    }
    const act = button.dataset.act;
    if (!act) return;
    const row = button.closest('tr');
    const field = (selector) => row.querySelector(selector).value;
    const body = { action: act, registrationId: row.dataset.id, expectedVersion: Number(row.dataset.version) };
    if (act === 'grant') {
      body.scopes = [{ project: field('[data-project]'), task: field('[data-task]'), mode: 'READ' }];
      body.expiresInMinutes = Number(field('[data-minutes]'));
    }
    if (act === 'rename') body.displayName = field('[data-name]');
    await withPasskey('/admin/action/options', body, '/admin/action/verify');
    location.reload();
  } catch (err) {
    msg('Refused: ' + err.message);
  }
});
document.addEventListener('submit', async (event) => {
  const form = event.target;
  if (!form.matches('[data-enroll]')) return;
  event.preventDefault();
  try {
    const start = await post('/admin/enroll/options', { code: form.code.value });
    const credential = await navigator.credentials.create({ publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(start.options) });
    await post('/admin/enroll/verify', { challengeId: start.challengeId, response: credential.toJSON() });
    msg('Enrolled. Sign in now.');
  } catch (err) {
    msg('Refused: ' + err.message);
  }
});
`;
