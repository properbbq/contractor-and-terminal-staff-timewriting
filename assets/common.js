// Shared by the website's pages: signing in, the session, and requests to the reset helper.
//
// The website holds only ciphertext: data/users.json (each sign-in) and data/app.enc.json (the
// app and the hourly rates). A password opens them here in the browser. The only things that
// leave the browser are sealed requests, which only the private repo's Action can open
// (tools/ctjm_accounts.py): a password change, a new password from a reset link, or the rates.
// They go through the reset helper (relay/Code.gs), which files them as issues in that repo.

export const $ = (selector) => document.querySelector(selector);

export function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (key in node && !key.includes('-')) node[key] = value;
    else node.setAttribute(key, value === true ? '' : value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

export class AppError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
const USERS_URL = 'data/users.json';
const APP_URL = 'data/app.enc.json';
const PBKDF2_ITERATIONS = 600000;
const MIN_OWN_PASSWORD = 12;
const SESSION_HOURS = 12;
const REMEMBER_DAYS = 30;
const KEYS = { session: 'ctjm.session.v1', username: 'ctjm.username', rates: 'ctjm.rates.v1' };
const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

export const normalizeUsername = (username) => String(username || '').normalize('NFC').trim().toLowerCase();
// Passwords ignore case, spaces and dashes (as in tools/ctjm_core.py).
export const normalizePassword = (password) => String(password || '').normalize('NFC').toUpperCase().replace(/[\s-]+/g, '');

// ---------------------------------------------------------------- storage

// Storage can be blocked (a private window, say). Then nothing is remembered, and that's all.
const store = {
  get(key, where = 'local') {
    try {
      return JSON.parse((where === 'session' ? sessionStorage : localStorage).getItem(key) || 'null');
    } catch {
      return null;
    }
  },
  set(key, value, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).setItem(key, JSON.stringify(value));
    } catch { /* not remembered */ }
  },
  remove(key, where = 'local') {
    try {
      (where === 'session' ? sessionStorage : localStorage).removeItem(key);
    } catch { /* nothing kept */ }
  },
};

export const lastName = {
  get: () => store.get(KEYS.username) || '',
  set: (name) => store.set(KEYS.username, name),
};

// A session lasts 12 hours, or 30 days with "Keep me signed in". It holds the user key, which
// opens the person's profile until their password changes.
export function saveSession(session) {
  clearSession();
  const hours = session.remember ? REMEMBER_DAYS * 24 : SESSION_HOURS;
  store.set(KEYS.session, { ...session, exp: Date.now() + hours * 3600 * 1000 }, session.remember ? 'local' : 'session');
}

export function loadSession() {
  const session = store.get(KEYS.session, 'session') || store.get(KEYS.session, 'local');
  if (!session?.uk || !(session.exp > Date.now())) {
    if (session) clearSession();
    return null;
  }
  return session;
}

export function clearSession() {
  store.remove(KEYS.session, 'session');
  store.remove(KEYS.session, 'local');
}

// ------------------------------------------------------------------ crypto

const b64ToBytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const b64urlToBytes = (text) => b64ToBytes(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4));

function bytesToB64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
const bytesToB64url = (bytes) => bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// AES-256-GCM as "<iv>.<ciphertext>" (base64url), with associated data saying what it is and
// whose it is: the same format as seal()/unseal() in tools/ctjm_core.py.
async function seal(keyBytes, bytes, aad) {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8.encode(aad) }, key, bytes));
  return `${bytesToB64url(iv)}.${bytesToB64url(ct)}`;
}

async function unseal(keyBytes, token, aad) {
  const [iv, ct] = String(token).split('.');
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlToBytes(iv), additionalData: utf8.encode(aad) }, key, b64urlToBytes(ct)));
}

const sealJSON = (keyBytes, value, aad) => seal(keyBytes, utf8.encode(JSON.stringify(value)), aad);
const unsealJSON = async (keyBytes, token, aad) => JSON.parse(fromUtf8.decode(await unseal(keyBytes, token, aad)));

async function passwordKey(password, saltB64, iterations) {
  const base = await crypto.subtle.importKey('raw', utf8.encode(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations }, base, 256));
}

// A new user key locked with a password: what data/users.json holds for each sign-in.
async function wrapKey(userKey, password, username) {
  const salt = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
  const key = await seal(await passwordKey(password, salt, PBKDF2_ITERATIONS), userKey, `ctjm-user-key|${username}`);
  return { salt, iterations: PBKDF2_ITERATIONS, key };
}

// ---------------------------------------------------------------- signing in

async function fetchJSON(url, what) {
  let response;
  try {
    response = await fetch(url, { cache: 'no-cache' });
  } catch {
    throw new AppError('network', 'Couldn’t reach the website. Check your connection and try again.');
  }
  if (response.status === 404) throw new AppError('missing', `The ${what} hasn’t been published yet.`);
  if (!response.ok) throw new AppError('network', `Couldn’t load the ${what} (error ${response.status}).`);
  return response.json();
}

const usersFile = () => fetchJSON(USERS_URL, 'sign-in list');

async function userEntry(username, users) {
  return (users || await usersFile()).users?.[await sha256Hex(`ctjm-user:${normalizeUsername(username)}`)] || null;
}

export const SIGN_IN_AGAIN = {
  again: 'Please sign in again.',
  changed: 'Your password has changed. Please sign in with the new one.',
};
const signInAgain = (reason = 'again') => Object.assign(new AppError('signin', SIGN_IN_AGAIN[reason]), { reason });
const badLogin = () => new AppError('bad-login', 'That username and password don’t match.');

function checkBrowser() {
  if (!globalThis.crypto?.subtle) {
    throw new AppError('browser', 'This browser can’t open the website. Please use an up-to-date Chrome, Edge, Safari or Firefox.');
  }
}

export async function signIn(username, password) {
  checkBrowser();
  const name = normalizeUsername(username);
  const entry = await userEntry(name);
  if (!entry?.profile) throw badLogin();
  let userKey;
  try {
    userKey = await unseal(await passwordKey(password, entry.salt, entry.iterations), entry.key, `ctjm-user-key|${name}`);
  } catch {
    throw badLogin();
  }
  return { username: name, uk: bytesToB64(userKey) };
}

// The helper's address and whether it can send reset emails (null until it's set up). The
// tools allow a helper on this computer only for testing (see tools/ctjm_publish.py).
function helperOf(users) {
  const helper = users?.helper;
  return helper && typeof helper.url === 'string' && /^(https:\/\/|http:\/\/127\.0\.0\.1:)/.test(helper.url)
    ? { url: helper.url, resets: Boolean(helper.resets) } : null;
}

// Open a signed-in session: the person's profile, the app and the reset helper's address.
// Right after a change the two files can briefly disagree (GitHub Pages updates them one after
// the other), so this waits a little for them to match.
export async function openSession(session) {
  checkBrowser();
  if (!session?.uk) throw signInAgain();
  for (let attempt = 0; ; attempt += 1) {
    const users = await usersFile();
    const entry = await userEntry(session.username, users);
    if (!entry?.profile) throw signInAgain();
    let profile;
    try {
      profile = await unsealJSON(b64ToBytes(session.uk), entry.profile, `ctjm-profile|${session.username}`);
    } catch {
      throw signInAgain('changed');
    }
    const blob = await fetchJSON(APP_URL, 'app');
    if (blob.epoch === profile.epoch) {
      const app = await unsealJSON(b64ToBytes(profile.appKey), blob.data, `ctjm-app|${blob.epoch}`);
      return { profile, app, helper: helperOf(users) };
    }
    if (attempt >= 8) throw new AppError('updating', 'The website is being updated. Please try again in a minute.');
    await sleep(4000);
  }
}

// ------------------------------------------------------------ the reset helper

// Send a sealed request to the reset helper, which files it for the Action.
async function submit(helper, kind, tag, token) {
  if (!helper) throw new AppError('no-helper', 'Saving to the website isn’t switched on yet.');
  const request = {
    method: 'POST', credentials: 'omit', cache: 'no-store', redirect: 'follow',
    headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ action: 'submit', kind, tag, token }),
  };
  let response;
  try {
    response = await fetch(helper.url, request);
  } catch {
    // The browser wouldn't let this page read the answer (or the helper couldn't be reached):
    // send it again without asking for one. Sending twice does no harm, as the Action applies
    // each request once, and what changes on the website shows it arrived.
    try {
      await fetch(helper.url, { ...request, mode: 'no-cors' });
      return;
    } catch {
      throw new AppError('network', 'Couldn’t reach the website’s helper. Check your connection and try again.');
    }
  }
  let answer = null;
  try {
    answer = await response.json();
  } catch { /* not an answer from the helper */ }
  if (!answer?.ok) throw new AppError('helper', `The website’s helper couldn’t take it (${answer?.error || `error ${response.status}`}). Try again in a minute.`);
}

// Wait (up to four minutes) for the website to show a new password, by its salt.
async function waitForSalt(username, salt) {
  const deadline = Date.now() + 4 * 60 * 1000;
  while (Date.now() < deadline) {
    await sleep(5000);
    const entry = await userEntry(username).catch(() => null);
    if (entry?.salt === salt) return true;
  }
  return false;
}

// Check a password someone chooses (the same rules as check_own_password in tools/ctjm_core.py).
export function passwordProblem(password, username) {
  const plain = normalizePassword(password);
  if (plain.length < MIN_OWN_PASSWORD) return `Use at least ${MIN_OWN_PASSWORD} characters. A few words with spaces works well.`;
  if (new Set(plain).size < 5) return 'Use a mix of different characters.';
  const name = normalizeUsername(username).toUpperCase();
  if (plain.includes(name) || plain.includes(name.replace(/\./g, ''))) return 'Don’t include your username.';
  return null;
}

// The sealed requests, as tools/ctjm_accounts.py expects them.

// A password change: a new user key, locked with the new password, sealed with the current key.
export async function passwordChangeRequest(session, fresh) {
  const userKey = crypto.getRandomValues(new Uint8Array(32));
  const wrap = await wrapKey(userKey, fresh, session.username);
  const request = { seq: Date.now(), userKey: bytesToB64(userKey), wrap };
  const token = `CTJMP1.${await sealJSON(b64ToBytes(session.uk), request, `ctjm-pw|${session.username}`)}`;
  return { token, salt: wrap.salt, next: { ...session, uk: bytesToB64(userKey) } };
}

// Everyone's hourly rates, sealed with the person's user key.
export async function ratesRequest(session, rates, seq = Date.now()) {
  return `CTJMQ1.${await sealJSON(b64ToBytes(session.uk), { seq, rates }, `ctjm-rates|${session.username}`)}`;
}

// The new password from a reset link: the link's new user key, locked with it.
export async function resetRequest(opened, password) {
  const { username, userKey, profile } = opened;
  const wrap = await wrapKey(userKey, password, username);
  const token = `CTJMR1.${await sealJSON(userKey, { id: profile.recover, wrap }, `ctjm-recover-pw|${username}|${profile.recover}`)}`;
  return { token, salt: wrap.salt };
}

// Change your own password. A new user key is locked with the new password here, and sent sealed
// with the current key, so only you can make the change and nobody sees the password. Once the
// website has it (about a minute), the old password, and anything it could open, stops working.
// Resolves to the new session, or null if it's taking longer than usual.
export async function changePassword(session, profile, helper, current, fresh) {
  const entry = await userEntry(session.username);
  try {
    const opened = await unseal(await passwordKey(current, entry.salt, entry.iterations), entry.key, `ctjm-user-key|${session.username}`);
    if (bytesToB64(opened) !== session.uk) throw new Error('stale');
  } catch {
    throw new AppError('bad-password', 'Your current password isn’t right.');
  }
  const { token, salt, next } = await passwordChangeRequest(session, fresh);
  await submit(helper, 'password', profile.tag, token);
  return (await waitForSalt(session.username, salt)) ? next : null;
}

// The hourly rates: sent to the website (sealed, for every computer) and kept on this one
// (sealed with the user key, so only this sign-in can read them back).
export async function saveRates(session, profile, helper, rates) {
  const seq = Date.now();
  const sealed = await sealJSON(b64ToBytes(session.uk), { seq, rates }, `ctjm-rates-here|${session.username}`);
  store.set(KEYS.rates, { username: session.username, sealed });
  if (!helper) return 'here';
  await submit(helper, 'rates', profile.tag, await ratesRequest(session, rates, seq));
  return 'saved';
}

// The rates kept on this computer ({seq, rates}), if this sign-in can open them.
export async function ratesHere(session) {
  const kept = store.get(KEYS.rates);
  if (kept?.username !== session.username) return null;
  try {
    return await unsealJSON(b64ToBytes(session.uk), kept.sealed, `ctjm-rates-here|${session.username}`);
  } catch {
    return null;
  }
}

// After a password change, keep this computer's copy of the rates readable with the new key.
export async function moveRatesHere(oldSession, newSession) {
  const kept = await ratesHere(oldSession);
  if (!kept) return;
  const sealed = await sealJSON(b64ToBytes(newSession.uk), kept, `ctjm-rates-here|${newSession.username}`);
  store.set(KEYS.rates, { username: newSession.username, sealed });
}

// ------------------------------------------------------- forgotten passwords
//
// "Forgot your password?" asks the reset helper for an email. The Action makes a new user key for
// that person and emails a link holding a secret, after the # so it never reaches a web server.
// The secret opens only a copy of the new key, published next to their sign-in, and a short
// profile with just enough to send a new password in. Their old password works until then.

export async function resetHelper() {
  const helper = helperOf(await usersFile());
  return helper?.resets ? helper : null;
}

// Ask for a reset email. It says nothing about whether the username exists.
export async function requestReset(username) {
  const helper = await resetHelper();
  if (!helper) throw new AppError('no-reset', 'Password reset by email isn’t switched on yet.');
  const uid = await sha256Hex(`ctjm-user:${normalizeUsername(username)}`);
  try {
    // "no-cors": the answer is the same whatever happens, so there's nothing to read.
    await fetch(helper.url, {
      method: 'POST', mode: 'no-cors', credentials: 'omit', cache: 'no-store', redirect: 'follow',
      headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify({ action: 'request', uid }),
    });
  } catch {
    throw new AppError('network', 'Couldn’t send the request. Check your connection and try again.');
  }
}

async function recoverKey(secret) {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8.encode('ctjm/recover') }, base, 256));
}

// What a reset link ({u, id, k, t} from the email) opens. status is 'ok', or 'missing' (not on the
// website yet, or used up), 'replaced' (a newer link was sent), 'expired' or 'bad'.
export async function openResetLink(link) {
  checkBrowser();
  const username = normalizeUsername(link?.u);
  if (!username || !/^[0-9a-f]{16}$/.test(link?.id || '') || !/^[A-Za-z0-9_-]{43}$/.test(link?.k || '')) return { status: 'bad' };
  const users = await usersFile();
  const recover = (await userEntry(username, users))?.recover;
  if (!recover) return { status: 'missing', username };
  if (recover.id !== link.id) return { status: 'replaced', username };
  if (!(Date.parse(recover.expires) > Date.now())) return { status: 'expired', username };
  try {
    const userKey = await unseal(await recoverKey(b64urlToBytes(link.k)), recover.key, `ctjm-recover|${username}|${link.id}`);
    const profile = await unsealJSON(userKey, recover.profile, `ctjm-recover-profile|${username}|${link.id}`);
    return { status: 'ok', username, userKey, profile, helper: helperOf(users), expires: recover.expires };
  } catch {
    return { status: 'bad', username };
  }
}

// Send the new password from a reset link, sealed with the link's new user key. Resolves true
// once the website has it (about a minute), or false if it's taking longer than usual.
export async function finishReset(opened, password) {
  const { token, salt } = await resetRequest(opened, password);
  await submit(opened.helper, 'password', opened.profile.tag, token);
  return waitForSalt(opened.username, salt);
}

// ------------------------------------------------------------- page helpers

// The eye next to a password box shows what's typed only while it's held down (with the mouse,
// a finger, or Space or Enter), and hides it again the moment it's let go.
export function holdToShow(button, inputs) {
  const set = (show) => {
    for (const input of inputs) input.type = show ? 'text' : 'password';
    button.classList.toggle('showing', show);
  };
  const hide = () => set(false);
  button.addEventListener('pointerdown', (event) => {
    if (event.button !== 0) return;
    event.preventDefault(); // keeps the cursor in the password box
    button.setPointerCapture?.(event.pointerId);
    set(true);
  });
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture', 'blur']) button.addEventListener(type, hide);
  button.addEventListener('keydown', (event) => {
    if (event.key !== ' ' && event.key !== 'Enter') return;
    event.preventDefault();
    if (!event.repeat) set(true);
  });
  button.addEventListener('keyup', (event) => {
    if (event.key === ' ' || event.key === 'Enter') hide();
  });
  button.addEventListener('click', (event) => event.preventDefault());
  button.addEventListener('contextmenu', (event) => event.preventDefault()); // a long press on a phone
  window.addEventListener('blur', hide);
  return hide;
}
