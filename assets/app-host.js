// The app page: opens the encrypted app with the signed-in session and runs it here. It also
// looks after the hourly rates (globalThis.ctjmHost, used by the app) and changing the password.

import {
  $, el, loadSession, saveSession, clearSession, openSession, changePassword, saveRates, ratesHere, moveRatesHere,
  passwordProblem, normalizePassword, holdToShow,
} from './common.js?v=332704f2010f';

let session = loadSession();

function notice(tone, ...content) {
  const box = el('div', { class: `notice notice-${tone}` }, el('div', { class: 'notice-text' }, ...content));
  $('#notices').append(box);
  return box;
}

// The app's page, built from the tree tools/ctjm_build.py made of site/index.html (so it needs
// no innerHTML).
const SVG = 'http://www.w3.org/2000/svg';
function build(node, inSvg = false) {
  if (typeof node === 'string') return document.createTextNode(node);
  const [tag, attributes, ...children] = node;
  const svg = inSvg || tag === 'svg';
  const element = svg ? document.createElementNS(SVG, tag) : document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
  for (const child of children) element.append(build(child, svg));
  return element;
}

// The app's modules, each from a blob: address, with every import pointed at the module it names.
async function runModules(modules, entry) {
  const urls = new Map();
  const loading = new Set();
  const load = (name) => {
    if (urls.has(name)) return urls.get(name);
    if (loading.has(name) || !Object.hasOwn(modules, name)) throw new Error(`the app is incomplete (${name})`);
    loading.add(name);
    const code = modules[name].replace(/from '\.\/([\w-]+\.js)'/g, (match, dependency) => `from '${load(dependency)}'`);
    const url = URL.createObjectURL(new Blob([code], { type: 'text/javascript' }));
    urls.set(name, url);
    return url;
  };
  await import(load(entry));
}

function setUpPassword(profile, helper, firstNotice) {
  const dialog = $('#pw-dialog');
  const form = $('#pw-form');
  const current = $('#current-password');
  const fresh = $('#new-password');
  const again = $('#new-password-again');
  const hides = [holdToShow($('#peek-current'), [current]), holdToShow($('#peek-new'), [fresh]), holdToShow($('#peek-again'), [again])];
  const message = $('#pw-message');
  const button = $('#pw-submit');
  if (profile.email) {
    $('#pw-email').textContent = `If you forget it, “Forgot your password?” on the sign-in page emails a reset link to ${profile.email}.`;
    $('#pw-email').hidden = false;
  }
  const fail = (text, field) => {
    message.textContent = text;
    message.hidden = false;
    field?.focus();
  };
  $('#change-password').addEventListener('click', () => {
    form.reset();
    message.hidden = true;
    dialog.showModal();
    if (!helper) fail('Changing your password needs the website’s helper, which isn’t set up yet.');
    else current.focus();
  });
  $('#pw-cancel').addEventListener('click', () => dialog.close());
  dialog.addEventListener('close', () => hides.forEach((hide) => hide()));
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (button.disabled) return;
    hides.forEach((hide) => hide());
    message.hidden = true;
    if (!helper) return fail('Changing your password needs the website’s helper, which isn’t set up yet.');
    if (!current.value.trim()) return fail('Enter your current password.', current);
    const problem = passwordProblem(fresh.value, profile.username);
    if (problem) return fail(problem, fresh);
    if (normalizePassword(fresh.value) !== normalizePassword(again.value)) return fail('The two new passwords don’t match.', again);
    if (normalizePassword(fresh.value) === normalizePassword(current.value)) return fail('That’s the same as your current password.', fresh);
    button.disabled = true;
    button.textContent = 'Changing… (about a minute)';
    try {
      const next = await changePassword(session, profile, helper, current.value, fresh.value);
      dialog.close();
      if (next) {
        await moveRatesHere(session, next);
        session = next;
        saveSession(session);
        firstNotice?.remove();
        notice('ok', 'Your password has been changed. Use the new one next time you sign in.');
      } else {
        notice('warn', 'This is taking longer than usual. In a few minutes, sign in with your new password. Until it works, your old one still does.');
      }
    } catch (error) {
      fail(error.message, error.code === 'bad-password' ? current : null);
    } finally {
      button.disabled = false;
      button.textContent = 'Change password';
    }
  });
}

async function start() {
  let opened;
  try {
    opened = await openSession(session);
  } catch (error) {
    if (error.code === 'signin') {
      clearSession();
      location.replace(`index.html?why=${error.reason || 'again'}`);
      return;
    }
    $('#app').replaceChildren(el('div', { class: 'page' }, el('div', { class: 'notice notice-error' },
      el('div', { class: 'notice-text' }, error.message),
      el('button', { class: 'btn btn-sm', type: 'button', onclick: () => location.reload() }, 'Try again'))));
    return;
  }
  const { profile, app, helper } = opened;
  $('#user-name').textContent = profile.name;
  $('#user').hidden = false;
  let firstNotice = null;
  if (profile.first) {
    firstNotice = notice('warn', el('strong', {}, 'Choose your own password. '),
      'You’re still using the one you were given, which others could guess. ',
      el('button', { class: 'btn btn-sm btn-primary', type: 'button', onclick: () => $('#change-password').click() }, 'Change password'));
  }
  setUpPassword(profile, helper, firstNotice);

  // The newest rates: the website's, or this computer's if they were changed here since.
  const here = await ratesHere(session);
  const rates = here && here.seq > (app.ratesSeq || 0) ? here.rates : (app.rates || {});
  globalThis.ctjmHost = {
    template: app.template,
    rates,
    saveRates: (next) => saveRates(session, profile, helper, next),
  };
  $('#app').replaceChildren(build(app.markup));
  try {
    await runModules(app.modules, app.entry);
  } catch (error) {
    notice('error', `The app couldn’t start (${error.message}). Try reloading the page.`);
  }
}

if (!session) location.replace('index.html');
else start();
