// "Forgot your password?": ask the reset helper to email a link. The page shows the same answer
// whether or not the username exists or has an email address.

import { $, lastName, normalizeUsername, requestReset, resetHelper } from './common.js?v=332704f2010f';

const form = $('#forgot-form');
const input = $('#username');
const button = $('#submit');
const message = $('#message');
input.value = lastName.get();
input.focus();

const switchedOff = () => {
  form.hidden = true;
  $('#off').hidden = false;
};

resetHelper().then((helper) => {
  if (!helper) switchedOff();
}).catch(() => { /* shown when they try */ });

function show(text) {
  message.textContent = text;
  message.hidden = false;
  input.focus();
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  message.hidden = true;
  const username = normalizeUsername(input.value);
  if (!username) return show('Enter your username.');
  if (!/^[a-z0-9][a-z0-9._-]{0,39}$/.test(username)) return show('Usernames only use letters, numbers and dots.');
  button.disabled = true;
  button.textContent = 'Sending…';
  try {
    await requestReset(username);
    lastName.set(username);
    $('#sent-user').textContent = username;
    form.hidden = true;
    $('#sent').hidden = false;
  } catch (error) {
    if (error.code === 'no-reset') switchedOff();
    else show(error.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Email me a reset link';
  }
});
