'use strict';

const form = document.querySelector('#login-form');
const tokenInput = document.querySelector('#access-token');
const status = document.querySelector('#status');

form.addEventListener('submit', async event => {
  event.preventDefault();
  const token = tokenInput.value;
  tokenInput.value = '';
  status.textContent = 'Signing in…';
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!response.ok) {
      throw new Error(
        response.status === 401 ? 'The access token was not accepted.' : await response.text(),
      );
    }
    location.replace('/');
  } catch (error) {
    status.textContent = error.message || String(error);
    tokenInput.focus();
  }
});
