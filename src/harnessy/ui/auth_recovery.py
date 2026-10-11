"""Recover the browser after account changes revoke its NiceGUI connection.

Navigation sent over an already-revoked WebSocket cannot be relied on. This
independent, read-only HTTP check redirects only after the authentication gate
explicitly reports that this browser needs to sign in again.
"""

AUTH_RECOVERY_JS = r'''
(() => {
  if (window.__harnessyAuthRecovery056) return;
  const state = {inFlight: false, redirecting: false, bound: false, bindAttempts: 0};
  window.__harnessyAuthRecovery056 = state;

  async function checkSession() {
    if (state.inFlight || state.redirecting) return;
    state.inFlight = true;
    const controller = new AbortController();
    let timer;
    try {
      // Racing the timeout also releases the coalescing guard if a transport
      // fails to settle its promise promptly after abort().
      const timeout = new Promise((_, reject) => {
        timer = window.setTimeout(() => {
          controller.abort();
          reject(new Error('Session check timed out'));
        }, 5000);
      });
      const response = await Promise.race([
        window.fetch('/__harnessy_session', {
          method: 'GET', credentials: 'same-origin', cache: 'no-store',
          redirect: 'error', headers: {'Accept': 'application/json'},
          signal: controller.signal,
        }),
        timeout,
      ]);
      if (response.status === 401) {
        state.redirecting = true;
        window.location.assign('/login');
      }
    } catch (_) {
      // Offline, busy and failed requests are not evidence of logout. Keep
      // HarnessyXO's existing connection-health and reconnection UI in charge.
    } finally {
      window.clearTimeout(timer);
      state.inFlight = false;
    }
  }

  function bindSocket() {
    if (state.bound) return;
    state.bindAttempts += 1;
    const socket = window.socket;
    if (socket && typeof socket.on === 'function') {
      socket.on('disconnect', checkSession);
      socket.on('connect_error', checkSession);
      state.bound = true;
    } else if (state.bindAttempts < 40) {
      window.setTimeout(bindSocket, 250);
    }
  }

  window.addEventListener('online', checkSession);
  window.addEventListener('pageshow', checkSession);
  bindSocket();
  // Covers a disconnect fired before installation and sockets not yet present.
  checkSession();
  // Low-frequency fallback also catches quiet revocation/expiry and browsers
  // whose Socket.IO object never appeared during the bounded binding window.
  window.setInterval(checkSession, 15000);
})();
'''
