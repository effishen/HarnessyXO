"""Tab-local unsent text recovery and explicit disconnected-send protection."""

COMPOSER_RECOVERY_JS = r'''
(() => {
  if (window.harnessyComposerRecovery) return;
  const PREFIX = 'harnessy_composer_draft_v1:';
  const OWNER_KEY = 'harnessy_composer_draft_owner_v1';
  const MAX_TEXT = 256000, MAX_TOTAL = 1000000, MAX_RECORDS = 12;
  const state = {active:null, owner:'', locked:false, timer:null, noticeTimer:null, sequence:0};
  window.harnessyComposerRecovery = state;

  function keys() {
    const found = [];
    for (let i=0; i<sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(PREFIX)) found.push(key);
    }
    return found;
  }
  function purge() {
    try { for (const key of keys()) sessionStorage.removeItem(key); sessionStorage.removeItem(OWNER_KEY); } catch (_) {}
  }
  function keyFor(user, workspace, chat) {
    return PREFIX + [user, workspace, chat].map(value => encodeURIComponent(String(value || ''))).join(':');
  }
  function notice(text) {
    const active = state.active;
    const host = active && document.getElementById(active.composer_id);
    if (!host) return;
    let label = host.querySelector('[data-hy-local-draft-notice]');
    if (!label) {
      label = document.createElement('div');
      label.setAttribute('data-hy-local-draft-notice', 'true');
      label.setAttribute('role', 'status');
      label.className = 'text-xs text-warning';
      host.appendChild(label);
    }
    label.textContent = text;
    if (state.noticeTimer) clearTimeout(state.noticeTimer);
    state.noticeTimer = setTimeout(() => label.remove(), 7000);
  }
  function write(active) {
    if (!active || state.locked || !active.username) return;
    if (active.text.length > MAX_TEXT) {
      try { sessionStorage.removeItem(active.key); } catch (_) {}
      notice('This unsent message is too long for browser backup. Keep this tab open.');
      return;
    }
    try {
      sessionStorage.setItem(active.key, JSON.stringify({revision:active.revision,
        text:active.text, updated_at:Date.now(), sequence:active.sequence}));
      const records = keys().map(key => {
        let row; try { row = JSON.parse(sessionStorage.getItem(key)); } catch (_) {}
        if (!row || typeof row.text !== 'string') { sessionStorage.removeItem(key); return null; }
        return {key, size:row.text.length, at:Number(row.updated_at || 0)};
      }).filter(Boolean).sort((a,b) => (a.key === active.key ? -1 : b.key === active.key ? 1 : b.at - a.at));
      let total = 0;
      records.forEach((row, index) => {
        total += row.size;
        if (index >= MAX_RECORDS || total > MAX_TOTAL) sessionStorage.removeItem(row.key);
      });
    } catch (_) { notice('Browser draft backup is unavailable. Keep this tab open until the connection returns.'); }
  }
  function flush() {
    if (state.timer) { clearTimeout(state.timer); state.timer = null; }
    write(state.active);
    emitDraft(state.active);
  }
  function connected() { return !state.locked && !!window.socket?.connected && !!window.did_handshake; }
  function emitDraft(active) {
    if (!connected() || !active || state.active !== active) return;
    window.emitEvent?.('harnessy_composer_draft', {workspace_id:active.workspace_id,
      chat_id:active.chat_id, composer_id:active.composer_id,
      revision:active.revision, value:active.text});
  }
  function capture(active) {
    active.text = String(active.input.value || '');
    active.sequence = ++state.sequence;
    if (state.timer) clearTimeout(state.timer);
    state.timer = setTimeout(flush, 120);
  }
  function putText(active, text) {
    if (!active.input || !active.input.isConnected) return;
    active.applying = true;
    try {
      const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')?.set;
      if (setter) setter.call(active.input, text); else active.input.value = text;
      if (connected()) active.input.dispatchEvent(new Event('input', {bubbles:true}));
    } finally { active.applying = false; }
  }
  window.harnessyLockComposerDrafts = () => {
    state.locked = true;
    if (state.timer) { clearTimeout(state.timer); state.timer = null; }
    state.active = null;
    purge();
  };
  window.harnessySetupComposerRecovery = payload => {
    if (state.locked) return;
    flush();
    if (!payload.composer_id) { state.active = null; return; }
    const username = String(payload.username || '');
    if (!username) { window.harnessyLockComposerDrafts(); return; }
    try {
      const previousOwner = sessionStorage.getItem(OWNER_KEY);
      if (previousOwner && previousOwner !== username) purge();
      sessionStorage.setItem(OWNER_KEY, username);
    } catch (_) {}
    state.owner = username;
    const active = {...payload, username, revision:String(payload.revision || ''),
      key:keyFor(username,payload.workspace_id,payload.chat_id), text:'', sequence:0,
      pending:null, input:null, applying:false};
    state.active = active;
    function bind(attempt=0) {
      if (state.active !== active || state.locked) return;
      const host = document.getElementById(active.composer_id);
      const input = host && host.querySelector('textarea');
      if (!input) { if (attempt < 60) setTimeout(() => bind(attempt+1), 50); return; }
      active.input = input;
      active.text = String(input.value || '');
      try {
        const saved = JSON.parse(sessionStorage.getItem(active.key) || 'null');
        if (saved && saved.revision === active.revision && typeof saved.text === 'string'
            && saved.text.length <= MAX_TEXT) {
          active.text = saved.text;
          active.sequence = Number(saved.sequence || 0);
          state.sequence = Math.max(state.sequence, active.sequence);
          if (saved.text !== input.value) putText(active, saved.text);
        } else if (saved) sessionStorage.removeItem(active.key);
      } catch (_) {}
      input.addEventListener('input', () => {
        if (state.active !== active || state.locked || active.applying) return;
        capture(active);
      });
      write(active);
      emitDraft(active);
    }
    bind();
  };
  window.harnessyResetComposerDraft = payload => {
    if (state.locked || !state.owner) return;
    const active = state.active;
    const key = keyFor(state.owner,payload.workspace_id,payload.chat_id);
    const revision = String(payload.revision || '');
    if (!active || active.key !== key) {
      try { sessionStorage.removeItem(key); } catch (_) {}
      return;
    }
    if (state.timer) { clearTimeout(state.timer); state.timer = null; }
    const newer = payload.preserve_newer === true && active.pending
      && active.sequence > active.pending.sequence;
    active.revision = revision;
    active.text = newer ? active.text : String(payload.text || '');
    active.pending = null;
    if (active.input && active.input.value !== active.text) putText(active, active.text);
    write(active);
    emitDraft(active);
  };
  window.harnessyCanSubmitComposer = event => {
    const active = state.active;
    if (!connected()) {
      flush();
      notice('App connection is interrupted. Your message has not been sent; send it when the connection returns.');
      event?.preventDefault?.();
      event?.stopImmediatePropagation?.();
      return false;
    }
    if (active) {
      active.text = String(active.input?.value ?? active.text);
      // Flush the current native value before the explicit Send event. This
      // also covers text typed while Vue input delivery was disconnected.
      putText(active, active.text);
      active.pending = {sequence:active.sequence, text:active.text};
      write(active);
      emitDraft(active);
    }
    return true;
  };
  document.addEventListener('click', event => {
    if (event.target?.closest?.('[data-hy-prompt-submit]')) window.harnessyCanSubmitComposer(event);
    if (event.target?.closest?.('[data-hy-sign-out]')) window.harnessyLockComposerDrafts();
  }, true);
  document.addEventListener('input', event => {
    const active = state.active;
    if (active && event.target === active.input && !active.applying && !connected()) {
      if (!state.locked) capture(active);
      // Socket.IO would otherwise buffer the framework's unversioned model
      // update and deliver stale text after a timeline reset or accepted Send.
      event.stopImmediatePropagation();
    }
  }, true);
  function bindSocket(attempt=0) {
    const socket = window.socket;
    if (!socket || typeof socket.on !== 'function') {
      if (attempt < 40) setTimeout(() => bindSocket(attempt+1), 250);
      return;
    }
    socket.on('disconnect', flush);
    socket.on('connect', () => setTimeout(() => {
      const active = state.active;
      if (!connected() || !active || !active.input?.isConnected) return;
      putText(active, active.text);
      emitDraft(active);
    }, 300));
  }
  bindSocket();
  window.addEventListener('pagehide', flush);
})();
'''
