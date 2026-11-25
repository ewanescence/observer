(() => {
  const state = {
    offset: 0,
    limit: 50,
    endpoints: [],
    currentPayload: ''
  };

  const $ = (id) => document.getElementById(id);

  async function api(path, opts = {}) {
    const headers = Object.assign({ 'X-Requested-With': 'observer' }, opts.headers || {});
    if (opts.body && typeof opts.body !== 'string') {
      headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const resp = await fetch(path, Object.assign({}, opts, { headers }));
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!resp.ok) {
      throw new Error((data && data.error) || resp.statusText);
    }
    return data;
  }

  function showToast(msg, isErr = false) {
    const el = $('toast');
    el.textContent = msg;
    el.className = isErr ? 'toast error' : 'toast';
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 4000);
  }

  function fmtDate(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
  }

  function fmtBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
  }

  // Tabs
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      ['events', 'endpoints', 'settings'].forEach((name) => {
        $(`tab-${name}`).hidden = name !== target;
      });
      if (target === 'events') loadEvents();
      if (target === 'endpoints') loadEndpoints();
      if (target === 'settings') loadSettings();
    });
  });

  async function loadMe() {
    try {
      const me = await api('/api/me');
      $('user-label').textContent = me.email || me.userId || '';
      if (me.logoutPath) {
        const form = $('logout-form');
        form.action = me.logoutPath;
        form.hidden = false;
      }
    } catch (e) {
      showToast(e.message, true);
    }
  }

  async function loadEndpoints() {
    try {
      const eps = await api('/api/endpoints');
      state.endpoints = eps;

      const sel = $('filter-endpoint');
      const prev = sel.value;
      sel.replaceChildren(new Option('All endpoints', ''));
      eps.forEach((ep) => sel.appendChild(new Option(`${ep.name} (/hooks/${ep.slug})`, String(ep.id))));
      sel.value = prev;

      const list = $('endpoints-list');
      list.replaceChildren();
      if (eps.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'card muted';
        empty.textContent = 'No endpoints configured yet. Click "+ New Endpoint" to create one.';
        list.appendChild(empty);
        return;
      }

      eps.forEach((ep) => {
        const card = document.createElement('div');
        card.className = 'card';

        const header = document.createElement('div');
        header.className = 'toolbar';
        header.style.justifyContent = 'space-between';
        header.style.marginBottom = '8px';

        const titleWrap = document.createElement('div');
        const strong = document.createElement('strong');
        strong.textContent = ep.name;
        const badge = document.createElement('span');
        badge.className = `badge ${ep.enabled ? 'badge-event' : 'badge-error'}`;
        badge.style.marginLeft = '8px';
        badge.textContent = ep.enabled ? 'enabled' : 'disabled';
        titleWrap.append(strong, badge);

        const actions = document.createElement('div');
        actions.style.display = 'flex';
        actions.style.gap = '6px';

        const hookURL = `${location.origin}/hooks/${ep.slug}`;
        const copyBtn = document.createElement('button');
        copyBtn.className = 'btn btn-sm';
        copyBtn.textContent = 'Copy URL';
        copyBtn.onclick = () => {
          navigator.clipboard?.writeText(hookURL);
          showToast(`Copied ${hookURL}`);
        };

        const editBtn = document.createElement('button');
        editBtn.className = 'btn btn-sm';
        editBtn.textContent = 'Edit';
        editBtn.onclick = () => openEndpointForm(ep);

        const delBtn = document.createElement('button');
        delBtn.className = 'btn btn-sm btn-danger';
        delBtn.textContent = 'Delete';
        delBtn.onclick = async () => {
          if (!confirm(`Delete endpoint "${ep.name}" and all its stored events?`)) return;
          try {
            await api(`/api/endpoints/${ep.id}`, { method: 'DELETE' });
            showToast('Endpoint deleted');
            loadEndpoints();
          } catch (e) { showToast(e.message, true); }
        };

        actions.append(copyBtn, editBtn, delBtn);
        header.append(titleWrap, actions);

        const meta = document.createElement('div');
        meta.className = 'muted';
        const flags = [
          `URL: ${hookURL}`,
          `API Key: ${ep.hasApiKey ? 'set' : 'none'}`,
          `HMAC: ${ep.hmacRequired ? (ep.hasHmacSecret ? 'required' : 'missing secret!') : 'optional'}`,
          `PGP: ${ep.hasPgpPrivateKey ? 'configured' : 'none'}`,
          `Custom Headers: ${Object.keys(ep.customHeaders || {}).length}`
        ];
        meta.textContent = flags.join(' · ');

        card.append(header, meta);
        list.appendChild(card);
      });
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function openEndpointForm(ep = null) {
    const form = $('endpoint-form');
    form.hidden = false;
    $('endpoint-form-title').textContent = ep ? `Edit Endpoint: ${ep.name}` : 'New Endpoint';
    $('ep-id').value = ep ? ep.id : '';
    $('ep-name').value = ep ? ep.name : '';
    $('ep-slug').value = ep ? ep.slug : '';
    $('ep-enabled').checked = ep ? ep.enabled : true;
    $('ep-hmac-required').checked = ep ? ep.hmacRequired : true;
    $('ep-apikey').value = '';
    $('ep-hmac').value = '';
    $('ep-pgp-key').value = '';
    $('ep-pgp-pass').value = '';
    $('ep-custom-headers').value = ep && ep.customHeaders && Object.keys(ep.customHeaders).length
      ? JSON.stringify(ep.customHeaders, null, 2)
      : '';
    $('ep-ret-days').value = ep && ep.retentionDays ? ep.retentionDays : '';
    $('ep-hb-days').value = ep && ep.heartbeatRetentionDays ? ep.heartbeatRetentionDays : '';
    $('ep-store-raw-err').checked = ep ? ep.storeRawOnError : false;

    const isEdit = Boolean(ep);
    $('ep-apikey-status').textContent = isEdit && ep.hasApiKey ? '(set — leave blank to keep)' : '';
    $('ep-hmac-status').textContent = isEdit && ep.hasHmacSecret ? '(set — leave blank to keep)' : '';
    $('ep-pgp-status').textContent = isEdit && ep.hasPgpPrivateKey ? '(set — leave blank to keep)' : '';
    $('ep-pgppass-status').textContent = isEdit && ep.hasPgpPassphrase ? '(set — leave blank to keep)' : '';

    $('ep-clear-apikey-wrap').hidden = !(isEdit && ep.hasApiKey);
    $('ep-clear-hmac-wrap').hidden = !(isEdit && ep.hasHmacSecret);
    $('ep-clear-pgp-wrap').hidden = !(isEdit && ep.hasPgpPrivateKey);
    $('ep-clear-pgppass-wrap').hidden = !(isEdit && ep.hasPgpPassphrase);
    $('ep-clear-apikey').checked = false;
    $('ep-clear-hmac').checked = false;
    $('ep-clear-pgp').checked = false;
    $('ep-clear-pgppass').checked = false;
    $('pgp-gen-name').value = ep ? ep.name : '';
    $('pgp-gen-email').value = '';
    $('pgp-gen-pass').value = '';
    $('pgp-pub-text').value = '';
    $('pgp-pub-meta').textContent = '';
    $('pgp-pub-output').hidden = true;

    form.scrollIntoView({ behavior: 'smooth' });
  }

  $('btn-new-endpoint').addEventListener('click', () => openEndpointForm(null));
  $('btn-cancel-endpoint').addEventListener('click', () => { $('endpoint-form').hidden = true; });
  $('ep-pgp-file').addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (file) $('ep-pgp-key').value = await file.text();
  });

  $('btn-gen-pgp').addEventListener('click', async () => {
    const btn = $('btn-gen-pgp');
    btn.disabled = true;
    btn.textContent = 'Generating...';
    try {
      const pass = $('pgp-gen-pass').value || $('ep-pgp-pass').value;
      const res = await api('/api/pgp/generate', {
        method: 'POST',
        body: {
          name: $('pgp-gen-name').value.trim() || $('ep-name').value.trim(),
          email: $('pgp-gen-email').value.trim(),
          passphrase: pass,
          bits: Number($('pgp-gen-bits').value)
        }
      });
      $('ep-pgp-key').value = res.privateKey;
      $('ep-clear-pgp').checked = false;
      if (pass) {
        $('ep-pgp-pass').value = pass;
        $('ep-clear-pgppass').checked = false;
      } else {
        $('ep-pgp-pass').value = '';
      }
      $('pgp-pub-text').value = res.publicKey;
      $('pgp-pub-meta').textContent = `Key ID: ${res.keyId} · Fingerprint: ${res.fingerprint}`;
      $('pgp-pub-output').hidden = false;
      showToast('PGP keypair generated — upload public key to CSOD and click Save Endpoint');
    } catch (err) {
      showToast(err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Generate Keypair';
    }
  });

  $('btn-copy-pub').addEventListener('click', () => {
    const pub = $('pgp-pub-text').value;
    if (pub) {
      navigator.clipboard?.writeText(pub);
      showToast('Public key copied to clipboard');
    }
  });

  $('btn-dl-pub').addEventListener('click', () => {
    const pub = $('pgp-pub-text').value;
    if (!pub) return;
    const slug = $('ep-slug').value.trim() || 'csod-webhook';
    const blob = new Blob([pub], { type: 'application/pgp-keys' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${slug}-public.asc`;
    a.click();
    URL.revokeObjectURL(url);
  });

  $('endpoint-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    let customHeaders = {};
    const rawHeaders = $('ep-custom-headers').value.trim();
    if (rawHeaders) {
      try { customHeaders = JSON.parse(rawHeaders); }
      catch { return showToast('Custom headers must be valid JSON', true); }
    }

    const id = $('ep-id').value;
    const retVal = $('ep-ret-days').value.trim();
    const hbVal = $('ep-hb-days').value.trim();
    const body = {
      name: $('ep-name').value.trim(),
      slug: $('ep-slug').value.trim(),
      enabled: $('ep-enabled').checked,
      hmacRequired: $('ep-hmac-required').checked,
      customHeaders,
      retentionDays: retVal ? Number(retVal) : null,
      heartbeatRetentionDays: hbVal ? Number(hbVal) : null,
      storeRawOnError: $('ep-store-raw-err').checked,
      clearApiKey: $('ep-clear-apikey').checked,
      clearHmacSecret: $('ep-clear-hmac').checked,
      clearPgpPrivateKey: $('ep-clear-pgp').checked,
      clearPgpPassphrase: $('ep-clear-pgppass').checked
    };

    if ($('ep-apikey').value) body.apiKey = $('ep-apikey').value;
    if ($('ep-hmac').value) body.hmacSecret = $('ep-hmac').value;
    if ($('ep-pgp-key').value.trim()) body.pgpPrivateKey = $('ep-pgp-key').value;
    if ($('ep-pgp-pass').value) body.pgpPassphrase = $('ep-pgp-pass').value;

    try {
      if (id) {
        await api(`/api/endpoints/${id}`, { method: 'PUT', body });
        showToast('Endpoint updated');
      } else {
        await api('/api/endpoints', { method: 'POST', body });
        showToast('Endpoint created');
      }
      $('endpoint-form').hidden = true;
      loadEndpoints();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  async function loadEvents() {
    const params = new URLSearchParams({
      limit: String(state.limit),
      offset: String(state.offset)
    });
    if ($('filter-endpoint').value) params.set('endpointId', $('filter-endpoint').value);
    if ($('filter-kind').value) params.set('kind', $('filter-kind').value);
    if ($('filter-heartbeats').checked) params.set('includeHeartbeats', '1');
    if ($('filter-query').value.trim()) params.set('q', $('filter-query').value.trim());

    try {
      const res = await api(`/api/events?${params.toString()}`);
      const tbody = $('events-tbody');
      tbody.replaceChildren();

      if (res.items.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 8;
        td.className = 'muted';
        td.textContent = 'No webhook deliveries match the current filters.';
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else {
        res.items.forEach((ev) => {
          const tr = document.createElement('tr');
          tr.onclick = () => openEventModal(ev.id);

          const c1 = document.createElement('td');
          c1.textContent = fmtDate(ev.receivedAt);

          const c2 = document.createElement('td');
          c2.textContent = ev.endpointSlug ? `/hooks/${ev.endpointSlug}` : ev.endpointName;

          const c3 = document.createElement('td');
          const b = document.createElement('span');
          b.className = `badge badge-${ev.kind}`;
          b.textContent = ev.kind;
          c3.appendChild(b);

          const c4 = document.createElement('td');
          c4.textContent = ev.eventCases || ev.errorMessage || '-';

          const c5 = document.createElement('td');
          c5.textContent = String(ev.recordCount);

          const c6 = document.createElement('td');
          const sec = [];
          if (ev.wasEncrypted) sec.push('PGP');
          if (ev.wasCompressed) sec.push('gzip');
          c6.textContent = sec.join(' + ') || 'plain';

          const c7 = document.createElement('td');
          c7.textContent = String(ev.statusCode);

          const c8 = document.createElement('td');
          const del = document.createElement('button');
          del.className = 'btn btn-sm btn-danger';
          del.textContent = 'Delete';
          del.onclick = async (e) => {
            e.stopPropagation();
            try {
              await api(`/api/events/${ev.id}`, { method: 'DELETE' });
              loadEvents();
            } catch (err) { showToast(err.message, true); }
          };
          c8.appendChild(del);

          tr.append(c1, c2, c3, c4, c5, c6, c7, c8);
          tbody.appendChild(tr);
        });
      }

      const start = res.total === 0 ? 0 : state.offset + 1;
      const end = Math.min(state.offset + res.items.length, res.total);
      $('events-count').textContent = `Showing ${start}-${end} of ${res.total}`;
      $('btn-prev').disabled = state.offset === 0;
      $('btn-next').disabled = state.offset + res.items.length >= res.total;
    } catch (e) {
      showToast(e.message, true);
    }
  }

  async function openEventModal(id) {
    try {
      const ev = await api(`/api/events/${id}`);
      $('modal-title').textContent = `${ev.kind.toUpperCase()} #${ev.id} — /hooks/${ev.endpointSlug}`;

      const meta = $('modal-meta');
      meta.replaceChildren();
      [
        ['Received', fmtDate(ev.receivedAt)],
        ['Status', ev.statusCode],
        ['Subscription ID', ev.subscriptionId || '-'],
        ['Session ID', ev.sessionId || '-'],
        ['Attempt #', ev.attemptNumber || '-'],
        ['PGP Key', ev.pgpKeyName || (ev.wasEncrypted ? 'yes' : 'no')],
        ['Sizes', `${fmtBytes(ev.rawSizeBytes)} -> ${fmtBytes(ev.decodedSizeBytes)}`],
        ['Error', ev.errorMessage || '-']
      ].forEach(([k, v]) => {
        const box = document.createElement('div');
        const lbl = document.createElement('div');
        lbl.className = 'muted';
        lbl.textContent = k;
        const val = document.createElement('div');
        val.textContent = String(v);
        box.append(lbl, val);
        meta.appendChild(box);
      });

      try {
        $('modal-headers').textContent = JSON.stringify(JSON.parse(ev.headersJson || '{}'), null, 2);
      } catch {
        $('modal-headers').textContent = ev.headersJson || '{}';
      }

      let formattedPayload = ev.payloadJson || '';
      try {
        if (formattedPayload) {
          formattedPayload = JSON.stringify(JSON.parse(formattedPayload), null, 2);
        }
      } catch {}
      state.currentPayload = formattedPayload;
      $('modal-payload').textContent = formattedPayload || '(empty)';
      $('event-modal').showModal();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  $('modal-close').addEventListener('click', () => $('event-modal').close());
  $('modal-copy-json').addEventListener('click', () => {
    navigator.clipboard?.writeText(state.currentPayload);
    showToast('Copied payload JSON');
  });

  ['filter-endpoint', 'filter-kind', 'filter-heartbeats'].forEach((id) => {
    $(id).addEventListener('change', () => { state.offset = 0; loadEvents(); });
  });
  $('filter-query').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { state.offset = 0; loadEvents(); }
  });
  $('btn-refresh-events').addEventListener('click', loadEvents);
  $('btn-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); loadEvents(); });
  $('btn-next').addEventListener('click', () => { state.offset += state.limit; loadEvents(); });

  async function loadSettings() {
    try {
      const res = await api('/api/settings');
      $('set-ret-days').value = res.retention.retentionDays;
      $('set-hb-days').value = res.retention.heartbeatRetentionDays;
      $('set-interval-note').textContent = `Automatic cleanup runs every ${res.interval}.`;

      const stats = $('stats-list');
      stats.replaceChildren();
      [
        ['Endpoints', res.stats.endpointCount],
        ['Total Stored Deliveries', res.stats.totalEvents],
        ['Heartbeats', res.stats.heartbeatEvents],
        ['Errors', res.stats.errorEvents],
        ['SQLite File Size', fmtBytes(res.stats.dbSizeBytes)],
        ['At-Rest Secret Encryption', res.stats.atRestEncryption ? 'AES-256-GCM active' : 'Disabled (no OBSERVER_MASTER_KEY)']
      ].forEach(([k, v]) => {
        const dt = document.createElement('dt');
        dt.textContent = k;
        const dd = document.createElement('dd');
        dd.textContent = String(v);
        stats.append(dt, dd);
      });
    } catch (e) {
      showToast(e.message, true);
    }
  }

  $('settings-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/settings', {
        method: 'PUT',
        body: {
          retentionDays: Number($('set-ret-days').value),
          heartbeatRetentionDays: Number($('set-hb-days').value)
        }
      });
      showToast('Retention settings saved');
      loadSettings();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  $('btn-purge-now').addEventListener('click', async () => {
    try {
      const res = await api('/api/retention/purge', { method: 'POST' });
      showToast(`Purged ${res.deleted} expired event(s)`);
      loadSettings();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  loadMe();
  loadEndpoints().then(loadEvents);
})();
