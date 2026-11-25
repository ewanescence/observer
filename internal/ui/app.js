(() => {
  const PRESET_ENVS = ['Production', 'Pilot', 'Stage', 'Sandbox'];
  const state = {
    offset: 0,
    limit: 50,
    auditOffset: 0,
    auditLimit: 50,
    portals: [],
    endpoints: [],
    currentPayload: '',
    slugTouched: false
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
    setTimeout(() => { el.hidden = true; }, 4500);
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

  function localTimeZoneLabel() {
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      const offsetMin = -new Date().getTimezoneOffset();
      const sign = offsetMin >= 0 ? '+' : '-';
      const absH = String(Math.floor(Math.abs(offsetMin) / 60)).padStart(2, '0');
      const absM = String(Math.abs(offsetMin) % 60).padStart(2, '0');
      return `${tz || 'Local'} (UTC${sign}${absH}:${absM})`;
    } catch {
      return 'Browser local timezone';
    }
  }

  function slugify(parts) {
    return parts
      .map((p) => String(p || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, ''))
      .filter(Boolean)
      .join('-')
      .slice(0, 64);
  }

  // Tabs
  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const target = btn.dataset.tab;
      ['events', 'endpoints', 'audit', 'settings'].forEach((name) => {
        $(`tab-${name}`).hidden = name !== target;
      });
      if (target === 'events') loadSummary().then(loadEvents);
      if (target === 'endpoints') loadSummary();
      if (target === 'audit') loadAudit();
      if (target === 'settings') loadSettings();
    });
  });

  // Identity & Sign Out (handles Autentico POST 204 No Content + optional central SSO logout)
  async function loadMe() {
    try {
      const me = await api('/api/me');
      const label = $('user-label');
      const who = me.displayName || me.email;
      if (who) {
        label.textContent = who;
        label.hidden = false;
      } else {
        label.hidden = true;
      }
      if (me.logoutPath) {
        const btn = $('btn-signout');
        btn.hidden = false;
        btn.onclick = async () => {
          btn.disabled = true;
          try {
            const resp = await fetch(me.logoutPath, {
              method: 'POST',
              credentials: 'same-origin'
            });
            if (resp.ok || resp.status === 204) {
              if (me.centralLogoutUrl) {
                window.location.href = me.centralLogoutUrl;
                return;
              }
              ['events', 'endpoints', 'audit', 'settings'].forEach((name) => {
                $(`tab-${name}`).hidden = true;
              });
              $('signed-out-view').hidden = false;
              btn.hidden = true;
              label.hidden = true;
              return;
            }
            showToast(`Sign out failed (HTTP ${resp.status})`, true);
          } catch (err) {
            showToast(`Sign out failed: ${err.message}`, true);
          } finally {
            btn.disabled = false;
          }
        };
      }
    } catch (e) {
      showToast(e.message, true);
    }
  }

  // Portal > Environment > Endpoint Summary & Cascading Selectors
  async function loadSummary() {
    try {
      const res = await api('/api/summary');
      state.portals = res.portals || [];
      state.endpoints = [];
      state.portals.forEach((p) => {
        (p.environments || []).forEach((env) => {
          (env.endpoints || []).forEach((ep) => state.endpoints.push(ep));
        });
      });

      populatePortalSuggestions();
      syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
      syncCascadingFilters('ep-filter-portal', 'ep-filter-env', null, false);
      renderEventsSummary();
      renderEndpointsTree();
    } catch (e) {
      showToast(e.message, true);
    }
  }

  function populatePortalSuggestions() {
    const dl = $('portal-suggestions');
    dl.replaceChildren();
    state.portals.forEach((p) => {
      const opt = document.createElement('option');
      opt.value = p.portal;
      dl.appendChild(opt);
    });
  }

  function syncCascadingFilters(portalSelId, envSelId, epSelId, withEndpoint) {
    const pSel = $(portalSelId);
    const eSel = $(envSelId);
    const prevP = pSel.value;
    const prevE = eSel.value;

    pSel.replaceChildren(new Option('All portals', ''));
    state.portals.forEach((p) => pSel.appendChild(new Option(p.portal, p.portal)));
    if (state.portals.some((p) => p.portal === prevP)) pSel.value = prevP;

    const activeP = pSel.value;
    const envSet = new Set();
    state.portals.forEach((p) => {
      if (!activeP || p.portal === activeP) {
        (p.environments || []).forEach((e) => envSet.add(e.environment));
      }
    });
    eSel.replaceChildren(new Option('All environments', ''));
    Array.from(envSet).forEach((env) => eSel.appendChild(new Option(env, env)));
    if (envSet.has(prevE)) eSel.value = prevE;

    if (withEndpoint && epSelId) {
      const epSel = $(epSelId);
      const prevEp = epSel.value;
      const activeE = eSel.value;
      epSel.replaceChildren(new Option('All endpoints', ''));
      const matching = state.endpoints.filter((ep) =>
        (!activeP || ep.portal === activeP) && (!activeE || ep.environment === activeE)
      );
      matching.forEach((ep) => {
        epSel.appendChild(new Option(`${ep.name} (${ep.portal} · ${ep.environment})`, String(ep.id)));
      });
      if (matching.some((ep) => String(ep.id) === prevEp)) epSel.value = prevEp;
    }
  }

  function computeFilteredSummary() {
    const pVal = $('filter-portal').value;
    const eVal = $('filter-env').value;
    const epVal = $('filter-endpoint').value;

    const matching = state.endpoints.filter((ep) =>
      (!pVal || ep.portal === pVal) &&
      (!eVal || ep.environment === eVal) &&
      (!epVal || String(ep.id) === epVal)
    );
    return matching.reduce((acc, ep) => {
      acc.events += ep.eventCount || 0;
      acc.heartbeats += ep.heartbeatCount || 0;
      acc.errors += ep.errorCount || 0;
      acc.endpoints += 1;
      if (ep.enabled) acc.enabled += 1;
      return acc;
    }, { events: 0, heartbeats: 0, errors: 0, endpoints: 0, enabled: 0 });
  }

  function renderEventsSummary() {
    const totals = computeFilteredSummary();
    const kpi = $('events-kpi');
    kpi.replaceChildren();

    [
      ['Events', totals.events, ''],
      ['Errors', totals.errors, totals.errors > 0 ? 'err' : ''],
      ['Heartbeats', totals.heartbeats, ''],
      ['Active Endpoints', `${totals.enabled} / ${totals.endpoints}`, '']
    ].forEach(([lbl, val, cls]) => {
      const card = document.createElement('div');
      card.className = 'kpi-card';
      const l = document.createElement('div');
      l.className = 'kpi-label';
      l.textContent = lbl;
      const v = document.createElement('div');
      v.className = `kpi-value ${cls}`.trim();
      v.textContent = String(val);
      card.append(l, v);
      kpi.appendChild(card);
    });

    const chips = $('events-scope-chips');
    chips.replaceChildren();
    if (state.portals.length === 0) return;

    const curP = $('filter-portal').value;
    const curE = $('filter-env').value;

    const allBtn = document.createElement('button');
    allBtn.type = 'button';
    allBtn.className = `chip ${!curP && !curE ? 'active' : ''}`;
    allBtn.textContent = 'All Portals';
    allBtn.onclick = () => {
      $('filter-portal').value = '';
      syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
      $('filter-env').value = '';
      $('filter-endpoint').value = '';
      state.offset = 0;
      renderEventsSummary();
      loadEvents();
    };
    chips.appendChild(allBtn);

    state.portals.forEach((p) => {
      (p.environments || []).forEach((env) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        const isActive = curP === p.portal && curE === env.environment;
        btn.className = `chip ${isActive ? 'active' : ''}`;
        const errPart = env.errorCount > 0 ? ` · ${env.errorCount} err` : '';
        btn.textContent = `${p.portal} › ${env.environment} (${env.eventCount}${errPart})`;
        btn.onclick = () => {
          $('filter-portal').value = p.portal;
          syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
          $('filter-env').value = env.environment;
          syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
          $('filter-endpoint').value = '';
          state.offset = 0;
          renderEventsSummary();
          loadEvents();
        };
        chips.appendChild(btn);
      });
    });
  }

  // Endpoints Hierarchy View
  function renderEndpointsTree() {
    const tree = $('endpoints-tree');
    tree.replaceChildren();

    const pFilter = $('ep-filter-portal').value;
    const eFilter = $('ep-filter-env').value;

    const visiblePortals = state.portals.filter((p) => !pFilter || p.portal === pFilter);
    if (visiblePortals.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'card muted';
      empty.textContent = 'No endpoints configured yet. Click "+ New Endpoint" to create one.';
      tree.appendChild(empty);
      return;
    }

    visiblePortals.forEach((p) => {
      const pEnvs = (p.environments || []).filter((e) => !eFilter || e.environment === eFilter);
      if (pEnvs.length === 0) return;

      const pGroup = document.createElement('div');
      pGroup.className = 'portal-group';

      const pHead = document.createElement('div');
      pHead.className = 'portal-head';

      const pLeft = document.createElement('div');
      const pTitle = document.createElement('strong');
      pTitle.textContent = p.portal;
      const pStats = document.createElement('span');
      pStats.className = 'muted';
      pStats.style.marginLeft = '10px';
      pStats.textContent = `${p.enabledCount}/${p.endpointCount} active · ${p.eventCount} events · ${p.errorCount} errors · ${p.heartbeatCount} heartbeats`;
      pLeft.append(pTitle, pStats);

      const pActions = document.createElement('div');
      pActions.style.display = 'flex';
      pActions.style.gap = '6px';

      const viewEvBtn = document.createElement('button');
      viewEvBtn.className = 'btn btn-sm';
      viewEvBtn.textContent = 'View Events';
      viewEvBtn.onclick = () => jumpToEventsScope(p.portal, '');

      const addInPortalBtn = document.createElement('button');
      addInPortalBtn.className = 'btn btn-sm';
      addInPortalBtn.textContent = '+ Add Endpoint';
      addInPortalBtn.onclick = () => openEndpointForm(null, p.portal, 'Production');

      pActions.append(viewEvBtn, addInPortalBtn);
      pHead.append(pLeft, pActions);
      pGroup.appendChild(pHead);

      pEnvs.forEach((env) => {
        const envBox = document.createElement('div');
        envBox.className = 'env-group';

        const envHead = document.createElement('div');
        envHead.className = 'env-head';

        const envLeft = document.createElement('div');
        const envBadge = document.createElement('span');
        envBadge.className = 'badge badge-env';
        envBadge.textContent = env.environment;
        const envMeta = document.createElement('span');
        envMeta.className = 'muted';
        envMeta.style.marginLeft = '8px';
        envMeta.textContent = `${env.endpointCount} endpoint(s) · ${env.eventCount} events · ${env.errorCount} errors · Last: ${fmtDate(env.lastReceivedAt)}`;
        envLeft.append(envBadge, envMeta);

        const envBtn = document.createElement('button');
        envBtn.className = 'btn btn-sm';
        envBtn.textContent = 'Filter Events';
        envBtn.onclick = () => jumpToEventsScope(p.portal, env.environment);

        envHead.append(envLeft, envBtn);
        envBox.appendChild(envHead);

        const epList = document.createElement('div');
        epList.className = 'ep-list';

        (env.endpoints || []).forEach((ep) => {
          const row = document.createElement('div');
          row.className = 'ep-row';

          const info = document.createElement('div');
          const nameEl = document.createElement('strong');
          nameEl.textContent = ep.name;
          const statusBadge = document.createElement('span');
          statusBadge.className = `badge ${ep.enabled ? 'badge-event' : 'badge-error'}`;
          statusBadge.style.marginLeft = '8px';
          statusBadge.textContent = ep.enabled ? 'active' : 'disabled';

          const hookURL = `${location.origin}/hooks/${ep.slug}`;
          const sub = document.createElement('div');
          sub.className = 'muted';
          const secParts = [
            ep.hmacRequired ? (ep.hasHmacSecret ? 'HMAC' : 'HMAC (missing secret!)') : 'HMAC off',
            ep.hasApiKey ? 'API Key' : null,
            ep.hasPgpPrivateKey ? 'PGP' : null,
            Object.keys(ep.customHeaders || {}).length ? `${Object.keys(ep.customHeaders).length} custom hdr` : null
          ].filter(Boolean);
          sub.textContent = `${hookURL} · ${secParts.join(', ')} · ${ep.eventCount} events / ${ep.errorCount} err`;
          info.append(nameEl, statusBadge, sub);

          const btns = document.createElement('div');
          btns.style.display = 'flex';
          btns.style.gap = '6px';

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
            if (!confirm(`Delete "${p.portal} › ${env.environment} › ${ep.name}" and all its stored events?`)) return;
            try {
              await api(`/api/endpoints/${ep.id}`, { method: 'DELETE' });
              showToast('Endpoint deleted');
              loadSummary();
            } catch (e) { showToast(e.message, true); }
          };

          btns.append(copyBtn, editBtn, delBtn);
          row.append(info, btns);
          epList.appendChild(row);
        });

        envBox.appendChild(epList);
        pGroup.appendChild(envBox);
      });

      tree.appendChild(pGroup);
    });
  }

  function jumpToEventsScope(portal, env) {
    document.querySelectorAll('.tab').forEach((b) => {
      b.classList.toggle('active', b.dataset.tab === 'events');
    });
    ['events', 'endpoints', 'audit', 'settings'].forEach((name) => {
      $(`tab-${name}`).hidden = name !== 'events';
    });
    $('filter-portal').value = portal || '';
    syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
    $('filter-env').value = env || '';
    syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
    $('filter-endpoint').value = '';
    state.offset = 0;
    renderEventsSummary();
    loadEvents();
  }

  // Guided Endpoint Form helpers
  function setFormEnv(envName) {
    const val = envName || 'Production';
    if (PRESET_ENVS.includes(val)) {
      $('ep-env-select').value = val;
      $('ep-env-custom').hidden = true;
      $('ep-env-custom').value = '';
    } else {
      $('ep-env-select').value = '__custom__';
      $('ep-env-custom').hidden = false;
      $('ep-env-custom').value = val;
    }
  }

  function getFormEnv() {
    const sel = $('ep-env-select').value;
    if (sel === '__custom__') {
      return $('ep-env-custom').value.trim() || 'Production';
    }
    return sel;
  }

  function updateURLPreview() {
    const slug = $('ep-slug').value.trim() || '<slug>';
    $('ep-url-preview').textContent = `${location.origin}/hooks/${slug}`;
  }

  function addCustomHeaderRow(key = '', val = '') {
    const container = $('custom-headers-rows');
    if (container.children.length >= 4) {
      return showToast('Cornerstone allows at most 4 custom headers', true);
    }
    const row = document.createElement('div');
    row.className = 'header-row';

    const kInput = document.createElement('input');
    kInput.type = 'text';
    kInput.placeholder = 'x-csod-authentication';
    kInput.value = key;
    kInput.className = 'hdr-key';

    const vInput = document.createElement('input');
    vInput.type = 'text';
    vInput.placeholder = 'Expected header value';
    vInput.value = val;
    vInput.className = 'hdr-val';

    const rmBtn = document.createElement('button');
    rmBtn.type = 'button';
    rmBtn.className = 'btn btn-sm btn-danger';
    rmBtn.textContent = 'Remove';
    rmBtn.onclick = () => row.remove();

    row.append(kInput, vInput, rmBtn);
    container.appendChild(row);
  }

  $('btn-add-header').addEventListener('click', () => addCustomHeaderRow());

  $('ep-env-select').addEventListener('change', () => {
    $('ep-env-custom').hidden = $('ep-env-select').value !== '__custom__';
    maybeAutoSlug();
  });
  ['ep-portal', 'ep-env-custom', 'ep-name'].forEach((id) => {
    $(id).addEventListener('input', maybeAutoSlug);
  });
  $('ep-slug').addEventListener('input', () => {
    state.slugTouched = true;
    updateURLPreview();
  });

  function maybeAutoSlug() {
    if ($('ep-id').value || state.slugTouched) return;
    const suggested = slugify([$('ep-portal').value, getFormEnv(), $('ep-name').value]);
    $('ep-slug').value = suggested;
    updateURLPreview();
  }

  function openEndpointForm(ep = null, defaultPortal = '', defaultEnv = 'Production') {
    const form = $('endpoint-form');
    form.hidden = false;
    state.slugTouched = Boolean(ep);

    $('endpoint-form-title').textContent = ep ? `Edit Endpoint: ${ep.name}` : 'New Webhook Endpoint';
    $('ep-id').value = ep ? ep.id : '';
    $('ep-portal').value = ep ? ep.portal : defaultPortal;
    setFormEnv(ep ? ep.environment : defaultEnv);
    $('ep-name').value = ep ? ep.name : '';
    $('ep-slug').value = ep ? ep.slug : '';
    updateURLPreview();

    $('ep-enabled').checked = ep ? ep.enabled : true;
    $('ep-hmac-required').checked = ep ? ep.hmacRequired : true;
    $('ep-apikey').value = '';
    $('ep-hmac').value = '';
    $('ep-pgp-key').value = '';
    $('ep-pgp-pass').value = '';

    const hdrWrap = $('custom-headers-rows');
    hdrWrap.replaceChildren();
    if (ep && ep.customHeaders) {
      Object.entries(ep.customHeaders).forEach(([k, v]) => addCustomHeaderRow(k, v));
    }

    $('ep-ret-days').value = ep && ep.retentionDays ? ep.retentionDays : '';
    $('ep-hb-days').value = ep && ep.heartbeatRetentionDays ? ep.heartbeatRetentionDays : '';
    $('ep-store-raw-err').checked = ep ? ep.storeRawOnError : false;

    const isEdit = Boolean(ep);
    $('ep-apikey-status').textContent = isEdit && ep.hasApiKey ? '(saved — leave blank to keep)' : '';
    $('ep-hmac-status').textContent = isEdit && ep.hasHmacSecret ? '(saved — leave blank to keep)' : '';
    $('ep-pgp-status').textContent = isEdit && ep.hasPgpPrivateKey ? '(saved — leave blank to keep)' : '';
    $('ep-pgppass-status').textContent = isEdit && ep.hasPgpPassphrase ? '(saved — leave blank to keep)' : '';

    $('ep-clear-apikey-wrap').hidden = !(isEdit && ep.hasApiKey);
    $('ep-clear-hmac-wrap').hidden = !(isEdit && ep.hasHmacSecret);
    $('ep-clear-pgp-wrap').hidden = !(isEdit && ep.hasPgpPrivateKey);
    $('ep-clear-pgppass-wrap').hidden = !(isEdit && ep.hasPgpPassphrase);
    $('ep-clear-apikey').checked = false;
    $('ep-clear-hmac').checked = false;
    $('ep-clear-pgp').checked = false;
    $('ep-clear-pgppass').checked = false;

    $('pgp-gen-name').value = ep ? `${ep.portal} ${ep.name}` : '';
    $('pgp-gen-email').value = '';
    $('pgp-gen-pass').value = '';
    $('pgp-gen-days').value = '730';
    $('pgp-pub-text').value = '';
    $('pgp-pub-meta').textContent = '';
    $('pgp-pub-output').hidden = true;

    form.scrollIntoView({ behavior: 'smooth' });
  }

  $('btn-new-endpoint').addEventListener('click', () => {
    openEndpointForm(null, $('ep-filter-portal').value, $('ep-filter-env').value || 'Production');
  });
  $('btn-cancel-endpoint').addEventListener('click', () => { $('endpoint-form').hidden = true; });
  $('btn-cancel-endpoint-top').addEventListener('click', () => { $('endpoint-form').hidden = true; });
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
      const defaultName = [$('ep-portal').value.trim(), $('ep-name').value.trim()].filter(Boolean).join(' ');
      const res = await api('/api/pgp/generate', {
        method: 'POST',
        body: {
          name: $('pgp-gen-name').value.trim() || defaultName,
          email: $('pgp-gen-email').value.trim(),
          passphrase: pass,
          bits: Number($('pgp-gen-bits').value),
          validDays: Number($('pgp-gen-days').value)
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
      $('pgp-pub-meta').textContent = `Key ID: ${res.keyId} · Expires: ${fmtDate(res.expiresAt)}`;
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
    const customHeaders = {};
    const rows = Array.from($('custom-headers-rows').children);
    for (const row of rows) {
      const k = row.querySelector('.hdr-key').value.trim();
      const v = row.querySelector('.hdr-val').value.trim();
      if (!k && !v) continue;
      if (!k) return showToast('Custom header key cannot be empty', true);
      customHeaders[k] = v;
    }

    const id = $('ep-id').value;
    const retVal = $('ep-ret-days').value.trim();
    const hbVal = $('ep-hb-days').value.trim();
    const body = {
      portal: $('ep-portal').value.trim(),
      environment: getFormEnv(),
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
      loadSummary();
    } catch (err) {
      showToast(err.message, true);
    }
  });

  // Events list
  async function loadEvents() {
    const params = new URLSearchParams({
      limit: String(state.limit),
      offset: String(state.offset)
    });
    if ($('filter-portal').value) params.set('portal', $('filter-portal').value);
    if ($('filter-env').value) params.set('environment', $('filter-env').value);
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
        td.colSpan = 9;
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
          const pText = document.createElement('span');
          pText.textContent = `${ev.endpointPortal || 'Default'} `;
          const envBadge = document.createElement('span');
          envBadge.className = 'badge badge-env';
          envBadge.textContent = ev.endpointEnvironment || 'Production';
          c2.append(pText, envBadge);

          const c3 = document.createElement('td');
          c3.textContent = ev.endpointName || `/hooks/${ev.endpointSlug}`;

          const c4 = document.createElement('td');
          const b = document.createElement('span');
          b.className = `badge badge-${ev.kind}`;
          b.textContent = ev.kind;
          c4.appendChild(b);

          const c5 = document.createElement('td');
          c5.textContent = ev.eventCases || ev.errorMessage || '-';

          const c6 = document.createElement('td');
          c6.textContent = String(ev.recordCount);

          const c7 = document.createElement('td');
          const sec = [];
          if (ev.wasEncrypted) sec.push('PGP');
          if (ev.wasCompressed) sec.push('gzip');
          c7.textContent = sec.join(' + ') || 'plain';

          const c8 = document.createElement('td');
          c8.textContent = String(ev.statusCode);

          const c9 = document.createElement('td');
          const del = document.createElement('button');
          del.className = 'btn btn-sm btn-danger';
          del.textContent = 'Delete';
          del.onclick = async (e) => {
            e.stopPropagation();
            try {
              await api(`/api/events/${ev.id}`, { method: 'DELETE' });
              loadSummary().then(loadEvents);
            } catch (err) { showToast(err.message, true); }
          };
          c9.appendChild(del);

          tr.append(c1, c2, c3, c4, c5, c6, c7, c8, c9);
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
      $('modal-title').textContent = `${ev.kind.toUpperCase()} #${ev.id} — ${ev.endpointPortal} › ${ev.endpointEnvironment} › ${ev.endpointName}`;

      const meta = $('modal-meta');
      meta.replaceChildren();
      [
        ['Received (Local)', fmtDate(ev.receivedAt)],
        ['Endpoint URL', `/hooks/${ev.endpointSlug}`],
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

  $('filter-portal').addEventListener('change', () => {
    syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
    state.offset = 0;
    renderEventsSummary();
    loadEvents();
  });
  $('filter-env').addEventListener('change', () => {
    syncCascadingFilters('filter-portal', 'filter-env', 'filter-endpoint', true);
    state.offset = 0;
    renderEventsSummary();
    loadEvents();
  });
  ['filter-endpoint', 'filter-kind', 'filter-heartbeats'].forEach((id) => {
    $(id).addEventListener('change', () => {
      state.offset = 0;
      renderEventsSummary();
      loadEvents();
    });
  });
  $('filter-query').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { state.offset = 0; loadEvents(); }
  });
  $('btn-refresh-events').addEventListener('click', () => loadSummary().then(loadEvents));
  $('btn-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - state.limit); loadEvents(); });
  $('btn-next').addEventListener('click', () => { state.offset += state.limit; loadEvents(); });

  $('ep-filter-portal').addEventListener('change', () => {
    syncCascadingFilters('ep-filter-portal', 'ep-filter-env', null, false);
    renderEndpointsTree();
  });
  $('ep-filter-env').addEventListener('change', renderEndpointsTree);

  // Audit Log Tab (read-only identities sourced from Autentico)
  async function loadAudit() {
    $('audit-tz-note').textContent = `Timestamps displayed in local timezone: ${localTimeZoneLabel()}`;
    const params = new URLSearchParams({
      limit: String(state.auditLimit),
      offset: String(state.auditOffset)
    });
    if ($('audit-filter-action').value) params.set('action', $('audit-filter-action').value);
    if ($('audit-filter-query').value.trim()) params.set('q', $('audit-filter-query').value.trim());

    try {
      const res = await api(`/api/audit?${params.toString()}`);
      const tbody = $('audit-tbody');
      tbody.replaceChildren();

      if (res.items.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'muted';
        td.textContent = 'No administrative operations recorded yet.';
        tr.appendChild(td);
        tbody.appendChild(tr);
      } else {
        res.items.forEach((item) => {
          const tr = document.createElement('tr');

          const c1 = document.createElement('td');
          c1.textContent = fmtDate(item.occurredAt);

          const c2 = document.createElement('td');
          const actorSpan = document.createElement('span');
          actorSpan.textContent = item.actorName || item.actorEmail || item.actorId || 'unknown';
          if (item.actorId) actorSpan.title = `Autentico ID: ${item.actorId}`;
          c2.appendChild(actorSpan);

          const c3 = document.createElement('td');
          const b = document.createElement('span');
          b.className = 'badge badge-challenge';
          b.textContent = item.action;
          c3.appendChild(b);

          const c4 = document.createElement('td');
          c4.textContent = item.targetLabel || item.targetId || '-';

          const c5 = document.createElement('td');
          c5.textContent = item.details || '-';

          tr.append(c1, c2, c3, c4, c5);
          tbody.appendChild(tr);
        });
      }

      const start = res.total === 0 ? 0 : state.auditOffset + 1;
      const end = Math.min(state.auditOffset + res.items.length, res.total);
      $('audit-count').textContent = `Showing ${start}-${end} of ${res.total}`;
      $('audit-prev').disabled = state.auditOffset === 0;
      $('audit-next').disabled = state.auditOffset + res.items.length >= res.total;
    } catch (e) {
      showToast(e.message, true);
    }
  }

  $('audit-filter-action').addEventListener('change', () => { state.auditOffset = 0; loadAudit(); });
  $('audit-filter-query').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { state.auditOffset = 0; loadAudit(); }
  });
  $('btn-refresh-audit').addEventListener('click', loadAudit);
  $('audit-prev').addEventListener('click', () => { state.auditOffset = Math.max(0, state.auditOffset - state.auditLimit); loadAudit(); });
  $('audit-next').addEventListener('click', () => { state.auditOffset += state.auditLimit; loadAudit(); });

  // Settings Tab
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
        ['Audit Log Entries', res.stats.auditLogCount],
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
  loadSummary().then(loadEvents);
})();
