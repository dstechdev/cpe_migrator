(() => {
  'use strict';

  const { convert } = window.SerialConverter;
  const $ = (id) => document.getElementById(id);

  const els = {
    status: $('api-status'), statusText: $('api-status-text'), host: $('api-host'), expiry: $('api-expiry'),
    reconnect: $('btn-reconnect'),
    dryrun: $('opt-dryrun'), skipUnlink: $('opt-skipunlink'),
    inId: $('in-id'), inSerial: $('in-serial'), form: $('form-single'), execSingle: $('btn-exec-single'),
    clientInfo: $('client-info'),
    converter: $('converter'), convBytes: $('conv-bytes'), convHex: $('conv-hex'), convMsg: $('conv-msg'), copy: $('btn-copy'),
    inBatch: $('in-batch'), batchBody: $('batch-body'), batchSummary: $('batch-summary'),
    execBatch: $('btn-exec-batch'), stopBatch: $('btn-stop-batch'), exportBatch: $('btn-export-batch'),
    progress: $('batch-progress'), progressBar: $('batch-progress-bar'), progressText: $('batch-progress-text'),
    log: $('log'), clearLog: $('btn-clear-log'), exportLog: $('btn-export-log'),
    cntOk: $('cnt-ok'), cntWarn: $('cnt-warn'), cntErr: $('cnt-err'),
    modal: $('modal'), modalBody: $('modal-body'), modalOk: $('modal-ok'), modalCancel: $('modal-cancel'),
    toast: $('toast'),
  };

  const state = { busy: false, stop: false, batch: [], logEntries: [], counts: { ok: 0, warn: 0, err: 0 }, status: null };

  // ---------------------------------------------------------------- helpers
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) {
      if (Array.isArray(text)) n.append(...text);
      else if (text instanceof Node) n.append(text);
      else n.textContent = text;
    }
    return n;
  };
  const now = () => new Date().toLocaleTimeString('pt-BR', { hour12: false });
  const isValidId = (v) => /^\d+$/.test(String(v).trim()) && Number(v) > 0;

  let toastTimer;
  function toast(msg) {
    els.toast.textContent = msg;
    els.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (els.toast.hidden = true), 2200);
  }

  function confirmModal(nodeOrHtml) {
    return new Promise((resolve) => {
      els.modalBody.replaceChildren(nodeOrHtml);
      els.modal.hidden = false;
      els.modalOk.focus();
      const done = (v) => {
        els.modal.hidden = true;
        els.modalOk.onclick = els.modalCancel.onclick = null;
        document.removeEventListener('keydown', onKey);
        resolve(v);
      };
      const onKey = (e) => { if (e.key === 'Escape') done(false); };
      document.addEventListener('keydown', onKey);
      els.modalOk.onclick = () => done(true);
      els.modalCancel.onclick = () => done(false);
    });
  }

  function download(name, content, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([content], { type }));
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  async function api(path, body) {
    const res = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    let data;
    try { data = await res.json(); } catch { data = { error: `Resposta inválida do servidor (HTTP ${res.status})` }; }
    return data;
  }

  // ---------------------------------------------------------------- log
  /**
   * @param {'ok'|'warn'|'err'|'info'|'sep'} level
   * @param {string} msg
   * @param {object} [detail] objeto exibido em <details>
   */
  function log(level, msg, detail) {
    const ts = now();
    state.logEntries.push({ ts: new Date().toISOString(), level, msg, detail });
    if (level in state.counts) {
      state.counts[level]++;
      els.cntOk.textContent = state.counts.ok;
      els.cntWarn.textContent = state.counts.warn;
      els.cntErr.textContent = state.counts.err;
    }

    const row = el('div', `log-entry ${level}`);
    if (level === 'sep') {
      row.textContent = `── ${msg} ${'─'.repeat(20)}`;
    } else {
      const label = { ok: 'OK  ', warn: 'WARN', err: 'ERRO', info: 'INFO' }[level];
      row.append(el('span', 'ts', ts), el('span', 'lvl', label), document.createTextNode(msg));
      if (detail !== undefined) {
        const d = el('details');
        d.append(el('summary', null, 'ver payload / resposta'), el('pre', null, JSON.stringify(detail, null, 2)));
        row.append(d);
      }
    }
    const stick = els.log.scrollHeight - els.log.scrollTop - els.log.clientHeight < 40;
    els.log.append(row);
    if (stick) els.log.scrollTop = els.log.scrollHeight;
  }

  els.clearLog.onclick = () => {
    els.log.replaceChildren();
    state.logEntries = [];
    state.counts = { ok: 0, warn: 0, err: 0 };
    els.cntOk.textContent = els.cntWarn.textContent = els.cntErr.textContent = '0';
  };
  els.exportLog.onclick = () => {
    if (!state.logEntries.length) return toast('Nenhum log para exportar.');
    download(`cpe-migrator-log-${Date.now()}.json`, JSON.stringify(state.logEntries, null, 2), 'application/json');
  };

  // ---------------------------------------------------------------- status
  async function refreshStatus() {
    try {
      const s = await api('/api/status');
      state.status = s;
      els.host.textContent = s.host.replace(/^https?:\/\//, '');
      if (s.connected) {
        els.status.className = 'status-pill status-ok';
        els.statusText.textContent = 'HubSoft conectado';
        const mins = Math.max(0, Math.round((new Date(s.expiresAt) - Date.now()) / 60000));
        els.expiry.textContent = `token expira em ~${mins} min`;
      } else if (s.lastError) {
        els.status.className = 'status-pill status-err';
        els.statusText.textContent = 'Falha OAuth2';
        els.expiry.textContent = 'clique em Reconectar';
        els.status.title = s.lastError;
      } else {
        els.status.className = 'status-pill status-pending';
        els.statusText.textContent = 'Sem token ativo';
        els.expiry.textContent = 'será gerado na 1ª operação';
      }
    } catch {
      els.status.className = 'status-pill status-err';
      els.statusText.textContent = 'Servidor offline';
      els.expiry.textContent = '';
    }
  }

  els.reconnect.onclick = async () => {
    els.reconnect.disabled = true;
    els.status.className = 'status-pill status-pending';
    els.statusText.textContent = 'Autenticando…';
    const r = await api('/api/auth/connect', { force: true });
    if (r.ok) log('ok', `Token OAuth2 renovado (expira ${new Date(r.expiresAt).toLocaleTimeString('pt-BR')}).`);
    else log('err', 'Falha na autenticação OAuth2.', r);
    await refreshStatus();
    els.reconnect.disabled = false;
  };

  // ---------------------------------------------------------------- options
  function syncModeUI() {
    const sim = els.dryrun.checked;
    [els.execSingle, els.execBatch].forEach((b) => b.classList.toggle('sim', sim));
    els.execSingle.querySelector('span').textContent = sim ? 'Simular migração' : 'Executar migração';
    els.execBatch.querySelector('span').textContent = sim ? 'Simular lote' : 'Executar lote';
  }
  els.dryrun.onchange = syncModeUI;

  // ---------------------------------------------------------------- tabs
  document.querySelectorAll('.tab').forEach((t) =>
    t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((x) => {
        x.classList.toggle('active', x === t);
        x.setAttribute('aria-selected', x === t);
      });
      document.querySelectorAll('.panel').forEach((p) => p.classList.toggle('active', p.id === `panel-${t.dataset.tab}`));
    })
  );

  // ---------------------------------------------------------------- converter (individual)
  let lastConv = null;
  function renderConverter() {
    const raw = els.inSerial.value;
    els.convBytes.replaceChildren();
    els.converter.classList.remove('valid', 'error', 'empty');

    if (!raw.trim()) {
      lastConv = null;
      els.converter.classList.add('empty');
      els.convHex.textContent = '————————————————';
      els.convMsg.textContent = 'Digite um serial de 12 (ex: prks00d5e8e9) ou 16 caracteres.';
      els.inSerial.classList.remove('invalid');
      els.copy.disabled = true;
      return updateSingleBtn();
    }

    const c = convert(raw);
    lastConv = c;
    if (!c.ok) {
      els.converter.classList.add('error');
      els.inSerial.classList.add('invalid');
      els.convHex.textContent = '————————————————';
      els.convMsg.textContent = c.error;
      els.copy.disabled = true;
      return updateSingleBtn();
    }

    els.converter.classList.add('valid');
    els.inSerial.classList.remove('invalid');
    Array.from(c.vendor).forEach((ch, i) => {
      const b = el('div', 'byte vendor');
      b.style.animationDelay = `${i * 40}ms`;
      b.append(el('span', 'ch', ch), el('span', 'hx', c.vendorHex.slice(i * 2, i * 2 + 2)));
      els.convBytes.append(b);
    });
    const sfx = el('div', 'byte suffix');
    sfx.style.animationDelay = '160ms';
    sfx.append(el('span', 'ch', c.suffix), el('span', 'hx', 'sufixo'));
    els.convBytes.append(sfx);

    els.convHex.replaceChildren(el('span', 'v', c.vendorHex), document.createTextNode(c.suffix));
    els.convMsg.textContent = c.alreadyHex
      ? `Já está em HEX Huawei (vendor ${c.vendor}). Apenas normalizado.`
      : `Vendor ${c.vendor} → ${c.vendorHex} · sufixo ${c.suffix}`;
    els.copy.disabled = false;
    updateSingleBtn();
  }

  let clientLookupTimer;
  async function fetchClientPreview(id) {
    if (!isValidId(id)) {
      els.clientInfo.hidden = true;
      els.clientInfo.replaceChildren();
      return;
    }
    try {
      const data = await api(`/api/client/${id}`);
      if (data && data.ok) {
        els.clientInfo.replaceChildren(
          el('div', 'client-info-item', [
            el('span', 'client-info-label', 'Cliente / Serviço'),
            el('span', 'client-info-val', data.cliente_servico?.display || data.login || `ID ${id}`),
          ]),
          el('div', 'client-info-item', [
            el('span', 'client-info-label', 'OLT Conexão'),
            el('span', 'client-info-val highlight', data.olt_nome),
          ]),
          el('div', 'client-info-item', [
            el('span', 'client-info-label', 'Interface GPON'),
            el('span', 'client-info-val highlight', `${data.interface_nome} (ID: ${data.id_interface_conexao})`),
          ]),
          el('div', 'client-info-item', [
            el('span', 'client-info-label', 'Serial Atual no ERP'),
            el('span', 'client-info-val highlight', data.cpes_vinculadas?.length
              ? `${data.phy_addr || 'N/A'} (CPE: ${data.cpes_vinculadas.join(', ')})`
              : (data.phy_addr || 'Nenhum vinculado')),
          ])
        );
        els.clientInfo.hidden = false;
      } else {
        els.clientInfo.hidden = true;
      }
    } catch {
      els.clientInfo.hidden = true;
    }
  }

  function updateSingleBtn() {
    const idOk = isValidId(els.inId.value);
    els.inId.classList.toggle('invalid', els.inId.value.trim() !== '' && !idOk);
    els.execSingle.disabled = state.busy || !idOk || !(lastConv && lastConv.ok);

    clearTimeout(clientLookupTimer);
    if (idOk) {
      clientLookupTimer = setTimeout(() => fetchClientPreview(els.inId.value.trim()), 350);
    } else {
      els.clientInfo.hidden = true;
    }
  }

  els.inSerial.addEventListener('input', renderConverter);
  els.inId.addEventListener('input', updateSingleBtn);
  els.copy.onclick = async () => {
    if (!lastConv?.ok) return;
    await navigator.clipboard.writeText(lastConv.hex);
    toast(`Copiado: ${lastConv.hex}`);
  };

  // ---------------------------------------------------------------- migração (core)
  function logResult(r, prefix = '') {
    const tag = `${prefix}[serviço ${r.id_cliente_servico}]`;
    for (const s of r.steps || []) {
      if (s.step === 'convert') {
        if (s.ok) log('info', `${tag} Conversão ${s.detail.input} → ${s.detail.hex}`);
        else log('err', `${tag} Conversão falhou: ${s.detail.error}`);
      } else if (s.step === 'auth') {
        if (!s.ok) log('err', `${tag} OAuth2: ${s.error}`);
      } else if (s.step === 'consultar_autenticacao') {
        if (s.simulated) {
          log('info', `${tag} [1/4 Consulta] ${s.detail}`);
        } else if (s.ok) {
          log('info', `${tag} [1/4 Consulta] Dados identificados: ${s.detail}`);
        } else {
          log('warn', `${tag} [1/4 Consulta] Aviso: ${s.warning || s.message}`);
        }
      } else if (s.step === 'desvincular_cpe') {
        if (s.simulated) {
          log('warn', `${tag} [2/4 SIMULAÇÃO] desvincular_cpe não executado`, s.request);
        } else {
          const info = `desvincular_cpe · HTTP ${s.httpStatus} · ${s.durationMs}ms${s.message ? ` · ${s.message}` : ''}`;
          log(s.ok ? 'warn' : 'err', `${tag} [2/4 Desvincular] ${info}`, { request: s.request, response: s.response });
        }
      } else if (s.step === 'configurar_autenticacao') {
        if (s.simulated) {
          log('info', `${tag} [3/5 SIMULAÇÃO] configurar_autenticacao com phy_addr ${s.request?.phy_addr}`, s.request);
        } else {
          const info = `configurar_autenticacao · HTTP ${s.httpStatus} · ${s.durationMs}ms${s.message ? ` · ${s.message}` : ''}`;
          log(s.ok ? 'info' : 'err', `${tag} [3/5 Autenticação] ${info}`, { request: s.request, response: s.response });
        }
      } else if (s.step === 'cadastrar_cpe') {
        const info = `rede/cpe · HTTP ${s.httpStatus || '-'} · ${s.durationMs || 0}ms${s.message ? ` · ${s.message}` : ''}`;
        log(s.ok ? 'ok' : 'warn', `${tag} [4/5 Cadastrar CPE] ${info}`, { request: s.request, response: s.response });
      } else if (s.step === 'vincular_cpe') {
        if (s.simulated) {
          log('info', `${tag} [5/5 SIMULAÇÃO] vincular_cpe não executado`, s.request);
        } else {
          const info = `vincular_cpe · HTTP ${s.httpStatus} · ${s.durationMs}ms${s.message ? ` · ${s.message}` : ''}`;
          log(s.ok ? 'ok' : 'warn', `${tag} [5/5 Vínculo CPE] ${info}`, { request: s.request, response: s.response });
        }
      }
    }
    if (r.ok && !r.dryRun) {
      if (r.warning) {
        log('warn', `${tag} ⚠ MAC Layer2 atualizado para ${r.hex}! Vínculo de inventário pendente (a ONT precisa sincronizar na OLT Huawei).`);
      } else {
        log('ok', `${tag} ✔ Migração concluída com sucesso! MAC Layer2 e CPE vinculados no HubSoft.`);
      }
    }
    else if (!r.ok) log('err', `${tag} ✖ ${r.error || 'Falha na migração da CPE.'}`);
  }

  async function migrate(id, serial) {
    try {
      return await api('/api/migrate', {
        id_cliente_servico: Number(id),
        serial,
        dryRun: els.dryrun.checked,
        skipUnlink: els.skipUnlink.checked,
      });
    } catch (e) {
      return { id_cliente_servico: Number(id), ok: false, steps: [], error: `Falha de rede: ${e.message}` };
    }
  }

  function setBusy(b) {
    state.busy = b;
    els.reconnect.disabled = b;
    els.dryrun.disabled = els.skipUnlink.disabled = b;
    els.inBatch.readOnly = b;
    updateSingleBtn();
    renderBatchControls();
  }

  function warnBox(text) {
    const d = el('div', 'alert', text);
    return d;
  }

  // ---------------------------------------------------------------- individual submit
  els.form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (els.execSingle.disabled) return;
    const id = els.inId.value.trim();
    const c = lastConv;

    if (!els.dryrun.checked) {
      const body = el('div');
      body.append(
        document.createTextNode('Serviço '), el('code', null, id), document.createTextNode(': '),
        el('br'),
        el('code', null, c.input), document.createTextNode(' → '), el('code', null, c.hex),
        el('br'), el('br'),
        document.createTextNode(els.skipUnlink.checked
          ? 'Será executado apenas vincular_cpe.'
          : 'Serão executados desvincular_cpe e depois vincular_cpe no HubSoft.'),
        warnBox('Operação real em produção. Se o vínculo falhar após desvincular, o cliente pode ficar sem CPE.')
      );
      if (!(await confirmModal(body))) return;
    }

    setBusy(true);
    els.execSingle.classList.add('loading');
    log('sep', `${els.dryrun.checked ? 'SIMULAÇÃO' : 'EXECUÇÃO'} individual · serviço ${id}`);
    const r = await migrate(id, c.input);
    logResult(r);
    els.execSingle.classList.remove('loading');
    setBusy(false);
    refreshStatus();
    fetchClientPreview(id);
  });

  // ---------------------------------------------------------------- lote
  function parseBatch(text) {
    const rows = [];
    const seen = new Map();
    text.split(/\r?\n/).forEach((line) => {
      const t = line.trim();
      if (!t || t.startsWith('#')) return;
      const parts = t.split(/[;,\t ]+/).filter(Boolean);
      const [id = '', serial = ''] = parts;
      if (rows.length === 0 && !/^\d+$/.test(id) && /id|servi/i.test(id)) return; // cabeçalho
      const conv = convert(serial);
      let error = null;
      if (!isValidId(id)) error = `ID inválido "${id}"`;
      else if (parts.length < 2) error = 'Serial ausente';
      else if (!conv.ok) error = conv.error;
      const row = { n: rows.length + 1, id, serial, hex: conv.ok ? conv.hex : null, error, status: error ? 'invalid' : 'ready', result: null };
      if (!error) {
        if (seen.has(id)) row.dup = seen.get(id);
        else seen.set(id, row.n);
      }
      rows.push(row);
    });
    return rows;
  }

  const BADGE = {
    ready: ['badge-ready', 'Pronto'], invalid: ['badge-err', 'Inválido'], running: ['badge-run', 'Executando…'],
    ok: ['badge-ok', 'Sucesso'], sim: ['badge-warn', 'Simulado'], warn: ['badge-warn', 'OK c/ aviso'], err: ['badge-err', 'Erro'],
    skipped: ['badge-ready', 'Cancelado'],
  };

  function renderBatchRow(row) {
    const tr = el('tr', row.status === 'invalid' ? 'invalid' : row.status === 'running' ? 'running' : '');
    tr.id = `batch-row-${row.n}`;
    const [cls, label] = BADGE[row.status];
    const badge = el('span', `badge ${cls}`, label);
    const tip = row.error || row.result?.error || row.result?.warning || (row.dup ? `ID duplicado (linha ${row.dup})` : '');
    if (tip) badge.title = tip;
    if (row.dup && row.status === 'ready') { badge.className = 'badge badge-warn'; badge.textContent = 'Duplicado'; }
    tr.append(
      el('td', null, row.n), el('td', null, row.id), el('td', null, row.serial),
      el('td', 'hex', row.hex || (row.error ? row.error : '—')), el('td')
    );
    tr.lastChild.append(badge);
    return tr;
  }

  function renderBatch() {
    const rows = state.batch;
    if (!rows.length) {
      const tr = el('tr', 'placeholder');
      const td = el('td', null, 'Cole a lista acima para pré-visualizar.');
      td.colSpan = 5;
      tr.append(td);
      els.batchBody.replaceChildren(tr);
    } else {
      els.batchBody.replaceChildren(...rows.map(renderBatchRow));
    }
    const valid = rows.filter((r) => r.status !== 'invalid').length;
    const invalid = rows.length - valid;
    const dups = rows.filter((r) => r.dup).length;
    els.batchSummary.replaceChildren(
      ...(rows.length
        ? [
            el('span', 'badge badge-ready', `${rows.length} linhas`),
            el('span', 'badge badge-ok', `${valid} válidas`),
            ...(invalid ? [el('span', 'badge badge-err', `${invalid} inválidas (serão ignoradas)`)] : []),
            ...(dups ? [el('span', 'badge badge-warn', `${dups} IDs duplicados`)] : []),
          ]
        : [])
    );
    renderBatchControls();
  }

  function updateBatchRow(row) {
    const old = $(`batch-row-${row.n}`);
    if (old) old.replaceWith(renderBatchRow(row));
  }

  function renderBatchControls() {
    const runnable = state.batch.filter((r) => r.status === 'ready').length;
    els.execBatch.disabled = state.busy || runnable === 0;
    els.stopBatch.hidden = !state.busy || !state.batchRunning;
    els.exportBatch.disabled = state.busy || !state.batch.some((r) => r.result);
  }

  let parseTimer;
  els.inBatch.addEventListener('input', () => {
    clearTimeout(parseTimer);
    parseTimer = setTimeout(() => { state.batch = parseBatch(els.inBatch.value); renderBatch(); }, 150);
  });

  els.execBatch.onclick = async () => {
    // Re-executar: linhas já processadas voltam a "pronto" somente se o usuário recolar/editar.
    const queue = state.batch.filter((r) => r.status === 'ready');
    if (!queue.length) return;
    const sim = els.dryrun.checked;

    if (!sim) {
      const body = el('div');
      body.append(
        document.createTextNode(`Serão processados `), el('code', null, String(queue.length)),
        document.createTextNode(` serviço(s) em produção, sequencialmente.`), el('br'),
        document.createTextNode(els.skipUnlink.checked ? 'Etapa: vincular_cpe.' : 'Etapas: desvincular_cpe → vincular_cpe.'),
        warnBox('Recomendado rodar primeiro em modo Simulação. Você pode parar o lote a qualquer momento (a linha em andamento será concluída).')
      );
      if (!(await confirmModal(body))) return;
    }

    state.stop = false;
    state.batchRunning = true;
    setBusy(true);
    els.progress.hidden = false;
    log('sep', `${sim ? 'SIMULAÇÃO' : 'EXECUÇÃO'} em lote · ${queue.length} serviço(s)`);

    let done = 0, ok = 0, fail = 0;
    const setProgress = () => {
      els.progressBar.style.width = `${(done / queue.length) * 100}%`;
      els.progressText.textContent = `${done}/${queue.length} · ${ok} ok · ${fail} erro(s)`;
    };
    setProgress();

    for (const row of queue) {
      if (state.stop) { row.status = 'skipped'; updateBatchRow(row); continue; }
      row.status = 'running';
      updateBatchRow(row);
      $(`batch-row-${row.n}`)?.scrollIntoView({ block: 'nearest' });

      const r = await migrate(row.id, row.serial);
      row.result = r;
      logResult(r, `#${row.n} `);
      if (r.ok) { ok++; row.status = r.dryRun ? 'sim' : r.warning ? 'warn' : 'ok'; }
      else { fail++; row.status = 'err'; }
      done++;
      updateBatchRow(row);
      setProgress();
    }

    if (state.stop) log('warn', `Lote interrompido pelo operador. ${done}/${queue.length} processados.`);
    log(fail ? 'warn' : 'ok', `Lote finalizado: ${ok} sucesso(s), ${fail} erro(s).`);
    state.batchRunning = false;
    setBusy(false);
    refreshStatus();
  };

  els.stopBatch.onclick = () => {
    state.stop = true;
    els.stopBatch.disabled = true;
    toast('Parando após a linha atual…');
    setTimeout(() => (els.stopBatch.disabled = false), 500);
  };

  els.exportBatch.onclick = () => {
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const lines = [['linha', 'id_cliente_servico', 'serial_antigo', 'phy_addr_hex', 'status', 'mensagem'].join(';')];
    for (const r of state.batch) {
      lines.push([r.n, r.id, r.serial, r.hex, BADGE[r.status][1], r.error || r.result?.error || r.result?.warning || ''].map(esc).join(';'));
    }
    download(`cpe-migrator-lote-${Date.now()}.csv`, '\uFEFF' + lines.join('\r\n'), 'text/csv;charset=utf-8');
  };

  // ---------------------------------------------------------------- init
  syncModeUI();
  renderConverter();
  refreshStatus();
  setInterval(refreshStatus, 30000);
  log('info', 'Interface carregada. Dica: ative "Simulação" para validar antes de executar em produção.');
})();
