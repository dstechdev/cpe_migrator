const crypto = require("crypto");
'use strict';

require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const { convert } = require('./public/converter');

function getConfig() {
  // Recarrega o .env para pegar alterações sem precisar reiniciar o servidor
  require('dotenv').config({ override: true });
  return {
    host: (process.env.HUBSOFT_HOST || 'https://api.dstech.hubsoft.com.br').replace(/\/+$/, ''),
    clientId: process.env.HUBSOFT_CLIENT_ID,
    clientSecret: process.env.HUBSOFT_CLIENT_SECRET,
    username: process.env.HUBSOFT_USERNAME,
    password: process.env.HUBSOFT_PASSWORD,
    port: Number(process.env.PORT) || 3000,
    bearerToken: process.env.HUBSOFT_BEARER_TOKEN || null,
    timeoutMs: 30000,
  };
}

// ---------------------------------------------------------------------------
// Auditoria (JSON Lines em logs/audit.log)
// ---------------------------------------------------------------------------
const LOG_DIR = path.join(__dirname, 'logs');
fs.mkdirSync(LOG_DIR, { recursive: true });
const AUDIT_FILE = path.join(LOG_DIR, 'audit.log');

function audit(entry) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
  fs.appendFile(AUDIT_FILE, line, (err) => err && console.error('[AUDIT] Falha ao gravar log:', err.message));
}

// ---------------------------------------------------------------------------
// OAuth2 – token em cache com renovação automática
// ---------------------------------------------------------------------------
const tokenState = {
  accessToken: null,
  expiresAt: 0, // epoch ms
  obtainedAt: 0,
  lastError: null,
  inflight: null, // Promise compartilhada para evitar logins simultâneos
};

const TOKEN_SAFETY_MS = 60_000;

function tokenValid() {
  return tokenState.accessToken && Date.now() < tokenState.expiresAt - TOKEN_SAFETY_MS;
}

async function readBody(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function generateTOTP(base32Secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of (base32Secret || "").replace(/=+$/, "").toUpperCase()) {
    const val = alphabet.indexOf(ch);
    if (val >= 0) bits += val.toString(2).padStart(5, "0");
  }
  const key = Buffer.alloc(Math.floor(bits.length / 8));
  for (let i = 0; i < key.length; i++) {
    key[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  const counter = Math.floor(Date.now() / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  return ((hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
}

async function fetchNewToken() {
  const host = (process.env.HUBSOFT_HOST || "https://api.dstech.hubsoft.com.br").replace(/\/+$/, "");
  const username = process.env.HUBSOFT_USERNAME;
  const password = process.env.HUBSOFT_PASSWORD;
  const totpSecret = process.env.HUBSOFT_TOTP_SECRET || "QJIWWJGLYKDX7NMR";

  if (!host || !username || !password) {
    throw new Error("Credenciais HubSoft incompletas no .env");
  }

  const res = await fetch(`${host}/api/v2/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      username,
      password,
      revenda: null,
      one_time_password: generateTOTP(totpSecret),
      origem: "web",
      two_factor_required: true,
      two_factor_type: "app",
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.status !== "success" || !data.login || !data.login.access_token) {
    throw new Error(`Falha no login HubSoft (${res.status}): ${data.msg || JSON.stringify(data)}`);
  }

  const expiresInSec = Number(data.login.expires_in) || 432000;
  tokenState = {
    accessToken: data.login.access_token,
    expiresAt: Date.now() + expiresInSec * 1000,
    obtainedAt: new Date().toISOString(),
    lastError: null,
  };
  return tokenState.accessToken;
}

async function getToken({ force = false } = {}) {
  const cfg = getConfig();
  if (cfg.bearerToken) {
    tokenState.accessToken = cfg.bearerToken;
    tokenState.expiresAt = Date.now() + 86400_000 * 30;
    return cfg.bearerToken;
  }
  if (!force && tokenValid()) return tokenState.accessToken;
  if (!tokenState.inflight) {
    tokenState.inflight = fetchNewToken()
      .catch((err) => {
        tokenState.accessToken = null;
        tokenState.expiresAt = 0;
        tokenState.lastError = err.message;
        audit({ type: 'auth', ok: false, error: err.message });
        throw err;
      })
      .finally(() => {
        tokenState.inflight = null;
      });
  }
  return tokenState.inflight;
}

// ---------------------------------------------------------------------------
// Chamadas à API HubSoft
// ---------------------------------------------------------------------------
/**
 * POST JSON autenticado. Em caso de 401 renova o token e tenta 1x novamente.
 * Considera sucesso: HTTP 2xx e corpo sem `status: "error"`.
 */
async function hubsoftPost(endpoint, payload) {
  const started = Date.now();
  const cfg = getConfig();
  let attempt = 0;
  let res, data;

  while (attempt < 2) {
    const token = await getToken({ force: attempt > 0 });
    res = await fetch(`${cfg.host}${endpoint}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    data = await readBody(res);
    if (res.status !== 401) break;
    attempt++;
  }

  const bodyStatus = data && typeof data === 'object' ? String(data.status || '').toLowerCase() : '';
  const ok = res.ok && bodyStatus !== 'error';
  return {
    ok,
    httpStatus: res.status,
    durationMs: Date.now() - started,
    request: { endpoint, payload },
    response: data,
    message: (data && typeof data === 'object' && (data.msg || data.message)) || null,
  };
}

/**
 * GET autenticado. Em caso de 401 renova o token e tenta 1x novamente.
 */
async function hubsoftGet(endpoint) {
  const started = Date.now();
  const cfg = getConfig();
  let attempt = 0;
  let res, data;

  while (attempt < 2) {
    const token = await getToken({ force: attempt > 0 });
    res = await fetch(`${cfg.host}${endpoint}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(cfg.timeoutMs),
    });
    data = await readBody(res);
    if (res.status !== 401) break;
    attempt++;
  }

  const bodyStatus = data && typeof data === 'object' ? String(data.status || '').toLowerCase() : '';
  const ok = res.ok && bodyStatus !== 'error';
  return {
    ok,
    httpStatus: res.status,
    durationMs: Date.now() - started,
    request: { endpoint, method: 'GET' },
    response: data,
    message: (data && typeof data === 'object' && (data.msg || data.message)) || null,
  };
}

// ---------------------------------------------------------------------------
// Express
// ---------------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/status', (_req, res) => {
  const cfg = getConfig();
  res.json({
    connected: Boolean(tokenValid()),
    host: cfg.host,
    username: cfg.username,
    obtainedAt: tokenState.obtainedAt ? new Date(tokenState.obtainedAt).toISOString() : null,
    expiresAt: tokenState.expiresAt ? new Date(tokenState.expiresAt).toISOString() : null,
    lastError: tokenState.lastError,
  });
});

app.post('/api/auth/connect', async (req, res) => {
  try {
    await getToken({ force: Boolean(req.body && req.body.force) });
    res.json({ ok: true, expiresAt: new Date(tokenState.expiresAt).toISOString() });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message });
  }
});

app.post('/api/convert', (req, res) => {
  res.json(convert(req.body && req.body.serial));
});

/**
 * Consulta prévia dos dados de autenticação e conexão do cliente no HubSoft
 */
app.get('/api/client/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, error: 'id_cliente_servico inválido.' });
  }

  try {
    const authGet = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${id}`);
    if (!authGet.ok || !authGet.response || !authGet.response.cliente_servico_autenticacao) {
      return res.status(authGet.httpStatus || 404).json({
        ok: false,
        error: authGet.message || 'Serviço do cliente não encontrado no HubSoft.',
      });
    }

    const a = authGet.response.cliente_servico_autenticacao;
    const cpesVinculadas = Array.isArray(a.cpes) ? a.cpes.map((c) => c.phy_addr).filter(Boolean) : [];
    res.json({
      ok: true,
      id_cliente_servico: id,
      login: a.login,
      mac_addr: a.mac_addr,
      phy_addr: a.phy_addr,
      cpes_vinculadas: cpesVinculadas,
      id_interface_conexao: a.id_interface_conexao || a.interface_conexao?.id_interface_conexao,
      interface_nome: a.interface_conexao?.nome || 'Não definida',
      id_equipamento_conexao: a.equipamento_conexao?.id_equipamento_conexao,
      olt_nome: a.equipamento_conexao?.nome || 'Não definida',
      olt_ip: a.equipamento_conexao?.ip || a.equipamento_conexao?.ipv4,
      cliente_servico: a.cliente_servico ? {
        id_cliente: a.cliente_servico.id_cliente,
        display: a.cliente_servico.display,
        servico: a.cliente_servico.servico?.descricao,
      } : null,
    });
  } catch (err) {
    res.status(502).json({ ok: false, error: err.message });
  }
});

app.post('/api/migrate', async (req, res) => {
  const { id_cliente_servico, serial, dryRun = false, skipUnlink = false } = req.body || {};
  const id = Number(id_cliente_servico);
  const result = { id_cliente_servico: id, serial, dryRun, steps: [], ok: false };

  if (!Number.isInteger(id) || id <= 0) {
    result.error = 'id_cliente_servico inválido (deve ser inteiro positivo).';
    audit({ type: 'migrate', ...result });
    return res.status(400).json(result);
  }

  const conv = convert(serial);
  result.steps.push({ step: 'convert', ok: conv.ok, detail: conv });
  if (!conv.ok) {
    result.error = conv.error;
    audit({ type: 'migrate', ...result });
    return res.status(400).json(result);
  }
  result.hex = conv.hex;

  if (dryRun) {
    result.ok = true;
    result.steps.push({
      step: 'consultar_autenticacao',
      ok: true,
      simulated: true,
      detail: 'Simulação: captura de OLT e Interface de Conexão prévias',
    });
    result.steps.push({ step: 'desvincular_cpe', ok: true, simulated: true, request: { id_cliente_servico: id } });
    result.steps.push({
      step: 'configurar_autenticacao',
      ok: true,
      simulated: true,
      request: { id_cliente_servico: id, phy_addr: conv.hex },
    });
    result.steps.push({
      step: 'vincular_cpe',
      ok: true,
      simulated: true,
      request: { id_cliente_servico: id },
    });
    audit({ type: 'migrate', ...result });
    return res.json(result);
  }

  try {
    await getToken();
    result.steps.push({ step: 'auth', ok: true });
  } catch (err) {
    result.steps.push({ step: 'auth', ok: false, error: err.message });
    result.error = 'Falha na autenticação OAuth2.';
    audit({ type: 'migrate', ...result });
    return res.status(502).json(result);
  }

  try {
    // 1. Consulta e preserva a interface de conexão e equipamento de conexão atuais
    let currentInterfaceId = null;
    let currentOltName = null;
    let currentInterfaceName = null;
    let currentPhyAddr = null;
    let authRaw = null;

    try {
      const getAuth = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${id}`);
      if (getAuth.ok && getAuth.response && getAuth.response.cliente_servico_autenticacao) {
        const authObj = getAuth.response.cliente_servico_autenticacao;
        authRaw = authObj;
        currentInterfaceId = authObj.id_interface_conexao || authObj.interface_conexao?.id_interface_conexao || null;
        currentOltName = authObj.equipamento_conexao?.nome || null;
        currentInterfaceName = authObj.interface_conexao?.nome || null;
        currentPhyAddr = authObj.phy_addr || null;
        result.info = {
          olt: currentOltName,
          interface: currentInterfaceName,
          id_interface_conexao: currentInterfaceId,
          oldPhyAddr: currentPhyAddr,
        };
        result.steps.push({
          step: 'consultar_autenticacao',
          ok: true,
          detail: `OLT: ${currentOltName || 'N/A'} | Interface: ${currentInterfaceName || 'N/A'} (ID: ${currentInterfaceId})`,
        });
      } else {
        result.steps.push({
          step: 'consultar_autenticacao',
          ok: false,
          warning: 'Não foi possível ler autenticação prévia; prosseguindo sem id_interface_conexao prévio.',
          message: getAuth.message,
        });
      }
    } catch (err) {
      result.steps.push({
        step: 'consultar_autenticacao',
        ok: false,
        warning: `Erro na consulta prévia: ${err.message}`,
      });
    }

    // 2. Desvincular CPE antiga (sempre que houver CPE antiga diferente do novo HEX ou quando !skipUnlink)
    const linkedCpes = Array.isArray(authRaw?.cpes) ? authRaw.cpes : [];
    const hasOldCpe = linkedCpes.some((c) => String(c.phy_addr || '').toUpperCase() !== conv.hex.toUpperCase());
    const alreadyHasNewCpeOnly =
      linkedCpes.length === 1 && String(linkedCpes[0].phy_addr || '').toUpperCase() === conv.hex.toUpperCase();

    if ((!skipUnlink || hasOldCpe) && !alreadyHasNewCpeOnly) {
      const unlink = await hubsoftPost('/api/v1/integracao/cliente/desvincular_cpe', { id_cliente_servico: id });
      const noCpeLinked = unlink.message && unlink.message.includes('não possui CPE vinculada');
      result.steps.push({
        step: 'desvincular_cpe',
        ...unlink,
        ok: unlink.ok || Boolean(noCpeLinked),
      });
    }

    // 3. Configurar autenticação (atualiza o MAC Layer 2 no HubSoft via API de integração)
    const authPayload = {
      id_cliente_servico: id,
      phy_addr: conv.hex,
    };

    const cfgAuth = await hubsoftPost('/api/v1/integracao/cliente/configurar_autenticacao', authPayload);
    const alreadyConfigured = cfgAuth.message && (
      cfgAuth.message.includes('já encontra-se com o phy_addr') ||
      cfgAuth.message.includes('não é necessário a alteração')
    );
    const authOk = cfgAuth.ok || alreadyConfigured;
    result.steps.push({ step: 'configurar_autenticacao', ...cfgAuth, ok: authOk });

    if (!authOk) {
      result.ok = false;
      result.error = `Falha ao configurar autenticação: ${cfgAuth.message || 'Erro desconhecido'}`;
      audit({ type: 'migrate', ...result });
      return res.status(502).json(result);
    }

    // 4. Cadastrar e vincular CPE na tabela de CPEs Vinculadas ao Assinante (/api/v1/rede/cpe)
    if (!alreadyHasNewCpeOnly) {
      try {
        // Reconsulta autenticação pós-desvínculo para garantir cpes: [] limpo e evitar erro de porta ocupada
        const freshAuthGet = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${id}`);
        const freshAuth = freshAuthGet.response?.cliente_servico_autenticacao || authRaw;
        if (freshAuth && freshAuth.equipamento_conexao && freshAuth.interface_conexao) {
          const cpePayload = {
            cliente_servico_autenticacao: freshAuth,
            equipamento: freshAuth.equipamento_conexao,
            interface_conexao: freshAuth.interface_conexao,
            phy_addr: conv.hex,
          };
          const cadCpe = await hubsoftPost('/api/v1/rede/cpe', cpePayload);
          result.steps.push({
            step: 'cadastrar_cpe',
            ...cadCpe,
            request: {
              endpoint: '/api/v1/rede/cpe',
              payload: {
                id_cliente_servico: id,
                id_equipamento_conexao: freshAuth.equipamento_conexao.id_equipamento_conexao,
                id_interface_conexao: freshAuth.interface_conexao.id_interface_conexao,
                phy_addr: conv.hex,
              },
            },
          });
        }
      } catch (err) {
        result.steps.push({ step: 'cadastrar_cpe', ok: false, message: err.message });
      }
    }

    // 5. Confirmar vínculo de CPE na autenticação (/api/v1/integracao/cliente/vincular_cpe)
    try {
      const link = await hubsoftPost('/api/v1/integracao/cliente/vincular_cpe', {
        id_cliente_servico: id,
      });
      result.steps.push({ step: 'vincular_cpe', ...link });
      if (!link.ok) {
        result.warning = `Autenticação alterada com sucesso! Vínculo de inventário: ${link.message || 'CPE não pré-cadastrada no estoque'}`;
      }
    } catch {
      // Se a rota de vincular falhar, a autenticação MAC Layer2 já está atualizada
    }

    result.ok = true;
  } catch (err) {
    result.error = `Erro de comunicação com HubSoft: ${err.message}`;
  }

  audit({ type: 'migrate', ...result });
  res.status(result.ok ? 200 : 502).json(result);
});

const initialCfg = getConfig();
app.listen(initialCfg.port, () => {
  console.log(`\n  HubSoft CPE Migrator rodando em http://localhost:${initialCfg.port}`);
  console.log(`  API alvo: ${initialCfg.host}`);
  console.log(`  Log de auditoria: ${AUDIT_FILE}\n`);
  getToken().then(
    () => console.log('  [OAuth] Token obtido com sucesso.'),
    (err) => console.warn(`  [OAuth] Falha inicial: ${err.message}`)
  );
});
