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
let tokenState = {
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

const TOKEN_CACHE_FILE = path.join(__dirname, "logs", "token-cache.json");

function loadCachedToken() {
  try {
    if (fs.existsSync(TOKEN_CACHE_FILE)) {
      const data = JSON.parse(fs.readFileSync(TOKEN_CACHE_FILE, "utf8"));
      if (data && data.accessToken && data.expiresAt && Date.now() < data.expiresAt - 300000) {
        return data;
      }
    }
  } catch (_) {}
  return null;
}

function saveCachedToken(state) {
  try {
    fs.mkdirSync(path.dirname(TOKEN_CACHE_FILE), { recursive: true });
    fs.writeFileSync(TOKEN_CACHE_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch (_) {}
}

async function fetchNewToken() {
  const cached = loadCachedToken();
  if (cached) {
    tokenState = cached;
    return tokenState.accessToken;
  }

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
  saveCachedToken(tokenState);
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

// === APP_AUTH_START ===
const APP_SESSION_SECRET = process.env.APP_SESSION_SECRET || crypto.createHash("sha256").update((process.env.HUBSOFT_PASSWORD || "dstech") + "_cpe_salt").digest("hex");
const loginAttempts = new Map();

function createSessionToken(user) {
  const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
  const payload = Buffer.from(JSON.stringify({ u: user, exp })).toString("base64url");
  const sig = crypto.createHmac("sha256", APP_SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + sig;
}

function verifySessionToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const expected = crypto.createHmac("sha256", APP_SESSION_SECRET).update(payload).digest("base64url");
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!data.exp || Date.now() > data.exp) return null;
    return data.u;
  } catch (_) { return null; }
}

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(";").forEach((c) => {
      const p = c.split("=");
      const k = p.shift().trim();
      if (k) list[k] = decodeURIComponent(p.join("="));
    });
  }
  return list;
}

app.get("/login", (req, res) => {
  if (verifySessionToken(parseCookies(req).cpe_session)) return res.redirect("/");
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/styles.css", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "styles.css"));
});

app.post("/api/app-login", (req, res) => {
  const ip = req.ip || "unknown";
  const rec = loginAttempts.get(ip) || { count: 0, lockUntil: 0 };
  if (Date.now() < rec.lockUntil) {
    return res.status(429).json({ ok: false, error: "Muitas tentativas. Aguarde alguns minutos." });
  }
  const { username, password } = req.body || {};
  const validUser = process.env.APP_ADMIN_USER || "admin";
  const validPass = process.env.APP_ADMIN_PASS || "Dstech677!";
  if (username === validUser && password === validPass) {
    loginAttempts.delete(ip);
    const token = createSessionToken(username);
    res.setHeader("Set-Cookie", "cpe_session=" + token + "; HttpOnly; Path=/; Max-Age=604800; SameSite=Lax");
    return res.json({ ok: true, user: username });
  }
  rec.count += 1;
  if (rec.count >= 5) { rec.lockUntil = Date.now() + 5 * 60 * 1000; rec.count = 0; }
  loginAttempts.set(ip, rec);
  return res.status(401).json({ ok: false, error: "Usuario ou senha incorretos." });
});

app.post("/api/app-logout", (req, res) => {
  res.setHeader("Set-Cookie", "cpe_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax");
  res.json({ ok: true });
});

const N8N_BRIDGE_API_KEY = process.env.N8N_BRIDGE_API_KEY || "dstech_n8n_secret_2026";

app.get("/api/n8n-token-hubsoft", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"] || "";
    const bearerKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    const providedKey = req.headers["x-api-key"] || bearerKey || req.query.api_key;

    if (!providedKey || providedKey !== N8N_BRIDGE_API_KEY) {
      return res.status(401).json({
        status: "error",
        message: "Nao autorizado. Informe um x-api-key valido.",
      });
    }

    const forceRefresh = req.query.force === "true" || req.query.force === "1";
    const accessToken = await getToken({ force: forceRefresh });
    const remainingSeconds = tokenState.expiresAt
      ? Math.max(0, Math.floor((tokenState.expiresAt - Date.now()) / 1000))
      : null;

    return res.status(200).json({
      status: "success",
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: remainingSeconds,
      obtained_at: tokenState.obtainedAt,
    });
  } catch (error) {
    return res.status(502).json({
      status: "error",
      message: error.message || "Falha ao obter token HubSoft com 2FA",
    });
  }
});

app.use((req, res, next) => {
  const user = verifySessionToken(parseCookies(req).cpe_session);
  if (user) { req.appUser = user; return next(); }
  if (req.path.startsWith("/api/")) return res.status(401).json({ ok: false, error: "Nao autenticado." });
  return res.redirect("/login");
});
// === APP_AUTH_END ===

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
 * Resolve automaticamente se o ID informado é id_cliente_servico, id_cliente_servico_autenticacao, id_cliente (da URL do navegador) ou codigo_cliente.
 * Nota importante do HubSoft: a rota GET /api/v1/cliente/servico/autenticacao/{id} recebe id_cliente_servico_autenticacao (que em serviços recentes como 81966 difere do id_cliente_servico!).
 */
async function resolveServiceAuth(inputId, conv = null) {
  const getAuth = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${inputId}`);
  const authObj = getAuth.ok ? getAuth.response?.cliente_servico_autenticacao : null;

  const matchesSerial = (phy) => {
    if (!conv || !phy) return false;
    const p = String(phy).trim().toUpperCase();
    const rawStr = String(conv.input || conv.raw || '').replace(/[\s:\-]/g, '').toUpperCase();
    const hexStr = String(conv.hex || '').trim().toUpperCase();
    const vendorSuffix = String((conv.vendor || '') + (conv.suffix || '')).trim().toUpperCase();
    return p === rawStr || p === hexStr || (vendorSuffix.length === 12 && p === vendorSuffix);
  };

  const isCancelled = (a) => {
    const d = String(a?.cliente_servico?.display || '').toUpperCase();
    return d.includes('(INATIVO)') || d.includes('CANCELADO');
  };

  // Só usa direto se o registro de autenticação realmente pertencer ao id_cliente_servico == inputId e o serial bater
  if (
    authObj &&
    Number(authObj.id_cliente_servico) === Number(inputId) &&
    !isCancelled(authObj) &&
    (!conv || matchesSerial(authObj.phy_addr))
  ) {
    return {
      resolvedId: Number(authObj.id_cliente_servico),
      authId: Number(authObj.id_cliente_servico_autenticacao || inputId),
      authObj,
      resolvedFrom: null,
    };
  }

  // Busca primeiro por id_cliente_servico (para descobrir o id_cliente_servico_autenticacao real quando divergem, ex: 81966 -> auth 81867),
  // e depois por id_cliente (da URL /cliente/editar/{id_cliente}/servico) ou codigo_cliente
  for (const tipo of ['id_cliente_servico', 'id_cliente', 'codigo_cliente']) {
    const search = await hubsoftGet(`/api/v1/integracao/cliente?busca=${tipo}&termo_busca=${inputId}`);
    const clientes = search.response?.clientes || [];
    for (const cli of clientes) {
      const servicos = cli.servicos || [];
      // 1º: Prioriza serviço cujo phy_addr bate exatamente com o serial informado (raw, hex ou vendor+suffix)
      if (conv) {
        for (const s of servicos) {
          if (matchesSerial(s.phy_addr) || (tipo === 'id_cliente_servico' && Number(s.id_cliente_servico) === Number(inputId))) {
            const targetAuthId = Number(s.id_cliente_servico_autenticacao || s.id_cliente_servico);
            const subAuth = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${targetAuthId}`);
            if (subAuth.ok && subAuth.response?.cliente_servico_autenticacao) {
              const aObj = subAuth.response.cliente_servico_autenticacao;
              if (!conv || matchesSerial(aObj.phy_addr) || matchesSerial(s.phy_addr)) {
                return {
                  resolvedId: Number(s.id_cliente_servico),
                  authId: targetAuthId,
                  authObj: aObj,
                  resolvedFrom:
                    tipo === 'id_cliente_servico' && Number(s.id_cliente_servico) === Number(inputId)
                      ? null
                      : `${tipo}:${inputId} -> id_cliente_servico:${s.id_cliente_servico} (${cli.nome_razaosocial})`,
                };
              }
            }
          }
        }
      }
      // 2º: Se for apenas consulta sem serial, procura o serviço correspondente ou ativo do cliente
      const candidates =
        tipo === 'id_cliente_servico'
          ? servicos.filter((s) => Number(s.id_cliente_servico) === Number(inputId))
          : servicos.filter((s) => !String(s.status || '').toLowerCase().includes('cancelado'));
      if (candidates.length === 1 && !conv) {
        const s = candidates[0];
        const targetAuthId = Number(s.id_cliente_servico_autenticacao || s.id_cliente_servico);
        const subAuth = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${targetAuthId}`);
        if (subAuth.ok && subAuth.response?.cliente_servico_autenticacao) {
          return {
            resolvedId: Number(s.id_cliente_servico),
            authId: targetAuthId,
            authObj: subAuth.response.cliente_servico_autenticacao,
            resolvedFrom:
              tipo === 'id_cliente_servico'
                ? null
                : `${tipo}:${inputId} -> id_cliente_servico:${s.id_cliente_servico} (${cli.nome_razaosocial})`,
          };
        }
      }
    }
  }

  return {
    resolvedId: inputId,
    authId: Number(authObj?.id_cliente_servico_autenticacao || inputId),
    authObj,
    resolvedFrom: null,
    rawResponse: getAuth,
  };
}

/**
 * Consulta prévia dos dados de autenticação e conexão do cliente no HubSoft
 */
app.get('/api/client/:id', async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, error: 'id_cliente_servico inválido.' });
  }

  try {
    const resolved = await resolveServiceAuth(id, null);
    if (!resolved.authObj) {
      return res.status(resolved.rawResponse?.httpStatus || 404).json({
        ok: false,
        error: resolved.rawResponse?.message || 'Serviço do cliente não encontrado no HubSoft.',
      });
    }

    const a = resolved.authObj;
    const cpesVinculadas = Array.isArray(a.cpes) ? a.cpes.map((c) => c.phy_addr).filter(Boolean) : [];
    res.json({
      ok: true,
      id_cliente_servico: resolved.resolvedId,
      input_id: id,
      resolved_from: resolved.resolvedFrom,
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
    // 1. Consulta e preserva a interface de conexão e equipamento de conexão atuais (auto-resolvendo id_cliente -> id_cliente_servico se necessário)
    let currentInterfaceId = null;
    let currentOltName = null;
    let currentInterfaceName = null;
    let currentPhyAddr = null;
    let authRaw = null;

    const resolved = await resolveServiceAuth(id, conv);
    const targetId = resolved.resolvedId;
    result.id_cliente_servico = targetId;
    if (resolved.resolvedFrom) {
      result.input_id = id;
      result.resolved_from = resolved.resolvedFrom;
      result.steps.push({
        step: 'resolver_id_servico',
        ok: true,
        detail: `ID informado (${id}) era id_cliente/código; convertido automaticamente para id_cliente_servico ${targetId} -> ${resolved.resolvedFrom}`,
      });
    }

    if (resolved.authObj) {
      const authObj = resolved.authObj;
      authRaw = authObj;
      currentInterfaceId = authObj.id_interface_conexao || authObj.interface_conexao?.id_interface_conexao || null;
      currentOltName = authObj.equipamento_conexao?.nome || null;
      currentInterfaceName = authObj.interface_conexao?.nome || null;
      currentPhyAddr = authObj.phy_addr || null;
      const clienteDisplay = authObj.cliente_servico?.display || 'N/A';

      // Trava de segurança anti-sobrescrita: se o serviço possui outro serial diferente do informado (nem input, nem hex, nem vendor+suffix), aborta!
      const cleanOld = String(currentPhyAddr || '').trim().toUpperCase();
      const rawStr = String(conv.input || conv.raw || '').replace(/[\s:\-]/g, '').toUpperCase();
      const hexStr = String(conv.hex || '').trim().toUpperCase();
      const vendorSuffix = String((conv.vendor || '') + (conv.suffix || '')).trim().toUpperCase();
      if (cleanOld && cleanOld !== rawStr && cleanOld !== hexStr && cleanOld !== vendorSuffix) {
        result.error = `Trava de segurança: O serviço ${targetId} (${clienteDisplay}) está com o serial "${currentPhyAddr}", que não corresponde ao serial informado ("${serial}"). Verifique se o ID pertence a este cliente.`;
        result.steps.push({
          step: 'consultar_autenticacao',
          ok: false,
          error: result.error,
        });
        audit({ type: 'migrate', ...result });
        return res.status(422).json(result);
      }

      result.info = {
        cliente: clienteDisplay,
        olt: currentOltName,
        interface: currentInterfaceName,
        id_interface_conexao: currentInterfaceId,
        oldPhyAddr: currentPhyAddr,
      };
      result.steps.push({
        step: 'consultar_autenticacao',
        ok: true,
        detail: `Cliente: ${clienteDisplay} | OLT: ${currentOltName || 'N/A'} | Interface: ${currentInterfaceName || 'N/A'} (ID: ${currentInterfaceId})`,
      });
    } else {
      result.steps.push({
        step: 'consultar_autenticacao',
        ok: false,
        warning: 'Não foi possível ler autenticação prévia; prosseguindo sem id_interface_conexao prévio.',
        message: resolved.rawResponse?.message,
      });
    }

    // 2. Desvincular CPE antiga (sempre que houver CPE antiga diferente do novo HEX ou quando !skipUnlink)
    const linkedCpes = Array.isArray(authRaw?.cpes) ? authRaw.cpes : [];
    const hasOldCpe = linkedCpes.some((c) => String(c.phy_addr || '').toUpperCase() !== conv.hex.toUpperCase());
    const alreadyHasNewCpeOnly =
      linkedCpes.length === 1 && String(linkedCpes[0].phy_addr || '').toUpperCase() === conv.hex.toUpperCase();

    if ((!skipUnlink || hasOldCpe) && !alreadyHasNewCpeOnly) {
      const unlink = await hubsoftPost('/api/v1/integracao/cliente/desvincular_cpe', { id_cliente_servico: targetId });
      const noCpeLinked = unlink.message && unlink.message.includes('não possui CPE vinculada');
      result.steps.push({
        step: 'desvincular_cpe',
        ...unlink,
        ok: unlink.ok || Boolean(noCpeLinked),
      });
    }

    // 3. Configurar autenticação (atualiza o MAC Layer 2 no HubSoft via API de integração)
    const authPayload = {
      id_cliente_servico: targetId,
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
        // Reconsulta autenticação pós-desvínculo usando o id_cliente_servico_autenticacao real (authId)
        const targetAuthId = resolved.authId || targetId;
        const freshAuthGet = await hubsoftGet(`/api/v1/cliente/servico/autenticacao/${targetAuthId}`);
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
                id_cliente_servico: targetId,
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
        id_cliente_servico: targetId,
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
