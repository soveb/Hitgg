// ============================================================================
// VTX DASHBOARD — arquivo único pra rodar na Vercel (serverless function).
// Coloque este arquivo em:  api/dashboard.js
// E o vercel.json (fornecido junto) na raiz do projeto.
//
// Variáveis de ambiente que você precisa configurar na Vercel:
//   OAUTH2_CLIENT_ID       -> mesmo Client ID do bot no Discord Developer Portal
//   OAUTH2_CLIENT_SECRET   -> mesmo Client Secret
//   DASHBOARD_REDIRECT_URI -> https://SEU-PROJETO.vercel.app/dashboard/callback
//   SESSION_SECRET         -> qualquer texto aleatório longo (você escolhe)
//   BOT_API_BASE_URL       -> URL pública do bot (ex: https://xxxx.trycloudflare.com)
//   DASHBOARD_API_SECRET   -> A MESMA senha que você configurou no bot (.env DASHBOARD_API_SECRET)
//
// Não esqueça de registrar o DASHBOARD_REDIRECT_URI em "Redirects" na aba
// OAuth2 do app no Discord Developer Portal.
// ============================================================================

import crypto from 'crypto';

const {
  OAUTH2_CLIENT_ID,
  OAUTH2_CLIENT_SECRET,
  DASHBOARD_REDIRECT_URI,
  SESSION_SECRET,
  BOT_API_BASE_URL,
  DASHBOARD_API_SECRET,
} = process.env;

// ── Assinatura de cookie (sessão fica inteira dentro do cookie, sem memória) ──
function sign(value) {
  const h = crypto.createHmac('sha256', SESSION_SECRET || 'troque-isso').update(value).digest('hex');
  return `${value}.${h}`;
}
function unsign(signed) {
  if (!signed) return null;
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET || 'troque-isso').update(value).digest('hex');
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length) return null;
  return crypto.timingSafeEqual(a, b) ? value : null;
}
function parseCookies(req) {
  const raw = req.headers.cookie;
  const out = {};
  if (!raw) return out;
  raw.split(';').forEach(p => {
    const idx = p.indexOf('=');
    if (idx === -1) return;
    out[p.slice(0, idx).trim()] = decodeURIComponent(p.slice(idx + 1).trim());
  });
  return out;
}
function getSessionUser(req) {
  const raw = unsign(parseCookies(req).vtx_sess);
  if (!raw) return null;
  try {
    const data = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}
function setSessionCookie(res, data) {
  const payload = Buffer.from(JSON.stringify(data)).toString('base64');
  const signed = sign(payload);
  res.setHeader('Set-Cookie', `vtx_sess=${encodeURIComponent(signed)}; HttpOnly; Path=/; Max-Age=${12 * 60 * 60}; SameSite=Lax; Secure`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `vtx_sess=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`);
}

// ── Chamada pra API interna do bot ──────────────────────────────────────────
async function botApi(path, { method = 'GET', body } = {}) {
  const r = await fetch(`${BOT_API_BASE_URL}/api/internal${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', 'x-dashboard-secret': DASHBOARD_API_SECRET },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await r.json().catch(() => ({}));
  return { status: r.status, data };
}

function sendJson(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(obj));
}
function sendHtml(res, status, html) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(html);
}

// ── OAuth "state" (CSRF) — assinado, sem precisar guardar em memória ────────
function newState() {
  const raw = crypto.randomBytes(16).toString('hex') + ':' + (Date.now() + 10 * 60 * 1000);
  return sign(Buffer.from(raw).toString('base64'));
}
function validState(state) {
  const raw = unsign(state);
  if (!raw) return false;
  const [, expStr] = Buffer.from(raw, 'base64').toString('utf8').split(':');
  return Number(expStr) > Date.now();
}

// ── HTML da aplicação (login + SPA), CSS e JS embutidos ─────────────────────
function pageShell(bodyHtml) {
  return `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VTX Dashboard</title>
<style>
* { box-sizing: border-box; }
body { margin:0; background:#0d0d12; color:#e9e9f0; font-family:'Segoe UI',Roboto,Arial,sans-serif; min-height:100vh; }
.loading { display:flex; align-items:center; justify-content:center; height:100vh; color:#888; }
.login-screen { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; text-align:center; gap:16px; padding:20px; }
.login-screen h1 { font-size:28px; margin:0; }
.login-screen p { color:#9a9ab0; max-width:380px; margin:0; }
.btn-discord { background:#5865f2; color:#fff; border:none; padding:12px 24px; border-radius:8px; font-size:15px; font-weight:600; cursor:pointer; text-decoration:none; display:inline-block; }
.btn-discord:hover { background:#4752c4; }
.layout { display:flex; min-height:100vh; }
.sidebar { width:260px; background:#131319; border-right:1px solid #24242f; padding:20px 16px; flex-shrink:0; }
.sidebar .user { display:flex; align-items:center; gap:10px; margin-bottom:20px; }
.sidebar .user img { width:36px; height:36px; border-radius:50%; }
.sidebar .user .name { font-weight:600; font-size:14px; }
.sidebar .user a { color:#f04747; font-size:12px; text-decoration:none; }
.guild-select { width:100%; padding:10px; border-radius:8px; background:#1c1c26; color:#fff; border:1px solid #2c2c3a; margin-bottom:18px; font-size:14px; }
.nav { display:flex; flex-direction:column; gap:4px; }
.nav button { background:transparent; border:none; color:#b3b3c6; text-align:left; padding:10px 12px; border-radius:8px; cursor:pointer; font-size:14px; }
.nav button.active, .nav button:hover { background:#1e1e2a; color:#fff; }
.main { flex:1; padding:28px 32px; max-width:980px; }
.main h2 { margin-top:0; }
.stat-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:14px; margin-top:18px; }
.stat-card { background:#15151d; border:1px solid #24242f; border-radius:12px; padding:16px; }
.stat-card .label { color:#8a8aa0; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
.stat-card .value { font-size:26px; font-weight:700; margin-top:6px; }
.config-item { display:flex; align-items:center; justify-content:space-between; gap:12px; background:#15151d; border:1px solid #24242f; border-radius:12px; padding:14px 16px; margin-bottom:10px; }
.config-item .info .title { font-weight:600; font-size:14px; }
.config-item .info .desc { color:#8a8aa0; font-size:12px; margin-top:2px; }
.switch { position:relative; width:46px; height:26px; flex-shrink:0; }
.switch input { opacity:0; width:0; height:0; }
.slider { position:absolute; cursor:pointer; inset:0; background:#33333f; border-radius:26px; transition:.2s; }
.slider:before { content:""; position:absolute; height:20px; width:20px; left:3px; bottom:3px; background:#fff; border-radius:50%; transition:.2s; }
.switch input:checked + .slider { background:#4cd964; }
.switch input:checked + .slider:before { transform:translateX(20px); }
.search-row { display:flex; gap:8px; margin-top:14px; }
.search-row input { flex:1; padding:10px 12px; border-radius:8px; background:#1c1c26; border:1px solid #2c2c3a; color:#fff; }
.btn { padding:9px 16px; border-radius:8px; border:none; cursor:pointer; font-weight:600; font-size:13px; }
.btn-primary { background:#5865f2; color:#fff; }
.btn-danger { background:#ed4245; color:#fff; }
.btn-warn { background:#faa61a; color:#131319; }
.btn-muted { background:#2c2c3a; color:#ddd; }
.member-card { display:flex; align-items:center; gap:12px; background:#15151d; border:1px solid #24242f; border-radius:12px; padding:12px 16px; margin-top:10px; flex-wrap:wrap; }
.member-card img { width:40px; height:40px; border-radius:50%; }
.member-card .info { flex:1; min-width:140px; }
.member-card .info .tag { font-weight:600; font-size:14px; }
.member-card .info .role { color:#8a8aa0; font-size:12px; }
.member-card .actions { display:flex; gap:6px; flex-wrap:wrap; }
.toast { position:fixed; bottom:20px; right:20px; background:#1c1c26; border:1px solid #2c2c3a; padding:12px 18px; border-radius:10px; font-size:14px; max-width:320px; z-index:99; }
.toast.err { border-color:#ed4245; color:#ff9b9d; }
.toast.ok { border-color:#4cd964; color:#b9f5c7; }
@media (max-width:760px) { .layout { flex-direction:column; } .sidebar { width:100%; border-right:none; border-bottom:1px solid #24242f; } .main { padding:20px; } }
</style></head>
<body><div id="app">${bodyHtml}</div>
<script>
const app = document.getElementById('app');
let state = { me: null, guildId: null, tab: 'stats', perms: null };

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { 'Content-Type':'application/json', ...(opts.headers||{}) } });
  if (res.status === 401) { renderLogin(); throw new Error('não autenticado'); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.erro || 'Erro desconhecido');
  return data;
}
function toast(msg, ok=true) {
  const t = document.createElement('div');
  t.className = 'toast ' + (ok ? 'ok' : 'err');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}
function renderLogin() {
  app.innerHTML = '<div class="login-screen"><h1>🔒 VTX Dashboard</h1><p>Faça login com sua conta Discord. Só quem tem cargo de staff/admin em algum servidor gerenciado pelo bot consegue entrar.</p><a class="btn-discord" href="/dashboard/login">Entrar com Discord</a></div>';
}
async function boot() {
  try {
    state.me = await api('/api/dashboard/me');
    if (!state.guildId && state.me.guilds.length) state.guildId = state.me.guilds[0].id;
    if (!state.me.guilds.length) { app.innerHTML = '<div class="login-screen"><h1>🚫 Sem acesso</h1><p>Sua conta não tem staff/admin em nenhum servidor.</p><a class="btn-discord" href="/dashboard/logout">Sair</a></div>'; return; }
    await carregarPerms();
    renderLayout();
  } catch { renderLogin(); }
}
async function carregarPerms() {
  try { state.perms = await api('/api/dashboard/guilds/'+state.guildId+'/permissions'); }
  catch { state.perms = { dono:false, administrator:false, manageGuild:false, banMembers:false, kickMembers:false, moderateMembers:false, staffInterno:false }; }
}
function renderLayout() {
  const { me, perms } = state;
  const podeConfig = perms.dono || perms.administrator || perms.manageGuild;
  app.innerHTML = '<div class="layout"><div class="sidebar"><div class="user"><img src="'+me.usuario.avatar+'"><div><div class="name">'+me.usuario.nome+'</div><a href="/dashboard/logout">Sair</a></div></div>'
    + '<select class="guild-select" id="guildSelect">' + me.guilds.map(g => '<option value="'+g.id+'"'+(g.id===state.guildId?' selected':'')+'>'+g.nome+'</option>').join('') + '</select>'
    + '<div class="nav"><button data-tab="stats">📊 Estatísticas</button>' + (podeConfig ? '<button data-tab="config">⚙️ Sistemas</button>' : '') + '<button data-tab="mod">🛡️ Moderação</button></div>'
    + '</div><div class="main" id="main"></div></div>';
  if (state.tab === 'config' && !podeConfig) state.tab = 'stats';
  document.getElementById('guildSelect').onchange = async e => { state.guildId = e.target.value; await carregarPerms(); renderLayout(); };
  document.querySelectorAll('.nav button').forEach(b => b.onclick = () => { state.tab = b.dataset.tab; renderTab(); });
  renderTab();
}
function renderTab() {
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === state.tab));
  if (state.tab === 'stats') return renderStats();
  if (state.tab === 'config') return renderConfig();
  if (state.tab === 'mod') return renderMod();
}
function fmtUptime(ms) {
  const s = Math.floor(ms/1000), d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  return d+'d '+h+'h '+m+'m';
}
async function renderStats() {
  const main = document.getElementById('main');
  main.innerHTML = '<h2>📊 Estatísticas</h2><div class="loading" style="height:auto;padding:30px 0">Carregando…</div>';
  try {
    const s = await api('/api/dashboard/guilds/'+state.guildId+'/stats');
    main.innerHTML = '<h2>📊 '+s.nome+'</h2><div class="stat-grid">'
      + '<div class="stat-card"><div class="label">Membros</div><div class="value">'+s.membros+'</div></div>'
      + '<div class="stat-card"><div class="label">Online</div><div class="value">'+s.online+'</div></div>'
      + '<div class="stat-card"><div class="label">Canais</div><div class="value">'+s.canais+'</div></div>'
      + '<div class="stat-card"><div class="label">Cargos</div><div class="value">'+s.cargos+'</div></div>'
      + '<div class="stat-card"><div class="label">Boosts</div><div class="value">'+s.boosts+' (nível '+s.nivelBoost+')</div></div>'
      + '<div class="stat-card"><div class="label">Ping do bot</div><div class="value">'+s.botPingMs+'ms</div></div>'
      + '<div class="stat-card"><div class="label">Uptime do bot</div><div class="value">'+fmtUptime(s.botUptimeMs)+'</div></div>'
      + '<div class="stat-card"><div class="label">Servidores com o bot</div><div class="value">'+s.totalServidoresBot+'</div></div></div>';
  } catch (err) { main.innerHTML = '<h2>📊 Estatísticas</h2><p style="color:#ff9b9d">'+err.message+'</p>'; }
}
async function renderConfig() {
  const main = document.getElementById('main');
  main.innerHTML = '<h2>⚙️ Sistemas</h2><div class="loading" style="height:auto;padding:30px 0">Carregando…</div>';
  try {
    const cfg = await api('/api/dashboard/guilds/'+state.guildId+'/config');
    const chaves = Object.keys(cfg);
    if (!chaves.length) { main.innerHTML = '<h2>⚙️ Sistemas</h2><p style="color:#8a8aa0">Nenhum sistema registrado ainda.</p>'; return; }
    main.innerHTML = '<h2>⚙️ Sistemas</h2>' + chaves.map(chave => {
      const s = cfg[chave];
      return '<div class="config-item"><div class="info"><div class="title">'+s.label+'</div><div class="desc">'+s.desc+'</div></div>'
        + '<label class="switch"><input type="checkbox" data-chave="'+chave+'" '+(s.valor?'checked':'')+'><span class="slider"></span></label></div>';
    }).join('');
    main.querySelectorAll('input[type=checkbox]').forEach(inp => {
      inp.onchange = async () => {
        const chave = inp.dataset.chave;
        try {
          await api('/api/dashboard/guilds/'+state.guildId+'/config/'+chave, { method:'POST', body: JSON.stringify({ valor: inp.checked }) });
          toast(chave+': '+(inp.checked?'ativado':'desativado'));
        } catch (err) { inp.checked = !inp.checked; toast(err.message, false); }
      };
    });
  } catch (err) { main.innerHTML = '<h2>⚙️ Sistemas</h2><p style="color:#ff9b9d">'+err.message+'</p>'; }
}
function renderMod() {
  const main = document.getElementById('main');
  const p = state.perms;
  const podeBan = p.dono || p.administrator || p.banMembers;
  const podeKick = p.dono || p.administrator || p.kickMembers;
  const podeMute = p.dono || p.administrator || p.moderateMembers;
  if (!podeBan && !podeKick && !podeMute) {
    main.innerHTML = '<h2>🛡️ Moderação</h2><p style="color:#8a8aa0">Você não tem permissão de banir, expulsar ou silenciar nesse servidor.</p>';
    return;
  }
  main.innerHTML = '<h2>🛡️ Moderação</h2><div class="search-row"><input id="searchInput" placeholder="Buscar por nome ou ID do membro…"><button class="btn btn-primary" id="searchBtn">Buscar</button></div><div id="results"></div>';
  const doSearch = async () => {
    const q = document.getElementById('searchInput').value.trim();
    const results = document.getElementById('results');
    if (!q) return;
    results.innerHTML = '<div class="loading" style="height:auto;padding:20px 0">Buscando…</div>';
    try {
      const membros = await api('/api/dashboard/guilds/'+state.guildId+'/members/search?q='+encodeURIComponent(q));
      if (!membros.length) { results.innerHTML = '<p style="color:#8a8aa0">Nenhum membro encontrado.</p>'; return; }
      results.innerHTML = membros.map(m => '<div class="member-card" data-id="'+m.id+'"><img src="'+m.avatar+'">'
        + '<div class="info"><div class="tag">'+m.tag+'</div><div class="role">'+(m.cargoMaisAlto||'')+(m.timeoutAte && m.timeoutAte>Date.now()?' · ⏱️ silenciado':'')+'</div></div>'
        + '<div class="actions">'
        + (podeMute ? '<button class="btn btn-warn" data-acao="timeout">Silenciar 10min</button><button class="btn btn-muted" data-acao="untimeout">Remover silêncio</button>' : '')
        + (podeKick ? '<button class="btn btn-danger" data-acao="kick">Expulsar</button>' : '')
        + (podeBan ? '<button class="btn btn-danger" data-acao="ban">Banir</button>' : '')
        + '</div></div>').join('');
      results.querySelectorAll('button[data-acao]').forEach(btn => btn.onclick = () => executarAcao(btn.closest('.member-card').dataset.id, btn.dataset.acao));
    } catch (err) { results.innerHTML = '<p style="color:#ff9b9d">'+err.message+'</p>'; }
  };
  document.getElementById('searchBtn').onclick = doSearch;
  document.getElementById('searchInput').onkeydown = e => { if (e.key==='Enter') doSearch(); };
}
async function executarAcao(userId, acao) {
  let motivo = '';
  if (acao === 'ban' || acao === 'kick') {
    motivo = prompt('Motivo ('+(acao==='ban'?'banir':'expulsar')+'):') || '';
    if (!confirm('Confirmar '+(acao==='ban'?'banimento':'expulsão')+'?')) return;
  }
  try {
    await api('/api/dashboard/guilds/'+state.guildId+'/members/'+userId+'/'+acao, { method:'POST', body: JSON.stringify({ motivo, minutos: 10 }) });
    toast('Ação aplicada com sucesso.');
    renderMod();
  } catch (err) { toast(err.message, false); }
}
boot();
</script></body></html>`;
}

// ============================================================================
// HANDLER PRINCIPAL — roteia manualmente com base na URL
// ============================================================================
export default async function handler(req, res) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const pathname = url.pathname;

  // Lê o corpo JSON em requisições POST (Vercel não faz isso sozinho aqui)
  async function readBody() {
    if (req.method !== 'POST') return {};
    return await new Promise(resolve => {
      let raw = '';
      req.on('data', c => raw += c);
      req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } });
    });
  }

  try {
    // ── Login ──────────────────────────────────────────────────────────────
    if (pathname === '/dashboard/login') {
      const state = newState();
      const params = new URLSearchParams({
        client_id: OAUTH2_CLIENT_ID, redirect_uri: DASHBOARD_REDIRECT_URI,
        response_type: 'code', scope: 'identify', state, prompt: 'consent',
      });
      res.statusCode = 302;
      res.setHeader('Location', `https://discord.com/oauth2/authorize?${params.toString()}`);
      return res.end();
    }

    if (pathname === '/dashboard/callback') {
      const code = url.searchParams.get('code');
      const st = url.searchParams.get('state');
      if (!code || !st || !validState(st)) return sendHtml(res, 400, 'Requisição inválida ou expirada. Tente logar novamente.');

      const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: OAUTH2_CLIENT_ID, client_secret: OAUTH2_CLIENT_SECRET,
          grant_type: 'authorization_code', code, redirect_uri: DASHBOARD_REDIRECT_URI,
        }),
      });
      const tokenData = await tokenRes.json();
      if (!tokenData.access_token) return sendHtml(res, 500, 'Erro ao autenticar com o Discord. Tente novamente.');

      const userRes = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
      const userData = await userRes.json();
      if (!userData?.id) return sendHtml(res, 500, 'Não foi possível obter seus dados do Discord.');

      const perm = await botApi(`/permissions?userId=${userData.id}`);
      if (perm.status !== 200 || !perm.data.guilds?.length) {
        return sendHtml(res, 403, `<html><body style="background:#0d0d12;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;text-align:center"><h2>🚫 Acesso negado</h2><p>Sua conta não tem staff/admin em nenhum servidor gerenciado pelo bot.</p></body></html>`);
      }

      setSessionCookie(res, {
        id: userData.id,
        nome: userData.username,
        avatar: userData.avatar ? `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png?size=128` : `https://cdn.discordapp.com/embed/avatars/${Number(userData.discriminator || 0) % 5}.png`,
        exp: Date.now() + 12 * 60 * 60 * 1000,
      });
      res.statusCode = 302;
      res.setHeader('Location', '/dashboard');
      return res.end();
    }

    if (pathname === '/dashboard/logout') {
      clearSessionCookie(res);
      res.statusCode = 302;
      res.setHeader('Location', '/dashboard');
      return res.end();
    }

    // ── Página principal ───────────────────────────────────────────────────
    if (pathname === '/dashboard' || pathname === '/') {
      return sendHtml(res, 200, pageShell('<div class="loading">Carregando…</div>'));
    }

    // ── API (proxy pra API interna do bot) ─────────────────────────────────
    if (pathname.startsWith('/api/dashboard/')) {
      const user = getSessionUser(req);
      if (!user) return sendJson(res, 401, { erro: 'Não autenticado.' });

      if (pathname === '/api/dashboard/me') {
        const perm = await botApi(`/permissions?userId=${user.id}`);
        if (perm.status !== 200) return sendJson(res, perm.status, perm.data);
        return sendJson(res, 200, { usuario: { id: user.id, nome: user.nome, avatar: user.avatar }, guilds: perm.data.guilds });
      }

      const m = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/stats$/);
      if (m) {
        const r = await botApi(`/guilds/${m[1]}/stats?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      const mPerms = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/permissions$/);
      if (mPerms) {
        const r = await botApi(`/guilds/${mPerms[1]}/permissions?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      const mCfgGet = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/config$/);
      if (mCfgGet) {
        const r = await botApi(`/guilds/${mCfgGet[1]}/config?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      const mCfgSet = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/config\/([^/]+)$/);
      if (mCfgSet && req.method === 'POST') {
        const body = await readBody();
        const r = await botApi(`/guilds/${mCfgSet[1]}/config/${mCfgSet[2]}`, { method: 'POST', body: { ...body, userId: user.id } });
        return sendJson(res, r.status, r.data);
      }

      const mSearch = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/members\/search$/);
      if (mSearch) {
        const q = url.searchParams.get('q') || '';
        const r = await botApi(`/guilds/${mSearch[1]}/members/search?userId=${user.id}&q=${encodeURIComponent(q)}`);
        return sendJson(res, r.status, r.data);
      }

      const mAcao = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/members\/([^/]+)\/(ban|kick|timeout|untimeout)$/);
      if (mAcao && req.method === 'POST') {
        const body = await readBody();
        const r = await botApi(`/guilds/${mAcao[1]}/members/${mAcao[2]}/${mAcao[3]}`, { method: 'POST', body: { ...body, requesterId: user.id } });
        return sendJson(res, r.status, r.data);
      }

      return sendJson(res, 404, { erro: 'Rota não encontrada.' });
    }

    return sendHtml(res, 404, 'Página não encontrada.');
  } catch (err) {
    return sendJson(res, 500, { erro: 'Erro interno.', detalhe: err?.message });
  }
}
