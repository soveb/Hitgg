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
//
// OBS sobre a aba de Logs em tempo real: ela usa Server-Sent Events (SSE),
// que fica aberto direto com o bot. Na Vercel (plano Hobby) funções serverless
// têm um limite de duração de execução — o navegador reconecta sozinho quando
// isso acontece (comportamento nativo do EventSource), então na prática os
// logs continuam chegando "quase em tempo real" mesmo assim. Se quiser 100%
// sem reconexões, rode esse arquivo num host que permita long-running
// connections (Railway, VPS, etc.) em vez da Vercel.
// ============================================================================

import crypto from 'crypto';

const {
  OAUTH2_CLIENT_ID,
  OAUTH2_CLIENT_SECRET,
  DASHBOARD_REDIRECT_URI,
  SESSION_SECRET,
  BOT_API_BASE_URL,
  DASHBOARD_API_SECRET,
  DASHBOARD_PASSWORD,   // senha alternativa de login (opcional)
  DASHBOARD_OWNER_ID,   // ID Discord usado na sessão quando loga por senha
} = process.env;

// ── Comparação segura de senha (evita timing attack) ────────────────────────
function senhaValida(informada) {
  const correta = DASHBOARD_PASSWORD || '';
  if (!correta) return false;
  const a = Buffer.from(String(informada || ''));
  const b = Buffer.from(correta);
  if (a.length !== b.length) {
    crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

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

// ============================================================================
// HTML da aplicação (login + SPA), CSS e JS embutidos
// ============================================================================
function pageShell(bodyHtml) {
  return `<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VTX Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#050307; --bg2:#0b0710; --panel:#0f0a15; --panel2:#150e1e;
  --border:#241a2b; --border-soft:#1a1220;
  --pink:#ff2d67; --pink2:#ff5c8a; --red:#c9184a; --hot:#ff1f4e;
  --grad: linear-gradient(135deg,#ff2d67 0%,#c9184a 55%,#7a0e2e 100%);
  --white:#f7f4f7; --dim:#a89aae; --dim2:#7a6d82;
  --ok:#2be27a; --warn:#ffb020; --danger:#ff3860;
  --radius:16px;
}
*{box-sizing:border-box;}
html,body{margin:0;padding:0;}
body{
  background:
    radial-gradient(1100px 700px at 12% -8%, rgba(255,45,103,.16), transparent 60%),
    radial-gradient(900px 600px at 105% 10%, rgba(201,24,74,.14), transparent 55%),
    radial-gradient(700px 500px at 50% 120%, rgba(255,45,103,.10), transparent 60%),
    var(--bg);
  color:var(--white); font-family:'Manrope',sans-serif; min-height:100vh; overflow-x:hidden;
}
h1,h2,h3,.brand{font-family:'Space Grotesk',sans-serif;}
::-webkit-scrollbar{width:10px;height:10px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:linear-gradient(var(--pink),var(--red));border-radius:10px;}
.glow-orb{position:fixed;border-radius:50%;filter:blur(90px);opacity:.35;pointer-events:none;z-index:0;animation:float 14s ease-in-out infinite;}
.glow-orb.o1{width:420px;height:420px;background:var(--pink);top:-160px;left:-120px;}
.glow-orb.o2{width:360px;height:360px;background:var(--red);bottom:-140px;right:-100px;animation-delay:-6s;}
@keyframes float{0%,100%{transform:translateY(0) translateX(0);}50%{transform:translateY(30px) translateX(20px);}}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
@keyframes pulseDot{0%,100%{box-shadow:0 0 0 0 rgba(43,226,122,.55);}70%{box-shadow:0 0 0 7px rgba(43,226,122,0);}}
@keyframes shimmer{0%{background-position:-400px 0;}100%{background-position:400px 0;}}
@keyframes spin{to{transform:rotate(360deg);}}

.loading{display:flex;align-items:center;justify-content:center;height:100vh;gap:12px;color:var(--dim);position:relative;z-index:1;}
.spinner{width:22px;height:22px;border-radius:50%;border:3px solid var(--border);border-top-color:var(--pink);animation:spin .8s linear infinite;}

.login-screen{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;text-align:center;gap:18px;padding:24px;position:relative;z-index:1;}
.login-card{background:rgba(15,10,21,.7);backdrop-filter:blur(18px);border:1px solid var(--border);border-radius:24px;padding:44px 36px;max-width:400px;width:100%;animation:fadeUp .5s ease;box-shadow:0 30px 80px -20px rgba(255,45,103,.25);}
.login-card .logo{width:64px;height:64px;border-radius:18px;background:var(--grad);display:flex;align-items:center;justify-content:center;margin:0 auto 18px;font-size:28px;box-shadow:0 10px 30px -6px rgba(255,45,103,.6);}
.login-card h1{font-size:24px;margin:0 0 6px;letter-spacing:-.02em;}
.login-card p{color:var(--dim);font-size:13.5px;line-height:1.5;margin:0 0 24px;}
.btn-discord{background:var(--grad);color:#fff;border:none;padding:13px 24px;border-radius:12px;font-size:14.5px;font-weight:700;cursor:pointer;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:8px;width:100%;transition:.2s;box-shadow:0 8px 24px -8px rgba(255,45,103,.55);}
.btn-discord:hover{transform:translateY(-2px);box-shadow:0 12px 30px -6px rgba(255,45,103,.7);}
.divider{display:flex;align-items:center;gap:10px;width:100%;color:var(--dim2);font-size:11.5px;margin:20px 0;text-transform:uppercase;letter-spacing:.08em;}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--border);}
.senha-box{display:flex;flex-direction:column;gap:10px;width:100%;}
.input{width:100%;padding:12px 14px;border-radius:11px;background:#100a17;border:1px solid var(--border);color:#fff;font-size:14px;outline:none;transition:.15s;}
.input:focus{border-color:var(--pink);box-shadow:0 0 0 3px rgba(255,45,103,.15);}
.err-text{color:var(--danger);font-size:12.5px;margin:0;display:none;}

.layout{display:flex;min-height:100vh;position:relative;z-index:1;}
.sidebar{width:264px;background:rgba(11,7,16,.75);backdrop-filter:blur(20px);border-right:1px solid var(--border-soft);padding:22px 16px;flex-shrink:0;display:flex;flex-direction:column;gap:18px;}
.brand-row{display:flex;align-items:center;gap:10px;padding:0 6px;}
.brand-row .mark{width:34px;height:34px;border-radius:10px;background:var(--grad);display:flex;align-items:center;justify-content:center;font-size:16px;box-shadow:0 6px 16px -4px rgba(255,45,103,.6);}
.brand-row .name{font-weight:800;font-size:16px;letter-spacing:-.01em;}
.brand-row .name span{color:var(--pink2);}
.user{display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--panel);border:1px solid var(--border-soft);border-radius:14px;}
.user img{width:38px;height:38px;border-radius:50%;border:2px solid var(--pink);}
.user .name{font-weight:700;font-size:13.5px;}
.user a{color:var(--dim2);font-size:11.5px;text-decoration:none;}
.user a:hover{color:var(--pink2);}
.guild-select{width:100%;padding:11px 12px;border-radius:12px;background:var(--panel);color:#fff;border:1px solid var(--border-soft);font-size:13.5px;font-weight:600;appearance:none;cursor:pointer;}
.nav{display:flex;flex-direction:column;gap:3px;}
.nav button{background:transparent;border:none;color:var(--dim);text-align:left;padding:11px 13px;border-radius:11px;cursor:pointer;font-size:13.8px;font-weight:600;display:flex;align-items:center;gap:10px;transition:.15s;position:relative;}
.nav button:hover{background:var(--panel2);color:#fff;}
.nav button.active{background:linear-gradient(90deg,rgba(255,45,103,.18),rgba(255,45,103,.02));color:#fff;box-shadow:inset 3px 0 0 var(--pink);}
.nav .grp-label{font-size:10.5px;text-transform:uppercase;letter-spacing:.1em;color:var(--dim2);padding:14px 13px 2px;font-weight:700;}

.main{flex:1;padding:30px 34px;max-width:1180px;animation:fadeUp .35s ease;}
.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;gap:14px;flex-wrap:wrap;}
.main h2{margin:0;font-size:22px;letter-spacing:-.02em;display:flex;align-items:center;gap:10px;}
.live-badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;color:var(--ok);background:rgba(43,226,122,.1);border:1px solid rgba(43,226,122,.25);padding:4px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:.04em;}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:pulseDot 1.6s infinite;}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px;margin-top:6px;}
.stat-card{background:linear-gradient(160deg,var(--panel),var(--panel2));border:1px solid var(--border-soft);border-radius:var(--radius);padding:18px;position:relative;overflow:hidden;transition:.2s;animation:fadeUp .4s ease;}
.stat-card:hover{border-color:rgba(255,45,103,.35);transform:translateY(-2px);}
.stat-card::before{content:"";position:absolute;top:0;left:0;width:100%;height:2px;background:var(--grad);opacity:.7;}
.stat-card .icon{font-size:18px;opacity:.85;margin-bottom:10px;}
.stat-card .label{color:var(--dim);font-size:11.5px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;}
.stat-card .value{font-size:27px;font-weight:800;margin-top:6px;font-family:'Space Grotesk',sans-serif;}
.stat-card .sub{font-size:11.5px;color:var(--dim2);margin-top:3px;}

.section-title{font-size:14px;font-weight:800;margin:28px 0 12px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;}
.chart-card{background:var(--panel);border:1px solid var(--border-soft);border-radius:var(--radius);padding:18px 20px;margin-bottom:14px;}
.chart-card .chead{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;}
.chart-card .chead h3{font-size:13.5px;margin:0;color:var(--white);}
.chart-card .chead .tot{font-size:12px;color:var(--pink2);font-weight:700;}
.bars{display:flex;align-items:flex-end;gap:6px;height:90px;}
.bars .bar{flex:1;background:linear-gradient(180deg,var(--pink),var(--red));border-radius:5px 5px 2px 2px;min-height:3px;position:relative;transition:.3s;opacity:.9;}
.bars .bar:hover{opacity:1;filter:brightness(1.2);}
.bars-labels{display:flex;gap:6px;margin-top:6px;}
.bars-labels span{flex:1;text-align:center;font-size:9.5px;color:var(--dim2);}

.config-item{display:flex;align-items:center;justify-content:space-between;gap:12px;background:var(--panel);border:1px solid var(--border-soft);border-radius:var(--radius);padding:16px 18px;margin-bottom:10px;transition:.15s;}
.config-item:hover{border-color:rgba(255,45,103,.3);}
.config-item .info .title{font-weight:700;font-size:14px;}
.config-item .info .desc{color:var(--dim);font-size:12px;margin-top:3px;}
.switch{position:relative;width:48px;height:27px;flex-shrink:0;}
.switch input{opacity:0;width:0;height:0;}
.slider{position:absolute;cursor:pointer;inset:0;background:#2a2030;border-radius:27px;transition:.25s;}
.slider:before{content:"";position:absolute;height:21px;width:21px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.25s;}
.switch input:checked + .slider{background:var(--grad);}
.switch input:checked + .slider:before{transform:translateX(21px);}

.search-row{display:flex;gap:8px;margin-top:14px;}
.search-row input{flex:1;padding:12px 14px;border-radius:12px;background:var(--panel);border:1px solid var(--border-soft);color:#fff;font-size:14px;}
.search-row input:focus{outline:none;border-color:var(--pink);}
.btn{padding:10px 18px;border-radius:11px;border:none;cursor:pointer;font-weight:700;font-size:12.8px;transition:.15s;}
.btn:hover{transform:translateY(-1px);}
.btn-primary{background:var(--grad);color:#fff;box-shadow:0 6px 16px -6px rgba(255,45,103,.55);}
.btn-danger{background:rgba(255,56,96,.14);color:#ff7f97;border:1px solid rgba(255,56,96,.3);}
.btn-danger:hover{background:var(--danger);color:#fff;}
.btn-warn{background:rgba(255,176,32,.14);color:#ffcb6b;border:1px solid rgba(255,176,32,.3);}
.btn-warn:hover{background:var(--warn);color:#1a1210;}
.btn-muted{background:var(--panel2);color:#ddd;border:1px solid var(--border-soft);}
.btn-muted:hover{background:#22182a;}

.member-card{display:flex;align-items:center;gap:14px;background:var(--panel);border:1px solid var(--border-soft);border-radius:var(--radius);padding:14px 18px;margin-top:10px;flex-wrap:wrap;animation:fadeUp .3s ease;}
.member-card img{width:44px;height:44px;border-radius:50%;border:2px solid var(--border-soft);}
.member-card .info{flex:1;min-width:150px;}
.member-card .info .tag{font-weight:700;font-size:14.5px;}
.member-card .info .role{color:var(--dim2);font-size:11.5px;margin-top:2px;}
.member-card .info .role .w{color:var(--warn);font-weight:700;}
.member-card .actions{display:flex;gap:6px;flex-wrap:wrap;}

.toast{position:fixed;bottom:22px;right:22px;background:var(--panel);border:1px solid var(--border-soft);padding:13px 18px;border-radius:13px;font-size:13.5px;max-width:320px;z-index:999;animation:fadeUp .25s ease;box-shadow:0 12px 30px -10px rgba(0,0,0,.6);}
.toast.err{border-color:rgba(255,56,96,.4);color:#ff9db0;}
.toast.ok{border-color:rgba(43,226,122,.4);color:#a9f5c4;}

.logs-box{background:#08050b;border:1px solid var(--border-soft);border-radius:var(--radius);padding:16px 18px;font-family:'Space Grotesk',monospace;font-size:12.3px;line-height:1.7;height:520px;overflow-y:auto;display:flex;flex-direction:column-reverse;}
.log-line{white-space:pre-wrap;word-break:break-word;border-bottom:1px solid rgba(255,255,255,.03);padding:3px 0;}
.log-line .lv{font-weight:800;padding:1px 6px;border-radius:5px;font-size:10px;margin-right:8px;}
.lv-OK{background:rgba(43,226,122,.15);color:#7bf0ab;} .lv-INFO{background:rgba(90,150,255,.15);color:#8fb4ff;}
.lv-WARN{background:rgba(255,176,32,.15);color:#ffcb6b;} .lv-ERROR{background:rgba(255,56,96,.18);color:#ff8fa3;}
.lv-FATAL{background:rgba(255,56,96,.35);color:#fff;} .lv-DEBUG{background:rgba(200,200,220,.12);color:#c9c4d6;}
.log-line .mod{color:var(--pink2);font-weight:700;margin-right:6px;}
.log-line .msg{color:#e6e0ea;}

.action-item{display:flex;align-items:center;gap:12px;background:var(--panel);border:1px solid var(--border-soft);border-radius:12px;padding:12px 16px;margin-bottom:8px;font-size:13px;}
.action-item .tag-acao{font-size:10.5px;font-weight:800;padding:3px 9px;border-radius:8px;text-transform:uppercase;}
.tag-ban{background:rgba(255,56,96,.16);color:#ff8fa3;} .tag-kick{background:rgba(255,176,32,.16);color:#ffcb6b;}
.tag-timeout{background:rgba(255,45,103,.16);color:var(--pink2);} .tag-untimeout{background:rgba(43,226,122,.16);color:#7bf0ab;}
.tag-warn{background:rgba(255,176,32,.16);color:#ffcb6b;}
.action-item .meta{color:var(--dim2);font-size:11.5px;}

.empty{color:var(--dim2);font-size:13.5px;padding:26px 0;text-align:center;}
.skeleton{background:linear-gradient(90deg,var(--panel) 0%,var(--panel2) 50%,var(--panel) 100%);background-size:800px 100%;animation:shimmer 1.4s infinite linear;border-radius:12px;}
@media (max-width:820px){.layout{flex-direction:column;}.sidebar{width:100%;border-right:none;border-bottom:1px solid var(--border-soft);}.main{padding:22px 18px;}}
</style></head>
<body>
<div class="glow-orb o1"></div><div class="glow-orb o2"></div>
<div id="app">${bodyHtml}</div>
<script>
const app = document.getElementById('app');
let state = { me:null, guildId:null, tab:'stats', perms:null, logSource:null };

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
  app.innerHTML = '<div class="login-screen"><div class="login-card">'
    + '<div class="logo">🛡️</div><h1>VTX Dashboard</h1>'
    + '<p>Faça login com sua conta Discord. Só quem tem cargo de staff/admin em algum servidor gerenciado pelo bot consegue entrar.</p>'
    + '<a class="btn-discord" href="/dashboard/login">Entrar com Discord</a>'
    + '<div class="divider">ou</div>'
    + '<div class="senha-box">'
    + '<input id="senhaInput" type="password" class="input" placeholder="Senha do dashboard">'
    + '<button id="senhaBtn" class="btn btn-primary" style="width:100%">Entrar com senha</button>'
    + '<p id="senhaErro" class="err-text"></p>'
    + '</div></div></div>';
  const senhaInput = document.getElementById('senhaInput');
  const senhaErro = document.getElementById('senhaErro');
  const tentarSenha = async () => {
    senhaErro.style.display = 'none';
    try {
      const r = await fetch('/dashboard/login-senha', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ senha: senhaInput.value }) });
      if (!r.ok) {
        const d = await r.json().catch(() => ({}));
        senhaErro.textContent = d.erro || 'Senha incorreta.';
        senhaErro.style.display = 'block';
        return;
      }
      location.href = '/dashboard';
    } catch {
      senhaErro.textContent = 'Erro de conexão. Tente novamente.';
      senhaErro.style.display = 'block';
    }
  };
  document.getElementById('senhaBtn').onclick = tentarSenha;
  senhaInput.onkeydown = e => { if (e.key === 'Enter') tentarSenha(); };
}
async function boot() {
  try {
    state.me = await api('/api/dashboard/me');
    if (!state.guildId && state.me.guilds.length) state.guildId = state.me.guilds[0].id;
    if (!state.me.guilds.length) { app.innerHTML = '<div class="login-screen"><div class="login-card"><div class="logo">🚫</div><h1>Sem acesso</h1><p>Sua conta não tem staff/admin em nenhum servidor gerenciado pelo bot.</p><a class="btn-discord" href="/dashboard/logout">Sair</a></div></div>'; return; }
    await carregarPerms();
    renderLayout();
  } catch { renderLogin(); }
}
async function carregarPerms() {
  try { state.perms = await api('/api/dashboard/guilds/'+state.guildId+'/permissions'); }
  catch { state.perms = { dono:false, administrator:false, manageGuild:false, banMembers:false, kickMembers:false, moderateMembers:false, staffInterno:false }; }
}
function icon(nome){
  const map = { stats:'📊', config:'⚙️', mod:'🛡️', logs:'🖥️', actions:'📋' };
  return map[nome] || '•';
}
function renderLayout() {
  const { me, perms } = state;
  const podeConfig = perms.dono || perms.administrator || perms.manageGuild;
  const podeMod = perms.dono || perms.administrator || perms.banMembers || perms.kickMembers || perms.moderateMembers || perms.staffInterno;
  const podeLogs = perms.dono;
  app.innerHTML = '<div class="layout"><div class="sidebar">'
    + '<div class="brand-row"><div class="mark">⚡</div><div class="name">VTX <span>Dashboard</span></div></div>'
    + '<div class="user"><img src="'+me.usuario.avatar+'"><div><div class="name">'+me.usuario.nome+'</div><a href="/dashboard/logout">Sair</a></div></div>'
    + '<select class="guild-select" id="guildSelect">' + me.guilds.map(g => '<option value="'+g.id+'"'+(g.id===state.guildId?' selected':'')+'>'+g.nome+'</option>').join('') + '</select>'
    + '<div class="nav">'
    + '<div class="grp-label">Visão geral</div>'
    + '<button data-tab="stats">'+icon('stats')+' Estatísticas</button>'
    + (podeMod ? '<button data-tab="mod">'+icon('mod')+' Moderação</button><button data-tab="actions">'+icon('actions')+' Ações recentes</button>' : '')
    + (podeConfig ? '<div class="grp-label">Administração</div><button data-tab="config">'+icon('config')+' Sistemas</button>' : '')
    + (podeLogs ? '<div class="grp-label">Dono</div><button data-tab="logs">'+icon('logs')+' Logs em tempo real</button>' : '')
    + '</div></div><div class="main" id="main"></div></div>';
  if (state.tab === 'config' && !podeConfig) state.tab = 'stats';
  if (state.tab === 'logs' && !podeLogs) state.tab = 'stats';
  if ((state.tab === 'mod' || state.tab === 'actions') && !podeMod) state.tab = 'stats';
  document.getElementById('guildSelect').onchange = async e => { closeLogStream(); state.guildId = e.target.value; await carregarPerms(); renderLayout(); };
  document.querySelectorAll('.nav button').forEach(b => b.onclick = () => { closeLogStream(); state.tab = b.dataset.tab; renderTab(); });
  renderTab();
}
function renderTab() {
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.tab === state.tab));
  if (state.tab === 'stats') return renderStats();
  if (state.tab === 'config') return renderConfig();
  if (state.tab === 'mod') return renderMod();
  if (state.tab === 'actions') return renderActions();
  if (state.tab === 'logs') return renderLogs();
}
function fmtUptime(ms) {
  const s = Math.floor(ms/1000), d = Math.floor(s/86400), h = Math.floor((s%86400)/3600), m = Math.floor((s%3600)/60);
  return d+'d '+h+'h '+m+'m';
}
function skeletonStats(){
  return '<div class="stat-grid">' + Array.from({length:8}).map(()=>'<div class="skeleton" style="height:88px;"></div>').join('') + '</div>';
}
function barsChart(titulo, valores, labels, total){
  const max = Math.max(1, ...valores);
  const bars = valores.map(v => '<div class="bar" style="height:'+Math.max(4, (v/max*100))+'%" title="'+v+'"></div>').join('');
  const labs = labels.map(l => '<span>'+l.slice(5).replace('-','/')+'</span>').join('');
  return '<div class="chart-card"><div class="chead"><h3>'+titulo+'</h3><div class="tot">'+total+' nos últimos 7 dias</div></div>'
    + '<div class="bars">'+bars+'</div><div class="bars-labels">'+labs+'</div></div>';
}
async function renderStats() {
  const main = document.getElementById('main');
  main.innerHTML = '<div class="topbar"><h2>📊 Estatísticas</h2></div>' + skeletonStats();
  try {
    const s = await api('/api/dashboard/guilds/'+state.guildId+'/stats');
    const h = s.historico7d || { labels:[], mensagens:[], entradas:[], saidas:[], vozMin:[] };
    const somaMsg = h.mensagens.reduce((a,b)=>a+b,0);
    const somaEntradas = h.entradas.reduce((a,b)=>a+b,0);
    main.innerHTML = '<div class="topbar"><h2>'+(s.icone?'<img src="'+s.icone+'" style="width:28px;height:28px;border-radius:8px;vertical-align:middle;margin-right:6px">':'📊')+' '+s.nome+'</h2><span class="live-badge"><span class="dot"></span>Ao vivo</span></div>'
      + '<div class="stat-grid">'
      + statCard('👥','Membros', s.membros)
      + statCard('🟢','Online agora', s.online)
      + statCard('💬','Mensagens hoje', s.mensagensHoje)
      + statCard('🎙️','Minutos de voz hoje', s.minutosVozHoje)
      + statCard('📥','Entradas hoje', s.entradasHoje)
      + statCard('📤','Saídas hoje', s.saidasHoje)
      + statCard('📺','Canais', s.canais)
      + statCard('🎭','Cargos', s.cargos)
      + statCard('💎','Boosts', s.boosts+' · nível '+s.nivelBoost)
      + statCard('📡','Ping do bot', s.botPingMs+'ms')
      + statCard('⏱️','Uptime do bot', fmtUptime(s.botUptimeMs))
      + statCard('🌐','Servidores com o bot', s.totalServidoresBot)
      + '</div>'
      + '<div class="section-title">Histórico — últimos 7 dias</div>'
      + barsChart('💬 Mensagens', h.mensagens, h.labels, somaMsg)
      + barsChart('📥 Entradas de membros', h.entradas, h.labels, somaEntradas);
  } catch (err) { main.innerHTML = '<h2>📊 Estatísticas</h2><p class="empty" style="color:#ff8fa3">'+err.message+'</p>'; }
}
function statCard(ic, label, value){
  return '<div class="stat-card"><div class="icon">'+ic+'</div><div class="label">'+label+'</div><div class="value">'+value+'</div></div>';
}
async function renderConfig() {
  const main = document.getElementById('main');
  main.innerHTML = '<h2>⚙️ Sistemas</h2><div class="skeleton" style="height:64px;margin-bottom:10px"></div><div class="skeleton" style="height:64px"></div>';
  try {
    const cfg = await api('/api/dashboard/guilds/'+state.guildId+'/config');
    const chaves = Object.keys(cfg);
    if (!chaves.length) { main.innerHTML = '<h2>⚙️ Sistemas</h2><p class="empty">Nenhum sistema registrado ainda.</p>'; return; }
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
  } catch (err) { main.innerHTML = '<h2>⚙️ Sistemas</h2><p class="empty" style="color:#ff8fa3">'+err.message+'</p>'; }
}
function renderMod() {
  const main = document.getElementById('main');
  const p = state.perms;
  const podeBan = p.dono || p.administrator || p.banMembers;
  const podeKick = p.dono || p.administrator || p.kickMembers;
  const podeMute = p.dono || p.administrator || p.moderateMembers;
  const podeWarn = podeMute;
  if (!podeBan && !podeKick && !podeMute) {
    main.innerHTML = '<h2>🛡️ Moderação</h2><p class="empty">Você não tem permissão de banir, expulsar ou silenciar nesse servidor.</p>';
    return;
  }
  main.innerHTML = '<h2>🛡️ Moderação</h2><div class="search-row"><input id="searchInput" placeholder="Buscar por nome, tag ou ID do membro…"><button class="btn btn-primary" id="searchBtn">Buscar</button></div><div id="results"></div>';
  const doSearch = async () => {
    const q = document.getElementById('searchInput').value.trim();
    const results = document.getElementById('results');
    if (!q) return;
    results.innerHTML = '<div class="skeleton" style="height:76px;margin-top:10px"></div>';
    try {
      const membros = await api('/api/dashboard/guilds/'+state.guildId+'/members/search?q='+encodeURIComponent(q));
      if (!membros.length) { results.innerHTML = '<p class="empty">Nenhum membro encontrado.</p>'; return; }
      results.innerHTML = membros.map(m => '<div class="member-card" data-id="'+m.id+'"><img src="'+m.avatar+'">'
        + '<div class="info"><div class="tag">'+m.tag+'</div><div class="role">'+(m.cargoMaisAlto||'sem cargo')+(m.timeoutAte && m.timeoutAte>Date.now()?' · ⏱️ silenciado':'')+(m.warns?' · <span class="w">⚠️ '+m.warns+' advertência(s)</span>':'')+'</div></div>'
        + '<div class="actions">'
        + (podeMute ? '<button class="btn btn-warn" data-acao="timeout">Silenciar</button><button class="btn btn-muted" data-acao="untimeout">Remover silêncio</button>' : '')
        + (podeWarn ? '<button class="btn btn-warn" data-acao="warn">Advertir</button>' : '')
        + (podeKick ? '<button class="btn btn-danger" data-acao="kick">Expulsar</button>' : '')
        + (podeBan ? '<button class="btn btn-danger" data-acao="ban">Banir</button>' : '')
        + '</div></div>').join('');
      results.querySelectorAll('button[data-acao]').forEach(btn => btn.onclick = () => executarAcao(btn.closest('.member-card').dataset.id, btn.dataset.acao));
    } catch (err) { results.innerHTML = '<p class="empty" style="color:#ff8fa3">'+err.message+'</p>'; }
  };
  document.getElementById('searchBtn').onclick = doSearch;
  document.getElementById('searchInput').onkeydown = e => { if (e.key==='Enter') doSearch(); };
}
async function executarAcao(userId, acao) {
  let motivo = '', minutos = 10;
  const nomes = { ban:'banir', kick:'expulsar', timeout:'silenciar', untimeout:'remover silêncio de', warn:'advertir' };
  if (acao === 'ban' || acao === 'kick' || acao === 'warn') {
    motivo = prompt('Motivo para '+nomes[acao]+':') || '';
    if (!confirm('Confirmar ação: '+nomes[acao]+'?')) return;
  }
  if (acao === 'timeout') {
    minutos = Number(prompt('Silenciar por quantos minutos?', '10')) || 10;
    motivo = prompt('Motivo (opcional):') || '';
  }
  try {
    await api('/api/dashboard/guilds/'+state.guildId+'/members/'+userId+'/'+acao, { method:'POST', body: JSON.stringify({ motivo, minutos }) });
    toast('Ação aplicada com sucesso.');
    renderMod();
  } catch (err) { toast(err.message, false); }
}
async function renderActions() {
  const main = document.getElementById('main');
  main.innerHTML = '<h2>📋 Ações recentes</h2><div class="skeleton" style="height:60px;margin-bottom:8px"></div><div class="skeleton" style="height:60px"></div>';
  try {
    const lista = await api('/api/dashboard/guilds/'+state.guildId+'/actions/recent');
    if (!lista.length) { main.innerHTML = '<h2>📋 Ações recentes</h2><p class="empty">Nenhuma ação de moderação registrada ainda.</p>'; return; }
    main.innerHTML = '<h2>📋 Ações recentes</h2>' + lista.map(a => {
      const data = new Date(a.em).toLocaleString('pt-BR');
      return '<div class="action-item"><span class="tag-acao tag-'+a.acao+'">'+a.acao+'</span><div style="flex:1"><b>'+(a.alvoTag||a.alvo)+'</b>'+(a.motivo?' — '+a.motivo:'')+'<div class="meta">por '+a.por+' · '+data+'</div></div></div>';
    }).join('');
  } catch (err) { main.innerHTML = '<h2>📋 Ações recentes</h2><p class="empty" style="color:#ff8fa3">'+err.message+'</p>'; }
}
function closeLogStream(){
  if (state.logSource) { state.logSource.close(); state.logSource = null; }
}
function logLine(entry){
  const lv = entry.nivel || 'INFO';
  const el = document.createElement('div');
  el.className = 'log-line';
  el.innerHTML = '<span class="lv lv-'+lv+'">'+lv+'</span><span class="mod">['+entry.modulo+']</span><span class="msg">'+escapeHtml(entry.msg)+(entry.extra?' <span style="color:#8a7d92">'+escapeHtml(entry.extra)+'</span>':'')+'</span>';
  return el;
}
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
async function renderLogs() {
  const main = document.getElementById('main');
  main.innerHTML = '<div class="topbar"><h2>🖥️ Logs em tempo real</h2><span class="live-badge"><span class="dot"></span>Conectando…</span></div><div class="logs-box" id="logsBox"></div>';
  const box = document.getElementById('main').querySelector('.logs-box');
  const badge = document.querySelector('.live-badge');
  try {
    const recentes = await api('/api/dashboard/logs/recent');
    recentes.forEach(e => box.prepend(logLine(e)));
  } catch {}
  closeLogStream();
  const es = new EventSource('/api/dashboard/logs/stream');
  state.logSource = es;
  es.onopen = () => { if (badge) badge.innerHTML = '<span class="dot"></span>Ao vivo'; };
  es.onerror = () => { if (badge) badge.innerHTML = '<span class="dot" style="background:#ffb020"></span>Reconectando…'; };
  es.onmessage = (ev) => {
    try {
      const entry = JSON.parse(ev.data);
      box.prepend(logLine(entry));
      while (box.children.length > 300) box.removeChild(box.lastChild);
    } catch {}
  };
}
boot();
</script></body></html>`;
}

// ============================================================================
// HANDLER PRINCIPAL — roteia manualmente com base na URL
// ============================================================================
export default async function dashboardHandler(req, res, next) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const pathname = url.pathname;

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
        return sendHtml(res, 403, `<html><body style="background:#050307;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;text-align:center"><h2>🚫 Acesso negado</h2><p>Sua conta não tem staff/admin em nenhum servidor gerenciado pelo bot.</p></body></html>`);
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

    if (pathname === '/dashboard/login-senha' && req.method === 'POST') {
      const body = await readBody();
      if (!senhaValida(body?.senha)) return sendJson(res, 401, { erro: 'Senha incorreta.' });
      if (!DASHBOARD_OWNER_ID) return sendJson(res, 500, { erro: 'DASHBOARD_OWNER_ID não configurado na Vercel.' });

      setSessionCookie(res, {
        id: DASHBOARD_OWNER_ID,
        nome: 'Acesso por senha',
        avatar: 'https://cdn.discordapp.com/embed/avatars/0.png',
        exp: Date.now() + 12 * 60 * 60 * 1000,
      });
      return sendJson(res, 200, { ok: true });
    }

    if (pathname === '/dashboard/logout') {
      clearSessionCookie(res);
      res.statusCode = 302;
      res.setHeader('Location', '/dashboard');
      return res.end();
    }

    // ── Página principal ───────────────────────────────────────────────────
    if (pathname === '/dashboard' || pathname === '/') {
      return sendHtml(res, 200, pageShell('<div class="loading"><div class="spinner"></div>Carregando…</div>'));
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

      // ── logs (somente dono) ────────────────────────────────────────────
      if (pathname === '/api/dashboard/logs/recent') {
        const r = await botApi(`/logs/recent?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      if (pathname === '/api/dashboard/logs/stream') {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache, no-transform');
        res.setHeader('Connection', 'keep-alive');
        res.flushHeaders?.();
        try {
          const upstream = await fetch(`${BOT_API_BASE_URL}/api/internal/logs/stream?userId=${user.id}`, {
            headers: { 'x-dashboard-secret': DASHBOARD_API_SECRET },
          });
          if (!upstream.ok || !upstream.body) {
            res.write(`data: ${JSON.stringify({ nivel:'ERROR', modulo:'DASHBOARD', msg:'Não foi possível conectar ao bot.' })}\n\n`);
            return res.end();
          }
          const reader = upstream.body.getReader();
          const decoder = new TextDecoder();
          req.on('close', () => { try { reader.cancel(); } catch {} });
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            res.write(decoder.decode(value, { stream: true }));
          }
          return res.end();
        } catch (err) {
          res.write(`data: ${JSON.stringify({ nivel:'ERROR', modulo:'DASHBOARD', msg:'Conexão perdida com o bot.' })}\n\n`);
          return res.end();
        }
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

      const mWarns = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/members\/([^/]+)\/warns$/);
      if (mWarns) {
        const r = await botApi(`/guilds/${mWarns[1]}/members/${mWarns[2]}/warns?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      const mActions = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/actions\/recent$/);
      if (mActions) {
        const r = await botApi(`/guilds/${mActions[1]}/actions/recent?userId=${user.id}`);
        return sendJson(res, r.status, r.data);
      }

      const mAcao = pathname.match(/^\/api\/dashboard\/guilds\/([^/]+)\/members\/([^/]+)\/(ban|kick|timeout|untimeout|warn)$/);
      if (mAcao && req.method === 'POST') {
        const body = await readBody();
        const r = await botApi(`/guilds/${mAcao[1]}/members/${mAcao[2]}/${mAcao[3]}`, { method: 'POST', body: { ...body, requesterId: user.id } });
        return sendJson(res, r.status, r.data);
      }

      return sendJson(res, 404, { erro: 'Rota não encontrada.' });
    }

    return next ? next() : sendHtml(res, 404, 'Página não encontrada.');
  } catch (err) {
    return sendJson(res, 500, { erro: 'Erro interno.', detalhe: err?.message });
  }
}
