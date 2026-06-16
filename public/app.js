const BASE = '/api/v1';

// ── TOAST NOTIFICATIONS ──
function showToast(title, message, type = 'info') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  let icon = '[!]';
  if(type === 'success') icon = '[OK]';
  if(type === 'error') icon = '[ERRO]';

  // Construção via DOM + textContent: o título/mensagem podem conter
  // texto vindo do servidor — nunca interpolar em innerHTML (XSS).
  const iconEl = document.createElement('div');
  iconEl.className = 'toast-icon';
  iconEl.textContent = icon;

  const content = document.createElement('div');
  content.className = 'toast-content';
  const h4 = document.createElement('h4'); h4.textContent = title;
  const p  = document.createElement('p');  p.textContent  = message;
  content.append(h4, p);

  const progress = document.createElement('div');
  progress.className = 'toast-progress';

  toast.append(iconEl, content, progress);
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('closing');
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// ── THEME TOGGLE ──
function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  localStorage.setItem('dems_theme', isLight ? 'light' : 'dark');
}

// ── SIDEBAR (fonte única — injetada em todas as páginas) ──
// Antes a sidebar estava copiada em 7 ficheiros HTML; qualquer
// alteração obrigava a editar todos. Agora vive aqui e é injetada
// num <aside class="sidebar" id="sidebar"></aside>.
const NAV = [
  { group: 'Dashboard', items: [
    { href: '/',         label: 'Upload',             icon: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>' },
    { href: '/explorer', label: 'Blockchain',         icon: '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>' },
  ]},
  { group: 'Forense', items: [
    { href: '/verify',   label: 'Verificar Prova',    icon: '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>' },
    { href: '/analyse',  label: 'Análise Prévia',     icon: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>' },
    { href: '/custody',  label: 'Gestão de Custódia', icon: '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1" ry="1"/><path d="M15 14l-3 3-3-3"/><path d="M12 17V9"/>' },
    { href: '/terminal', label: 'Terminal',           icon: '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>' },
    { href: '/chaos',    label: 'Simulador de Falhas', icon: '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>', danger: true },
  ]},
];

function renderSidebar() {
  const el = document.getElementById('sidebar');
  if (!el) return;
  const path = window.location.pathname;
  const active = (href) => (href === '/' ? path === '/' : path.startsWith(href)) ? ' active' : '';
  const ico = (paths) => `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${paths}</svg>`;

  const groups = NAV.map(g => `
    <div class="nav-lbl">${g.group}</div>
    <div class="nav">
      ${g.items.map(it => `<a href="${it.href}" class="nav-btn${active(it.href)}"${it.danger ? ' style="color:#ff4444;"' : ''}>${ico(it.icon)} ${it.label}</a>`).join('')}
    </div>`).join('');

  el.innerHTML = `
    <div class="brand">
      <div class="brand-inner">
        <div class="logo"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
        <h1>Incorrupt</h1>
      </div>
      <button class="theme-toggle" onclick="toggleTheme()" title="Modo Claro/Escuro"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg></button>
    </div>
    ${groups}
    <div class="sb-footer spotlight">
      <div class="user-badge" id="userBadge" style="display:none"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> <span id="userBadgeText"></span></div>
      <div class="badge off" id="serverBadge"><div class="dot"></div> <span id="serverStatus">A carregar...</span></div>
      <button class="btn-logout" onclick="doLogout()">Terminar Sessão</button>
    </div>`;
}

// ── AUTH & INIT ──
// Páginas públicas (não exigem login): login, e a verificação/análise
// de ficheiros que qualquer cidadão pode usar.
const PUBLIC_PATHS = ['/login', '/verify', '/analyse'];

function isPublicPage() {
  return PUBLIC_PATHS.some(p => window.location.pathname.startsWith(p));
}

function initApp() {
  const token = localStorage.getItem('dems_token');
  if (!token && !isPublicPage()) {
    // Sem sessão e numa página protegida → vai para o login.
    window.location.href = '/login';
    return;
  }

  // Injeta a sidebar (fonte única) antes de usar os seus elementos.
  renderSidebar();

  // Restore theme
  if(localStorage.getItem('dems_theme') === 'light') {
    document.body.classList.add('light-theme');
  }

  // User Badge
  try {
    const u = JSON.parse(localStorage.getItem('dems_user') || '{}');
    const badgeText = document.getElementById('userBadgeText');
    if (badgeText && (u.name || u.email)) {
      badgeText.textContent = u.name || u.email;
      document.getElementById('userBadge').style.display = 'flex';
    }
  } catch {}

  if (!window.location.pathname.startsWith('/login')) {
    checkHealth();
    setInterval(checkHealth, 15000);
  }
}

function doLogout() {
  localStorage.removeItem('dems_token');
  localStorage.removeItem('dems_user');
  window.location.href = '/login';
}

// ── HEALTH CHECK ──
async function checkHealth() {
  const statusEl = document.getElementById('serverStatus');
  const badgeEl = document.getElementById('serverBadge');
  if(!statusEl) return;

  try {
    const d = await (await fetch(`${BASE}/health`)).json();
    const ok = d.quorum?.quorumAchievable;
    
    badgeEl.className = 'badge' + (ok ? '' : ' off');
    statusEl.textContent = ok ? 'Rede Online' : 'Falha no Quórum';
    
    const nodesVal = document.getElementById('statNodes');
    if(nodesVal) nodesVal.textContent = `${d.quorum?.healthy}/${d.quorum?.total}`;
    
    const quorumVal = document.getElementById('statQuorum');
    if(quorumVal) quorumVal.textContent = d.quorum?.quorumAchievable ? 'Garantido' : 'Falhou';
    
    const modeVal = document.getElementById('statMode');
    if(modeVal) modeVal.textContent = d.mode || 'N/A';
    
    const grid = document.getElementById('nodesGrid');
    if(grid) {
      grid.innerHTML = (d.auditNodes||[]).map((n,i)=>`
        <div class="node ${n.healthy?'up':'dn'} spotlight">
          <div class="node-hdr"><span class="node-nm">audit_node_${i+1}</span><span class="tag ${n.healthy?'':'dn'}">${n.healthy?'UP':'DOWN'}</span></div>
          <div class="node-uri" style="margin-top:8px">${n.uri||'in-memory'}</div>
        </div>`).join('');
    }
  } catch {
    badgeEl.className = 'badge off';
    statusEl.textContent = 'Rede Offline';
  }
}

// ── Definição de texto (sóbrio — sem efeito "scramble") ──
// Mantém a assinatura usada pelas páginas, mas escreve o valor de
// forma direta e legível (hashes lêem-se melhor sem animação).
function scrambleText(element, finalString) {
  element.textContent = finalString;
  element.setAttribute('data-text', finalString);
}

// ── CRYPTO (DIGITAL SIGNATURES) ──
async function initCryptoKeys() {
  if (localStorage.getItem('dems_privateKey') && localStorage.getItem('dems_publicKey')) return;
  
  const keyPair = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  
  const exportKey = async (k) => {
    const exported = await window.crypto.subtle.exportKey("jwk", k);
    return JSON.stringify(exported);
  };
  
  localStorage.setItem('dems_privateKey', await exportKey(keyPair.privateKey));
  localStorage.setItem('dems_publicKey', await exportKey(keyPair.publicKey));
  console.log("[Crypto] Chaves ECDSA geradas para Não-Repúdio.");
}

async function signData(dataStr) {
  const privKeyStr = localStorage.getItem('dems_privateKey');
  if(!privKeyStr) throw new Error("Chave Privada não encontrada");
  
  const privateKey = await window.crypto.subtle.importKey(
    "jwk", JSON.parse(privKeyStr),
    { name: "ECDSA", namedCurve: "P-256" },
    true, ["sign"]
  );
  
  const enc = new TextEncoder();
  const signatureBuffer = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    privateKey,
    enc.encode(dataStr)
  );
  
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  return signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getPublicKeyHex() {
  const pubKeyStr = localStorage.getItem('dems_publicKey');
  if(!pubKeyStr) return 'NONE';
  const pubKeyObj = JSON.parse(pubKeyStr);
  return pubKeyObj.x + pubKeyObj.y; // Simplified public key rep
}

// ── SCREEN LOCK (INACTIVITY) ──
let inactivityTimer;
const LOCK_TIME = 5 * 60 * 1000; // 5 minutos de inatividade
let isLocked = false;

function initScreenLock() {
  const token = localStorage.getItem('dems_token');
  if (!token) return; // Only lock if user is logged in

  // Inject Lock Screen HTML
  const lockHtml = `
    <div id="screenLockOverlay" class="screen-lock-overlay">
      <div class="screen-lock-modal">
        <h2>Sessão bloqueada</h2>
        <p>A sessão foi bloqueada por inatividade. Introduza a sua palavra-passe para continuar.</p>
        <input type="password" id="lockPassword" placeholder="Palavra-passe" onkeydown="if(event.key === 'Enter') unlockScreen()" autocomplete="off">
        <button onclick="unlockScreen()">Desbloquear</button>
      </div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', lockHtml);

  // Setup timers
  resetTimer();
  window.addEventListener('mousemove', resetTimer);
  window.addEventListener('keydown', resetTimer);
  window.addEventListener('click', resetTimer);
  window.addEventListener('scroll', resetTimer);
}

function resetTimer() {
  if (isLocked) return;
  clearTimeout(inactivityTimer);
  inactivityTimer = setTimeout(lockScreen, LOCK_TIME);
}

function lockScreen() {
  isLocked = true;
  document.getElementById('screenLockOverlay').classList.add('active');
  document.getElementById('lockPassword').value = '';
  setTimeout(() => document.getElementById('lockPassword').focus(), 100);
}

async function unlockScreen() {
  const pwd = document.getElementById('lockPassword').value;
  if (!pwd) return;

  const uStr = localStorage.getItem('dems_user');
  if (!uStr) return;
  const email = JSON.parse(uStr).email;

  try {
    const res = await fetch(BASE + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pwd })
    });
    
    if (res.ok) {
      const d = await res.json();
      localStorage.setItem('dems_token', d.token);
      document.getElementById('screenLockOverlay').classList.remove('active');
      isLocked = false;
      resetTimer();
      showToast('Sessão Reativada', 'Autenticação confirmada.', 'success');
    } else {
      showToast('Acesso Negado', 'Palavra-passe incorreta.', 'error');
      document.getElementById('lockPassword').value = '';
    }
  } catch(e) {
    showToast('Erro', 'Falha na comunicação com o servidor.', 'error');
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    initScreenLock();
    if(window.location.pathname.includes('/login') === false) {
        initCryptoKeys();
    }
});
