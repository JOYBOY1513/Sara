'use strict';
/* Sara front-end (vanilla JS single-page app) */
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const LV = { Low: '#22c55e', Medium: '#eab308', High: '#f97316', Critical: '#ef4444' };
const fmt = t => new Date(t).toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
const fmtD = t => new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
let me = null, stats = null, rt = 0, openAfter = null;

async function api(p, method = 'GET', body) {
  const r = await fetch('/api' + p, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  let d = {}; try { d = await r.json(); } catch { }
  if (!r.ok) { if (r.status === 401 && me && !p.startsWith('/login')) { me = null; renderAcct(); } throw new Error(d.error || 'Request failed'); }
  return d;
}
let tt; function toast(m) { const t = $('#toast'); t.textContent = m; t.classList.add('show'); clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2600); }
async function refreshMe() { try { const d = await api('/me'); me = d.user; stats = d.stats || null; } catch { me = null; } renderAcct(); }

/* ---------- Header account area ---------- */
function renderAcct() {
  const a = $('#acct');
  if (!me) { a.innerHTML = '<a class="btn sm" href="#/login">Sign in</a><a class="btn sm primary" href="#/signup">Sign up</a>'; return; }
  a.innerHTML = `<button class="avatar" id="av" aria-haspopup="true" aria-label="Account menu">${esc(me.name[0].toUpperCase())}</button>
  <div class="menu" id="menu" hidden><div class="who">${esc(me.name)}<br>${esc(me.email)}</div>
  <a href="#/profile">Profile</a>${me.role === 'admin' ? '<a href="#/admin">Admin panel</a>' : ''}<button id="out">Sign out</button></div>`;
  $('#av').onclick = e => { e.stopPropagation(); $('#menu').hidden = !$('#menu').hidden; };
  $('#out').onclick = async () => { await api('/logout', 'POST', {}); me = null; stats = null; renderAcct(); location.hash = '#/'; route(); toast('Signed out'); };
}
document.addEventListener('click', e => {
  const m = $('#menu'); if (m && !e.target.closest('#acct')) m.hidden = true;
  const p = $('#pop'); if (p && !e.target.closest('#pop,#plus')) p.hidden = true;
});

/* ---------- Router ---------- */
const pages = { '': chatPage, login: () => authPage('login'), signup: () => authPage('signup'), 'admin-login': () => authPage('admin'), profile: profilePage, community: communityPage, about: aboutPage, admin: adminPage };
function route() {
  rt++; const r = location.hash.replace(/^#\/?/, '').split('?')[0];
  document.querySelectorAll('#nav a').forEach(a => a.classList.toggle('on', a.dataset.r === r));
  const m = $('#menu'); if (m) m.hidden = true;
  $('#app').innerHTML = ''; (pages[r] || chatPage)(rt); $('#app').scrollTop = 0;
}
addEventListener('hashchange', route);

/* ---------- Auth pages ---------- */
function authPage(mode) {
  if (me && mode !== 'admin') { location.hash = '#/'; return; }
  if (me && me.role === 'admin' && mode === 'admin') { location.hash = '#/admin'; return; }
  const T = { login: ['Welcome back', 'Sign in to Sara'], signup: ['Create your account', 'Save your scans and access them anywhere'], admin: ['Admin sign in', 'Restricted area for Sara administrators'] }[mode];
  $('#app').innerHTML = `<div class="page"><div class="card auth"><div style="text-align:center;margin-bottom:14px"><span class="logo" style="margin:0 auto 10px">S</span><h1>${T[0]}</h1><div class="mut">${T[1]}</div></div>
  <form id="f" novalidate><div id="err"></div>
  ${mode === 'signup' ? '<div class="f"><label for="n">Full name</label><input type="text" id="n" name="name" autocomplete="name" required></div>' : ''}
  <div class="f"><label for="e">Email</label><input type="email" id="e" name="email" autocomplete="email" required></div>
  <div class="f"><label for="p">Password</label><div class="pw"><input type="password" id="p" name="password" autocomplete="${mode === 'signup' ? 'new-password' : 'current-password'}" required><button type="button" id="sp" aria-label="Show password">Show</button></div></div>
  ${mode === 'signup' ? '<div class="f"><label for="p2">Confirm password</label><input type="password" id="p2" name="confirm" autocomplete="new-password" required><div class="mut" style="font-size:12px;margin-top:4px">8+ characters with a letter and a number.</div></div>' : ''}
  <button class="btn primary" style="width:100%;justify-content:center" id="go">${{ login: 'Sign in', signup: 'Create account', admin: 'Sign in as admin' }[mode]}</button></form>
  <p class="mut" style="text-align:center;margin:16px 0 0;font-size:14px">${mode === 'login' ? 'New to Sara? <a href="#/signup">Create an account</a><br><a href="#/admin-login">Admin sign in</a>' : mode === 'signup' ? 'Already have an account? <a href="#/login">Sign in</a>' : '<a href="#/login">Back to user sign in</a>'}</p></div></div>`;
  $('#sp').onclick = () => { const i = $('#p'), s = i.type === 'password'; i.type = s ? 'text' : 'password'; $('#sp').textContent = s ? 'Hide' : 'Show'; };
  $('#f').onsubmit = async e => {
    e.preventDefault(); const d = Object.fromEntries(new FormData(e.target)); const err = m => $('#err').innerHTML = m ? `<div class="err">${esc(m)}</div>` : '';
    err('');
    if (!d.email || !d.password || (mode === 'signup' && !d.name)) return err('Please fill in all fields.');
    if (mode === 'signup' && d.password !== d.confirm) return err('Passwords do not match.');
    const b = $('#go'); b.disabled = true;
    try {
      await api(mode === 'admin' ? '/admin/login' : '/' + mode, 'POST', d);
      await refreshMe(); toast(mode === 'signup' ? 'Welcome to Sara!' : 'Signed in'); location.hash = mode === 'admin' ? '#/admin' : '#/';
    } catch (x) { err(x.message); b.disabled = false; }
  };
}

/* ---------- Gauge ---------- */
function arc(a0, a1, col) {
  const p = a => { const t = (180 - a) * Math.PI / 180; return [(110 + 90 * Math.cos(t)).toFixed(2), (110 - 90 * Math.sin(t)).toFixed(2)]; };
  const [x0, y0] = p(a0), [x1, y1] = p(a1);
  return `<path d="M${x0} ${y0}A90 90 0 0 1 ${x1} ${y1}" stroke="${col}" stroke-width="16" fill="none"/>`;
}
const gauge = () => `<svg class="gauge" viewBox="0 0 220 140" role="img" aria-label="Risk gauge">${arc(1, 44, LV.Low)}${arc(46, 89, LV.Medium)}${arc(91, 134, LV.High)}${arc(136, 179, LV.Critical)}
<text x="20" y="130" fill="#8f9ab0" font-size="11" text-anchor="middle">0</text><text x="200" y="130" fill="#8f9ab0" font-size="11" text-anchor="middle">100</text>
<g class="needle"><line x1="110" y1="110" x2="110" y2="38" stroke="#e8ecf4" stroke-width="3" stroke-linecap="round"/></g><circle cx="110" cy="110" r="8" fill="#e8ecf4"/><circle cx="110" cy="110" r="3" fill="#0a0c11"/></svg>`;

function resultHTML(d) {
  const r = d.result, col = LV[r.level], sev = w => w >= 50 ? '#ef4444' : w >= 30 ? '#f97316' : '#eab308';
  return `<div class="res"><div class="gwrap">${gauge()}<div class="score" style="color:${col}"><span class="num">0</span><small style="font-size:16px;color:var(--mut)">/100</small></div>
  <div style="margin-top:8px"><span class="badge b-${r.level.toLowerCase()}">${r.level} risk</span> <span class="mut" style="font-size:13px">confidence: ${esc(r.confidence)}</span></div></div>
  <p style="text-align:center;margin:12px 0 4px">${esc(r.summary)}</p>
  ${r.findings.length ? `<div class="list-sec"><h3>Warning signs</h3>${r.findings.map(f => `<div class="fi"><span class="dot" style="background:${sev(f.weight)};margin-top:7px"></span><div><b>${esc(f.title)}</b><small>${esc(f.detail)}</small></div></div>`).join('')}</div>` : ''}
  ${r.urls.length ? `<div class="list-sec"><h3>Links checked</h3><ul class="plain">${r.urls.map(u => `<li><code>${esc(u.host)}</code> ${u.flags.length ? '<span class="mut">- ' + u.flags.map(f => esc(f.t)).join('; ') + '</span>' : '<span class="mut">- no issues found</span>'}</li>`).join('')}</ul></div>` : ''}
  ${r.good.length ? `<div class="list-sec"><h3>Reassuring signs</h3><ul class="plain">${r.good.map(g => `<li>${esc(g)}</li>`).join('')}</ul></div>` : ''}
  ${r.notes?.length ? `<div class="list-sec"><h3>Notes</h3><ul class="plain">${r.notes.map(g => `<li>${esc(g)}</li>`).join('')}</ul></div>` : ''}
  <div class="list-sec"><h3>What to do</h3><ul class="plain">${r.advice.map(g => `<li>${esc(g)}</li>`).join('')}</ul></div>
  <div class="row" style="margin-top:14px"><button class="btn sm" data-copy>Copy report</button><span class="mut" style="font-size:13px">${d.saved ? 'Saved to your history' : '<a href="#/login">Sign in</a> to save scans'}</span></div></div>`;
}
function animateResult(el, d) {
  const n = el.querySelector('.needle'), num = el.querySelector('.num'), s = d.result.score;
  requestAnimationFrame(() => requestAnimationFrame(() => { n.style.transform = `rotate(${s * 1.8 - 90}deg)`; }));
  const t0 = performance.now(); (function step(t) { const k = Math.min(1, (t - t0) / 1200); num.textContent = Math.round(s * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); })(t0);
  el.querySelector('[data-copy]').onclick = async () => {
    const r = d.result, txt = `Sara report\nRisk score: ${r.score}/100 (${r.level})\n${r.summary}\n\nWarning signs:\n${r.findings.map(f => '- ' + f.title).join('\n') || '- none'}\n\nWhat to do:\n${r.advice.map(a => '- ' + a).join('\n')}`;
    try { await navigator.clipboard.writeText(txt); toast('Report copied'); } catch { toast('Copy not available in this browser'); }
  };
}

/* ---------- Chat page ---------- */
const OK_EXT = ['.pdf', '.docx', '.txt', '.csv', '.md', '.html', '.htm', '.eml', '.json'];
const SAMPLES = ['Congratulations! You are selected for a work from home data entry job at TCS. Earn ₹40,000 per week. Pay ₹1,500 refundable registration fee to confirm. Contact HR on WhatsApp urgently!',
  'Hi, this is Priya from the recruiting team. We would like to schedule a technical round next week. Please apply through our careers page at careers.google.com',
  'http://infosys-careers-apply.xyz/offer - send your Aadhaar and bank details to hr.infosys@gmail.com to receive your offer letter'];
let pend = [], busy = false, ocrP = null;

function chatPage(t) {
  pend = [];
  $('#app').innerHTML = `<div class="chat"><aside class="side" id="side"><button class="btn primary" id="newc" style="justify-content:center">+ New scan</button>
  ${me ? '<input type="text" id="hq" placeholder="Search history..." aria-label="Search history"><div class="list" id="hl"></div><button class="btn danger sm" id="clr" style="justify-content:center">Clear all history</button>'
      : '<div class="mut" style="padding:6px 4px">Your previous searches are saved when you <a href="#/login">sign in</a> or <a href="#/signup">sign up</a>.</div><div class="list"></div>'}</aside>
  <section class="main"><button class="ib tg" id="tg" aria-label="Toggle history">&#9776;</button><div class="msgs"><div class="msgs-in" id="mi"></div></div>
  <div class="comp"><div class="comp-in" style="position:relative"><div class="pend" id="pend"></div>
  <div class="pop" id="pop" hidden><button data-pick="photo">&#128247; Upload photo</button><button data-pick="file">&#128206; Upload file</button></div>
  <div class="box"><button class="ib" id="plus" aria-label="Add photo or file" aria-haspopup="true">+</button>
  <textarea id="in" rows="1" placeholder="Paste a job message, email or link to check..." aria-label="Message"></textarea>
  <button class="ib send" id="send" aria-label="Send">&#10148;</button></div>
  <input type="file" id="fp" accept="image/*" multiple hidden><input type="file" id="ff" accept="${OK_EXT.join(',')}" multiple hidden>
  <div class="hint">Sara estimates risk and can be wrong. Verify employers independently.</div></div></div></section></div>`;
  hero();
  const ta = $('#in'), size = () => { ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 180) + 'px'; };
  ta.oninput = size; ta.onkeydown = e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
  $('#send').onclick = send;
  $('#plus').onclick = () => { $('#pop').hidden = !$('#pop').hidden; };
  $('#pop').onclick = e => { const b = e.target.closest('[data-pick]'); if (!b) return; $('#pop').hidden = true; (b.dataset.pick === 'photo' ? $('#fp') : $('#ff')).click(); };
  $('#fp').onchange = $('#ff').onchange = e => { addFiles([...e.target.files]); e.target.value = ''; };
  $('#pend').onclick = e => { const b = e.target.closest('.rm'); if (b) { const [f] = pend.splice(+b.dataset.i, 1); if (f.thumb) URL.revokeObjectURL(f.thumb); renderPend(); } };
  const main = $('.main'); main.ondragover = e => { e.preventDefault(); main.classList.add('drop'); }; main.ondragleave = () => main.classList.remove('drop');
  main.ondrop = e => { e.preventDefault(); main.classList.remove('drop'); addFiles([...e.dataTransfer.files]); };
  ta.onpaste = e => { const f = [...(e.clipboardData?.files || [])]; if (f.length) { e.preventDefault(); addFiles(f); } };
  $('#tg').onclick = () => $('#side').classList.toggle('open');
  $('#newc').onclick = () => { $('#side').classList.remove('open'); document.querySelectorAll('.hi.on').forEach(x => x.classList.remove('on')); hero(); ta.focus(); };
  if (me) {
    let dt; $('#hq').oninput = () => { clearTimeout(dt); dt = setTimeout(() => loadHistory(), 250); };
    $('#hl').onclick = async e => {
      const row = e.target.closest('.hi'); if (!row) return; const id = row.dataset.id;
      if (e.target.closest('.x')) { if (!confirm('Delete this search from your history?')) return; try { await api('/history/' + id, 'DELETE', {}); if (row.classList.contains('on')) hero(); loadHistory(); } catch (x) { toast(x.message); } return; }
      openHistory(id);
    };
    $('#clr').onclick = async () => { if (!confirm('Delete ALL your saved searches? This cannot be undone.')) return; try { await api('/history', 'DELETE', {}); hero(); loadHistory(); toast('History cleared'); } catch (x) { toast(x.message); } };
    loadHistory().then(() => { if (openAfter && t === rt) { const id = openAfter; openAfter = null; openHistory(id); } });
  }
}
function hero() {
  $('#mi').innerHTML = `<div class="hero"><span class="logo">S</span><h1>What should Sara check?</h1><div class="mut">Paste a job offer, recruiter message, email or link, or upload a screenshot or document with the <b>+</b> button.</div>
  <div class="chips">${SAMPLES.map((s, i) => `<button class="chip" data-s="${i}">Try example ${i + 1}</button>`).join('')}</div></div>`;
  $('.chips').onclick = e => { const b = e.target.closest('[data-s]'); if (!b) return; const ta = $('#in'); ta.value = SAMPLES[b.dataset.s]; ta.dispatchEvent(new Event('input')); ta.focus(); };
}
async function loadHistory(activeId) {
  if (!me || !$('#hl')) return;
  try {
    const { items } = await api('/history?q=' + encodeURIComponent($('#hq')?.value || ''));
    const cur = activeId || $('.hi.on')?.dataset.id;
    $('#hl').innerHTML = items.length ? items.map(h => `<div class="hi${String(h.id) === String(cur) ? ' on' : ''}" data-id="${h.id}" tabindex="0"><span class="dot" style="background:${LV[h.level]}"></span><div class="t"><div>${esc(h.query)}</div><small>${h.score}/100 &middot; ${fmt(h.created)}</small></div><button class="x" aria-label="Delete search">&#10005;</button></div>`).join('') : '<div class="mut" style="padding:8px;font-size:13px">No searches yet.</div>';
  } catch { }
}
async function openHistory(id) {
  try {
    const d = await api('/history/' + id); d.saved = true; $('#side').classList.remove('open');
    document.querySelectorAll('.hi').forEach(x => x.classList.toggle('on', x.dataset.id == id));
    $('#mi').innerHTML = ''; userMsg(d.query, d.files.map(f => ({ name: f.name, thumb: f.image ? f.url : null })));
    const am = asstMsg(''); am.innerHTML = resultHTML(d); animateResult(am, d);
  } catch (x) { toast(x.message); }
}
const chipHTML = f => `<div class="f">${f.thumb ? `<img src="${esc(f.thumb)}" alt="">` : '&#128196;'}<span>${esc(f.name)}</span></div>`;
function userMsg(text, files) {
  const d = document.createElement('div'); d.className = 'um';
  d.innerHTML = esc(text) + (files.length ? `<div class="att">${files.map(chipHTML).join('')}</div>` : ''); $('#mi').appendChild(d); scrollDown(); return d;
}
function asstMsg(html) {
  const d = document.createElement('div'); d.className = 'am'; d.innerHTML = '<span class="logo">S</span><div class="body"></div>'; $('#mi').appendChild(d);
  const b = d.querySelector('.body'); b.innerHTML = html; scrollDown(); return b;
}
const scrollDown = () => { const m = $('.msgs'); if (m) setTimeout(() => m.scrollTo({ top: m.scrollHeight, behavior: 'smooth' }), 30); };
function renderPend() {
  $('#pend').innerHTML = pend.map((f, i) => `<div class="f">${f.thumb ? `<img src="${esc(f.thumb)}" alt="">` : '&#128196;'}<span>${esc(f.name)}</span><button class="rm" data-i="${i}" aria-label="Remove ${esc(f.name)}">&times;</button></div>`).join('');
}
function addFiles(list) {
  for (const f of list) {
    if (pend.length >= 4) { toast('You can attach up to 4 files'); break; }
    const ext = (f.name.match(/\.\w+$/) || [''])[0].toLowerCase(), image = f.type.startsWith('image/');
    if (!image && !OK_EXT.includes(ext)) { toast(`${f.name}: unsupported type`); continue; }
    if (f.size > (image ? 15e6 : 5e6)) { toast(`${f.name}: too large (max ${image ? 15 : 5} MB)`); continue; }
    pend.push({ blob: f, name: f.name || 'pasted-image.png', image, thumb: image ? URL.createObjectURL(f) : null });
  }
  renderPend();
}
async function shrink(blob) {
  if (!/^image\/(png|jpe?g|webp)$/.test(blob.type)) return blob;
  try {
    const bm = await createImageBitmap(blob), k = Math.min(1, 1600 / Math.max(bm.width, bm.height)), c = document.createElement('canvas');
    c.width = Math.round(bm.width * k); c.height = Math.round(bm.height * k); c.getContext('2d').drawImage(bm, 0, 0, c.width, c.height);
    return await new Promise(r => c.toBlob(b => r(b || blob), 'image/jpeg', .88));
  } catch { return blob; }
}
function ocrImage(blob) {
  ocrP = ocrP || new Promise((ok, no) => { if (window.Tesseract) return ok(); const s = document.createElement('script'); s.src = 'https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js'; s.onload = ok; s.onerror = () => { ocrP = null; no(); }; document.head.appendChild(s); });
  return ocrP.then(() => Tesseract.recognize(blob, 'eng')).then(r => r.data.text || '');
}
const b64 = blob => new Promise(r => { const fr = new FileReader(); fr.onload = () => r(String(fr.result).split(',')[1]); fr.readAsDataURL(blob); });

async function send() {
  const ta = $('#in'); const text = ta.value.trim();
  if (busy || (!text && !pend.length)) return;
  busy = true; $('#send').disabled = true;
  const files = pend.splice(0); ta.value = ''; ta.style.height = 'auto'; renderPend();
  if ($('.hero')) $('#mi').innerHTML = '';
  document.querySelectorAll('.hi.on').forEach(x => x.classList.remove('on'));
  userMsg(text, files); const am = asstMsg('<div class="typing"><span></span><span></span><span></span></div>');
  try {
    const out = [];
    for (const f of files) {
      let blob = f.blob, name = f.name, ocr = '';
      if (f.image) {
        blob = await shrink(f.blob); if (blob !== f.blob) name = name.replace(/\.\w+$/, '') + '.jpg';
        am.innerHTML = '<span class="mut">Reading text in image&hellip;</span>';
        try { ocr = await ocrImage(blob); } catch { }
      }
      out.push({ name, data: await b64(blob), ocr });
    }
    am.innerHTML = '<div class="typing"><span></span><span></span><span></span></div>';
    const d = await api('/scan', 'POST', { text, files: out });
    am.innerHTML = resultHTML(d); animateResult(am, d); am.closest('.am').scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (d.saved) { loadHistory(d.id); refreshMe(); }
  } catch (e) { am.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  busy = false; $('#send') && ($('#send').disabled = false); $('#in') && $('#in').focus();
}

/* ---------- Profile ---------- */
async function profilePage(t) {
  if (!me) { location.hash = '#/login'; return; }
  await refreshMe(); if (t !== rt || !me) return;
  let recent = []; try { recent = (await api('/history')).items.slice(0, 5); } catch { }
  if (t !== rt) return;
  $('#app').innerHTML = `<div class="page"><div class="card" style="margin-bottom:16px"><div class="row" style="gap:16px"><div class="avatar" style="width:64px;height:64px;font-size:28px;display:grid;place-items:center">${esc(me.name[0].toUpperCase())}</div>
  <div style="flex:1;min-width:200px"><h1 style="margin:0">${esc(me.name)}</h1><div class="mut">${esc(me.email)} &middot; ${me.role === 'admin' ? 'Administrator' : 'Member'} &middot; joined ${fmtD(me.created)}</div></div><button class="btn" id="so">Sign out</button></div>
  <div class="grid" style="margin-top:16px"><div class="stat"><span class="mut">Scans</span><b>${stats?.searches ?? 0}</b></div><div class="stat"><span class="mut">Average risk</span><b>${stats?.avgScore ?? '-'}</b></div><div class="stat"><span class="mut">Last scan</span><b style="font-size:16px;padding-top:8px">${stats?.last ? fmtD(stats.last) : 'None yet'}</b></div></div></div>
  <div class="card" style="margin-bottom:16px"><h2>Recent searches</h2>${recent.length ? recent.map(h => `<div class="hi" data-open="${h.id}"><span class="dot" style="background:${LV[h.level]}"></span><div class="t"><div>${esc(h.query)}</div><small>${h.score}/100 &middot; ${fmt(h.created)}</small></div></div>`).join('') : '<div class="mut">Nothing yet. <a href="#/">Run your first scan</a>.</div>'}</div>
  <div class="card" style="margin-bottom:16px"><h2>Edit profile</h2><form id="pf" novalidate><div id="pm"></div><div class="f"><label for="pn">Name</label><input type="text" id="pn" name="name" value="${esc(me.name)}"></div><div class="f"><label for="pe">Email</label><input type="email" id="pe" name="email" value="${esc(me.email)}"></div>
  <div class="f"><label for="pc">Current password (needed only to change email)</label><input type="password" id="pc" name="currentPassword" autocomplete="current-password"></div><button class="btn primary">Save changes</button></form></div>
  <div class="card" style="margin-bottom:16px"><h2>Change password</h2><form id="pw" novalidate><div id="pwm"></div><div class="f"><label for="c1">Current password</label><input type="password" id="c1" name="currentPassword" autocomplete="current-password"></div><div class="f"><label for="c2">New password</label><input type="password" id="c2" name="newPassword" autocomplete="new-password"></div><button class="btn primary">Update password</button></form></div>
  ${me.role === 'admin' ? '' : `<div class="card"><h2>Delete account</h2><p class="mut">Permanently removes your account and all saved searches.</p><form id="del" class="row" novalidate><input type="password" name="password" placeholder="Confirm password" aria-label="Confirm password" style="max-width:260px" autocomplete="current-password"><button class="btn danger">Delete my account</button></form></div>`}</div>`;
  const msg = (id, m, ok) => $(id).innerHTML = m ? `<div class="${ok ? 'ok' : 'err'}">${esc(m)}</div>` : '';
  $('#so').onclick = () => $('#out').click();
  $('.page').onclick = e => { const r = e.target.closest('[data-open]'); if (r) { openAfter = r.dataset.open; location.hash = '#/'; } };
  $('#pf').onsubmit = async e => { e.preventDefault(); msg('#pm', ''); try { await api('/me', 'PUT', Object.fromEntries(new FormData(e.target))); await refreshMe(); msg('#pm', 'Profile updated.', true); } catch (x) { msg('#pm', x.message); } };
  $('#pw').onsubmit = async e => { e.preventDefault(); msg('#pwm', ''); const d = Object.fromEntries(new FormData(e.target)); try { await api('/me', 'PUT', { ...d, name: me.name, email: me.email }); e.target.reset(); msg('#pwm', 'Password updated.', true); } catch (x) { msg('#pwm', x.message); } };
  const del = $('#del'); if (del) del.onsubmit = async e => { e.preventDefault(); if (!confirm('Delete your account permanently?')) return; try { await api('/me', 'DELETE', Object.fromEntries(new FormData(e.target))); me = null; renderAcct(); location.hash = '#/'; toast('Account deleted'); } catch (x) { toast(x.message); } };
}

/* ---------- Community ---------- */
async function communityPage(t) {
  $('#app').innerHTML = '<div class="page"><h1>Community alerts</h1><p class="mut">Recent ongoing recruitment frauds, posted by Sara admins. Stay one step ahead.</p><div id="pl" class="mut">Loading...</div></div>';
  try {
    const { items } = await api('/posts'); if (t !== rt) return;
    $('#pl').className = ''; $('#pl').innerHTML = (me?.role === 'admin' ? '<p><a class="btn sm" href="#/admin">Manage alerts</a></p>' : '') + (items.length ? items.map(p => `<div class="card post"><span class="badge b-${p.severity}">${esc(p.severity)}</span> <span class="mut" style="font-size:13px">${fmtD(p.created)} &middot; ${esc(p.author || 'Admin')}</span><h3>${esc(p.title)}</h3><p>${esc(p.body)}</p></div>`).join('') : '<div class="mut">No alerts right now.</div>');
  } catch (x) { if (t === rt) $('#pl').textContent = x.message; }
}

/* ---------- About ---------- */
function aboutPage() {
  $('#app').innerHTML = `<div class="page"><div class="card"><div class="row" style="margin-bottom:10px"><span class="logo">S</span><h1 style="margin:0">About Sara</h1></div>
  <p>Sara is a Smart Recruitment Scam Detection Platform. Paste a job offer, recruiter message, email or link, or upload a screenshot or document, and Sara returns a 0&ndash;100 risk score on a gauge with the exact warning signs behind it.</p>
  <h2>What Sara looks for</h2><ul class="plain"><li>Upfront fees, deposits, and refundable &ldquo;registration&rdquo; payments</li><li>Requests for OTPs, PINs, passwords, ID or bank details</li><li>Guaranteed jobs with no interview, and unrealistic pay</li><li>Recruiters on free email domains or WhatsApp/Telegram only</li><li>Look-alike, shortened, insecure or suspicious links</li><li>Urgency, secrecy and fake-cheque patterns</li></ul>
  <h2 style="margin-top:16px">How it works</h2><p>Signals are weighted and combined into one score. Images are read with in-browser text recognition; PDFs, Word and text files are read on the server. Sara gives an estimate and can miss new scams or flag genuine offers, so always confirm on the employer's official careers page.</p>
  <h2 style="margin-top:16px">Privacy</h2><p>Signed-in scans are saved to your history so you can reopen or delete them any time. Guest scans are not stored.</p>
  <p class="mut">Site administrator? <a href="#/admin-login">Admin sign in</a></p></div></div>`;
}

/* ---------- Admin ---------- */
let atab = 'overview', editing = null;
async function adminPage(t) {
  if (!me || me.role !== 'admin') { location.hash = '#/admin-login'; return; }
  $('#app').innerHTML = `<div class="page"><h1>Admin panel</h1><div class="tabs">${['overview', 'alerts', 'users'].map(k => `<button data-t="${k}" class="${k === atab ? 'on' : ''}">${k[0].toUpperCase() + k.slice(1)}</button>`).join('')}</div><div id="at">Loading...</div></div>`;
  $('.tabs').onclick = e => { const b = e.target.closest('[data-t]'); if (b) { atab = b.dataset.t; editing = null; adminPage(rt); } };
  const box = $('#at');
  try {
    if (atab === 'overview') {
      const s = await api('/admin/stats'); if (t !== rt) return; const max = Math.max(1, ...Object.values(s.levels));
      box.innerHTML = `<div class="grid"><div class="stat"><span class="mut">Users</span><b>${s.users}</b></div><div class="stat"><span class="mut">Scans</span><b>${s.scans}</b></div><div class="stat"><span class="mut">Alerts</span><b>${s.posts}</b></div><div class="stat"><span class="mut">Avg risk</span><b>${s.avg}</b></div></div>
      <div class="card" style="margin-top:16px"><h2>Scans by risk level</h2>${Object.entries(s.levels).map(([l, n]) => `<div class="row" style="margin:8px 0"><span style="width:70px">${l}</span><div style="flex:1;background:#0e121a;border-radius:99px;height:12px;overflow:hidden"><div style="width:${n / max * 100}%;height:100%;background:${LV[l]}"></div></div><b style="width:30px;text-align:right">${n}</b></div>`).join('')}</div>`;
    } else if (atab === 'alerts') {
      const { items } = await api('/posts'); if (t !== rt) return; const e = items.find(p => p.id === editing);
      box.innerHTML = `<div class="card" style="margin-bottom:16px"><h2>${e ? 'Edit alert' : 'Post a new alert'}</h2><form id="pf" novalidate><div id="pm"></div><div class="f"><label for="t1">Title</label><input type="text" id="t1" name="title" value="${esc(e?.title || '')}"></div>
      <div class="f"><label for="sv">Severity</label><select id="sv" name="severity">${['low', 'medium', 'high', 'critical'].map(s => `<option ${((e?.severity || 'medium') === s) ? 'selected' : ''}>${s}</option>`).join('')}</select></div>
      <div class="f"><label for="bd">Details</label><textarea id="bd" name="body" rows="4">${esc(e?.body || '')}</textarea></div><div class="row"><button class="btn primary">${e ? 'Save alert' : 'Publish alert'}</button>${e ? '<button type="button" class="btn" id="cx">Cancel</button>' : ''}</div></form></div>
      ${items.map(p => `<div class="card post"><span class="badge b-${p.severity}">${p.severity}</span> <span class="mut" style="font-size:13px">${fmtD(p.created)}</span><h3>${esc(p.title)}</h3><p>${esc(p.body)}</p><div class="row" style="margin-top:10px"><button class="btn sm" data-e="${p.id}">Edit</button><button class="btn sm danger" data-d="${p.id}">Delete</button></div></div>`).join('')}`;
      $('#pf').onsubmit = async ev => { ev.preventDefault(); try { await api(e ? '/posts/' + e.id : '/posts', e ? 'PUT' : 'POST', Object.fromEntries(new FormData(ev.target))); toast(e ? 'Alert updated' : 'Alert published'); editing = null; adminPage(rt); } catch (x) { $('#pm').innerHTML = `<div class="err">${esc(x.message)}</div>`; } };
      if (e) $('#cx').onclick = () => { editing = null; adminPage(rt); };
      box.onclick = async ev => {
        const ed = ev.target.closest('[data-e]'), dl = ev.target.closest('[data-d]');
        if (ed) { editing = +ed.dataset.e; adminPage(rt); scrollTo(0, 0); }
        if (dl && confirm('Delete this alert?')) { try { await api('/posts/' + dl.dataset.d, 'DELETE', {}); toast('Alert deleted'); adminPage(rt); } catch (x) { toast(x.message); } }
      };
    } else {
      const { items } = await api('/admin/users'); if (t !== rt) return;
      box.innerHTML = `<div class="card scroll-x"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Scans</th><th>Joined</th><th></th></tr></thead><tbody>${items.map(u => `<tr><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td>${u.role}</td><td>${u.scans}</td><td>${fmtD(u.created)}</td><td>${u.role === 'admin' ? '' : `<button class="btn sm danger" data-u="${u.id}">Remove</button>`}</td></tr>`).join('')}</tbody></table></div>`;
      box.onclick = async ev => { const b = ev.target.closest('[data-u]'); if (b && confirm('Remove this user and all their data?')) { try { await api('/admin/users/' + b.dataset.u, 'DELETE', {}); toast('User removed'); adminPage(rt); } catch (x) { toast(x.message); } } };
    }
  } catch (x) { if (t === rt) box.innerHTML = `<div class="err">${esc(x.message)}</div>`; }
}

/* ---------- Blue "slicing" cursor effect ---------- */
(function () {
  const cv = $('#fx'), cx = cv.getContext('2d'); if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  let W, H, cuts = [], last = null, mx = -999, my = -999, gx = -999, gy = -999;
  const rs = () => { const d = devicePixelRatio || 1; W = innerWidth; H = innerHeight; cv.width = W * d; cv.height = H * d; cx.setTransform(d, 0, 0, d, 0, 0); }; rs(); addEventListener('resize', rs);
  addEventListener('pointermove', e => {
    mx = e.clientX; my = e.clientY;
    if (last && Math.hypot(mx - last.x, my - last.y) > 22) {
      const a = Math.atan2(my - last.y, mx - last.x) + Math.PI / 2 + (Math.random() - .5) * .5;
      cuts.push({ x: mx, y: my, a, len: 70 + Math.random() * 110, life: 1 }); if (cuts.length > 36) cuts.shift(); last = { x: mx, y: my };
    } else if (!last) last = { x: mx, y: my };
  });
  (function loop() {
    cx.clearRect(0, 0, W, H); gx += (mx - gx) * .14; gy += (my - gy) * .14;
    if (mx > -900) { const g = cx.createRadialGradient(gx, gy, 0, gx, gy, 230); g.addColorStop(0, 'rgba(59,130,246,.16)'); g.addColorStop(1, 'rgba(59,130,246,0)'); cx.fillStyle = g; cx.fillRect(gx - 230, gy - 230, 460, 460); }
    for (const c of cuts) {
      const dx = Math.cos(c.a) * c.len, dy = Math.sin(c.a) * c.len, g = cx.createLinearGradient(c.x - dx, c.y - dy, c.x + dx, c.y + dy);
      g.addColorStop(0, 'rgba(96,165,250,0)'); g.addColorStop(.5, `rgba(96,165,250,${.85 * c.life})`); g.addColorStop(1, 'rgba(96,165,250,0)');
      cx.strokeStyle = g; cx.lineWidth = 1.6 * c.life + .4; cx.shadowColor = '#3b82f6'; cx.shadowBlur = 14 * c.life;
      cx.beginPath(); cx.moveTo(c.x - dx, c.y - dy); cx.lineTo(c.x + dx, c.y + dy); cx.stroke(); c.life -= .022;
    }
    cx.shadowBlur = 0; cuts = cuts.filter(c => c.life > 0); requestAnimationFrame(loop);
  })();
})();

/* ---------- Init ---------- */
$('#yr').textContent = new Date().getFullYear();
refreshMe().then(route);
