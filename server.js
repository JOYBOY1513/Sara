'use strict';
// Sara – Smart Recruitment Scam Detection. Zero-dependency backend (Node >= 22.5).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');
const { DatabaseSync } = require('node:sqlite');

const PORT = process.env.PORT || 3000;
const PUB = path.join(__dirname, 'public'), DATA = path.join(__dirname, 'data'), UP = path.join(DATA, 'uploads');
fs.mkdirSync(UP, { recursive: true });

/* ---------- Database ---------- */
const db = new DatabaseSync(path.join(DATA, 'sara.db'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS searches(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, query TEXT, score INTEGER, level TEXT, result TEXT, files TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, severity TEXT NOT NULL DEFAULT 'medium', author TEXT, created INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS ix_searches ON searches(user_id, created DESC);`);

const now = () => Date.now();
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function addUser(name, email, pw, role = 'user') {
  const salt = crypto.randomBytes(16).toString('hex');
  return db.prepare('INSERT INTO users(name,email,salt,hash,role,created) VALUES(?,?,?,?,?,?)')
    .run(name, email, salt, hashPw(pw, salt), role, now()).lastInsertRowid;
}
const checkPw = (u, pw) => {
  const a = Buffer.from(hashPw(pw, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};

// Seed admin + sample community alerts
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'admin@sara.local').toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin@12345';
if (!db.prepare('SELECT 1 FROM users WHERE role=?').get('admin')) addUser('Sara Admin', ADMIN_EMAIL, ADMIN_PASSWORD, 'admin');
if (!db.prepare('SELECT COUNT(*) c FROM posts').get().c) {
  const ins = db.prepare('INSERT INTO posts(title,body,severity,author,created) VALUES(?,?,?,?,?)');
  const t = now();
  ins.run('Fake "Work From Home" data-entry offers asking for a kit fee', 'Scammers send offer letters for data-entry jobs and ask for a refundable "registration/kit fee". Once paid, they vanish. No real employer charges you to start work.', 'high', 'Sara Admin', t - 864e5);
  ins.run('Impersonation of big-company recruiters on WhatsApp/Telegram', 'Messages claim to be from well-known firms, offer easy pay for "liking" or "rating" tasks, then push you to deposit money for "premium tasks".', 'critical', 'Sara Admin', t - 2 * 864e5);
  ins.run('Fake offer letters from look-alike domains', 'Check the sender domain carefully: careers-company.xyz is not company.com. Always verify offers on the company\'s official careers page.', 'medium', 'Sara Admin', t - 4 * 864e5);
}

/* ---------- Scam analysis engine ---------- */
const RULES = [
  [/(registration|processing|security|training|application|joining|verification|onboarding|interview|kit|admin|document)\s*(fee|fees|charge|charges|deposit|amount|payment)\b|\b(pay|deposit|transfer|send)\s+(rs\.?|inr|₹|usd|\$)?\s*[\d,]{3,}|refundable/i, .6, 'Upfront payment requested', 'Legitimate employers never charge candidates to apply, train, or onboard.'],
  [/\b(otp|cvv|atm pin|upi pin|password|net ?banking)\b/i, .55, 'Asks for OTP / PIN / password', 'No recruiter ever needs your OTP, PIN or password.'],
  [/aadhaar|aadhar|pan card|bank (account|details)|passbook|debit card|credit card|passport copy|\bssn\b/i, .3, 'Requests sensitive personal or bank documents', 'Sharing ID/bank details before a verified offer enables identity theft.'],
  [/(cheque|check)[^.\n]{0,40}(deposit|cash|forward|balance)|equipment purchase|reimburse/i, .55, 'Fake-cheque / reimbursement pattern', 'A common scam: you deposit a cheque and "return the balance" before it bounces.'],
  [/guaranteed (job|placement|selection|income)|100% (job|placement|selection)|direct (joining|selection)|no interview|without (an )?interview|selected without/i, .5, 'Guaranteed job / no interview', 'Real hiring involves screening or interviews; guarantees are a red flag.'],
  [/(earn|make|income)[^.\n]{0,40}(per|\/|a)\s*(day|daily|hour|week)|(₹|rs\.?|inr|\$)\s*\d[\d,]*\s*(per|\/|a)\s*(day|daily|hour|hr|week)/i, .35, 'Unrealistic pay claims', 'Very high pay for little work is a classic lure.'],
  [/work from home|data entry|typing job|like (and|&) (subscribe|share)|just (liking|rating)|no (experience|skills|qualification)|simple tasks?|prepaid tasks?/i, .25, 'Easy work / no skills needed', 'Scam listings often advertise effortless work to attract many victims.'],
  [/bitcoin|crypto|usdt|wallet|binance|gift ?card|western union|moneygram/i, .4, 'Crypto / gift-card / wire payment', 'Untraceable payment methods are favoured by fraudsters.'],
  [/\b(whatsapp|telegram|signal)\b/i, .3, 'Moves conversation to WhatsApp/Telegram', 'Official recruiters use company email or portals, not chat apps only.'],
  [/\b(urgent|immediately|hurry|limited (seats|slots|vacanc\w+)|last chance|act now|today only|within \d+ (hours|hrs|minutes))\b/i, .2, 'Pressure / urgency', 'Artificial deadlines are meant to stop you from verifying.'],
  [/(do not|don't|dont) (share|tell|disclose)|keep (this )?(confidential|secret)/i, .25, 'Secrecy pressure', 'Scammers isolate victims so nobody can warn them.'],
  [/(congratulations|you (have been|are|were) (selected|shortlisted|chosen))/i, .15, 'Unsolicited selection notice', 'Be cautious of "you are selected" messages for jobs you never applied to.'],
  [/(visa|work permit|abroad|dubai|canada|germany|gulf)[^.\n]{0,30}(job|sponsorship|processing|offer)/i, .2, 'Overseas job promise', 'Overseas placement scams often charge "visa processing" money.'],
];
const BRANDS = { tcs: 'tcs.com', infosys: 'infosys.com', wipro: 'wipro.com', accenture: 'accenture.com', amazon: 'amazon.com', google: 'google.com', microsoft: 'microsoft.com', cognizant: 'cognizant.com', capgemini: 'capgemini.com', deloitte: 'deloitte.com', flipkart: 'flipkart.com', naukri: 'naukri.com', linkedin: 'linkedin.com', indeed: 'indeed.com' };
const OFFICIAL = new Set([...Object.values(BRANDS), 'amazon.jobs', 'amazon.in', 'google.co.in', 'microsoft.com', 'github.com']);
const BAD_TLD = /\.(xyz|top|click|work|site|online|club|live|shop|biz|link|icu|buzz|rest|cfd|sbs|vip|loan)$/i;
const SHORT = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|rb\.gy|is\.gd|shorturl\.at|wa\.me|t\.me)$/i;
const FREEHOST = /(blogspot|wixsite|weebly|godaddysites|000webhostapp|netlify\.app|vercel\.app|github\.io|pages\.dev|forms\.gle)/i;

function analyzeUrl(raw) {
  let u; const explicit = /^https?:\/\//i.test(raw);
  try { u = new URL(explicit ? raw : 'http://' + raw); } catch { return null; }
  const host = u.hostname.toLowerCase().replace(/^www\./, ''), flags = [];
  const add = (w, t) => flags.push({ w, t });
  if (explicit && u.protocol === 'http:') add(.15, 'Not using HTTPS');
  if (SHORT.test(host)) add(.25, 'Link shortener hides destination');
  if (BAD_TLD.test(host)) add(.3, 'Suspicious domain ending');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(.4, 'Raw IP address instead of a domain');
  if (host.includes('xn--')) add(.4, 'Punycode (look-alike characters)');
  if (host.split('.').length > 4 || (host.match(/-/g) || []).length >= 3) add(.2, 'Unusually long / hyphenated domain');
  if (FREEHOST.test(host)) add(.3, 'Hosted on a free site-builder platform');
  const official = [...OFFICIAL].some(d => host === d || host.endsWith('.' + d));
  if (!official) for (const b of Object.keys(BRANDS)) if (host.split(/[.\-]/).some(p => p === b || p.includes(b))) { add(.45, `Imitates "${b}" but is not its official domain`); break; }
  return { url: raw.slice(0, 200), host, official, flags };
}

function analyze(text) {
  const findings = [], good = [];
  const body = text.slice(0, 20000);
  for (const [re, w, title, detail] of RULES) if (re.test(body)) findings.push({ title, detail, weight: w });
  const letters = body.replace(/[^A-Za-z]/g, '');
  const caps = letters.length > 40 && (body.match(/[A-Z]/g) || []).length / letters.length > .45;
  if (caps || (body.match(/!/g) || []).length >= 4) findings.push({ title: 'Shouting / excessive punctuation', detail: 'Over-excited formatting is common in mass-sent scam messages.', weight: .12 });

  const noEmail = body.replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, m => (m.match(/@(gmail|yahoo|outlook|hotmail|rediffmail|proton|protonmail|aol|ymail)\./i) ? ' FREEMAIL ' : ' '));
  const freeMail = /FREEMAIL/.test(noEmail);
  if (freeMail) findings.push({ title: 'Recruiter uses a free email address', detail: 'Companies hire from their own domain, not Gmail/Yahoo/Outlook.', weight: .3 });
  const brandMention = Object.keys(BRANDS).find(b => new RegExp('\\b' + b + '\\b', 'i').test(body));
  if (brandMention && freeMail) findings.push({ title: `Claims to be "${brandMention}" but uses a free email`, detail: 'Brand impersonation: the sender is not on the company\'s domain.', weight: .35 });

  const urlRe = /\b((?:https?:\/\/|www\.)[^\s<>"')]+|[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|xyz|top|click|work|site|online|info|co|io|link|live|club|shop|biz|me|app|icu|vip|cfd|sbs)(?:\/[^\s<>"')]*)?)/gi;
  const urls = [...new Set((noEmail.match(urlRe) || []).map(x => x.replace(/[.,;:!?]+$/, '')))].slice(0, 10)
    .map(analyzeUrl).filter(Boolean);
  for (const u of urls) {
    if (u.official && !u.flags.length) good.push(`${u.host} is a recognised official domain`);
    for (const f of u.flags) findings.push({ title: f.t, detail: `Link: ${u.host}`, weight: f.w });
  }
  if (/interview (round|process|schedule|link)|technical round|hr round/i.test(body) && !findings.some(f => f.weight >= .5)) good.push('Mentions a normal interview process');

  let p = 1; for (const f of findings) p *= 1 - f.weight;
  let score = Math.round((1 - p) * 100);
  if (good.length) score = Math.max(0, score - Math.min(10, good.length * 5));
  if (body.trim().length && !findings.length) score = Math.max(score, 4);
  score = Math.min(99, score);
  const level = score < 25 ? 'Low' : score < 50 ? 'Medium' : score < 75 ? 'High' : 'Critical';
  const confidence = body.trim().length < 40 && !urls.length ? 'Low' : findings.length >= 2 ? 'High' : 'Medium';
  findings.sort((a, b) => b.weight - a.weight);
  const summary = {
    Low: 'No strong scam signals found. Still verify the employer on its official careers page before sharing personal details.',
    Medium: 'Some suspicious signals found. Do not share documents or money until you independently verify this employer.',
    High: 'Several scam indicators detected. Treat this as likely fraudulent and do not pay or share personal data.',
    Critical: 'Strong scam pattern detected. Stop all contact, do not pay anything, and report it.',
  }[level];
  const advice = ['Verify the company and the recruiter on the official careers website or LinkedIn.', 'Never pay any fee for a job, training, or equipment.'];
  if (level !== 'Low') advice.push('Do not share ID, bank details, OTPs or passwords.', 'Report the message to your local cybercrime authority (in India: cybercrime.gov.in or helpline 1930).');
  return { score, level, confidence, summary, findings: findings.map(f => ({ ...f, weight: Math.round(f.weight * 100) })), urls, good, advice };
}

/* ---------- File text extraction (best effort) ---------- */
function pdfText(buf) {
  const s = buf.toString('latin1'); let out = '', m; const re = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  while ((m = re.exec(s))) {
    let d = Buffer.from(m[1], 'latin1'); try { d = zlib.inflateSync(d, { maxOutputLength: 8e6 }); } catch { }
    const t = d.toString('latin1'), ops = t.match(/\[(?:[^\]]*)\]\s*TJ|\((?:\\.|[^\\)])*\)\s*Tj/g);
    if (ops) out += ops.map(o => (o.match(/\((?:\\.|[^\\)])*\)/g) || []).map(x => x.slice(1, -1).replace(/\\([()\\])/g, '$1')).join('')).join(' ') + '\n';
  }
  return out.replace(/[^\x20-\x7E\n]/g, ' ');
}
function docxText(buf) {
  const e = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 5, 6])); if (e < 0) return '';
  const n = buf.readUInt16LE(e + 10); let p = buf.readUInt32LE(e + 16);
  for (let i = 0; i < n && buf.readUInt32LE(p) === 0x02014b50; i++) {
    const meth = buf.readUInt16LE(p + 10), csz = buf.readUInt32LE(p + 20), nl = buf.readUInt16LE(p + 28), el = buf.readUInt16LE(p + 30), cl = buf.readUInt16LE(p + 32), off = buf.readUInt32LE(p + 42);
    if (buf.toString('utf8', p + 46, p + 46 + nl) === 'word/document.xml') {
      const start = off + 30 + buf.readUInt16LE(off + 26) + buf.readUInt16LE(off + 28), data = buf.subarray(start, start + csz);
      const xml = (meth === 8 ? zlib.inflateRawSync(data, { maxOutputLength: 1e7 }) : data).toString('utf8');
      return xml.replace(/<\/w:p>/g, '\n').replace(/<[^>]+>/g, '');
    }
    p += 46 + nl + el + cl;
  }
  return '';
}
function fileText(name, buf) {
  const ext = path.extname(name).toLowerCase();
  try {
    if (['.txt', '.csv', '.md', '.json', '.log', '.eml', '.xml', '.rtf'].includes(ext)) return buf.toString('utf8');
    if (['.html', '.htm'].includes(ext)) return buf.toString('utf8').replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ');
    if (ext === '.pdf') return pdfText(buf);
    if (ext === '.docx') return docxText(buf);
  } catch { }
  return '';
}

/* ---------- HTTP helpers ---------- */
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
const IMG = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp' };
const send = (res, code, obj, headers = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers }); res.end(JSON.stringify(obj)); };
class HttpError extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const fail = (c, m) => { throw new HttpError(c, m); };
const readBody = req => new Promise((ok, no) => {
  let n = 0; const ch = [];
  req.on('data', c => { n += c.length; if (n > 25e6) { no(new HttpError(413, 'Upload too large')); req.destroy(); } else ch.push(c); });
  req.on('end', () => { try { ok(ch.length ? JSON.parse(Buffer.concat(ch).toString()) : {}); } catch { no(new HttpError(400, 'Invalid JSON')); } });
  req.on('error', no);
});
const cookie = (req, k) => (req.headers.cookie || '').split(/;\s*/).map(c => c.split('=')).find(c => c[0] === k)?.[1];
function userOf(req) {
  const t = cookie(req, 'sara_sid'); if (!t) return null;
  const r = db.prepare('SELECT u.id,u.name,u.email,u.role,u.created,u.salt,u.hash,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?').get(t);
  if (!r) return null; if (r.expires < now()) { db.prepare('DELETE FROM sessions WHERE token=?').run(t); return null; }
  return r;
}
const pub = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, created: u.created });
function startSession(req, res, uid, extra) {
  const token = crypto.randomBytes(32).toString('hex'), days = 14;
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(token, uid, now() + days * 864e5);
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return { 'Set-Cookie': `sara_sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${days * 86400}${secure}` };
}
const tries = new Map();
function throttle(key) {
  const t = now(), a = (tries.get(key) || []).filter(x => t - x < 9e5);
  if (a.length >= 10) fail(429, 'Too many attempts. Try again in a few minutes.');
  a.push(t); tries.set(key, a);
}
const clean = (s, max) => String(s ?? '').trim().slice(0, max);
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;
const validPw = p => typeof p === 'string' && p.length >= 8 && p.length <= 100 && /[A-Za-z]/.test(p) && /\d/.test(p);
const PW_MSG = 'Password must be 8+ characters with at least one letter and one number.';
const need = u => u || fail(401, 'Please sign in first.');
const needAdmin = u => (need(u).role === 'admin') || fail(403, 'Admin access required.');

/* ---------- API routes ---------- */
const routes = [];
const R = (m, p, h) => routes.push([m, new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h]);

R('POST', '/api/signup', async ({ req, res, body }) => {
  throttle('su' + req.socket.remoteAddress);
  const name = clean(body.name, 60), email = clean(body.email, 120).toLowerCase();
  if (name.length < 2) fail(400, 'Please enter your name.');
  if (!validEmail(email)) fail(400, 'Please enter a valid email.');
  if (!validPw(body.password)) fail(400, PW_MSG);
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) fail(409, 'An account with this email already exists.');
  const id = Number(addUser(name, email, body.password));
  send(res, 201, { user: pub({ id, name, email, role: 'user', created: now() }) }, startSession(req, res, id));
});
R('POST', '/api/login', async ({ req, res, body }) => {
  const email = clean(body.email, 120).toLowerCase(); throttle('li' + req.socket.remoteAddress + email);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !checkPw(u, String(body.password || ''))) fail(401, 'Incorrect email or password.');
  if (u.role === 'admin') fail(403, 'This is an admin account. Please use the admin login.');
  send(res, 200, { user: pub(u) }, startSession(req, res, u.id));
});
R('POST', '/api/admin/login', async ({ req, res, body }) => {
  const email = clean(body.email, 120).toLowerCase(); throttle('al' + req.socket.remoteAddress + email);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || u.role !== 'admin' || !checkPw(u, String(body.password || ''))) fail(401, 'Incorrect admin email or password.');
  send(res, 200, { user: pub(u) }, startSession(req, res, u.id));
});
R('POST', '/api/logout', async ({ req, res }) => {
  const t = cookie(req, 'sara_sid'); if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  send(res, 200, { ok: true }, { 'Set-Cookie': 'sara_sid=; HttpOnly; Path=/; Max-Age=0' });
});
R('GET', '/api/me', async ({ res, user }) => {
  if (!user) return send(res, 200, { user: null });
  const s = db.prepare('SELECT COUNT(*) n, AVG(score) avg, MAX(created) last FROM searches WHERE user_id=?').get(user.id);
  send(res, 200, { user: pub(user), stats: { searches: s.n, avgScore: s.avg == null ? null : Math.round(s.avg), last: s.last } });
});
R('PUT', '/api/me', async ({ res, user, body }) => {
  need(user);
  const name = clean(body.name ?? user.name, 60), email = clean(body.email ?? user.email, 120).toLowerCase();
  if (name.length < 2) fail(400, 'Please enter your name.');
  if (!validEmail(email)) fail(400, 'Please enter a valid email.');
  const wantsPw = !!body.newPassword;
  if ((email !== user.email || wantsPw) && !checkPw(user, String(body.currentPassword || ''))) fail(403, 'Current password is required and must be correct.');
  if (wantsPw && !validPw(body.newPassword)) fail(400, PW_MSG);
  if (email !== user.email && db.prepare('SELECT 1 FROM users WHERE email=? AND id<>?').get(email, user.id)) fail(409, 'That email is already in use.');
  db.prepare('UPDATE users SET name=?,email=? WHERE id=?').run(name, email, user.id);
  if (wantsPw) { const salt = crypto.randomBytes(16).toString('hex'); db.prepare('UPDATE users SET salt=?,hash=? WHERE id=?').run(salt, hashPw(body.newPassword, salt), user.id); }
  send(res, 200, { user: pub({ ...user, name, email }) });
});
function removeFiles(rows) { for (const r of rows) for (const f of JSON.parse(r.files || '[]')) if (f.stored) fs.rm(path.join(UP, f.stored), { force: true }, () => { }); }
R('DELETE', '/api/me', async ({ res, user, body }) => {
  need(user); if (user.role === 'admin') fail(400, 'Admin accounts cannot be deleted here.');
  if (!checkPw(user, String(body.password || ''))) fail(403, 'Incorrect password.');
  removeFiles(db.prepare('SELECT files FROM searches WHERE user_id=?').all(user.id));
  db.prepare('DELETE FROM users WHERE id=?').run(user.id);
  send(res, 200, { ok: true }, { 'Set-Cookie': 'sara_sid=; HttpOnly; Path=/; Max-Age=0' });
});

R('POST', '/api/scan', async ({ res, user, body }) => {
  let text = clean(body.text, 20000); const files = Array.isArray(body.files) ? body.files.slice(0, 4) : [];
  const meta = [], notes = [];
  for (const f of files) {
    const name = clean(f.name, 100).replace(/[^\w.\- ]/g, '_') || 'file', ext = path.extname(name).toLowerCase();
    const buf = Buffer.from(String(f.data || ''), 'base64');
    if (!buf.length || buf.length > 6e6) { notes.push(`${name}: skipped (empty or over 6 MB)`); continue; }
    let extracted = fileText(name, buf);
    if (!extracted && f.ocr) extracted = clean(f.ocr, 20000);
    extracted = extracted.trim();
    if (extracted) text += `\n${extracted.slice(0, 20000)}`;
    else notes.push(`${name}: no readable text found${ext in IMG ? ' (image text recognition unavailable or empty)' : ''}`);
    let stored = null;
    if (user && (ext in IMG || ['.pdf', '.docx', '.txt', '.csv', '.md', '.html', '.eml', '.json'].includes(ext))) {
      stored = crypto.randomBytes(12).toString('hex') + ext; fs.writeFileSync(path.join(UP, stored), buf);
    }
    meta.push({ name, size: buf.length, image: ext in IMG, stored, read: !!extracted });
  }
  if (!text.trim()) fail(422, notes.length ? 'I couldn\'t read any text from the attachment. Paste the message text or try a clearer photo. ' + notes.join('; ') : 'Paste a job message, email, link, or upload a file to analyze.');
  const result = analyze(text); result.notes = notes;
  let id = null;
  if (user) {
    const q = clean(body.text, 500) || meta.map(m => m.name).join(', ') || 'Attachment scan';
    id = Number(db.prepare('INSERT INTO searches(user_id,query,score,level,result,files,created) VALUES(?,?,?,?,?,?,?)')
      .run(user.id, q, result.score, result.level, JSON.stringify(result), JSON.stringify(meta), now()).lastInsertRowid);
  }
  send(res, 200, { id, saved: !!user, result, files: meta.map(({ stored, ...m }) => ({ ...m, url: stored ? '/api/file/' + stored : null })) });
});
R('GET', '/api/history', async ({ res, user, query }) => {
  need(user); const q = '%' + String(query.get('q') || '').replace(/[%_]/g, '') + '%';
  const rows = db.prepare('SELECT id,query,score,level,created,files FROM searches WHERE user_id=? AND query LIKE ? ORDER BY created DESC LIMIT 200').all(user.id, q);
  send(res, 200, { items: rows.map(r => ({ id: r.id, query: r.query, score: r.score, level: r.level, created: r.created, files: JSON.parse(r.files || '[]').length })) });
});
R('GET', '/api/history/:id', async ({ res, user, params }) => {
  need(user); const r = db.prepare('SELECT * FROM searches WHERE id=? AND user_id=?').get(params.id, user.id); if (!r) fail(404, 'Search not found.');
  send(res, 200, { id: r.id, query: r.query, created: r.created, result: JSON.parse(r.result), files: JSON.parse(r.files || '[]').map(({ stored, ...m }) => ({ ...m, url: stored ? '/api/file/' + stored : null })) });
});
R('DELETE', '/api/history/:id', async ({ res, user, params }) => {
  need(user); const r = db.prepare('SELECT files FROM searches WHERE id=? AND user_id=?').get(params.id, user.id);
  if (r) { removeFiles([r]); db.prepare('DELETE FROM searches WHERE id=?').run(params.id); }
  send(res, 200, { ok: true });
});
R('DELETE', '/api/history', async ({ res, user }) => {
  need(user); removeFiles(db.prepare('SELECT files FROM searches WHERE user_id=?').all(user.id));
  db.prepare('DELETE FROM searches WHERE user_id=?').run(user.id); send(res, 200, { ok: true });
});
R('GET', '/api/file/:name', async ({ res, user, params }) => {
  need(user); const name = path.basename(params.name);
  const owner = db.prepare('SELECT 1 FROM searches WHERE files LIKE ? AND (user_id=? OR ?)').get('%' + name + '%', user.id, user.role === 'admin' ? 1 : 0);
  if (!owner || !fs.existsSync(path.join(UP, name))) fail(404, 'File not found.');
  const ext = path.extname(name).toLowerCase(), isImg = ext in IMG;
  res.writeHead(200, { 'Content-Type': isImg ? IMG[ext] : 'application/octet-stream', 'Content-Disposition': isImg ? 'inline' : 'attachment', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'private, max-age=3600' });
  fs.createReadStream(path.join(UP, name)).pipe(res);
});

R('GET', '/api/posts', async ({ res }) => send(res, 200, { items: db.prepare('SELECT * FROM posts ORDER BY created DESC LIMIT 100').all() }));
const SEV = ['low', 'medium', 'high', 'critical'];
function postFields(body) {
  const title = clean(body.title, 140), text = clean(body.body, 3000), severity = SEV.includes(body.severity) ? body.severity : 'medium';
  if (title.length < 3 || text.length < 10) fail(400, 'Add a title and a description (at least 10 characters).');
  return [title, text, severity];
}
R('POST', '/api/posts', async ({ res, user, body }) => {
  needAdmin(user); const [t, b, s] = postFields(body);
  const id = Number(db.prepare('INSERT INTO posts(title,body,severity,author,created) VALUES(?,?,?,?,?)').run(t, b, s, user.name, now()).lastInsertRowid);
  send(res, 201, { id });
});
R('PUT', '/api/posts/:id', async ({ res, user, body, params }) => {
  needAdmin(user); const [t, b, s] = postFields(body);
  db.prepare('UPDATE posts SET title=?,body=?,severity=? WHERE id=?').run(t, b, s, params.id); send(res, 200, { ok: true });
});
R('DELETE', '/api/posts/:id', async ({ res, user, params }) => { needAdmin(user); db.prepare('DELETE FROM posts WHERE id=?').run(params.id); send(res, 200, { ok: true }); });

R('GET', '/api/admin/stats', async ({ res, user }) => {
  needAdmin(user);
  const c = t => db.prepare(`SELECT COUNT(*) c FROM ${t}`).get().c;
  const lv = Object.fromEntries(['Low', 'Medium', 'High', 'Critical'].map(l => [l, db.prepare('SELECT COUNT(*) c FROM searches WHERE level=?').get(l).c]));
  send(res, 200, { users: c('users'), scans: c('searches'), posts: c('posts'), avg: Math.round(db.prepare('SELECT AVG(score) a FROM searches').get().a || 0), levels: lv });
});
R('GET', '/api/admin/users', async ({ res, user }) => {
  needAdmin(user);
  send(res, 200, { items: db.prepare('SELECT u.id,u.name,u.email,u.role,u.created,(SELECT COUNT(*) FROM searches s WHERE s.user_id=u.id) scans FROM users u ORDER BY u.created DESC').all() });
});
R('DELETE', '/api/admin/users/:id', async ({ res, user, params }) => {
  needAdmin(user); const t = db.prepare('SELECT * FROM users WHERE id=?').get(params.id);
  if (!t) fail(404, 'User not found.'); if (t.role === 'admin') fail(400, 'Admin accounts cannot be removed.');
  removeFiles(db.prepare('SELECT files FROM searches WHERE user_id=?').all(t.id)); db.prepare('DELETE FROM users WHERE id=?').run(t.id);
  send(res, 200, { ok: true });
});

/* ---------- Server ---------- */
function serveStatic(req, res, pathname) {
  let p = path.normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  if (p === '/' || p === '\\') p = '/index.html';
  const file = path.join(PUB, p);
  if (!file.startsWith(PUB) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-cache' });
  fs.createReadStream(file).pipe(res);
}
http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
    if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
      const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) fail(403, 'Bad origin.');
    }
    for (const [m, re, h] of routes) {
      const mt = m === req.method && re.exec(url.pathname); if (!mt) continue;
      const body = ['POST', 'PUT', 'DELETE'].includes(m) ? await readBody(req) : {};
      return await h({ req, res, body, user: userOf(req), params: mt.groups || {}, query: url.searchParams });
    }
    fail(404, 'Not found.');
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    if (!res.headersSent) send(res, e.code || 500, { error: e instanceof HttpError ? e.message : 'Something went wrong on the server.' });
  }
}).listen(PORT, () => console.log(`Sara running on http://localhost:${PORT}`));
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(now()), 36e5).unref();

