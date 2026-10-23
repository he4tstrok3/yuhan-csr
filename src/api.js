// 함께하는 유한 · 사회공헌 페이지 API
// 바인딩: DB(D1), PHOTOS(R2)
// 비밀값: ADMIN_PASSWORD, SESSION_SECRET, TURNSTILE_SECRET_KEY
// 환경변수: TURNSTILE_SITE_KEY

const SITES = ['본사', '연구소', '공장', '전사'];
const ORGS = ['본사', '연구소', '공장'];
const QTYPES = ['text', 'long', 'choice', 'multi'];
const IDEA_STATUS = ['new', 'review', 'adopt', 'hold'];
const FORM_HOSTS = ['form.naver.com', 'm.form.naver.com', 'naver.me'];
const LINK_RE = /(https?:\/\/|www\.|[a-z0-9-]+\.(com|net|org|kr|io|me|ly|co|xyz|site|link)(\/|\b))/i;
const BANNED_Q = /주민|계좌|카드\s*번호|비밀번호|패스워드|여권/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const KEY_RE = /^[a-f0-9]{32}$/;
const MAX_UPLOAD = 5 * 1024 * 1024;
const SESSION_HOURS = 8;

export async function onRequest(ctx) {
  try {
    return await route(ctx.request, ctx.env);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(e);
    return json({ error: '요청을 처리하지 못했어요. 잠시 후 다시 시도해 주세요.' }, 500);
  }
}

class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const fail = (status, message) => { throw new HttpError(status, message); };

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

// ---------- utils ----------
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
async function sha256(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }
async function hmac(secret, s) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', key, enc.encode(s)));
}
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0;
}
const randomId = () => crypto.randomUUID().replace(/-/g, '');
const now = () => Date.now();
const todayKST = () => new Date(Date.now() + 9 * 3600e3).toISOString().slice(0, 10);
const dayBefore = (d) => new Date(new Date(d + 'T00:00:00Z').getTime() - 864e5).toISOString().slice(0, 10);
const str = (v, max) => String(v ?? '').trim().slice(0, max);
const clientIp = (req) => req.headers.get('CF-Connecting-IP') || '0.0.0.0';
async function ipHash(req, env) { return (await sha256(clientIp(req) + '|' + (env.SESSION_SECRET || ''))).slice(0, 32); }

async function body(req) {
  const ct = req.headers.get('Content-Type') || '';
  if (!ct.includes('application/json')) fail(415, '잘못된 요청이에요.');
  const len = +req.headers.get('Content-Length') || 0;
  if (len > 64 * 1024) fail(413, '보낸 내용이 너무 커요.');
  try { return await req.json(); } catch { fail(400, '잘못된 요청이에요.'); }
}

function sameOrigin(req) {
  const origin = req.headers.get('Origin');
  if (!origin) return true;
  try { return new URL(origin).host === new URL(req.url).host; } catch { return false; }
}

async function limited(env, key, max, windowSec) {
  const t = now();
  if (Math.random() < 0.05) await env.DB.prepare('DELETE FROM rl WHERE ts < ?').bind(t - 2 * 864e5).run();
  const r = await env.DB.prepare('SELECT COUNT(*) AS c FROM rl WHERE k = ? AND ts > ?').bind(key, t - windowSec * 1000).first();
  if ((r?.c || 0) >= max) return true;
  await env.DB.prepare('INSERT INTO rl (k, ts) VALUES (?, ?)').bind(key, t).run();
  return false;
}

async function turnstileOk(req, env, token) {
  if (!env.TURNSTILE_SECRET_KEY) return true; // 아직 설정 전이면 통과 (README 참고)
  if (!token) return false;
  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', String(token).slice(0, 2048));
  form.append('remoteip', clientIp(req));
  const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body: form });
  const j = await r.json().catch(() => ({}));
  return !!j.success;
}
async function requireHuman(req, env, token) {
  if (!(await turnstileOk(req, env, token))) fail(403, '로봇 확인에 실패했어요. 확인 표시를 다시 눌러 주세요.');
}

// ---------- admin session ----------
async function makeSession(env) {
  const exp = now() + SESSION_HOURS * 3600e3;
  const payload = `${exp}.${randomId()}`;
  return `${payload}.${await hmac(env.SESSION_SECRET, payload)}`;
}
async function isAdmin(req, env) {
  if (!env.SESSION_SECRET) return false;
  const m = (req.headers.get('Cookie') || '').match(/(?:^|;\s*)__Host-csr_admin=([^;]+)/);
  if (!m) return false;
  const parts = m[1].split('.');
  if (parts.length !== 3) return false;
  const [exp, nonce, sig] = parts;
  if (!(+exp > now())) return false;
  return safeEqual(sig, await hmac(env.SESSION_SECRET, `${exp}.${nonce}`));
}
const sessionCookie = (v, maxAge) => `__Host-csr_admin=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
async function log(env, req, action, target) {
  await env.DB.prepare('INSERT INTO logs (at, action, target, ip_hash) VALUES (?, ?, ?, ?)')
    .bind(now(), str(action, 40), str(target, 120), await ipHash(req, env)).run();
}

// ---------- validation ----------
function safeForm(u) {
  try { const x = new URL(String(u || '').trim()); return x.protocol === 'https:' && FORM_HOSTS.includes(x.hostname) ? x.href : ''; } catch { return ''; }
}
function programState(p) {
  const t = todayKST();
  if (!p.date || p.date < t) return 'past';
  const dl = p.deadline || dayBefore(p.date);
  if (p.status === 'closed' || dl < t) return 'closed';
  return 'open';
}
function cleanQuestions(qs) {
  if (!Array.isArray(qs)) return [];
  return qs.slice(0, 15).map((q) => ({
    id: str(q.id, 40).replace(/[^\w-]/g, '') || randomId().slice(0, 12),
    label: str(q.label, 60),
    type: QTYPES.includes(q.type) ? q.type : 'text',
    required: !!q.required,
    options: (q.type === 'choice' || q.type === 'multi') && Array.isArray(q.options) ? q.options.slice(0, 10).map((o) => str(o, 40)).filter(Boolean) : [],
  })).filter((q) => q.label && !BANNED_Q.test(q.label));
}
function cleanSites(d) {
  let cats = (Array.isArray(d.categories) ? d.categories : [d.category]).filter((c) => SITES.includes(c));
  cats = SITES.filter((c) => cats.includes(c));
  if (cats.includes('전사')) cats = ['전사'];
  if (!cats.length) cats = [SITES[0]];
  return { category: cats[0], categories: cats };
}
function cleanProgram(d) {
  const mode = d.applyMode === 'naver' ? 'naver' : 'site';
  const p = {
    title: str(d.title, 60), ...cleanSites(d),
    date: DATE_RE.test(d.date) ? d.date : '', deadline: DATE_RE.test(d.deadline) ? d.deadline : '',
    time: str(d.time, 30), place: str(d.place, 60), meeting: str(d.meeting, 60), bring: str(d.bring, 80), desc: str(d.desc, 800),
    capacity: Math.max(0, Math.min(10000, parseInt(d.capacity, 10) || 0)),
    applyMode: mode, formUrl: mode === 'naver' ? safeForm(d.formUrl) : '',
    appliedCount: mode === 'naver' && d.appliedCount !== null && d.appliedCount !== '' && d.appliedCount !== undefined ? Math.max(0, parseInt(d.appliedCount, 10) || 0) : null,
    questions: mode === 'site' ? cleanQuestions(d.questions) : [],
    cover: KEY_RE.test(d.cover || '') ? d.cover : '',
    status: d.status === 'closed' ? 'closed' : 'open', sample: !!d.sample,
  };
  if (!p.title) fail(400, '활동명을 적어 주세요.');
  if (!p.date) fail(400, '활동일을 확인해 주세요.');
  if (mode === 'naver' && !p.formUrl) fail(400, '네이버폼 주소(form.naver.com 또는 naver.me)를 넣어 주세요.');
  return p;
}
function cleanArchive(d) {
  const a = {
    title: str(d.title, 60), category: SITES.includes(d.category) ? d.category : SITES[0],
    date: DATE_RE.test(d.date) ? d.date : '', place: str(d.place, 60),
    participants: Math.max(0, Math.min(100000, parseInt(d.participants, 10) || 0)), summary: str(d.summary, 1200),
    photos: Array.isArray(d.photos) ? d.photos.filter((k) => KEY_RE.test(k)).slice(0, 30) : [], sample: !!d.sample,
  };
  if (!a.title) fail(400, '활동명을 적어 주세요.');
  if (!a.date) fail(400, '활동일을 확인해 주세요.');
  return a;
}
function checkAnswers(qs, answers) {
  const out = {};
  const src = answers && typeof answers === 'object' ? answers : {};
  for (const q of qs) {
    let v = src[q.id];
    if (q.type === 'text' || q.type === 'long') {
      v = str(v, q.type === 'text' ? 200 : 500);
      if (q.required && !v) fail(400, `‘${q.label}’에 답해 주세요.`);
    } else {
      const picked = (Array.isArray(v) ? v : [v]).map((x) => String(x ?? '')).filter((x) => q.options.includes(x));
      if (q.required && !picked.length) fail(400, `‘${q.label}’에서 하나 이상 골라 주세요.`);
      v = q.type === 'multi' ? [...new Set(picked)] : (picked[0] || '');
    }
    out[q.id] = v;
  }
  return out;
}
function checkPerson(d) {
  const org = ORGS.includes(d.org) ? d.org : '';
  const name = str(d.name, 20).replace(/\s+/g, ' ');
  const empNo = String(d.empNo ?? '').trim();
  if (!org) fail(400, '소속을 골라 주세요.');
  if (!name || /[<>{}\d]/.test(name)) fail(400, '이름을 확인해 주세요.');
  if (!/^\d{6}$/.test(empNo)) fail(400, '사번은 숫자 6자리로 적어 주세요.');
  return { org, name, empNo };
}
function checkText(text, max, label) {
  const t = str(text, max);
  if (!t) fail(400, `${label}을(를) 적어 주세요.`);
  if (LINK_RE.test(t)) fail(400, '스팸 방지를 위해 링크는 올릴 수 없어요.');
  return t;
}
async function markPhotos(env, keys, status) {
  for (const k of keys) if (KEY_RE.test(k)) await env.DB.prepare('UPDATE photos SET status = ? WHERE key = ?').bind(status, k).run();
}

// ---------- data loaders ----------
async function loadPrograms(env) {
  const { results } = await env.DB.prepare('SELECT id, data FROM programs ORDER BY date').all();
  return results.map((r) => ({ id: r.id, ...JSON.parse(r.data) }));
}
async function loadArchive(env) {
  const { results } = await env.DB.prepare('SELECT id, data FROM archive ORDER BY date DESC').all();
  return results.map((r) => ({ id: r.id, ...JSON.parse(r.data) }));
}
async function signupCounts(env) {
  const { results } = await env.DB.prepare('SELECT program_id, COUNT(*) AS c FROM signups GROUP BY program_id').all();
  return Object.fromEntries(results.map((r) => [r.program_id, r.c]));
}
async function rankOf(env, s) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS c FROM signups WHERE program_id = ? AND (created_at < ? OR (created_at = ? AND id < ?))')
    .bind(s.program_id, s.created_at, s.created_at, s.id).first();
  return (r?.c || 0) + 1;
}
async function getSignupWithToken(env, id, token) {
  if (!/^[a-f0-9]{32}$/.test(id || '') || typeof token !== 'string' || token.length > 100) fail(404, '신청 정보를 찾지 못했어요.');
  const s = await env.DB.prepare('SELECT * FROM signups WHERE id = ?').bind(id).first();
  if (!s || !safeEqual(s.token_hash, await sha256(token))) fail(404, '신청 정보를 찾지 못했어요.');
  return s;
}
async function signupView(env, s, programs) {
  const p = programs ? programs.find((x) => x.id === s.program_id) : null;
  const cap = p ? +p.capacity || 0 : 0;
  const rank = await rankOf(env, s);
  return { id: s.id, programId: s.program_id, org: s.org, name: s.name, empNo: s.emp_no, answers: JSON.parse(s.answers || '{}'), at: s.created_at,
    rank, confirmed: !cap || rank <= cap, wait: cap && rank > cap ? rank - cap : 0 };
}

// ---------- router ----------
async function route(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, '').replace(/\/+$/, '') || '/';
  const seg = path.split('/').filter(Boolean);
  const method = req.method;
  if (method !== 'GET' && method !== 'HEAD' && !sameOrigin(req)) fail(403, '허용되지 않은 요청이에요.');
  if (!env.DB) fail(500, '데이터베이스가 연결되지 않았어요. (DB 바인딩 확인)');

  // ---- public ----
  if (method === 'GET' && path === '/bootstrap') return bootstrap(req, env);
  if (method === 'GET' && seg[0] === 'img' && seg.length === 2) return image(req, env, seg[1]);
  if (method === 'POST' && path === '/upload') return upload(req, env, false);
  if (seg[0] === 'signups') {
    if (method === 'POST' && seg.length === 1) return createSignup(req, env);
    if (seg.length === 2 && (method === 'GET' || method === 'PUT' || method === 'DELETE')) return mySignup(req, env, seg[1], method, url);
  }
  if (method === 'POST' && path === '/stories') return createStory(req, env);
  if (method === 'POST' && path === '/ideas') return createIdea(req, env);
  if (method === 'POST' && seg[0] === 'ideas' && seg[2] === 'vote' && seg.length === 3) return vote(req, env, seg[1]);

  // ---- admin ----
  if (seg[0] === 'admin') return adminRoute(req, env, seg.slice(1), method);
  fail(404, '찾는 주소가 없어요.');
}

async function bootstrap(req, env) {
  const cid = str(req.headers.get('X-Client-Id'), 64);
  const voter = cid ? await sha256('v|' + cid) : '';
  const [programs, archive, counts, storiesQ, ideasQ, votesQ, mineQ, cfg] = await Promise.all([
    loadPrograms(env), loadArchive(env), signupCounts(env),
    env.DB.prepare("SELECT id, author, text, archive_id, photos, created_at FROM stories WHERE status = 'approved' ORDER BY created_at DESC LIMIT 200").all(),
    env.DB.prepare("SELECT id, author, title, description, category, status, created_at FROM ideas WHERE status != 'hidden' ORDER BY created_at DESC LIMIT 300").all(),
    env.DB.prepare('SELECT idea_id, COUNT(*) AS c FROM votes GROUP BY idea_id').all(),
    voter ? env.DB.prepare('SELECT idea_id FROM votes WHERE voter = ?').bind(voter).all() : Promise.resolve({ results: [] }),
    env.DB.prepare("SELECT v FROM config WHERE k = 'contact'").first(),
  ]);
  const vc = Object.fromEntries(votesQ.results.map((r) => [r.idea_id, r.c]));
  const mine = new Set(mineQ.results.map((r) => r.idea_id));
  return json({
    programs: programs.map((p) => ({ ...p, formUrl: p.applyMode === 'naver' ? p.formUrl : '', count: counts[p.id] || 0 })),
    archive,
    stories: storiesQ.results.map((s) => ({ id: s.id, author: s.author, text: s.text, archiveId: s.archive_id || '', photos: JSON.parse(s.photos || '[]'), at: s.created_at })),
    ideas: ideasQ.results.map((i) => ({ id: i.id, author: i.author, title: i.title, desc: i.description || '', category: i.category, status: i.status, at: i.created_at, votes: vc[i.id] || 0, voted: mine.has(i.id) })),
    config: { contact: cfg?.v || '', turnstileSiteKey: env.TURNSTILE_SITE_KEY || '' },
  });
}

async function image(req, env, key) {
  if (!KEY_RE.test(key)) fail(404, '사진을 찾지 못했어요.');
  const row = await env.DB.prepare('SELECT status FROM photos WHERE key = ?').bind(key).first();
  const pub = row?.status === 'public';
  if (!row || (!pub && !(await isAdmin(req, env)))) fail(404, '사진을 찾지 못했어요.');
  const obj = await env.PHOTOS.get(key);
  if (!obj) fail(404, '사진을 찾지 못했어요.');
  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
      'Cache-Control': pub ? 'public, max-age=86400' : 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'none'",
    },
  });
}

function sniff(b) {
  const u = new Uint8Array(b.slice(0, 12));
  if (u[0] === 0xff && u[1] === 0xd8 && u[2] === 0xff) return 'image/jpeg';
  if (u[0] === 0x89 && u[1] === 0x50 && u[2] === 0x4e && u[3] === 0x47) return 'image/png';
  if (u[0] === 0x52 && u[1] === 0x49 && u[2] === 0x46 && u[3] === 0x46 && u[8] === 0x57 && u[9] === 0x45 && u[10] === 0x42 && u[11] === 0x50) return 'image/webp';
  return '';
}
async function upload(req, env, asAdmin) {
  if (!env.PHOTOS) fail(500, '사진 저장소가 연결되지 않았어요. (PHOTOS 바인딩 확인)');
  const admin = asAdmin || (await isAdmin(req, env));
  if (!admin && (await limited(env, 'up|' + (await ipHash(req, env)), 20, 3600))) fail(429, '사진을 너무 많이 올렸어요. 잠시 후 다시 시도해 주세요.');
  const len = +req.headers.get('Content-Length') || 0;
  if (len > MAX_UPLOAD) fail(413, '사진 한 장은 5MB 이하로 올려 주세요.');
  const buf = await req.arrayBuffer();
  if (!buf.byteLength || buf.byteLength > MAX_UPLOAD) fail(413, '사진 한 장은 5MB 이하로 올려 주세요.');
  const type = sniff(buf);
  if (!type) fail(415, 'JPG, PNG, WEBP 사진만 올릴 수 있어요.');
  const key = randomId();
  await env.PHOTOS.put(key, buf, { httpMetadata: { contentType: type } });
  await env.DB.prepare('INSERT INTO photos (key, status, created_at, ip_hash) VALUES (?, ?, ?, ?)')
    .bind(key, admin ? 'public' : 'pending', now(), await ipHash(req, env)).run();
  return json({ id: key });
}

async function createSignup(req, env) {
  const d = await body(req);
  await requireHuman(req, env, d.turnstile);
  if (await limited(env, 'su|' + (await ipHash(req, env)), 15, 3600)) fail(429, '신청이 너무 많아요. 잠시 후 다시 시도해 주세요.');
  if (d.consent !== true) fail(400, '개인정보 수집·이용에 동의해 주세요.');
  const row = await env.DB.prepare('SELECT id, data FROM programs WHERE id = ?').bind(str(d.programId, 64)).first();
  if (!row) fail(404, '공고를 찾지 못했어요.');
  const p = { id: row.id, ...JSON.parse(row.data) };
  if (p.applyMode === 'naver') fail(400, '이 봉사는 네이버폼으로 신청해요.');
  if (programState(p) !== 'open') fail(400, '모집이 마감된 봉사예요.');
  const person = checkPerson(d);
  const answers = checkAnswers(p.questions || [], d.answers);
  const id = randomId(), token = randomId() + randomId();
  try {
    await env.DB.prepare('INSERT INTO signups (id, program_id, emp_no, org, name, answers, token_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .bind(id, p.id, person.empNo, person.org, person.name, JSON.stringify(answers), await sha256(token), now(), now()).run();
  } catch (e) {
    if (String(e.message || e).includes('UNIQUE')) fail(409, '이 사번으로 이미 신청했어요. 수정하려면 신청한 기기에서 열거나 담당자에게 문의해 주세요.');
    throw e;
  }
  const s = await env.DB.prepare('SELECT * FROM signups WHERE id = ?').bind(id).first();
  return json({ token, signup: await signupView(env, s, [p]) }, 201);
}

async function mySignup(req, env, id, method, url) {
  if (method === 'GET') {
    const s = await getSignupWithToken(env, id, url.searchParams.get('token'));
    return json({ signup: await signupView(env, s, await loadPrograms(env)) });
  }
  const d = await body(req);
  const s = await getSignupWithToken(env, id, d.token);
  if (method === 'DELETE') {
    await env.DB.prepare('DELETE FROM signups WHERE id = ?').bind(s.id).run();
    return json({ ok: true });
  }
  const row = await env.DB.prepare('SELECT id, data FROM programs WHERE id = ?').bind(s.program_id).first();
  if (!row) fail(404, '공고를 찾지 못했어요.');
  const p = { id: row.id, ...JSON.parse(row.data) };
  if (programState(p) === 'past') fail(400, '종료된 봉사는 수정할 수 없어요.');
  const person = checkPerson(d);
  const answers = checkAnswers(p.questions || [], d.answers);
  try {
    await env.DB.prepare('UPDATE signups SET org = ?, name = ?, emp_no = ?, answers = ?, updated_at = ? WHERE id = ?')
      .bind(person.org, person.name, person.empNo, JSON.stringify(answers), now(), s.id).run();
  } catch (e) {
    if (String(e.message || e).includes('UNIQUE')) fail(409, '이 사번으로 이미 다른 신청이 있어요.');
    throw e;
  }
  const s2 = await env.DB.prepare('SELECT * FROM signups WHERE id = ?').bind(s.id).first();
  return json({ signup: await signupView(env, s2, [p]) });
}

async function createStory(req, env) {
  const d = await body(req);
  await requireHuman(req, env, d.turnstile);
  const ih = await ipHash(req, env);
  if (await limited(env, 'st|' + ih, 5, 3600) || await limited(env, 'std|' + ih, 10, 86400)) fail(429, '후기를 너무 많이 올렸어요. 내일 다시 올려 주세요.');
  const text = checkText(d.text, 1500, '후기');
  const author = str(d.author, 20).replace(/[<>{}]/g, '');
  if (LINK_RE.test(author)) fail(400, '이름에는 링크를 넣을 수 없어요.');
  const dup = await env.DB.prepare('SELECT 1 FROM stories WHERE text = ? LIMIT 1').bind(text).first();
  if (dup) fail(409, '같은 내용이 이미 올라와 있어요.');
  const photos = Array.isArray(d.photos) ? d.photos.filter((k) => KEY_RE.test(k)).slice(0, 3) : [];
  for (const k of photos) {
    const r = await env.DB.prepare('SELECT 1 FROM photos WHERE key = ?').bind(k).first();
    if (!r) fail(400, '사진을 다시 올려 주세요.');
  }
  const archiveId = str(d.archiveId, 64);
  await env.DB.prepare("INSERT INTO stories (id, author, text, archive_id, photos, status, created_at, ip_hash) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)")
    .bind(randomId(), author, text, archiveId, JSON.stringify(photos), now(), ih).run();
  return json({ ok: true, pending: true }, 201);
}

async function createIdea(req, env) {
  const d = await body(req);
  await requireHuman(req, env, d.turnstile);
  const ih = await ipHash(req, env);
  if (await limited(env, 'id|' + ih, 5, 3600) || await limited(env, 'idd|' + ih, 10, 86400)) fail(429, '제안을 너무 많이 올렸어요. 내일 다시 올려 주세요.');
  const title = checkText(d.title, 80, '제목');
  const desc = str(d.desc, 1000);
  if (LINK_RE.test(desc)) fail(400, '스팸 방지를 위해 링크는 올릴 수 없어요.');
  const author = str(d.author, 20).replace(/[<>{}]/g, '');
  const dup = await env.DB.prepare('SELECT 1 FROM ideas WHERE title = ? AND description = ? LIMIT 1').bind(title, desc).first();
  if (dup) fail(409, '같은 내용이 이미 올라와 있어요.');
  await env.DB.prepare("INSERT INTO ideas (id, author, title, description, category, status, created_at, ip_hash) VALUES (?, ?, ?, ?, ?, 'new', ?, ?)")
    .bind(randomId(), author, title, desc, SITES.includes(d.category) ? d.category : SITES[0], now(), ih).run();
  return json({ ok: true }, 201);
}

async function vote(req, env, ideaId) {
  const cid = str(req.headers.get('X-Client-Id'), 64);
  if (!cid) fail(400, '잘못된 요청이에요.');
  if (await limited(env, 'vt|' + (await ipHash(req, env)), 60, 3600)) fail(429, '잠시 후 다시 시도해 주세요.');
  const idea = await env.DB.prepare("SELECT id FROM ideas WHERE id = ? AND status != 'hidden'").bind(str(ideaId, 64)).first();
  if (!idea) fail(404, '제안을 찾지 못했어요.');
  const voter = await sha256('v|' + cid);
  const has = await env.DB.prepare('SELECT 1 FROM votes WHERE idea_id = ? AND voter = ?').bind(idea.id, voter).first();
  if (has) await env.DB.prepare('DELETE FROM votes WHERE idea_id = ? AND voter = ?').bind(idea.id, voter).run();
  else await env.DB.prepare('INSERT INTO votes (idea_id, voter, created_at) VALUES (?, ?, ?)').bind(idea.id, voter, now()).run();
  const c = await env.DB.prepare('SELECT COUNT(*) AS c FROM votes WHERE idea_id = ?').bind(idea.id).first();
  return json({ voted: !has, votes: c?.c || 0 });
}

// ---------- admin ----------
async function adminRoute(req, env, seg, method) {
  const path = '/' + seg.join('/');
  if (method === 'POST' && path === '/login') {
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) fail(500, '관리자 비밀번호가 설정되지 않았어요. (README 참고)');
    const key = 'lg|' + (await ipHash(req, env));
    const t = now();
    const r = await env.DB.prepare('SELECT COUNT(*) AS c FROM rl WHERE k = ? AND ts > ?').bind(key, t - 15 * 60e3).first();
    if ((r?.c || 0) >= 5) fail(429, '비밀번호를 여러 번 틀렸어요. 15분 뒤에 다시 시도해 주세요.');
    const d = await body(req);
    const ok = safeEqual(await hmac(env.SESSION_SECRET, String(d.password ?? '')), await hmac(env.SESSION_SECRET, env.ADMIN_PASSWORD));
    if (!ok) {
      await env.DB.prepare('INSERT INTO rl (k, ts) VALUES (?, ?)').bind(key, t).run();
      await log(env, req, '관리자 로그인 실패', '');
      fail(401, '비밀번호가 맞지 않아요.');
    }
    await log(env, req, '관리자 로그인', '');
    return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(await makeSession(env), SESSION_HOURS * 3600) });
  }
  if (method === 'POST' && path === '/logout') return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
  if (!(await isAdmin(req, env))) fail(401, '관리자 로그인이 필요해요.');
  if (method === 'GET' && path === '/session') return json({ ok: true });

  if (method === 'GET' && path === '/all') {
    const [programs, archive, stories, ideas, votes, signups, logs, cfg] = await Promise.all([
      loadPrograms(env), loadArchive(env),
      env.DB.prepare('SELECT id, author, text, archive_id, photos, status, created_at FROM stories ORDER BY created_at DESC').all(),
      env.DB.prepare('SELECT id, author, title, description, category, status, created_at FROM ideas ORDER BY created_at DESC').all(),
      env.DB.prepare('SELECT idea_id, COUNT(*) AS c FROM votes GROUP BY idea_id').all(),
      env.DB.prepare('SELECT id, program_id, emp_no, org, name, answers, created_at FROM signups ORDER BY program_id, created_at, id').all(),
      env.DB.prepare('SELECT at, action, target FROM logs ORDER BY id DESC LIMIT 200').all(),
      env.DB.prepare("SELECT v FROM config WHERE k = 'contact'").first(),
    ]);
    const vc = Object.fromEntries(votes.results.map((r) => [r.idea_id, r.c]));
    return json({
      programs, archive,
      stories: stories.results.map((s) => ({ id: s.id, author: s.author, text: s.text, archiveId: s.archive_id || '', photos: JSON.parse(s.photos || '[]'), status: s.status, at: s.created_at })),
      ideas: ideas.results.map((i) => ({ id: i.id, author: i.author, title: i.title, desc: i.description || '', category: i.category, status: i.status, at: i.created_at, votes: vc[i.id] || 0 })),
      signups: signups.results.map((s) => ({ id: s.id, programId: s.program_id, empNo: s.emp_no, org: s.org, name: s.name, answers: JSON.parse(s.answers || '{}'), at: s.created_at })),
      logs: logs.results, config: { contact: cfg?.v || '' },
    });
  }
  if (method === 'POST' && path === '/upload') return upload(req, env, true);

  const [kind, id] = seg;
  const validId = (x) => /^[\w-]{1,64}$/.test(x || '');
  if (kind === 'programs' && validId(id)) {
    if (method === 'PUT') {
      const p = cleanProgram(await body(req));
      await env.DB.prepare('INSERT INTO programs (id, data, date, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, date = excluded.date, updated_at = excluded.updated_at')
        .bind(id, JSON.stringify({ ...p, updatedAt: now() }), p.date, now()).run();
      if (p.cover) await markPhotos(env, [p.cover], 'public');
      await log(env, req, '공고 저장', p.title);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM programs WHERE id = ?').bind(id).run();
      await env.DB.prepare('DELETE FROM signups WHERE program_id = ?').bind(id).run();
      await log(env, req, '공고 삭제', id);
      return json({ ok: true });
    }
  }
  if (kind === 'archive' && validId(id)) {
    if (method === 'PUT') {
      const a = cleanArchive(await body(req));
      await env.DB.prepare('INSERT INTO archive (id, data, date, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data, date = excluded.date, updated_at = excluded.updated_at')
        .bind(id, JSON.stringify({ ...a, updatedAt: now() }), a.date, now()).run();
      await markPhotos(env, a.photos, 'public');
      await log(env, req, '활동 기록 저장', a.title);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM archive WHERE id = ?').bind(id).run();
      await log(env, req, '활동 기록 삭제', id);
      return json({ ok: true });
    }
  }
  if (kind === 'stories' && validId(id)) {
    const s = await env.DB.prepare('SELECT * FROM stories WHERE id = ?').bind(id).first();
    if (!s) fail(404, '후기를 찾지 못했어요.');
    if (method === 'PATCH') {
      const d = await body(req);
      const status = ['approved', 'pending', 'hidden'].includes(d.status) ? d.status : 'pending';
      await env.DB.prepare('UPDATE stories SET status = ? WHERE id = ?').bind(status, id).run();
      await markPhotos(env, JSON.parse(s.photos || '[]'), status === 'approved' ? 'public' : 'pending');
      await log(env, req, status === 'approved' ? '후기 승인' : '후기 숨김', s.text.slice(0, 40));
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM stories WHERE id = ?').bind(id).run();
      for (const k of JSON.parse(s.photos || '[]')) if (KEY_RE.test(k)) {
        await env.DB.prepare('DELETE FROM photos WHERE key = ?').bind(k).run();
        await env.PHOTOS.delete(k);
      }
      await log(env, req, '후기 삭제', s.text.slice(0, 40));
      return json({ ok: true });
    }
  }
  if (kind === 'ideas' && validId(id)) {
    if (method === 'PATCH') {
      const d = await body(req);
      const status = [...IDEA_STATUS, 'hidden'].includes(d.status) ? d.status : 'new';
      await env.DB.prepare('UPDATE ideas SET status = ? WHERE id = ?').bind(status, id).run();
      await log(env, req, '제안 상태 변경', `${id} → ${status}`);
      return json({ ok: true });
    }
    if (method === 'DELETE') {
      await env.DB.prepare('DELETE FROM ideas WHERE id = ?').bind(id).run();
      await env.DB.prepare('DELETE FROM votes WHERE idea_id = ?').bind(id).run();
      await log(env, req, '제안 삭제', id);
      return json({ ok: true });
    }
  }
  if (kind === 'signups' && validId(id) && method === 'DELETE') {
    await env.DB.prepare('DELETE FROM signups WHERE id = ?').bind(id).run();
    await log(env, req, '신청 삭제', id);
    return json({ ok: true });
  }
  if (kind === 'config' && method === 'PUT') {
    const d = await body(req);
    const contact = str(d.contact, 80);
    if (LINK_RE.test(contact)) fail(400, '문의처에는 링크를 넣을 수 없어요.');
    await env.DB.prepare("INSERT INTO config (k, v) VALUES ('contact', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").bind(contact).run();
    await log(env, req, '문의처 변경', contact);
    return json({ ok: true });
  }
  fail(404, '찾는 주소가 없어요.');
}
