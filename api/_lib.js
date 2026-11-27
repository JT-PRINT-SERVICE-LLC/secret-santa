import crypto from 'node:crypto';

// Find the Upstash REST settings however Vercel prefixed them (KV_, STORAGE_, UPSTASH_REDIS_, etc.)
function findEnv(suffixes) {
  for (const s of suffixes) if (process.env[s]) return process.env[s];
  for (const [k, v] of Object.entries(process.env)) {
    if (v && suffixes.some(s => k.endsWith('_' + s) || k.endsWith(s)) && !k.includes('READ_ONLY')) return v;
  }
  return undefined;
}
const DB_URL = findEnv(['KV_REST_API_URL', 'UPSTASH_REDIS_REST_URL', 'REDIS_REST_URL']);
const DB_TOKEN = findEnv(['KV_REST_API_TOKEN', 'UPSTASH_REDIS_REST_TOKEN', 'REDIS_REST_TOKEN']);

export const MAX_PIN_TRIES = 8;
const P = 'gx:';
const enc = encodeURIComponent;
export const K = {
  admin: P + 'admin',
  adminFails: P + 'adminfails',
  config: P + 'config',
  round: P + 'round',
  pin: (r, n) => `${P}pin:${r}:${enc(n)}`,
  fails: (r, n) => `${P}fails:${r}:${enc(n)}`,
  wish: (r, n) => `${P}wish:${r}:${enc(n)}`,
  links: (r, n) => `${P}links:${r}:${enc(n)}`,
  assign: (r) => `${P}assign:${r}`,
  lock: (r) => `${P}lock:${r}`,
  log: P + 'log',
};

// ---------- database (Upstash Redis REST) ----------
const mem = globalThis.__giftMem || (globalThis.__giftMem = new Map());
function mock(cmd) {
  const [op, ...a] = cmd;
  switch (op.toUpperCase()) {
    case 'GET': return mem.has(a[0]) ? mem.get(a[0]) : null;
    case 'SET': { if (a.includes('NX') && mem.has(a[0])) return null; mem.set(a[0], String(a[1])); return 'OK'; }
    case 'DEL': { let n = 0; for (const k of a) if (mem.delete(k)) n++; return n; }
    case 'INCR': { const v = Number(mem.get(a[0]) || 0) + 1; mem.set(a[0], String(v)); return v; }
    case 'EXPIRE': return 1;
    case 'MGET': return a.map(k => (mem.has(k) ? mem.get(k) : null));
    case 'LPUSH': { const l = JSON.parse(mem.get(a[0]) || '[]'); l.unshift(...a.slice(1).reverse()); mem.set(a[0], JSON.stringify(l)); return l.length; }
    case 'LTRIM': { const l = JSON.parse(mem.get(a[0]) || '[]'); mem.set(a[0], JSON.stringify(l.slice(Number(a[1]), Number(a[2]) + 1))); return 'OK'; }
    case 'LRANGE': { const l = JSON.parse(mem.get(a[0]) || '[]'); return l.slice(Number(a[1]), Number(a[2]) + 1); }
    default: throw new Error('mock: unsupported ' + op);
  }
}

export async function db(...cmd) {
  if (process.env.MOCK_REDIS) return mock(cmd);
  if (!DB_URL || !DB_TOKEN) throw new Error('DB_NOT_CONNECTED');
  const r = await fetch(DB_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${DB_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

export async function getJSON(key) {
  const v = await db('GET', key);
  return v ? JSON.parse(v) : null;
}

// Simple lock so two people spinning at the same moment can't collide
export async function withLock(round, fn) {
  const key = K.lock(round);
  for (let i = 0; i < 60; i++) {
    const ok = await db('SET', key, '1', 'NX', 'PX', '8000');
    if (ok === 'OK') {
      try { return await fn(); } finally { await db('DEL', key); }
    }
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error('BUSY');
}

// ---------- activity log ----------
function device(req) {
  const ua = String(req?.headers?.['user-agent'] || '');
  if (/iPhone/i.test(ua)) return 'iPhone';
  if (/iPad/i.test(ua)) return 'iPad';
  if (/Android/i.test(ua)) return 'Android';
  if (/Macintosh/i.test(ua)) return 'Mac';
  if (/Windows/i.test(ua)) return 'Windows';
  if (/CrOS/i.test(ua)) return 'Chromebook';
  return ua ? 'Other' : '';
}
// Never throws: logging must not break the site
export async function log(req, who, what) {
  try {
    await db('LPUSH', K.log, JSON.stringify({ t: Date.now(), who: who || '', what, dev: device(req) }));
    await db('LTRIM', K.log, 0, 1999);
  } catch {}
}
export async function readLog(n = 500) {
  const rows = await db('LRANGE', K.log, 0, n - 1);
  return (rows || []).map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
}

// ---------- hashing ----------
export function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(String(secret), salt, 32).toString('hex')}`;
}
export function checkSecret(secret, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, h] = stored.split(':');
  const test = crypto.scryptSync(String(secret), salt, 32);
  const real = Buffer.from(h, 'hex');
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}

// ---------- drawing rules ----------
export function makeAllowed(groups) {
  const banned = new Set();
  for (const g of groups || []) for (const a of g) for (const b of g) if (a !== b) banned.add(a + '\u0000' + b);
  return (g, r) => g !== r && !banned.has(g + '\u0000' + r);
}

// Can every giver still get a different allowed receiver? (bipartite matching)
export function canFinish(givers, receivers, allowed) {
  if (givers.length !== receivers.length) return false;
  const matchR = new Map();
  const tryG = (g, seen) => {
    for (const r of receivers) {
      if (!allowed(g, r) || seen.has(r)) continue;
      seen.add(r);
      if (!matchR.has(r) || tryG(matchR.get(r), seen)) { matchR.set(r, g); return true; }
    }
    return false;
  };
  return givers.every(g => tryG(g, new Set()));
}

// Pick a receiver for `giver`, preferring people who already have wish lists,
// and never picking someone that would leave the rest of the draw impossible.
export function pickReceiver(giver, names, assign, allowed, hasWish) {
  const takenR = new Set(Object.values(assign));
  const givers = names.filter(n => !(n in assign));
  const receivers = names.filter(n => !takenR.has(n));
  const restG = givers.filter(n => n !== giver);
  const ok = receivers.filter(r => allowed(giver, r) && canFinish(restG, receivers.filter(x => x !== r), allowed));
  if (!ok.length) return null;
  // Always pick someone who has a wish list if any are available; otherwise anyone allowed.
  const withWish = ok.filter(r => hasWish.has(r));
  const pool = withWish.length ? withWish : ok;
  return pool[crypto.randomInt(pool.length)];
}

// ---------- wish list links ----------
const MAX_LINKS = 25;
export function parseLinks(v) {
  if (!v) return [];
  try { const a = JSON.parse(v); return Array.isArray(a) ? a : []; } catch { return []; }
}
// Accepts [{url, note}], pulls the real link out of share text like "Check out this item on Amazon https://a.co/d/xyz"
export function cleanLinks(arr) {
  const out = []; let skipped = 0;
  for (const item of (arr || []).slice(0, MAX_LINKS)) {
    let raw = String(item?.url ?? '').trim();
    let note = String(item?.note ?? '').replace(/\s+/g, ' ').trim().slice(0, 200);
    if (!raw && !note) continue;
    const found = raw.match(/https?:\/\/[^\s<>"]+/i);
    let url = found ? found[0] : (/^[^\s]+\.[a-z]{2,}(\/\S*)?$/i.test(raw) ? 'https://' + raw : '');
    url = url.replace(/[).,!?]+$/, '');
    try {
      const u = new URL(url);
      if (!/^https?:$/.test(u.protocol) || url.length > 2000) throw 0;
      if (found && !note) {
        const leftover = raw.replace(found[0], '').replace(/\s+/g, ' ').trim();
        if (leftover) note = leftover.slice(0, 200);
      }
      out.push({ url: u.toString(), note });
    } catch { skipped++; }
  }
  return { links: out, skipped };
}
// Links typed into the wish list text (same rules as the page uses to display them)
export // Display-only: pull links typed into wish list text out into link cards. Never saved.
function splitWishLinks(text) {
  const URL_G = /https?:\/\/[^\s<>"]+/gi;
  const lines = String(text || '').replace(/\r/g, '').split('\n');
  const keep = [], links = [];
  const tidy = s => s.replace(/^[\s\-–—•*·>]+/, '').replace(/[\s\-–—:|·,(\[]+$/, '').trim();
  const unparen = s => { const t = s.trim(); const m = t.match(/^\((.*)\)$/); return (m ? m[1] : t).trim(); };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const found = line.match(URL_G) || [];
    if (found.length !== 1) { keep.push(line); continue; }   // no link, or several on one line: leave as text
    const raw = found[0];
    const url = raw.replace(/[).,!?]+$/, '');
    try { const u = new URL(url); if (!/^https?:$/.test(u.protocol)) throw 0; } catch { keep.push(line); continue; }
    const at = line.indexOf(raw);
    const before = tidy(line.slice(0, at));
    let after = line.slice(at + url.length).trim();
    if (after.startsWith(')') && !after.includes('(')) after = after.slice(1).trim();
    const extras = [];
    if (tidy(after)) extras.push(unparen(tidy(after)));
    const next = lines[i + 1];
    if (next !== undefined && /^\s*\([^()]*\)\s*$/.test(next) && !URL_G.test(next)) { extras.push(unparen(next)); i++; }
    URL_G.lastIndex = 0;
    links.push({ url, note: [before, ...extras].filter(Boolean).join(' · ') });
  }
  return { text: keep.join('\n').replace(/\n{3,}/g, '\n\n').trim(), links };
}

const linkKey = (u) => { try { const x = new URL(u); return (x.host.replace(/^www\./, '') + x.pathname.replace(/\/+$/, '') + x.search).toLowerCase(); } catch { return String(u).toLowerCase(); } };
// Adds links found in the text to the saved links. Never removes or edits existing ones.
export function mergeTextLinks(saved, text) {
  const out = [...(saved || [])];
  const seen = new Set(out.map(l => linkKey(l.url)));
  let added = 0;
  for (const l of splitWishLinks(text).links) {
    if (out.length >= MAX_LINKS) break;
    const k = linkKey(l.url);
    if (seen.has(k)) continue;
    seen.add(k); out.push({ url: l.url, note: String(l.note || '').slice(0, 200) }); added++;
  }
  return { links: out, added };
}

export async function hasListFor(round, name) {
  const [w, l] = await db('MGET', K.wish(round, name), K.links(round, name));
  return !!w || parseLinks(l).length > 0;
}

// ---------- status ----------
export async function statusOf(round, names) {
  if (!names.length) return { setup: [], wish: [], drawn: [], assign: {} };
  const vals = await db('MGET', ...names.map(n => K.pin(round, n)), ...names.map(n => K.wish(round, n)), ...names.map(n => K.links(round, n)));
  const assign = (await getJSON(K.assign(round))) || {};
  const n = names.length;
  return {
    setup: vals.slice(0, n).map(v => v !== null),
    wish: names.map((_, i) => !!vals[n + i] || parseLinks(vals[2 * n + i]).length > 0),
    drawn: names.map(x => x in assign),
    assign,
  };
}

// ---------- http helpers ----------
export function send(res, code, body) {
  res.setHeader('Cache-Control', 'no-store');
  res.status(code).json(body);
}
export function body(req) {
  if (!req.body) return {};
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return {}; } }
  return req.body;
}
export async function handleErr(res, e, req, who) {
  if (e.message === 'DB_NOT_CONNECTED') return send(res, 503, { error: 'db', message: 'Database not connected yet.' });
  if (e.message === 'BUSY') { await log(req, who, 'Spin had to wait too long (busy). Told them to try again.'); return send(res, 503, { error: 'busy', message: 'Lots of people spinning right now. Try again in a few seconds.' }); }
  console.error(e);
  await log(req, who, 'ERROR: ' + String(e.message || e).slice(0, 200));
  return send(res, 500, { error: 'server', message: 'Something went wrong. Try again.' });
}
