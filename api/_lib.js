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
  assign: (r) => `${P}assign:${r}`,
  lock: (r) => `${P}lock:${r}`,
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
  // Prefer people who have a wish list, but only when there are at least 3 of them to pick from.
  // With fewer, picking only from them makes the draw guessable (2nd person to join always gets the 1st).
  const withWish = ok.filter(r => hasWish.has(r));
  const pool = withWish.length >= 3 ? withWish : ok;
  return pool[crypto.randomInt(pool.length)];
}

// ---------- status ----------
export async function statusOf(round, names) {
  if (!names.length) return { setup: [], wish: [], drawn: [], assign: {} };
  const vals = await db('MGET', ...names.map(n => K.pin(round, n)), ...names.map(n => K.wish(round, n)));
  const assign = (await getJSON(K.assign(round))) || {};
  const n = names.length;
  return {
    setup: vals.slice(0, n).map(v => v !== null),
    wish: vals.slice(n).map(v => !!v),
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
export function handleErr(res, e) {
  if (e.message === 'DB_NOT_CONNECTED') return send(res, 503, { error: 'db', message: 'Database not connected yet.' });
  if (e.message === 'BUSY') return send(res, 503, { error: 'busy', message: 'Lots of people spinning right now. Try again in a few seconds.' });
  console.error(e);
  return send(res, 500, { error: 'server', message: 'Something went wrong. Try again.' });
}
