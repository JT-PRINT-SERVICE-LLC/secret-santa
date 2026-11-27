import crypto from 'node:crypto';

const DB_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const DB_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

export const MAX_PIN_TRIES = 8;
const P = 'gx:';
export const K = {
  admin: P + 'admin',
  adminFails: P + 'adminfails',
  config: P + 'config',
  assign: P + 'assign',
  round: P + 'round',
  claim: (round, name) => `${P}claim:${round}:${encodeURIComponent(name)}`,
  fails: (round, name) => `${P}fails:${round}:${encodeURIComponent(name)}`,
  wish: (round, name) => `${P}wish:${round}:${encodeURIComponent(name)}`,
};

// ---------- database (Upstash Redis REST) ----------
const mem = globalThis.__giftMem || (globalThis.__giftMem = new Map());

function mock(cmd) {
  const [op, ...a] = cmd;
  switch (op.toUpperCase()) {
    case 'GET': return mem.has(a[0]) ? mem.get(a[0]) : null;
    case 'SET': {
      if (a.includes('NX') && mem.has(a[0])) return null;
      mem.set(a[0], String(a[1])); return 'OK';
    }
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

// ---------- hashing ----------
export function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const h = crypto.scryptSync(String(secret), salt, 32).toString('hex');
  return `${salt}:${h}`;
}

export function checkSecret(secret, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, h] = stored.split(':');
  const test = crypto.scryptSync(String(secret), salt, 32);
  const real = Buffer.from(h, 'hex');
  return real.length === test.length && crypto.timingSafeEqual(real, test);
}

// ---------- drawing ----------
function rand(n) { return crypto.randomInt(n); }
function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) { const j = rand(i + 1); [arr[i], arr[j]] = [arr[j], arr[i]]; }
  return arr;
}

// groups: arrays of names that must not draw each other (couples / households)
export function drawNames(names, groups) {
  const banned = new Set();
  for (const g of groups) for (const a of g) for (const b of g) if (a !== b) banned.add(a + '\u0000' + b);
  const ok = (g, r) => g !== r && !banned.has(g + '\u0000' + r);

  // Uniformly random: shuffle until every pairing is allowed
  for (let t = 0; t < 20000; t++) {
    const perm = shuffle([...names]);
    if (names.every((g, i) => ok(g, perm[i]))) {
      const out = {}; names.forEach((g, i) => { out[g] = perm[i]; }); return out;
    }
  }
  // Fallback: randomized backtracking (tight constraints)
  const out = {}; const used = new Set(); const givers = shuffle([...names]);
  const bt = (i) => {
    if (i === givers.length) return true;
    const g = givers[i];
    for (const r of shuffle(names.filter(n => !used.has(n) && ok(g, n)))) {
      used.add(r); out[g] = r;
      if (bt(i + 1)) return true;
      used.delete(r); delete out[g];
    }
    return false;
  };
  return bt(0) ? out : null;
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

export async function claimedList(round, names) {
  if (!names.length) return [];
  const vals = await db('MGET', ...names.map(n => K.claim(round, n)));
  return vals.map(v => v !== null);
}

export function handleErr(res, e) {
  if (e.message === 'DB_NOT_CONNECTED') return send(res, 503, { error: 'db', message: 'Database not connected yet.' });
  console.error(e);
  return send(res, 500, { error: 'server', message: 'Something went wrong. Try again.' });
}
