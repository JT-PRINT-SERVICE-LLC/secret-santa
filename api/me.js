import {
  db, getJSON, K, send, body, hashSecret, checkSecret, handleErr, MAX_PIN_TRIES,
  withLock, makeAllowed, pickReceiver,
} from './_lib.js';

const MAX_WISH = 1500;
const cleanWish = (w) => String(w ?? '').replace(/\r/g, '').slice(0, MAX_WISH).trim();

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  try {
    const { name, pin, action, wish } = body(req);
    if (!/^\d{4}$/.test(String(pin || ''))) return send(res, 400, { error: 'pin', message: 'The PIN has to be 4 numbers.' });

    const config = await getJSON(K.config);
    if (!config) return send(res, 409, { error: 'notready', message: 'This isn’t set up yet.' });
    if (!config.names.includes(name)) return send(res, 404, { error: 'name', message: 'Name not found. Refresh the page.' });

    const round = await db('GET', K.round);
    const pinKey = K.pin(round, name);
    const failKey = K.fails(round, name);
    const who = config.organizer || 'the organizer';

    const panel = async () => {
      const assign = (await getJSON(K.assign(round))) || {};
      const receiver = assign[name] || null;
      const keys = [K.wish(round, name)];
      if (receiver) keys.push(K.wish(round, receiver));
      const [myWish, theirWish] = await db('MGET', ...keys);
      return { receiver, myWish: myWish || '', theirWish: theirWish || '' };
    };

    // First time: save wish list + PIN together
    if (action === 'setup') {
      const text = cleanWish(wish);
      const existing = await db('GET', K.wish(round, name));
      if (!text && !existing) return send(res, 400, { error: 'wish', message: 'Type at least one thing you’d like.' });
      const ok = await db('SET', pinKey, hashSecret(pin), 'NX');
      if (ok !== 'OK') return send(res, 409, { error: 'taken', message: `${name} is already set up. Tap the name and enter the PIN.` });
      if (text) await db('SET', K.wish(round, name), text);
      return send(res, 200, await panel());
    }

    // Everything else needs the right PIN
    const stored = await db('GET', pinKey);
    if (!stored) return send(res, 409, { error: 'nopin', message: 'This name isn’t set up yet.' });
    const fails = Number((await db('GET', failKey)) || 0);
    if (fails >= MAX_PIN_TRIES) return send(res, 423, { error: 'locked', message: `Too many wrong PINs. Text ${who} to unlock it.` });
    if (!checkSecret(pin, stored)) {
      const n = await db('INCR', failKey);
      const left = Math.max(0, MAX_PIN_TRIES - n);
      return send(res, 401, {
        error: 'wrongpin',
        message: left ? `That PIN isn’t right. ${left} ${left === 1 ? 'try' : 'tries'} left.` : `Too many wrong PINs. Text ${who} to unlock it.`,
      });
    }
    if (fails) await db('DEL', failKey);

    if (action === 'wish') {
      const text = cleanWish(wish);
      if (text) await db('SET', K.wish(round, name), text);
      else await db('DEL', K.wish(round, name));
      return send(res, 200, await panel());
    }

    if (action === 'draw') {
      const mine = await db('GET', K.wish(round, name));
      if (!mine) return send(res, 400, { error: 'nowish', message: 'Save your wish list first, then you can spin.' });
      const result = await withLock(round, async () => {
        const assign = (await getJSON(K.assign(round))) || {};
        if (assign[name]) return { already: true };
        const wishes = await db('MGET', ...config.names.map(n => K.wish(round, n)));
        const hasWish = new Set(config.names.filter((n, i) => !!wishes[i]));
        const r = pickReceiver(name, config.names, assign, makeAllowed(config.groups), hasWish);
        if (!r) return { stuck: true };
        assign[name] = r;
        await db('SET', K.assign(round), JSON.stringify(assign));
        return { ok: true };
      });
      if (result.stuck) return send(res, 409, { error: 'stuck', message: `Something’s off with the drawing. Text ${who}.` });
      return send(res, 200, { ...(await panel()), justDrew: !result.already });
    }

    // action === 'login'
    return send(res, 200, await panel());
  } catch (e) { handleErr(res, e); }
}
