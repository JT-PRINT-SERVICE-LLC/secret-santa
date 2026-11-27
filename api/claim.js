import { db, getJSON, K, send, body, hashSecret, checkSecret, handleErr, MAX_PIN_TRIES } from './_lib.js';

const MAX_WISH = 1500;

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  try {
    const { name, pin, mode, wish } = body(req);
    if (!/^\d{4}$/.test(String(pin || ''))) return send(res, 400, { error: 'pin', message: 'The PIN has to be 4 numbers.' });

    const config = await getJSON(K.config);
    const assign = await getJSON(K.assign);
    if (!config || !assign) return send(res, 409, { error: 'notready', message: 'The drawing isn’t set up yet.' });
    if (!config.names.includes(name)) return send(res, 404, { error: 'name', message: 'Name not found. Refresh the page.' });

    const round = await db('GET', K.round);
    const claimKey = K.claim(round, name);
    const failKey = K.fails(round, name);
    const who = config.organizer || 'the organizer';

    const result = async () => {
      const receiver = assign[name];
      const [theirWish, myWish] = await db('MGET', K.wish(round, receiver), K.wish(round, name));
      return { receiver, theirWish: theirWish || '', myWish: myWish || '' };
    };

    if (mode === 'claim') {
      const set = await db('SET', claimKey, hashSecret(pin), 'NX');
      if (set === 'OK') return send(res, 200, await result());
      return send(res, 409, { error: 'taken', message: `${name} already drew. Tap the name again and enter the PIN.` });
    }

    // 'view' and 'wish' both need the right PIN
    const stored = await db('GET', claimKey);
    if (!stored) return send(res, 409, { error: 'unclaimed', message: 'This name hasn’t drawn yet.' });
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

    if (mode === 'wish') {
      const text = String(wish ?? '').replace(/\r/g, '').slice(0, MAX_WISH).trim();
      if (text) await db('SET', K.wish(round, name), text);
      else await db('DEL', K.wish(round, name));
      return send(res, 200, { ok: true, myWish: text });
    }

    return send(res, 200, await result());
  } catch (e) { handleErr(res, e); }
}
