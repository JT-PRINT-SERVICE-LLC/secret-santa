import {
  db, getJSON, K, send, body, hashSecret, checkSecret, handleErr, MAX_PIN_TRIES,
  withLock, makeAllowed, pickReceiver, log, cleanLinks, parseLinks, hasListFor,
} from './_lib.js';

const MAX_WISH = 1500;
const cleanWish = (w) => String(w ?? '').replace(/\r/g, '').slice(0, MAX_WISH).trim();

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  let name = '';
  try {
    const b = body(req); name = String(b.name || '').slice(0, 40);
    const { pin, action, wish } = b;
    if (!/^\d{4}$/.test(String(pin || ''))) return send(res, 400, { error: 'pin', message: 'The PIN has to be 4 numbers.' });

    const config = await getJSON(K.config);
    if (!config) return send(res, 409, { error: 'notready', message: 'This isn’t set up yet.' });
    if (!config.names.includes(name)) return send(res, 404, { error: 'name', message: 'Name not found. Refresh the page.' });

    const round = await db('GET', K.round);
    const pinKey = K.pin(round, name);
    const failKey = K.fails(round, name);
    const who = config.organizer || 'the organizer';

    // Links are only touched when the page sends them (older open pages don't)
    const sentLinks = Array.isArray(b.links) ? cleanLinks(b.links) : null;
    const saveLinks = async () => {
      if (!sentLinks) return;
      if (sentLinks.links.length) await db('SET', K.links(round, name), JSON.stringify(sentLinks.links));
      else await db('DEL', K.links(round, name));
    };
    const linkNote = () => (sentLinks ? `, ${sentLinks.links.length} link${sentLinks.links.length === 1 ? '' : 's'}` : '');

    const panel = async (extra = {}) => {
      const assign = (await getJSON(K.assign(round))) || {};
      const receiver = assign[name] || null;
      const keys = [K.wish(round, name), K.links(round, name)];
      if (receiver) keys.push(K.wish(round, receiver), K.links(round, receiver));
      const [myWish, myLinks, theirWish, theirLinks] = await db('MGET', ...keys);
      return {
        receiver,
        myWish: myWish || '', myLinks: parseLinks(myLinks),
        theirWish: theirWish || '', theirLinks: parseLinks(theirLinks),
        skippedLinks: sentLinks ? sentLinks.skipped : 0,
        ...extra,
      };
    };

    // First time: save wish list + PIN together
    if (action === 'setup') {
      const text = cleanWish(wish);
      const [existingWish, existingLinks] = await db('MGET', K.wish(round, name), K.links(round, name));
      const hasAny = text || (sentLinks && sentLinks.links.length) || existingWish || parseLinks(existingLinks).length;
      if (!hasAny) return send(res, 400, { error: 'wish', message: 'Add at least one thing you’d like (or a link).' });
      const ok = await db('SET', pinKey, hashSecret(pin), 'NX');
      if (ok !== 'OK') { await log(req, name, 'Tried to set up, but this name was already set up'); return send(res, 409, { error: 'taken', message: `${name} is already set up. Tap the name and enter the PIN.` }); }
      if (text) await db('SET', K.wish(round, name), text);
      if (sentLinks && sentLinks.links.length) await saveLinks();
      const fresh = text || (sentLinks && sentLinks.links.length);
      await log(req, name, fresh ? `Set up: made PIN and saved wish list (${text.length} chars${linkNote()})` : 'Made a new PIN (kept old wish list)');
      return send(res, 200, await panel());
    }

    // Everything else needs the right PIN
    const stored = await db('GET', pinKey);
    if (!stored) return send(res, 409, { error: 'nopin', message: 'This name isn’t set up yet.' });
    const fails = Number((await db('GET', failKey)) || 0);
    if (fails >= MAX_PIN_TRIES) { await log(req, name, 'Blocked: locked out from too many wrong PINs'); return send(res, 423, { error: 'locked', message: `Too many wrong PINs. Text ${who} to unlock it.` }); }
    if (!checkSecret(pin, stored)) {
      const n = await db('INCR', failKey);
      const left = Math.max(0, MAX_PIN_TRIES - n);
      await log(req, name, `Wrong PIN (${left} tries left)${left ? '' : ' - now LOCKED'}`);
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
      await saveLinks();
      await log(req, name, `Updated wish list (${text.length} chars${linkNote()})`);
      return send(res, 200, await panel());
    }

    if (action === 'draw') {
      if (!(await hasListFor(round, name))) { await log(req, name, 'Tried to spin without a wish list (blocked)'); return send(res, 400, { error: 'nowish', message: 'Save your wish list first, then you can spin.' }); }
      const result = await withLock(round, async () => {
        const assign = (await getJSON(K.assign(round))) || {};
        if (assign[name]) return { already: true };
        const vals = await db('MGET', ...config.names.map(n => K.wish(round, n)), ...config.names.map(n => K.links(round, n)));
        const N = config.names.length;
        const hasWish = new Set(config.names.filter((n, i) => !!vals[i] || parseLinks(vals[N + i]).length > 0));
        const r = pickReceiver(name, config.names, assign, makeAllowed(config.groups), hasWish);
        if (!r) return { stuck: true };
        assign[name] = r;
        await db('SET', K.assign(round), JSON.stringify(assign));
        return { ok: true };
      });
      await log(req, name, result.stuck ? 'SPIN FAILED: no valid person left (stuck)' : result.already ? 'Tapped spin again (already had a person)' : 'Spun the wheel and got their person');
      if (result.stuck) return send(res, 409, { error: 'stuck', message: `Something’s off with the drawing. Text ${who}.` });
      return send(res, 200, await panel({ justDrew: !result.already }));
    }

    // action === 'login'
    await log(req, name, 'Logged in with PIN');
    return send(res, 200, await panel());
  } catch (e) { return handleErr(res, e, req, name); }
}
