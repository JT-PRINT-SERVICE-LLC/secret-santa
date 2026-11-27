import {
  db, getJSON, K, send, body, hashSecret, checkSecret, handleErr,
  statusOf, withLock, makeAllowed, canFinish,
} from './_lib.js';

const clean = (s, max = 80) => String(s ?? '').replace(/\s+/g, ' ').trim().slice(0, max);

export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { error: 'method' });
  try {
    const b = body(req);
    const stored = await db('GET', K.admin);

    if (b.action === 'status') return send(res, 200, { hasPassword: !!stored });

    if (b.action === 'setup') {
      if (stored) return send(res, 409, { error: 'exists', message: 'Password already set. Log in instead.' });
      if (String(b.password || '').length < 6) return send(res, 400, { error: 'short', message: 'Use at least 6 characters.' });
      const ok = await db('SET', K.admin, hashSecret(b.password), 'NX');
      if (ok !== 'OK') return send(res, 409, { error: 'exists', message: 'Password already set. Log in instead.' });
      return send(res, 200, { ok: true });
    }

    const fails = Number((await db('GET', K.adminFails)) || 0);
    if (fails >= 10) return send(res, 429, { error: 'slow', message: 'Too many wrong passwords. Wait 15 minutes.' });
    if (!stored || !checkSecret(b.password || '', stored)) {
      await db('INCR', K.adminFails);
      await db('EXPIRE', K.adminFails, 900);
      return send(res, 401, { error: 'auth', message: 'Wrong password.' });
    }
    if (fails) await db('DEL', K.adminFails);

    const config = await getJSON(K.config);
    const round = await db('GET', K.round);

    if (b.action === 'load') {
      if (!config) return send(res, 200, { config: null });
      const st = await statusOf(round, config.names);
      return send(res, 200, { config, setup: st.setup, wish: st.wish, drawn: st.drawn });
    }

    if (b.action === 'details') {
      if (!config) return send(res, 409, { error: 'none', message: 'Set up the names first.' });
      const next = { ...config, title: clean(b.title) || config.title, organizer: clean(b.organizer, 40), price: clean(b.price, 40), date: clean(b.date, 60) };
      await db('SET', K.config, JSON.stringify(next));
      return send(res, 200, { ok: true });
    }

    // Start (or restart) with a list of names. Wipes all PINs, wish lists and draws.
    if (b.action === 'open') {
      const names = [...new Set((b.names || []).map(n => clean(n, 40)).filter(Boolean))];
      if (names.length < 3) return send(res, 400, { error: 'few', message: 'Need at least 3 names.' });
      const lower = new Map(names.map(n => [n.toLowerCase(), n]));
      const groups = [];
      for (const g of b.groups || []) {
        const members = [];
        for (const raw of g) {
          const n = lower.get(clean(raw, 40).toLowerCase());
          if (!n) return send(res, 400, { error: 'group', message: `"${clean(raw, 40)}" in the couples list isn’t in the names list.` });
          members.push(n);
        }
        if (members.length > 1) groups.push(members);
      }
      if (!canFinish(names, names, makeAllowed(groups))) {
        return send(res, 400, { error: 'impossible', message: 'Those couple rules make a full drawing impossible. Check the lists.' });
      }
      if (config && !b.confirm) {
        const st = await statusOf(round, config.names);
        if (st.setup.some(Boolean)) return send(res, 409, { error: 'confirm', message: 'People already set up. Starting over wipes everything.' });
      }
      await db('INCR', K.round);
      await db('SET', K.config, JSON.stringify({
        title: clean(b.title) || 'Secret Santa',
        organizer: clean(b.organizer, 40),
        price: clean(b.price, 40),
        date: clean(b.date, 60),
        names, groups,
      }));
      return send(res, 200, { ok: true });
    }

    if (!config || !config.names.includes(b.name)) {
      if (['newpin', 'reset'].includes(b.action)) return send(res, 404, { error: 'name', message: 'Name not found.' });
    }

    // Forgot PIN / locked out: keeps their wish list and their person
    if (b.action === 'newpin') {
      await db('DEL', K.pin(round, b.name), K.fails(round, b.name));
      return send(res, 200, { ok: true });
    }

    // Wrong person used this name: clears PIN, wish list, and their draw
    if (b.action === 'reset') {
      await withLock(round, async () => {
        const assign = (await getJSON(K.assign(round))) || {};
        delete assign[b.name];
        await db('SET', K.assign(round), JSON.stringify(assign));
      });
      await db('DEL', K.pin(round, b.name), K.fails(round, b.name), K.wish(round, b.name));
      return send(res, 200, { ok: true });
    }

    if (b.action === 'reveal') {
      if (!config) return send(res, 409, { error: 'none', message: 'Nothing set up yet.' });
      const assign = (await getJSON(K.assign(round))) || {};
      return send(res, 200, { pairs: config.names.map(n => [n, assign[n] || null]) });
    }

    return send(res, 400, { error: 'action' });
  } catch (e) { handleErr(res, e); }
}
