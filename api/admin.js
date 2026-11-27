import { db, getJSON, K, send, body, hashSecret, checkSecret, drawNames, claimedList, handleErr } from './_lib.js';

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

    // everything below needs the organizer password
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
    const hasDraw = !!(await db('GET', K.assign));

    if (b.action === 'load') {
      const claimed = config && hasDraw ? await claimedList(round, config.names) : [];
      const wishes = config && hasDraw ? (await db('MGET', ...config.names.map(n => K.wish(round, n)))).map(v => !!v) : [];
      return send(res, 200, { config, drawn: hasDraw, claimed, wishes });
    }

    if (b.action === 'details') {
      if (!config) return send(res, 409, { error: 'none', message: 'Draw names first.' });
      const next = { ...config, title: clean(b.title) || config.title, organizer: clean(b.organizer, 40), price: clean(b.price, 40), date: clean(b.date, 60) };
      await db('SET', K.config, JSON.stringify(next));
      return send(res, 200, { ok: true });
    }

    if (b.action === 'draw') {
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
      if (hasDraw && config) {
        const claimed = await claimedList(round, config.names);
        if (claimed.some(Boolean) && !b.confirm) {
          return send(res, 409, { error: 'confirm', message: 'Some people already drew. Redrawing wipes their picks.' });
        }
      }
      const assign = drawNames(names, groups);
      if (!assign) return send(res, 400, { error: 'impossible', message: 'Can’t make a draw with those couple rules. Check the lists.' });
      const next = {
        title: clean(b.title) || 'Gift Exchange',
        organizer: clean(b.organizer, 40),
        price: clean(b.price, 40),
        date: clean(b.date, 60),
        names,
        groups,
      };
      await db('INCR', K.round); // new round = all old claims and PINs are void
      await db('SET', K.config, JSON.stringify(next));
      await db('SET', K.assign, JSON.stringify(assign));
      return send(res, 200, { ok: true });
    }

    if (b.action === 'reset') {
      if (!config || !config.names.includes(b.name)) return send(res, 404, { error: 'name', message: 'Name not found.' });
      await db('DEL', K.claim(round, b.name), K.fails(round, b.name), K.wish(round, b.name));
      return send(res, 200, { ok: true });
    }

    if (b.action === 'reveal') {
      const assign = await getJSON(K.assign);
      if (!assign || !config) return send(res, 409, { error: 'none', message: 'Nothing drawn yet.' });
      return send(res, 200, { pairs: config.names.map(n => [n, assign[n]]) });
    }

    return send(res, 400, { error: 'action' });
  } catch (e) { handleErr(res, e); }
}
