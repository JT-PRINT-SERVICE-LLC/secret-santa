import { db, getJSON, K, send, claimedList, handleErr } from './_lib.js';

export default async function handler(req, res) {
  try {
    const config = await getJSON(K.config);
    const assign = await db('GET', K.assign);
    if (!config || !assign) return send(res, 200, { ready: false, title: config?.title || '' });
    const round = await db('GET', K.round);
    const claimed = await claimedList(round, config.names);
    send(res, 200, {
      ready: true,
      title: config.title,
      organizer: config.organizer,
      price: config.price,
      date: config.date,
      names: config.names,
      claimed,
    });
  } catch (e) { handleErr(res, e); }
}
