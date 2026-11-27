import { db, getJSON, K, send, statusOf, handleErr } from './_lib.js';

export default async function handler(req, res) {
  try {
    const config = await getJSON(K.config);
    if (!config) return send(res, 200, { ready: false });
    const round = await db('GET', K.round);
    const st = await statusOf(round, config.names);
    send(res, 200, {
      ready: true,
      title: config.title,
      organizer: config.organizer,
      price: config.price,
      date: config.date,
      names: config.names,
      setup: st.setup,
      wish: st.wish,
      drawn: st.drawn,
    });
  } catch (e) { handleErr(res, e); }
}
