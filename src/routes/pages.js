const db = require('../services/arango');

async function getURLs(request, reply) {
  try {
    // Fetch only IDs to minimize payload
    const cursor = await db.query(`
      FOR vul IN vulnerabilities
      FILTER HAS(vul, 'id') && STARTS_WITH(vul.id, "CVE-")
      RETURN vul.id
    `);
    const ids = await cursor.all();
    // const base = process.env.PUBLIC_SITE_BASE || 'http://localhost:3000';
    // const urls = ids.map(id => `${base.replace(/\/$/, '')}/vulnerability/${encodeURIComponent(id)}`);
    const urls = ids.map(id => `/vulnerability/${encodeURIComponent(id)}`);
    reply.send({ count: urls.length, urls });
  } catch (err) {
    request.log.error(err, 'Failed to build URLs');
    reply.code(500).send({ error: 'Failed to build URLs' });
  }
}

async function routes(fastify, options) {
  fastify.get('/urls', getURLs);
}

module.exports = routes;
