const db = require('../services/arango');

async function getURLs(request, reply) {
  try {
    const cursor = await db.query(`
      FOR vul IN vulnerabilities
        FILTER HAS(vul, 'id') && STARTS_WITH(vul.id, "CVE-")
        RETURN { id: vul.id, lastmod: vul.updated_at }       
    `);
    const results = await cursor.all();
    const urlData = results.map(row => ({
      link: `/vulnerability/${encodeURIComponent(row.id)}`,
      lastmod: row.lastmod
    }));
    reply.send({ count: urlData.length, urls: urlData });
  } catch (err) {
    request.log.error(err, 'Failed to build URLs');
    reply.code(500).send({ error: 'Failed to build URLs' });
  }
}

async function routes(fastify, options) {
  fastify.get('/urls', getURLs);
}

module.exports = routes;
