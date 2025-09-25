const db = require('../services/arango');

// GET /datasources -> list all data source tracking docs with selected fields
async function listDataSources(request, reply) {
  try {
    const cursor = await db.query(`
      FOR ds IN data_sources
        SORT ds.last_pull_date DESC
        RETURN {
          name: ds.name,
          last_pull_date: ds.last_pull_date,
          last_update_date: ds.last_update_date,
          current_version: ds.current_version,
          source_url: ds.source_url,
          local_path: ds.local_path,
          model_version: ds.model_version,
          score_date: ds.score_date,
          last_pull_status: ds.last_pull_status,
          last_pull_error: ds.last_pull_error
        }
    `);
    const results = await cursor.all();
    reply.send({ count: results.length, results });
  } catch (err) {
    request.log.error(err, 'Failed to fetch data sources');
    reply.code(500).send({ error: 'Failed to fetch data sources' });
  }
}

async function routes(fastify, options) {
  fastify.get('/', listDataSources);
}

module.exports = routes;
