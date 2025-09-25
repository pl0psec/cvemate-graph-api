const db = require('../services/arango');

async function getCwes(request, reply) {
  const { page = 1, limit = 10, id, name } = request.query;
  const offset = (page - 1) * limit;
  let filter = '';
  const bindVars = {};
  if (id) {
    filter += 'FILTER cwe.id == @id ';
    bindVars.id = id;
  }
  if (name) {
    filter += 'FILTER cwe.name == @name ';
    bindVars.name = name;
  }
  const query = `
    FOR cwe IN cwe_nodes
      ${filter}
      SORT cwe.id ASC
      LIMIT @offset, @limit
      RETURN { id: cwe.id, name: cwe.name, description: cwe.description }
  `;
  const cursor = await db.query(query, { ...bindVars, offset, limit: Number(limit) });
  const result = await cursor.all();
  reply.send(result);
}

async function routes(fastify, options) {
  fastify.get('/', getCwes);
}

module.exports = routes;
