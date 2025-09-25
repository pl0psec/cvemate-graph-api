const { Database } = require('arangojs');
const config = require('../config');

const db = new Database({
  url: config.ARANGO_URL // Use a valid URL, e.g., 'http://localhost:8529'
});
const database = db.database(config.ARANGO_DB); // Select the database by name
database.useBasicAuth(config.ARANGO_USER, config.ARANGO_PASSWORD);

// Ensure required collections exist (minimal set for current routes)
async function ensureCollections() {
  const required = [
    { name: 'vulnerabilities', edge: false },
    { name: 'aliases', edge: false },
    { name: 'vuln_aliases', edge: true },
    { name: 'vuln_related', edge: true },
    { name: 'stats', edge: false }
  ];
  for (const spec of required) {
    try {
      const exists = await database.collection(spec.name).exists();
      if (!exists) {
        await database.createCollection(spec.name, { type: spec.edge ? 3 : 2 });
        // type 2 = document, 3 = edge in arangojs low-level API
        // (alternatively database.edgeCollection when edge true)
      }
    } catch (e) {
      // Log to stderr (fastify logger may not be ready yet)
      console.error(`[arango-init] Failed ensuring collection '${spec.name}': ${e.message}`);
    }
  }
}

// Kick off (no await export – fire and forget)
ensureCollections();

module.exports = database;
