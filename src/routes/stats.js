const db = require('../services/arango');

// Returns last 10 CRITICAL vulnerabilities not with status Deferred or Rejected
async function getLastVul(request, reply) {
  try {
    const cursor = await db.query(`
      FOR v IN vulnerabilities
        FILTER v.summary != null
          AND v.summary.severity != null
          AND LOWER(v.summary.severity) == 'critical'
          AND HAS(v, 'source_metadata')
          AND HAS(v.source_metadata, 'NVD')
          AND v.source_metadata.NVD.published != null
          AND (
            v.source_metadata.NVD.vulnStatus == null OR 
            !(v.source_metadata.NVD.vulnStatus IN ['Rejected','Deferred'])
          )
        SORT v.source_metadata.NVD.published DESC
        LIMIT 10
        RETURN { id: v.id, created_at: v.created_at, summary: v.summary }
    `);
    const results = await cursor.all();
    reply.send(results);
  } catch (err) {
    request.log.error(err, 'Failed to fetch last critical vulnerabilities');
    reply.code(500).send({ error: 'Failed to fetch last critical vulnerabilities' });
  }
}

// Returns last 10 vulnerabilities where summary.cisa_kev == true
async function getLastKev(request, reply) {
  try {
    const cursor = await db.query(`
      FOR v IN vulnerabilities
        FILTER v.summary != null
          AND v.summary.cisa_kev == true
          AND HAS(v, 'source_metadata')
          AND HAS(v.source_metadata, 'NVD')
          AND v.source_metadata.NVD.published != null
        SORT v.source_metadata.NVD.published DESC
        LIMIT 10
        RETURN { id: v.id, created_at: v.created_at, summary: v.summary }
    `);
    const results = await cursor.all();
    reply.send(results);
  } catch (err) {
    request.log.error(err, 'Failed to fetch last KEV vulnerabilities');
    reply.code(500).send({ error: 'Failed to fetch last KEV vulnerabilities' });
  }
}

// Returns last 10 vulnerabilities where summary.cisa_ransomware == true
async function getLastRansonware(request, reply) {
  try {
    const cursor = await db.query(`
      FOR v IN vulnerabilities
        FILTER v.summary != null
          AND v.summary.cisa_ransomware == true          
        SORT v.source_metadata.NVD.published DESC
        LIMIT 10
        RETURN { id: v.id, created_at: v.created_at, summary: v.summary }
    `);
    const results = await cursor.all();
    reply.send(results);
  } catch (err) {
    request.log.error(err, 'Failed to fetch last ransomware-linked vulnerabilities');
    reply.code(500).send({ error: 'Failed to fetch last ransomware-linked vulnerabilities' });
  }
}

// Returns last 10 vulnerabilities where summary.epss_severity == critical
async function getLastEpss(request, reply) {
  try {
    const cursor = await db.query(`
      FOR v IN vulnerabilities
        FILTER v.summary != null
          AND LOWER(v.summary.epss_severity) == 'critical'
          AND HAS(v, 'source_metadata')
          AND HAS(v.source_metadata, 'NVD')
          AND v.source_metadata.NVD.published != null
        SORT v.source_metadata.NVD.published DESC
        LIMIT 10
        RETURN { id: v.id, created_at: v.created_at, summary: v.summary }
    `);
    const results = await cursor.all();
    reply.send(results);
  } catch (err) {
    request.log.error(err, 'Failed to fetch last critical EPSS vulnerabilities');
    reply.code(500).send({ error: 'Failed to fetch last critical EPSS vulnerabilities' });
  }
}

// Returns last 10 vulnerabilities where summary.exploit_count > 0
async function getLastExploit(request, reply) {
  try {
    const cursor = await db.query(`
      FOR v IN vulnerabilities
        FILTER v.summary != null
          AND v.summary.exploit_count > 0
          AND HAS(v, 'source_metadata')
          AND HAS(v.source_metadata, 'NVD')
          AND v.source_metadata.NVD.published != null
        SORT v.source_metadata.NVD.published DESC
        LIMIT 10
        RETURN { id: v.id, created_at: v.created_at, summary: v.summary }
    `);
    const results = await cursor.all();
    reply.send(results);
  } catch (err) {
    request.log.error(err, 'Failed to fetch last exploited vulnerabilities');
    reply.code(500).send({ error: 'Failed to fetch last exploited vulnerabilities' });
  }
}

// Returns aggregated stats in a single payload
// Query param: limit (default 5, max 20)
async function getStats(request, reply) {
  const { limit } = request.query || {};
  let parsedLimit = parseInt(limit, 5);
  if (isNaN(parsedLimit) || parsedLimit <= 0) parsedLimit = 5; // default
  if (parsedLimit > 20) parsedLimit = 20; // clamp max

  try {
    // Parallel queries for better wall-clock latency
    const [LastVul, LastKev, LastRansonware, LastEpss, LastExploit] = await Promise.all([
      db.query(`
        FOR v IN vulnerabilities
          FILTER v.summary != null
            AND v.summary.severity != null
            AND LOWER(v.summary.severity) == 'critical'
            AND HAS(v, 'source_metadata')
            AND HAS(v.source_metadata, 'NVD')
            AND v.source_metadata.NVD.published != null
            AND (
              v.source_metadata.NVD.vulnStatus == null OR 
              !(v.source_metadata.NVD.vulnStatus IN ['Rejected','Deferred'])
            )
          SORT v.source_metadata.NVD.published DESC
          LIMIT ${parsedLimit}
          RETURN { id: v.id, description: v.descriptions[0].value,  created_at: v.created_at, summary: v.summary }
      `).then(c => c.all()),
      db.query(`
        FOR v IN vulnerabilities
          FILTER v.summary != null
            AND v.summary.cisa_kev == true
            AND HAS(v, 'source_metadata')
            AND HAS(v.source_metadata, 'NVD')
            AND v.source_metadata.NVD.published != null
          SORT v.source_metadata.NVD.published DESC
          LIMIT ${parsedLimit}
          RETURN { id: v.id, description: v.descriptions[0].value,  created_at: v.created_at, summary: v.summary }
      `).then(c => c.all()),
      db.query(`
        FOR v IN vulnerabilities
          FILTER v.summary != null
            AND v.summary.cisa_ransomware == true
            AND HAS(v, 'source_metadata')
            AND HAS(v.source_metadata, 'NVD')
            AND v.source_metadata.NVD.published != null
          SORT v.source_metadata.NVD.published DESC
          LIMIT ${parsedLimit}
          RETURN { id: v.id, description: v.descriptions[0].value,  created_at: v.created_at, summary: v.summary }
      `).then(c => c.all()),
      db.query(`
        FOR v IN vulnerabilities
          FILTER v.summary != null
            AND LOWER(v.summary.epss_severity) == 'critical'
            AND HAS(v, 'source_metadata')
            AND HAS(v.source_metadata, 'NVD')
            AND v.source_metadata.NVD.published != null
          SORT v.source_metadata.NVD.published DESC
          LIMIT ${parsedLimit}
          RETURN { id: v.id, description: v.descriptions[0].value,  created_at: v.created_at, summary: v.summary }
      `).then(c => c.all()),
      db.query(`
        FOR v IN vulnerabilities
          FILTER v.summary != null
            AND v.summary.exploit_count > 0
            AND HAS(v, 'source_metadata')
            AND HAS(v.source_metadata, 'NVD')
            AND v.source_metadata.NVD.published != null
          SORT v.source_metadata.NVD.published DESC
          LIMIT ${parsedLimit}
          RETURN { id: v.id, description: v.descriptions[0].value,  created_at: v.created_at, summary: v.summary }
      `).then(c => c.all())
    ]);

    reply.send({ LastVul, LastKev, LastRansonware, LastEpss, LastExploit });
  } catch (err) {
    request.log.error(err, 'Failed to fetch stats');
    reply.code(500).send({ error: 'Failed to fetch stats' });
  }
}


async function routes(fastify, options) {
  // fastify.get('/sources', getSources);
  // fastify.get('/cti', getCti);
  fastify.get('/tops', getLastVul);
  fastify.get('/kev', getLastKev);
  fastify.get('/ransomware', getLastRansonware);
  fastify.get('/epss', getLastEpss);
  fastify.get('/exploits', getLastExploit);
  fastify.get('/exploit', getLastExploit); // alias
  fastify.get('/', getStats);
}

module.exports = routes;

