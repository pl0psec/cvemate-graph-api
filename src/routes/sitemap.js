const db = require('../services/arango');

// Cache storage
let cachedData = null;
let cacheExpiry = null;
let isRefreshing = false;

const CACHE_DURATION = 60 * 60 * 1000; // 1 hour in milliseconds

async function fetchURLsFromDB(fastify) {
  const startTime = Date.now();
  fastify.log.info('🔄 Fetching URLs from ArangoDB...');

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

    const duration = ((Date.now() - startTime) / 1000).toFixed(2);
    fastify.log.info(`✅ Fetched ${urlData.length} URLs in ${duration}s`);

    return { count: urlData.length, urls: urlData };
  } catch (err) {
    fastify.log.error(err, '❌ Failed to fetch URLs from database');
    throw err;
  }
}

async function refreshCache(fastify) {
  if (isRefreshing) {
    fastify.log.info('⏭️  Cache refresh already in progress, skipping...');
    return;
  }

  isRefreshing = true;

  try {
    const data = await fetchURLsFromDB(fastify);
    cachedData = data;
    cacheExpiry = Date.now() + CACHE_DURATION;
    
    fastify.log.info(`✅ Cache refreshed. Next refresh at: ${new Date(cacheExpiry).toISOString()}`);
  } catch (err) {
    fastify.log.error(err, '❌ Cache refresh failed');
    // Keep old cache if refresh fails
  } finally {
    isRefreshing = false;
  }
}

function isCacheValid() {
  return cachedData !== null && cacheExpiry !== null && Date.now() < cacheExpiry;
}

async function getURLs(request, reply) {
  try {
    // Check if cache is valid
    if (isCacheValid()) {
      request.log.info('✅ Serving from cache');
      return reply.send(cachedData);
    }

    // Cache expired or doesn't exist
    request.log.info('⚠️  Cache expired or empty, fetching fresh data...');
    
    // If we have stale cache, serve it while refreshing in background
    if (cachedData !== null) {
      request.log.info('📤 Serving stale cache while refreshing...');
      
      // Refresh in background (don't await)
      refreshCache(request.server);
      
      return reply.send(cachedData);
    }

    // No cache at all, must wait for fresh data
    const data = await fetchURLsFromDB(request.server);
    cachedData = data;
    cacheExpiry = Date.now() + CACHE_DURATION;
    
    return reply.send(data);
  } catch (err) {
    request.log.error(err, '❌ Failed to get URLs');
    return reply.code(500).send({ error: 'Failed to build URLs' });
  }
}

async function routes(fastify, options) {
  // Warmup cache when Fastify starts
  fastify.addHook('onReady', async () => {
    fastify.log.info('🔥 Warming up cache on server start...');
    await refreshCache(fastify);
  });

  // Schedule periodic cache refresh (every 55 minutes)
  const refreshInterval = 55 * 60 * 1000; // 55 minutes (before 1 hour expiry)
  
  setInterval(async () => {
    fastify.log.info('⏰ Scheduled cache refresh triggered');
    await refreshCache(fastify);
  }, refreshInterval);

  fastify.log.info(`⏰ Cache auto-refresh scheduled every ${refreshInterval / 60000} minutes`);

  // Routes
  fastify.get('/urls', getURLs);

  // Optional: Manual cache refresh endpoint
  fastify.post('/urls/refresh', async (request, reply) => {
    await refreshCache(fastify);
    return reply.send({ success: true, message: 'Cache refreshed' });
  });

  // Optional: Cache status endpoint
  fastify.get('/urls/status', async (request, reply) => {
    return reply.send({
      cached: cachedData !== null,
      valid: isCacheValid(),
      count: cachedData?.count || 0,
      expiresAt: cacheExpiry ? new Date(cacheExpiry).toISOString() : null,
      expiresIn: cacheExpiry ? Math.max(0, cacheExpiry - Date.now()) : 0
    });
  });
}

module.exports = routes;