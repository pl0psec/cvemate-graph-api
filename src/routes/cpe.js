const db = require('../services/arango');

// GET /vendors?search=...  -- search vendors
// GET /products?search=...&vendor=...  -- search products, optionally filter by vendor
// GET /versions?vendor=...&product=...  -- get all versions for a vendor/product
// GET /cves?vendor=...&product=...&version=...  -- get all CVEs for a vendor/product/version
// GET /vendor/:vendor/products  -- list products for a vendor
// GET /product/:product/versions  -- list versions for a product

async function cpeRoutes(fastify, options) {
  // Search vendors
  fastify.get('/vendors', async (req, reply) => {
    const { search } = req.query;
    if (!search || typeof search !== 'string' || search.length < 3) {
      return reply.code(400).send({ error: 'Query must be at least 3 characters' });
    }
    try {
      const queryStr = `FOR v IN cpe_vendors FILTER LIKE(LOWER(v.name), LOWER(@q), true) RETURN v.name`;
      const cursor = await db.query(queryStr, { q: `%${search}%` });
      const results = await cursor.all();
      return { vendors: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });

  // Search products, optionally filter by vendor
  fastify.get('/products', async (req, reply) => {
    const { search, vendor } = req.query;
    if (!search || typeof search !== 'string' || search.length < 3) {
      return reply.code(400).send({ error: 'Query must be at least 3 characters' });
    }
    try {
      let queryStr = `FOR p IN cpe_products FILTER LIKE(LOWER(p.name), LOWER(@q), true)`;
      const bindVars = { q: `%${search}%` };
      if (vendor) {
        queryStr += ' && p.vendor == @vendor';
        bindVars.vendor = vendor;
      }
      queryStr += ' RETURN p.name';
      const cursor = await db.query(queryStr, bindVars);
      const results = await cursor.all();
      return { products: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });

  // Get all versions for a vendor/product
  fastify.get('/versions', async (req, reply) => {
    const { vendor, product } = req.query;
    if (!vendor || !product) {
      return reply.code(400).send({ error: 'vendor and product are required' });
    }
    try {
      const queryStr = `FOR v IN cpe_versions FILTER v.product == @product && v.vendor == @vendor RETURN DISTINCT v.version`;
      const cursor = await db.query(queryStr, { vendor, product });
      const results = await cursor.all();
      return { versions: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });

  // Get all CVEs for a vendor/product/version
  fastify.get('/cves', async (req, reply) => {
    const { vendor, product, version } = req.query;
    if (!vendor || !product || !version) {
      return reply.code(400).send({ error: 'vendor, product, and version are required' });
    }
    try {
      const version_key = `${vendor}:${product}:${version}`;
      const queryStr = `
        FOR v IN cpe_versions
          FILTER v._key == @version_key
          FOR edge IN version_cve_edges
            FILTER edge._from == v._id
            FOR cve IN vulnerabilities
              FILTER cve._id == edge._to
              RETURN cve.id
      `;
      const cursor = await db.query(queryStr, { version_key });
      const results = await cursor.all();
      return { cves: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });

  // List products for a vendor
  fastify.get('/vendor/:vendor/products', async (req, reply) => {
    const { vendor } = req.params;
    if (!vendor) {
      return reply.code(400).send({ error: 'vendor is required' });
    }
    try {
      const queryStr = `FOR p IN cpe_products FILTER p.vendor == @vendor RETURN p.name`;
      const cursor = await db.query(queryStr, { vendor });
      const results = await cursor.all();
      return { products: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });

  // List versions for a product
  fastify.get('/product/:product/versions', async (req, reply) => {
    const { product } = req.params;
    if (!product) {
      return reply.code(400).send({ error: 'product is required' });
    }
    try {
      const queryStr = `FOR v IN cpe_versions FILTER v.product == @product RETURN DISTINCT v.version`;
      const cursor = await db.query(queryStr, { product });
      const results = await cursor.all();
      return { versions: results };
    } catch (err) {
      req.log.error(err);
      return reply.code(500).send({ error: 'Database error' });
    }
  });
}

module.exports = cpeRoutes;