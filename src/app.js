const fastify = require('fastify')({
  logger: {
    transport: {
      target: 'pino-pretty',
      options: { colorize: true }
    },
    // Include params/query/body in request logs
    serializers: {
      req(request) {
        return {
          id: request.id,
          method: request.method,
            // originalUrl retains query string
          url: request.url,
          params: request.params,
          query: request.query,
          // Be careful logging bodies in production (PII / size). Limit depth.
          body: request.body && typeof request.body === 'object' ? truncateObject(request.body) : request.body
        };
      },
      res(reply) {
        return {
          statusCode: reply.statusCode
        };
      }
    }
  }
});

// Helper to shallow copy and truncate large string fields
function truncateObject(obj) {
  const out = {};
  const maxLen = 500; // chars
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string') {
      out[k] = v.length > maxLen ? v.slice(0, maxLen) + '…(truncated)' : v;
    } else if (Array.isArray(v)) {
      out[k] = v.length > 50 ? v.slice(0, 50) : v; // avoid huge arrays
    } else if (v && typeof v === 'object') {
      // one level only to prevent massive logs
      out[k] = '[Object]';
    } else {
      out[k] = v;
    }
  }
  return out;
}

// Load environment variables from .env file if present
// require('dotenv').config();

// Load configuration 
const config = require('./config');

// Helper to mask secrets (show first & last char, preserve length)
function maskSecret(value) {
  if (!value) return value;
  const str = String(value);
  if (str.length <= 4) return '*'.repeat(str.length);
  return str[0] + '*'.repeat(str.length - 2) + str[str.length - 1];
}

// Build safe copy of configuration for logging (structured + human readable)
const safeConfig = {
  ...config,
  ARANGO_PASSWORD: config.ARANGO_PASSWORD ? maskSecret(config.ARANGO_PASSWORD) : undefined
};

// Track whether each value came from env or default file
const configSources = {
  ARANGO_URL: process.env.ARANGO_URL ? 'env' : 'default',
  ARANGO_DB: process.env.ARANGO_DB ? 'env' : 'default',
  ARANGO_USER: process.env.ARANGO_USER ? 'env' : 'default',
  ARANGO_PASSWORD: process.env.ARANGO_PASSWORD ? 'env' : 'default',
  PORT: process.env.PORT ? 'env' : 'default'
};

// Emit pretty table (human friendly)
function renderConfigTable(cfg, sources) {
  const rows = Object.keys(cfg).map(k => [k, cfg[k] === undefined ? '' : String(cfg[k]), sources[k] || '']);
  const headers = ['Key', 'Value', 'Source'];
  const data = [headers, ...rows];
  const colWidths = headers.map((_, i) => Math.max(...data.map(r => r[i].length)));
  const sep = '+' + colWidths.map(w => '-'.repeat(w + 2)).join('+') + '+';
  const fmtRow = r => '| ' + r.map((cell, i) => cell.padEnd(colWidths[i])).join(' | ') + ' |';
  const lines = [sep, fmtRow(headers), sep, ...rows.map(fmtRow), sep];
  return lines.join('\n');
}

fastify.log.info('\nConfiguration Recap:\n' + renderConfigTable(safeConfig, configSources));

// Import routes
const statsRoutes = require('./routes/stats');
const datasourcesRoutes = require('./routes/datasources');
const cveRoutes   = require('./routes/vulnerabilities');
const cweRoutes   = require('./routes/cwe');
const cpeRoutes   = require('./routes/cpe');
const pagesRoutes = require('./routes/pages');

// Enable CORS for Nuxt frontend
fastify.register(require('@fastify/cors'), {
  origin: 'http://localhost:3000',
  credentials: true
});

fastify.register(datasourcesRoutes, { prefix: '/api/datasources' });
fastify.register(statsRoutes, { prefix: '/api/stats' });

fastify.register(cveRoutes,   { prefix: '/api/vulnerabilities' });
fastify.register(cweRoutes,   { prefix: '/api/cwe' });
fastify.register(cpeRoutes,   { prefix: '/api/cpe' });
fastify.register(pagesRoutes, { prefix: '/api/pages' });

// Timing + detailed completion log
fastify.addHook('onRequest', (req, _reply, done) => {
  req._startTime = process.hrtime.bigint();
  done();
});

fastify.addHook('onResponse', (req, reply, done) => {
  const durationMs = req._startTime ? Number(process.hrtime.bigint() - req._startTime) / 1e6 : undefined;
  req.log.info({
    msg: 'request completed',
    params: req.params,
    query: req.query,
    // Don't re-log body if large; rely on serializer for initial line
    durationMs: durationMs !== undefined ? +durationMs.toFixed(2) : undefined,
    statusCode: reply.statusCode
  });
  done();
});

// Global error handler for friendlier output
fastify.setErrorHandler((error, request, reply) => {
  reply.status(error.statusCode || 500).send({
    error: error.name,
    message: error.message,
    stack: process.env.NODE_ENV === 'production' ? undefined : error.stack
  });
});

const start = async () => {
  try {
    await fastify.listen({ port: config.PORT, host: '0.0.0.0' });
    fastify.log.info(`Server listening on port ${config.PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
