require('dotenv').config();

// Required config keys
const required = ['ARANGO_URL', 'ARANGO_DB', 'ARANGO_USER', 'ARANGO_PASSWORD'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`\nFATAL: Missing required environment variables: ${missing.join(', ')}`);
  console.error('Set these as env vars or secrets. Exiting.');
  process.exit(1);
}

const config = {
  ARANGO_URL: process.env.ARANGO_URL,
  ARANGO_DB: process.env.ARANGO_DB,
  ARANGO_USER: process.env.ARANGO_USER,
  ARANGO_PASSWORD: process.env.ARANGO_PASSWORD,
  PORT: process.env.PORT || 3000
};

module.exports = config;
