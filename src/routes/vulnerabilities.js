const db = require('../services/arango');

// Helper to execute an AQL query and log the query + bindVars if it fails
async function executeQueryWithDebug(request, aql, bindVars = {}, label = 'AQL') {
  try {
    return await db.query(aql, bindVars);
  } catch (err) {
    const compact = aql.replace(/\s+/g, ' ').trim();
    // Produce an interpolated version replacing @var with JSON value (best effort)
    const interp = aql.replace(/@([A-Za-z0-9_]+)/g, (m, v) => {
      if (!(v in bindVars)) return m; // leave untouched if not provided
      try {
        const val = bindVars[v];
        if (val === null || val === undefined) return 'null';
        if (typeof val === 'number') return String(val);
        if (typeof val === 'boolean') return val ? 'true' : 'false';
        // Strings / arrays / objects -> JSON stringify
        return JSON.stringify(val);
      } catch (_) {
        return m;
      }
    });
    // Emit a separate raw multiline block to stderr for easy copy (not JSON escaped)
    try {
      // Delimiters make it easy to copy in terminals; include interpolated variant
      process.stderr.write(`\n==== AQL RAW (${label}) BEGIN ====\n${aql}\n---- Interpolated (${label}) ----\n${interp}\n==== AQL RAW (${label}) END ====\n`);
    } catch (_) {/* ignore */}
    request.log.error({
      msg: 'AQL query failed',
      label,
      aql_compact: compact,
      aql_interpolated: interp.replace(/\s+/g,' ').trim(),
      // Keep original (may be escaped by logger) under different key
      aql_raw_len: aql.length,
      bindVars,
      arango: {
        errorNum: err.errorNum,
        code: err.code,
        isArangoError: err.isArangoError || err.name === 'ArangoError'
      }
    }, `AQL error in ${label}: ${err.message}`);
    throw err; // rethrow so route error handler still returns 500
  }
}

async function getAllVulnerabilities(request, reply) {
  try {
    const { page = 1, limit = 20, id, published } = request.query;
    const offset = (page - 1) * limit;
    let filter = '';
    const bindVars = {};
    if (id) {
      filter += 'FILTER cve.id == @id ';
      bindVars.id = id;
    }
    if (published) {
      filter += 'FILTER cve.published == @published ';
      bindVars.published = published;
    }
    // Count total    
    const countQuery = `FOR cve IN vulnerabilities ${filter} COLLECT WITH COUNT INTO length RETURN length`;
  const countCursor = await executeQueryWithDebug(request, countQuery, bindVars, 'vuln_count');
    const count = await countCursor.next();
    // Get paginated results
    const query = `
      FOR cve IN vulnerabilities
        ${filter}
        SORT cve.published DESC
        LIMIT @offset, @limit
        RETURN { 
          id: cve._key,
          vulnStatus: cve.vulnStatus,
          published: cve.published,
          updated_at: cve.updated_at,
          descriptions: cve.descriptions,          
          tags: cve.tags
        }
    `;
  const cursor = await executeQueryWithDebug(request, query, { ...bindVars, offset, limit: Number(limit) }, 'vuln_list');
    const results = await cursor.all();
    reply.send({
      count: count || 0,
      page: Number(page),
      itemsPerPage: Number(limit),
      query: { ...request.query },
      results
    });
  } catch (err) {
    request.log.error(err);
    reply.status(500).send({ error: 'Internal Server Error' });
  }
}

async function getVulnerability(request, reply) {
  try {
    const { id } = request.params;
    // Validate that an ID is provided in the request
    if (!id) {
      return reply.status(400).send({ error: 'Missing vulnerability ID' });
    }
    /*
      Query logic:
      - First try to find vulnerability by its _key (direct lookup)
      - If not found, search for it via alias
      - Ensure cve.weaknesses is always an array (never null) before looping
      - Enrich each weakness with its CWE name and description if present
      - Return the vulnerability with enriched weaknesses and all relevant fields
      - Include information about which alias was used to access the vulnerability
    */
    //     }
    // `;

    const query = `
      // First, try to find the vulnerability directly by _key
      LET directMatch = (
        FOR cve IN vulnerabilities
          FILTER cve._key == @id
          LIMIT 1
          RETURN cve
      )[0]
      
      // If no direct match, search by alias
      LET aliasMatch = directMatch ? null : (
        FOR alias IN aliases
          FILTER alias._key == @id
          FOR cve IN 1..1 INBOUND alias vuln_aliases
            LIMIT 1
            RETURN cve
      )[0]
      
      // Use whichever match we found
      LET cve = directMatch || aliasMatch
      
      // Return null if no vulnerability found
      FILTER cve != null
      
      LET weaknessesArray = (cve.weaknesses != null && IS_ARRAY(cve.weaknesses)) ? cve.weaknesses : []
      LET enrichedWeaknesses = (
        LENGTH(weaknessesArray) > 0
          ? (
              FOR weakness IN weaknessesArray
                LET cweDoc = DOCUMENT(CONCAT('cwe/', weakness.id))
                RETURN MERGE(weakness, {
                  name: cweDoc.name,
                  description: cweDoc.description
                })
            )
          : []
      )
      
      // Get aliases for this vulnerability
      LET aliasesArray = (
        FOR aliases IN 1..1 OUTBOUND cve vuln_aliases
          RETURN {
            alias: aliases._key
          }
      )
      
      // Get related vulnerabilities (both directions)
      LET relatedArray = (
        FOR v IN 1..1 OUTBOUND cve vuln_related
          RETURN {
            v:v
          }
      )
      
      LET reverseRelatedArray = (
        FOR v, e, related IN 1..1 INBOUND cve vuln_related
          RETURN {
            id: related._key,
            title: related.descriptions ? related.descriptions[0].value : null,
            published: related.published,
            vulnStatus: related.vulnStatus,
            relationship_type: e.relationship_type,
            direction: "inbound"
          }
      )
      
      RETURN { 
        id: cve._key,
        vulnStatus: cve.vulnStatus || (cve.source_metadata && cve.source_metadata.NVD ? cve.source_metadata.NVD.vulnStatus : null),
        tags: cve.tags || cve.cveTags,
        published: cve.source_metadata && cve.source_metadata.NVD ? cve.source_metadata.NVD.published : null,
        lastModified: cve.source_metadata && cve.source_metadata.NVD ? cve.source_metadata.NVD.lastModified : null,
        updated_at: cve.updated_at,
        descriptions: cve.descriptions,
        sourceIdentifier: cve.sourceIdentifier || (cve.source_metadata && cve.source_metadata.NVD ? cve.source_metadata.NVD.sourceIdentifier : null),
        weaknesses: enrichedWeaknesses,
        metrics: cve.metrics,
        references: cve.references,
        cisa: cve.CISA,
        affected: cve.affected,        
        epss: cve.epss,
        epss_history: cve.epss_history,
        exploits: cve.exploits,
        aliases: aliasesArray,
        related: APPEND(relatedArray, reverseRelatedArray),
        accessedVia: @id,
        isAliasAccess: directMatch ? false : true
      }
    `;

    // Execute the query with the provided ID
  const cursor = await executeQueryWithDebug(request, query, { id }, 'vuln_get');
    const result = await cursor.next();
    // If no result, return 404
    if (!result) {
      return reply.status(404).send({ error: 'Vulnerability not found' });
    }
    // Send the result
    reply.send(result);
  } catch (err) {
    // Log and handle errors
    request.log.error(err);
    reply.status(500).send({ error: 'Internal Server Error' });
  }
}

// Search vulnerability / alias IDs by flexible input patterns
async function searchVulnerabilityIds(request, reply) {
  try {
    const { q } = request.query;
    if (!q || String(q).trim().length === 0) {
      return reply.send({ query: q || '', matches: [] });
    }
    const raw = String(q);

    // 1. Enforce max length (original input)
    if (raw.length > 15) {
      return reply.status(400).send({ error: 'query too long (max 15 chars)', query: raw });
    }

    // 2. Sanitize: convert percent triplets & stray % into spaces (do NOT decode -> avoid hidden control chars)
    let sanitized = raw.replace(/%[0-9A-Fa-f]{2}/g, ' ').replace(/%/g, ' ');
    // 3. Remove control chars, collapse whitespace
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, ' ').trim();
    if (!sanitized) return reply.send({ query: raw, matches: [] });
    // 4. Allow only A-Za-z0-9:- and spaces after sanitization
    if (!/^[A-Za-z0-9:\-\s]+$/.test(sanitized)) {
      return reply.status(400).send({ error: 'invalid characters (allowed: A-Za-z0-9: -)', query: raw });
    }
    // 5. Remove spaces for pattern logic
    const compact = sanitized.replace(/\s+/g, '');
    const upper = compact.toUpperCase();

    // Extract year + numeric part (first 4+ digits then remaining digits) for candidate generation
    const digits = upper.replace(/[^0-9]/g, '');
    let year = null, num = null;
    if (digits.length >= 5) { // need at least year + 1 digit
      year = digits.slice(0,4);
      num = digits.slice(4); // remaining
    }

    // Helper zero pad (CVE usually at least 4, but allow variable)
    function padCve(n) {
      if (!n) return n;
      return n.length >= 4 ? n : n.padStart(4,'0');
    }

  const candidates = new Set();

    // Direct cleaned token variants
  candidates.add(upper);

    // CVE patterns
    if (upper.startsWith('CVE')) {
      const norm = upper.replace(/CVE[^0-9]*(\d{4})[^0-9]*(\d+)/, (m,y,n) => `CVE-${y}-${padCve(n)}`);
      candidates.add(norm);
    } else if (year && num) {
      candidates.add(`CVE-${year}-${padCve(num)}`);
      candidates.add(`CVE-${year}-${num}`);
    }

    // RHSA patterns (retain colon form as canonical, also dash form)
    const rhsaDetected = upper.includes('RHSA') || /:\d{2,}$/.test(upper) || /RHSA[^0-9]*\d{4}[^0-9]*\d+/.test(upper);
    if (rhsaDetected && year && num) {
      const baseNum = num.replace(/^0+/,'') || num;
      candidates.add(`RHSA-${year}:${baseNum}`);
      candidates.add(`RHSA-${year}-${baseNum}`);
    } else if (year && num) {
      // Allow generation even if not explicitly RHSA to broaden cross-matches
      const baseNum = num.replace(/^0+/,'') || num;
      candidates.add(`RHSA-${year}:${baseNum}`);
    }

    // GitHub / other advisory-like (CGA-, GHSA-) prefix handling if user typed beginning
    if (/^(CGA|GHSA)[-A-Z0-9]*$/.test(upper)) {
      candidates.add(upper);
    }

    // Also expand colon/dash normalization (replace : with - and vice versa after first 4 digits)
    [...Array.from(candidates)].forEach(c => {
      if (c.includes(':')) candidates.add(c.replace(':','-'));
      if (/^[A-Z]+-\d{4}-\d+$/.test(c)) {
        // insert colon variant after year for non-CVE prefixes
        const m = c.match(/^([A-Z]+)-(\d{4})-(\d+)$/);
        if (m && m[1] !== 'CVE') candidates.add(`${m[1]}-${m[2]}:${m[3]}`);
      }
    });

  const candidateList = Array.from(candidates).slice(0,50); // tighter cap

    // Build safer, bounded fuzzy regex (no catastrophic .* chains)
    let regex = null;
    if (year && num) {
      // Accept exact CVE or RHSA with optional separators + zero padding on numeric part
      regex = `(CVE-${year}-0*${num})|(RHSA-${year}[:-]?0*${num})`;
    } else {
      // Generic short pattern: treat hyphen/colon as optional separators
      const esc = upper.replace(/[-]/g,'[-:]').replace(/([.*+?^${}()|[\]\\])/g,'\\$1');
      regex = esc;
    }

    const aql = `
      LET candidates = @candidates
      LET exact = (
        FOR id IN candidates
          LET v = DOCUMENT(CONCAT('vulnerabilities/', id))
          LET a = DOCUMENT(CONCAT('aliases/', id))
          FILTER v != null || a != null
          RETURN id
      )
      LET fuzzyV = (
        FOR v IN vulnerabilities
          FILTER REGEX_TEST(UPPER(v._key), @regex, true)
          LIMIT 15
          RETURN v._key
      )
      LET fuzzyA = (
        FOR al IN aliases
          FILTER REGEX_TEST(UPPER(al._key), @regex, true)
          LIMIT 15
          RETURN al._key
      )
      LET merged = UNION_DISTINCT(exact, fuzzyV, fuzzyA)
      RETURN SLICE(merged, 0, 10)
    `;

    const cursor = await executeQueryWithDebug(request, aql, { candidates: candidateList, regex }, 'vuln_search');
  const all = await cursor.next(); // single array result (already sliced)
  reply.send({ query: compact, original: raw, matches: all || [] });
  } catch (err) {
    request.log.error(err);
    reply.status(500).send({ error: 'Internal Server Error' });
  }
}

async function routes(fastify, options) {
  fastify.get('/', getAllVulnerabilities);
  fastify.get('/search', searchVulnerabilityIds); // must be before '/:id'
  fastify.get('/:id', getVulnerability);
}

module.exports = routes;
