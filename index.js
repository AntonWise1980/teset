// Load environment variables from .env file
require('dotenv').config({ debug: false });
const crypto = require('crypto');

// Log database name for debugging
console.log('DB_DATABASE:', process.env.DB_DATABASE);

// Import required modules
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const fetch = require('node-fetch'); // <-- EKLENDİ: Ülke tespiti için

// Initialize Express app
const app = express();

if (process.env.NODE_ENV === 'production' || process.env.FORCE_HTTPS) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && req.headers['x-forwarded-proto'] !== undefined) {
      return res.redirect(301, 'https://' + req.headers.host + req.url);
    }
    next();
  });
}

app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  typeCast: function (field, next) {
    if (field.type === 'JSON') {
      const val = field.string('utf8');
      return val ? JSON.parse(val) : null;
    }
    return next();
  }
});

// Initialize Redis client
const redis = new Redis(process.env.REDIS_URL, {
  retryStrategy: times => Math.min(times * 50, 2000),
  maxRetriesPerRequest: null,
  connectTimeout: 10000,
  lazyConnect: true
});

// Extract clean IPv4 address
const getCleanIp = (req) => {
  let ip = req.ip;
  if (!ip && req.connection?.remoteAddress) ip = req.connection.remoteAddress;
  if (!ip && req.socket?.remoteAddress) ip = req.socket.remoteAddress;
  if (!ip && req.headers['x-forwarded-for']) {
    ip = req.headers['x-forwarded-for'].split(',')[0].trim();
  }
  if (!ip) return 'unknown';
  if (ip === '::1') return '127.0.0.1';
  if (ip.startsWith('::ffff:')) {
    const ipv4 = ip.slice(7);
    if (/^\d+\.\d+\.\d+\.\d+$/.test(ipv4)) return ipv4;
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip;
  return 'unknown';
};

// ====== API KEY VALIDATION MIDDLEWARE ======
function extractApiKey(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization || '';
  if (authHeader.startsWith('Bearer ') || authHeader.startsWith('bearer ')) {
    return authHeader.split(' ')[1].trim();
  }
  if (req.query.key) {
    const keys = Array.isArray(req.query.key) ? req.query.key : [req.query.key];
    if (keys.length > 1) throw new Error('MULTIPLE_QUERY_KEYS');
    return keys[0].trim();
  }
  return null;
}

async function validateApiKey(req, res, next) {
  let key;
  let keySource = 'none';
  try {
    key = extractApiKey(req);
  } catch (err) {
    if (err.message === 'MULTIPLE_QUERY_KEYS') {
      return res.status(400).json({
        success: false,
        error: 'Multiple keys not allowed',
        message: 'Only one API key can be provided in the query parameters.'
      });
    }
    return res.status(400).json({ success: false, error: 'Invalid API key format' });
  }

  if (!key) {
    req.isKeyValid = false;
    req.usedKeySource = 'none';
    return next();
  }

  const hasHeader = !!(req.headers.authorization || req.headers.Authorization);
  const hasQuery = !!req.query.key;
  if (hasHeader && hasQuery) {
    return res.status(400).json({
      success: false,
      error: 'Conflicting API keys',
      message: 'Do not send API key in both Authorization header and query parameter.'
    });
  }

  keySource = hasHeader ? 'header' : 'query';

  try {
    const [rows] = await pool.query(
      'SELECT id, api_key, description FROM api_keys WHERE api_key = ? AND is_active = TRUE LIMIT 1',
      [key]
    );
    if (rows.length > 0) {
      req.isKeyValid = true;
      req.apiKeyInfo = rows[0];
      req.usedKeySource = keySource;
      if (hasQuery) delete req.query.key;
      return next();
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid or inactive API key',
        message: 'The provided API key is not valid or has been deactivated.',
        contact: 'antonwise1980@gmail.com'
      });
    }
  } catch (err) {
    console.error('API Key validation error:', err);
    return res.status(500).json({
      success: false,
      error: 'Server error',
      message: 'API key could not be validated due to a server error.'
    });
  }
}

// Rate Limiter
const apiLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: 500,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  validate: { ip: false },
  keyGenerator: (req) => {
    if (req.isKeyValid) return `${getCleanIp(req)}:apikey:${req.query.key}`;
    return getCleanIp(req);
  },
  handler: (req, res) => {
    const resetTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const trTime = resetTime.toLocaleString('tr-TR', {
      timeZone: 'Europe/Istanbul',
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    res.status(429).json({
      success: false,
      error: 'Daily limit exceeded',
      message: 'Your daily limit of 500 requests for this IP has been reached.',
      limit: 500,
      resetTime: trTime,
      suggestion: 'You can get unlimited access by obtaining an API key.',
      getKey: 'Contact: antonwise1980@gmail.com',
      retryAfter: 86400
    });
  },
  skip: (req) => req.isKeyValid === true
});

// Middleware
app.options('/api/v1/synonyms', (req, res) => res.sendStatus(200));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/api/v1/synonyms', validateApiKey);
app.use('/api/v1/synonyms', apiLimiter);
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== MAIN API ENDPOINT ==========
app.get('/api/v1/synonyms', async (req, res) => {
  const search = req.query.search?.trim();
  const hasKey = !!req.query.key;
  let connection;

  try {
    connection = await pool.getConnection();
    let rows = [];

    // Cache kontrol
    if (search) {
      const cacheKey = `synonym:${search.toLowerCase()}`;
      try {
        const cached = await redis.get(cacheKey);
        if (cached) {
          const parsed = JSON.parse(cached);
          parsed.meta.from_cache = true;
          return res.status(200).json(parsed);
        }
      } catch (redisErr) {
        console.warn('Redis cache hatası, MySQL kullanılıyor:', redisErr.message);
      }
    }

    // Arama veya random
    if (!search) {
      const [countResult] = await connection.query('SELECT COUNT(*) as total FROM data_json_tbl');
      const total = countResult[0].total;
      if (total === 0) {
        return res.status(404).json({
          success: false, error: 'No data in database', message: 'No words in the database.',
          meta: { timestamp: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }), powered_by: 'IELTS Synonyms API', apiVersion: 'v1.0', yoursIP: getCleanIp(req) }
        });
      }
      const randomOffset = Math.floor(Math.random() * total);
      [rows] = await connection.query('SELECT * FROM data_json_tbl LIMIT 1 OFFSET ?', [randomOffset]);
    } else {
      const lowerSearch = search.toLowerCase();
      [rows] = await connection.query('SELECT * FROM data_json_tbl WHERE LOWER(TRIM(word)) = ? LIMIT 1', [lowerSearch]);
      if (!rows || rows.length === 0) {
        [rows] = await connection.query(`
          SELECT * FROM data_json_tbl WHERE JSON_CONTAINS(LOWER(synonyms), ?) LIMIT 1
        `, [JSON.stringify(lowerSearch)]);
      }
    }

    if (!rows || rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'No result found',
        message: `Search: "${search || 'random'}" → No result in word or synonyms.`,
        meta: { searched: search || 'random', timestamp: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }), powered_by: 'IELTS Synonyms API', apiVersion: 'v1.0', yoursIP: getCleanIp(req), api_key_used: hasKey }
      });
    }

    const result = rows[0];
    const lowerSearch = search?.toLowerCase();
    const originalWord = (result.word || '').toString().trim().toLowerCase();

    result.synonyms = Array.isArray(result.synonyms) ? result.synonyms.map(s => (s || '').toString().trim().toLowerCase()) : [];
    result.antonyms = Array.isArray(result.antonyms) ? result.antonyms.map(a => (a || '').toString().trim().toLowerCase()) : [];

    let source = 'word';
    if (lowerSearch && lowerSearch !== originalWord && result.synonyms.includes(lowerSearch)) {
      result.word = lowerSearch;
      result.synonyms = result.synonyms.filter(s => s !== lowerSearch);
      if (!result.synonyms.includes(originalWord)) result.synonyms.unshift(originalWord);
      source = 'synonyms';
    } else {
      result.word = originalWord;
    }

    // ========== YENİ: LOGLAMA VE POPÜLER KELİME GÜNCELLEME ==========
    if (search) {
      const clientIp = getCleanIp(req);
      const ipHash = crypto.createHash('sha256').update(clientIp).digest('hex');
      let country = 'Unknown';

      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        const geoRes = await fetch(`http://ip-api.com/json/${clientIp}?fields=country`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (geoRes.ok) {
          const geo = await geoRes.json();
          if (geo && geo.country) country = geo.country;
        }
      } catch (e) { /* sessiz kal */ }

      const logWord = lowerSearch || '(random)';

      try {
        await connection.query(
          `INSERT INTO search_logs (word, ip_hash, country, searched_at)
           VALUES (?, ?, ?, NOW())
           ON DUPLICATE KEY UPDATE searched_at = NOW(), country = VALUES(country)`,
          [logWord, ipHash, country]
        );

        if (logWord !== '(random)') {
          await connection.query(`
            INSERT INTO popular_searches (word, search_count, last_searched_at, sample_country)
            VALUES (?, 1, NOW(), ?)
            ON DUPLICATE KEY UPDATE
              search_count = search_count + 1,
              last_searched_at = NOW(),
              sample_country = IF(sample_country IS NULL OR sample_country = 'Unknown', VALUES(sample_country), sample_country)
          `, [logWord, country]);
        }
      } catch (logErr) {
        console.warn('Log/popular kaydetme hatası (devam ediliyor):', logErr.message);
      }
    }

    // Console log
    const logTime = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
    console.log(`[${logTime}] Search: "${search || 'random'}" | Found in: ${source} | word: "${result.word}" | IP: ${getCleanIp(req)} | Key: ${hasKey ? 'Yes' : 'No'}`);

    const response = {
      success: true,
      data: result,
      meta: {
        searched: search || null,
        found_in: source,
        timestamp: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }),
        powered_by: 'IELTS Synonyms API',
        apiVersion: 'v1.0',
        yoursIP: getCleanIp(req),
        api_key_used: hasKey,
        ...(hasKey && { note: 'Unlimited access provided with API key.' })
      }
    };

    // Cache'le
    if (search) {
      const cacheKey = `synonym:${search.toLowerCase()}`;
      await redis.set(cacheKey, JSON.stringify(response), 'EX', 3600);
    }

    res.status(200).json(response);

  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'A server error occurred.',
      details: error.message,
      meta: { timestamp: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }), powered_by: 'IELTS Synonyms API', apiVersion: 'v1.0', yoursIP: getCleanIp(req) }
    });
  } finally {
    if (connection) connection.release();
  }
});

// ========== YENİ: EN ÇOK ARANAN KELİMELER ENDPOINT ==========
app.get('/api/v1/popular', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT word, search_count, last_searched_at, sample_country
      FROM popular_searches
      WHERE word != '(random)'
      ORDER BY search_count DESC, last_searched_at DESC
      LIMIT 20
    `);

    res.json({
      success: true,
      data: rows.map(r => ({
        word: r.word,
        count: Number(r.search_count),
        last_seen: new Date(r.last_searched_at).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }),
        country: r.sample_country || 'Bilinmiyor'
      })),
      meta: {
        total: rows.length,
        updated_at: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })
      }
    });
  } catch (err) {
    console.error('Popular endpoint error:', err);
    res.status(500).json({ success: false, error: 'Failed to load popular searches' });
  }
});

// Info endpoints
app.get(['/api', '/api/'], (req, res) => {
  res.json({
    api: "IELTS Synonyms API", version: "v1.0", endpoint: "/api/v1/synonyms",
    examples: ["GET /api/v1/synonyms", "GET /api/v1/synonyms?search=fast", "GET /api/v1/synonyms?search=quick&key=YOUR_KEY"],
    rate_limit: "500/day (without key)", unlimited: "Use ?key=...", documentation: "https://synon-6f0dbe944806.herokuapp.com/", contact: "antonwise1980@gmail.com"
  });
});

app.get(['/api/v1', '/api/v1/'], (req, res) => {
  res.json({
    api: "IELTS Synonyms API", version: "v1.0", endpoint: "/api/v1/synonyms",
    examples: ["GET /api/v1/synonyms", "GET /api/v1/synonyms?search=fast", "GET /api/v1/synonyms?search=quick&key=YOUR_KEY"],
    rate_limit: "500/day (without key)", unlimited: "Use ?key=...", documentation: "https://synon-6f0dbe944806.herokuapp.com/", contact: "antonwise1980@gmail.com"
  });
});

// Redis test
redis.ping()
  .then(reply => console.log('Redis bağlantısı BAŞARILI:', reply))
  .catch(err => console.error('Redis bağlantı HATASI:', err.message));

// Start server
app.listen(PORT, () => {
  const startTime = new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' });
  console.log(`Server listening on http://localhost:${PORT}`);
  console.log(`Turkey time: ${startTime}`);
  console.log(`Rate Limit: 500 requests / 24 hours (only for users without key)`);
  console.log(`Unlimited access with API Key is active.`);
  console.log(`ACTIVE ENDPOINT: http://localhost:${PORT}/api/v1/synonyms`);
  console.log(`NEW: Popular searches → /api/v1/popular`);
});