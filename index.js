// Load environment variables from .env file
require('dotenv').config({ debug: false });
const crypto = require('crypto');
console.log('DB_DATABASE:', process.env.DB_DATABASE);

// Import required modules
const express = require('express');
const mysql = require('mysql2/promise');
const path = require('path');
const rateLimit = require('express-rate-limit');
const Redis = require('ioredis');
const fetch = require('node-fetch');

const app = express();

// HTTPS redirect (Heroku vs.)
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

// Redis
const redis = new Redis(process.env.REDIS_URL, {
  retryStrategy: times => Math.min(times * 50, 2000),
  maxRetriesPerRequest: null,
  connectTimeout: 10000,
  lazyConnect: true
});

// Clean IP
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

// ====== API KEY VALIDATION ======
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
  try {
    key = extractApiKey(req);
  } catch (err) {
    if (err.message === 'MULTIPLE_QUERY_KEYS') {
      return res.status(400).json({ success: false, error: 'Multiple keys not allowed' });
    }
    return res.status(400).json({ success: false, error: 'Invalid API key format' });
  }

  if (!key) {
    req.isKeyValid = false;
    return next();
  }

  const hasHeader = !!(req.headers.authorization || req.headers.Authorization);
  const hasQuery = !!req.query.key;
  if (hasHeader && hasQuery) {
    return res.status(400).json({ success: false, error: 'Conflicting API keys' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, api_key, description FROM api_keys WHERE api_key = ? AND is_active = TRUE LIMIT 1',
      [key]
    );
    if (rows.length > 0) {
      req.isKeyValid = true;
      req.apiKeyInfo = rows[0];
      if (hasQuery) delete req.query.key;
      return next();
    } else {
      return res.status(401).json({
        success: false,
        error: 'Invalid or inactive API key',
        contact: 'antonwise1980@gmail.com'
      });
    }
  } catch (err) {
    console.error('API Key validation error:', err);
    return res.status(500).json({ success: false, error: 'Server error' });
  }
}

// ======================== RATE LIMITERS ========================

// 1. Çok hızlı istekleri engelle (burst protection)
const burstLimiter = rateLimit({
  windowMs: 60 * 1000,    // 1 dakika
  max: 10,                // max 10 istek
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Çok hızlısın, biraz yavaşla!' }
});

// 2. API key sahipleri için limit (saatte 5000 istek – gerçekten sınırsız gibi)
const keyLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 saat
  max: 5000,                 // saatte 5000 istek (istersen 10000 yap)
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.isKeyValid ? `apikey:${req.apiKeyInfo.id}` : null,
  skip: (req) => !req.isKeyValid,  // sadece key varsa uygula
  message: { success: false, error: 'API key limit exceeded (5000/saat)' }
});

// 3. Key olmayanlar için IP bazlı sıkı limit
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 dakika
  max: 30,                   // 15 dakikada max 30 istek
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `ip:${getCleanIp(req)}`,
  skip: (req) => req.isKeyValid === true,  // key varsa bu limit geçilmez
  message: {
    success: false,
    error: 'Limit aşıldı',
    message: '15 dakikada en fazla 30 istek atabilirsiniz.',
    unlimited: 'API key alarak sınırsız erişim: antonwise1980@gmail.com'
  }
});

// ======================== MIDDLEWARES ========================
app.options('/api/v1/synonyms', (req, res) => res.sendStatus(200));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// API route – doğru sırayla limitler
app.use('/api/v1/synonyms', validateApiKey);
app.use('/api/v1/synonyms', burstLimiter);   // 1. çok hızlıları durdur
app.use('/api/v1/synonyms', keyLimiter);    // 2. key sahiplerine özel limit
app.use('/api/v1/synonyms', ipLimiter);     // 3. key olmayanları sıkı sınırla

// ======================== YARDIMCI FONKSİYON ========================
async function logSearchAndUpdatePopular(word, clientIp, ipHash, country, connection) {
  const logWord = word || '(random)';
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
          sample_country = IF(sample_country IS NULL OR sample_country = '' OR sample_country = 'Unknown', VALUES(sample_country), sample_country)
      `, [logWord, country]);
    }
  } catch (err) {
    console.warn('Log/popular hatası:', err.message);
  }
}

// ======================== MAIN ENDPOINT ========================
app.get('/api/v1/synonyms', async (req, res) => {
  const search = req.query.search?.trim();
  const hasKey = req.isKeyValid === true;
  let connection;

  try {
    connection = await pool.getConnection();

    // IP & Ülke
    const clientIp = getCleanIp(req);
    const ipHash = crypto.createHash('sha256').update(clientIp).digest('hex');
    let country = 'Unknown';
    if (search) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3000);
        const geoRes = await fetch(`http://ip-api.com/json/${clientIp}?fields=country`, { signal: controller.signal });
        clearTimeout(timeoutId);
        if (geoRes.ok) {
          const geo = await geoRes.json();
          if (geo?.country) country = geo.country;
        }
      } catch (e) { /* sessiz */ }
    }

    // Logla (cache'den dönse bile)
    if (search) {
      await logSearchAndUpdatePopular(search.toLowerCase(), clientIp, ipHash, country, connection);
    }

    // Cache kontrol
    if (search) {
      const cacheKey = `synonym:${search.toLowerCase()}`;
      try {
        const cached = await redis.get(cacheKey);
        if (cached) {
          const parsed = JSON.parse(cached);
          parsed.meta.from_cache = true;
          return res.json(parsed);
        }
      } catch (e) {
        console.warn('Redis hatası:', e.message);
      }
    }

    // Veritabanından çek
    let rows = [];
    if (!search) {
      const [countResult] = await connection.query('SELECT COUNT(*) as total FROM data_json_tbl');
      const total = countResult[0].total || 0;
      if (total === 0) return res.status(404).json({ success: false, error: 'No data' });
      const randomOffset = Math.floor(Math.random() * total);
      [rows] = await connection.query('SELECT * FROM data_json_tbl LIMIT 1 OFFSET ?', [randomOffset]);
    } else {
      const lowerSearch = search.toLowerCase();
      [rows] = await connection.query('SELECT * FROM data_json_tbl WHERE LOWER(TRIM(word)) = ? LIMIT 1', [lowerSearch]);
      if (!rows.length) {
        [rows] = await connection.query(`SELECT * FROM data_json_tbl WHERE JSON_CONTAINS(LOWER(synonyms), ?) LIMIT 1`, [JSON.stringify(lowerSearch)]);
      }
    }

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        error: 'No result found',
        meta: { searched: search || 'random', yoursIP: clientIp, api_key_used: hasKey }
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

    const response = {
      success: true,
      data: result,
      meta: {
        searched: search || null,
        found_in: source,
        timestamp: new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }),
        powered_by: 'IELTS Synonyms API',
        apiVersion: 'v1.0',
        yoursIP: clientIp,
        api_key_used: hasKey,
        ...(hasKey && { note: 'Unlimited access provided with API key.' })
      }
    };

    // Cache'e yaz
    if (search) {
      const cacheKey = `synonym:${search.toLowerCase()}`;
      await redis.set(cacheKey, JSON.stringify(response), 'EX', 3600);
    }

    res.json(response);
  } catch (error) {
    console.error('API Error:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  } finally {
    if (connection) connection.release();
  }
});

// Diğer endpointler (popular, info vs.) aynı kalıyor...
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
      meta: { total: rows.length }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to load popular searches' });
  }
});

app.get(['/api', '/api/', '/api/v1', '/api/v1/'], (req, res) => {
  res.json({
    api: "IELTS Synonyms API", version: "v1.0",
    endpoint: "/api/v1/synonyms",
    rate_limit: "30 istek / 15 dakika (key olmadan)",
    unlimited: "API key ile saatte 5000 istek",
    documentation: "https://synon-6f0dbe944806.herokuapp.com/",
    contact: "antonwise1980@gmail.com"
  });
});

// Redis test
redis.ping()
  .then(() => console.log('Redis BAĞLANDI'))
  .catch(err => console.error('Redis HATASI:', err.message));

// Start
app.listen(PORT, () => {
  console.log(`Server çalışıyor → http://localhost:${PORT}`);
  console.log(`Saat: ${new Date().toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' })}`);
  console.log(`Rate limiting aktif – Güvenlik seviyesi: YÜKSEK`);
});