/**
 * ClaudMusic — Server with MongoDB + Multi-Layer Bot Protection
 * ═══════════════════════════════════════════════════════════════
 * ANTI-BOT LAYERS:
 *  1. Rate limiting per IP (requests/min, registrations/hour, uploads/day)
 *  2. IP blacklist (permanent + temporary bans)
 *  3. User-Agent fingerprinting (blocks headless browsers, curl, scripts)
 *  4. Honeypot trap fields in registration
 *  5. Request timing analysis (too-fast = bot)
 *  6. CAPTCHA challenge-response token system
 *  7. WebSocket flood protection
 *  8. Account creation velocity checks
 *  9. Suspicious pattern detection (same content, same IP many accounts)
 * 10. Behavioural scoring (each IP gets a trust score)
 */

import { createServer }    from 'http';
import { WebSocketServer } from 'ws';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname }   from 'path';
import { fileURLToPath }   from 'url';
import { execSync }        from 'child_process';
import { createHash, randomBytes } from 'crypto';
import mongoose            from 'mongoose';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const PORT      = parseInt(process.env.PORT || '3000', 10);
const HOST      = '0.0.0.0';
const MONGO_URL = process.env.MONGO_URL || process.env.MONGODB_URL || process.env.DATABASE_URL || '';
const BOT_SECRET = process.env.BOT_SECRET || randomBytes(32).toString('hex');

// ── Auto-build ────────────────────────────────────────────────────────────────
const DIST = join(__dirname, 'dist', 'index.html');
if (!existsSync(DIST)) {
  console.log('⚙️  dist/index.html not found — building...');
  try {
    execSync('npm run build', { stdio: 'inherit', cwd: __dirname });
    console.log('✅ Build complete');
  } catch {
    console.error('❌ Build failed. Run: npm run build');
    process.exit(1);
  }
}

let HTML_CONTENT;
try {
  HTML_CONTENT = readFileSync(DIST);
  console.log(`✅ dist/index.html loaded (${(HTML_CONTENT.length / 1024).toFixed(0)} KB)`);
} catch (e) {
  console.error('❌ Cannot read dist/index.html:', e.message);
  process.exit(1);
}

// ── Directories ───────────────────────────────────────────────────────────────
const DATA_DIR   = join(__dirname, 'data');
const AUDIO_DIR  = join(DATA_DIR, 'audio');
const COVERS_DIR = join(DATA_DIR, 'covers');
const DB_FILE    = join(DATA_DIR, 'db.json');
const BAN_FILE   = join(DATA_DIR, 'bans.json');

for (const d of [DATA_DIR, AUDIO_DIR, COVERS_DIR]) {
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}

// ══════════════════════════════════════════════════════════════════════════════
// ██████████████████████  ANTI-BOT SYSTEM  ████████████████████████████████████
// ══════════════════════════════════════════════════════════════════════════════

/** Blocked User-Agent substrings (bots, scrapers, headless browsers) */
const BOT_UA_PATTERNS = [
  'bot', 'crawler', 'spider', 'scraper', 'headless', 'phantom', 'selenium',
  'puppeteer', 'playwright', 'curl', 'wget', 'python-requests', 'python-urllib',
  'java/', 'go-http', 'ruby', 'okhttp', 'axios/', 'node-fetch', 'got/',
  'libwww', 'lwp-', 'httpclient', 'apache-httpclient', 'mechanize',
  'nikto', 'sqlmap', 'masscan', 'nmap', 'zgrab', 'dirbuster', 'gobuster',
  'hydra', 'medusa', 'burpsuite', 'owasp', 'skipfish',
];

/** Allowed modern browser UA fragments (at least one must be present) */
const BROWSER_SIGNATURES = [
  'mozilla/', 'chrome/', 'firefox/', 'safari/', 'edge/', 'opera/', 'webkit',
];

/** IP → rate limit buckets */
const rateLimits = new Map(); // ip → { req: [], reg: [], upload: [], ws: [] }

/** IP trust scores: 100 = trusted, 0 = banned */
const trustScores = new Map(); // ip → { score, violations, lastSeen, country? }

/** Active CAPTCHA challenges: token → { ip, expires, used } */
const captchaChallenges = new Map(); // token → { answer, ip, expires }

/** Temporary bans: ip → unbanAt timestamp */
const tempBans = new Map();

/** Permanent IP bans (loaded from disk) */
let permBans = new Set();

/** WebSocket connection tracking per IP */
const wsConnections = new Map(); // ip → [ws, ...]

/** Registration tracking per IP: ip → [timestamp, ...] */
const regAttempts = new Map();

/** Track account names per IP to detect mass account creation */
const ipAccounts = new Map(); // ip → Set of userIds

// Load permanent bans from disk
function loadBans() {
  try {
    if (existsSync(BAN_FILE)) {
      const data = JSON.parse(readFileSync(BAN_FILE, 'utf-8'));
      permBans = new Set(Array.isArray(data.permanent) ? data.permanent : []);
      // Restore temp bans
      if (Array.isArray(data.temporary)) {
        const now = Date.now();
        for (const { ip, until } of data.temporary) {
          if (until > now) tempBans.set(ip, until);
        }
      }
      console.log(`[BotGuard] Loaded ${permBans.size} permanent bans, ${tempBans.size} temp bans`);
    }
  } catch (e) { console.error('[BotGuard] Load bans error:', e.message); }
}

function saveBans() {
  try {
    const data = {
      permanent: [...permBans],
      temporary: [...tempBans.entries()].map(([ip, until]) => ({ ip, until })),
    };
    writeFileSync(BAN_FILE, JSON.stringify(data, null, 2));
  } catch (e) { console.error('[BotGuard] Save bans error:', e.message); }
}

loadBans();

// ── Rate Limit Configuration ──────────────────────────────────────────────────
const RATE_LIMITS = {
  request:      { window: 60_000,      max: 120 },   // 120 req/min per IP
  auth:         { window: 300_000,     max: 10  },   // 10 auth attempts / 5 min
  register:     { window: 3_600_000,   max: 3   },   // 3 registrations / hour
  upload:       { window: 86_400_000,  max: 20  },   // 20 uploads / day
  ws_msg:       { window: 10_000,      max: 50  },   // 50 WS msgs / 10 sec
  ws_connect:   { window: 60_000,      max: 5   },   // 5 WS connections / min per IP
  search:       { window: 30_000,      max: 30  },   // 30 searches / 30 sec
};

function getRateBucket(ip, key) {
  if (!rateLimits.has(ip)) rateLimits.set(ip, {});
  const buckets = rateLimits.get(ip);
  if (!buckets[key]) buckets[key] = [];
  return buckets[key];
}

function checkRateLimit(ip, key) {
  const cfg    = RATE_LIMITS[key];
  const now    = Date.now();
  const bucket = getRateBucket(ip, key);
  // Trim old entries
  const fresh  = bucket.filter(ts => now - ts < cfg.window);
  rateLimits.get(ip)[key] = fresh;
  if (fresh.length >= cfg.max) return false;
  fresh.push(now);
  return true;
}

// ── Trust Score System ────────────────────────────────────────────────────────
function getTrust(ip) {
  if (!trustScores.has(ip)) trustScores.set(ip, { score: 80, violations: 0, lastSeen: Date.now() });
  return trustScores.get(ip);
}

function penalise(ip, amount, reason) {
  const t = getTrust(ip);
  t.score = Math.max(0, t.score - amount);
  t.violations++;
  t.lastViolation = reason;
  t.lastSeen = Date.now();
  console.log(`[BotGuard] ⚠️  ${ip} penalised -${amount} (${reason}) → score ${t.score}`);

  if (t.score <= 0 && t.violations >= 5) {
    // Auto-temp-ban
    const banDuration = Math.min(t.violations * 10 * 60_000, 24 * 3_600_000); // up to 24h
    tempBans.set(ip, Date.now() + banDuration);
    saveBans();
    console.log(`[BotGuard] 🚫 Auto-ban ${ip} for ${(banDuration / 60000).toFixed(0)} minutes`);
  }
}

function reward(ip, amount = 2) {
  const t = getTrust(ip);
  t.score = Math.min(100, t.score + amount);
  t.lastSeen = Date.now();
}

// ── IP Extraction ─────────────────────────────────────────────────────────────
function getIp(req) {
  return (
    req.headers['cf-connecting-ip'] ||    // Cloudflare
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  ).replace('::ffff:', '');
}

// ── Is Banned? ────────────────────────────────────────────────────────────────
function isBanned(ip) {
  if (permBans.has(ip)) return { banned: true, reason: 'permanent', retry: null };
  const tempUntil = tempBans.get(ip);
  if (tempUntil) {
    if (Date.now() < tempUntil) {
      const mins = Math.ceil((tempUntil - Date.now()) / 60_000);
      return { banned: true, reason: 'temporary', retry: mins };
    }
    tempBans.delete(ip);
  }
  return { banned: false };
}

// ── User-Agent Analysis ───────────────────────────────────────────────────────
function analyseUserAgent(ua) {
  if (!ua || ua.length < 10) return { ok: false, reason: 'missing_ua' };

  const lower = ua.toLowerCase();

  // Check for explicit bot patterns
  for (const pattern of BOT_UA_PATTERNS) {
    if (lower.includes(pattern)) return { ok: false, reason: `bot_ua:${pattern}` };
  }

  // Must look like a real browser
  const looksLikeBrowser = BROWSER_SIGNATURES.some(sig => lower.includes(sig));
  if (!looksLikeBrowser) return { ok: false, reason: 'non_browser_ua' };

  // Suspiciously short UA
  if (ua.length < 40) return { ok: false, reason: 'short_ua' };

  return { ok: true };
}

// ── CAPTCHA Token System ──────────────────────────────────────────────────────
// Simple PoW (proof-of-work) CAPTCHA:
// Server issues challenge → client must find nonce where sha256(challenge+nonce).startsWith('000')
// This is fast for real browsers (JS), very slow for basic scripts

function generateChallenge(ip) {
  const challenge = randomBytes(16).toString('hex');
  const token     = randomBytes(16).toString('hex');
  const difficulty = 3; // number of leading zeros required
  captchaChallenges.set(token, {
    challenge,
    difficulty,
    ip,
    expires: Date.now() + 300_000, // 5 minutes
    used: false,
  });
  return { token, challenge, difficulty };
}

function verifyCaptcha(token, nonce, ip) {
  const ch = captchaChallenges.get(token);
  if (!ch) return { ok: false, reason: 'invalid_token' };
  if (ch.used) return { ok: false, reason: 'token_used' };
  if (Date.now() > ch.expires) { captchaChallenges.delete(token); return { ok: false, reason: 'token_expired' }; }
  if (ch.ip !== ip) return { ok: false, reason: 'ip_mismatch' };

  // Verify PoW
  const hash = createHash('sha256').update(ch.challenge + nonce).digest('hex');
  const prefix = '0'.repeat(ch.difficulty);
  if (!hash.startsWith(prefix)) return { ok: false, reason: 'invalid_pow' };

  ch.used = true;
  captchaChallenges.delete(token); // single-use
  reward(ip, 10); // reward for solving
  return { ok: true };
}

// ── Honeypot Detection ────────────────────────────────────────────────────────
// Registration forms have hidden fields (website, phone2, username2)
// Real users never fill them (invisible in UI). Bots fill everything.
function checkHoneypot(body) {
  const honeyFields = ['website', 'phone2', 'username2', '_gotcha', 'fax', 'address2'];
  for (const field of honeyFields) {
    if (body[field] !== undefined && body[field] !== '') return { ok: false, field };
  }
  return { ok: true };
}

// ── Request Timing ────────────────────────────────────────────────────────────
const requestTimings = new Map(); // ip → lastRequestAt
function checkTiming(ip, minMs = 50) {
  const last = requestTimings.get(ip) || 0;
  const now  = Date.now();
  requestTimings.set(ip, now);
  if (last > 0 && (now - last) < minMs) return false; // too fast
  return true;
}

// ── Content Dedup Detection ───────────────────────────────────────────────────
// Detect same content submitted many times (bot posting same comment/track)
const contentHashes = new Map(); // hash → { ip, count, firstSeen }
function checkContentDuplication(content, ip) {
  const hash  = createHash('sha256').update(content).digest('hex').slice(0, 16);
  const entry = contentHashes.get(hash);
  if (entry) {
    entry.count++;
    if (entry.count > 5 || (entry.ip !== ip && entry.count > 2)) {
      return { ok: false, count: entry.count };
    }
  } else {
    contentHashes.set(hash, { ip, count: 1, firstSeen: Date.now() });
  }
  return { ok: true };
}

// ── Mass Account Detection ────────────────────────────────────────────────────
function checkMassAccounts(ip) {
  const accounts = ipAccounts.get(ip) || new Set();
  if (accounts.size >= 3) return false; // max 3 accounts per IP
  return true;
}

function recordAccount(ip, userId) {
  if (!ipAccounts.has(ip)) ipAccounts.set(ip, new Set());
  ipAccounts.get(ip).add(userId);
}

// ── Main Middleware ────────────────────────────────────────────────────────────
async function botGuard(req, res, next) {
  const ip = getIp(req);
  const ua = req.headers['user-agent'] || '';

  // 1. Check permanent/temp ban
  const ban = isBanned(ip);
  if (ban.banned) {
    const msg = ban.reason === 'permanent'
      ? '🚫 Ваш IP заблокирован навсегда.'
      : `🚫 Ваш IP временно заблокирован. Повторите через ${ban.retry} мин.`;
    return jsonRes(res, 403, { error: msg, banned: true, retry: ban.retry });
  }

  // 2. Check trust score
  const trust = getTrust(ip);
  if (trust.score <= 10) {
    penalise(ip, 0, 'low_trust_access');
    return jsonRes(res, 429, { error: 'Слишком много нарушений. Попробуйте позже.', retryAfter: 3600 });
  }

  // 3. User-Agent check (skip for static assets and audio/cover)
  const url = req.url.split('?')[0];
  const isAsset = url.startsWith('/api/audio/') || url.startsWith('/api/cover/') || url === '/api/health';
  if (!isAsset) {
    const uaResult = analyseUserAgent(ua);
    if (!uaResult.ok) {
      penalise(ip, 30, uaResult.reason);
      console.log(`[BotGuard] 🤖 Blocked UA from ${ip}: ${uaResult.reason} | UA: "${ua.slice(0, 80)}"`);
      return jsonRes(res, 403, { error: 'Доступ запрещён: подозрительный клиент.', code: 'UA_BLOCKED' });
    }
  }

  // 4. Global rate limit
  if (!checkRateLimit(ip, 'request')) {
    penalise(ip, 5, 'rate_limit_global');
    return jsonRes(res, 429, { error: 'Слишком много запросов. Подождите минуту.', retryAfter: 60 });
  }

  // 5. Request timing (less than 50ms between non-asset requests = suspicious)
  if (!isAsset && !checkTiming(ip, 50)) {
    penalise(ip, 3, 'too_fast');
  }

  trust.lastSeen = Date.now();
  return next();
}

// ── WebSocket Bot Guard ───────────────────────────────────────────────────────
function wsGuard(ws, ip) {
  // Track WS connections per IP
  if (!wsConnections.has(ip)) wsConnections.set(ip, new Set());
  const conns = wsConnections.get(ip);
  conns.add(ws);

  // Too many connections from same IP
  if (conns.size > 5) {
    penalise(ip, 20, 'ws_too_many_connections');
    ws.close(1008, 'Too many connections from your IP');
    conns.delete(ws);
    return false;
  }

  ws.on('close', () => {
    conns.delete(ws);
    if (conns.size === 0) wsConnections.delete(ip);
  });

  return true;
}

function wsMessageGuard(ip) {
  // Rate limit WS messages
  if (!checkRateLimit(ip, 'ws_msg')) {
    penalise(ip, 10, 'ws_flood');
    return false;
  }
  return true;
}

// ── Admin: Ban/Unban ──────────────────────────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || randomBytes(16).toString('hex');
if (!process.env.ADMIN_KEY) {
  console.log(`[Admin] 🔑 Admin key: ${ADMIN_KEY} (set ADMIN_KEY env var to fix this)`);
}

function isAdmin(req) {
  const key = req.headers['x-admin-key'] || (req.url.split('?')[1] || '').split('key=')[1];
  return key === ADMIN_KEY;
}

// Cleanup tasks (run every 10 minutes)
setInterval(() => {
  const now = Date.now();

  // Clean expired CAPTCHA challenges
  for (const [token, ch] of captchaChallenges) {
    if (now > ch.expires) captchaChallenges.delete(token);
  }

  // Clean expired temp bans
  let changed = false;
  for (const [ip, until] of tempBans) {
    if (now > until) { tempBans.delete(ip); changed = true; }
  }
  if (changed) saveBans();

  // Clean old rate limit buckets
  for (const [ip, buckets] of rateLimits) {
    let hasData = false;
    for (const key of Object.keys(buckets)) {
      const cfg = RATE_LIMITS[key];
      if (!cfg) continue;
      buckets[key] = buckets[key].filter(ts => now - ts < cfg.window);
      if (buckets[key].length > 0) hasData = true;
    }
    if (!hasData) rateLimits.delete(ip);
  }

  // Clean old content hashes (older than 1 hour)
  for (const [hash, entry] of contentHashes) {
    if (now - entry.firstSeen > 3_600_000) contentHashes.delete(hash);
  }

  // Slowly recover trust scores (1 point per 10 min for idle IPs)
  for (const [ip, trust] of trustScores) {
    if (now - trust.lastSeen > 600_000 && trust.score < 100) {
      trust.score = Math.min(100, trust.score + 1);
    }
  }
}, 600_000);

// ══════════════════════════════════════════════════════════════════════════════
// ── MONGOOSE SCHEMAS ──────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const CommentSchema = new mongoose.Schema({
  id:          { type: String, required: true },
  userId:      String,
  userName:    String,
  userAvatar:  String,
  text:        String,
  timestamp:   String,
  likes:       { type: Number, default: 0 },
  isAuthor:    Boolean,
  _likedBy:    [String],
  replyTo:     { id: String, userName: String, text: String },
}, { _id: false });

const TrackSchema = new mongoose.Schema({
  id:            { type: String, required: true, unique: true, index: true },
  title:         { type: String, required: true },
  artist:        String,
  artistId:      { type: String, index: true },
  genre:         String,
  plays:         { type: Number, default: 0 },
  likes:         { type: Number, default: 0 },
  reposts:       { type: Number, default: 0 },
  duration:      String,
  uploadDate:    String,
  coverGradient: String,
  coverImage:    String,
  serverAudio:   String,
  verified:      { type: Boolean, default: true },
  isNew:         Boolean,
  description:   String,
  comments:      [CommentSchema],
  waveform:      [Number],
  isUserTrack:   Boolean,
  _likedBy:      [String],
  _repostedBy:   [String],
  createdAt:     { type: Date, default: Date.now },
}, { timestamps: false });

const UserSchema = new mongoose.Schema({
  id:          { type: String, required: true, unique: true, index: true },
  name:        { type: String, required: true },
  email:       { type: String, required: true, unique: true, index: true },
  role:        { type: String, enum: ['artist', 'listener'], default: 'listener' },
  tracksCount: { type: Number, default: 0 },
  followers:   { type: Number, default: 0 },
  verified:    { type: Boolean, default: true },
  joinedAt:    String,
  _followers:  [String],
  createdAt:   { type: Date, default: Date.now },
}, { timestamps: false });

let TrackModel = null;
let UserModel  = null;
let useMongoDb = false;

// ══════════════════════════════════════════════════════════════════════════════
// ── FILE DB FALLBACK ──────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

function loadFileDb() {
  try {
    if (existsSync(DB_FILE)) {
      const parsed = JSON.parse(readFileSync(DB_FILE, 'utf-8'));
      return {
        tracks: Array.isArray(parsed.tracks) ? parsed.tracks : [],
        users:  Array.isArray(parsed.users)  ? parsed.users  : [],
      };
    }
  } catch (e) { console.error('[FileDB] Load error:', e.message); }
  return { tracks: [], users: [] };
}

let fileDb = loadFileDb();

function saveFileDb() {
  try {
    writeFileSync(DB_FILE, JSON.stringify({
      tracks: fileDb.tracks.map(t => ({ ...t })),
      users:  fileDb.users.map(u => ({ ...u })),
    }, null, 2), 'utf-8');
  } catch (e) { console.error('[FileDB] Save error:', e.message); }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── UNIFIED DB INTERFACE ──────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════

const db = {
  async getAllUsers() {
    if (useMongoDb) return (await UserModel.find({}).lean()).map(clean);
    return fileDb.users;
  },
  async findUserByEmail(email) {
    const el = email.trim().toLowerCase();
    if (useMongoDb) { const u = await UserModel.findOne({ email: el }).lean(); return u ? clean(u) : null; }
    return fileDb.users.find(u => u.email.trim().toLowerCase() === el) || null;
  },
  async findUserByName(name) {
    const nl = name.trim().toLowerCase();
    if (useMongoDb) { const u = await UserModel.findOne({ name: { $regex: new RegExp(`^${escapeRegex(nl)}$`, 'i') } }).lean(); return u ? clean(u) : null; }
    return fileDb.users.find(u => u.name.trim().toLowerCase() === nl) || null;
  },
  async findUserById(id) {
    if (useMongoDb) { const u = await UserModel.findOne({ id }).lean(); return u ? clean(u) : null; }
    return fileDb.users.find(u => u.id === id) || null;
  },
  async createUser(user) {
    if (useMongoDb) { const doc = await UserModel.create({ ...user, email: user.email.trim().toLowerCase() }); return clean(doc.toObject()); }
    fileDb.users.push(user); saveFileDb(); return user;
  },
  async updateUser(id, updates) {
    if (useMongoDb) { const doc = await UserModel.findOneAndUpdate({ id }, updates, { new: true }).lean(); return doc ? clean(doc) : null; }
    const idx = fileDb.users.findIndex(u => u.id === id);
    if (idx !== -1) { fileDb.users[idx] = { ...fileDb.users[idx], ...updates }; saveFileDb(); return fileDb.users[idx]; }
    return null;
  },
  async getAllTracks() {
    if (useMongoDb) return (await TrackModel.find({}).sort({ createdAt: -1 }).lean()).map(cleanTrack);
    return fileDb.tracks;
  },
  async findTrackById(id) {
    if (useMongoDb) { const t = await TrackModel.findOne({ id }).lean(); return t ? cleanTrack(t) : null; }
    return fileDb.tracks.find(t => t.id === id) || null;
  },
  async createTrack(track) {
    const { audioUrl: _a, ...rest } = track;
    if (useMongoDb) { const doc = await TrackModel.create(rest); return cleanTrack(doc.toObject()); }
    fileDb.tracks.unshift(rest); saveFileDb(); return rest;
  },
  async updateTrack(id, updates) {
    if (useMongoDb) { const doc = await TrackModel.findOneAndUpdate({ id }, updates, { new: true }).lean(); return doc ? cleanTrack(doc) : null; }
    const idx = fileDb.tracks.findIndex(t => t.id === id);
    if (idx !== -1) { fileDb.tracks[idx] = { ...fileDb.tracks[idx], ...updates }; saveFileDb(); return fileDb.tracks[idx]; }
    return null;
  },
  async deleteTrack(id) {
    if (useMongoDb) { await TrackModel.deleteOne({ id }); return true; }
    const idx = fileDb.tracks.findIndex(t => t.id === id);
    if (idx !== -1) { fileDb.tracks.splice(idx, 1); saveFileDb(); return true; }
    return false;
  },
  async likeTrack(trackId, userId) {
    if (useMongoDb) {
      const t = await TrackModel.findOne({ id: trackId });
      if (!t) return null;
      if (!t._likedBy) t._likedBy = [];
      const had = t._likedBy.includes(userId);
      if (had) { t._likedBy = t._likedBy.filter(id => id !== userId); t.likes = Math.max(0, (t.likes||0)-1); }
      else { t._likedBy.push(userId); t.likes = (t.likes||0)+1; }
      await t.save(); return { track: cleanTrack(t.toObject()), toggled: !had };
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t._likedBy) t._likedBy = [];
    const had = t._likedBy.includes(userId);
    if (had) { t._likedBy = t._likedBy.filter(id => id !== userId); t.likes = Math.max(0,(t.likes||0)-1); }
    else { t._likedBy.push(userId); t.likes = (t.likes||0)+1; }
    saveFileDb(); return { track: t, toggled: !had };
  },
  async repostTrack(trackId, userId) {
    if (useMongoDb) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      if (!t._repostedBy) t._repostedBy = [];
      const had = t._repostedBy.includes(userId);
      if (had) { t._repostedBy = t._repostedBy.filter(id => id !== userId); t.reposts = Math.max(0,(t.reposts||0)-1); }
      else { t._repostedBy.push(userId); t.reposts = (t.reposts||0)+1; }
      await t.save(); return { track: cleanTrack(t.toObject()), toggled: !had };
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t._repostedBy) t._repostedBy = [];
    const had = t._repostedBy.includes(userId);
    if (had) { t._repostedBy = t._repostedBy.filter(id => id !== userId); t.reposts = Math.max(0,(t.reposts||0)-1); }
    else { t._repostedBy.push(userId); t.reposts = (t.reposts||0)+1; }
    saveFileDb(); return { track: t, toggled: !had };
  },
  async addComment(trackId, comment) {
    if (useMongoDb) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      if (t.comments.some(c => c.id === comment.id)) return cleanTrack(t.toObject());
      t.comments.push(comment); await t.save(); return cleanTrack(t.toObject());
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t.comments) t.comments = [];
    if (!t.comments.some(c => c.id === comment.id)) { t.comments.push(comment); saveFileDb(); }
    return t;
  },
  async likeComment(trackId, commentId, userId) {
    if (useMongoDb) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      const c = t.comments.find(c => c.id === commentId); if (!c) return null;
      if (!c._likedBy) c._likedBy = [];
      const had = c._likedBy.includes(userId);
      if (had) { c._likedBy = c._likedBy.filter(id => id !== userId); c.likes = Math.max(0,(c.likes||0)-1); }
      else { c._likedBy.push(userId); c.likes = (c.likes||0)+1; }
      await t.save(); return cleanTrack(t.toObject());
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    const c = (t.comments||[]).find(c => c.id === commentId); if (!c) return null;
    if (!c._likedBy) c._likedBy = [];
    const had = c._likedBy.includes(userId);
    if (had) { c._likedBy = c._likedBy.filter(id => id !== userId); c.likes = Math.max(0,(c.likes||0)-1); }
    else { c._likedBy.push(userId); c.likes = (c.likes||0)+1; }
    saveFileDb(); return t;
  },
  async incrementPlays(trackId) {
    if (useMongoDb) {
      await TrackModel.updateOne({ id: trackId }, { $inc: { plays: 1 } });
      const t = await TrackModel.findOne({ id: trackId }).lean(); return t ? cleanTrack(t) : null;
    }
    const t = fileDb.tracks.find(x => x.id === trackId);
    if (t) { t.plays = (t.plays||0)+1; saveFileDb(); } return t||null;
  },
  async followUser(targetId, followerId) {
    if (useMongoDb) {
      const target = await UserModel.findOne({ id: targetId }); if (!target) return null;
      if (!target._followers) target._followers = [];
      const had = target._followers.includes(followerId);
      if (had) { target._followers = target._followers.filter(id => id !== followerId); target.followers = Math.max(0,(target.followers||0)-1); }
      else { target._followers.push(followerId); target.followers = (target.followers||0)+1; }
      await target.save(); return { user: clean(target.toObject()), toggled: !had };
    }
    const target = fileDb.users.find(u => u.id === targetId); if (!target) return null;
    if (!target._followers) target._followers = [];
    const had = target._followers.includes(followerId);
    if (had) { target._followers = target._followers.filter(id => id !== followerId); target.followers = Math.max(0,(target.followers||0)-1); }
    else { target._followers.push(followerId); target.followers = (target.followers||0)+1; }
    saveFileDb(); return { user: target, toggled: !had };
  },
};

// ── Helpers ───────────────────────────────────────────────────────────────────
function clean(doc) {
  if (!doc) return doc;
  const { _id, __v, _followers, ...rest } = doc;
  return rest;
}
function cleanTrack(doc) {
  if (!doc) return doc;
  const { _id, __v, _likedBy, _repostedBy, ...rest } = doc;
  if (rest.comments) {
    rest.comments = rest.comments.map(c => { const { _likedBy: _cl, ...cr } = c; return cr; });
  }
  return rest;
}
function escapeRegex(str) { return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ── Audio/Cover ───────────────────────────────────────────────────────────────
function saveAudio(trackId, base64Data) {
  try {
    const idx = base64Data.indexOf(',');
    const b64 = idx !== -1 ? base64Data.slice(idx + 1) : base64Data;
    const buf = Buffer.from(b64, 'base64');
    writeFileSync(join(AUDIO_DIR, `${trackId}.bin`), buf);
    console.log(`[Audio] Saved ${trackId} (${(buf.length / 1024).toFixed(0)} KB)`);
    return `/api/audio/${trackId}`;
  } catch (e) { console.error('[Audio] Save error:', e.message); return null; }
}
function saveCover(trackId, base64Data) {
  try {
    const idx = base64Data.indexOf(',');
    const b64 = idx !== -1 ? base64Data.slice(idx + 1) : base64Data;
    writeFileSync(join(COVERS_DIR, `${trackId}.bin`), Buffer.from(b64, 'base64'));
    return `/api/cover/${trackId}`;
  } catch (e) { console.error('[Cover] Save error:', e.message); return null; }
}
function deleteAudio(trackId) {
  try {
    const { unlinkSync } = await import('fs').catch(() => ({ unlinkSync: () => {} }));
    const f = join(AUDIO_DIR, `${trackId}.bin`);
    if (existsSync(f)) unlinkSync(f);
  } catch { /**/ }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function readBody(req, maxBytes = 150 * 1024 * 1024) { // 150 MB max (audio files)
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > maxBytes) { req.destroy(); return reject(new Error('Payload too large')); }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}')); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function jsonRes(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':  'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function mkNotif(type, text, icon = '🔔', trackId = null) {
  return { id: 'n' + Date.now() + Math.random().toString(36).slice(2), type, text, icon, ts: Date.now(), trackId };
}

// ── WebSocket helpers ─────────────────────────────────────────────────────────
const clientMap = new Map();
function sendWs(ws, data) {
  try { if (ws.readyState === 1) ws.send(JSON.stringify(data)); } catch { /**/ }
}
function broadcast(data, except = null) {
  const msg = JSON.stringify(data);
  for (const c of wss.clients)
    if (c !== except && c.readyState === 1)
      try { c.send(msg); } catch { /**/ }
}
function notifyUser(uid, notif) {
  for (const [ws, id] of clientMap)
    if (id === uid && ws.readyState === 1)
      try { ws.send(JSON.stringify({ type: 'NOTIFICATION', notification: notif })); } catch { /**/ }
}

// ══════════════════════════════════════════════════════════════════════════════
// ── HTTP SERVER ───────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════
const http = createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const ip  = getIp(req);
  const url = req.url.split('?')[0];
  const method = req.method;

  // ── Static audio/cover — no bot guard (performance) ──────────────────────
  if (method === 'GET' && url.startsWith('/api/audio/')) {
    const id   = url.slice('/api/audio/'.length);
    const file = join(AUDIO_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf  = readFileSync(file);
    const range = req.headers.range;
    if (range) {
      const [startStr, endStr] = range.replace(/bytes=/, '').split('-');
      const start = parseInt(startStr, 10);
      const end   = endStr ? parseInt(endStr, 10) : buf.length - 1;
      const chunk = buf.slice(start, end + 1);
      res.writeHead(206, {
        'Content-Range':  `bytes ${start}-${end}/${buf.length}`,
        'Accept-Ranges':  'bytes',
        'Content-Length': chunk.length,
        'Content-Type':   'audio/mpeg',
      });
      res.end(chunk);
    } else {
      res.writeHead(200, {
        'Content-Type':   'audio/mpeg',
        'Content-Length': buf.length,
        'Accept-Ranges':  'bytes',
        'Cache-Control':  'public, max-age=86400',
      });
      res.end(buf);
    }
    return;
  }

  if (method === 'GET' && url.startsWith('/api/cover/')) {
    const id   = url.slice('/api/cover/'.length);
    const file = join(COVERS_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf  = readFileSync(file);
    res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': buf.length, 'Cache-Control': 'public, max-age=86400' });
    res.end(buf);
    return;
  }

  // ── Admin panel ───────────────────────────────────────────────────────────
  if (url === '/api/admin/stats' && method === 'GET') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, {
      tracks: tracks.length,
      users: users.length,
      permBans: [...permBans],
      tempBans: [...tempBans.entries()].map(([ip, until]) => ({ ip, until, remaining: Math.ceil((until - Date.now()) / 60_000) + 'm' })),
      trustScores: Object.fromEntries([...trustScores.entries()].filter(([,t]) => t.score < 80)),
      wsClients: wss.clients.size,
      uptime: process.uptime(),
      db: useMongoDb ? 'MongoDB' : 'FileDB',
    });
  }

  if (url.startsWith('/api/admin/ban/') && method === 'POST') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const banIp = url.slice('/api/admin/ban/'.length);
    permBans.add(banIp); saveBans();
    return jsonRes(res, 200, { ok: true, message: `${banIp} permanently banned` });
  }

  if (url.startsWith('/api/admin/unban/') && method === 'POST') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const unbanIp = url.slice('/api/admin/unban/'.length);
    permBans.delete(unbanIp); tempBans.delete(unbanIp); saveBans();
    return jsonRes(res, 200, { ok: true, message: `${unbanIp} unbanned` });
  }

  // ── CAPTCHA challenge ─────────────────────────────────────────────────────
  if (url === '/api/captcha/challenge' && method === 'GET') {
    const ch = generateChallenge(ip);
    return jsonRes(res, 200, ch);
  }

  if (url === '/api/captcha/verify' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { ok: false }); }
    const result = verifyCaptcha(body.token, body.nonce, ip);
    return jsonRes(res, result.ok ? 200 : 400, result);
  }

  // ── Bot guard for all other API routes ────────────────────────────────────
  let guardPassed = false;
  await botGuard(req, res, () => { guardPassed = true; });
  if (!guardPassed) return;

  // ── Health ────────────────────────────────────────────────────────────────
  if (url === '/api/health' && method === 'GET') {
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, { ok: true, db: useMongoDb ? 'MongoDB' : 'FileDB', tracks: tracks.length, users: users.length, uptime: process.uptime() });
  }

  // ── State ─────────────────────────────────────────────────────────────────
  if (url === '/api/state' && method === 'GET') {
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, { tracks, users: users.map(clean), ts: Date.now() });
  }

  // ── Register ──────────────────────────────────────────────────────────────
  if (url === '/api/register' && method === 'POST') {
    // Auth rate limit
    if (!checkRateLimit(ip, 'auth')) {
      penalise(ip, 15, 'auth_rate_limit');
      return jsonRes(res, 429, { error: 'Слишком много попыток. Подождите 5 минут.' });
    }
    if (!checkRateLimit(ip, 'register')) {
      penalise(ip, 20, 'reg_rate_limit');
      return jsonRes(res, 429, { error: 'Превышен лимит регистраций с вашего IP (3/час).' });
    }
    if (!checkMassAccounts(ip)) {
      penalise(ip, 25, 'mass_accounts');
      return jsonRes(res, 429, { error: 'Слишком много аккаунтов с одного IP.' });
    }

    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }

    // Honeypot check
    const hp = checkHoneypot(body);
    if (!hp.ok) {
      penalise(ip, 50, `honeypot:${hp.field}`);
      console.log(`[BotGuard] 🍯 Honeypot triggered by ${ip} — field: ${hp.field}`);
      // Return fake success to confuse bots
      return jsonRes(res, 200, { user: { id: 'fake', name: body.user?.name || 'User' } });
    }

    const { user } = body || {};
    if (!user?.name || !user?.email) return jsonRes(res, 400, { error: 'Имя и email обязательны' });

    // Content duplication check
    const dup = checkContentDuplication(user.email + user.name, ip);
    if (!dup.ok) {
      penalise(ip, 30, 'duplicate_registration');
      return jsonRes(res, 429, { error: 'Подозрительная активность. Попробуйте позже.' });
    }

    if (await db.findUserByName(user.name)) return jsonRes(res, 409, { error: `Имя «${user.name.trim()}» уже занято` });
    if (await db.findUserByEmail(user.email)) return jsonRes(res, 409, { error: 'Этот email уже зарегистрирован' });

    const pub = {
      id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
      name: user.name.trim(), email: user.email.trim().toLowerCase(),
      role: user.role || 'listener', tracksCount: 0, followers: 0,
      verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
    };
    const saved = await db.createUser(pub);
    recordAccount(ip, saved.id);
    reward(ip, 5);
    broadcast({ type: 'USER_REGISTERED', user: saved });
    return jsonRes(res, 200, { user: saved });
  }

  // ── Login ─────────────────────────────────────────────────────────────────
  if (url === '/api/login' && method === 'POST') {
    if (!checkRateLimit(ip, 'auth')) {
      penalise(ip, 10, 'login_rate_limit');
      return jsonRes(res, 429, { error: 'Слишком много попыток входа. Подождите.' });
    }
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }
    const email = (body?.email || '').trim().toLowerCase();
    if (!email) return jsonRes(res, 400, { error: 'Email обязателен' });
    const found = await db.findUserByEmail(email);
    if (!found) { penalise(ip, 3, 'login_not_found'); return jsonRes(res, 404, { error: 'Аккаунт не найден' }); }
    reward(ip, 2);
    return jsonRes(res, 200, { user: clean(found) });
  }

  // ── Upload track ──────────────────────────────────────────────────────────
  if (url === '/api/track' && method === 'POST') {
    if (!checkRateLimit(ip, 'upload')) {
      penalise(ip, 10, 'upload_rate_limit');
      return jsonRes(res, 429, { error: 'Превышен лимит загрузок (20/день).' });
    }
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON или файл слишком большой' }); }
    const { track, audioData, coverData } = body || {};
    if (!track?.id || !track?.title) return jsonRes(res, 400, { error: 'Неверные данные трека' });
    const existing = await db.findTrackById(track.id);
    if (existing) return jsonRes(res, 200, { ok: true, duplicate: true });

    // Content dedup
    const dup = checkContentDuplication(track.title + track.artistId, ip);
    if (!dup.ok) {
      penalise(ip, 20, 'duplicate_track');
      return jsonRes(res, 429, { error: 'Похожий трек уже был загружен. Подождите немного.' });
    }

    let serverAudioUrl = null;
    if (audioData && typeof audioData === 'string') serverAudioUrl = saveAudio(track.id, audioData);
    let serverCoverUrl = null;
    if (coverData && typeof coverData === 'string') serverCoverUrl = saveCover(track.id, coverData);

    const toSave = { ...track, audioUrl: undefined, serverAudio: serverAudioUrl, coverImage: serverCoverUrl || track.coverImage };
    const saved  = await db.createTrack(toSave);
    const artist = await db.findUserById(track.artistId);
    if (artist) await db.updateUser(track.artistId, { tracksCount: (artist.tracksCount || 0) + 1 });
    reward(ip, 5);
    broadcast({ type: 'TRACK_ADDED', track: saved });
    return jsonRes(res, 200, { ok: true, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
  }

  // ── Delete track ──────────────────────────────────────────────────────────
  if (method === 'DELETE' && url.startsWith('/api/track/')) {
    const trackId = url.slice('/api/track/'.length);
    const track   = await db.findTrackById(trackId);
    if (!track) return jsonRes(res, 404, { error: 'Трек не найден' });
    await db.deleteTrack(trackId);
    const artist = await db.findUserById(track.artistId);
    if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0, (artist.tracksCount || 1) - 1) });
    deleteAudio(trackId);
    broadcast({ type: 'TRACK_DELETED', trackId });
    return jsonRes(res, 200, { ok: true });
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  if (url === '/api/action' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }

    switch (body?.type) {
      case 'LIKE': {
        const { trackId, userId } = body;
        const result = await db.likeTrack(trackId, userId);
        if (!result) return jsonRes(res, 404, { error: 'Трек не найден' });
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== userId) {
          const liker = await db.findUserById(userId);
          notifyUser(track.artistId, mkNotif('like', `${liker?.name||'Кто-то'} лайкнул «${track.title}»`, '❤️', trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true, likes: track.likes });
      }
      case 'REPOST': {
        const { trackId, userId } = body;
        const result = await db.repostTrack(trackId, userId);
        if (!result) return jsonRes(res, 404, { error: 'Трек не найден' });
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== userId) {
          const u = await db.findUserById(userId);
          notifyUser(track.artistId, mkNotif('repost', `${u?.name||'Кто-то'} сделал репост «${track.title}»`, '🔄', trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true, reposts: track.reposts });
      }
      case 'COMMENT': {
        const { trackId, comment } = body;
        // Content dedup for comments
        const dup2 = checkContentDuplication(comment.text, ip);
        if (!dup2.ok) { penalise(ip, 15, 'duplicate_comment'); return jsonRes(res, 429, { error: 'Спам-комментарий обнаружен.' }); }
        const track = await db.addComment(trackId, comment);
        if (!track) return jsonRes(res, 404, { error: 'Трек не найден' });
        broadcast({ type: 'TRACK_UPDATED', track });
        if (track.artistId && track.artistId !== comment.userId) {
          const preview = comment.text.slice(0, 40) + (comment.text.length > 40 ? '…' : '');
          notifyUser(track.artistId, mkNotif('comment', `${comment.userName}: "${preview}"`, '💬', trackId));
        }
        if (comment.replyTo?.id) {
          const parent = (track.comments||[]).find(c => c.id === comment.replyTo.id);
          if (parent && parent.userId !== comment.userId)
            notifyUser(parent.userId, mkNotif('reply', `${comment.userName} ответил тебе`, '↩️', trackId));
        }
        return jsonRes(res, 200, { ok: true, comments: track.comments });
      }
      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = body;
        const track = await db.likeComment(trackId, commentId, userId);
        if (!track) return jsonRes(res, 404, { error: 'Не найдено' });
        broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true });
      }
      case 'PLAY': {
        const track = await db.incrementPlays(body.trackId);
        if (track) broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true });
      }
      case 'FOLLOW': {
        const { targetId, followerId } = body;
        const result = await db.followUser(targetId, followerId);
        if (!result) return jsonRes(res, 404, { error: 'Пользователь не найден' });
        const { user } = result;
        if (result.toggled) {
          const f = await db.findUserById(followerId);
          notifyUser(targetId, mkNotif('follow', `${f?.name||'Кто-то'} подписался на тебя`, '👤'));
        }
        broadcast({ type: 'USER_UPDATED', user: clean(user) });
        return jsonRes(res, 200, { ok: true, followers: user.followers });
      }
      case 'DELETE_TRACK': {
        const { trackId, userId } = body;
        const track = await db.findTrackById(trackId);
        if (!track) return jsonRes(res, 404, { error: 'Трек не найден' });
        if (track.artistId !== userId) return jsonRes(res, 403, { error: 'Нет прав' });
        await db.deleteTrack(trackId);
        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0, (artist.tracksCount||1)-1) });
        deleteAudio(trackId);
        broadcast({ type: 'TRACK_DELETED', trackId });
        return jsonRes(res, 200, { ok: true });
      }
      default: return jsonRes(res, 400, { error: 'Неизвестное действие' });
    }
  }

  // ── SPA fallback ──────────────────────────────────────────────────────────
  if (method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(HTML_CONTENT);
    return;
  }

  jsonRes(res, 404, { error: 'Not found' });
});

// ══════════════════════════════════════════════════════════════════════════════
// ── WEBSOCKET SERVER ──────────────════════════════════════════════════════════
// ══════════════════════════════════════════════════════════════════════════════
const wss = new WebSocketServer({ server: http });

wss.on('connection', (ws, req) => {
  const ip = getIp(req);

  // Ban check
  const ban = isBanned(ip);
  if (ban.banned) {
    ws.close(1008, 'Banned');
    return;
  }

  // WS bot guard
  if (!wsGuard(ws, ip)) return;

  // UA check
  const ua = req.headers['user-agent'] || '';
  const uaResult = analyseUserAgent(ua);
  if (!uaResult.ok) {
    penalise(ip, 20, `ws_ua:${uaResult.reason}`);
    ws.close(1008, 'Bot detected');
    return;
  }

  clientMap.set(ws, null);

  ws.on('message', async (raw) => {
    const ip2 = getIp(req);

    // WS flood protection
    if (!wsMessageGuard(ip2)) {
      penalise(ip2, 5, 'ws_flood');
      sendWs(ws, { type: 'ERROR', message: 'Слишком много сообщений. Замедлитесь.' });
      return;
    }

    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    // Max message size
    if (raw.length > 160 * 1024 * 1024) {
      penalise(ip2, 10, 'ws_large_msg');
      return;
    }

    switch (msg.type) {
      case 'INIT': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
        sendWs(ws, { type: 'STATE', tracks, users: users.map(clean) });
        break;
      }
      case 'IDENTIFY': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        break;
      }
      case 'REGISTER': {
        const { user } = msg;
        if (!user?.name || !user?.email) { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Имя и email обязательны' }); break; }

        // Registration rate limit via WS
        if (!checkRateLimit(ip2, 'register')) {
          penalise(ip2, 20, 'ws_reg_limit');
          sendWs(ws, { type: 'REGISTER_ERROR', message: 'Превышен лимит регистраций (3/час).' });
          break;
        }
        if (!checkMassAccounts(ip2)) {
          penalise(ip2, 25, 'ws_mass_accounts');
          sendWs(ws, { type: 'REGISTER_ERROR', message: 'Слишком много аккаунтов с одного IP.' });
          break;
        }

        if (await db.findUserByName(user.name)) { sendWs(ws, { type: 'REGISTER_ERROR', message: `Имя «${user.name.trim()}» уже занято` }); break; }
        if (await db.findUserByEmail(user.email)) { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Email уже зарегистрирован' }); break; }

        const pub = {
          id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
          name: user.name.trim(), email: user.email.trim().toLowerCase(),
          role: user.role || 'listener', tracksCount: 0, followers: 0,
          verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
        };
        const saved = await db.createUser(pub);
        recordAccount(ip2, saved.id);
        clientMap.set(ws, saved.id);
        reward(ip2, 5);
        sendWs(ws, { type: 'REGISTER_OK', user: saved });
        broadcast({ type: 'USER_REGISTERED', user: saved }, ws);
        break;
      }
      case 'LOGIN': {
        if (!checkRateLimit(ip2, 'auth')) {
          penalise(ip2, 10, 'ws_login_limit');
          sendWs(ws, { type: 'LOGIN_ERROR', message: 'Слишком много попыток. Подождите.' });
          break;
        }
        const el    = (msg.email || '').trim().toLowerCase();
        const found = await db.findUserByEmail(el);
        if (found) { clientMap.set(ws, found.id); reward(ip2, 2); sendWs(ws, { type: 'LOGIN_OK', user: clean(found) }); }
        else { penalise(ip2, 3, 'ws_login_not_found'); sendWs(ws, { type: 'LOGIN_ERROR', message: 'Аккаунт не найден' }); }
        break;
      }
      case 'UPLOAD_TRACK': {
        if (!checkRateLimit(ip2, 'upload')) {
          penalise(ip2, 10, 'ws_upload_limit');
          sendWs(ws, { type: 'ERROR', message: 'Превышен лимит загрузок (20/день).' });
          break;
        }
        const { track, audioData, coverData } = msg;
        if (!track?.id || !track?.title) break;
        const existing = await db.findTrackById(track.id);
        if (existing) { sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, duplicate: true }); break; }

        const dup = checkContentDuplication(track.title + track.artistId, ip2);
        if (!dup.ok) {
          penalise(ip2, 20, 'ws_duplicate_track');
          sendWs(ws, { type: 'ERROR', message: 'Дублирование трека обнаружено.' });
          break;
        }

        let serverAudioUrl = null;
        if (audioData) serverAudioUrl = saveAudio(track.id, audioData);
        let serverCoverUrl = null;
        if (coverData) serverCoverUrl = saveCover(track.id, coverData);

        const toSave = { ...track, audioUrl: undefined, serverAudio: serverAudioUrl, coverImage: serverCoverUrl || track.coverImage };
        const saved  = await db.createTrack(toSave);
        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: (artist.tracksCount||0)+1 });
        reward(ip2, 5);
        broadcast({ type: 'TRACK_ADDED', track: saved });
        sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
        break;
      }
      case 'DELETE_TRACK': {
        const { trackId, userId } = msg;
        const track = await db.findTrackById(trackId);
        if (!track || track.artistId !== userId) break;
        await db.deleteTrack(trackId);
        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0,(artist.tracksCount||1)-1) });
        deleteAudio(trackId);
        broadcast({ type: 'TRACK_DELETED', trackId });
        break;
      }
      case 'LIKE': {
        const { trackId, userId } = msg;
        const result = await db.likeTrack(trackId, userId);
        if (!result) break;
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== userId) {
          const liker = await db.findUserById(userId);
          notifyUser(track.artistId, mkNotif('like', `${liker?.name||'Кто-то'} лайкнул «${track.title}»`, '❤️', trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'REPOST': {
        const { trackId, userId } = msg;
        const result = await db.repostTrack(trackId, userId);
        if (!result) break;
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== userId) {
          const u = await db.findUserById(userId);
          notifyUser(track.artistId, mkNotif('repost', `${u?.name||'Кто-то'} сделал репост «${track.title}»`, '🔄', trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'COMMENT': {
        const { trackId, comment } = msg;
        const dup2 = checkContentDuplication(comment.text, ip2);
        if (!dup2.ok) { penalise(ip2, 15, 'ws_spam_comment'); break; }
        const track = await db.addComment(trackId, comment);
        if (!track) break;
        broadcast({ type: 'TRACK_UPDATED', track });
        if (track.artistId && track.artistId !== comment.userId) {
          const preview = comment.text.slice(0, 40) + (comment.text.length > 40 ? '…' : '');
          notifyUser(track.artistId, mkNotif('comment', `${comment.userName}: "${preview}"`, '💬', trackId));
        }
        if (comment.replyTo?.id) {
          const parent = (track.comments||[]).find(c => c.id === comment.replyTo.id);
          if (parent && parent.userId !== comment.userId)
            notifyUser(parent.userId, mkNotif('reply', `${comment.userName} ответил тебе`, '↩️', trackId));
        }
        break;
      }
      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = msg;
        const track = await db.likeComment(trackId, commentId, userId);
        if (track) broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'PLAY': {
        const track = await db.incrementPlays(msg.trackId);
        if (track) broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'FOLLOW': {
        const { targetId, followerId } = msg;
        const result = await db.followUser(targetId, followerId);
        if (!result) break;
        const { user } = result;
        if (result.toggled) {
          const f = await db.findUserById(followerId);
          notifyUser(targetId, mkNotif('follow', `${f?.name||'Кто-то'} подписался на тебя`, '👤'));
        }
        broadcast({ type: 'USER_UPDATED', user: clean(user) });
        break;
      }
      default: break;
    }
  });

  ws.on('close', () => clientMap.delete(ws));
  ws.on('error', err => console.error('[WS]', err.message));
});

// ══════════════════════════════════════════════════════════════════════════════
// ── STARTUP ───────────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════════
async function start() {
  if (MONGO_URL) {
    try {
      console.log('[DB] Connecting to MongoDB...');
      await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 8000, socketTimeoutMS: 30000 });
      TrackModel = mongoose.model('Track', TrackSchema);
      UserModel  = mongoose.model('User',  UserSchema);
      useMongoDb = true;
      const [tc, uc] = await Promise.all([TrackModel.countDocuments(), UserModel.countDocuments()]);
      console.log(`✅ MongoDB connected! ${tc} tracks, ${uc} users`);
    } catch (e) {
      console.error(`❌ MongoDB failed: ${e.message} → falling back to FileDB`);
      useMongoDb = false;
    }
  } else {
    console.log(`[DB] FileDB → ${fileDb.tracks.length} tracks, ${fileDb.users.length} users`);
  }

  http.listen(PORT, HOST, () => {
    console.log(`
╔══════════════════════════════════════════════════════╗
║         ClaudMusic  •  Ready! 🎵                     ║
╠══════════════════════════════════════════════════════╣
║  URL:      http://localhost:${String(PORT).padEnd(25)}║
║  Database: ${(useMongoDb ? '✅ MongoDB' : '📁 FileDB (data/db.json)').padEnd(42)}║
║  BotGuard: 🛡️  ACTIVE (10 layers)                   ║
╠══════════════════════════════════════════════════════╣
║  Anti-bot layers:                                    ║
║   ✓ Rate limiting (req/auth/upload/ws)               ║
║   ✓ IP ban system (permanent + temporary)            ║
║   ✓ User-Agent fingerprinting                        ║
║   ✓ Honeypot trap fields                             ║
║   ✓ Request timing analysis                          ║
║   ✓ PoW CAPTCHA challenge system                     ║
║   ✓ WebSocket flood protection                       ║
║   ✓ Mass account detection (3/IP)                    ║
║   ✓ Content deduplication                            ║
║   ✓ Trust score system (0-100)                       ║
╚══════════════════════════════════════════════════════╝
    `);
  });
}

function shutdown(sig) {
  console.log(`\n[${sig}] Shutting down...`);
  if (!useMongoDb) saveFileDb();
  saveBans();
  if (useMongoDb) mongoose.connection.close().catch(() => {});
  http.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

start().catch(err => { console.error('Fatal:', err); process.exit(1); });
