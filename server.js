/**
 * ClaudMusic — Production Server
 * ═══════════════════════════════
 * Storage: MongoDB (primary) → data/db.json (fallback)
 * Realtime: WebSocket
 * Anti-bot: 10-layer protection
 */

import { createServer }    from 'http';
import { WebSocketServer } from 'ws';
import {
  readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync,
} from 'fs';
import { join, dirname }   from 'path';
import { fileURLToPath }   from 'url';
import { execSync }        from 'child_process';
import crypto              from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const PORT      = parseInt(process.env.PORT || '3000', 10);
const HOST      = '0.0.0.0';
const MONGO_URL = process.env.MONGO_URL
               || process.env.MONGODB_URL
               || process.env.DATABASE_URL
               || '';

// ── Auto-build ────────────────────────────────────────────────────────────────
const DIST = join(__dirname, 'dist', 'index.html');
if (!existsSync(DIST)) {
  console.log('⚙️  Building...');
  try {
    execSync('npm run build', { stdio: 'inherit', cwd: __dirname });
  } catch {
    console.error('❌ Build failed. Run: npm run build');
    process.exit(1);
  }
}

let HTML_CONTENT;
try {
  HTML_CONTENT = readFileSync(DIST);
  console.log(`✅ dist/index.html (${(HTML_CONTENT.length / 1024).toFixed(0)} KB)`);
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
// ANTI-BOT SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

const BOT_UA_PATTERNS = [
  'bot','crawler','spider','scraper','headless','phantom','selenium',
  'puppeteer','playwright','curl','wget','python-requests','python-urllib',
  'java/','go-http','ruby','okhttp','axios/','node-fetch','got/',
  'libwww','lwp-','httpclient','mechanize','nikto','sqlmap','masscan',
  'nmap','zgrab','dirbuster','gobuster','hydra','medusa','skipfish',
];
const BROWSER_SIGS = ['mozilla/','chrome/','firefox/','safari/','edge/','opera/','webkit'];

const rateLimits   = new Map();
const trustScores  = new Map();
const captchas     = new Map();
const tempBans     = new Map();
const wsConns      = new Map();
const ipAccounts   = new Map();
const contentHashes = new Map();
const reqTimings   = new Map();
let   permBans     = new Set();

const RATE_CFG = {
  request:    { window: 60_000,     max: 120 },
  auth:       { window: 300_000,    max: 10  },
  register:   { window: 3_600_000,  max: 3   },
  upload:     { window: 86_400_000, max: 20  },
  ws_msg:     { window: 10_000,     max: 50  },
  ws_connect: { window: 60_000,     max: 5   },
};

function loadBans() {
  try {
    if (existsSync(BAN_FILE)) {
      const d = JSON.parse(readFileSync(BAN_FILE, 'utf-8'));
      permBans = new Set(Array.isArray(d.permanent) ? d.permanent : []);
      if (Array.isArray(d.temporary)) {
        const now = Date.now();
        for (const { ip, until } of d.temporary)
          if (until > now) tempBans.set(ip, until);
      }
      console.log(`[BotGuard] ${permBans.size} perm bans, ${tempBans.size} temp bans`);
    }
  } catch {}
}
function saveBans() {
  try {
    writeFileSync(BAN_FILE, JSON.stringify({
      permanent: [...permBans],
      temporary: [...tempBans.entries()].map(([ip, until]) => ({ ip, until })),
    }, null, 2));
  } catch {}
}
loadBans();

function bucket(ip, key) {
  if (!rateLimits.has(ip)) rateLimits.set(ip, {});
  const b = rateLimits.get(ip);
  if (!b[key]) b[key] = [];
  return b[key];
}
function checkRate(ip, key) {
  const cfg = RATE_CFG[key]; const now = Date.now();
  const b = bucket(ip, key);
  const fresh = b.filter(t => now - t < cfg.window);
  rateLimits.get(ip)[key] = fresh;
  if (fresh.length >= cfg.max) return false;
  fresh.push(now); return true;
}

function getTrust(ip) {
  if (!trustScores.has(ip)) trustScores.set(ip, { score: 80, violations: 0, lastSeen: Date.now() });
  return trustScores.get(ip);
}
function penalise(ip, n, reason) {
  const t = getTrust(ip);
  t.score = Math.max(0, t.score - n);
  t.violations++; t.lastSeen = Date.now();
  if (t.score <= 0 && t.violations >= 5) {
    const dur = Math.min(t.violations * 10 * 60_000, 86_400_000);
    tempBans.set(ip, Date.now() + dur); saveBans();
    console.log(`[BotGuard] Auto-ban ${ip} for ${(dur/60000).toFixed(0)}m (${reason})`);
  }
}
function reward(ip, n = 2) {
  const t = getTrust(ip);
  t.score = Math.min(100, t.score + n); t.lastSeen = Date.now();
}

function getIp(req) {
  return (
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress || 'unknown'
  ).replace('::ffff:', '');
}

function isBanned(ip) {
  if (permBans.has(ip)) return { banned: true, reason: 'permanent', retry: null };
  const u = tempBans.get(ip);
  if (u) {
    if (Date.now() < u) return { banned: true, reason: 'temporary', retry: Math.ceil((u - Date.now()) / 60_000) };
    tempBans.delete(ip);
  }
  return { banned: false };
}

function checkUA(ua) {
  if (!ua || ua.length < 10) return { ok: false, reason: 'no_ua' };
  const l = ua.toLowerCase();
  for (const p of BOT_UA_PATTERNS) if (l.includes(p)) return { ok: false, reason: `bot:${p}` };
  if (!BROWSER_SIGS.some(s => l.includes(s))) return { ok: false, reason: 'non_browser' };
  return { ok: true };
}

function checkHoneypot(body) {
  for (const f of ['website','phone2','username2','_gotcha','fax','address2'])
    if (body[f] !== undefined && body[f] !== '') return { ok: false, field: f };
  return { ok: true };
}

function checkTiming(ip) {
  const last = reqTimings.get(ip) || 0; const now = Date.now();
  reqTimings.set(ip, now);
  return last === 0 || (now - last) >= 50;
}

function checkDup(content, ip) {
  const hash = crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
  const e = contentHashes.get(hash);
  if (e) {
    e.count++;
    if (e.count > 5 || (e.ip !== ip && e.count > 2)) return { ok: false };
  } else contentHashes.set(hash, { ip, count: 1, firstSeen: Date.now() });
  return { ok: true };
}

const ADMIN_KEY = process.env.ADMIN_KEY || crypto.randomBytes(16).toString('hex');
if (!process.env.ADMIN_KEY) console.log(`[Admin] Key: ${ADMIN_KEY}`);
function isAdmin(req) {
  const k = req.headers['x-admin-key'] || (req.url.split('?')[1] || '').split('key=')[1];
  return k === ADMIN_KEY;
}

async function botGuard(req, res, next) {
  const ip = getIp(req); const ua = req.headers['user-agent'] || '';
  const ban = isBanned(ip);
  if (ban.banned) return jsonRes(res, 403, { error: ban.reason === 'permanent' ? '🚫 IP заблокирован навсегда.' : `🚫 Временный бан. Повтори через ${ban.retry} мин.`, banned: true });
  const trust = getTrust(ip);
  if (trust.score <= 10) { penalise(ip, 0, 'low_trust'); return jsonRes(res, 429, { error: 'Слишком много нарушений.' }); }
  const url = req.url.split('?')[0];
  const isAsset = url.startsWith('/api/audio/') || url.startsWith('/api/cover/') || url === '/api/health';
  if (!isAsset) {
    const ur = checkUA(ua);
    if (!ur.ok) { penalise(ip, 30, ur.reason); return jsonRes(res, 403, { error: 'Доступ запрещён.', code: 'UA_BLOCKED' }); }
  }
  if (!checkRate(ip, 'request')) { penalise(ip, 5, 'rate_global'); return jsonRes(res, 429, { error: 'Слишком много запросов. Подождите.', retryAfter: 60 }); }
  if (!isAsset && !checkTiming(ip)) penalise(ip, 3, 'too_fast');
  trust.lastSeen = Date.now();
  return next();
}

setInterval(() => {
  const now = Date.now();
  for (const [t, ch] of captchas) if (now > ch.expires) captchas.delete(t);
  let changed = false;
  for (const [ip, u] of tempBans) if (now > u) { tempBans.delete(ip); changed = true; }
  if (changed) saveBans();
  for (const [, b] of rateLimits) for (const k of Object.keys(b)) { const cfg = RATE_CFG[k]; if (cfg) b[k] = b[k].filter(t => now - t < cfg.window); }
  for (const [h, e] of contentHashes) if (now - e.firstSeen > 3_600_000) contentHashes.delete(h);
  for (const [ip, t] of trustScores) if (now - t.lastSeen > 600_000 && t.score < 100) t.score = Math.min(100, t.score + 1);
}, 600_000);

// ══════════════════════════════════════════════════════════════════════════════
// DATABASE — MongoDB primary, file fallback
// ══════════════════════════════════════════════════════════════════════════════

let mongoose = null;
let TrackModel = null;
let UserModel  = null;
let useMongo   = false;

// ── File DB ───────────────────────────────────────────────────────────────────
function loadFileDb() {
  try {
    if (existsSync(DB_FILE)) {
      const p = JSON.parse(readFileSync(DB_FILE, 'utf-8'));
      return {
        tracks: Array.isArray(p.tracks) ? p.tracks : [],
        users:  Array.isArray(p.users)  ? p.users  : [],
      };
    }
  } catch (e) { console.error('[FileDB] Load error:', e.message); }
  return { tracks: [], users: [] };
}

let fileDb = loadFileDb();
let saveTimer = null;

function scheduleFileSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(flushFileSave, 500);
}

function flushFileSave() {
  saveTimer = null;
  try {
    writeFileSync(DB_FILE, JSON.stringify({
      tracks: fileDb.tracks.map(t => ({ ...t, audioUrl: undefined })),
      users:  fileDb.users.map(u => ({ ...u })),
    }, null, 2), 'utf-8');
  } catch (e) { console.error('[FileDB] Save error:', e.message); }
}

// ── Mongoose schemas ──────────────────────────────────────────────────────────
async function initMongo() {
  if (!MONGO_URL) return false;
  try {
    mongoose = (await import('mongoose')).default;
    await mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 8000, socketTimeoutMS: 30000 });

    const CommentSchema = new mongoose.Schema({
      id: String, userId: String, userName: String, userAvatar: String,
      text: String, timestamp: String, likes: { type: Number, default: 0 },
      isAuthor: Boolean, _likedBy: [String],
      replyTo: { id: String, userName: String, text: String },
    }, { _id: false });

    const TrackSchema = new mongoose.Schema({
      id:            { type: String, required: true, unique: true, index: true },
      title:         String,
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
    }, { timestamps: true });

    const UserSchema = new mongoose.Schema({
      id:          { type: String, required: true, unique: true, index: true },
      name:        String,
      email:       { type: String, unique: true, index: true },
      role:        { type: String, enum: ['artist', 'listener'], default: 'listener' },
      tracksCount: { type: Number, default: 0 },
      followers:   { type: Number, default: 0 },
      verified:    { type: Boolean, default: true },
      joinedAt:    String,
      _followers:  [String],
    }, { timestamps: true });

    TrackModel = mongoose.models.Track || mongoose.model('Track', TrackSchema);
    UserModel  = mongoose.models.User  || mongoose.model('User',  UserSchema);
    useMongo   = true;

    const [tc, uc] = await Promise.all([TrackModel.countDocuments(), UserModel.countDocuments()]);
    console.log(`✅ MongoDB connected! ${tc} tracks, ${uc} users`);

    // Migrate fileDb → MongoDB if MongoDB is empty and fileDb has data
    if (tc === 0 && fileDb.tracks.length > 0) {
      console.log(`[DB] Migrating ${fileDb.tracks.length} tracks from FileDB → MongoDB...`);
      for (const t of fileDb.tracks) {
        try { await TrackModel.create({ ...t, audioUrl: undefined }); } catch {}
      }
    }
    if (uc === 0 && fileDb.users.length > 0) {
      console.log(`[DB] Migrating ${fileDb.users.length} users from FileDB → MongoDB...`);
      for (const u of fileDb.users) {
        try { await UserModel.create(u); } catch {}
      }
    }

    return true;
  } catch (e) {
    console.error(`❌ MongoDB failed: ${e.message} → FileDB`);
    return false;
  }
}

// ── Clean helpers ─────────────────────────────────────────────────────────────
function cleanUser(u) {
  if (!u) return u;
  const { _id, __v, _followers, password, ...r } = (u.toObject ? u.toObject() : u);
  return r;
}
function cleanTrack(t) {
  if (!t) return t;
  const raw = t.toObject ? t.toObject() : t;
  const { _id, __v, _likedBy, _repostedBy, audioUrl, ...r } = raw;
  if (r.comments) r.comments = r.comments.map(c => { const { _likedBy: _cl, ...cr } = c; return cr; });
  return r;
}
function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// ── Unified DB interface ──────────────────────────────────────────────────────
const db = {
  async getAllUsers() {
    if (useMongo) return (await UserModel.find({}).lean()).map(cleanUser);
    return fileDb.users.map(u => cleanUser(u));
  },
  async findUserByEmail(email) {
    const el = email.trim().toLowerCase();
    if (useMongo) { const u = await UserModel.findOne({ email: el }).lean(); return u ? cleanUser(u) : null; }
    return cleanUser(fileDb.users.find(u => (u.email||'').trim().toLowerCase() === el)) || null;
  },
  async findUserByName(name) {
    const nl = name.trim().toLowerCase();
    if (useMongo) {
      const u = await UserModel.findOne({ name: { $regex: new RegExp(`^${escapeRegex(nl)}$`, 'i') } }).lean();
      return u ? cleanUser(u) : null;
    }
    return cleanUser(fileDb.users.find(u => (u.name||'').trim().toLowerCase() === nl)) || null;
  },
  async findUserById(id) {
    if (useMongo) { const u = await UserModel.findOne({ id }).lean(); return u ? cleanUser(u) : null; }
    return cleanUser(fileDb.users.find(u => u.id === id)) || null;
  },
  async createUser(user) {
    if (useMongo) {
      try {
        const doc = await UserModel.create({ ...user, email: user.email.trim().toLowerCase() });
        return cleanUser(doc.toObject());
      } catch (e) {
        if (e.code === 11000) throw new Error('duplicate');
        throw e;
      }
    }
    const u = { ...user, email: user.email.trim().toLowerCase() };
    fileDb.users.push(u); scheduleFileSave(); return cleanUser(u);
  },
  async updateUser(id, updates) {
    if (useMongo) {
      const doc = await UserModel.findOneAndUpdate({ id }, updates, { new: true }).lean();
      return doc ? cleanUser(doc) : null;
    }
    const idx = fileDb.users.findIndex(u => u.id === id);
    if (idx !== -1) { fileDb.users[idx] = { ...fileDb.users[idx], ...updates }; scheduleFileSave(); return cleanUser(fileDb.users[idx]); }
    return null;
  },
  async getAllTracks() {
    if (useMongo) return (await TrackModel.find({}).sort({ createdAt: -1 }).lean()).map(cleanTrack);
    return fileDb.tracks.map(t => cleanTrack(t));
  },
  async findTrackById(id) {
    if (useMongo) { const t = await TrackModel.findOne({ id }).lean(); return t ? cleanTrack(t) : null; }
    return cleanTrack(fileDb.tracks.find(t => t.id === id)) || null;
  },
  async createTrack(track) {
    const { audioUrl: _a, ...rest } = track;
    if (useMongo) {
      try {
        const doc = await TrackModel.create(rest);
        return cleanTrack(doc.toObject());
      } catch (e) {
        if (e.code === 11000) return null; // duplicate
        throw e;
      }
    }
    fileDb.tracks.unshift(rest); scheduleFileSave(); return cleanTrack(rest);
  },
  async updateTrack(id, updates) {
    if (useMongo) {
      const doc = await TrackModel.findOneAndUpdate({ id }, updates, { new: true }).lean();
      return doc ? cleanTrack(doc) : null;
    }
    const idx = fileDb.tracks.findIndex(t => t.id === id);
    if (idx !== -1) { fileDb.tracks[idx] = { ...fileDb.tracks[idx], ...updates }; scheduleFileSave(); return cleanTrack(fileDb.tracks[idx]); }
    return null;
  },
  async deleteTrack(id) {
    if (useMongo) { await TrackModel.deleteOne({ id }); return true; }
    const idx = fileDb.tracks.findIndex(t => t.id === id);
    if (idx !== -1) { fileDb.tracks.splice(idx, 1); scheduleFileSave(); return true; }
    return false;
  },
  async likeTrack(trackId, userId) {
    if (useMongo) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      if (!t._likedBy) t._likedBy = [];
      const had = t._likedBy.includes(userId);
      if (had) { t._likedBy = t._likedBy.filter(x => x !== userId); t.likes = Math.max(0, (t.likes||0) - 1); }
      else      { t._likedBy.push(userId); t.likes = (t.likes||0) + 1; }
      await t.save(); return { track: cleanTrack(t.toObject()), toggled: !had };
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t._likedBy) t._likedBy = [];
    const had = t._likedBy.includes(userId);
    if (had) { t._likedBy = t._likedBy.filter(x => x !== userId); t.likes = Math.max(0, (t.likes||0) - 1); }
    else      { t._likedBy.push(userId); t.likes = (t.likes||0) + 1; }
    scheduleFileSave(); return { track: cleanTrack(t), toggled: !had };
  },
  async repostTrack(trackId, userId) {
    if (useMongo) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      if (!t._repostedBy) t._repostedBy = [];
      const had = t._repostedBy.includes(userId);
      if (had) { t._repostedBy = t._repostedBy.filter(x => x !== userId); t.reposts = Math.max(0, (t.reposts||0) - 1); }
      else      { t._repostedBy.push(userId); t.reposts = (t.reposts||0) + 1; }
      await t.save(); return { track: cleanTrack(t.toObject()), toggled: !had };
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t._repostedBy) t._repostedBy = [];
    const had = t._repostedBy.includes(userId);
    if (had) { t._repostedBy = t._repostedBy.filter(x => x !== userId); t.reposts = Math.max(0, (t.reposts||0) - 1); }
    else      { t._repostedBy.push(userId); t.reposts = (t.reposts||0) + 1; }
    scheduleFileSave(); return { track: cleanTrack(t), toggled: !had };
  },
  async addComment(trackId, comment) {
    if (useMongo) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      if (t.comments.some(c => c.id === comment.id)) return cleanTrack(t.toObject());
      t.comments.push(comment); await t.save(); return cleanTrack(t.toObject());
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    if (!t.comments) t.comments = [];
    if (!t.comments.some(c => c.id === comment.id)) { t.comments.push(comment); scheduleFileSave(); }
    return cleanTrack(t);
  },
  async likeComment(trackId, commentId, userId) {
    if (useMongo) {
      const t = await TrackModel.findOne({ id: trackId }); if (!t) return null;
      const c = t.comments.find(c => c.id === commentId); if (!c) return null;
      if (!c._likedBy) c._likedBy = [];
      const had = c._likedBy.includes(userId);
      if (had) { c._likedBy = c._likedBy.filter(x => x !== userId); c.likes = Math.max(0, (c.likes||0) - 1); }
      else      { c._likedBy.push(userId); c.likes = (c.likes||0) + 1; }
      await t.save(); return cleanTrack(t.toObject());
    }
    const t = fileDb.tracks.find(x => x.id === trackId); if (!t) return null;
    const c = (t.comments||[]).find(c => c.id === commentId); if (!c) return null;
    if (!c._likedBy) c._likedBy = [];
    const had = c._likedBy.includes(userId);
    if (had) { c._likedBy = c._likedBy.filter(x => x !== userId); c.likes = Math.max(0, (c.likes||0) - 1); }
    else      { c._likedBy.push(userId); c.likes = (c.likes||0) + 1; }
    scheduleFileSave(); return cleanTrack(t);
  },
  async incrementPlays(trackId) {
    if (useMongo) {
      await TrackModel.updateOne({ id: trackId }, { $inc: { plays: 1 } });
      const t = await TrackModel.findOne({ id: trackId }).lean();
      return t ? cleanTrack(t) : null;
    }
    const t = fileDb.tracks.find(x => x.id === trackId);
    if (t) { t.plays = (t.plays||0) + 1; scheduleFileSave(); }
    return t ? cleanTrack(t) : null;
  },
  async followUser(targetId, followerId) {
    if (useMongo) {
      const target = await UserModel.findOne({ id: targetId }); if (!target) return null;
      if (!target._followers) target._followers = [];
      const had = target._followers.includes(followerId);
      if (had) { target._followers = target._followers.filter(x => x !== followerId); target.followers = Math.max(0, (target.followers||0) - 1); }
      else      { target._followers.push(followerId); target.followers = (target.followers||0) + 1; }
      await target.save(); return { user: cleanUser(target.toObject()), toggled: !had };
    }
    const target = fileDb.users.find(u => u.id === targetId); if (!target) return null;
    if (!target._followers) target._followers = [];
    const had = target._followers.includes(followerId);
    if (had) { target._followers = target._followers.filter(x => x !== followerId); target.followers = Math.max(0, (target.followers||0) - 1); }
    else      { target._followers.push(followerId); target.followers = (target.followers||0) + 1; }
    scheduleFileSave(); return { user: cleanUser(target), toggled: !had };
  },
};

// ── Audio / Cover storage ─────────────────────────────────────────────────────
function saveAudio(trackId, base64Data) {
  try {
    const idx = base64Data.indexOf(',');
    const b64 = idx !== -1 ? base64Data.slice(idx + 1) : base64Data;
    const buf = Buffer.from(b64, 'base64');
    writeFileSync(join(AUDIO_DIR, `${trackId}.bin`), buf);
    console.log(`[Audio] Saved ${trackId} (${(buf.length/1024).toFixed(0)} KB)`);
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
  try { const f = join(AUDIO_DIR, `${trackId}.bin`); if (existsSync(f)) unlinkSync(f); } catch {}
}
function deleteCover(trackId) {
  try { const f = join(COVERS_DIR, `${trackId}.bin`); if (existsSync(f)) unlinkSync(f); } catch {}
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────
function readBody(req, maxBytes = 150 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = []; let total = 0;
    req.on('data', chunk => {
      total += chunk.length;
      if (total > maxBytes) { req.destroy(); return reject(new Error('Too large')); }
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
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}
function mkNotif(type, text, icon = '🔔', trackId = null) {
  return { id: 'n' + Date.now() + Math.random().toString(36).slice(2), type, text, icon, ts: Date.now(), trackId };
}

// ── WebSocket helpers ─────────────────────────────────────────────────────────
const clientMap = new Map(); // ws → userId
function sendWs(ws, data) {
  try { if (ws.readyState === 1) ws.send(JSON.stringify(data)); } catch {}
}
function broadcast(data, except = null) {
  const msg = JSON.stringify(data);
  for (const c of wss.clients)
    if (c !== except && c.readyState === 1)
      try { c.send(msg); } catch {}
}
function notifyUser(uid, notif) {
  for (const [ws, id] of clientMap)
    if (id === uid && ws.readyState === 1)
      try { ws.send(JSON.stringify({ type: 'NOTIFICATION', notification: notif })); } catch {}
}

// ══════════════════════════════════════════════════════════════════════════════
// HTTP SERVER
// ══════════════════════════════════════════════════════════════════════════════
const http = createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Key');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const ip  = getIp(req);
  const url = req.url.split('?')[0];
  const method = req.method;

  // ── Audio streaming (Range request support) ────────────────────────────────
  if (method === 'GET' && url.startsWith('/api/audio/')) {
    const id   = decodeURIComponent(url.slice('/api/audio/'.length));
    const file = join(AUDIO_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf  = readFileSync(file);
    const range = req.headers.range;
    if (range) {
      const [s, e] = range.replace(/bytes=/, '').split('-');
      const start = parseInt(s, 10);
      const end   = e ? parseInt(e, 10) : buf.length - 1;
      const chunk = buf.slice(start, end + 1);
      res.writeHead(206, {
        'Content-Range':  `bytes ${start}-${end}/${buf.length}`,
        'Accept-Ranges':  'bytes',
        'Content-Length': chunk.length,
        'Content-Type':   'audio/mpeg',
        'Cache-Control':  'public, max-age=86400',
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
    const id   = decodeURIComponent(url.slice('/api/cover/'.length));
    const file = join(COVERS_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf  = readFileSync(file);
    res.writeHead(200, { 'Content-Type': 'image/jpeg', 'Content-Length': buf.length, 'Cache-Control': 'public, max-age=86400' });
    res.end(buf);
    return;
  }

  // ── Admin ─────────────────────────────────────────────────────────────────
  if (url === '/api/admin/stats' && method === 'GET') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, {
      tracks: tracks.length, users: users.length,
      permBans: [...permBans],
      tempBans: [...tempBans.entries()].map(([ip, u]) => ({ ip, until: u, remaining: Math.ceil((u - Date.now()) / 60_000) + 'm' })),
      db: useMongo ? 'MongoDB' : 'FileDB',
      uptime: process.uptime(),
    });
  }
  if (url.startsWith('/api/admin/ban/') && method === 'POST') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const banIp = url.slice('/api/admin/ban/'.length);
    permBans.add(banIp); saveBans();
    return jsonRes(res, 200, { ok: true });
  }
  if (url.startsWith('/api/admin/unban/') && method === 'POST') {
    if (!isAdmin(req)) return jsonRes(res, 403, { error: 'Forbidden' });
    const unIp = url.slice('/api/admin/unban/'.length);
    permBans.delete(unIp); tempBans.delete(unIp); saveBans();
    return jsonRes(res, 200, { ok: true });
  }

  // ── Bot guard for all other API ───────────────────────────────────────────
  let passed = false;
  await botGuard(req, res, () => { passed = true; });
  if (!passed) return;

  // ── Health ────────────────────────────────────────────────────────────────
  if (url === '/api/health' && method === 'GET') {
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, { ok: true, db: useMongo ? 'MongoDB' : 'FileDB', tracks: tracks.length, users: users.length, uptime: process.uptime() });
  }

  // ── State ─────────────────────────────────────────────────────────────────
  if (url === '/api/state' && method === 'GET') {
    const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
    return jsonRes(res, 200, { tracks, users, ts: Date.now() });
  }

  // ── Register ──────────────────────────────────────────────────────────────
  if (url === '/api/register' && method === 'POST') {
    if (!checkRate(ip, 'auth'))     { penalise(ip, 15, 'auth_rate');  return jsonRes(res, 429, { error: 'Слишком много попыток. Подождите 5 минут.' }); }
    if (!checkRate(ip, 'register')) { penalise(ip, 20, 'reg_rate');   return jsonRes(res, 429, { error: 'Превышен лимит регистраций (3/час).' }); }
    if ((ipAccounts.get(ip)?.size || 0) >= 3) { penalise(ip, 25, 'mass_acc'); return jsonRes(res, 429, { error: 'Слишком много аккаунтов с одного IP.' }); }

    let body; try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }

    const hp = checkHoneypot(body);
    if (!hp.ok) {
      penalise(ip, 50, `honeypot:${hp.field}`);
      return jsonRes(res, 200, { user: { id: 'fake', name: body.user?.name || 'User' } }); // fake ok
    }

    const { user } = body || {};
    if (!user?.name || !user?.email) return jsonRes(res, 400, { error: 'Имя и email обязательны' });

    if (!checkDup(user.email + user.name, ip).ok) { penalise(ip, 30, 'dup_reg'); return jsonRes(res, 429, { error: 'Подозрительная активность.' }); }

    if (await db.findUserByName(user.name)) return jsonRes(res, 409, { error: `Имя «${user.name.trim()}» уже занято` });
    if (await db.findUserByEmail(user.email)) return jsonRes(res, 409, { error: 'Email уже зарегистрирован' });

    const pub = {
      id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
      name: user.name.trim(), email: user.email.trim().toLowerCase(),
      role: user.role || 'listener', tracksCount: 0, followers: 0,
      verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
    };
    let saved;
    try { saved = await db.createUser(pub); }
    catch (e) {
      if (e.message === 'duplicate') return jsonRes(res, 409, { error: 'Email уже зарегистрирован' });
      throw e;
    }
    if (!ipAccounts.has(ip)) ipAccounts.set(ip, new Set());
    ipAccounts.get(ip).add(saved.id);
    reward(ip, 5);
    broadcast({ type: 'USER_REGISTERED', user: saved });
    return jsonRes(res, 200, { user: saved });
  }

  // ── Login ─────────────────────────────────────────────────────────────────
  if (url === '/api/login' && method === 'POST') {
    if (!checkRate(ip, 'auth')) { penalise(ip, 10, 'login_rate'); return jsonRes(res, 429, { error: 'Слишком много попыток.' }); }
    let body; try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }
    const email = (body?.email || '').trim().toLowerCase();
    if (!email) return jsonRes(res, 400, { error: 'Email обязателен' });
    const found = await db.findUserByEmail(email);
    if (!found) { penalise(ip, 3, 'login_miss'); return jsonRes(res, 404, { error: 'Аккаунт не найден' }); }
    reward(ip, 2);
    return jsonRes(res, 200, { user: found });
  }

  // ── Upload track ──────────────────────────────────────────────────────────
  if (url === '/api/track' && method === 'POST') {
    if (!checkRate(ip, 'upload')) { penalise(ip, 10, 'upload_rate'); return jsonRes(res, 429, { error: 'Превышен лимит загрузок (20/день).' }); }
    let body; try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Файл слишком большой или неверный JSON' }); }
    const { track, audioData, coverData } = body || {};
    if (!track?.id || !track?.title) return jsonRes(res, 400, { error: 'Неверные данные трека' });
    if (await db.findTrackById(track.id)) return jsonRes(res, 200, { ok: true, duplicate: true });
    if (!checkDup(track.title + track.artistId, ip).ok) { penalise(ip, 20, 'dup_track'); return jsonRes(res, 429, { error: 'Дублирование трека.' }); }

    let serverAudioUrl = null;
    if (audioData) serverAudioUrl = saveAudio(track.id, audioData);
    let serverCoverUrl = null;
    if (coverData) serverCoverUrl = saveCover(track.id, coverData);

    const toSave = { ...track, audioUrl: undefined, serverAudio: serverAudioUrl, coverImage: serverCoverUrl || track.coverImage };
    const saved  = await db.createTrack(toSave);
    if (!saved) return jsonRes(res, 200, { ok: true, duplicate: true });

    const artist = await db.findUserById(track.artistId);
    if (artist) await db.updateUser(track.artistId, { tracksCount: (artist.tracksCount || 0) + 1 });
    reward(ip, 5);
    broadcast({ type: 'TRACK_ADDED', track: saved });
    return jsonRes(res, 200, { ok: true, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
  }

  // ── Delete track ──────────────────────────────────────────────────────────
  if (method === 'DELETE' && url.startsWith('/api/track/')) {
    const tid   = url.slice('/api/track/'.length);
    const track = await db.findTrackById(tid); if (!track) return jsonRes(res, 404, { error: 'Не найден' });
    await db.deleteTrack(tid);
    const artist = await db.findUserById(track.artistId);
    if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0, (artist.tracksCount || 1) - 1) });
    deleteAudio(tid); deleteCover(tid);
    broadcast({ type: 'TRACK_DELETED', trackId: tid });
    return jsonRes(res, 200, { ok: true });
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  if (url === '/api/action' && method === 'POST') {
    let body; try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }

    switch (body?.type) {
      case 'LIKE': {
        const result = await db.likeTrack(body.trackId, body.userId); if (!result) return jsonRes(res, 404, { error: 'Трек не найден' });
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== body.userId) {
          const liker = await db.findUserById(body.userId);
          notifyUser(track.artistId, mkNotif('like', `${liker?.name||'Кто-то'} лайкнул «${track.title}»`, '❤️', body.trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true, likes: track.likes });
      }
      case 'REPOST': {
        const result = await db.repostTrack(body.trackId, body.userId); if (!result) return jsonRes(res, 404, { error: 'Трек не найден' });
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== body.userId) {
          const u = await db.findUserById(body.userId);
          notifyUser(track.artistId, mkNotif('repost', `${u?.name||'Кто-то'} сделал репост «${track.title}»`, '🔄', body.trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        return jsonRes(res, 200, { ok: true, reposts: track.reposts });
      }
      case 'COMMENT': {
        const dup = checkDup(body.comment?.text || '', ip);
        if (!dup.ok) { penalise(ip, 15, 'spam_comment'); return jsonRes(res, 429, { error: 'Спам обнаружен.' }); }
        const track = await db.addComment(body.trackId, body.comment); if (!track) return jsonRes(res, 404, { error: 'Трек не найден' });
        broadcast({ type: 'TRACK_UPDATED', track });
        if (track.artistId && track.artistId !== body.comment.userId) {
          const prev = (body.comment.text||'').slice(0, 40) + ((body.comment.text||'').length > 40 ? '…' : '');
          notifyUser(track.artistId, mkNotif('comment', `${body.comment.userName}: "${prev}"`, '💬', body.trackId));
        }
        if (body.comment.replyTo?.id) {
          const parent = (track.comments||[]).find(c => c.id === body.comment.replyTo.id);
          if (parent && parent.userId !== body.comment.userId)
            notifyUser(parent.userId, mkNotif('reply', `${body.comment.userName} ответил тебе`, '↩️', body.trackId));
        }
        return jsonRes(res, 200, { ok: true, comments: track.comments });
      }
      case 'COMMENT_LIKE': {
        const track = await db.likeComment(body.trackId, body.commentId, body.userId);
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
        const result = await db.followUser(body.targetId, body.followerId); if (!result) return jsonRes(res, 404, { error: 'Пользователь не найден' });
        const { user } = result;
        if (result.toggled) {
          const f = await db.findUserById(body.followerId);
          notifyUser(body.targetId, mkNotif('follow', `${f?.name||'Кто-то'} подписался на тебя`, '👤'));
        }
        broadcast({ type: 'USER_UPDATED', user });
        return jsonRes(res, 200, { ok: true, followers: user.followers });
      }
      case 'DELETE_TRACK': {
        const track = await db.findTrackById(body.trackId); if (!track) return jsonRes(res, 404, { error: 'Трек не найден' });
        if (track.artistId !== body.userId) return jsonRes(res, 403, { error: 'Нет прав' });
        await db.deleteTrack(body.trackId);
        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0, (artist.tracksCount||1) - 1) });
        deleteAudio(body.trackId); deleteCover(body.trackId);
        broadcast({ type: 'TRACK_DELETED', trackId: body.trackId });
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
// WEBSOCKET SERVER
// ══════════════════════════════════════════════════════════════════════════════
const wss = new WebSocketServer({ server: http });

wss.on('connection', (ws, req) => {
  const ip = getIp(req);

  // Ban check
  const ban = isBanned(ip);
  if (ban.banned) { ws.close(1008, 'Banned'); return; }

  // Rate limit WS connections
  if (!checkRate(ip, 'ws_connect')) { penalise(ip, 15, 'ws_flood'); ws.close(1008, 'Too many connections'); return; }

  // UA check
  const ua = req.headers['user-agent'] || '';
  const ur = checkUA(ua);
  if (!ur.ok) { penalise(ip, 20, `ws_ua:${ur.reason}`); ws.close(1008, 'Bot'); return; }

  // Track connections per IP
  if (!wsConns.has(ip)) wsConns.set(ip, new Set());
  wsConns.get(ip).add(ws);
  if (wsConns.get(ip).size > 5) {
    penalise(ip, 20, 'ws_too_many');
    ws.close(1008, 'Too many connections from your IP');
    wsConns.get(ip).delete(ws);
    return;
  }

  clientMap.set(ws, null);

  ws.on('message', async (raw) => {
    if (!checkRate(ip, 'ws_msg')) { penalise(ip, 5, 'ws_msg_flood'); sendWs(ws, { type: 'ERROR', message: 'Слишком много сообщений.' }); return; }
    if (raw.length > 160 * 1024 * 1024) { penalise(ip, 10, 'ws_large'); return; }

    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }

    switch (msg.type) {
      case 'INIT': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        const [tracks, users] = await Promise.all([db.getAllTracks(), db.getAllUsers()]);
        sendWs(ws, { type: 'STATE', tracks, users });
        break;
      }
      case 'IDENTIFY': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        break;
      }
      case 'REGISTER': {
        const { user } = msg;
        if (!user?.name || !user?.email) { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Имя и email обязательны' }); break; }
        if (!checkRate(ip, 'register')) { penalise(ip, 20, 'ws_reg_rate'); sendWs(ws, { type: 'REGISTER_ERROR', message: 'Превышен лимит регистраций (3/час).' }); break; }
        if ((ipAccounts.get(ip)?.size || 0) >= 3) { penalise(ip, 25, 'ws_mass_acc'); sendWs(ws, { type: 'REGISTER_ERROR', message: 'Слишком много аккаунтов с одного IP.' }); break; }

        if (await db.findUserByName(user.name)) { sendWs(ws, { type: 'REGISTER_ERROR', message: `Имя «${user.name.trim()}» уже занято` }); break; }
        if (await db.findUserByEmail(user.email)) { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Email уже зарегистрирован' }); break; }

        const pub = {
          id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
          name: user.name.trim(), email: user.email.trim().toLowerCase(),
          role: user.role || 'listener', tracksCount: 0, followers: 0,
          verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
        };
        let saved;
        try { saved = await db.createUser(pub); }
        catch (e) {
          if (e.message === 'duplicate') { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Email уже зарегистрирован' }); break; }
          throw e;
        }
        if (!ipAccounts.has(ip)) ipAccounts.set(ip, new Set());
        ipAccounts.get(ip).add(saved.id);
        clientMap.set(ws, saved.id);
        reward(ip, 5);
        sendWs(ws, { type: 'REGISTER_OK', user: saved });
        broadcast({ type: 'USER_REGISTERED', user: saved }, ws);
        break;
      }
      case 'LOGIN': {
        if (!checkRate(ip, 'auth')) { penalise(ip, 10, 'ws_login_rate'); sendWs(ws, { type: 'LOGIN_ERROR', message: 'Слишком много попыток.' }); break; }
        const el    = (msg.email || '').trim().toLowerCase();
        const found = await db.findUserByEmail(el);
        if (found) { clientMap.set(ws, found.id); reward(ip, 2); sendWs(ws, { type: 'LOGIN_OK', user: found }); }
        else        { penalise(ip, 3, 'ws_login_miss'); sendWs(ws, { type: 'LOGIN_ERROR', message: 'Аккаунт не найден' }); }
        break;
      }
      case 'UPLOAD_TRACK': {
        if (!checkRate(ip, 'upload')) { penalise(ip, 10, 'ws_upload_rate'); sendWs(ws, { type: 'ERROR', message: 'Превышен лимит загрузок.' }); break; }
        const { track, audioData, coverData } = msg;
        if (!track?.id || !track?.title) break;
        if (await db.findTrackById(track.id)) { sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, duplicate: true }); break; }

        const dup = checkDup(track.title + track.artistId, ip);
        if (!dup.ok) { penalise(ip, 20, 'ws_dup_track'); sendWs(ws, { type: 'ERROR', message: 'Дублирование трека.' }); break; }

        let serverAudioUrl = null; if (audioData) serverAudioUrl = saveAudio(track.id, audioData);
        let serverCoverUrl = null; if (coverData) serverCoverUrl = saveCover(track.id, coverData);

        const toSave = { ...track, audioUrl: undefined, serverAudio: serverAudioUrl, coverImage: serverCoverUrl || track.coverImage };
        const saved  = await db.createTrack(toSave);
        if (!saved) { sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, duplicate: true }); break; }

        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: (artist.tracksCount || 0) + 1 });
        reward(ip, 5);
        broadcast({ type: 'TRACK_ADDED', track: saved });
        sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
        break;
      }
      case 'DELETE_TRACK': {
        const track = await db.findTrackById(msg.trackId);
        if (!track || track.artistId !== msg.userId) break;
        await db.deleteTrack(msg.trackId);
        const artist = await db.findUserById(track.artistId);
        if (artist) await db.updateUser(track.artistId, { tracksCount: Math.max(0, (artist.tracksCount||1) - 1) });
        deleteAudio(msg.trackId); deleteCover(msg.trackId);
        broadcast({ type: 'TRACK_DELETED', trackId: msg.trackId });
        break;
      }
      case 'LIKE': {
        const result = await db.likeTrack(msg.trackId, msg.userId); if (!result) break;
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== msg.userId) {
          const liker = await db.findUserById(msg.userId);
          notifyUser(track.artistId, mkNotif('like', `${liker?.name||'Кто-то'} лайкнул «${track.title}»`, '❤️', msg.trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'REPOST': {
        const result = await db.repostTrack(msg.trackId, msg.userId); if (!result) break;
        const { track } = result;
        if (result.toggled && track.artistId && track.artistId !== msg.userId) {
          const u = await db.findUserById(msg.userId);
          notifyUser(track.artistId, mkNotif('repost', `${u?.name||'Кто-то'} сделал репост «${track.title}»`, '🔄', msg.trackId));
        }
        broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'COMMENT': {
        const dup = checkDup(msg.comment?.text || '', ip);
        if (!dup.ok) { penalise(ip, 15, 'ws_spam'); break; }
        const track = await db.addComment(msg.trackId, msg.comment); if (!track) break;
        broadcast({ type: 'TRACK_UPDATED', track });
        if (track.artistId && track.artistId !== msg.comment.userId) {
          const prev = (msg.comment.text||'').slice(0, 40) + ((msg.comment.text||'').length > 40 ? '…' : '');
          notifyUser(track.artistId, mkNotif('comment', `${msg.comment.userName}: "${prev}"`, '💬', msg.trackId));
        }
        if (msg.comment.replyTo?.id) {
          const parent = (track.comments||[]).find(c => c.id === msg.comment.replyTo.id);
          if (parent && parent.userId !== msg.comment.userId)
            notifyUser(parent.userId, mkNotif('reply', `${msg.comment.userName} ответил тебе`, '↩️', msg.trackId));
        }
        break;
      }
      case 'COMMENT_LIKE': {
        const track = await db.likeComment(msg.trackId, msg.commentId, msg.userId);
        if (track) broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'PLAY': {
        const track = await db.incrementPlays(msg.trackId);
        if (track) broadcast({ type: 'TRACK_UPDATED', track });
        break;
      }
      case 'FOLLOW': {
        const result = await db.followUser(msg.targetId, msg.followerId); if (!result) break;
        const { user } = result;
        if (result.toggled) {
          const f = await db.findUserById(msg.followerId);
          notifyUser(msg.targetId, mkNotif('follow', `${f?.name||'Кто-то'} подписался на тебя`, '👤'));
        }
        broadcast({ type: 'USER_UPDATED', user });
        break;
      }
      default: break;
    }
  });

  ws.on('close', () => {
    clientMap.delete(ws);
    if (wsConns.has(ip)) { wsConns.get(ip).delete(ws); if (wsConns.get(ip).size === 0) wsConns.delete(ip); }
  });
  ws.on('error', err => console.error('[WS]', err.message));
});

// ══════════════════════════════════════════════════════════════════════════════
// STARTUP
// ══════════════════════════════════════════════════════════════════════════════
async function start() {
  useMongo = await initMongo();
  if (!useMongo) {
    console.log(`[DB] FileDB → ${fileDb.tracks.length} tracks, ${fileDb.users.length} users`);
  }

  http.listen(PORT, HOST, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║       ClaudMusic  🎵  Server Ready               ║
╠══════════════════════════════════════════════════╣
║  URL:  http://localhost:${String(PORT).padEnd(26)}║
║  DB:   ${(useMongo ? '✅ MongoDB (persistent)' : '📁 FileDB → data/db.json').padEnd(43)}║
║  Bot:  🛡️  10-layer protection ACTIVE           ║
╚══════════════════════════════════════════════════╝

${useMongo ? '' : `⚠️  No MongoDB. Treки НЕ сохраняются между деплоями.
   Добавь переменную MONGO_URL для постоянного хранения.
   MongoDB Atlas FREE: https://mongodb.com/atlas
`}
 Запуск: npm start  →  http://localhost:${PORT}
    `);
  });
}

function shutdown(sig) {
  console.log(`\n[${sig}] Shutting down...`);
  if (saveTimer) { clearTimeout(saveTimer); flushFileSave(); }
  if (!useMongo) flushFileSave();
  saveBans();
  if (mongoose) mongoose.connection.close().catch(() => {});
  http.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

start().catch(err => { console.error('Fatal:', err); process.exit(1); });
