/**
 * ClaudMusic — Server
 * Supports: Railway, Render, any Node.js host
 * Start: node server.js
 */

import { createServer }    from 'http';
import { WebSocketServer } from 'ws';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname }   from 'path';
import { fileURLToPath }   from 'url';
import { execSync }        from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = '0.0.0.0';

// ── Auto-build if dist missing ────────────────────────────────────────────────
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

// ── Persistence ───────────────────────────────────────────────────────────────
const DATA_DIR   = join(__dirname, 'data');
const DB_FILE    = join(DATA_DIR, 'db.json');
const AUDIO_DIR  = join(DATA_DIR, 'audio');
const COVERS_DIR = join(DATA_DIR, 'covers');

for (const d of [DATA_DIR, AUDIO_DIR, COVERS_DIR]) {
  if (!existsSync(d)) mkdirSync(d, { recursive: true });
}

function loadDb() {
  try {
    if (existsSync(DB_FILE)) {
      const parsed = JSON.parse(readFileSync(DB_FILE, 'utf-8'));
      return {
        tracks: Array.isArray(parsed.tracks) ? parsed.tracks : [],
        users:  Array.isArray(parsed.users)  ? parsed.users  : [],
      };
    }
  } catch (e) { console.error('[DB] Load error:', e.message); }
  return { tracks: [], users: [] };
}

function saveDb() {
  try { writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8'); }
  catch (e) { console.error('[DB] Save error:', e.message); }
}

const db = loadDb();
console.log(`[DB] ${db.tracks.length} tracks, ${db.users.length} users`);

// ── Helpers ───────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
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

// Save base64 audio to disk, return server URL
function saveAudio(trackId, base64Data) {
  try {
    // Strip data URL prefix if present: "data:audio/mp3;base64,..."
    const idx = base64Data.indexOf(',');
    const b64 = idx !== -1 ? base64Data.slice(idx + 1) : base64Data;
    const buf = Buffer.from(b64, 'base64');
    const file = join(AUDIO_DIR, `${trackId}.bin`);
    writeFileSync(file, buf);
    console.log(`[Audio] Saved ${trackId} (${(buf.length / 1024).toFixed(0)} KB)`);
    return `/api/audio/${trackId}`;
  } catch (e) {
    console.error('[Audio] Save error:', e.message);
    return null;
  }
}

// Save base64 cover to disk, return server URL
function saveCover(trackId, base64Data) {
  try {
    const idx = base64Data.indexOf(',');
    const b64 = idx !== -1 ? base64Data.slice(idx + 1) : base64Data;
    const buf = Buffer.from(b64, 'base64');
    const file = join(COVERS_DIR, `${trackId}.bin`);
    writeFileSync(file, buf);
    return `/api/cover/${trackId}`;
  } catch (e) {
    console.error('[Cover] Save error:', e.message);
    return null;
  }
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const http = createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url    = req.url.split('?')[0];
  const method = req.method;

  // ── GET /api/audio/:id ──────────────────────────────────────────────────
  if (method === 'GET' && url.startsWith('/api/audio/')) {
    const id   = url.slice('/api/audio/'.length);
    const file = join(AUDIO_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf = readFileSync(file);
    res.writeHead(200, {
      'Content-Type':   'audio/mpeg',
      'Content-Length': buf.length,
      'Accept-Ranges':  'bytes',
      'Cache-Control':  'public, max-age=86400',
    });
    res.end(buf);
    return;
  }

  // ── GET /api/cover/:id ──────────────────────────────────────────────────
  if (method === 'GET' && url.startsWith('/api/cover/')) {
    const id   = url.slice('/api/cover/'.length);
    const file = join(COVERS_DIR, `${id}.bin`);
    if (!existsSync(file)) { res.writeHead(404); res.end('Not found'); return; }
    const buf = readFileSync(file);
    res.writeHead(200, {
      'Content-Type':   'image/jpeg',
      'Content-Length': buf.length,
      'Cache-Control':  'public, max-age=86400',
    });
    res.end(buf);
    return;
  }

  // ── GET /api/health ─────────────────────────────────────────────────────
  if (url === '/api/health' && method === 'GET') {
    return jsonRes(res, 200, { ok: true, tracks: db.tracks.length, users: db.users.length, uptime: process.uptime() });
  }

  // ── GET /api/state ──────────────────────────────────────────────────────
  if (url === '/api/state' && method === 'GET') {
    // Return tracks without internal fields
    const tracks = db.tracks.map(t => ({ ...t, _likedBy: undefined, _repostedBy: undefined }));
    return jsonRes(res, 200, { tracks, users: db.users, ts: Date.now() });
  }

  // ── POST /api/register ──────────────────────────────────────────────────
  if (url === '/api/register' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }
    const { user } = body || {};
    if (!user?.name || !user?.email) return jsonRes(res, 400, { error: 'Имя и email обязательны' });

    const nl = user.name.trim().toLowerCase();
    const el = user.email.trim().toLowerCase();
    if (db.users.some(u => u.name.trim().toLowerCase() === nl))
      return jsonRes(res, 409, { error: `Имя «${user.name.trim()}» уже занято` });
    if (db.users.some(u => u.email.trim().toLowerCase() === el))
      return jsonRes(res, 409, { error: 'Этот email уже зарегистрирован' });

    const pub = {
      id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
      name: user.name.trim(), email: el,
      role: user.role || 'listener', tracksCount: 0, followers: 0,
      verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
    };
    db.users.push(pub); saveDb();
    broadcast({ type: 'USER_REGISTERED', user: pub });
    return jsonRes(res, 200, { user: pub });
  }

  // ── POST /api/login ─────────────────────────────────────────────────────
  if (url === '/api/login' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }
    const email = (body?.email || '').trim().toLowerCase();
    if (!email) return jsonRes(res, 400, { error: 'Email обязателен' });
    const found = db.users.find(u => u.email.trim().toLowerCase() === email);
    if (!found) return jsonRes(res, 404, { error: 'Аккаунт не найден' });
    return jsonRes(res, 200, { user: found });
  }

  // ── POST /api/track ─────────────────────────────────────────────────────
  if (url === '/api/track' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }
    const { track, audioData, coverData } = body || {};
    if (!track?.id || !track?.title) return jsonRes(res, 400, { error: 'Неверные данные трека' });

    if (db.tracks.some(t => t.id === track.id))
      return jsonRes(res, 200, { ok: true, duplicate: true });

    // Save audio file to disk
    let serverAudioUrl = null;
    if (audioData && typeof audioData === 'string') {
      serverAudioUrl = saveAudio(track.id, audioData);
    }

    // Save cover to disk
    let serverCoverUrl = null;
    if (coverData && typeof coverData === 'string') {
      serverCoverUrl = saveCover(track.id, coverData);
    }

    const saved = {
      ...track,
      audioUrl:    undefined,  // never store blob urls on server
      coverImage:  serverCoverUrl || track.coverImage,  // use server URL if available
      serverAudio: serverAudioUrl,  // server-side audio URL
    };
    db.tracks.unshift(saved);
    const ui = db.users.findIndex(u => u.id === track.artistId);
    if (ui !== -1) db.users[ui].tracksCount = (db.users[ui].tracksCount || 0) + 1;
    saveDb();

    // Broadcast to all connected clients (with server audio URL)
    const broadcastTrack = { ...saved };
    broadcast({ type: 'TRACK_ADDED', track: broadcastTrack });
    return jsonRes(res, 200, { ok: true, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
  }

  // ── DELETE /api/track/:id ────────────────────────────────────────────────
  if (method === 'DELETE' && url.startsWith('/api/track/')) {
    const trackId = url.slice('/api/track/'.length);
    const idx = db.tracks.findIndex(t => t.id === trackId);
    if (idx === -1) return jsonRes(res, 404, { error: 'Трек не найден' });
    const track = db.tracks[idx];
    db.tracks.splice(idx, 1);
    const ui = db.users.findIndex(u => u.id === track.artistId);
    if (ui !== -1) db.users[ui].tracksCount = Math.max(0, (db.users[ui].tracksCount || 1) - 1);
    saveDb();
    // Try to remove audio file
    try {
      const af = join(AUDIO_DIR, `${trackId}.bin`);
      if (existsSync(af)) { const { unlinkSync } = await import('fs'); unlinkSync(af); }
    } catch { /* ignore */ }
    broadcast({ type: 'TRACK_DELETED', trackId });
    return jsonRes(res, 200, { ok: true });
  }

  // ── POST /api/action ────────────────────────────────────────────────────
  if (url === '/api/action' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonRes(res, 400, { error: 'Неверный JSON' }); }

    switch (body?.type) {
      case 'LIKE': {
        const { trackId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonRes(res, 404, { error: 'Трек не найден' });
        if (!t._likedBy) t._likedBy = [];
        const had = t._likedBy.includes(userId);
        if (had) { t._likedBy = t._likedBy.filter(id => id !== userId); t.likes = Math.max(0, (t.likes || 0) - 1); }
        else {
          t._likedBy.push(userId); t.likes = (t.likes || 0) + 1;
          if (t.artistId && t.artistId !== userId) {
            const liker = db.users.find(u => u.id === userId);
            notifyUser(t.artistId, mkNotif('like', `${liker?.name || 'Кто-то'} лайкнул «${t.title}»`, '❤️', trackId));
          }
        }
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: { ...t, _likedBy: undefined } });
        return jsonRes(res, 200, { ok: true, likes: t.likes });
      }

      case 'REPOST': {
        const { trackId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonRes(res, 404, { error: 'Трек не найден' });
        if (!t._repostedBy) t._repostedBy = [];
        const had = t._repostedBy.includes(userId);
        if (had) { t._repostedBy = t._repostedBy.filter(id => id !== userId); t.reposts = Math.max(0, (t.reposts || 0) - 1); }
        else {
          t._repostedBy.push(userId); t.reposts = (t.reposts || 0) + 1;
          if (t.artistId && t.artistId !== userId) {
            const u = db.users.find(u => u.id === userId);
            notifyUser(t.artistId, mkNotif('repost', `${u?.name || 'Кто-то'} сделал репост «${t.title}»`, '🔄', trackId));
          }
        }
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: { ...t, _repostedBy: undefined } });
        return jsonRes(res, 200, { ok: true, reposts: t.reposts });
      }

      case 'COMMENT': {
        const { trackId, comment } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t || !comment?.id) return jsonRes(res, 404, { error: 'Трек не найден' });
        if (!t.comments) t.comments = [];
        if (!t.comments.some(c => c.id === comment.id)) {
          t.comments.push(comment); saveDb();
          broadcast({ type: 'TRACK_UPDATED', track: t });
          if (t.artistId && t.artistId !== comment.userId) {
            const preview = comment.text.slice(0, 40) + (comment.text.length > 40 ? '…' : '');
            notifyUser(t.artistId, mkNotif('comment', `${comment.userName}: "${preview}"`, '💬', trackId));
          }
          if (comment.replyTo?.id) {
            const parent = t.comments.find(c => c.id === comment.replyTo.id);
            if (parent && parent.userId !== comment.userId)
              notifyUser(parent.userId, mkNotif('reply', `${comment.userName} ответил тебе`, '↩️', trackId));
          }
        }
        return jsonRes(res, 200, { ok: true, comments: t.comments });
      }

      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonRes(res, 404, { error: 'Трек не найден' });
        const c = (t.comments || []).find(c => c.id === commentId);
        if (!c) return jsonRes(res, 404, { error: 'Комментарий не найден' });
        if (!c._likedBy) c._likedBy = [];
        const had = c._likedBy.includes(userId);
        if (had) { c._likedBy = c._likedBy.filter(id => id !== userId); c.likes = Math.max(0, (c.likes || 0) - 1); }
        else { c._likedBy.push(userId); c.likes = (c.likes || 0) + 1; }
        saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t });
        return jsonRes(res, 200, { ok: true });
      }

      case 'PLAY': {
        const t = db.tracks.find(x => x.id === body.trackId);
        if (t) { t.plays = (t.plays || 0) + 1; saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t }); }
        return jsonRes(res, 200, { ok: true });
      }

      case 'FOLLOW': {
        const { targetId, followerId } = body;
        const target = db.users.find(u => u.id === targetId);
        if (!target) return jsonRes(res, 404, { error: 'Пользователь не найден' });
        if (!target._followers) target._followers = [];
        const had = target._followers.includes(followerId);
        if (had) { target._followers = target._followers.filter(id => id !== followerId); target.followers = Math.max(0, (target.followers || 0) - 1); }
        else {
          target._followers.push(followerId); target.followers = (target.followers || 0) + 1;
          const f = db.users.find(u => u.id === followerId);
          notifyUser(targetId, mkNotif('follow', `${f?.name || 'Кто-то'} подписался на тебя`, '👤'));
        }
        saveDb();
        broadcast({ type: 'USER_UPDATED', user: { ...target, _followers: undefined } });
        return jsonRes(res, 200, { ok: true, followers: target.followers });
      }

      case 'DELETE_TRACK': {
        const { trackId, userId } = body;
        const idx = db.tracks.findIndex(t => t.id === trackId);
        if (idx === -1) return jsonRes(res, 404, { error: 'Трек не найден' });
        const track = db.tracks[idx];
        if (track.artistId !== userId) return jsonRes(res, 403, { error: 'Нет прав' });
        db.tracks.splice(idx, 1);
        const ui = db.users.findIndex(u => u.id === track.artistId);
        if (ui !== -1) db.users[ui].tracksCount = Math.max(0, (db.users[ui].tracksCount || 1) - 1);
        saveDb();
        broadcast({ type: 'TRACK_DELETED', trackId });
        return jsonRes(res, 200, { ok: true });
      }

      default:
        return jsonRes(res, 400, { error: 'Неизвестное действие' });
    }
  }

  // ── All other GET → index.html (SPA) ────────────────────────────────────
  if (method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
    res.end(HTML_CONTENT);
    return;
  }

  jsonRes(res, 404, { error: 'Not found' });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server: http });
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

wss.on('connection', (ws) => {
  clientMap.set(ws, null);

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    switch (msg.type) {
      case 'INIT': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        const tracks = db.tracks.map(t => ({ ...t, _likedBy: undefined, _repostedBy: undefined }));
        sendWs(ws, { type: 'STATE', tracks, users: db.users });
        break;
      }
      case 'IDENTIFY': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        break;
      }
      case 'REGISTER': {
        const { user } = msg;
        if (!user?.name || !user?.email) { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Имя и email обязательны' }); break; }
        const nl = user.name.trim().toLowerCase();
        const el = user.email.trim().toLowerCase();
        if (db.users.some(u => u.name.trim().toLowerCase() === nl))
          { sendWs(ws, { type: 'REGISTER_ERROR', message: `Имя «${user.name.trim()}» уже занято` }); break; }
        if (db.users.some(u => u.email.trim().toLowerCase() === el))
          { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Email уже зарегистрирован' }); break; }
        const pub = {
          id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
          name: user.name.trim(), email: el,
          role: user.role || 'listener', tracksCount: 0, followers: 0,
          verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
        };
        db.users.push(pub); clientMap.set(ws, pub.id); saveDb();
        sendWs(ws, { type: 'REGISTER_OK', user: pub });
        broadcast({ type: 'USER_REGISTERED', user: pub }, ws);
        break;
      }
      case 'LOGIN': {
        const el = (msg.email || '').trim().toLowerCase();
        const found = db.users.find(u => u.email.trim().toLowerCase() === el);
        if (found) { clientMap.set(ws, found.id); sendWs(ws, { type: 'LOGIN_OK', user: found }); }
        else sendWs(ws, { type: 'LOGIN_ERROR', message: 'Аккаунт не найден' });
        break;
      }
      case 'UPLOAD_TRACK': {
        const { track, audioData, coverData } = msg;
        if (!track?.id || !track?.title) break;
        if (db.tracks.some(t => t.id === track.id)) break; // deduplicate

        let serverAudioUrl = null;
        if (audioData) serverAudioUrl = saveAudio(track.id, audioData);

        let serverCoverUrl = null;
        if (coverData) serverCoverUrl = saveCover(track.id, coverData);

        const saved = {
          ...track,
          audioUrl:    undefined,
          coverImage:  serverCoverUrl || track.coverImage,
          serverAudio: serverAudioUrl,
        };
        db.tracks.unshift(saved);
        const ui = db.users.findIndex(u => u.id === track.artistId);
        if (ui !== -1) db.users[ui].tracksCount = (db.users[ui].tracksCount || 0) + 1;
        saveDb();
        broadcast({ type: 'TRACK_ADDED', track: saved });
        sendWs(ws, { type: 'UPLOAD_OK', trackId: track.id, serverAudio: serverAudioUrl, serverCover: serverCoverUrl });
        break;
      }
      case 'DELETE_TRACK': {
        const { trackId, userId } = msg;
        const idx = db.tracks.findIndex(t => t.id === trackId);
        if (idx === -1) break;
        const track = db.tracks[idx];
        if (track.artistId !== userId) break;
        db.tracks.splice(idx, 1);
        const ui = db.users.findIndex(u => u.id === track.artistId);
        if (ui !== -1) db.users[ui].tracksCount = Math.max(0, (db.users[ui].tracksCount || 1) - 1);
        saveDb();
        try {
          const af = join(AUDIO_DIR, `${trackId}.bin`);
          if (existsSync(af)) { const { unlinkSync } = await import('fs'); unlinkSync(af); }
        } catch { /**/ }
        broadcast({ type: 'TRACK_DELETED', trackId });
        break;
      }
      case 'LIKE': {
        const { trackId, userId } = msg;
        const t = db.tracks.find(x => x.id === trackId); if (!t) break;
        if (!t._likedBy) t._likedBy = [];
        const had = t._likedBy.includes(userId);
        if (had) { t._likedBy = t._likedBy.filter(id => id !== userId); t.likes = Math.max(0, (t.likes || 0) - 1); }
        else {
          t._likedBy.push(userId); t.likes = (t.likes || 0) + 1;
          if (t.artistId && t.artistId !== userId) {
            const liker = db.users.find(u => u.id === userId);
            notifyUser(t.artistId, mkNotif('like', `${liker?.name || 'Кто-то'} лайкнул «${t.title}»`, '❤️', trackId));
          }
        }
        saveDb(); broadcast({ type: 'TRACK_UPDATED', track: { ...t, _likedBy: undefined } });
        break;
      }
      case 'REPOST': {
        const { trackId, userId } = msg;
        const t = db.tracks.find(x => x.id === trackId); if (!t) break;
        if (!t._repostedBy) t._repostedBy = [];
        const had = t._repostedBy.includes(userId);
        if (had) { t._repostedBy = t._repostedBy.filter(id => id !== userId); t.reposts = Math.max(0, (t.reposts || 0) - 1); }
        else {
          t._repostedBy.push(userId); t.reposts = (t.reposts || 0) + 1;
          if (t.artistId && t.artistId !== userId) {
            const u = db.users.find(u => u.id === userId);
            notifyUser(t.artistId, mkNotif('repost', `${u?.name || 'Кто-то'} сделал репост «${t.title}»`, '🔄', trackId));
          }
        }
        saveDb(); broadcast({ type: 'TRACK_UPDATED', track: { ...t, _repostedBy: undefined } });
        break;
      }
      case 'COMMENT': {
        const { trackId, comment } = msg;
        const t = db.tracks.find(x => x.id === trackId); if (!t || !comment?.id) break;
        if (!t.comments) t.comments = [];
        if (!t.comments.some(c => c.id === comment.id)) {
          t.comments.push(comment); saveDb();
          broadcast({ type: 'TRACK_UPDATED', track: t });
          if (t.artistId && t.artistId !== comment.userId) {
            const preview = comment.text.slice(0, 40) + (comment.text.length > 40 ? '…' : '');
            notifyUser(t.artistId, mkNotif('comment', `${comment.userName}: "${preview}"`, '💬', trackId));
          }
          if (comment.replyTo?.id) {
            const parent = t.comments.find(c => c.id === comment.replyTo.id);
            if (parent && parent.userId !== comment.userId)
              notifyUser(parent.userId, mkNotif('reply', `${comment.userName} ответил тебе`, '↩️', trackId));
          }
        }
        break;
      }
      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = msg;
        const t = db.tracks.find(x => x.id === trackId); if (!t) break;
        const c = (t.comments || []).find(c => c.id === commentId); if (!c) break;
        if (!c._likedBy) c._likedBy = [];
        const had = c._likedBy.includes(userId);
        if (had) { c._likedBy = c._likedBy.filter(id => id !== userId); c.likes = Math.max(0, (c.likes || 0) - 1); }
        else { c._likedBy.push(userId); c.likes = (c.likes || 0) + 1; }
        saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t });
        break;
      }
      case 'PLAY': {
        const t = db.tracks.find(x => x.id === msg.trackId);
        if (t) { t.plays = (t.plays || 0) + 1; saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t }); }
        break;
      }
      case 'FOLLOW': {
        const { targetId, followerId } = msg;
        const target = db.users.find(u => u.id === targetId); if (!target) break;
        if (!target._followers) target._followers = [];
        const had = target._followers.includes(followerId);
        if (had) { target._followers = target._followers.filter(id => id !== followerId); target.followers = Math.max(0, (target.followers || 0) - 1); }
        else {
          target._followers.push(followerId); target.followers = (target.followers || 0) + 1;
          const f = db.users.find(u => u.id === followerId);
          notifyUser(targetId, mkNotif('follow', `${f?.name || 'Кто-то'} подписался на тебя`, '👤'));
        }
        saveDb(); broadcast({ type: 'USER_UPDATED', user: { ...target, _followers: undefined } });
        break;
      }
      default: break;
    }
  });

  ws.on('close', () => clientMap.delete(ws));
  ws.on('error', err => console.error('[WS]', err.message));
});

// ── Start ─────────────────────────────────────────────────────────────────────
http.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════╗
║        ClaudMusic  •  Ready!             ║
║                                          ║
║  Local:   http://localhost:${String(PORT).padEnd(14)}║
║  WS:      ws://localhost:${String(PORT).padEnd(16)}║
╚══════════════════════════════════════════╝
`);
});

function shutdown(sig) {
  console.log(`\n[${sig}] Saving & shutting down...`);
  saveDb();
  http.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
