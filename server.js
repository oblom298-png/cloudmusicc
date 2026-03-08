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

// Cache the single HTML file
let HTML_CONTENT;
try {
  HTML_CONTENT = readFileSync(DIST);
  console.log(`✅ dist/index.html loaded (${(HTML_CONTENT.length / 1024).toFixed(0)} KB)`);
} catch (e) {
  console.error('❌ Cannot read dist/index.html:', e.message);
  process.exit(1);
}

// ── Persistence ───────────────────────────────────────────────────────────────
const DATA_DIR = join(__dirname, 'data');
const DB_FILE  = join(DATA_DIR, 'db.json');

if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
  console.log('📁 Created data/ directory');
}

function loadDb() {
  try {
    if (existsSync(DB_FILE)) {
      const raw = readFileSync(DB_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      return {
        tracks: Array.isArray(parsed.tracks) ? parsed.tracks : [],
        users:  Array.isArray(parsed.users)  ? parsed.users  : [],
      };
    }
  } catch (e) {
    console.error('[DB] Load error:', e.message);
  }
  return { tracks: [], users: [] };
}

function saveDb() {
  try {
    writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf-8');
  } catch (e) {
    console.error('[DB] Save error:', e.message);
  }
}

const db = loadDb();
console.log(`[DB] ${db.tracks.length} tracks, ${db.users.length} users`);

// ── Helpers ───────────────────────────────────────────────────────────────────
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf-8');
        resolve(text ? JSON.parse(text) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

function jsonResponse(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type':                'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Content-Length':              Buffer.byteLength(body),
  });
  res.end(body);
}

function mkNotif(type, text, icon = '🔔', trackId = null) {
  return {
    id:      'n' + Date.now() + Math.random().toString(36).slice(2),
    type, text, icon, ts: Date.now(), trackId,
  };
}

// ── HTTP server ───────────────────────────────────────────────────────────────
const http = createServer(async (req, res) => {
  // CORS pre-flight
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url    = req.url.split('?')[0]; // strip query
  const method = req.method;

  // ── GET /api/health ─────────────────────────────────────────────────────
  if (url === '/api/health' && method === 'GET') {
    return jsonResponse(res, 200, {
      ok: true,
      tracks: db.tracks.length,
      users:  db.users.length,
      uptime: process.uptime(),
    });
  }

  // ── GET /api/state ──────────────────────────────────────────────────────
  if (url === '/api/state' && method === 'GET') {
    const tracks = db.tracks.map(t => ({ ...t, audioUrl: undefined }));
    return jsonResponse(res, 200, { tracks, users: db.users, ts: Date.now() });
  }

  // ── POST /api/register ──────────────────────────────────────────────────
  if (url === '/api/register' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonResponse(res, 400, { error: 'Неверный JSON' }); }
    const { user } = body || {};
    if (!user?.name || !user?.email) return jsonResponse(res, 400, { error: 'Имя и email обязательны' });

    const nl = user.name.trim().toLowerCase();
    const el = user.email.trim().toLowerCase();

    if (db.users.some(u => u.name.trim().toLowerCase() === nl))
      return jsonResponse(res, 409, { error: `Имя «${user.name.trim()}» уже занято` });
    if (db.users.some(u => u.email.trim().toLowerCase() === el))
      return jsonResponse(res, 409, { error: 'Этот email уже зарегистрирован' });

    const pub = {
      id:          user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
      name:        user.name.trim(),
      email:       el,
      role:        user.role || 'listener',
      tracksCount: 0,
      followers:   0,
      verified:    true,
      joinedAt:    user.joinedAt || new Date().toLocaleDateString('ru-RU'),
    };
    db.users.push(pub);
    saveDb();
    broadcast({ type: 'USER_REGISTERED', user: pub });
    return jsonResponse(res, 200, { user: pub });
  }

  // ── POST /api/login ─────────────────────────────────────────────────────
  if (url === '/api/login' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonResponse(res, 400, { error: 'Неверный JSON' }); }
    const email = (body?.email || '').trim().toLowerCase();
    if (!email) return jsonResponse(res, 400, { error: 'Email обязателен' });

    const found = db.users.find(u => u.email.trim().toLowerCase() === email);
    if (!found) return jsonResponse(res, 404, { error: 'Аккаунт не найден' });
    return jsonResponse(res, 200, { user: found });
  }

  // ── POST /api/track ─────────────────────────────────────────────────────
  if (url === '/api/track' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonResponse(res, 400, { error: 'Неверный JSON' }); }
    const { track } = body || {};
    if (!track?.id || !track?.title) return jsonResponse(res, 400, { error: 'Неверные данные трека' });

    const saved = { ...track, audioUrl: undefined };
    if (!db.tracks.some(t => t.id === saved.id)) {
      db.tracks.unshift(saved);
      const ui = db.users.findIndex(u => u.id === track.artistId);
      if (ui !== -1) db.users[ui].tracksCount = (db.users[ui].tracksCount || 0) + 1;
      saveDb();
      broadcast({ type: 'TRACK_ADDED', track: saved });
    }
    return jsonResponse(res, 200, { ok: true });
  }

  // ── POST /api/action ────────────────────────────────────────────────────
  if (url === '/api/action' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch { return jsonResponse(res, 400, { error: 'Неверный JSON' }); }

    switch (body?.type) {
      case 'LIKE': {
        const { trackId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonResponse(res, 404, { error: 'Трек не найден' });
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
        return jsonResponse(res, 200, { ok: true, likes: t.likes });
      }

      case 'REPOST': {
        const { trackId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonResponse(res, 404, { error: 'Трек не найден' });
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
        return jsonResponse(res, 200, { ok: true, reposts: t.reposts });
      }

      case 'COMMENT': {
        const { trackId, comment } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t || !comment?.id) return jsonResponse(res, 404, { error: 'Трек не найден' });
        if (!t.comments) t.comments = [];
        if (!t.comments.some(c => c.id === comment.id)) {
          t.comments.push(comment);
          saveDb();
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
        return jsonResponse(res, 200, { ok: true, comments: t.comments });
      }

      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = body;
        const t = db.tracks.find(x => x.id === trackId);
        if (!t) return jsonResponse(res, 404, { error: 'Трек не найден' });
        const c = (t.comments || []).find(c => c.id === commentId);
        if (!c) return jsonResponse(res, 404, { error: 'Комментарий не найден' });
        if (!c._likedBy) c._likedBy = [];
        const had = c._likedBy.includes(userId);
        if (had) { c._likedBy = c._likedBy.filter(id => id !== userId); c.likes = Math.max(0, (c.likes || 0) - 1); }
        else { c._likedBy.push(userId); c.likes = (c.likes || 0) + 1; }
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: t });
        return jsonResponse(res, 200, { ok: true });
      }

      case 'PLAY': {
        const t = db.tracks.find(x => x.id === body.trackId);
        if (t) { t.plays = (t.plays || 0) + 1; saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t }); }
        return jsonResponse(res, 200, { ok: true });
      }

      case 'FOLLOW': {
        const { targetId, followerId } = body;
        const target = db.users.find(u => u.id === targetId);
        if (!target) return jsonResponse(res, 404, { error: 'Пользователь не найден' });
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
        return jsonResponse(res, 200, { ok: true, followers: target.followers });
      }

      default:
        return jsonResponse(res, 400, { error: 'Неизвестное действие' });
    }
  }

  // ── All other GET → index.html (SPA) ────────────────────────────────────
  if (method === 'GET') {
    res.writeHead(200, {
      'Content-Type':  'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    });
    res.end(HTML_CONTENT);
    return;
  }

  // Unknown endpoint
  jsonResponse(res, 404, { error: 'Not found' });
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server: http });
const clientMap = new Map(); // ws → userId

function sendWs(ws, data) {
  try { if (ws.readyState === 1) ws.send(JSON.stringify(data)); } catch { /* */ }
}

function broadcast(data, except = null) {
  const msg = JSON.stringify(data);
  for (const c of wss.clients)
    if (c !== except && c.readyState === 1)
      try { c.send(msg); } catch { /* */ }
}

function notifyUser(uid, notif) {
  for (const [ws, id] of clientMap)
    if (id === uid && ws.readyState === 1)
      try { ws.send(JSON.stringify({ type: 'NOTIFICATION', notification: notif })); } catch { /* */ }
}

wss.on('connection', (ws) => {
  clientMap.set(ws, null);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    switch (msg.type) {

      case 'INIT': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        const tracks = db.tracks.map(t => ({ ...t, audioUrl: undefined }));
        sendWs(ws, { type: 'STATE', tracks, users: db.users });
        break;
      }

      case 'IDENTIFY': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        break;
      }

      case 'REGISTER': {
        const { user } = msg;
        if (!user?.name || !user?.email) { sendWs(ws, { type: 'ERROR', message: 'Имя и email обязательны' }); break; }
        const nl = user.name.trim().toLowerCase();
        const el = user.email.trim().toLowerCase();
        if (db.users.some(u => u.name.trim().toLowerCase() === nl))
          { sendWs(ws, { type: 'REGISTER_ERROR', message: `Имя «${user.name.trim()}» уже занято` }); break; }
        if (db.users.some(u => u.email.trim().toLowerCase() === el))
          { sendWs(ws, { type: 'REGISTER_ERROR', message: 'Этот email уже зарегистрирован' }); break; }
        const pub = {
          id: user.id || ('u_' + Date.now() + '_' + Math.random().toString(36).slice(2)),
          name: user.name.trim(), email: el,
          role: user.role || 'listener', tracksCount: 0, followers: 0,
          verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
        };
        db.users.push(pub);
        clientMap.set(ws, pub.id);
        saveDb();
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
        const { track } = msg;
        if (!track?.id || !track?.title) break;
        const saved = { ...track, audioUrl: undefined };
        if (!db.tracks.some(t => t.id === saved.id)) {
          db.tracks.unshift(saved);
          const ui = db.users.findIndex(u => u.id === track.artistId);
          if (ui !== -1) db.users[ui].tracksCount = (db.users[ui].tracksCount || 0) + 1;
          saveDb();
          broadcast({ type: 'TRACK_ADDED', track: saved });
        }
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
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: { ...t, _likedBy: undefined } });
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
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: { ...t, _repostedBy: undefined } });
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
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: t });
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
        saveDb();
        broadcast({ type: 'USER_UPDATED', user: { ...target, _followers: undefined } });
        break;
      }

      default: break;
    }
  });

  ws.on('close', () => clientMap.delete(ws));
  ws.on('error', err => console.error('[WS error]', err.message));
});

// ── Start ─────────────────────────────────────────────────────────────────────
http.listen(PORT, HOST, () => {
  console.log(`
╔══════════════════════════════════════════╗
║        ClaudMusic  •  Ready!             ║
║                                          ║
║  Local:   http://localhost:${String(PORT).padEnd(14)}║
║  Network: http://0.0.0.0:${String(PORT).padEnd(16)}║
║                                          ║
║  API:     /api/health                    ║
║           /api/state                     ║
║           /api/register  (POST)          ║
║           /api/login     (POST)          ║
║           /api/track     (POST)          ║
║           /api/action    (POST)          ║
║  WS:      ws://localhost:${String(PORT).padEnd(16)}║
╚══════════════════════════════════════════╝
`);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
function shutdown(signal) {
  console.log(`\n[${signal}] Saving DB and shutting down...`);
  saveDb();
  http.close(() => {
    console.log('[Server] Closed. Goodbye!');
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 3000);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
