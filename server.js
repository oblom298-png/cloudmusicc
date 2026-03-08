/**
 * ClaudMusic — Railway Server
 * node server.js
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
  console.log('⚙️  Building...');
  try { execSync('npm run build', { stdio: 'inherit', cwd: __dirname }); }
  catch { console.error('❌ Build failed'); process.exit(1); }
}

// Read the single HTML file once
const HTML = readFileSync(DIST);

// ── Persistence ───────────────────────────────────────────────────────────────
const DATA_DIR = join(__dirname, 'data');
const DB_FILE  = join(DATA_DIR, 'db.json');
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

const EMPTY_DB = { tracks: [], users: [] };

function loadDb() {
  try {
    if (existsSync(DB_FILE)) {
      const p = JSON.parse(readFileSync(DB_FILE, 'utf-8'));
      return {
        tracks: Array.isArray(p.tracks) ? p.tracks : [],
        users:  Array.isArray(p.users)  ? p.users  : [],
      };
    }
  } catch (e) { console.error('[DB] load error:', e.message); }
  return { ...EMPTY_DB };
}

function saveDb() {
  try { writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
  catch (e) { console.error('[DB] save error:', e.message); }
}

const db = loadDb();
console.log(`[DB] ${db.tracks.length} tracks, ${db.users.length} users`);

// ── HTTP server ───────────────────────────────────────────────────────────────
const http = createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── /api/health ─────────────────────────────────────────────────────────
  if (req.url === '/api/health' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, tracks: db.tracks.length, users: db.users.length }));
    return;
  }

  // ── /api/state ──────────────────────────────────────────────────────────
  if (req.url === '/api/state' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    // Strip large audio blobs (not stored server-side), keep coverImage
    const tracks = db.tracks.map(t => ({ ...t, audioUrl: undefined }));
    res.end(JSON.stringify({ tracks, users: db.users, ts: Date.now() }));
    return;
  }

  // ── All other requests → index.html (SPA) ───────────────────────────────
  res.writeHead(200, {
    'Content-Type':  'text/html; charset=utf-8',
    'Cache-Control': 'no-cache',
  });
  res.end(HTML);
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
const wss = new WebSocketServer({ server: http });
const clientMap = new Map(); // ws → userId

function send(ws, data) {
  try { if (ws.readyState === 1) ws.send(JSON.stringify(data)); } catch { /**/ }
}
function broadcast(data, except = null) {
  const msg = JSON.stringify(data);
  for (const c of wss.clients)
    if (c !== except && c.readyState === 1) try { c.send(msg); } catch { /**/ }
}
function notifyUser(uid, notif) {
  for (const [ws, id] of clientMap)
    if (id === uid && ws.readyState === 1)
      try { ws.send(JSON.stringify({ type: 'NOTIFICATION', notification: notif })); } catch { /**/ }
}
function mkNotif(type, text, icon = '🔔', trackId = null) {
  return { id: 'n' + Date.now() + Math.random().toString(36).slice(2), type, text, icon, ts: Date.now(), trackId };
}

wss.on('connection', (ws) => {
  clientMap.set(ws, null);

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }

    switch (msg.type) {

      case 'INIT': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        const tracks = db.tracks.map(t => ({ ...t, audioUrl: undefined }));
        send(ws, { type: 'STATE', tracks, users: db.users });
        break;
      }

      case 'IDENTIFY': {
        if (msg.userId) clientMap.set(ws, msg.userId);
        break;
      }

      case 'REGISTER': {
        const { user } = msg;
        if (!user?.name || !user?.email) { send(ws, { type: 'ERROR', message: 'Имя и email обязательны' }); break; }
        const nl = user.name.trim().toLowerCase();
        const el = user.email.trim().toLowerCase();
        if (db.users.some(u => u.name.trim().toLowerCase() === nl))
          { send(ws, { type: 'ERROR', message: `Имя «${user.name.trim()}» уже занято` }); break; }
        if (db.users.some(u => u.email.trim().toLowerCase() === el))
          { send(ws, { type: 'ERROR', message: 'Этот email уже зарегистрирован' }); break; }
        const pub = {
          id: user.id, name: user.name.trim(), email: el,
          role: user.role || 'listener', tracksCount: 0, followers: 0,
          verified: true, joinedAt: user.joinedAt || new Date().toLocaleDateString('ru-RU'),
        };
        db.users.push(pub);
        clientMap.set(ws, pub.id);
        saveDb();
        send(ws, { type: 'REGISTER_OK', user: pub });
        broadcast({ type: 'USER_REGISTERED', user: pub }, ws);
        break;
      }

      case 'LOGIN': {
        const el = (msg.email || '').trim().toLowerCase();
        const found = db.users.find(u => u.email.trim().toLowerCase() === el);
        if (found) { clientMap.set(ws, found.id); send(ws, { type: 'LOGIN_OK', user: found }); }
        else send(ws, { type: 'LOGIN_NOT_FOUND' });
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
        if (had) { t._likedBy = t._likedBy.filter(id => id !== userId); t.likes = Math.max(0, (t.likes||0)-1); }
        else {
          t._likedBy.push(userId); t.likes = (t.likes||0)+1;
          if (t.artistId && t.artistId !== userId) {
            const liker = db.users.find(u => u.id === userId);
            notifyUser(t.artistId, mkNotif('like', `${liker?.name||'Кто-то'} лайкнул «${t.title}»`, '❤️', trackId));
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
        if (had) { t._repostedBy = t._repostedBy.filter(id=>id!==userId); t.reposts=Math.max(0,(t.reposts||0)-1); }
        else {
          t._repostedBy.push(userId); t.reposts=(t.reposts||0)+1;
          if (t.artistId && t.artistId !== userId) {
            const u = db.users.find(u=>u.id===userId);
            notifyUser(t.artistId, mkNotif('repost', `${u?.name||'Кто-то'} сделал репост «${t.title}»`, '🔄', trackId));
          }
        }
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: { ...t, _repostedBy: undefined } });
        break;
      }

      case 'COMMENT': {
        const { trackId, comment } = msg;
        const t = db.tracks.find(x => x.id === trackId); if (!t||!comment?.id) break;
        if (!t.comments) t.comments = [];
        if (!t.comments.some(c => c.id === comment.id)) {
          t.comments.push(comment); saveDb();
          broadcast({ type: 'TRACK_UPDATED', track: t });
          if (t.artistId && t.artistId !== comment.userId) {
            const preview = comment.text.slice(0,40)+(comment.text.length>40?'…':'');
            notifyUser(t.artistId, mkNotif('comment', `${comment.userName}: "${preview}"`, '💬', trackId));
          }
          if (comment.replyTo?.id) {
            const parent = t.comments.find(c=>c.id===comment.replyTo.id);
            if (parent && parent.userId !== comment.userId)
              notifyUser(parent.userId, mkNotif('reply', `${comment.userName} ответил тебе`, '↩️', trackId));
          }
        }
        break;
      }

      case 'COMMENT_LIKE': {
        const { trackId, commentId, userId } = msg;
        const t = db.tracks.find(x=>x.id===trackId); if (!t) break;
        const c = (t.comments||[]).find(c=>c.id===commentId); if (!c) break;
        if (!c._likedBy) c._likedBy=[];
        const had=c._likedBy.includes(userId);
        if (had) { c._likedBy=c._likedBy.filter(id=>id!==userId); c.likes=Math.max(0,(c.likes||0)-1); }
        else { c._likedBy.push(userId); c.likes=(c.likes||0)+1; }
        saveDb();
        broadcast({ type: 'TRACK_UPDATED', track: t });
        break;
      }

      case 'PLAY': {
        const t = db.tracks.find(x=>x.id===msg.trackId);
        if (t) { t.plays=(t.plays||0)+1; saveDb(); broadcast({ type: 'TRACK_UPDATED', track: t }); }
        break;
      }

      case 'FOLLOW': {
        const { targetId, followerId } = msg;
        const target = db.users.find(u=>u.id===targetId); if (!target) break;
        if (!target._followers) target._followers=[];
        const had=target._followers.includes(followerId);
        if (had) { target._followers=target._followers.filter(id=>id!==followerId); target.followers=Math.max(0,(target.followers||0)-1); }
        else {
          target._followers.push(followerId); target.followers=(target.followers||0)+1;
          const f=db.users.find(u=>u.id===followerId);
          notifyUser(targetId, mkNotif('follow',`${f?.name||'Кто-то'} подписался на тебя`,'👤'));
        }
        saveDb();
        broadcast({ type: 'USER_UPDATED', user: { ...target, _followers: undefined } });
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
╔══════════════════════════════════════╗
║     ClaudMusic  •  port ${String(PORT).padEnd(13)}║
║     http://localhost:${String(PORT).padEnd(16)}║
║     data/db.json  •  WebSocket ✓    ║
╚══════════════════════════════════════╝`);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
const shutdown = () => { console.log('\n[Server] Saving DB...'); saveDb(); process.exit(0); };
process.on('SIGTERM', shutdown);
process.on('SIGINT',  shutdown);
