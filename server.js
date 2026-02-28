'use strict';
const express    = require('express');
const { createServer } = require('http');
const WebSocket  = require('ws');
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const Database   = require('better-sqlite3');
const path       = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'nexus_super_secret_2024_change_me';
const PORT       = process.env.PORT || 3000;

// ══════════════════════════════════════════════════════════════════
//  DATABASE
// ══════════════════════════════════════════════════════════════════
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'nexus.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    display_name  TEXT    NOT NULL,
    avatar_color  TEXT    DEFAULT '#5C5FEF',
    bio           TEXT    DEFAULT '',
    last_seen     INTEGER DEFAULT (unixepoch()),
    created_at    INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         TEXT    NOT NULL CHECK(type IN ('direct','group')),
    name         TEXT,
    avatar_color TEXT    DEFAULT '#5C5FEF',
    created_by   INTEGER REFERENCES users(id),
    created_at   INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id   INTEGER REFERENCES chats(id) ON DELETE CASCADE,
    user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT    DEFAULT 'member' CHECK(role IN ('admin','member')),
    joined_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id    INTEGER REFERENCES chats(id)  ON DELETE CASCADE,
    sender_id  INTEGER REFERENCES users(id),
    content    TEXT    NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    edited_at  INTEGER,
    deleted    INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS message_reads (
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    user_id    INTEGER REFERENCES users(id)    ON DELETE CASCADE,
    read_at    INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (message_id, user_id)
  );

  CREATE INDEX IF NOT EXISTS idx_msg_chat   ON messages(chat_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_cm_user    ON chat_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_mr_msg     ON message_reads(message_id);
`);

// ══════════════════════════════════════════════════════════════════
//  PREPARED STATEMENTS
// ══════════════════════════════════════════════════════════════════
const Q = {
  userByName : db.prepare('SELECT * FROM users WHERE LOWER(username)=LOWER(?)'),
  userById   : db.prepare('SELECT id,username,display_name,avatar_color,bio,last_seen FROM users WHERE id=?'),
  createUser : db.prepare('INSERT INTO users (username,password_hash,display_name,avatar_color) VALUES (?,?,?,?)'),
  searchUsers: db.prepare('SELECT id,username,display_name,avatar_color FROM users WHERE LOWER(username) LIKE LOWER(?) AND id!=? LIMIT 12'),
  updateSeen : db.prepare('UPDATE users SET last_seen=unixepoch() WHERE id=?'),

  userChats: db.prepare(`
    SELECT c.*,
      lm.content      AS last_message,
      lm.created_at   AS last_message_at,
      lm.sender_id    AS last_sender_id,
      lu.display_name AS last_sender_name,
      (SELECT COUNT(*) FROM messages mx
       LEFT JOIN message_reads mr ON mx.id=mr.message_id AND mr.user_id=?
       WHERE mx.chat_id=c.id AND mx.sender_id!=? AND mx.deleted=0 AND mr.message_id IS NULL
      ) AS unread
    FROM chats c
    JOIN chat_members cm ON c.id=cm.chat_id AND cm.user_id=?
    LEFT JOIN messages lm ON lm.id=(
      SELECT id FROM messages WHERE chat_id=c.id AND deleted=0 ORDER BY created_at DESC LIMIT 1
    )
    LEFT JOIN users lu ON lm.sender_id=lu.id
    ORDER BY COALESCE(lm.created_at, c.created_at) DESC
  `),

  directBetween: db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members a ON c.id=a.chat_id AND a.user_id=?
    JOIN chat_members b ON c.id=b.chat_id AND b.user_id=?
    WHERE c.type='direct' LIMIT 1
  `),

  chatById   : db.prepare('SELECT * FROM chats WHERE id=?'),
  createChat : db.prepare('INSERT INTO chats (type,name,avatar_color,created_by) VALUES (?,?,?,?)'),
  addMember  : db.prepare('INSERT OR IGNORE INTO chat_members (chat_id,user_id,role) VALUES (?,?,?)'),
  isMember   : db.prepare('SELECT 1 FROM chat_members WHERE chat_id=? AND user_id=?'),
  members    : db.prepare(`
    SELECT u.id,u.username,u.display_name,u.avatar_color,cm.role
    FROM users u JOIN chat_members cm ON u.id=cm.user_id WHERE cm.chat_id=?
  `),
  memberIds  : db.prepare('SELECT user_id FROM chat_members WHERE chat_id=?'),

  messages: db.prepare(`
    SELECT m.*,u.username,u.display_name,u.avatar_color,
      (SELECT COUNT(*) FROM message_reads WHERE message_id=m.id) AS read_count
    FROM messages m JOIN users u ON m.sender_id=u.id
    WHERE m.chat_id=? AND m.deleted=0 AND m.id < ?
    ORDER BY m.created_at DESC LIMIT ?
  `),

  insertMsg  : db.prepare('INSERT INTO messages (chat_id,sender_id,content) VALUES (?,?,?)'),
  msgById    : db.prepare(`
    SELECT m.*,u.username,u.display_name,u.avatar_color,0 AS read_count
    FROM messages m JOIN users u ON m.sender_id=u.id WHERE m.id=?
  `),
  markRead   : db.prepare('INSERT OR IGNORE INTO message_reads (message_id,user_id) VALUES (?,?)'),
  unreadInChat: db.prepare(`
    SELECT m.id FROM messages m
    LEFT JOIN message_reads mr ON m.id=mr.message_id AND mr.user_id=?
    WHERE m.chat_id=? AND m.sender_id!=? AND m.deleted=0 AND mr.message_id IS NULL
  `),
  otherInDirect: db.prepare(`
    SELECT u.id,u.username,u.display_name,u.avatar_color,u.last_seen
    FROM users u JOIN chat_members cm ON u.id=cm.user_id
    WHERE cm.chat_id=? AND u.id!=? LIMIT 1
  `),
};

// ══════════════════════════════════════════════════════════════════
//  HTTP API
// ══════════════════════════════════════════════════════════════════
const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Auth middleware
const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

// AVATAR COLORS
const COLORS = ['#5C5FEF','#E84393','#00C59C','#FF6B35','#7C3AED','#0EA5E9','#F59E0B','#EF4444'];
const randColor = () => COLORS[Math.floor(Math.random() * COLORS.length)];

// POST /api/register
app.post('/api/register', (req, res) => {
  let { username, password, display_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  username = username.trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username))
    return res.status(400).json({ error: 'Username must be 3–32 chars: letters, numbers, underscores' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (Q.userByName.get(username))
    return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const r    = Q.createUser.run(username, hash, (display_name || username).trim().slice(0, 64), randColor());
  const token = jwt.sign({ id: r.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: Q.userById.get(r.lastInsertRowid) });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = Q.userByName.get(username);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: Q.userById.get(u.id) });
});

// GET /api/me
app.get('/api/me', auth, (req, res) => res.json(Q.userById.get(req.user.id)));

// GET /api/users/search?q=
app.get('/api/users/search', auth, (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json([]);
  res.json(Q.searchUsers.all(`%${q}%`, req.user.id));
});

// GET /api/chats
app.get('/api/chats', auth, (req, res) => {
  const chats = Q.userChats.all(req.user.id, req.user.id, req.user.id);
  res.json(chats.map(c => {
    if (c.type === 'direct') c.other_user = Q.otherInDirect.get(c.id, req.user.id);
    return c;
  }));
});

// POST /api/chats
app.post('/api/chats', auth, (req, res) => {
  const { type, username, name, member_ids } = req.body;

  if (type === 'direct') {
    const target = Q.userByName.get(username);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot start a chat with yourself' });

    const ex = Q.directBetween.get(req.user.id, target.id);
    if (ex) {
      const c = Q.chatById.get(ex.id);
      c.other_user = Q.otherInDirect.get(ex.id, req.user.id);
      return res.json(c);
    }

    const r = Q.createChat.run('direct', null, null, req.user.id);
    Q.addMember.run(r.lastInsertRowid, req.user.id, 'member');
    Q.addMember.run(r.lastInsertRowid, target.id,  'member');
    const c = Q.chatById.get(r.lastInsertRowid);
    c.other_user = Q.userById.get(target.id);
    return res.json(c);
  }

  if (type === 'group') {
    if (!name?.trim()) return res.status(400).json({ error: 'Group name required' });
    const r = Q.createChat.run('group', name.trim().slice(0, 64), randColor(), req.user.id);
    Q.addMember.run(r.lastInsertRowid, req.user.id, 'admin');
    if (Array.isArray(member_ids)) {
      for (const mid of member_ids) Q.addMember.run(r.lastInsertRowid, mid, 'member');
    }
    return res.json(Q.chatById.get(r.lastInsertRowid));
  }

  res.status(400).json({ error: 'Invalid type' });
});

// GET /api/chats/:id/messages
app.get('/api/chats/:id/messages', auth, (req, res) => {
  const cid = parseInt(req.params.id);
  if (!Q.isMember.get(cid, req.user.id)) return res.status(403).json({ error: 'Not a member' });

  const before = parseInt(req.query.before) || 2147483647;
  const limit  = Math.min(parseInt(req.query.limit) || 50, 100);
  const msgs   = Q.messages.all(cid, before, limit).reverse();

  // mark as read
  for (const m of Q.unreadInChat.all(req.user.id, cid, req.user.id)) {
    Q.markRead.run(m.id, req.user.id);
  }
  res.json(msgs);
});

// GET /api/chats/:id/members
app.get('/api/chats/:id/members', auth, (req, res) => {
  const cid = parseInt(req.params.id);
  if (!Q.isMember.get(cid, req.user.id)) return res.status(403).json({ error: 'Not a member' });
  res.json(Q.members.all(cid));
});

// ══════════════════════════════════════════════════════════════════
//  WEBSOCKET
// ══════════════════════════════════════════════════════════════════
const server = createServer(app);
const wss    = new WebSocket.Server({ server });

/** userId → Set<WebSocket> */
const clients = new Map();
/** `${chatId}:${userId}` → timeout */
const typingTimers = new Map();

function memberIds(chatId) {
  return Q.memberIds.all(chatId).map(r => r.user_id);
}

function send(ws, data) {
  if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data));
}

function sendUser(uid, data) {
  clients.get(uid)?.forEach(ws => send(ws, data));
}

function broadcast(uids, data, skip = null) {
  const raw = JSON.stringify(data);
  for (const uid of uids) {
    if (uid === skip) continue;
    clients.get(uid)?.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(raw));
  }
}

function getContacts(userId) {
  const rows = db.prepare('SELECT DISTINCT chat_id FROM chat_members WHERE user_id=?').all(userId);
  const set  = new Set();
  for (const { chat_id } of rows) {
    memberIds(chat_id).forEach(id => id !== userId && set.add(id));
  }
  return [...set];
}

wss.on('connection', ws => {
  let uid = null;

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── AUTH ──────────────────────────────────────────────────────
    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        uid = payload.id;
        if (!clients.has(uid)) clients.set(uid, new Set());
        clients.get(uid).add(ws);
        Q.updateSeen.run(uid);
        send(ws, { type: 'auth_ok', user_id: uid });
        broadcast(getContacts(uid), { type: 'user_online', user_id: uid });
      } catch { send(ws, { type: 'auth_fail', error: 'Invalid token' }); }
      return;
    }

    if (!uid) return;

    // ── SEND MESSAGE ──────────────────────────────────────────────
    if (msg.type === 'send_message') {
      const { chat_id, content, temp_id } = msg;
      if (!content?.trim() || !chat_id) return;
      if (!Q.isMember.get(chat_id, uid)) return;

      const r   = Q.insertMsg.run(chat_id, uid, content.trim().slice(0, 8000));
      const message = Q.msgById.get(r.lastInsertRowid);
      Q.markRead.run(message.id, uid); // sender's own read

      sendUser(uid, { type: 'message_sent', temp_id, message });
      broadcast(memberIds(chat_id), { type: 'new_message', message }, uid);
    }

    // ── TYPING ────────────────────────────────────────────────────
    else if (msg.type === 'typing') {
      const { chat_id } = msg;
      if (!Q.isMember.get(chat_id, uid)) return;
      const key = `${chat_id}:${uid}`;
      if (!typingTimers.has(key)) {
        const user = Q.userById.get(uid);
        broadcast(memberIds(chat_id), { type: 'typing', chat_id, user_id: uid, name: user.display_name }, uid);
      }
      clearTimeout(typingTimers.get(key));
      typingTimers.set(key, setTimeout(() => {
        typingTimers.delete(key);
        broadcast(memberIds(chat_id), { type: 'stop_typing', chat_id, user_id: uid }, uid);
      }, 3500));
    }

    // ── MARK READ ─────────────────────────────────────────────────
    else if (msg.type === 'mark_read') {
      const { chat_id } = msg;
      if (!Q.isMember.get(chat_id, uid)) return;
      const unread = Q.unreadInChat.all(uid, chat_id, uid);
      for (const m of unread) Q.markRead.run(m.id, uid);
      if (unread.length > 0) {
        broadcast(memberIds(chat_id),
          { type: 'messages_read', chat_id, user_id: uid, ids: unread.map(m => m.id) });
      }
    }
  });

  ws.on('close', () => {
    if (!uid) return;
    clients.get(uid)?.delete(ws);
    if (!clients.get(uid)?.size) {
      clients.delete(uid);
      Q.updateSeen.run(uid);
      broadcast(getContacts(uid), { type: 'user_offline', user_id: uid, last_seen: Math.floor(Date.now() / 1000) });
    }
  });

  ws.on('error', () => {});
});

// ══════════════════════════════════════════════════════════════════
//  START
// ══════════════════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log('');
  console.log('  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗');
  console.log('  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝');
  console.log('  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗');
  console.log('  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║');
  console.log('  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║');
  console.log('  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝');
  console.log('');
  console.log(`  🔗  Messenger is running → http://localhost:${PORT}`);
  console.log('');
});
