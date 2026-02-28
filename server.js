'use strict';
const express   = require('express');
const { createServer } = require('http');
const WebSocket = require('ws');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const fs        = require('fs');
const path      = require('path');

const JWT_SECRET = process.env.JWT_SECRET || 'nexus_super_secret_2024_change_me';
const PORT       = process.env.PORT || 3000;
const DB_PATH    = process.env.DB_PATH || path.join(__dirname, 'nexus-data.json');

// ══════════════════════════════════════════════════════════════════
//  PURE-JS IN-MEMORY DATABASE  (persisted to JSON file)
//  No native addons — works on any platform without build tools
// ══════════════════════════════════════════════════════════════════
let DB = {
  users:    [],
  chats:    [],
  members:  [],
  messages: [],
  reads:    [],
  _seq:     { users: 0, chats: 0, messages: 0 }
};

function loadDB() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
      DB = raw;
      if (!DB._seq)     DB._seq = { users: 0, chats: 0, messages: 0 };
      if (!DB.reads)    DB.reads = [];
      if (!DB.members)  DB.members = [];
      DB._seq.users    = DB.users.reduce((m, u) => Math.max(m, u.id), 0);
      DB._seq.chats    = DB.chats.reduce((m, c) => Math.max(m, c.id), 0);
      DB._seq.messages = DB.messages.reduce((m, x) => Math.max(m, x.id), 0);
      console.log(`  Loaded DB: ${DB.users.length} users, ${DB.messages.length} messages`);
    }
  } catch(e) {
    console.error('DB load error, starting fresh:', e.message);
  }
}

let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DB_PATH, JSON.stringify(DB), 'utf8'); }
    catch(e) { console.error('DB save error:', e.message); }
  }, 300);
}

loadDB();

// ── Helpers ──────────────────────────────────────────────────────
const now = () => Math.floor(Date.now() / 1000);
function nextId(table) { DB._seq[table] = (DB._seq[table] || 0) + 1; return DB._seq[table]; }

// USERS
function userByName(username) {
  return DB.users.find(u => u.username.toLowerCase() === username.toLowerCase()) || null;
}
function userById(id) {
  const u = DB.users.find(u => u.id === id);
  if (!u) return null;
  return { id: u.id, username: u.username, display_name: u.display_name,
           avatar_color: u.avatar_color, bio: u.bio || '', last_seen: u.last_seen };
}
function createUser(username, hash, display_name, avatar_color) {
  const id = nextId('users');
  DB.users.push({ id, username, password_hash: hash, display_name,
                  avatar_color, bio: '', last_seen: now(), created_at: now() });
  saveDB();
  return id;
}
function updateSeen(id) {
  const u = DB.users.find(u => u.id === id);
  if (u) { u.last_seen = now(); saveDB(); }
}
function searchUsers(q, excludeId) {
  const lq = q.toLowerCase();
  return DB.users
    .filter(u => u.id !== excludeId && u.username.toLowerCase().includes(lq))
    .slice(0, 12)
    .map(u => ({ id: u.id, username: u.username, display_name: u.display_name, avatar_color: u.avatar_color }));
}

// CHATS
function chatById(id) { return DB.chats.find(c => c.id === id) || null; }
function createChat(type, name, avatar_color, created_by) {
  const id = nextId('chats');
  DB.chats.push({ id, type, name: name || null, avatar_color: avatar_color || '#5C5FEF',
                  created_by, created_at: now() });
  saveDB();
  return id;
}
function isMember(chat_id, user_id) {
  return DB.members.some(m => m.chat_id === chat_id && m.user_id === user_id);
}
function addMember(chat_id, user_id, role = 'member') {
  if (!isMember(chat_id, user_id)) {
    DB.members.push({ chat_id, user_id, role, joined_at: now() });
    saveDB();
  }
}
function getMembers(chat_id) {
  return DB.members
    .filter(m => m.chat_id === chat_id)
    .map(m => {
      const u = DB.users.find(u => u.id === m.user_id);
      if (!u) return null;
      return { id: u.id, username: u.username, display_name: u.display_name,
               avatar_color: u.avatar_color, role: m.role };
    }).filter(Boolean);
}
function getMemberIds(chat_id) {
  return DB.members.filter(m => m.chat_id === chat_id).map(m => m.user_id);
}
function directBetween(uid1, uid2) {
  const ids1 = new Set(DB.members.filter(m => m.user_id === uid1).map(m => m.chat_id));
  const ids2 = new Set(DB.members.filter(m => m.user_id === uid2).map(m => m.chat_id));
  for (const cid of ids1) {
    if (ids2.has(cid)) {
      const c = chatById(cid);
      if (c && c.type === 'direct') return c;
    }
  }
  return null;
}
function getUserChats(userId) {
  const myChatIds = DB.members.filter(m => m.user_id === userId).map(m => m.chat_id);
  return DB.chats
    .filter(c => myChatIds.includes(c.id))
    .map(c => {
      const msgs = DB.messages.filter(m => m.chat_id === c.id && !m.deleted)
                              .sort((a, b) => b.created_at - a.created_at);
      const last = msgs[0] || null;
      const unread = msgs.filter(m =>
        m.sender_id !== userId &&
        !DB.reads.some(r => r.message_id === m.id && r.user_id === userId)
      ).length;
      const obj = { ...c, unread,
        last_message:    last?.content    || null,
        last_message_at: last?.created_at || null,
        last_sender_id:  last?.sender_id  || null,
      };
      if (c.type === 'direct') {
        const om = DB.members.find(m => m.chat_id === c.id && m.user_id !== userId);
        if (om) {
          const ou = DB.users.find(u => u.id === om.user_id);
          obj.other_user = ou ? { id: ou.id, username: ou.username, display_name: ou.display_name,
                                  avatar_color: ou.avatar_color, last_seen: ou.last_seen } : null;
        }
      }
      return obj;
    })
    .sort((a, b) => (b.last_message_at || b.created_at) - (a.last_message_at || a.created_at));
}
function otherInDirect(chat_id, user_id) {
  const m = DB.members.find(m => m.chat_id === chat_id && m.user_id !== user_id);
  if (!m) return null;
  const u = DB.users.find(u => u.id === m.user_id);
  if (!u) return null;
  return { id: u.id, username: u.username, display_name: u.display_name,
           avatar_color: u.avatar_color, last_seen: u.last_seen };
}

// MESSAGES
function insertMessage(chat_id, sender_id, content) {
  const id = nextId('messages');
  DB.messages.push({ id, chat_id, sender_id, content, created_at: now(), deleted: false });
  saveDB();
  return id;
}
function getMessages(chat_id, before, limit) {
  return DB.messages
    .filter(m => m.chat_id === chat_id && !m.deleted && m.id < before)
    .sort((a, b) => b.created_at - a.created_at)
    .slice(0, limit)
    .reverse()
    .map(m => {
      const u = DB.users.find(u => u.id === m.sender_id);
      const read_count = DB.reads.filter(r => r.message_id === m.id).length;
      return { ...m, username: u?.username || '', display_name: u?.display_name || '',
               avatar_color: u?.avatar_color || '#5C5FEF', read_count };
    });
}
function msgById(id) {
  const m = DB.messages.find(m => m.id === id);
  if (!m) return null;
  const u = DB.users.find(u => u.id === m.sender_id);
  return { ...m, username: u?.username || '', display_name: u?.display_name || '',
           avatar_color: u?.avatar_color || '#5C5FEF', read_count: 0 };
}
function markRead(message_id, user_id) {
  if (!DB.reads.some(r => r.message_id === message_id && r.user_id === user_id)) {
    DB.reads.push({ message_id, user_id, read_at: now() });
    saveDB();
  }
}
function getUnread(userId, chat_id) {
  return DB.messages.filter(m =>
    m.chat_id === chat_id && m.sender_id !== userId && !m.deleted &&
    !DB.reads.some(r => r.message_id === m.id && r.user_id === userId)
  );
}

// ══════════════════════════════════════════════════════════════════
//  HTTP API
// ══════════════════════════════════════════════════════════════════
const app = express();
app.use(express.json({ limit: '4mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (req, res, next) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
};

const COLORS = ['#5C5FEF','#E84393','#00C59C','#FF6B35','#7C3AED','#0EA5E9','#F59E0B','#EF4444'];
const randColor = () => COLORS[Math.floor(Math.random() * COLORS.length)];

// POST /api/register
app.post('/api/register', (req, res) => {
  let { username, password, display_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  username = username.trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username))
    return res.status(400).json({ error: 'Username: 3-32 chars, letters/numbers/underscore only' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (userByName(username))
    return res.status(409).json({ error: 'Username already taken' });

  const hash  = bcrypt.hashSync(password, 10);
  const id    = createUser(username, hash, (display_name || username).trim().slice(0, 64), randColor());
  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: userById(id) });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = userByName(username);
  if (!u || !bcrypt.compareSync(password, u.password_hash))
    return res.status(401).json({ error: 'Invalid username or password' });
  const token = jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: userById(u.id) });
});

// GET /api/me
app.get('/api/me', auth, (req, res) => res.json(userById(req.user.id)));

// GET /api/users/search?q=
app.get('/api/users/search', auth, (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json([]);
  res.json(searchUsers(q, req.user.id));
});

// GET /api/chats
app.get('/api/chats', auth, (req, res) => res.json(getUserChats(req.user.id)));

// POST /api/chats
app.post('/api/chats', auth, (req, res) => {
  const { type, username, name, member_ids } = req.body;

  if (type === 'direct') {
    const target = userByName(username);
    if (!target) return res.status(404).json({ error: 'User not found' });
    if (target.id === req.user.id) return res.status(400).json({ error: 'Cannot chat with yourself' });

    const existing = directBetween(req.user.id, target.id);
    if (existing) {
      existing.other_user = otherInDirect(existing.id, req.user.id);
      return res.json(existing);
    }
    const cid = createChat('direct', null, null, req.user.id);
    addMember(cid, req.user.id);
    addMember(cid, target.id);
    const c = chatById(cid);
    c.other_user = userById(target.id);
    return res.json(c);
  }

  if (type === 'group') {
    if (!name?.trim()) return res.status(400).json({ error: 'Group name required' });
    const cid = createChat('group', name.trim().slice(0, 64), randColor(), req.user.id);
    addMember(cid, req.user.id, 'admin');
    if (Array.isArray(member_ids)) member_ids.forEach(mid => addMember(cid, mid, 'member'));
    return res.json(chatById(cid));
  }

  res.status(400).json({ error: 'Invalid type' });
});

// GET /api/chats/:id/messages
app.get('/api/chats/:id/messages', auth, (req, res) => {
  const cid = parseInt(req.params.id);
  if (!isMember(cid, req.user.id)) return res.status(403).json({ error: 'Not a member' });

  const before = parseInt(req.query.before) || 2147483647;
  const limit  = Math.min(parseInt(req.query.limit) || 50, 100);
  const msgs   = getMessages(cid, before, limit);
  for (const m of getUnread(req.user.id, cid)) markRead(m.id, req.user.id);
  res.json(msgs);
});

// GET /api/chats/:id/members
app.get('/api/chats/:id/members', auth, (req, res) => {
  const cid = parseInt(req.params.id);
  if (!isMember(cid, req.user.id)) return res.status(403).json({ error: 'Not a member' });
  res.json(getMembers(cid));
});

// ══════════════════════════════════════════════════════════════════
//  WEBSOCKET
// ══════════════════════════════════════════════════════════════════
const server      = createServer(app);
const wss         = new WebSocket.Server({ server });
const clients     = new Map();
const typingTimers = new Map();

function wsend(ws, data) { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(data)); }
function sendUser(uid, data) { clients.get(uid)?.forEach(ws => wsend(ws, data)); }
function broadcast(uids, data, skip = null) {
  const raw = JSON.stringify(data);
  for (const uid of uids) {
    if (uid === skip) continue;
    clients.get(uid)?.forEach(ws => ws.readyState === WebSocket.OPEN && ws.send(raw));
  }
}
function getContactIds(userId) {
  const chatIds = DB.members.filter(m => m.user_id === userId).map(m => m.chat_id);
  const set = new Set();
  for (const cid of chatIds) getMemberIds(cid).forEach(id => id !== userId && set.add(id));
  return [...set];
}

wss.on('connection', ws => {
  let uid = null;

  ws.on('message', raw => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'auth') {
      try {
        const p = jwt.verify(msg.token, JWT_SECRET);
        uid = p.id;
        if (!clients.has(uid)) clients.set(uid, new Set());
        clients.get(uid).add(ws);
        updateSeen(uid);
        wsend(ws, { type: 'auth_ok', user_id: uid });
        broadcast(getContactIds(uid), { type: 'user_online', user_id: uid });
      } catch { wsend(ws, { type: 'auth_fail' }); }
      return;
    }

    if (!uid) return;

    if (msg.type === 'send_message') {
      const { chat_id, content, temp_id } = msg;
      if (!content?.trim() || !chat_id) return;
      if (!isMember(chat_id, uid)) return;
      const id = insertMessage(chat_id, uid, content.trim().slice(0, 8000));
      markRead(id, uid);
      const message = msgById(id);
      sendUser(uid, { type: 'message_sent', temp_id, message });
      broadcast(getMemberIds(chat_id), { type: 'new_message', message }, uid);
    }

    else if (msg.type === 'typing') {
      const { chat_id } = msg;
      if (!isMember(chat_id, uid)) return;
      const key = `${chat_id}:${uid}`;
      if (!typingTimers.has(key)) {
        const u = userById(uid);
        broadcast(getMemberIds(chat_id), { type: 'typing', chat_id, user_id: uid, name: u.display_name }, uid);
      }
      clearTimeout(typingTimers.get(key));
      typingTimers.set(key, setTimeout(() => {
        typingTimers.delete(key);
        broadcast(getMemberIds(chat_id), { type: 'stop_typing', chat_id, user_id: uid }, uid);
      }, 3500));
    }

    else if (msg.type === 'mark_read') {
      const { chat_id } = msg;
      if (!isMember(chat_id, uid)) return;
      const unread = getUnread(uid, chat_id);
      for (const m of unread) markRead(m.id, uid);
      if (unread.length) {
        broadcast(getMemberIds(chat_id),
          { type: 'messages_read', chat_id, user_id: uid, ids: unread.map(m => m.id) });
      }
    }
  });

  ws.on('close', () => {
    if (!uid) return;
    clients.get(uid)?.delete(ws);
    if (!clients.get(uid)?.size) {
      clients.delete(uid);
      updateSeen(uid);
      broadcast(getContactIds(uid), { type: 'user_offline', user_id: uid, last_seen: now() });
    }
  });

  ws.on('error', () => {});
});

server.listen(PORT, () => {
  console.log('');
  console.log('  ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗');
  console.log('  ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝');
  console.log('  ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗');
  console.log('  ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║');
  console.log('  ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║');
  console.log('  ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝');
  console.log('');
  console.log(`  🔗  Running → http://localhost:${PORT}`);
  console.log(`  💾  Database → ${DB_PATH}`);
  console.log('');
});
