const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto'),{EventEmitter}=require('events');

const db={users:new Map(),usernames:new Map(),sessions:new Map(),chats:new Map(),messages:new Map(),userChats:new Map(),blocked:new Map(),muted:new Map(),pinnedChats:new Map()};

const hashPw=pw=>{const s=crypto.randomBytes(16).toString('hex');return s+':'+crypto.pbkdf2Sync(pw,s,100000,64,'sha512').toString('hex');};
const checkPw=(pw,h)=>{const[s,k]=h.split(':');return crypto.pbkdf2Sync(pw,s,100000,64,'sha512').toString('hex')===k;};
const genToken=()=>crypto.randomBytes(32).toString('hex');
const genId=()=>crypto.randomBytes(10).toString('hex');

const mkSess=uid=>{const t=genToken();db.sessions.set(t,{userId:uid,expiresAt:Date.now()+30*86400000});return t;};
const getSess=t=>{if(!t)return null;const s=db.sessions.get(t);if(!s||s.expiresAt<Date.now()){db.sessions.delete(t);return null;}return s;};

/* ── WebSocket ── */
class WSServer extends EventEmitter{
  constructor(srv){super();this.clients=new Map();srv.on('upgrade',(req,sock)=>{
    const key=req.headers['sec-websocket-key'];if(!key){sock.destroy();return;}
    sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+crypto.createHash('sha1').update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')+'\r\n\r\n');
    const ws=new WSConn(sock);this.emit('connection',ws,req);
  });}
  _s(ws,d){ws.send(typeof d==='string'?d:JSON.stringify(d));}
  toUser(uid,d){for(const[ws,i]of this.clients)if(i.userId===uid)this._s(ws,d);}
  toChat(cid,d,ex=null){const c=db.chats.get(cid);if(!c)return;for(const uid of c.members)if(uid!==ex)this.toUser(uid,d);}
  broadcast(d,exWs=null){for(const[ws]of this.clients)if(ws!==exWs)this._s(ws,d);}
  online(){const s=new Set();for(const[,i]of this.clients)s.add(i.userId);return s;}
}
class WSConn extends EventEmitter{
  constructor(sock){super();this.sock=sock;this.buf=Buffer.alloc(0);
    sock.on('data',d=>{this.buf=Buffer.concat([this.buf,d]);
      while(this.buf.length>=2){
        const op=this.buf[0]&0xf,masked=!!(this.buf[1]&0x80);let len=this.buf[1]&0x7f,off=2;
        if(len===126){if(this.buf.length<4)break;len=this.buf.readUInt16BE(2);off=4;}
        else if(len===127){if(this.buf.length<10)break;len=Number(this.buf.readBigUInt64BE(2));off=10;}
        const ml=masked?4:0;if(this.buf.length<off+ml+len)break;
        let pay=this.buf.slice(off+ml,off+ml+len);
        if(masked){const m=this.buf.slice(off,off+4);for(let i=0;i<pay.length;i++)pay[i]^=m[i%4];}
        this.buf=this.buf.slice(off+ml+len);
        if(op===8){this.emit('close');return;}if(op===9){this._f(10,Buffer.alloc(0));continue;}
        if(op===1||op===2)this.emit('message',pay.toString());
      }
    });
    sock.on('close',()=>this.emit('close'));sock.on('error',()=>this.emit('close'));
  }
  _f(op,data){const l=data.length;let h;
    if(l<126)h=Buffer.from([0x80|op,l]);
    else if(l<65536){h=Buffer.alloc(4);h[0]=0x80|op;h[1]=126;h.writeUInt16BE(l,2);}
    else{h=Buffer.alloc(10);h[0]=0x80|op;h[1]=127;h.writeBigUInt64BE(BigInt(l),2);}
    try{this.sock.write(Buffer.concat([h,data]));}catch{}
  }
  send(d){this._f(1,Buffer.from(d));}close(){try{this.sock.destroy();}catch{}}
}

const readBody=req=>new Promise((res,rej)=>{const c=[];req.on('data',d=>c.push(d));req.on('end',()=>res(Buffer.concat(c)));req.on('error',rej);});
const parseJSON=req=>new Promise((res,rej)=>{let b='';req.on('data',c=>b+=c);req.on('end',()=>{try{res(JSON.parse(b));}catch{res({});}});req.on('error',rej);});
const json=(res,data,st=200)=>{res.writeHead(st,{'Content-Type':'application/json','Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,Authorization'});res.end(JSON.stringify(data));};
const getAuth=req=>{const t=(req.headers['authorization']||'').replace('Bearer ','');const s=getSess(t);return s?db.users.get(s.userId)||null:null;};

function parseMultipart(body,boundary){
  const parts=[],sep=Buffer.from('--'+boundary);let pos=0;
  while(pos<body.length){
    const start=ibuf(body,sep,pos);if(start===-1)break;pos=start+sep.length;
    if(body[pos]===45&&body[pos+1]===45)break;if(body[pos]===13)pos+=2;
    const he=ibuf(body,Buffer.from('\r\n\r\n'),pos);if(he===-1)break;
    const hs=body.slice(pos,he).toString();pos=he+4;
    const ns=ibuf(body,sep,pos);const de=ns===-1?body.length:ns-2;
    const data=body.slice(pos,de);pos=ns===-1?body.length:ns;
    const nm=hs.match(/name="([^"]+)"/),fn=hs.match(/filename="([^"]+)"/),ct=hs.match(/Content-Type:\s*([^\r\n]+)/i);
    parts.push({name:nm?.[1],filename:fn?.[1],contentType:ct?.[1]?.trim(),data});
  }
  return parts;
}
function ibuf(buf,search,from=0){
  for(let i=from;i<=buf.length-search.length;i++){let ok=true;for(let j=0;j<search.length;j++){if(buf[i+j]!==search[j]){ok=false;break;}}if(ok)return i;}return -1;
}

const NIGHTMARE_ID='nightmare_admin_fixed_id';

const serUser=(u,on,meId)=>{
  const isNightmare=u.username==='nightmare';
  return{id:u.id,username:u.username,displayName:u.displayName||u.username,bio:u.bio||'',avatar:u.avatar||null,avatarColor:u.avatarColor||'#2b8af5',online:on?on.has(u.id):false,createdAt:u.createdAt,birthday:u.birthday||null,verified:u.verified||false,isCreator:isNightmare,showOnline:u.showOnline!==false,hiddenLastSeen:u.hiddenLastSeen||null,deleted:u.deleted||false,isBanned:u.isBanned||false,pinnedChats:u.pinnedChats||[]};
};

const serChat=(chat,meId,on)=>{
  const msgs=db.messages.get(chat.id)||[];
  const last=msgs[msgs.length-1]||null;
  const unread=msgs.filter(m=>m.senderId!==meId&&!m.readBy.has(meId)).length;
  const muted=(db.muted.get(meId)||new Set()).has(chat.id);
  const pinned=chat.pinnedMessageId||null;
  const userPins=db.pinnedChats.get(meId)||new Set();
  let name=chat.name,avatar=chat.avatar||null,avatarColor=chat.avatarColor||'#2b8af5',onlineStatus=null,showOnlineStatus=true;
  const members=[...chat.members].map(id=>{const u=db.users.get(id);return u?serUser(u,on,meId):null;}).filter(Boolean);
  if(chat.type==='dm'){const other=db.users.get([...chat.members].find(id=>id!==meId));if(other){name=other.displayName||other.username;avatar=other.avatar;avatarColor=other.avatarColor||'#2b8af5';showOnlineStatus=other.showOnline!==false;onlineStatus=showOnlineStatus?on.has(other.id):null;}}
  return{id:chat.id,type:chat.type,name,username:chat.username||null,avatar,avatarColor,verified:chat.verified||false,online:onlineStatus,members,ownerId:chat.ownerId||null,description:chat.description||'',subscribersCount:chat.type==='channel'?chat.members.size:undefined,lastMessage:last?{id:last.id,text:last.text||'',type:last.type||'text',caption:last.caption||'',senderId:last.senderId,senderName:(()=>{const u=db.users.get(last.senderId);return u?(u.displayName||u.username):''})(),createdAt:last.createdAt}:null,unreadCount:unread,createdAt:chat.createdAt,muted,pinnedMessageId:pinned,roles:chat.roles||{},isPinnedByUser:userPins.has(chat.id)};
};

const serMsg=msg=>{
  const u=db.users.get(msg.senderId);
  return{id:msg.id,chatId:msg.chatId,senderId:msg.senderId,senderName:u?(u.displayName||u.username):'Deleted',senderUsername:u?u.username:'',senderAvatar:u?u.avatar:null,senderAvatarColor:u?(u.avatarColor||'#2b8af5'):'#2b8af5',senderVerified:u?u.verified||false:false,senderIsCreator:u?u.username==='nightmare':false,text:msg.text||'',caption:msg.caption||'',type:msg.type||'text',fileUrl:msg.fileUrl||null,fileName:msg.fileName||null,fileSize:msg.fileSize||null,fileMime:msg.fileMime||null,waveform:msg.waveform||null,duration:msg.duration||null,createdAt:msg.createdAt,readBy:[...msg.readBy],edited:msg.edited||false,pinned:msg.pinned||false};
};

/* ── Create nightmare admin account ── */
const NIGHTMARE_PWD=hashPw('nightmare2024');
const nmId=NIGHTMARE_ID;
db.users.set(nmId,{id:nmId,username:'nightmare',displayName:'Nightmare',bio:'#создатель_мессенджера ⚡ Основатель Nexus',avatar:null,avatarColor:'#7c3aed',passwordHash:NIGHTMARE_PWD,createdAt:Date.now()-365*86400000,verified:true,isCreator:true,showOnline:true,pinnedChats:[],isBanned:false,deleted:false,birthday:null,hiddenLastSeen:null});
db.usernames.set('nightmare',nmId);
db.userChats.set(nmId,new Set());

const UPDIR=path.join(__dirname,'uploads');
if(!fs.existsSync(UPDIR))fs.mkdirSync(UPDIR,{recursive:true});

const server=http.createServer(async(req,res)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if(req.method==='OPTIONS'){res.writeHead(204);res.end();return;}
  const url=new URL(req.url,'http://localhost');
  const p=url.pathname;

  if(req.method==='GET'&&(p==='/'||p==='/index.html')){res.writeHead(200,{'Content-Type':'text/html'});res.end(fs.readFileSync(path.join(__dirname,'index.html')));return;}

  if(req.method==='GET'&&p.startsWith('/uploads/')){
    const fp=path.join(UPDIR,path.basename(p.slice(9)));
    if(fs.existsSync(fp)){
      const ext=path.extname(fp).toLowerCase();
      const mimes={'.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp','.mp3':'audio/mpeg','.ogg':'audio/ogg','.wav':'audio/wav','.webm':'audio/webm'};
      res.writeHead(200,{'Content-Type':mimes[ext]||'application/octet-stream','Cache-Control':'public,max-age=86400','Access-Control-Allow-Origin':'*'});
      fs.createReadStream(fp).pipe(res);
    }else{res.writeHead(404);res.end();}
    return;
  }

  if(req.method==='POST'&&p==='/api/register'){
    const b=await parseJSON(req);
    const uname=(b.username||'').toLowerCase().replace(/^@/,'').replace(/[^a-z0-9_.]/g,'');
    if(!uname||uname.length<5)return json(res,{error:'Username минимум 5 символов'},400);
    if(!b.password||b.password.length<4)return json(res,{error:'Пароль минимум 4 символа'},400);
    if(db.usernames.has(uname))return json(res,{error:'Username уже занят'},409);
    if(uname==='nightmare')return json(res,{error:'Этот username зарезервирован'},403);
    const colors=['#2b8af5','#7c5ce4','#10b981','#f59e0b','#ef4444','#06b6d4','#ec4899','#14b8a6'];
    const id=genId();
    const user={id,username:uname,displayName:(b.displayName||uname).slice(0,32),bio:'',avatar:null,birthday:null,avatarColor:colors[Math.floor(Math.random()*colors.length)],passwordHash:hashPw(b.password),createdAt:Date.now(),verified:false,isCreator:false,showOnline:true,pinnedChats:[],isBanned:false,deleted:false,hiddenLastSeen:null};
    db.users.set(id,user);db.usernames.set(uname,id);db.userChats.set(id,new Set());
    return json(res,{token:mkSess(id),user:serUser(user,wss.online(),id),isNew:true});
  }

  if(req.method==='POST'&&p==='/api/login'){
    const b=await parseJSON(req);
    const uname=(b.username||'').toLowerCase().replace(/^@/,'').trim();
    const uid=db.usernames.get(uname);const user=uid?db.users.get(uid):null;
    if(!user||!checkPw(b.password,user.passwordHash))return json(res,{error:'Неверный логин или пароль'},401);
    if(user.isBanned)return json(res,{error:'Аккаунт заблокирован администратором'},403);
    if(user.deleted)return json(res,{error:'Аккаунт удалён'},403);
    return json(res,{token:mkSess(user.id),user:serUser(user,wss.online(),user.id)});
  }

  const me=getAuth(req);if(!me)return json(res,{error:'Unauthorized'},401);
  const on=wss.online();

  if(req.method==='GET'&&p==='/api/me')return json(res,serUser(me,on,me.id));
  if(req.method==='PUT'&&p==='/api/me'){
    const b=await parseJSON(req);
    if(b.displayName!==undefined)me.displayName=b.displayName.slice(0,32)||me.displayName;
    if(b.bio!==undefined)me.bio=b.bio.slice(0,160);
    if('avatar'in b)me.avatar=b.avatar;
    if(b.avatarColor)me.avatarColor=b.avatarColor;
    if('birthday'in b)me.birthday=b.birthday;
    if('showOnline'in b)me.showOnline=!!b.showOnline;
    wss.broadcast({type:'user_updated',user:serUser(me,on,me.id)});
    localStorage_save_user:;
    return json(res,serUser(me,on,me.id));
  }

  /* Delete own account */
  if(req.method==='POST'&&p==='/api/me/delete'){
    if(me.username==='nightmare')return json(res,{error:'Нельзя удалить аккаунт создателя'},403);
    me.deleted=true;me.displayName='Deleted User';me.avatar=null;me.bio='';
    for(const[,sess]of db.sessions)if(sess.userId===me.id)db.sessions.delete(sess);
    wss.broadcast({type:'user_updated',user:serUser(me,on,me.id)});
    return json(res,{ok:true});
  }

  /* Admin endpoints (nightmare only) */
  const isNm=me.username==='nightmare';

  if(req.method==='POST'&&p.match(/^\/api\/admin\/verify\/user\/([^/]+)$/)){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    const uid=p.match(/^\/api\/admin\/verify\/user\/([^/]+)$/)[1];
    const u=db.users.get(uid);if(!u)return json(res,{error:'Not found'},404);
    u.verified=!u.verified;
    wss.broadcast({type:'user_updated',user:serUser(u,on,me.id)});
    return json(res,{verified:u.verified});
  }
  if(req.method==='POST'&&p.match(/^\/api\/admin\/verify\/chat\/([^/]+)$/)){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    const cid=p.match(/^\/api\/admin\/verify\/chat\/([^/]+)$/)[1];
    const c=db.chats.get(cid);if(!c)return json(res,{error:'Not found'},404);
    c.verified=!c.verified;
    wss.toChat(cid,{type:'chat_updated',chat:serChat(c,me.id,on)});
    return json(res,{verified:c.verified});
  }
  if(req.method==='POST'&&p.match(/^\/api\/admin\/ban\/([^/]+)$/)){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    const uid=p.match(/^\/api\/admin\/ban\/([^/]+)$/)[1];
    const u=db.users.get(uid);if(!u)return json(res,{error:'Not found'},404);
    if(u.username==='nightmare')return json(res,{error:'Нельзя'},403);
    u.isBanned=!u.isBanned;
    wss.broadcast({type:'user_updated',user:serUser(u,on,me.id)});
    return json(res,{banned:u.isBanned});
  }
  if(req.method==='DELETE'&&p.match(/^\/api\/admin\/user\/([^/]+)$/)){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    const uid=p.match(/^\/api\/admin\/user\/([^/]+)$/)[1];
    const u=db.users.get(uid);if(!u)return json(res,{error:'Not found'},404);
    if(u.username==='nightmare')return json(res,{error:'Нельзя'},403);
    u.deleted=true;u.isBanned=true;u.displayName='Deleted User';u.avatar=null;
    wss.broadcast({type:'user_updated',user:serUser(u,on,me.id)});
    return json(res,{ok:true});
  }
  if(req.method==='GET'&&p==='/api/admin/users'){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    return json(res,[...db.users.values()].map(u=>serUser(u,on,me.id)));
  }
  if(req.method==='GET'&&p==='/api/admin/chats'){
    if(!isNm)return json(res,{error:'Forbidden'},403);
    return json(res,[...db.chats.values()].map(c=>serChat(c,me.id,on)));
  }

  if(req.method==='GET'&&p==='/api/users')return json(res,[...db.users.values()].filter(u=>!u.deleted&&u.id!==me.id).map(u=>serUser(u,on,me.id)));
  const uM=p.match(/^\/api\/users\/([^/]+)$/);
  if(req.method==='GET'&&uM){const u=db.users.get(uM[1])||db.users.get(db.usernames.get(uM[1]));return u?json(res,serUser(u,on,me.id)):json(res,{error:'Not found'},404);}
  if(req.method==='GET'&&p==='/api/search'){
    const q=(url.searchParams.get('q')||'').toLowerCase();
    return json(res,[...db.users.values()].filter(u=>!u.deleted&&u.id!==me.id).filter(u=>!q||u.username.includes(q)||(u.displayName||'').toLowerCase().includes(q)).slice(0,30).map(u=>serUser(u,on,me.id)));
  }

  if(req.method==='GET'&&p==='/api/chats'){
    const ids=db.userChats.get(me.id)||new Set();
    return json(res,[...ids].map(id=>{const c=db.chats.get(id);return c?serChat(c,me.id,on):null;}).filter(Boolean).sort((a,b)=>{const ap=a.isPinnedByUser?1:0,bp=b.isPinnedByUser?1:0;if(bp!==ap)return bp-ap;return(b.lastMessage?.createdAt||b.createdAt)-(a.lastMessage?.createdAt||a.createdAt);}));
  }

  /* Pin/unpin chat */
  const pinChatM=p.match(/^\/api\/chats\/([^/]+)\/pin-chat$/);
  if(req.method==='POST'&&pinChatM){
    if(!db.pinnedChats.has(me.id))db.pinnedChats.set(me.id,new Set());
    const s=db.pinnedChats.get(me.id);
    if(s.has(pinChatM[1]))s.delete(pinChatM[1]);else s.add(pinChatM[1]);
    return json(res,{pinned:s.has(pinChatM[1])});
  }

  if(req.method==='POST'&&p==='/api/chats/dm'){
    const{userId}=await parseJSON(req);if(!userId||!db.users.has(userId))return json(res,{error:'User not found'},404);
    let chat=null;
    for(const cid of(db.userChats.get(me.id)||[])){const c=db.chats.get(cid);if(c?.type==='dm'&&c.members.has(userId)){chat=c;break;}}
    if(!chat){
      const id=genId();chat={id,type:'dm',name:null,members:new Set([me.id,userId]),createdAt:Date.now(),roles:{},pinnedMessageId:null};
      db.chats.set(id,chat);db.messages.set(id,[]);
      for(const uid of[me.id,userId]){if(!db.userChats.has(uid))db.userChats.set(uid,new Set());db.userChats.get(uid).add(id);}
      wss.toUser(userId,{type:'chat_created',chat:serChat(chat,userId,on)});
    }
    return json(res,serChat(chat,me.id,on));
  }

  if(req.method==='POST'&&p==='/api/chats/group'){
    const{name,memberIds,description}=await parseJSON(req);
    if(!name?.trim()||!Array.isArray(memberIds)||!memberIds.length)return json(res,{error:'Invalid'},400);
    const id=genId();const members=new Set([me.id,...memberIds]);
    const colors=['#2b8af5','#7c5ce4','#10b981','#f59e0b','#ef4444'];
    const chat={id,type:'group',name:name.trim(),description:description||'',members,ownerId:me.id,avatarColor:colors[Math.floor(Math.random()*colors.length)],createdAt:Date.now(),roles:{[me.id]:'admin'},pinnedMessageId:null};
    db.chats.set(id,chat);db.messages.set(id,[]);
    for(const uid of members){if(!db.userChats.has(uid))db.userChats.set(uid,new Set());db.userChats.get(uid).add(id);if(uid!==me.id)wss.toUser(uid,{type:'chat_created',chat:serChat(chat,uid,on)});}
    return json(res,serChat(chat,me.id,on));
  }

  if(req.method==='POST'&&p==='/api/chats/channel'){
    const{name,description,username:chanUn}=await parseJSON(req);
    if(!name?.trim())return json(res,{error:'Нужно название'},400);
    if(!chanUn||chanUn.length<3)return json(res,{error:'Username канала обязателен (мин. 3 символа)'},400);
    const cleanUn=chanUn.toLowerCase().replace(/[^a-z0-9_.]/g,'');
    if(cleanUn!==chanUn.toLowerCase())return json(res,{error:'Username может содержать только a-z, 0-9, точку, подчёркивание'},400);
    if(db.usernames.has(cleanUn))return json(res,{error:'Username уже занят'},409);
    const colors=['#2b8af5','#7c5ce4','#10b981','#f59e0b','#ef4444'];
    const id=genId();
    const chat={id,type:'channel',name:name.trim(),username:cleanUn,description:description||'',members:new Set([me.id]),ownerId:me.id,avatarColor:colors[Math.floor(Math.random()*colors.length)],createdAt:Date.now(),roles:{[me.id]:'admin'},pinnedMessageId:null,verified:false};
    db.chats.set(id,chat);db.messages.set(id,[]);
    db.usernames.set(cleanUn,id);
    if(!db.userChats.has(me.id))db.userChats.set(me.id,new Set());
    db.userChats.get(me.id).add(id);
    return json(res,serChat(chat,me.id,on));
  }

  const chatUpdM=p.match(/^\/api\/chats\/([^/]+)$/);
  if(req.method==='PUT'&&chatUpdM){
    const chat=db.chats.get(chatUpdM[1]);if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    const b=await parseJSON(req);
    if(b.avatar!==undefined)chat.avatar=b.avatar;if(b.name)chat.name=b.name.slice(0,64);if(b.description!==undefined)chat.description=b.description;
    if(b.username!==undefined&&chat.type==='channel'){
      const nu=b.username.toLowerCase().replace(/[^a-z0-9_.]/g,'');
      if(nu&&db.usernames.has(nu)&&db.usernames.get(nu)!==chat.id)return json(res,{error:'Username занят'},409);
      if(chat.username)db.usernames.delete(chat.username);chat.username=nu||null;if(nu)db.usernames.set(nu,chat.id);
    }
    wss.toChat(chat.id,{type:'chat_updated',chat:serChat(chat,me.id,on)});
    return json(res,serChat(chat,me.id,on));
  }

  /* Delete chat */
  const chatDelM=p.match(/^\/api\/chats\/([^/]+)\/delete$/);
  if(req.method==='POST'&&chatDelM){
    const chat=db.chats.get(chatDelM[1]);if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    if(chat.type!=='dm'&&chat.ownerId!==me.id)return json(res,{error:'Только владелец'},403);
    const members=[...chat.members];
    if(chat.username)db.usernames.delete(chat.username);
    db.chats.delete(chat.id);db.messages.delete(chat.id);
    for(const uid of members){const s=db.userChats.get(uid);if(s)s.delete(chat.id);}
    for(const uid of members)wss.toUser(uid,{type:'chat_deleted',chatId:chat.id});
    return json(res,{ok:true});
  }

  /* Subscribe */
  const subM=p.match(/^\/api\/chats\/([^/]+)\/subscribe$/);
  if(req.method==='POST'&&subM){
    const chat=db.chats.get(subM[1]);if(!chat||chat.type!=='channel')return json(res,{error:'Not found'},404);
    chat.members.add(me.id);if(!db.userChats.has(me.id))db.userChats.set(me.id,new Set());db.userChats.get(me.id).add(chat.id);
    wss.toChat(chat.id,{type:'chat_updated',chat:serChat(chat,me.id,on)});
    return json(res,serChat(chat,me.id,on));
  }

  /* Kick */
  const kickM=p.match(/^\/api\/chats\/([^/]+)\/kick\/([^/]+)$/);
  if(req.method==='POST'&&kickM){
    const chat=db.chats.get(kickM[1]);const targetId=kickM[2];
    if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    if(chat.ownerId!==me.id&&chat.roles?.[me.id]!=='admin')return json(res,{error:'Нет прав'},403);
    if(targetId===chat.ownerId)return json(res,{error:'Нельзя кикнуть владельца'},403);
    chat.members.delete(targetId);const s=db.userChats.get(targetId);if(s)s.delete(chat.id);
    wss.toUser(targetId,{type:'chat_deleted',chatId:chat.id});
    wss.toChat(chat.id,{type:'chat_updated',chat:serChat(chat,me.id,on)});
    return json(res,{ok:true});
  }

  /* Role */
  const roleM=p.match(/^\/api\/chats\/([^/]+)\/role\/([^/]+)$/);
  if(req.method==='POST'&&roleM){
    const chat=db.chats.get(roleM[1]);const targetId=roleM[2];
    if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    if(chat.ownerId!==me.id&&chat.roles?.[me.id]!=='admin')return json(res,{error:'Нет прав'},403);
    const{role}=await parseJSON(req);if(!chat.roles)chat.roles={};
    if(role==='remove')delete chat.roles[targetId];else chat.roles[targetId]=role;
    wss.toChat(chat.id,{type:'chat_updated',chat:serChat(chat,me.id,on)});
    return json(res,serChat(chat,me.id,on));
  }

  /* Channels discover */
  if(req.method==='GET'&&p==='/api/channels'){
    const q=(url.searchParams.get('q')||'').toLowerCase();
    return json(res,[...db.chats.values()].filter(c=>c.type==='channel'&&(!q||c.name.toLowerCase().includes(q)||(c.description||'').toLowerCase().includes(q)||(c.username||'').includes(q))).map(c=>serChat(c,me.id,on)));
  }

  /* Messages */
  const msgM=p.match(/^\/api\/chats\/([^/]+)\/messages$/);
  if(req.method==='GET'&&msgM){
    const chat=db.chats.get(msgM[1]);if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    const msgs=db.messages.get(chat.id)||[];
    if(chat.type!=='channel'){msgs.forEach(m=>{if(m.senderId!==me.id)m.readBy.add(me.id);});wss.toChat(chat.id,{type:'messages_read',chatId:chat.id,userId:me.id},me.id);}
    return json(res,msgs.slice(-60).map(serMsg));
  }

  /* Pin message */
  const pinM=p.match(/^\/api\/chats\/([^/]+)\/pin\/([^/]+)$/);
  if(req.method==='POST'&&pinM){
    const chat=db.chats.get(pinM[1]);if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    const msgs=db.messages.get(pinM[1])||[];const msg=msgs.find(m=>m.id===pinM[2]);if(!msg)return json(res,{error:'Not found'},404);
    const isPinned=chat.pinnedMessageId===pinM[2];
    chat.pinnedMessageId=isPinned?null:pinM[2];msg.pinned=!isPinned;
    wss.toChat(chat.id,{type:'message_pinned',chatId:chat.id,messageId:isPinned?null:pinM[2],message:isPinned?null:serMsg(msg)});
    return json(res,{ok:true,pinned:!isPinned});
  }

  /* Upload */
  if(req.method==='POST'&&p==='/api/upload'){
    const ct=req.headers['content-type']||'';const bm=ct.match(/boundary=(.+)$/);if(!bm)return json(res,{error:'No boundary'},400);
    const raw=await readBody(req);const parts=parseMultipart(raw,bm[1].trim());const fp=parts.find(p=>p.filename);if(!fp)return json(res,{error:'No file'},400);
    const ext=path.extname(fp.filename||'').toLowerCase()||'.bin';const safe=genId()+ext;
    fs.writeFileSync(path.join(UPDIR,safe),fp.data);
    return json(res,{url:`/uploads/${safe}`,name:fp.filename,size:fp.data.length,mime:fp.contentType||'application/octet-stream'});
  }
  if(req.method==='POST'&&p==='/api/avatar'){
    const ct=req.headers['content-type']||'';const bm=ct.match(/boundary=(.+)$/);if(!bm)return json(res,{error:'No boundary'},400);
    const raw=await readBody(req);const parts=parseMultipart(raw,bm[1].trim());const fp=parts.find(p=>p.filename);if(!fp)return json(res,{error:'No file'},400);
    const mime=fp.contentType||'image/jpeg';const ext='.'+mime.split('/')[1].split(';')[0].trim();
    const safe=genId()+ext;fs.writeFileSync(path.join(UPDIR,safe),fp.data);
    me.avatar=`/uploads/${safe}`;wss.broadcast({type:'user_updated',user:serUser(me,on,me.id)});
    return json(res,{avatar:me.avatar,user:serUser(me,on,me.id)});
  }
  const chatAvaM=p.match(/^\/api\/chats\/([^/]+)\/avatar$/);
  if(req.method==='POST'&&chatAvaM){
    const chat=db.chats.get(chatAvaM[1]);if(!chat||!chat.members.has(me.id))return json(res,{error:'Forbidden'},403);
    const ct=req.headers['content-type']||'';const bm=ct.match(/boundary=(.+)$/);if(!bm)return json(res,{error:'No boundary'},400);
    const raw=await readBody(req);const parts=parseMultipart(raw,bm[1].trim());const fp=parts.find(p=>p.filename);if(!fp)return json(res,{error:'No file'},400);
    const mime=fp.contentType||'image/jpeg';const ext='.'+mime.split('/')[1].split(';')[0].trim();
    const safe=genId()+ext;fs.writeFileSync(path.join(UPDIR,safe),fp.data);
    chat.avatar=`/uploads/${safe}`;wss.toChat(chat.id,{type:'chat_updated',chat:serChat(chat,me.id,on)});
    return json(res,{avatar:chat.avatar});
  }

  const muteM=p.match(/^\/api\/chats\/([^/]+)\/(mute|unmute)$/);
  if(req.method==='POST'&&muteM){
    if(!db.muted.has(me.id))db.muted.set(me.id,new Set());
    muteM[2]==='mute'?db.muted.get(me.id).add(muteM[1]):db.muted.get(me.id).delete(muteM[1]);
    return json(res,{muted:muteM[2]==='mute'});
  }
  const blkM=p.match(/^\/api\/users\/([^/]+)\/(block|unblock)$/);
  if(req.method==='POST'&&blkM){
    if(!db.blocked.has(me.id))db.blocked.set(me.id,new Set());
    blkM[2]==='block'?db.blocked.get(me.id).add(blkM[1]):db.blocked.get(me.id).delete(blkM[1]);
    return json(res,{blocked:blkM[2]==='block'});
  }
  const isBlkM=p.match(/^\/api\/users\/([^/]+)\/blocked$/);
  if(req.method==='GET'&&isBlkM)return json(res,{blocked:(db.blocked.get(me.id)||new Set()).has(isBlkM[1])});

  json(res,{error:'Not found'},404);
});

const wss=new WSServer(server);
wss.on('connection',(ws,req)=>{
  const url=new URL(req.url,'http://localhost');
  const sess=getSess(url.searchParams.get('token'));
  if(!sess){ws.close();return;}
  const user=db.users.get(sess.userId);if(!user||user.deleted||user.isBanned){ws.close();return;}
  const uid=user.id;wss.clients.set(ws,{userId:uid});
  wss.broadcast({type:'presence',userId:uid,online:true,showOnline:user.showOnline!==false},ws);

  ws.on('message',raw=>{
    let msg;try{msg=JSON.parse(raw);}catch{return;}
    switch(msg.type){
      case 'send_message':{
        const{chatId,text,caption,msgType,fileUrl,fileName,fileSize,fileMime,waveform,duration}=msg;
        if(!chatId)return;const chat=db.chats.get(chatId);if(!chat||!chat.members.has(uid))return;
        if(chat.type==='channel'&&chat.ownerId!==uid&&chat.roles?.[uid]!=='admin')return;
        if(!text?.trim()&&!fileUrl)return;
        const m={id:genId(),chatId,senderId:uid,text:text?.trim()||'',caption:caption?.trim()||'',type:msgType||'text',fileUrl:fileUrl||null,fileName:fileName||null,fileSize:fileSize||null,fileMime:fileMime||null,waveform:waveform||null,duration:duration||null,createdAt:Date.now(),readBy:new Set([uid]),edited:false,pinned:false};
        (db.messages.get(chatId)||[]).push(m);wss.toChat(chatId,{type:'new_message',message:serMsg(m)});break;
      }
      case 'edit_message':{
        const{chatId,messageId,text}=msg;const m=(db.messages.get(chatId)||[]).find(x=>x.id===messageId&&x.senderId===uid);
        if(!m||!text?.trim())return;m.text=text.trim();m.edited=true;wss.toChat(chatId,{type:'message_edited',message:serMsg(m)});break;
      }
      case 'delete_message':{
        const{chatId,messageId}=msg;const msgs=db.messages.get(chatId)||[];const idx=msgs.findIndex(x=>x.id===messageId&&x.senderId===uid);
        if(idx===-1)return;msgs.splice(idx,1);wss.toChat(chatId,{type:'message_deleted',chatId,messageId});break;
      }
      case 'typing':{
        const{chatId,isTyping}=msg;const chat=db.chats.get(chatId);if(!chat||!chat.members.has(uid))return;
        wss.toChat(chatId,{type:'typing',chatId,userId:uid,displayName:user.displayName||user.username,isTyping,avatar:user.avatar,avatarColor:user.avatarColor||'#2b8af5'},uid);break;
      }
      case 'mark_read':{
        const{chatId}=msg;const msgs=db.messages.get(chatId)||[];msgs.forEach(m=>{if(m.senderId!==uid)m.readBy.add(uid);});
        wss.toChat(chatId,{type:'messages_read',chatId,userId:uid},uid);break;
      }
    }
  });

  ws.on('close',()=>{
    wss.clients.delete(ws);
    if(![...wss.clients.values()].some(c=>c.userId===uid)){
      const u=db.users.get(uid);if(u)u.hiddenLastSeen=Date.now();
      wss.broadcast({type:'presence',userId:uid,online:false,showOnline:user.showOnline!==false,lastSeen:Date.now()});
    }
  });
});

const PORT=process.env.PORT||3000;
server.listen(PORT,()=>{
  console.log(`\n⚡ Nexus Messenger v4.0 → http://localhost:${PORT}`);
  console.log('\n🔐 Аккаунт администратора:');
  console.log('   @nightmare — пароль: nightmare2024\n');
});
