const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_THIS_SECRET_BEFORE_PRODUCTION';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const INITIAL_FILE = path.join(__dirname, 'initial-data.json');
const PUBLIC = path.join(__dirname, 'public');
let state = null;
let version = 0;
let pg = null;
let pgEnabled = false;
const clients = new Set();

function clone(x){return JSON.parse(JSON.stringify(x));}
function normalize(s){
  s=s||{};
  return {users:Array.isArray(s.users)?s.users:[],settings:s.settings||{},sales:Array.isArray(s.sales)?s.sales:[],expenses:Array.isArray(s.expenses)?s.expenses:[]};
}
function publicState(s){
  const x=clone(normalize(s));
  x.users=x.users.map(u=>({id:u.id,name:u.name,role:u.role,color:u.color||null}));
  return x;
}
function cleanIncoming(data){
  const x=normalize(data);
  x.users=x.users.map(u=>({id:String(u.id||''),name:String(u.name||''),role:u.role==='admin'?'admin':'staff',color:/^#[0-9A-Fa-f]{6}$/.test(String(u.color||''))?String(u.color):null,passwordHash:u.passwordHash}));
  return x;
}
function notify(){const msg=`data: ${JSON.stringify({version})}\n\n`;for(const res of clients){try{res.write(msg)}catch{clients.delete(res)}}}
async function init(){
  if(process.env.DATABASE_URL){
    pg=new Client({connectionString:process.env.DATABASE_URL,ssl:process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:false});
    await pg.connect(); pgEnabled=true;
    await pg.query(`CREATE TABLE IF NOT EXISTS app_state(id INTEGER PRIMARY KEY CHECK(id=1), version BIGINT NOT NULL, data JSONB NOT NULL)`);
    const r=await pg.query('SELECT version,data FROM app_state WHERE id=1');
    if(r.rowCount){version=Number(r.rows[0].version);state=normalize(r.rows[0].data)} else {state=await loadInitial();version=1;await pg.query('INSERT INTO app_state(id,version,data) VALUES(1,$1,$2)',[version,state])}
  } else {
    if(fs.existsSync(DATA_FILE)){const x=JSON.parse(fs.readFileSync(DATA_FILE,'utf8'));version=Number(x.version||1);state=normalize(x.data||x)}
    else {state=await loadInitial();version=1;saveFile()}
  }
}
async function loadInitial(){const x=JSON.parse(fs.readFileSync(INITIAL_FILE,'utf8'));for(const u of x.users){u.passwordHash=await bcrypt.hash(u.password||'1234',12);delete u.password}return normalize(x)}
function saveFile(){fs.writeFileSync(DATA_FILE,JSON.stringify({version,data:state},null,2),'utf8')}
async function persist(next){
  if(pgEnabled){await pg.query('BEGIN');try{const r=await pg.query('SELECT version FROM app_state WHERE id=1 FOR UPDATE');const nv=Number(r.rows[0].version)+1;await pg.query('UPDATE app_state SET version=$1,data=$2 WHERE id=1',[nv,next]);await pg.query('COMMIT');version=nv;state=next}catch(e){await pg.query('ROLLBACK');throw e}}
  else {version++;state=next;saveFile()}
  notify();
}
function tokenFor(u){return jwt.sign({sub:u.id,role:u.role},JWT_SECRET,{expiresIn:'7d'})}
function auth(req){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return null;try{return jwt.verify(h.slice(7),JWT_SECRET)}catch{return null}}
function currentUser(req){const p=auth(req);if(!p)return null;return state.users.find(u=>u.id===p.sub)||null}
function send(res,status,obj,headers={}){const body=JSON.stringify(obj);res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(body)}
function readBody(req){return new Promise((resolve,reject)=>{let b='';req.on('data',c=>{b+=c;if(b.length>8e6)req.destroy()});req.on('end',()=>{try{resolve(b?JSON.parse(b):{})}catch(e){reject(e)}});req.on('error',reject)})}
function same(a,b){return JSON.stringify(a)===JSON.stringify(b)}
function validateState(next,actor){
  if(!next.users.some(u=>u.id==='admin'&&u.role==='admin'))throw new Error('관리자 계정은 반드시 1개 이상 필요합니다.');
  if(actor.role!=='admin'){
    const pub=publicState(state), inc=publicState(next);
    if(!same(pub.users,inc.users)||!same(pub.settings,inc.settings)||!same(pub.expenses,inc.expenses))throw new Error('직원 계정은 결제/매출 데이터만 변경할 수 있습니다.');
    const oldMine=state.sales.filter(x=>x.inputter===actor.name), newMine=next.sales.filter(x=>x.inputter===actor.name);
    if(next.sales.some(x=>x.inputter!==actor.name && !state.sales.some(y=>y.id===x.id)))throw new Error('권한이 없습니다.');
    // staff may add/edit/delete only their own records; records belonging to others must be unchanged.
    const oldOther=state.sales.filter(x=>x.inputter!==actor.name), newOther=next.sales.filter(x=>x.inputter!==actor.name);
    if(!same(oldOther,newOther))throw new Error('본인이 입력한 매출만 변경할 수 있습니다.');
    for(const x of newMine)if(x.inputter!==actor.name)throw new Error('입력자는 본인으로만 저장할 수 있습니다.');
  }
}
function staticFile(res,p){const ext=path.extname(p).toLowerCase();const types={'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.json':'application/json'};if(!fs.existsSync(p)){res.writeHead(404);return res.end('Not found')}res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':'no-cache'});fs.createReadStream(p).pipe(res)}

async function handle(req,res){
  const parsed=url.parse(req.url,true),p=parsed.pathname;
  if(req.method==='GET'&&p==='/api/state'){const u=currentUser(req);return send(res,200,{data:publicState(state),version,user:u?{id:u.id,name:u.name,role:u.role}:null})}
  if(req.method==='POST'&&p==='/api/login'){
    const b=await readBody(req),u=state.users.find(x=>x.id===String(b.id||''));
    if(!u||!u.passwordHash||!(await bcrypt.compare(String(b.password||''),u.passwordHash)))return send(res,401,{error:'아이디 또는 비밀번호를 확인하세요.'});
    return send(res,200,{token:tokenFor(u),user:{id:u.id,name:u.name,role:u.role}})
  }
  if(req.method==='GET'&&p==='/api/events'){
    res.writeHead(200,{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache','Connection':'keep-alive','Access-Control-Allow-Origin':'*'});res.write(`data: ${JSON.stringify({version})}\n\n`);clients.add(res);req.on('close',()=>clients.delete(res));return;
  }
  const u=currentUser(req);if(!u)return send(res,401,{error:'로그인이 필요합니다.'});
  if(req.method==='POST'&&p==='/api/change-password'){
    const b=await readBody(req),pw=String(b.password||'');if(pw.length<4)return send(res,400,{error:'비밀번호는 4자 이상이어야 합니다.'});
    const next=clone(state),idx=next.users.findIndex(x=>x.id===u.id);next.users[idx].passwordHash=await bcrypt.hash(pw,12);await persist(next);return send(res,200,{ok:true})
  }
  if(req.method==='PUT'&&p==='/api/state'){
    if(u.role!=='admin'){
      const b=await readBody(req),next=cleanIncoming(b.data);
    next.users=next.users.map(nu=>({...nu,passwordHash:state.users.find(ou=>ou.id===nu.id)?.passwordHash}));
    try{validateState(next,u);await persist(next);return send(res,200,{data:publicState(state),version})}catch(e){return send(res,403,{error:e.message})}
    }
    const b=await readBody(req),next=cleanIncoming(b.data); // preserve existing password hashes by ID
    for(const nu of next.users){const old=state.users.find(x=>x.id===nu.id);nu.passwordHash=old?.passwordHash||bcrypt.hashSync('1234',12)}
    // restore/admin state should not accidentally delete password hashes for omitted users; if admin restored user list, passwords default only for new users.
    try{await persist(next);return send(res,200,{data:publicState(state),version})}catch(e){return send(res,500,{error:e.message})}
  }
  if(p==='/api/users'&&(req.method==='PUT'||req.method==='DELETE')){
    if(u.role!=='admin')return send(res,403,{error:'관리자만 사용자관리를 사용할 수 있습니다.'});
    const b=await readBody(req),next=clone(state);
    if(req.method==='DELETE'){
      if(b.id==='admin'||b.id===u.id)return send(res,400,{error:'해당 계정은 삭제할 수 없습니다.'});next.users=next.users.filter(x=>x.id!==b.id)
    } else {
      const d=b.data||{},id=String(d.id||''),name=String(d.name||'').trim();if(!id||!name)return send(res,400,{error:'ID와 이름을 입력하세요.'});
      const idx=next.users.findIndex(x=>x.id===b.oldId),old=idx>=0?next.users[idx]:null;
      if(!old&&next.users.some(x=>x.id===id))return send(res,400,{error:'이미 존재하는 ID입니다.'});
      if(old&&b.oldId!=='admin'&&id==='admin')return send(res,400,{error:'admin ID는 변경할 수 없습니다.'});
      const color=/^#[0-9A-Fa-f]{6}$/.test(String(d.color||''))?String(d.color):null;
      const nu={id,name,role:d.role==='admin'?'admin':'staff',color,passwordHash:old?.passwordHash};
      if(d.password){if(String(d.password).length<4)return send(res,400,{error:'비밀번호는 4자 이상이어야 합니다.'});nu.passwordHash=await bcrypt.hash(String(d.password),12)}
      if(!nu.passwordHash)nu.passwordHash=await bcrypt.hash('1234',12);
      if(old){next.users[idx]=nu;if(old.name!==name){next.sales.forEach(x=>{if(x.inputter===old.name)x.inputter=name});next.expenses.forEach(x=>{if(x.type==='변동'&&x.class==='급여'&&x.item===old.name)x.item=name})}}
      else next.users.push(nu);
    }
    await persist(next);return send(res,200,{data:publicState(state),version})
  }
  return send(res,404,{error:'요청을 찾을 수 없습니다.'});
}
const server=http.createServer(async(req,res)=>{try{if(req.url.startsWith('/api/'))return await handle(req,res);let p=url.parse(req.url).pathname;if(p==='/')p='/index.html';if(p.includes('..'))return send(res,400,{error:'bad path'});staticFile(res,path.join(PUBLIC,p));}catch(e){console.error(e);if(!res.headersSent)send(res,500,{error:'서버 오류가 발생했습니다.'})}});
init().then(()=>server.listen(PORT,()=>console.log(`+BILITY 4차 server listening on ${PORT} (${pgEnabled?'PostgreSQL':'JSON'})`))).catch(e=>{console.error(e);process.exit(1)});
