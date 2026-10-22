import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import http from 'node:http';
import { Server } from 'socket.io';

const { Pool } = pg;
const required = ['DATABASE_URL', 'JWT_SECRET'];
for (const k of required) if (!process.env[k]) throw new Error(`Missing environment variable: ${k}`);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false }
});
const app = express();
const server = http.createServer(app);
const allowed = (process.env.FRONTEND_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
const io = new Server(server, {
  cors: { origin: allowed.length ? allowed : false, methods: ['GET','POST','PATCH','DELETE'] }
});
app.use(cors({ origin: allowed.length ? allowed : false }));
app.use(express.json({ limit: '2mb' }));

await pool.query(`
CREATE TABLE IF NOT EXISTS app_users (
 id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'User',
 password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_records (
 id TEXT NOT NULL, collection TEXT NOT NULL, payload JSONB NOT NULL,
 updated_by TEXT, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY(collection,id)
);
CREATE INDEX IF NOT EXISTS app_records_collection_updated ON app_records(collection, updated_at);
`);

const sign = u => jwt.sign({ sub: String(u.id), username: u.username, role: u.role, name: u.display_name }, process.env.JWT_SECRET, { expiresIn: '12h' });
function auth(req,res,next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i,'');
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({error:'جلسة غير صالحة، سجّل الدخول مجدداً'}); }
}
function admin(req,res,next) {
  if (req.user?.role !== 'Admin') return res.status(403).json({error:'غير مصرح'});
  next();
}
const safeCollections = new Set(['temps','ncr','returns','complaints','flow','batches','ops','veh','capa','recall','prods','rcv','mvs','lt','audit','settings']);
app.get('/health', (_req,res) => res.json({ok:true,service:'FrozenGuard API'}));

// Bootstrap one administrator through Render Shell or a one-time script; no public signup endpoint.
app.post('/api/auth/login', async (req,res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({error:'أدخل اسم المستخدم وكلمة المرور'});
  const q = await pool.query('SELECT * FROM app_users WHERE username=$1', [username]);
  const u = q.rows[0];
  if (!u || !(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({error:'بيانات الدخول غير صحيحة'});
  res.json({token:sign(u), user:{username:u.username,name:u.display_name,role:u.role}});
});

app.get('/api/collections/:collection', auth, async (req,res) => {
  const {collection}=req.params;
  if (!safeCollections.has(collection)) return res.status(400).json({error:'قسم غير صالح'});
  const q=await pool.query('SELECT id,payload,updated_at FROM app_records WHERE collection=$1 ORDER BY updated_at DESC',[collection]);
  res.json({records:q.rows.map(r=>({...r.payload,id:r.id,updated_at:r.updated_at}))});
});
app.put('/api/collections/:collection/:id', auth, async (req,res) => {
  const {collection,id}=req.params;
  if (!safeCollections.has(collection)) return res.status(400).json({error:'قسم غير صالح'});
  if (!req.body || typeof req.body!=='object' || Array.isArray(req.body)) return res.status(400).json({error:'سجل غير صالح'});
  const payload={...req.body,id};
  const q=await pool.query(
    `INSERT INTO app_records(id,collection,payload,updated_by,updated_at)
     VALUES($1,$2,$3,$4,now())
     ON CONFLICT(collection,id) DO UPDATE SET payload=EXCLUDED.payload,updated_by=EXCLUDED.updated_by,updated_at=now()
     RETURNING id,payload,updated_at`,
    [id,collection,payload,req.user.username]
  );
  const record={...q.rows[0].payload,updated_at:q.rows[0].updated_at};
  io.to(`collection:${collection}`).emit('record:changed',{collection,action:'upsert',record});
  res.json({record});
});
app.delete('/api/collections/:collection/:id', auth, async (req,res) => {
  const {collection,id}=req.params;
  if (!safeCollections.has(collection)) return res.status(400).json({error:'قسم غير صالح'});
  await pool.query('DELETE FROM app_records WHERE collection=$1 AND id=$2',[collection,id]);
  io.to(`collection:${collection}`).emit('record:changed',{collection,action:'delete',id});
  res.status(204).end();
});
io.use((socket,next)=>{
  try { socket.user=jwt.verify(socket.handshake.auth?.token,process.env.JWT_SECRET); next(); }
  catch { next(new Error('unauthorized')); }
});
io.on('connection',socket=>{
  socket.on('subscribe', collection=>{
    if (typeof collection==='string' && safeCollections.has(collection)) socket.join(`collection:${collection}`);
  });
});
const port=Number(process.env.PORT||10000);
server.listen(port,'0.0.0.0',()=>console.log(`FrozenGuard API listening on ${port}`));
