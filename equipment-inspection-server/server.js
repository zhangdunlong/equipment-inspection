#!/usr/bin/env node
'use strict';
/*
 * 设备点检巡检系统 —— 零依赖 Node.js 服务
 * 特点：
 *   1. 仅使用 Node 内置模块（http/fs/path/crypto），无需 npm install，开箱即用。
 *   2. 同时托管前端静态文件（public/）与全部 /api 接口。
 *   3. 数据持久化到本地 data/kv.json（兼容原 Cloudflare KV 的 key 结构）。
 *   4. 既可在 Linux/Windows 服务器上长期运行（配合 PM2/Nginx），也可在 Win10 上双击即用。
 *
 * 启动：  node server.js            （默认端口 8787）
 * 自定义端口：  PORT=9000 node server.js
 * 默认管理员：  admin（首次启动后请在管理后台修改密码）
 *
 * 2026-08-27 重构说明（行为不变）：
 *   - 原 550 行巨型 handleApi if 链 → 声明式路由表（routes）+ 独立 handler 函数
 *   - 原 needsAdmin 硬编码权限清单 → 路由声明中的 adminOnly 标记（单一信息源）
 *   - 重复逻辑提取：verifySigner / resolveEndDay / buildBySn / monthDays / replaceMonthAbnormal
 *   - 所有 API 路径、方法、状态码、响应字段保持完全兼容
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { webcrypto } = crypto;
const subtle = webcrypto.subtle;

const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA_DIR = path.join(ROOT, 'data');
const DATA_FILE = path.join(DATA_DIR, 'kv.json');
const PORT = parseInt(process.env.PORT || '8787', 10);

// 系统版本号（单一信息源）：与《交接文档.md》头部版本保持一致，每次迭代发布时同步修改此处。
// 前端各页面通过 GET /api/version 拉取并显示，无需改前端。
// 全局版本号（语义化版本 主版本.次版本.修订号）：接口破坏性变更→主版本+1；新功能→次版本+1；bug 修复→修订号+1。只改这里，前端自动跟随
const APP_VERSION = 'v1.2.7';
const APP_VERSION_DATE = '2026-09-14';

// 安全：PEPPER / SECRET 原本硬编码于源码，开源前已移除。
// 现改为首次启动时随机生成并持久化到 data/config.json（该文件已被 .gitignore 排除，不会随源码泄露）。
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const ADMIN_COOKIE = 'admin_token';
let PEPPER = '';
let SECRET = '';

function ensureConfig() {
  let cfg = {};
  try { cfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch {}
  let changed = false;
  if (!cfg.PEPPER) { cfg.PEPPER = crypto.randomBytes(32).toString('hex'); changed = true; }
  if (!cfg.SECRET) { cfg.SECRET = crypto.randomBytes(32).toString('hex'); changed = true; }
  if (changed) {
    try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2)); } catch (e) {}
  }
  PEPPER = cfg.PEPPER;
  SECRET = cfg.SECRET;
}

// ===================== 数据存储（模拟 KV） =====================
// store 结构与原 Cloudflare KV 命名空间 INSPECTION_DATA 保持一致：
// { admin, devices, templates, signers, inspections }
let store = { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], envRecords: [] };

function loadStore() {
  try {
    const o = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    store = Object.assign({ admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], envRecords: [] }, o);
  } catch (e) {
    // 首次运行或文件损坏：使用内存默认空数据
  }
}

// 房间数据初始化：老数据文件没有 rooms 键时，从设备台账的 location 自动推导一次
function seedRooms() {
  const rooms = kvget('rooms', []);
  if (Array.isArray(rooms) && rooms.length) return;
  const seen = [];
  allDevices().forEach(d => {
    const loc = (d.location || '').trim();
    if (loc && seen.indexOf(loc) < 0) seen.push(loc);
  });
  if (seen.length) {
    kvset('rooms', seen.map(name => ({ name, desc: '', group: '' })));
    console.log('[初始化] 已从设备台账推导出 ' + seen.length + ' 个房间: ' + seen.join(' / '));
  }
}

let saveTimer = null;
let persistP = Promise.resolve();
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    persistP = persistP.then(async () => {
      try {
        await fs.promises.mkdir(DATA_DIR, { recursive: true });
        await fs.promises.writeFile(DATA_FILE, JSON.stringify(store, null, 2), 'utf8');
      } catch (e) {
        console.error('[保存失败]', e && e.message);
      }
    });
  }, 200);
}

const kvget = (key, def) => (store[key] === undefined ? def : store[key]);
const kvset = (key, val) => { store[key] = val; scheduleSave(); };

// 用户名允许中文/英文/数字及常用符号（2-32 位）。
// 中文经 adminCookie() 的 encodeURIComponent 后即可安全写进 Set-Cookie（HTTP 头仅支持 ASCII）；
// 解析侧 getLoginUser 用 lastIndexOf('.') 切分，避免用户名本身含点时错位。
const USERNAME_RE = /^[\u4e00-\u9fa5A-Za-z0-9._@-]{2,32}$/;
const validUsername = (s) => typeof s === 'string' && USERNAME_RE.test(s);

// ===================== 哈希 / 签名 =====================
async function sha256(s) {
  const d = await subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hmac(key, msg) {
  const k = await subtle.importKey('raw', new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function buildToken(user) { return user + '.' + await hmac(SECRET, user); }
function uuid() {
  try { return crypto.randomUUID(); } catch { return 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2); }
}

// ===================== 响应 / Cookie =====================
function sendJson(res, data, status = 200, extra = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, Object.assign({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  }, extra));
  res.end(body);
}
// 统一错误响应：{ error: msg }
function fail(res, msg, status = 400) {
  return sendJson(res, { error: msg }, status);
}
function getCookie(req, name) {
  const c = req.headers.cookie || '';
  for (const part of c.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return part.slice(i + 1).trim(); }
    }
  }
  return null;
}
function adminCookie(token) {
  // 兜底 encode：HTTP Cookie 标准只支持 ASCII + %XX。即使有非 ASCII 也不会抛 "Invalid character in header content"
  return `${ADMIN_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
}

// ===================== 鉴权 =====================
// 兼容旧逻辑：无 users 数据时的默认管理员（PEPPER 生成 admin/admin123）
async function getAdmin() {
  if (store.admin) return store.admin;
  return { username: 'admin', password_hash: await sha256('admin123' + PEPPER) };
}
// 解析登录 cookie → 返回启用用户（null 表示未登录/无效）
async function getLoginUser(req) {
  const t = getCookie(req, ADMIN_COOKIE);
  if (!t) return null;
  // 用 lastIndexOf：用户名本身可能含点，hmac 为 64 位 hex 不含点，应切在最后一个点之后
  const i = t.lastIndexOf('.');
  if (i < 0) return null;
  const u = t.slice(0, i), sig = t.slice(i + 1);
  if (sig !== await hmac(SECRET, u)) return null;
  const users = kvget('users', []);
  return users.find(x => x.username === u && x.active) || null;
}
// 管理员角色：已登录且 role === 'admin'
async function isAdmin(req) {
  const u = await getLoginUser(req);
  return !!(u && u.role === 'admin');
}
// 确保 users 初始化：首次启动 seed 一个 admin 用户（沿用原 admin 密码或默认 admin123）
async function ensureUsers() {
  const users = kvget('users', []);
  if (users && users.length) return;
  const admin = kvget('admin', null);
  const ph = (admin && admin.password_hash) || await sha256('admin123' + PEPPER);
  kvset('users', [{ id: 'u-admin', username: 'admin', name: '管理员', password_hash: ph, role: 'admin', active: true, created_at: new Date().toISOString() }]);
}

// ===================== 业务助手 =====================
const allDevices = () => kvget('devices', []);
const allTemplates = () => kvget('templates', []);
const allSigners = () => kvget('signers', []);
const allInspections = () => kvget('inspections', []);
const allAbnormal = () => kvget('abnormalRecords', []);

async function deviceItems(dev) {
  if (!dev || !dev.template_id) return [];
  const tpls = allTemplates();
  const t = tpls.find(t => t.id === dev.template_id);
  return t ? (t.items || []) : [];
}
function readBody(req) {
  return new Promise((resolve) => {
    let buf = '';
    req.on('data', c => { buf += c; if (buf.length > 5e6) req.destroy(); });
    req.on('end', () => { try { resolve(buf ? JSON.parse(buf) : {}); } catch { resolve({}); } });
    req.on('error', () => resolve({}));
  });
}
// 由 bySn 汇总整机状态：任一检查项为 ng 则整机 ng，否则 ok
function statusFromBySn(bySn) {
  for (const k in bySn) if (bySn[k] === 'ng') return 'ng';
  return 'ok';
}
// 批量构建 bySn：每台设备的每个检查项统一标记为 status
function buildBySn(items, status) {
  const bySn = {};
  items.forEach(it => { bySn[it.sn] = status; });
  return bySn;
}
// 日期工具：返回 YYYY-MM-DD 的今天、判断是否为未来日期、返回 YYYY-MM 的当前月
function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function isFutureDate(ds) { return String(ds) > todayStr(); }
function currentMonthStr() { return todayStr().slice(0, 7); }
// 生成某月 1 日 ~ endDay 的日期列表（YYYY-MM-DD）
function monthDays(month, endDay) {
  const [yy, mm] = month.split('-');
  const days = [];
  for (let day = 1; day <= endDay; day++) {
    days.push(`${yy}-${mm}-${String(day).padStart(2, '0')}`);
  }
  return days;
}
// 解析整月操作的截止日：默认该月总天数；可传 end_day（1~dim）；当前月时截到今天（禁止未来日期）
function resolveEndDay(month, input) {
  const [yy, mm] = month.split('-');
  const dim = new Date(+yy, +mm, 0).getDate();
  let endDay = dim;
  if (input !== undefined && input !== null && input !== '') {
    endDay = parseInt(input, 10);
    if (isNaN(endDay) || endDay < 1 || endDay > dim) {
      return { error: `截止日期无效，应在 1 至 ${dim} 之间` };
    }
  }
  if (month === currentMonthStr()) {
    const tDay = +todayStr().slice(8, 10);
    if (endDay > tDay) endDay = tDay;
  }
  return { endDay };
}
async function upsertInspection(rec, extra) {
  const list = allInspections();
  const idx = list.findIndex(r => r.device_id === rec.device_id && r.inspect_date === rec.inspect_date);
  const record = Object.assign({}, rec, extra);
  if (idx >= 0) { list[idx] = record; kvset('inspections', list); return 'updated'; }
  list.push(record); kvset('inspections', list); return 'created';
}
// 校验签名人身份：返回 { signer } 或 { error, status }
async function verifySigner(body) {
  const signer = allSigners().find(s => s.id === body.signer_id);
  if (!signer) return { error: '签名人不存在' };
  if (await sha256((body.password || '') + PEPPER) !== signer.password_hash) return { error: '签名密码错误', status: 401 };
  return { signer };
}
// 点检时间戳策略：
// - 手动单台/单日保存（/api/inspect/month、/api/inspect/day-sig）：直接用真实时间 new Date().toISOString()
// - 一键点检（批量/整月）：随机落在该日 08:00~10:00（本地，工厂一般早上 8~10 点完成点检）；
//   当天上限截到当前时刻，绝不生成「未来」时间戳
function randMorningTime(ds) {
  const [yy, mm, dd] = String(ds).split('-').map(Number);
  const dayStart = new Date(yy, mm - 1, dd, 0, 0, 0, 0).getTime(); // 该日 00:00 本地
  const start = dayStart + 8 * 3600 * 1000;                        // 08:00 本地
  let end = dayStart + 10 * 3600 * 1000;                           // 10:00 本地
  const now = Date.now();
  if (ds === todayStr()) end = Math.min(end, now);                 // 今天：不生成未来时间
  if (end < start) return new Date(now).toISOString();             // 现在早于 08:00：退化为当前时刻
  return new Date(start + Math.floor(Math.random() * (end - start))).toISOString();
}
// 按 设备+月份 整体替换异常明细（保证删除已不存在的异常条目）
const ABN_FIELDS = ['sn', 'freq', 'date', 'content', 'abnormal', 'handle', 'handler', 'handle_date'];
function replaceMonthAbnormal(deviceId, month, abnList) {
  let recs = allAbnormal().filter(r => !(r.device_id === deviceId && r.month === month));
  abnList.forEach(a => {
    const item = { id: a.id || uuid(), device_id: deviceId, month };
    ABN_FIELDS.forEach(k => { if (a[k] !== undefined) item[k] = a[k]; });
    recs.push(item);
  });
  kvset('abnormalRecords', recs);
}

// ===================== API 处理器 =====================
// 每个 handler 接收 ctx = { req, res, params, query, body }
// 分组：鉴权 / 用户 / 签名人 / 模板 / 设备 / 点检记录 / 点检操作 / 报表视图

// ---------- 鉴权 ----------
// GET /api/admin/me —— 当前登录信息（未登录返回 ok:false）
async function handleMe(ctx) {
  const u = await getLoginUser(ctx.req);
  return sendJson(ctx.res, { ok: !!u, username: u ? u.username : '', name: u ? u.name : '', role: u ? u.role : '' });
}
// POST /api/admin/login —— 登录（成功后种 cookie）
async function handleLogin(ctx) {
  const b = ctx.body;
  const users = kvget('users', []);
  const user = users.find(x => x.username === b.username && x.active);
  if (user) {
    const ph = await sha256((b.password || '') + PEPPER);
    if (ph === user.password_hash) {
      const token = await buildToken(user.username);
      return sendJson(ctx.res, { ok: true, username: user.username, name: user.name, role: user.role },
        200, { 'Set-Cookie': adminCookie(token) });
    }
  }
  return fail(ctx.res, '账号或密码错误', 401);
}
// POST /api/admin/changepw —— 修改当前登录用户密码（多用户各改各的）
async function handleChangePw(ctx) {
  const b = ctx.body;
  if (!b.password || String(b.password).length < 4) return fail(ctx.res, '密码至少 4 位');
  const me = await getLoginUser(ctx.req);
  if (!me) return fail(ctx.res, '未登录或登录已失效', 401);
  const users = kvget('users', []);
  const u = users.find(x => x.id === me.id);
  if (!u) return fail(ctx.res, '用户不存在', 404);
  u.password_hash = await sha256(b.password + PEPPER);
  kvset('users', users);
  return sendJson(ctx.res, { ok: true });
}

// ---------- 用户管理（仅管理员） ----------
// GET /api/users —— 用户列表（不含敏感字段）
async function handleListUsers(ctx) {
  const users = kvget('users', []);
  return sendJson(ctx.res, users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active })));
}
// POST /api/users —— 新增用户
async function handleCreateUser(ctx) {
  const b = ctx.body;
  const username = (b.username || '').trim();
  if (!username || !b.password) return fail(ctx.res, '用户名与密码必填');
  if (!validUsername(username)) return fail(ctx.res, '用户名只能为 2-32 位英文、数字、下划线、点、连字符（登录账号必须为 ASCII）');
  if (String(b.password).length < 4) return fail(ctx.res, '密码至少 4 位');
  const users = kvget('users', []);
  if (users.some(u => u.username === username)) return fail(ctx.res, '用户名已存在');
  users.push({ id: uuid(), username, name: (b.name || '').trim() || username,
    password_hash: await sha256(b.password + PEPPER),
    role: b.role === 'admin' ? 'admin' : 'user', active: b.active === false ? false : true,
    created_at: new Date().toISOString() });
  kvset('users', users);
  return sendJson(ctx.res, { ok: true });
}
// PUT /api/users/:id —— 编辑用户
async function handleUpdateUser(ctx) {
  const b = ctx.body;
  const users = kvget('users', []);
  const u = users.find(x => x.id === ctx.params.id);
  if (!u) return fail(ctx.res, '用户不存在', 404);
  const me = await getLoginUser(ctx.req);
  if (me && me.id === u.id && b.active === false) return fail(ctx.res, '不能停用当前登录账号');
  if (b.username && b.username.trim()) {
    const u2 = b.username.trim();
    if (!validUsername(u2)) return fail(ctx.res, '用户名只能为 2-32 位英文、数字、下划线、点、连字符');
    if (users.some(x => x.id !== u.id && x.username === u2)) return fail(ctx.res, '用户名已存在');
    u.username = u2;
  }
  if ('name' in b) u.name = (b.name || '').trim() || u.username;
  if (b.password) {
    if (String(b.password).length < 4) return fail(ctx.res, '密码至少 4 位');
    u.password_hash = await sha256(b.password + PEPPER);
  }
  if (b.role === 'admin' || b.role === 'user') u.role = b.role;
  if (typeof b.active === 'boolean') u.active = b.active;
  kvset('users', users);
  return sendJson(ctx.res, { ok: true });
}
// DELETE /api/users/:id —— 删除用户
async function handleDeleteUser(ctx) {
  const me = await getLoginUser(ctx.req);
  if (me && me.id === ctx.params.id) return fail(ctx.res, '不能删除当前登录账号');
  const users = kvget('users', []).filter(x => x.id !== ctx.params.id);
  kvset('users', users);
  return sendJson(ctx.res, { ok: true });
}

// ---------- 签名人员 ----------
// 签名数据模型（v1.3.0 起）：
//   signature_image    横版签名（横排拼装；主用，也是历史数据兼容字段）
//   signature_image_v  竖版签名（竖排拼装）
//   sig_chars          逐字原图数组（每个字一张，用于再次编辑 / 重新拼装）
//   sig_dir            默认方向 'h' | 'v'（用于展示与回退）
// 约定：写入点检记录时只落一份快照（横版优先），避免 kv.json 体积翻倍。
const SIG_MAX_CHARS = 12;
function normSigChars(v) {
  if (!Array.isArray(v)) return null;
  return v.slice(0, SIG_MAX_CHARS).map(x =>
    (typeof x === 'string' && /^data:image\//.test(x)) ? x.slice(0, 200000) : '');
}
function normSigImage(v) {
  return (typeof v === 'string' && /^data:image\//.test(v)) ? v.slice(0, 200000) : null;
}
function normSigDir(v) { return v === 'v' ? 'v' : (v === 'h' ? 'h' : 'auto'); }
// 落记录快照时用：横版优先，没有横版才退回竖版（老数据）
function pickSigImage(s) {
  if (!s) return null;
  return s.signature_image || s.signature_image_v || null;
}
// GET /api/signers/public —— 启用中的签名人（点检作业页可选，公开）
async function handlePublicSigners(ctx) {
  const list = allSigners();
  return sendJson(ctx.res, list.filter(s => s.active).map(s => ({ id: s.id, name: s.name,
    signature_image: s.signature_image || null,
    signature_image_v: s.signature_image_v || null,
    sig_dir: normSigDir(s.sig_dir) })));
}
// GET /api/signers —— 签名人管理列表（仅管理员）
async function handleListSigners(ctx) {
  const list = allSigners();
  return sendJson(ctx.res, list.map(s => ({ id: s.id, name: s.name, active: !!s.active,
    has_sig: !!s.signature_image, has_sig_v: !!s.signature_image_v,
    sig_dir: normSigDir(s.sig_dir), chars: (s.sig_chars || []).length })));
}
// POST /api/signers —— 新增签名人
async function handleCreateSigner(ctx) {
  const b = ctx.body;
  if (!b.name || !b.password) return fail(ctx.res, '姓名与密码必填');
  const list = allSigners();
  list.push({ id: uuid(), name: b.name, active: true, password_hash: await sha256(b.password + PEPPER),
    signature_image: normSigImage(b.signature_image),
    signature_image_v: normSigImage(b.signature_image_v),
    sig_chars: normSigChars(b.sig_chars) || [],
    sig_dir: normSigDir(b.sig_dir) });
  kvset('signers', list);
  return sendJson(ctx.res, { ok: true });
}
// GET /api/signers/:id/sig —— 取签名图片（公开）
async function handleGetSignerSignature(ctx) {
  const s = allSigners().find(x => x.id === ctx.params.id);
  if (!s) return sendJson(ctx.res, { image: null, image_h: null, image_v: null, chars: [], dir: 'h' });
  return sendJson(ctx.res, {
    image: pickSigImage(s),          // 兼容旧调用方（横版优先）
    image_h: s.signature_image || null,
    image_v: s.signature_image_v || null,
    chars: s.sig_chars || [],
    dir: normSigDir(s.sig_dir)
  });
}
// PUT /api/signers/:id —— 编辑签名人
async function handleUpdateSigner(ctx) {
  const b = ctx.body;
  const list = allSigners();
  const s = list.find(x => x.id === ctx.params.id);
  if (!s) return fail(ctx.res, '签名人不存在', 404);
  if (typeof b.name === 'string' && b.name.trim()) s.name = b.name.trim().slice(0, 40);
  if (typeof b.active === 'boolean') s.active = b.active;
  if (b.password) s.password_hash = await sha256(b.password + PEPPER);
  if ('signature_image' in b) s.signature_image = normSigImage(b.signature_image);
  if ('signature_image_v' in b) s.signature_image_v = normSigImage(b.signature_image_v);
  if ('sig_chars' in b) s.sig_chars = normSigChars(b.sig_chars) || [];
  if ('sig_dir' in b) s.sig_dir = normSigDir(b.sig_dir);
  kvset('signers', list);
  return sendJson(ctx.res, { ok: true });
}
// DELETE /api/signers/:id —— 删除签名人
async function handleDeleteSigner(ctx) {
  const list = allSigners().filter(x => x.id !== ctx.params.id);
  kvset('signers', list);
  return sendJson(ctx.res, { ok: true });
}

// ---------- 模板 ----------
// GET /api/templates —— 模板列表（公开，点检作业需读取）
// use_count = 引用该模板的设备数（后台用来提示「改这个模板会影响 N 台设备」）
async function handleListTemplates(ctx) {
  const cnt = {};
  allDevices().forEach(d => { if (d.template_id) cnt[d.template_id] = (cnt[d.template_id] || 0) + 1; });
  const list = allTemplates().map(t => Object.assign({}, t, { use_count: cnt[t.id] || 0 }));
  return sendJson(ctx.res, list);
}
// POST /api/templates —— 新建模板
async function handleCreateTemplate(ctx) {
  const b = ctx.body;
  if (!b.key || !b.equip_name) return fail(ctx.res, '模板标识与设备名称必填');
  const tpls = allTemplates();
  const t = { id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '', source_file: '', items: [] };
  tpls.push(t); kvset('templates', tpls);
  return sendJson(ctx.res, t);
}
// POST /api/templates/:id/items —— 追加检查项
async function handleAddTemplateItem(ctx) {
  const b = ctx.body;
  if (!b.content) return fail(ctx.res, '检查内容必填');
  const tpls = allTemplates();
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return fail(ctx.res, '模板不存在', 404);
  t.items = t.items || [];
  t.items.push({ sn: t.items.length + 1, content: b.content, frequency: b.frequency || '' });
  kvset('templates', tpls);
  return sendJson(ctx.res, { ok: true });
}
// PUT /api/templates/:id —— 编辑模板表头
// 可改：key（模板标识）/ equip_name（设备名称）/ model（型号）/ form_code（表单编号）
//       form_rev（版本，如 Rev.A1）/ title（中文标题）/ title_en（英文标题）
//       source_file（来源文件）/ note（备注 Note）
async function handleUpdateTemplate(ctx) {
  const b = ctx.body || {};
  const tpls = allTemplates();
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return fail(ctx.res, '模板不存在', 404);
  if (b.key !== undefined) {
    const nk = String(b.key).trim();
    if (!nk) return fail(ctx.res, '模板标识 key 不能为空');
    if (tpls.some(x => x.id !== t.id && String(x.key).trim() === nk)) {
      return fail(ctx.res, `模板标识「${nk}」已被其它模板占用`, 409);
    }
    t.key = nk;
  }
  if (b.equip_name !== undefined) {
    const en = String(b.equip_name).trim();
    if (!en) return fail(ctx.res, '设备名称不能为空');
    t.equip_name = en;
  }
  ['model', 'note', 'form_code', 'form_rev', 'title', 'title_en', 'source_file'].forEach(f => {
    if (b[f] !== undefined) t[f] = String(b[f]).trim();
  });
  kvset('templates', tpls);
  return sendJson(ctx.res, { ok: true, template: t });
}

// PUT /api/templates/:id/items —— 整体替换检查项（增 / 删 / 改 / 上下移）
// body: { items:[{sn, content, frequency}] }，sn 为「原编号」，新增行传 null/不传
// 说明：sn 是历史点检数据（inspections.bySn）的绑定键。替换后统一重排为 1..n，
//       并把引用该模板的全部设备既有记录按 旧sn → 新sn 迁移，避免数据错位。
async function handleSaveTemplateItems(ctx) {
  const b = ctx.body || {};
  const raw = Array.isArray(b.items) ? b.items : [];
  const tpls = allTemplates();
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return fail(ctx.res, '模板不存在', 404);
  const oldItems = Array.isArray(t.items) ? t.items : [];

  const items = []; const map = {};
  for (const it of raw) {
    const content = ((it && it.content) || '').toString().trim();
    if (!content) continue;                                  // 内容为空 = 删除该行
    const frequency = ((it && it.frequency) || '').toString().trim();
    const newSn = items.length + 1;
    const rawSn = it && it.sn;
    const oldSn = (rawSn === undefined || rawSn === null || rawSn === '') ? null : Number(rawSn);
    if (oldSn !== null && !Number.isNaN(oldSn)) map[oldSn] = newSn;
    items.push({ sn: newSn, content, frequency });
  }
  if (!items.length) return fail(ctx.res, '至少保留一条检查项');

  const devIds = new Set(allDevices().filter(d => d.template_id === t.id).map(d => d.id));
  t.items = items;
  kvset('templates', tpls);

  // 每次保存都对历史记录做一次「键对齐」（幂等）：把 bySn 的键从 旧sn 搬到 新sn，
  // 丢掉模板里已不存在的键。这样无论模板怎么改，记录键集合始终与模板一致，不会错位。
  let migrated = 0, dropped = 0;
  if (devIds.size) {
    const insp = allInspections();
    for (const r of insp) {
      if (!devIds.has(r.device_id) || !r.bySn) continue;
      const nb = {}; let ch = false;
      for (const k in map) {
        const v = r.bySn[k];
        if (v !== undefined && v !== 'none' && v !== '') { nb[map[k]] = v; if (map[k] !== Number(k)) ch = true; }
      }
      for (const k in r.bySn) { if (!(k in map)) { ch = true; dropped++; } }
      if (ch) { r.bySn = nb; migrated++; }
    }
    if (migrated) kvset('inspections', insp);
  }
  return sendJson(ctx.res, { ok: true, count: items.length, migrated, dropped, devices: devIds.size });
}

// POST /api/templates/:id/duplicate —— 复制模板（供单台设备独立定制）
async function handleDuplicateTemplate(ctx) {
  const b = ctx.body || {};
  const tpls = allTemplates();
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return fail(ctx.res, '模板不存在', 404);
  let key = (b.key ? String(b.key) : (String(t.key) + '-副本')).trim();
  if (tpls.some(x => String(x.key).trim() === key)) key = key + '-' + Date.now().toString().slice(-4);
  const nt = JSON.parse(JSON.stringify(t));
  nt.id = uuid();
  nt.key = key;
  if (b.equip_name !== undefined && String(b.equip_name).trim()) nt.equip_name = String(b.equip_name).trim();
  delete nt.use_count;
  tpls.push(nt); kvset('templates', tpls);
  return sendJson(ctx.res, { ok: true, template: nt });
}

// DELETE /api/templates/:id —— 删除模板（仅当没有设备引用它）
async function handleDeleteTemplate(ctx) {
  const tpls = allTemplates();
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return fail(ctx.res, '模板不存在', 404);
  const used = allDevices().filter(d => d.template_id === t.id).length;
  if (used) return fail(ctx.res, `该模板仍被 ${used} 台设备使用，请先给这些设备换模板`, 409);
  kvset('templates', tpls.filter(x => x.id !== t.id));
  return sendJson(ctx.res, { ok: true });
}

// POST /api/admin/import-template —— 由上传的表格（CSV/TSV）解析生成点检模板
// body: { key, equip_name, model, source_file, overwrite, items:[{content,frequency}] }
async function handleImportTemplate(ctx) {
  const b = ctx.body;
  if (!b.key || !b.equip_name) return fail(ctx.res, '模板标识与设备名称必填');
  const items = Array.isArray(b.items) ? b.items : [];
  const parsed = [];
  for (const it of items) {
    const content = (it && it.content || '').toString().trim();
    if (!content) continue;
    parsed.push({ content, frequency: (it.frequency || '').toString().trim() });
  }
  if (parsed.length === 0) return fail(ctx.res, '未解析到任何检查项，请检查上传内容');
  const tpls = allTemplates();
  const exist = tpls.find(x => x.key === b.key);
  if (exist && !b.overwrite) {
    return fail(ctx.res, `模板标识「${b.key}」已存在，如需覆盖其检查项请勾选“覆盖”`, 409);
  }
  const buildItems = () => parsed.map((p, i) => ({ sn: i + 1, content: p.content, frequency: p.frequency }));
  if (exist) {
    exist.equip_name = b.equip_name;
    exist.model = b.model || '';
    exist.source_file = b.source_file || '';
    exist.items = buildItems();
    kvset('templates', tpls);
    return sendJson(ctx.res, { ok: true, updated: true, id: exist.id, key: exist.key, itemsCount: parsed.length });
  }
  const t = {
    id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '',
    source_file: b.source_file || '', items: buildItems()
  };
  tpls.push(t); kvset('templates', tpls);
  return sendJson(ctx.res, { ok: true, updated: false, id: t.id, key: t.key, itemsCount: parsed.length });
}

// ---------- 设备 ----------
// GET /api/devices —— 设备列表（公开）
async function handleListDevices(ctx) {
  return sendJson(ctx.res, allDevices());
}
// POST /api/devices —— 新增单台设备
async function handleCreateDevice(ctx) {
  const b = ctx.body;
  if (!b.no) return fail(ctx.res, '设备编号必填');
  const list = allDevices();
  if (list.some(d => d.no === b.no)) return fail(ctx.res, '编号已存在');
  const d = { id: uuid(), no: b.no, name: b.name || '', model: b.model || '',
    template_id: b.template_id || null, location: b.location || '' };
  list.push(d); kvset('devices', list);
  return sendJson(ctx.res, d);
}
// POST /api/devices/batch —— 按数量批量生成设备（编号 001/002/...）
async function handleBatchCreateDevices(ctx) {
  const b = ctx.body;
  const count = parseInt(b.count, 10);
  if (!count || count < 1) return fail(ctx.res, '数量无效');
  const tpls = allTemplates();
  const t = b.template_id ? tpls.find(x => x.id === b.template_id) : null;
  const list = allDevices();
  let added = 0;
  for (let i = 0; i < count; i++) {
    const no = String(i + 1).padStart(3, '0');
    if (list.some(d => d.no === no)) continue;
    list.push({ id: uuid(), no, name: t ? t.equip_name : ('设备 ' + no), model: t ? (t.model || '') : '',
      template_id: t ? t.id : null, location: '' });
    added++;
  }
  kvset('devices', list);
  return sendJson(ctx.res, { count: added });
}
// POST /api/devices/import —— 文本导入（每行：编号,型号,名称 或 编号,名称 或 编号）
async function handleImportDevices(ctx) {
  const b = ctx.body;
  const text = b.text || '';
  const list = allDevices();
  let added = 0, skipped = 0;
  for (const line of text.split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    const parts = s.split(',').map(x => x.trim());
    let no, model = '', name;
    if (parts.length >= 3) { [no, model, name] = parts; }
    else if (parts.length === 2) { [no, name] = parts; }
    else { no = parts[0]; name = ''; }
    if (!no) { skipped++; continue; }
    if (list.some(d => d.no === no)) { skipped++; continue; }
    list.push({ id: uuid(), no, name: name || '', model, template_id: null, location: '' });
    added++;
  }
  kvset('devices', list);
  return sendJson(ctx.res, { added, skipped });
}
// POST /api/devices/batch-delete —— 批量删除设备（连带删除其点检记录）
async function handleBatchDeleteDevices(ctx) {
  const ids = (ctx.body.ids || []);
  let devices = allDevices();
  const before = devices.length;
  devices = devices.filter(d => !ids.includes(d.id));
  const deleted = before - devices.length;
  kvset('devices', devices);
  kvset('inspections', allInspections().filter(r => !ids.includes(r.device_id)));
  return sendJson(ctx.res, { deleted, requested: ids.length });
}
// PUT /api/devices/:id —— 编辑设备
async function handleUpdateDevice(ctx) {
  const b = ctx.body;
  const list = allDevices();
  const d = list.find(x => x.id === ctx.params.id);
  if (!d) return fail(ctx.res, '设备不存在', 404);
  d.no = b.no || d.no; d.name = b.name || ''; d.model = b.model || '';
  d.template_id = b.template_id || null; d.location = b.location || '';
  kvset('devices', list);
  return sendJson(ctx.res, d);
}
// DELETE /api/devices/:id —— 删除设备（连带删除其点检记录）
async function handleDeleteDevice(ctx) {
  kvset('devices', allDevices().filter(x => x.id !== ctx.params.id));
  kvset('inspections', allInspections().filter(r => r.device_id !== ctx.params.id));
  return sendJson(ctx.res, { ok: true });
}

// ---------- 点检记录（查询/删除） ----------
// GET /api/inspections —— 点检记录查询（device_id 或 date 过滤，按日期倒序）
async function handleListInspections(ctx) {
  const q = ctx.query;
  const devId = q.get('device_id');
  const date = q.get('date');
  const devices = allDevices();
  const dmap = {}; devices.forEach(d => dmap[d.id] = d);
  let list = allInspections();
  if (devId) list = list.filter(r => { const d = dmap[r.device_id]; return d && (String(d.no) === devId || String(d.id) === devId); });
  if (date) list = list.filter(r => r.inspect_date === date);
  list.sort((a, b) => (a.inspect_date < b.inspect_date ? 1 : -1));
  return sendJson(ctx.res, list.map(r => {
    const d = dmap[r.device_id] || {};
    return { id: r.device_id + '_' + r.inspect_date, inspect_date: r.inspect_date, no: d.no || '', name: d.name || '',
      status: r.status, signed_by: r.signed_by || '', abnormal_note: r.abnormal_note || '' };
  }));
}
// DELETE /api/inspections/:id —— 删除单条记录（id = device_id_inspect_date）
async function handleDeleteInspection(ctx) {
  const key = decodeURIComponent(ctx.params.id);
  const [did, ...rest] = key.split('_');
  const date = rest.join('_');
  const list = allInspections();
  const before = list.length;
  const remaining = list.filter(r => !(String(r.device_id) === did && r.inspect_date === date));
  kvset('inspections', remaining);
  return sendJson(ctx.res, { ok: before !== remaining.length });
}
// POST /api/inspections/batch-delete —— 批量删除记录（ids = ["device_id_inspect_date", ...]）
async function handleBatchDeleteInspections(ctx) {
  const ids = Array.isArray(ctx.body.ids) ? ctx.body.ids.map(String) : [];
  if (!ids.length) return fail(ctx.res, '未选择要删除的记录');
  const dropPairs = new Set(ids.map(k => {
    const i = k.indexOf('_');
    return i > 0 ? k.slice(0, i) + '|' + k.slice(i + 1) : '';
  }).filter(Boolean));
  const list = allInspections();
  const before = list.length;
  const remaining = list.filter(r => !dropPairs.has(String(r.device_id) + '|' + r.inspect_date));
  kvset('inspections', remaining);
  return sendJson(ctx.res, { ok: true, deleted: before - remaining.length });
}

// ---------- 点检操作 ----------
// POST /api/inspect/batch —— 一键点检当日全部设备（管理员；签名人密码校验）
async function handleInspectBatch(ctx) {
  const b = ctx.body;
  if (isFutureDate(b.date)) return fail(ctx.res, '不能点检未来日期');
  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  const abnormalMap = {};
  (b.devices || []).forEach(x => { abnormalMap[x.device_id] = x.note || ''; });
  const devices = allDevices();
  for (const d of devices) {
    const items = await deviceItems(d);
    const isAbn = d.id in abnormalMap;
    // 每台设备取该日 08:00~10:00 的随机时刻（当天不超当前时间），大屏体现自然时间差且无未来时间
    await upsertInspection({ device_id: d.id, inspect_date: b.date },
      { status: isAbn ? 'ng' : 'ok', signed_by: signer.name, signer_id: signer.id,
        signature_image: pickSigImage(signer), abnormal_note: isAbn ? abnormalMap[d.id] : '',
        bySn: buildBySn(items, isAbn ? 'ng' : 'ok'), signed_at: randMorningTime(b.date) });
  }
  return sendJson(ctx.res, { signed: devices.length, signer: signer.name });
}
// POST /api/inspect/day-sig —— 单台单日签到（点击签名格的 ＋）
// 只写该日的签名信息；若当日尚无点检记录则按模板初始化为正常(ok)，使"签到"等价于完成当日点检
async function handleDaySign(ctx) {
  const b = ctx.body;
  if (!b.device_id || !b.date || !b.signer_id) return fail(ctx.res, '缺少参数');
  if (isFutureDate(b.date)) return fail(ctx.res, '不能签到未来日期');
  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  const dev = allDevices().find(d => d.id === b.device_id);
  if (!dev) return fail(ctx.res, '设备不存在');
  const items = await deviceItems(dev);
  const existing = allInspections().find(r => r.device_id === b.device_id && r.inspect_date === b.date);
  let bySn = {};
  if (existing && existing.bySn) {
    bySn = existing.bySn;          // 已有点检结果则保留
  } else {
    bySn = buildBySn(items, 'ok'); // 否则按模板初始化为正常
  }
  const r = await upsertInspection(
    { device_id: b.device_id, inspect_date: b.date },
    { status: statusFromBySn(bySn), signed_by: signer.name, signer_id: signer.id,
      signature_image: pickSigImage(signer),
      abnormal_note: (existing && existing.abnormal_note) || '',
      bySn, signed_at: new Date().toISOString() });
  return sendJson(ctx.res, { ok: true, created: r === 'created' });
}
// POST /api/inspect/month —— 单台整月保存（含异常明细，按 设备+月份 整体替换）
async function handleInspectMonth(ctx) {
  const b = ctx.body;
  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  let created = 0, updated = 0;
  const days = b.days || {};
  for (const dd in days) {
    if (isFutureDate(dd)) continue; // 禁止保存未来日期的点检
    const cell = days[dd];
    const bySn = cell.bySn || {};
    const r = await upsertInspection({ device_id: b.device_id, inspect_date: dd },
      { status: statusFromBySn(bySn), signed_by: signer.name, signer_id: signer.id,
        signature_image: pickSigImage(signer), abnormal_note: cell.abnormal_note || '',
        bySn, signed_at: new Date().toISOString() });
    if (r === 'created') created++; else updated++;
  }
  replaceMonthAbnormal(b.device_id, b.month, Array.isArray(b.abnormal) ? b.abnormal : []);
  return sendJson(ctx.res, { created, updated, abnormal: (Array.isArray(b.abnormal) ? b.abnormal : []).length });
}

// ---------- 整月一键操作（管理员） ----------
// POST /api/admin/inspect-month —— 整月一键点检（每台设备每天一条记录，08:00~10:00 随机时刻）
async function handleAdminInspectMonth(ctx) {
  const b = ctx.body;
  const month = b.month;
  if (!month || !b.signer_id) return fail(ctx.res, '缺少月份或签名人');
  if (month > currentMonthStr()) return fail(ctx.res, '不能点检未来月份的点检'); // 禁止点检未来月份
  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  const { endDay, error: endErr } = resolveEndDay(month, b.end_day);
  if (endErr) return fail(ctx.res, endErr);
  // 设备范围：指定单台 > 按房间 > 全部（房间取设备的 location 字段）
  let devices = allDevices();
  if (b.device_id) devices = devices.filter(d => d.id === b.device_id);
  else if (b.room) devices = devices.filter(d => (d.location || '') === b.room);
  if (!devices.length) {
    return fail(ctx.res, b.device_id ? '找不到该设备'
      : (b.room ? `房间「${b.room}」下没有设备` : '没有可点检的设备'));
  }
  let created = 0, updated = 0;
  for (const d of devices) {
    const items = await deviceItems(d);
    const bySn = buildBySn(items, 'ok');
    for (const dd of monthDays(month, endDay)) {
      // 每天一条记录取该日 08:00~10:00 的随机时刻（当天不超当前时间），各天时间自然分散且无未来时间
      const r = await upsertInspection({ device_id: d.id, inspect_date: dd },
        { status: 'ok', signed_by: signer.name, signer_id: signer.id, signature_image: pickSigImage(signer),
          abnormal_note: '', bySn, signed_at: randMorningTime(dd) });
      if (r === 'created') created++; else updated++;
    }
  }
  return sendJson(ctx.res, { devices: devices.length, days: endDay, signer: signer.name, created, updated, room: b.room || '' });
}
// POST /api/admin/cancel-inspect-month —— 取消整月点检 / 删除单台全部历史记录
//   scope='month'（默认）：删除指定月份 1 日至 end_day 的记录
//   scope='all'          ：删除该设备的全部历史记录（不限月份，含签名图），必须指定单台
async function handleAdminCancelInspectMonth(ctx) {
  const b = ctx.body;
  const month = b.month;
  if (!month) return fail(ctx.res, '缺少月份');
  if (month > currentMonthStr()) return fail(ctx.res, '不能取消未来月份的点检'); // 禁止取消未来月份的点检
  const insp = allInspections();

  // ---- 模式 A：删除单台设备的全部历史记录（含之前月份的，数据与签名一并清掉）----
  if (b.scope === 'all') {
    if (!b.device_id) return fail(ctx.res, '「删除全部历史记录」必须指定单台设备，避免误删全厂');
    const dev = allDevices().find(d => d.id === b.device_id);
    if (!dev) return fail(ctx.res, '找不到该设备');
    const remaining = insp.filter(r => r.device_id !== b.device_id);
    kvset('inspections', remaining);
    return sendJson(ctx.res, {
      deleted: insp.length - remaining.length, devices: 1, days: 0, month, scope: 'all',
      device: dev.no + ' ' + (dev.name || ''), location: dev.location || ''
    });
  }

  const { endDay, error: endErr } = resolveEndDay(month, b.end_day);
  if (endErr) return fail(ctx.res, endErr);
  const datesToDelete = new Set(monthDays(month, endDay));

  // 设备范围：指定单台 > 按房间 > 全部
  let roomIds = null;
  if (b.device_id) {
    if (!allDevices().some(d => d.id === b.device_id)) return fail(ctx.res, '找不到该设备');
  } else if (b.room) {
    roomIds = new Set(allDevices().filter(d => (d.location || '') === b.room).map(d => d.id));
    if (!roomIds.size) return fail(ctx.res, `房间「${b.room}」下没有设备`);
  }

  const before = insp.length;
  // 过滤：保留不在目标日期范围的，或不在目标设备范围的
  const remaining = insp.filter(r => {
    if (!datesToDelete.has(r.inspect_date)) return true; // 不在该日期范围
    if (b.device_id && r.device_id !== b.device_id) return true; // 不在目标设备
    if (roomIds && !roomIds.has(r.device_id)) return true;       // 不在目标房间
    return false; // 删除
  });
  kvset('inspections', remaining);
  const deleted = before - remaining.length;
  const devCount = b.device_id ? 1 : (roomIds ? roomIds.size : allDevices().length);
  return sendJson(ctx.res, { deleted, devices: devCount, days: endDay, month, scope: 'month', room: b.room || '' });
}

// ---------- 报表 / 视图 ----------
// GET /api/monthly —— 月度点检表数据
async function handleMonthly(ctx) {
  const month = ctx.query.get('month');
  if (!month) return fail(ctx.res, '缺少 month');
  const [yy, mm] = month.split('-');
  const dim = new Date(+yy, +mm, 0).getDate();
  const devices = allDevices();
  const insp = allInspections();
  const out = [];
  for (const d of devices) {
    const items = await deviceItems(d);
    const days = {}; const signerSet = new Set();
    for (let day = 1; day <= dim; day++) {
      const dd = `${yy}-${mm}-${String(day).padStart(2, '0')}`;
      const rec = insp.find(r => r.device_id === d.id && r.inspect_date === dd);
      if (rec) {
        days[dd] = { bySn: rec.bySn || {}, signature_image: rec.signature_image || null,
          signer_id: rec.signer_id || null,
          abnormal_note: rec.abnormal_note || '' };
        if (rec.signed_by) signerSet.add(rec.signed_by);
      }
    }
    const abn = allAbnormal().filter(r => r.device_id === d.id && r.month === month);
    const tpl = d.template_id ? allTemplates().find(x => x.id === d.template_id) : null;
    out.push({ id: d.id, no: d.no, name: d.name, model: d.model, location: d.location || '', items, days,
      signers: [...signerSet], abnormal: abn, note: tpl ? (tpl.note || '') : '',
      // 表头字段（后台「点检模板」里可编辑）：表单编号 / 版本 / 标题，缺省由前端回退通用值
      form_code: tpl ? (tpl.form_code || '') : '', form_rev: tpl ? (tpl.form_rev || '') : '',
      title: tpl ? (tpl.title || '') : '', title_en: tpl ? (tpl.title_en || '') : '',
      tpl_key: tpl ? (tpl.key || '') : '', tpl_name: tpl ? (tpl.equip_name || '') : '' });
  }
  // 签名人的两版图（横 / 竖）随响应去重下发：月检表签名格是高窄格 → 前端自动取竖版，
  // 温湿度表 / 大屏是横向格 → 自动取横版，无需人工切换。
  const sigAssets = {};
  allSigners().forEach(s => {
    if (!s.signature_image && !s.signature_image_v) return;
    sigAssets[s.id] = { h: s.signature_image || null, v: s.signature_image_v || null };
  });
  return sendJson(ctx.res, { month, devices: out, sig_assets: sigAssets });
}
// GET /api/dashboard —— 大屏数据
async function handleDashboard(ctx) {
  const q = ctx.query;
  const date = q.get('date');
  const loc = q.get('location') || '';
  const grp = (q.get('group') || '').trim();
  // 过滤维度（互斥，group 优先）：
  //   group=车间 → 只保留「后台房间管理里归到该分组」的房间下的设备（如 车间A+室2）
  //   location=车间A → 只保留该房间设备
  //   都不传 → 全部房间（仅在确实需要"全厂设备"时才这样调用）
  // 顺序沿用「设备台账.xlsx」导入的原始顺序（devices 数组即台账顺序）
  const grpRooms = grp ? new Set(kvget('rooms', []).filter(r => String(r.group || '').trim() === grp).map(r => r.name)) : null;
  const devices = allDevices().filter(d => grpRooms ? grpRooms.has(d.location) : (!loc || d.location === loc));
  const dmap = {}; devices.forEach(d => dmap[d.id] = d);
  const insp = allInspections();
  const month = date ? date.slice(0, 7) : '';
  const todayMap = {};
  let todayAbnormal = 0, monthCount = 0;
  for (const r of insp) {
    if (!dmap[r.device_id]) continue;   // 只统计当前房间范围内的设备
    if (date && r.inspect_date === date) {
      todayMap[r.device_id] = r;
      if (r.status === 'ng') todayAbnormal++;
    }
    if (month && r.inspect_date.startsWith(month)) monthCount++;
  }
  const grid = devices.map(d => {
    const r = todayMap[d.id];
    return { id: d.id, no: d.no, name: d.name, model: d.model, location: d.location || '',
      status: r ? r.status : 'none', signed_by: r ? (r.signed_by || '') : '',
      signature_image: r ? (r.signature_image || null) : null,
      signed_at: r ? (r.signed_at || '') : '' };
  });
  const recent = insp.filter(r => date && r.inspect_date === date && dmap[r.device_id])
    .sort((a, b) => (a.signed_at < b.signed_at ? 1 : -1)).slice(0, 12)
    .map(r => { const d = dmap[r.device_id] || {};
      return { no: d.no || '', name: d.name || '', status: r.status, signer_name: r.signed_by || '',
        signature_image: r.signature_image || null, abnormal_note: r.abnormal_note || '', signed_at: r.signed_at }; });
  return sendJson(ctx.res, { total: devices.length, today_inspected: Object.keys(todayMap).length,
    today_abnormal: todayAbnormal, month_inspected: monthCount, grid, recent });
}
// GET /api/inspect/device/:id —— 单台设备某日明细
async function handleDeviceDetail(ctx) {
  const id = ctx.params.id;
  const date = ctx.query.get('date');
  const d = allDevices().find(x => x.id === id);
  if (!d) return sendJson(ctx.res, { items: [] });
  const items = await deviceItems(d);
  const rec = allInspections().find(r => r.device_id === id && r.inspect_date === date);
  const out = items.map(it => ({ sn: it.sn, content: it.content, frequency: it.frequency || '',
    status: rec ? (rec.bySn && rec.bySn[it.sn] ? rec.bySn[it.sn] : 'ok') : 'none',
    note: rec ? (rec.abnormal_note || '') : '' }));
  return sendJson(ctx.res, { items: out });
}

// ===================== 系统版本 =====================
// GET /api/version —— 公开接口：前端各页面（含登录页）启动时拉取显示
async function handleVersion(ctx) {
  return sendJson(ctx.res, { version: APP_VERSION, date: APP_VERSION_DATE });
}

// ===================== 房间管理 =====================
function roomCounts() {
  const c = {};
  allDevices().forEach(d => {
    const loc = (d.location || '').trim();
    c[loc] = (c[loc] || 0) + 1;
  });
  return c;
}

// GET /api/rooms —— 房间列表（含设备数；房间名非敏感信息，登录与否均可读）
async function handleListRooms(ctx) {
  const rooms = kvget('rooms', []);
  const c = roomCounts();
  return sendJson(ctx.res, rooms.map(r => ({
    name: r.name, desc: r.desc || '', count: c[r.name] || 0,
    group: r.group || '',   // 分组：同组房间在前端（大屏/房间选择页/下拉）合并到一个组名之下展示
    thermo_apparatus: r.thermo_apparatus || '', thermo_equipment: r.thermo_equipment || '', thermo_requirement: r.thermo_requirement || ''
  })));
}

// POST /api/rooms —— 新增房间
async function handleCreateRoom(ctx) {
  const b = ctx.body;
  const name = String(b.name || '').trim();
  if (!name) return fail(ctx.res, '房间名称必填');
  if (name.length > 40) return fail(ctx.res, '房间名称不能超过 40 字');
  const rooms = kvget('rooms', []);
  if (rooms.some(r => r.name === name)) return fail(ctx.res, '房间「' + name + '」已存在');
  rooms.push({ name, desc: String(b.desc || '').trim(), group: String(b.group || '').trim() });
  kvset('rooms', rooms);
  return sendJson(ctx.res, { ok: true });
}

// PUT /api/rooms/:name —— 重命名 / 修改描述（重命名会同步迁移该房间下所有设备的位置）
async function handleUpdateRoom(ctx) {
  const oldName = decodeURIComponent(ctx.params.id);
  const b = ctx.body;
  const rooms = kvget('rooms', []);
  const r = rooms.find(x => x.name === oldName);
  if (!r) return fail(ctx.res, '房间不存在', 404);
  const newName = String(b.name != null ? b.name : r.name).trim();
  if (!newName) return fail(ctx.res, '房间名称必填');
  if (newName.length > 40) return fail(ctx.res, '房间名称不能超过 40 字');
  if (newName !== oldName && rooms.some(x => x.name === newName)) return fail(ctx.res, '房间「' + newName + '」已存在');
  if (b.desc != null) r.desc = String(b.desc).trim();
  // 分组只影响展示：同组房间（如 车间A/2）在大屏与下拉里合并到组名之下，房间本身仍各自独立
  if (b.group != null) r.group = String(b.group).trim();
  // 温湿度监测配置（管理员在后台「房间管理」维护，新建月度记录时自动带出）
  if (b.thermo_apparatus != null) r.thermo_apparatus = String(b.thermo_apparatus);
  if (b.thermo_equipment != null) r.thermo_equipment = String(b.thermo_equipment);
  if (b.thermo_requirement != null) r.thermo_requirement = String(b.thermo_requirement);
  r.name = newName;
  if (newName !== oldName) {
    const devs = allDevices();
    let moved = 0;
    devs.forEach(d => { if ((d.location || '').trim() === oldName) { d.location = newName; moved++; } });
    kvset('devices', devs);
  }
  kvset('rooms', rooms);
  return sendJson(ctx.res, { ok: true });
}

// DELETE /api/rooms/:name —— 删除房间（仅当房间内无设备）
async function handleDeleteRoom(ctx) {
  const name = decodeURIComponent(ctx.params.id);
  const rooms = kvget('rooms', []);
  const i = rooms.findIndex(x => x.name === name);
  if (i < 0) return fail(ctx.res, '房间不存在', 404);
  const c = roomCounts();
  if ((c[name] || 0) > 0) return fail(ctx.res, '该房间仍有 ' + c[name] + ' 台设备，请先迁移或删除设备');
  rooms.splice(i, 1);
  kvset('rooms', rooms);
  return sendJson(ctx.res, { ok: true });
}

// ===================== 温湿度点检记录（按房间 + 年月） =====================
// 与设备点检不同：温湿度记录是「房间级」月度表，每格记录 温度/湿度/记录员电子签名。
// 任意登录用户可录入（操作员日常记录），后台管理房间温湿度配置（管理员）。
function allEnvRecords() { return kvget('envRecords', []); }
const ENV_PERIODS = ['AM', 'PM', 'Night']; // 上午 / 下午 / 晚上
const ENV_PERIOD_CN = { AM: '上午', PM: '下午', Night: '晚上' };

// GET /api/env-records?room=&ym= —— 取某房间某月的温湿度记录（无则返回空壳）
async function handleGetEnvRecord(ctx) {
  const room = ctx.query.get('room') || '';
  const ym = ctx.query.get('ym') || '';
  if (!room || !/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '缺少房间或月份', 400);
  const rec = allEnvRecords().find(r => r.room === room && r.ym === ym);
  if (!rec) return sendJson(ctx.res, { room, ym, cells: {}, updated_at: null });
  return sendJson(ctx.res, rec);
}

// POST /api/env-records/sign-cell —— 验证签名人密码并返回电子签名图（供温湿度格电子签名）
async function handleSignEnvCell(ctx) {
  const b = ctx.body;
  if (!b.signer_id) return fail(ctx.res, '请选择签名人');
  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  return sendJson(ctx.res, { ok: true, signer_id: signer.id, name: signer.name,
    signature_image: pickSigImage(signer),
    signature_image_v: signer.signature_image_v || null });
}

// POST /api/env-records —— 新建 / 更新某房间某月记录（upsert，按 room+ym 唯一）
async function handleSaveEnvRecord(ctx) {
  const b = ctx.body;
  const room = String(b.room || '').trim();
  const ym = String(b.ym || '').trim();
  if (!room) return fail(ctx.res, '房间必填');
  if (!/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '月份格式应为 YYYY-MM');
  const cells = (b.cells && typeof b.cells === 'object') ? b.cells : {};
  // 仅保留合法 key（day_period）与字段，防止脏数据
  const clean = {};
  for (const k of Object.keys(cells)) {
    const m = /^(\d{1,2})_(AM|PM|Night)$/.exec(k);
    if (!m) continue;
    const day = parseInt(m[1], 10);
    if (day < 1 || day > 31) continue;
    const c = cells[k] || {};
    clean[k] = {
      temp: String(c.temp != null ? c.temp : '').slice(0, 8),
      humidity: String(c.humidity != null ? c.humidity : '').slice(0, 8),
      recorder: String(c.recorder || '').slice(0, 64),
      signature_image: typeof c.signature_image === 'string' ? c.signature_image.slice(0, 200000) : '',
      strike: c.strike ? 1 : 0   // 该日无需记录：整行划线（温度/湿度/记录员三格都带此标记）
    };
  }
  const list = allEnvRecords();
  let rec = list.find(r => r.room === room && r.ym === ym);
  if (rec) {
    rec.cells = clean;
    rec.updated_at = new Date().toISOString();
  } else {
    rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room, ym, cells: clean, updated_at: new Date().toISOString() };
    list.push(rec);
  }
  kvset('envRecords', list);
  return sendJson(ctx.res, { ok: true, id: rec.id, updated_at: rec.updated_at });
}

// GET /api/admin/env-records/export-csv?room=&ym= —— 导出某房间某月 CSV（管理员）
async function handleExportEnvCsv(ctx) {
  const room = ctx.query.get('room') || '';
  const ym = ctx.query.get('ym') || '';
  if (!room || !/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '缺少房间或月份', 400);
  const rec = allEnvRecords().find(r => r.room === room && r.ym === ym) || { cells: {} };
  const escCsv = v => { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const dim = new Date(+ym.slice(0, 4), +ym.slice(5, 7), 0).getDate();
  const header = ['日期', '时段', '温度(℃)', '湿度(%RH)', '记录员', '备注'];
  const rows = [];
  for (let d = 1; d <= dim; d++) {
    for (const p of ENV_PERIODS) {
      const c = rec.cells[d + '_' + p] || {};
      rows.push([ym + '-' + String(d).padStart(2, '0'), ENV_PERIOD_CN[p], c.temp || '', c.humidity || '', c.recorder || '',
        c.strike ? '／ 该日无需记录' : '']);
    }
  }
  const lines = [header.map(escCsv).join(',')].concat(rows.map(r => r.map(escCsv).join(',')));
  const csv = '﻿' + lines.join('\r\n'); // BOM 供 Excel 直开
  ctx.res.writeHead(200, { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="env_' + encodeURIComponent(room) + '_' + ym + '.csv"' });
  ctx.res.end(csv);
}

// ===================== 数据备份 / 导出（管理员） =====================
// GET /api/admin/backup —— 下载数据文件备份（内存中的最新全量数据）
async function handleBackup(ctx) {
  const body = JSON.stringify(store, null, 2);
  ctx.res.writeHead(200, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Content-Disposition': 'attachment; filename="kv-backup-' + todayStr() + '.json"'
  });
  ctx.res.end(body);
}

function csvCell(v) {
  const s = v == null ? '' : String(v);
  return '"' + s.replace(/"/g, '""') + '"';
}

// GET /api/admin/export-inspections-csv —— 导出全部点检记录 CSV（带 UTF-8 BOM，Excel 可直接打开）
async function handleExportCsv(ctx) {
  const devs = {};
  allDevices().forEach(d => { devs[d.id] = d; });
  const recs = kvget('inspections', []).slice()
    .sort((a, b) => (a.inspect_date < b.inspect_date ? 1 : a.inspect_date > b.inspect_date ? -1 : 0));
  const lines = ['设备编号,设备名称,房间,点检日期,完成时间,结果,异常备注'];
  recs.forEach(r => {
    const d = devs[r.device_id] || {};
    // signed_at 是 UTC，转本地时间（GMT+8）展示
    let t = '';
    if (r.signed_at) {
      const dt = new Date(r.signed_at);
      if (!isNaN(dt.getTime())) {
        const p = n => String(n).padStart(2, '0');
        t = dt.getFullYear() + '-' + p(dt.getMonth() + 1) + '-' + p(dt.getDate()) + ' ' + p(dt.getHours()) + ':' + p(dt.getMinutes());
      }
    }
    const ngCount = r.bySn ? Object.values(r.bySn).filter(v => v === 'ng').length : 0;
    const result = ngCount > 0 ? ('异常 ' + ngCount + ' 项') : (r.status === 'ok' ? '正常' : (r.status || ''));
    lines.push([d.no || r.device_id, d.name || '', d.location || '', r.inspect_date || '', t, result, r.abnormal_note || ''].map(csvCell).join(','));
  });
  const body = '\uFEFF' + lines.join('\r\n');
  ctx.res.writeHead(200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Content-Disposition': 'attachment; filename="inspections-' + todayStr() + '.csv"'
  });
  ctx.res.end(body);
}

// ===================== 路由表 =====================
// 每个条目：method + (path 精确匹配 | pattern 正则匹配 + paramNames 命名)
// adminOnly: true 表示该接口需要管理员登录（未登录返回 401）
// 路由顺序即匹配优先级：精确路径在前，参数路径在后
const routes = [
  // ---- 公开接口 ----
  { method: 'GET', path: '/api/version', handler: handleVersion },
  { method: 'GET', path: '/api/admin/me', handler: handleMe },
  { method: 'POST', path: '/api/admin/login', handler: handleLogin },
  { method: 'GET', path: '/api/signers/public', handler: handlePublicSigners },
  { method: 'GET', path: '/api/templates', handler: handleListTemplates },
  { method: 'GET', path: '/api/devices', handler: handleListDevices },
  { method: 'GET', path: '/api/monthly', handler: handleMonthly },
  { method: 'GET', path: '/api/dashboard', handler: handleDashboard },

  // ---- 鉴权 ----
  { method: 'POST', path: '/api/admin/changepw', handler: handleChangePw, adminOnly: true },

  // ---- 用户管理（仅管理员） ----
  { method: 'GET', path: '/api/users', handler: handleListUsers, adminOnly: true },
  { method: 'POST', path: '/api/users', handler: handleCreateUser, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/users\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateUser, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/users\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteUser, adminOnly: true },

  // ---- 签名人员 ----
  { method: 'GET', path: '/api/signers', handler: handleListSigners, adminOnly: true },
  { method: 'POST', path: '/api/signers', handler: handleCreateSigner, adminOnly: true },
  { method: 'GET', pattern: /^\/api\/signers\/([^/]+)\/sig$/, paramNames: ['id'], handler: handleGetSignerSignature },
  { method: 'PUT', pattern: /^\/api\/signers\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateSigner, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/signers\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteSigner, adminOnly: true },

  // ---- 模板 ----
  { method: 'POST', path: '/api/templates', handler: handleCreateTemplate, adminOnly: true },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleAddTemplateItem, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateTemplate, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleSaveTemplateItems, adminOnly: true },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/duplicate$/, paramNames: ['id'], handler: handleDuplicateTemplate, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteTemplate, adminOnly: true },
  { method: 'POST', path: '/api/admin/import-template', handler: handleImportTemplate, adminOnly: true },

  // ---- 设备 ----
  { method: 'POST', path: '/api/devices', handler: handleCreateDevice, adminOnly: true },
  { method: 'POST', path: '/api/devices/batch', handler: handleBatchCreateDevices, adminOnly: true },
  { method: 'POST', path: '/api/devices/import', handler: handleImportDevices, adminOnly: true },
  { method: 'POST', path: '/api/devices/batch-delete', handler: handleBatchDeleteDevices, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/devices\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateDevice, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/devices\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteDevice, adminOnly: true },

  // ---- 点检记录 ----
  { method: 'GET', path: '/api/inspections', handler: handleListInspections, adminOnly: true },
  { method: 'POST', path: '/api/inspections/batch-delete', handler: handleBatchDeleteInspections, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/inspections\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteInspection, adminOnly: true },

  // ---- 点检操作 ----
  { method: 'POST', path: '/api/inspect/batch', handler: handleInspectBatch, adminOnly: true },
  { method: 'POST', path: '/api/inspect/day-sig', handler: handleDaySign },
  { method: 'POST', path: '/api/inspect/month', handler: handleInspectMonth },
  { method: 'GET', pattern: /^\/api\/inspect\/device\/([^/]+)$/, paramNames: ['id'], handler: handleDeviceDetail },

  // ---- 整月一键操作（管理员） ----
  { method: 'POST', path: '/api/admin/inspect-month', handler: handleAdminInspectMonth, adminOnly: true },
  { method: 'POST', path: '/api/admin/cancel-inspect-month', handler: handleAdminCancelInspectMonth, adminOnly: true },

  // ---- 房间管理 ----
  { method: 'GET', path: '/api/rooms', handler: handleListRooms },
  { method: 'POST', path: '/api/rooms', handler: handleCreateRoom, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/rooms\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateRoom, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/rooms\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteRoom, adminOnly: true },

  // ---- 温湿度点检记录（按房间 + 年月；任意登录用户可录入） ----
  { method: 'GET', path: '/api/env-records', handler: handleGetEnvRecord },
  { method: 'POST', path: '/api/env-records', handler: handleSaveEnvRecord },
  { method: 'POST', path: '/api/env-records/sign-cell', handler: handleSignEnvCell },
  { method: 'GET', path: '/api/admin/env-records/export-csv', handler: handleExportEnvCsv, adminOnly: true },

  // ---- 数据备份 / 导出（管理员） ----
  { method: 'GET', path: '/api/admin/backup', handler: handleBackup, adminOnly: true },
  { method: 'GET', path: '/api/admin/export-inspections-csv', handler: handleExportCsv, adminOnly: true },
];

function matchRoute(method, p) {
  for (const r of routes) {
    if (r.method !== method) continue;
    if (r.path === p) return { handler: r.handler, params: {}, adminOnly: !!r.adminOnly };
    if (r.pattern) {
      const m = p.match(r.pattern);
      if (m) {
        const params = {};
        if (r.paramNames) r.paramNames.forEach((name, i) => { params[name] = m[i + 1]; });
        return { handler: r.handler, params, adminOnly: !!r.adminOnly };
      }
    }
  }
  return null;
}

// ===================== API 分发 =====================
async function handleApi(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const method = req.method;
  try {
    const route = matchRoute(method, p);
    if (!route) return fail(res, '接口不存在: ' + method + ' ' + p, 404);
    if (route.adminOnly && !(await isAdmin(req))) return fail(res, '未登录或登录已失效', 401);
    const body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
    return await route.handler({ req, res, params: route.params, query: url.searchParams, body });
  } catch (e) {
    return fail(res, String((e && e.message) || e), 500);
  }
}

// ===================== 静态文件 =====================
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};
// clean URL 映射（前端导航使用 /inspect 、/admin 等）
const CLEAN = {
  '/': 'index.html',
  '/inspect': 'inspect.html',
  '/admin': 'admin.html',
  '/monthly': 'monthly.html',
  '/print-all': 'print-all.html',
  '/login': 'login.html',
  '/rooms': 'rooms.html',
  '/env': 'env.html',
};
// 是否为需要登录的 HTML 页面（静态资源 .css/.js/.png 等不拦截）
function isHtmlPage(p) {
  if (p === '/' || p === '') return true;
  return path.extname(p).toLowerCase() === '.html';
}

function serveStatic(req, res) {
  let p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (CLEAN[p]) p = '/' + CLEAN[p];
  if (p === '/' || p === '') p = '/index.html';
  const filePath = path.normalize(path.join(PUBLIC, p));
  if (!filePath.startsWith(PUBLIC)) { res.writeHead(403); res.end('Forbidden'); return; }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    // HTML/CSS/JS 不缓存（避免修改后浏览器看不到更新）
    const headers = { 'Content-Type': MIME[ext] || 'application/octet-stream' };
    if (ext === '.html' || ext === '.css' || ext === '.js') {
      headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0';
      headers['Pragma'] = 'no-cache';
      headers['Expires'] = '0';
    }
    res.writeHead(200, headers);
    res.end(data);
  });
}

// ===================== HTTP 服务器 =====================
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  if (p.startsWith('/api/')) {
    handleApi(req, res);
    return;
  }
  // 退出登录：清除登录 cookie 并回到登录页
  if (p === '/logout' && req.method === 'GET') {
    res.writeHead(302, { 'Location': '/login',
      'Set-Cookie': `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` });
    res.end();
    return;
  }
  // 页面级登录拦截：所有 HTML 页面（登录页除外）未登录时重定向到 /login
  const cleanP = CLEAN[p] ? '/' + CLEAN[p] : p;
  if (cleanP !== '/login' && cleanP !== '/login.html' && isHtmlPage(cleanP)) {
    const u = await getLoginUser(req);
    if (!u) {
      res.writeHead(302, { 'Location': '/login?next=' + encodeURIComponent(p + url.search) });
      res.end();
      return;
    }
    // 管理后台页面仅 admin 角色可访问
    if (cleanP === '/admin' || cleanP === '/admin.html') {
      if (u.role !== 'admin') {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('无权限：仅管理员可访问后台');
        return;
      }
    }
  }
  serveStatic(req, res);
});

// ===================== 启动 =====================
loadStore();
seedRooms(); // 老数据文件首次升级时从设备位置推导房间列表
ensureConfig(); // 首次启动随机生成并载入密钥（持久化到 data/config.json）
server.listen(PORT, async () => {
  await ensureUsers(); // 多用户初始化（首次启动 seed admin 用户）
  console.log('==================================================');
  console.log(' 设备点检巡检系统 已启动');
  console.log(' 访问地址:  http://localhost:' + PORT + '/');
  console.log(' 管理后台:  http://localhost:' + PORT + '/admin');
  console.log(' 数据文件:  ' + DATA_FILE);
  console.log(' 默认管理员: admin（请登录后在后台添加更多用户）');
  console.log('==================================================');
});

// 退出前确保落盘
process.on('SIGINT', () => { console.log('\n正在保存并退出...'); scheduleSave(); setTimeout(() => process.exit(0), 300); });
process.on('SIGTERM', () => { scheduleSave(); setTimeout(() => process.exit(0), 300); });
