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
const os = require('os');
const zlib = require('zlib');
const { Readable } = require('stream');      // 本机自升级要造一个「内部请求」喂给接收流程
const crypto = require('crypto');
const { spawn } = require('child_process');
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
const APP_VERSION = 'v1.4.0';
const APP_VERSION_DATE = '2026-09-15';

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
let store = { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], depts: [], envRecords: [] };

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
// 科室清单（后台维护）：房间与用户都从这里选。默认空数组，老库无 depts 键时不报错
const allDepts = () => kvget('depts', []);
const allInspections = () => kvget('inspections', []);
const allAbnormal = () => kvget('abnormalRecords', []);

async function deviceItems(dev) {
  if (!dev || !dev.template_id) return [];
  const tpls = allTemplates();
  const t = tpls.find(t => t.id === dev.template_id);
  return t ? (t.items || []) : [];
}
// 请求体上限（字符数）。签名图的 base64 是主要体量来源，20M 对正常使用足够宽松。
const BODY_LIMIT = 2e7;
function readBody(req, res) {
  return new Promise((resolve) => {
    let buf = '', tooBig = false;
    req.on('data', c => {
      if (tooBig) return;
      buf += c;
      if (buf.length > BODY_LIMIT) {
        // 关键：这里「不能 destroy」。destroy 会让客户端直接收到连接重置，
        // fetch 抛异常而前端拿不到任何响应 —— 表现就是「点了按钮毫无反应」。
        // 改为立刻回 413，并把剩余数据读掉丢弃，前端才能拿到可读的错误提示。
        tooBig = true; buf = '';
        try {
          sendJson(res, { error: '上传内容过大（超过 ' + Math.round(BODY_LIMIT / 1024 / 1024) +
            'MB）。请压缩签名图片，或减少签名字数后重试' }, 413);
        } catch (e) { }
        req.resume();
      }
    });
    req.on('end', () => {
      if (tooBig) return resolve({});
      try { resolve(buf ? JSON.parse(buf) : {}); } catch { resolve({}); }
    });
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
  return sendJson(ctx.res, { ok: !!u, username: u ? u.username : '', name: u ? u.name : '', role: u ? u.role : '', dept: u ? (u.dept || '') : '' });
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
  return sendJson(ctx.res, users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active, dept: u.dept || '' })));
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
    dept: (b.dept || '').toString().trim(),
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
  if ('dept' in b) u.dept = (b.dept || '').toString().trim();
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
// 单张签名图上限（base64 字符数）。超限一律「拒绝并报错」，绝不静默截断 ——
// 被截断的 base64 是坏数据：浏览器渲染必破图，调用方却以为保存成功了，
// 排查起来极难（2026-09-15 定位到：上传大图后签名显示不出来就是这个原因）。
const SIG_IMG_MAX = 2000000;   // ≈1.5MB 图片，够放下高清手写/扫描签名
function sigImageNorm(v, label) {
  if (v == null || v === '') return { value: null };
  if (typeof v !== 'string' || !/^data:image\//.test(v)) return { value: null };
  if (v.length > SIG_IMG_MAX) {
    return { error: (label || '电子签名图') + '过大（约 ' + Math.round(v.length / 1024) +
      'KB，上限 ' + Math.round(SIG_IMG_MAX / 1024) + 'KB）。请把图片裁小/压缩后再上传，或减少签名字数' };
  }
  return { value: v };
}
function sigCharsNorm(v) {
  if (!Array.isArray(v)) return { value: null };
  const out = [];
  for (let i = 0; i < Math.min(v.length, SIG_MAX_CHARS); i++) {
    const r = sigImageNorm(v[i], '第 ' + (i + 1) + ' 个字的签名图');
    if (r.error) return { error: r.error };
    out.push(r.value || '');
  }
  return { value: out };
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
  const him = sigImageNorm(b.signature_image, '横版签名图');
  if (him.error) return fail(ctx.res, him.error, 413);
  const vim = sigImageNorm(b.signature_image_v, '竖版签名图');
  if (vim.error) return fail(ctx.res, vim.error, 413);
  const chk = sigCharsNorm(b.sig_chars);
  if (chk.error) return fail(ctx.res, chk.error, 413);
  const list = allSigners();
  list.push({ id: uuid(), name: b.name, active: true, password_hash: await sha256(b.password + PEPPER),
    signature_image: him.value,
    signature_image_v: vim.value,
    sig_chars: chk.value || [],
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
  // 先做体量校验、再改内存：allSigners() 返回的是 store 内的引用，
  // 若中途 return 失败，内存对象已被改而磁盘未落盘 → 内存与磁盘不一致，故校验必须前置。
  const him = ('signature_image' in b) ? sigImageNorm(b.signature_image, '横版签名图') : {};
  if (him.error) return fail(ctx.res, him.error, 413);
  const vim = ('signature_image_v' in b) ? sigImageNorm(b.signature_image_v, '竖版签名图') : {};
  if (vim.error) return fail(ctx.res, vim.error, 413);
  const chk = ('sig_chars' in b) ? sigCharsNorm(b.sig_chars) : {};
  if (chk.error) return fail(ctx.res, chk.error, 413);
  if (typeof b.name === 'string' && b.name.trim()) s.name = b.name.trim().slice(0, 40);
  if (typeof b.active === 'boolean') s.active = b.active;
  if (b.password) s.password_hash = await sha256(b.password + PEPPER);
  if ('signature_image' in b) s.signature_image = him.value;
  if ('signature_image_v' in b) s.signature_image_v = vim.value;
  if ('sig_chars' in b) s.sig_chars = chk.value || [];
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
  // 科室作用域（服务端兜底）：普通用户设了科室时，最多只能看到本科室房间的设备。
  // 这样即使前端被绕过、或某个分组跨越了多个科室（如 室1 属 A 科、室2 属 B 科），
  // 普通用户也不会通过 group 视图看到别的科室设备。管理员 / 未登录（老行为）不受限。
  const me = await getLoginUser(ctx.req);
  let deptRooms = null;
  if (me && me.role !== 'admin' && String(me.dept || '').trim()) {
    deptRooms = new Set(kvget('rooms', []).filter(r => (r.dept || '') === me.dept).map(r => r.name));
  }
  const devices = allDevices().filter(d => {
    if (deptRooms && !deptRooms.has(String(d.location || '').trim())) return false;
    return grpRooms ? grpRooms.has(d.location) : (!loc || d.location === loc);
  });
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
    dept: r.dept || '',     // 科室：该房间归属的科室（空 = 不限定，全厂可见）
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
  rooms.push({ name, desc: String(b.desc || '').trim(), group: String(b.group || '').trim(), dept: String(b.dept || '').trim() });
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
  // 科室：该房间归属的科室（留空 = 不限定，全员可见）
  if (b.dept != null) r.dept = String(b.dept).trim();
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

// ---- 科室管理（管理员维护清单） ----
// GET /api/depts —— 科室清单（登录用户可读，用于房间/用户表单的下拉）
async function handleListDepts(ctx) {
  return sendJson(ctx.res, { depts: allDepts() });
}
// POST /api/depts —— 新增科室（管理员）
async function handleCreateDept(ctx) {
  const name = String(ctx.body.name || '').trim();
  if (!name) return fail(ctx.res, '科室名称必填');
  if (name.length > 20) return fail(ctx.res, '科室名称不能超过 20 字');
  const depts = allDepts();
  if (depts.includes(name)) return fail(ctx.res, '科室「' + name + '」已存在');
  depts.push(name);
  kvset('depts', depts);
  return sendJson(ctx.res, { ok: true });
}
// DELETE /api/depts/:name —— 删除科室（管理员）；被房间/用户引用时拒绝，避免产生孤儿数据
async function handleDeleteDept(ctx) {
  const name = decodeURIComponent(ctx.params.name);
  const depts = allDepts();
  if (!depts.includes(name)) return fail(ctx.res, '科室不存在', 404);
  const roomCnt = kvget('rooms', []).filter(r => (r.dept || '') === name).length;
  const userCnt = kvget('users', []).filter(u => (u.dept || '') === name).length;
  if (roomCnt || userCnt) return fail(ctx.res, '该科室仍被 ' + roomCnt + ' 个房间 / ' + userCnt + ' 个用户引用，请先改派后再删除');
  kvset('depts', depts.filter(d => d !== name));
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
    // 签名图不再静默截断：超限就报 413 让用户去换张小图。
    // （旧的 slice(0, 200000) 会把签名存成半截 base64 → 表格里签名显示残缺，且接口照样返回 ok）
    const sigRaw = (typeof c.signature_image === 'string') ? c.signature_image : '';
    if (sigRaw.length > SIG_IMG_MAX) {
      return fail(ctx.res, day + ' 日的签名图过大（约 ' + Math.round(sigRaw.length / 1024) +
        'KB，上限 ' + Math.round(SIG_IMG_MAX / 1024) + 'KB）。请重新上传更小的签名图', 413);
    }
    clean[k] = {
      temp: String(c.temp != null ? c.temp : '').slice(0, 8),
      humidity: String(c.humidity != null ? c.humidity : '').slice(0, 8),
      recorder: String(c.recorder || '').slice(0, 64),
      signature_image: sigRaw,
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

// ---- 温湿度一键填充（管理员）----
// 把某月 1 日 ~ 截止日之间「还没填」的格子批量补上温湿度，并套用所选签名人的电子签名。
// 三条硬约束：
//   1) 数值必须落在该房间「综合温湿度要求」解析出的范围内 —— 解析不出来就整间跳过，不猜；
//   2) 只补空格：任何已有内容的格子（含签名、划线）一律不动，重复点也不会破坏已录数据；
//   3) 绝不为未来日期生成记录：截止日上限就是今天。
// 限值解析必须与 public/env.html 的 parseLimits 保持一致（改一边就要同步另一边），
// 否则会出现「后台填进去的值，在温湿度页反而被标红」这种自相矛盾的结果。
function parseEnvLimits(txt) {
  const s = String(txt || '');
  const t = s.match(/温度(?:要求)?\s*[：:]\s*(-?\d+(?:\.\d+)?)\s*(?:℃|°C)?\s*[-~—～]\s*(-?\d+(?:\.\d+)?)/);
  const h = s.match(/湿度(?:要求)?\s*[：:]\s*(≤|<=|<|不超过)\s*(\d+(?:\.\d+)?)/);
  if (!t && !h) return null;
  return { tMin: t ? parseFloat(t[1]) : null, tMax: t ? parseFloat(t[2]) : null, hMax: h ? parseFloat(h[2]) : null };
}
// 在 [lo,hi] 内取一个「留了余量」的安全区间：两端各退让 max(绝对余量, 跨度×比例)。
// 为什么要留余量：填出来的值若贴着边界（10℃ 房间填 10.0），打印评审时容易被质疑是不是超了；
// 同时给随机波动留出空间，波动后再夹取也不会总撞边界。
function safeBand(lo, hi, absMargin, ratio) {
  const span = hi - lo;
  const m = Math.max(absMargin, span * ratio);
  let a = lo + m, b = hi - m;
  if (a > b) { const mid = (lo + hi) / 2; const half = Math.min(0.3, span / 4); a = mid - half; b = mid + half; }
  if (b < a) { a = lo; b = hi; }
  return [a, b];
}
// 由房间要求推出「温度取值区间」「湿度取值区间」；任一项缺失就返回 error（整间跳过，不填）
function envBands(lim) {
  lim = lim || {};
  if (lim.tMin == null || lim.tMax == null) return { error: '未配置温度范围（应形如「温度：10℃-35℃」）' };
  if (!(lim.tMax > lim.tMin)) return { error: '温度范围写法有误（下限不小于上限）' };
  if (lim.hMax == null) return { error: '未配置湿度上限（应形如「湿度：≤80%RH」）' };
  if (!(lim.hMax > 0)) return { error: '湿度上限写法有误' };
  const temp = safeBand(lim.tMin, lim.tMax, 0.5, 0.10);
  // 湿度只有上限 → 下限取上限的一半（且不低于 30%RH），上限再退让 3~6 个点
  const hl = Math.max(30, lim.hMax * 0.5);
  const hh = lim.hMax - Math.max(3, lim.hMax * 0.06);
  const hum = hh > hl ? [hl, hh]
            : [Math.max(1, lim.hMax * 0.4), Math.max(2, lim.hMax - Math.max(1, lim.hMax * 0.05))];
  return { temp, hum };
}
// 一天三个时段共用一条「基准值」，各自在基准上小幅波动（温度 ±0.8℃ / 湿度 ±3.5%RH 以内），
// 再夹进安全区间 —— 同一天的上午/下午/晚上读数因而连贯可信，不像三个互不相干的随机数。
function envDayValues(band, jitter) {
  const a = band[0], b = band[1];
  const base = a + Math.random() * (b - a);
  const out = [];
  for (let i = 0; i < ENV_PERIODS.length; i++) {
    const v = base + (Math.random() * 2 - 1) * jitter;
    out.push((v < a ? a : (v > b ? b : v)).toFixed(1));
  }
  return out;
}
// 该格是否已有内容：任一项非空即视为已录入（填充时一律跳过，保证只补空格）
function envCellHasData(c) {
  if (!c) return false;
  return !!(String(c.temp || '').trim() || String(c.humidity || '').trim() || c.recorder || c.signature_image || c.strike);
}
const fmtBand = b => b[0].toFixed(1) + '~' + b[1].toFixed(1);

// POST /api/admin/env-fill —— 一键填充温湿度（管理员；需签名人密码）
async function handleEnvFill(ctx) {
  const b = ctx.body || {};
  const ym = String(b.ym || '').trim();
  if (!/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '月份格式应为 YYYY-MM');
  const cur = currentMonthStr();
  if (ym > cur) return fail(ctx.res, '不能填充未来月份（' + ym + '）');
  const [yy, mm] = ym.split('-').map(Number);
  const dim = new Date(yy, mm, 0).getDate();
  // 截止日：默认「今天」（历史月份则取该月最后一天）；上限不超过今天 —— 不为未来日期生成记录
  const maxDay = (ym === cur) ? Number(todayStr().slice(8, 10)) : dim;
  let endDay = (b.end_day == null || b.end_day === '') ? maxDay : parseInt(b.end_day, 10);
  if (!Number.isFinite(endDay)) endDay = maxDay;
  endDay = Math.min(Math.max(endDay, 1), maxDay);

  const { signer, error } = await verifySigner(b);
  if (error) return fail(ctx.res, error, error === '签名密码错误' ? 401 : 400);
  const sigImg = pickSigImage(signer);   // 温湿度记录员格是横向格 → 横版签名

  const rooms = kvget('rooms', []);
  let targets = rooms;
  if (b.scope === 'room') {
    const name = String(b.room || '').trim();
    if (!name) return fail(ctx.res, '请选择房间');
    const hit = rooms.filter(r => r.name === name);
    if (!hit.length) return fail(ctx.res, '房间不存在：' + name, 404);
    targets = hit;
  }
  if (!targets.length) return fail(ctx.res, '没有可填充的房间');

  const list = allEnvRecords();
  const detail = [], skipped = [];
  let cells = 0, days = 0, touched = 0;
  for (const r of targets) {
    const bands = envBands(parseEnvLimits(r.thermo_requirement));
    if (bands.error) { skipped.push({ room: r.name, reason: bands.error }); continue; }
    let rec = list.find(x => x.room === r.name && x.ym === ym);
    if (rec && !rec.cells) rec.cells = {};
    let nCells = 0, nDays = 0;
    for (let day = 1; day <= endDay; day++) {
      const temps = envDayValues(bands.temp, 0.8);
      const hums = envDayValues(bands.hum, 3.5);
      let dayFilled = false;
      for (let i = 0; i < ENV_PERIODS.length; i++) {
        const k = day + '_' + ENV_PERIODS[i];
        if (envCellHasData(rec && rec.cells[k])) continue;   // 只补空格
        if (!rec) {
          rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
                  room: r.name, ym, cells: {}, updated_at: null };
          list.push(rec);
        }
        rec.cells[k] = { temp: temps[i], humidity: hums[i], recorder: signer.id, signature_image: sigImg || '', strike: 0 };
        nCells++; dayFilled = true;
      }
      if (dayFilled) nDays++;
    }
    if (nCells) { rec.updated_at = new Date().toISOString(); touched++; }
    detail.push({ room: r.name, cells: nCells, days: nDays,
      temp_band: fmtBand(bands.temp), hum_band: fmtBand(bands.hum) });
    cells += nCells; days += nDays;
  }
  if (cells) kvset('envRecords', list);   // 一格都没填就别白写一次全量数据
  return sendJson(ctx.res, {
    ok: true, ym, end_day: endDay, cells, days, rooms: touched,
    signer: { id: signer.id, name: signer.name }, signer_has_sig: !!sigImg,
    detail, skipped
  });
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
// ===================== 局域网远程升级 =====================
// 同一份代码承担两种角色，而且每台机器两种能力都有：
//   · 发起端：后台维护「电脑清单」，把升级包推送给局域网内其它装了本系统的机器
//   · 目标端：接受推送，复用 _setup.ps1 完成
//     备份 → 停服 → 覆盖 → 重启 → 校验 → 失败自动回滚（与 U 盘一键升级同一套引擎）
// 没有「中心机」：任意一台电脑只要管理员登录它自己的后台，就能给清单里任意一台电脑推升级；
// 目标端默认接受（零配置），不需要预先开开关或抄令牌。
//
// 硬约束（安全底线）：升级包只允许含程序文件，一旦出现 data/ 一律拒收 ——
// 点检记录 / 电子签名 / 房间配置都在 data/kv.json 里，绝不能远程被覆盖。
const UPGRADE_DIR   = path.join(DATA_DIR, '_lan_upgrade');   // 收到的包：暂存 + 解压
const LAN_PKG_DIR   = path.join(DATA_DIR, 'lan_packages');   // 后台上传的升级包仓库
const DIST_DIR      = path.join(ROOT, '部署包');              // build-deploy.py 的产物目录（自动扫描）
const SETUP_ENGINE  = path.join(ROOT, 'tools', 'deploy', '_setup.ps1');
// 升级引擎用的 PowerShell 解释器：优先绝对路径 —— spawn 裸名在 PATH 异常时会失败，
// 而这一步失败意味着远程目标机永远收不到升级，属于必须规避的静默故障。
const PSEXE = (() => {
  for (const p of [
    path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'powershell.exe'),
    path.join(process.env.ProgramFiles || 'C:\\Program Files', 'PowerShell', '7', 'pwsh.exe'),
  ]) { try { if (fs.existsSync(p)) return p; } catch { } }
  return 'powershell.exe';
})();
const DEFAULT_PORT_ = 8787;
const MAX_PKG_BYTES = 96 * 1024 * 1024;
const PAYLOAD_MARK  = '__PAYLOAD__';
const PKG_ALLOW = ['server.js', 'public', 'tools', 'runtime', '启动.bat', '停止.bat',
                   '_run_hidden.vbs', 'setup.ps1', 'version.txt', '安装.bat', '安装说明.txt'];

// ---------- 通用小工具 ----------
function verCmp(a, b) {
  const pa = String(a || '').replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0);
  const pb = String(b || '').replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d > 0 ? 1 : -1;
  }
  return 0;
}
function readRawBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0; let done = false;
    req.on('data', c => {
      if (done) return;
      n += c.length;
      if (n > max) { done = true; reject(new Error('内容超过 ' + Math.round(max / 1048576) + ' MB 上限')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on('error', e => { if (!done) { done = true; reject(e); } });
  });
}
// 零依赖 zip 解包：读中央目录 + zlib.inflateRaw。仅支持本系统生成的包（stored / deflate）。
function unzip(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 30) throw new Error('文件太小，不是有效的 ZIP');
  let eocd = -1;
  const low = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= low; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('找不到 ZIP 结尾标记（文件可能不完整）');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  if (!count) throw new Error('ZIP 里没有任何文件');
  const out = [];
  for (let n = 0; n < count; n++) {
    if (off + 46 > buf.length || buf.readUInt32LE(off) !== 0x02014b50) throw new Error('ZIP 目录项损坏（第 ' + (n + 1) + ' 项）');
    const method = buf.readUInt16LE(off + 10);
    const csize  = buf.readUInt32LE(off + 20);
    const usize  = buf.readUInt32LE(off + 24);
    const nlen   = buf.readUInt16LE(off + 28);
    const elen   = buf.readUInt16LE(off + 30);
    const clen   = buf.readUInt16LE(off + 32);
    const lho    = buf.readUInt32LE(off + 42);
    const name   = buf.toString('utf8', off + 46, off + 46 + nlen);
    if (lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) throw new Error('ZIP 数据头损坏：' + name);
    const lnlen = buf.readUInt16LE(lho + 26);
    const lelen = buf.readUInt16LE(lho + 28);
    const start = lho + 30 + lnlen + lelen;
    const raw   = buf.subarray(start, start + csize);
    let data;
    if (method === 0) data = Buffer.from(raw);
    else if (method === 8) data = zlib.inflateRawSync(raw);
    else throw new Error('不支持的压缩方式 ' + method + '（' + name + '）');
    if (usize && data.length !== usize) throw new Error('解压后大小不符：' + name);
    out.push({ name: name.replace(/\\/g, '/'), data });
    off += 46 + nlen + elen + clen;
  }
  return out;
}
// 校验升级包内容（白名单 + 必须有 server.js/public + 读出版本号）
function inspectEntries(entries) {
  const names = entries.map(e => e.name);
  const bad = [];
  for (const n of names) {
    if (n.startsWith('/') || /^[A-Za-z]:/.test(n) || n.split('/').includes('..')) bad.push('含非法路径：' + n);
    else if (n === 'data' || n.startsWith('data/')) bad.push('包内含 data/（点检数据），已拒收：' + n);
    else if (!PKG_ALLOW.some(pre => n === pre || n.startsWith(pre + '/'))) bad.push('含白名单外的文件：' + n);
  }
  if (bad.length) return { ok: false, error: bad[0] + (bad.length > 1 ? '（共 ' + bad.length + ' 处问题）' : '') };
  if (!names.includes('server.js')) return { ok: false, error: '不是本系统的升级包：缺少 server.js' };
  if (!names.some(n => n.startsWith('public/'))) return { ok: false, error: '不是本系统的升级包：缺少 public/' };
  let version = '';
  const vt = entries.find(e => e.name === 'version.txt');
  if (vt) version = vt.data.toString('utf8').split(/\r?\n/)[0].trim();
  if (!version) {
    const sj = entries.find(e => e.name === 'server.js');
    const m = sj && sj.data.toString('utf8').match(/APP_VERSION\s*=\s*'([^']+)'/);
    if (m) version = m[1];
  }
  if (!version) return { ok: false, error: '升级包里读不到版本号（缺 version.txt，server.js 里也没有 APP_VERSION）' };
  return { ok: true, version, files: entries.length };
}
// 一键升级 .bat 里内嵌的 base64 → zip Buffer
function extractBatPayload(buf) {
  const txt = buf.toString('latin1');
  const i = txt.lastIndexOf(PAYLOAD_MARK);
  if (i < 0) throw new Error('不是本系统的一键升级包（找不到内嵌数据标记）');
  const b64 = txt.slice(i + PAYLOAD_MARK.length).replace(/[^A-Za-z0-9+/=]/g, '');
  if (b64.length < 100) throw new Error('升级包内嵌数据不完整，请重新获取');
  const out = Buffer.from(b64, 'base64');
  if (out.length < 30) throw new Error('内嵌数据解码后不是有效的 ZIP');
  return out;
}
// 读磁盘上的升级包（.zip 直读；.bat 取出内嵌 zip）
function readPkgFile(p) {
  const buf = fs.readFileSync(p);
  return /\.bat$/i.test(p) ? extractBatPayload(buf) : buf;
}
// 请求另一台机器（绕开系统代理；Node 原生 http 本就不走系统代理）
function httpJson(host, port, p, opt = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let req;
    try {
      req = http.request({
        host, port, path: p, method: opt.method || 'GET',
        headers: opt.headers || {}, timeout: opt.timeout || 5000,
      }, (r) => {
        let s = '';
        r.setEncoding('utf8');
        r.on('data', c => { s += c; if (s.length > 2e6) req.destroy(); });
        r.on('end', () => { let j = null; try { j = JSON.parse(s); } catch { } finish({ status: r.statusCode, json: j, text: s }); });
      });
    } catch (e) { return finish({ status: 0, json: null, text: '', error: String(e.message || e) }); }
    req.on('timeout', () => { try { req.destroy(); } catch { } finish({ status: 0, json: null, text: '', error: '连接超时' }); });
    req.on('error', e => finish({ status: 0, json: null, text: '', error: String(e.message || e) }));
    if (opt.body) req.write(opt.body);
    req.end();
  });
}
function localAddrs() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const k in ifs) for (const a of (ifs[k] || [])) if (a.family === 'IPv4') out.push(a.address);
  return out;
}
// 发起端绝不能给自己推送 —— setup.ps1 会把本服务杀掉，页面跟着断
function isSelfTarget(host, port) {
  if (parseInt(port, 10) !== PORT) return false;
  const h = String(host || '').trim().toLowerCase();
  return h === 'localhost' || h === '127.0.0.1' || h === '::1' ||
         h === String(os.hostname() || '').toLowerCase() || localAddrs().includes(h);
}

// ---------- 系统级共享密钥：目标端「零配置」的前提 ----------
// 装了本系统的电脑之间要能互相认证，而现场没人愿意去每台机器后台各抄一遍令牌。
// 于是由源码派生一把「所有同版本机器都一样」的钥匙：推送端自动带上、目标端自动认，
// 管理员在任意一台电脑登录后台即可直接推。
// 安全边界（须知情）：它随源码下发 —— 能拿到升级包/server.js 的人就能算出来。所以它挡的是
// 「误推」和「乱调接口」，不是「拿到源码的内行」。要更严的隔离时，到目标机后台点
// 「🔒 只认专用令牌」即可切回逐机专用令牌模式（open=false）——零配置只影响默认值。
const LAN_CLUSTER_KEY = crypto.createHash('sha256')
  .update('equipment-inspection/lan-upgrade/cluster-key/v1')
  .digest('base64url');

// ---------- 本机作为「被升级目标」 ----------
function lanCfg() {
  const c = kvget('lanUpgrade', null) || {};
  // enabled：本机是否接受局域网升级 —— 默认 true，开箱即可被升级，只有管理员显式关过才是 false
  // open   ：是否接受系统级共享密钥 —— 默认 true（零配置）；显式关掉后只认下面的专用令牌
  // 用 hasOwnProperty 区分「从没配过」（→ 默认 true）和「配过并关掉」（→ false）；
  // 早期写的是 !!c.enabled，把「没配过」也当成关闭，导致每台机器都得手工开一次。
  const has = k => Object.prototype.hasOwnProperty.call(c, k);
  return {
    enabled: has('enabled') ? !!c.enabled : true,
    open: has('open') ? !!c.open : true,
    token: String(c.token || ''), name: String(c.name || ''),
  };
}
function lanName() { const c = lanCfg(); return c.name || os.hostname() || '未命名电脑'; }
function tokenEq(a, b) {
  const x = Buffer.from(String(a == null ? '' : a)), y = Buffer.from(String(b == null ? '' : b));
  return !!y.length && x.length === y.length && crypto.timingSafeEqual(x, y);
}
// 目标机自检：环境是否具备被远程升级的条件
function lanReady() {
  return {
    platform: process.platform,
    win: process.platform === 'win32',
    engine: fs.existsSync(SETUP_ENGINE),
    writable: (() => { try { fs.mkdirSync(DATA_DIR, { recursive: true }); fs.accessSync(ROOT, fs.constants.W_OK); return true; } catch { return false; } })(),
  };
}
// 目标端收包校验。发起端接口是 adminOnly（必须管理员登录才能发起），所以这里只判断两件事：
// 「本机是否允许被升级」+「来源是不是本系统的分发端」。两种凭据都收：
//   · 专用令牌（老方式；显式开 open=false 后是唯一方式）—— 逐台配置，最严
//   · 系统级共享密钥（默认）—— 零配置，任意一台机器登录后台即可推
function lanAccept(given) {
  const c = lanCfg();
  if (!c.enabled) {
    return { ok: false, code: 403, msg: '目标机已关闭「接受局域网升级」。要远程升它，请先到那台电脑的后台·系统页把它打开。' };
  }
  if (c.token && tokenEq(given, c.token)) return { ok: true };
  if (c.open && tokenEq(given, LAN_CLUSTER_KEY)) return { ok: true };
  return { ok: false, code: 401, msg: c.open
    ? '升级凭据不正确。目标机接受系统共享密钥，这次却没对上 —— 多半两边版本不一致，请到目标机确认它已升到 ' + APP_VERSION + ' 或更高。'
    : '目标机被设成「只认专用令牌」。请到那台电脑的后台复制令牌，填到本机电脑清单里再推。' };
}
async function handleLanTargetConfig(ctx) {
  const c = lanCfg(), r = lanReady();
  return sendJson(ctx.res, {
    ok: true, enabled: c.enabled, open: c.open, token: c.token, name: c.name || os.hostname(),
    host: os.hostname(), version: APP_VERSION, date: APP_VERSION_DATE,
    install_dir: ROOT, port: PORT, ready: r, can_push: true,
  });
}
async function handleLanTargetConfigPut(ctx) {
  const b = ctx.body || {};
  // 从原始对象上改，不拿 lanCfg() 的结果 —— 否则「默认值」会被当成用户的显式选择写进库，
  // 以后改默认值就改不动这些机器了。
  const c = kvget('lanUpgrade', null) || {};
  if (typeof b.enabled === 'boolean') c.enabled = b.enabled;
  if (typeof b.open === 'boolean') c.open = b.open;
  if (typeof b.name === 'string') c.name = b.name.trim().slice(0, 40);
  if (b.regenerate || !c.token) c.token = crypto.randomBytes(24).toString('base64url');
  // 只在「这一次是显式打开」时校验引擎：默认开启的机器不该因为缺引擎就连名字都改不动
  if (b.enabled === true) {
    const r = lanReady();
    if (!r.win) return fail(ctx.res, '本机不是 Windows，无法使用一键升级引擎', 400);
    if (!r.engine) return fail(ctx.res, '本机缺少升级引擎 tools/deploy/_setup.ps1，请先用一键升级包升到 ' + APP_VERSION, 400);
  }
  kvset('lanUpgrade', c);
  const nc = lanCfg();
  return sendJson(ctx.res, { ok: true, enabled: nc.enabled, open: nc.open, token: nc.token,
    name: nc.name || os.hostname(), port: PORT, ready: lanReady() });
}
// 「检测」用：一次拿到在线 + 版本 + 是否允许被升级
async function handleLanPing(ctx) {
  const c = lanCfg();
  const a = lanAccept(ctx.req.headers['x-eq-token']);
  if (!a.ok) return fail(ctx.res, a.msg, a.code);
  const r = lanReady();
  return sendJson(ctx.res, {
    ok: true, name: lanName(), host: os.hostname(),
    version: APP_VERSION, date: APP_VERSION_DATE,
    enabled: c.enabled, open: c.open, engine: r.engine, win: r.win, writable: r.writable,
    install_dir: ROOT, port: PORT,
  });
}
// 接收推送的升级包 → 落盘 → 交给 _setup.ps1
async function handleLanApply(ctx) {
  const req = ctx.req, res = ctx.res;
  // req.__eqSelf = 本机自升级（见 handleLanSelfUpgrade）：那条路径已经过了管理员登录鉴权，
  // 不再校验集群令牌 —— 否则把机器设成「只认专用令牌」后，本机反而升不了自己。
  const self = !!req.__eqSelf;
  const who = self ? '本机' : '目标机';
  if (!self) {
    const a = lanAccept(req.headers['x-eq-token']);
    if (!a.ok) return fail(res, a.msg, a.code);
  }
  const r0 = lanReady();
  if (!r0.win) return fail(res, who + '不是 Windows，暂不支持远程一键升级', 400);
  if (!r0.engine) return fail(res, who + '缺少升级引擎 tools/deploy/_setup.ps1，请先用一键升级包升级一次', 400);

  let raw;
  try { raw = await readRawBody(req, MAX_PKG_BYTES); }
  catch (e) { return fail(res, String((e && e.message) || e), 413); }
  if (!raw || !raw.length) return fail(res, '没有收到升级包内容', 400);

  let entries;
  try { entries = unzip(raw); } catch (e) { return fail(res, '升级包无法解析：' + e.message, 400); }
  const info = inspectEntries(entries);
  if (!info.ok) return fail(res, info.error, 400);

  const force = String(req.headers['x-eq-force'] || '') === '1';
  if (!force && verCmp(info.version, APP_VERSION) < 0) {
    return fail(res, '升级包版本 ' + info.version + ' 低于本机 ' + APP_VERSION + '（确实要降级请勾选「允许降级」）', 409);
  }

  const stage = path.join(UPGRADE_DIR, 'stage');
  try {
    fs.rmSync(stage, { recursive: true, force: true });
    for (const e of entries) {
      if (e.name.endsWith('/')) continue;
      const dst = path.join(stage, e.name);
      fs.mkdirSync(path.dirname(dst), { recursive: true });
      fs.writeFileSync(dst, e.data);
    }
    fs.writeFileSync(path.join(UPGRADE_DIR, 'receipt.json'), JSON.stringify({
      received_at: new Date().toISOString(), from_version: APP_VERSION, to_version: info.version,
      pushed_by: String(req.headers['x-eq-from'] || 'unknown'), files: entries.length,
    }, null, 2), 'utf8');
  } catch (e) {
    return fail(res, '写入暂存目录失败：' + e.message, 500);
  }

  const engine = path.join(stage, 'setup.ps1');
  if (!fs.existsSync(engine)) return fail(res, '升级包里没有 setup.ps1 安装引擎（请用 build-deploy.py 生成的包）', 400);
  // 引擎能力自检（两项都必须过，否则宁可拒收）：
  //  ① 认 -Port —— 老包（v1.3.0 之前）端口写死 8787，拿它去停自定义端口的服务会误杀别的 node 进程；
  //  ② 会「自派独立进程」—— 否则它作为本服务进程的子进程，会在停服那一刻被一起杀掉，
  //     升级永远卡在第 4 步「停止服务」（实测踩过：日志停在那里，后面什么都没执行）。
  let engineSrc = '', engineRaw = null;
  try { engineRaw = fs.readFileSync(engine); engineSrc = engineRaw.toString('utf8'); } catch { }
  // 包内引擎必须带 UTF-8 BOM：中文 Windows 的代码页是 GBK(936)，Windows PowerShell 5.1
  // 读「无 BOM 的 UTF-8 .ps1」会按 GBK 解码 —— 实测结果是脚本连一行都跑不出来。
  // 与其让目标机静默失败（人不在现场，最难查），不如在这里直接拒收说清原因。
  if (!engineRaw || !(engineRaw[0] === 0xEF && engineRaw[1] === 0xBB && engineRaw[2] === 0xBF)) {
    return fail(res, '这个升级包内置的安装引擎没有 UTF-8 BOM，在中文 Windows 上 PowerShell 会读成乱码、'
      + '根本跑不起来。请改用最新生成的升级包（v1.3.0 及以上）。', 400);
  }
  if (!/\[int\]\s*\$Port/.test(engineSrc)) {
    return fail(res, '这个升级包内置的安装引擎较旧、不支持自定义端口，而本机服务跑在 ' + PORT
      + ' 端口，用它升级会误杀其它进程。请改用最新生成的升级包（v1.3.0 及以上）。', 400);
  }
  if (!/\$Detached/.test(engineSrc)) {
    return fail(res, '这个升级包内置的安装引擎不会「自派独立进程」，被远程拉起后会在停服那一刻被一起杀掉、'
      + '升级永远卡在第 4 步。请改用最新生成的升级包（v1.3.0 及以上）。', 400);
  }

  // 收到的包顺手留一份进本机包仓库（同版本覆盖）—— 这样这台机器升完之后，它自己也能把这个
  // 版本继续推给别的电脑。现场常见情况是只有一台机器拿 U 盘里的包，链式分发能省掉逐台拷包；
  // 少了这一步，「任意一台电脑都能选包升级」在没拷过包的机器上就是句空话（部署包/ 目录不进升级包）。
  try {
    const keep = '收到_' + String(info.version).replace(/^v?/i, 'v').replace(/[^\w.\-]/g, '_') + '.zip';
    fs.mkdirSync(LAN_PKG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LAN_PKG_DIR, keep), raw);
  } catch { /* 留档失败不影响升级本身 */ }

  // 先回响应，再拉起独立的升级进程 —— 它随后会停掉本进程，必须等响应发完
  sendJson(res, {
    ok: true, upgrading: true, from: APP_VERSION, to: info.version,
    files: entries.length, install_dir: ROOT,
    note: self
      ? '本机即将停服并覆盖文件，约 20 秒后自动重启 —— 这个页面会断开，等一会儿刷新即可（日志 _升级日志.txt）'
      : '目标机即将停服并覆盖文件，约 20 秒后自动重启，请到目标机查看 _升级日志.txt',
  });
  setTimeout(() => {
    try {
      const applyLog = path.join(UPGRADE_DIR, 'apply.log');
      const args = ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', engine,
        '-Source', stage, '-Target', ROOT, '-Port', String(PORT), '-LogFile', applyLog];
      // 引擎输出必须落盘：远程升级失败时人不在现场，这份日志是唯一的线索。
      // 这里【不预先往 apply.log 写头部】—— 引擎用 Start-Process 的重定向（覆盖写）
      // 打开它，预写内容会被冲掉；日志头部改由引擎自己输出（参数、时间、PID 一应俱全）。
      //
      // 【踩过坑·关键】为什么这里只要把引擎拉起来就行、停服不再需要本进程配合：
      // 三组对照实验实测（Windows）—— node 直接 spawn 出来的子进程会被「连坐」：
      //   · 本进程被外部杀掉       → 子 PowerShell 约 1 秒后一起消失；
      //   · 子 PowerShell 亲手 Stop-Process 杀掉本进程 → 它自己在 1 秒后也消失
      //     （现场日志正好停在「④ 停止服务」，后面的覆盖 / 重启 / 写日志全都没执行）；
      //   · 由 PowerShell 再用 Start-Process 派生出的「孙进程」→ 完全不受影响，跑完全程。
      // 所以引擎第一步会把自己重新派生成独立进程再交棒，本进程怎么死都不影响它。
      // 另外【绝不能】在这里用 detached:true —— 与 windowsHide 同用时进程会被创建出来
      // 但 PowerShell 完全不执行（无输出、无报错、无副作用，看起来像"升级没反应"）。
      const child = spawn(PSEXE, args, { windowsHide: true, stdio: 'ignore' });
      child.on('error', (e) => {
        try { fs.appendFileSync(applyLog, '[失败] 启动升级引擎出错：' + ((e && e.message) || e) + '\r\n'); } catch { }
        console.error('[远程升级] 启动升级引擎出错：', e && e.message);
      });
      child.unref();
      // 这里【不再做】「5 秒兜底重试」：引擎交棒后启动器进程会立刻退出，退出状态说明不了任何问题；
      // 而此刻引擎的重定向文件未必已建好，"零输出"极易误判 → 拉出第二个引擎 → 两个进程同时升级。
      // 静默失败的风险，改由「引擎自己写日志 + 前端读 receipt/日志」来兜。
      console.log('[远程升级] 已拉起升级进程（端口 ' + PORT + '），本机即将被停止并重启');
    } catch (e) {
      try {
        fs.appendFileSync(path.join(ROOT, '_升级日志.txt'),
          new Date().toLocaleString() + '  [远程升级] 拉起升级进程失败：' + e.message + '\r\n');
        fs.appendFileSync(path.join(UPGRADE_DIR, 'apply.log'),
          new Date().toLocaleString() + '  [失败] 拉起升级进程失败：' + e.message + '\r\n');
      } catch { }
      console.error('[远程升级] 拉起升级进程失败：', e && e.message);
    }
  }, 700);
  return;
}

// ---------- 本机自升级（这台电脑升它自己） ----------
// 现场最常见的其实是「工厂只有这一台机器跑系统」：包已经在这台机器上，但页面是在别处
// （另一台电脑的浏览器，或远程桌面）打开的，不想为了双击一个 .bat 特地跑一趟机器前。
// 做法是【把本机当成一台目标机】—— 直接复用上面那套已实测的接收流程
// （校验包 → 解到 UPGRADE_DIR/stage → 拉起独立安装引擎），不新增任何危险逻辑。
// 与远程推送只有两点差别：① 鉴权走管理员登录（adminOnly 路由），不校验集群令牌，否则
// 把机器设成「只认专用令牌」后本机反而升不了自己；② 包直接来自本机磁盘，不走网络。
// 引擎会先把自己派生成独立进程，所以本服务随后停掉不会把引擎连坐杀掉，升级能跑完。
async function handleLanSelfUpgrade(ctx) {
  const b = ctx.body || {};
  const r0 = lanReady();
  if (!r0.win) return fail(ctx.res, '本机不是 Windows，暂不支持一键自升级', 400);
  if (!r0.engine) return fail(ctx.res, '本机缺少升级引擎 tools/deploy/_setup.ps1，请先用一键升级包手工升一次', 400);
  let p;
  try { p = resolvePkg(b.pkg); } catch (e) { return fail(ctx.res, e.message, 400); }
  let raw;
  try { raw = fs.readFileSync(p.path); } catch (e) { return fail(ctx.res, '读不到升级包：' + e.message, 500); }
  if (!raw.length) return fail(ctx.res, '升级包是空的', 400);
  // 造一个「内部请求」喂给接收流程：包体来自磁盘，响应用真实的 res（页面那边能拿到统一的回执）
  const fake = new Readable({ read() { } });
  fake.__eqSelf = true;
  fake.headers = { 'x-eq-force': b.force ? '1' : '', 'x-eq-from': '本机后台' };
  fake.push(raw); fake.push(null);
  return handleLanApply({ req: fake, res: ctx.res });
}

// ---------- 电脑清单（发起端维护） ----------
const allLanClients = () => kvget('lanClients', []);
function findLanClient(id) { return allLanClients().find(c => c.id === id) || null; }
function normClient(b, base) {
  const c = Object.assign({ id: uuid(), name: '', host: '', port: DEFAULT_PORT_, token: '', note: '',
    created_at: new Date().toISOString(), last_ok: null, last_version: '', last_check: '', last_error: '' }, base || {});
  if (typeof b.name === 'string') c.name = b.name.trim().slice(0, 40);
  if (typeof b.host === 'string') c.host = b.host.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  if (b.port !== undefined && b.port !== '') {
    const p = parseInt(b.port, 10);
    if (!(p > 0 && p < 65536)) throw new Error('端口号不正确');
    c.port = p;
  }
  if (typeof b.token === 'string') c.token = b.token.trim();
  if (typeof b.note === 'string') c.note = b.note.trim().slice(0, 80);
  if (!c.host) throw new Error('请填写目标机的 IP 或计算机名');
  if (!/^[A-Za-z0-9._:\-\[\]]+$/.test(c.host)) throw new Error('IP / 计算机名格式不正确');
  if (!c.name) c.name = c.host;
  return c;
}
async function handleLanClients(ctx) {
  return sendJson(ctx.res, { ok: true, clients: allLanClients(),
    self: { host: os.hostname(), port: PORT, addrs: localAddrs(),
            version: APP_VERSION, install_dir: ROOT, ready: lanReady() } });
}
async function handleLanClientCreate(ctx) {
  let c;
  try { c = normClient(ctx.body || {}); } catch (e) { return fail(ctx.res, e.message); }
  if (isSelfTarget(c.host, c.port)) return fail(ctx.res, '这就是本机（' + c.host + ':' + c.port + '）—— 不用加进清单：要升级这台电脑自己，请在系统页点「🖥 升级本机」', 400);
  const list = allLanClients();
  if (list.some(x => x.host === c.host && x.port === c.port)) return fail(ctx.res, '这台电脑已经在清单里了', 409);
  list.push(c);
  kvset('lanClients', list);
  return sendJson(ctx.res, { ok: true, client: c });
}
async function handleLanClientUpdate(ctx) {
  const list = allLanClients();
  const i = list.findIndex(x => x.id === ctx.params.id);
  if (i < 0) return fail(ctx.res, '这台电脑不在清单里', 404);
  let c;
  try { c = normClient(ctx.body || {}, list[i]); } catch (e) { return fail(ctx.res, e.message); }
  c.id = list[i].id; c.created_at = list[i].created_at;
  if (isSelfTarget(c.host, c.port)) return fail(ctx.res, '这就是本机，不能加进待升级清单', 400);
  list[i] = c;
  kvset('lanClients', list);
  return sendJson(ctx.res, { ok: true, client: c });
}
async function handleLanClientDelete(ctx) {
  const list = allLanClients();
  const n = list.length;
  const next = list.filter(x => x.id !== ctx.params.id);
  if (next.length === n) return fail(ctx.res, '这台电脑不在清单里', 404);
  kvset('lanClients', next);
  return sendJson(ctx.res, { ok: true, removed: 1 });
}
// 探测单台：拿到版本 / 可用性 / 失败原因
async function probeClient(c, timeout) {
  const port = c.port || DEFAULT_PORT_;
  const t0 = Date.now();
  const r = await httpJson(c.host, port, '/api/lan-upgrade/ping',
    { headers: { 'X-EQ-Token': c.token || LAN_CLUSTER_KEY }, timeout: timeout || 5000 });
  const ms = Date.now() - t0;
  if (r.status === 200 && r.json && r.json.ok) {
    return { ok: true, ms, reachable: true, version: r.json.version, date: r.json.date,
      peer: r.json.name, enabled: r.json.enabled, engine: r.json.engine,
      install_dir: r.json.install_dir, peer_port: r.json.port };
  }
  if (r.status === 401) return { ok: false, ms, reachable: true, code: 401, version: '', error: '目标机不认这次的升级凭据 —— 它可能被设成了「只认专用令牌」（若是，请到那台电脑后台复制令牌填到这里），也可能两边版本差得太多' };
  if (r.status === 403) return { ok: false, ms, reachable: true, code: 403, version: '', error: '目标机已连上，但它关掉了「接受局域网升级」—— 要到那台电脑的后台·系统页打开' };
  if (r.status === 404) {
    const v = await httpJson(c.host, port, '/api/version', { timeout: 3000 });
    const ver = (v.json && v.json.version) || '';
    return { ok: false, ms, reachable: true, code: 404, version: ver,
      error: '目标是旧版本' + (ver ? '（' + ver + '）' : '') + '，还不支持远程升级 —— 先用一键升级包升级一次' };
  }
  if (r.status === 0) return { ok: false, ms, reachable: false, code: 0, version: '', error: '连不上：' + (r.error || '超时') };
  return { ok: false, ms, reachable: true, code: r.status, version: '', error: '目标机返回异常：HTTP ' + r.status };
}
async function handleLanCheck(ctx) {
  const b = ctx.body || {};
  let list = allLanClients();
  if (Array.isArray(b.ids) && b.ids.length) list = list.filter(c => b.ids.includes(c.id));
  if (!list.length) return sendJson(ctx.res, { ok: true, results: [], at: new Date().toISOString() });
  const results = [];
  const CONC = 6;
  for (let i = 0; i < list.length; i += CONC) {
    const chunk = list.slice(i, i + CONC);
    const rs = await Promise.all(chunk.map(c => probeClient(c)));
    chunk.forEach((c, k) => results.push(Object.assign({ id: c.id, name: c.name, host: c.host, port: c.port }, rs[k])));
  }
  // 回写最近状态，清单里直接能看到
  const all = allLanClients(); let dirty = false;
  for (const r of results) {
    const c = all.find(x => x.id === r.id);
    if (!c) continue;
    c.last_ok = !!r.ok;
    if (r.version) c.last_version = r.version;
    c.last_check = new Date().toISOString();
    c.last_error = r.ok ? '' : (r.error || '');
    dirty = true;
  }
  if (dirty) kvset('lanClients', all);
  return sendJson(ctx.res, { ok: true, results, at: new Date().toISOString() });
}
// ---------- 升级包仓库（扫 部署包/ + 后台上传 + 本机收包留档） ----------
function listPackages() {
  const out = [];
  const scan = (dir, origin) => {
    let names = [];
    try { names = fs.readdirSync(dir); } catch { return; }
    for (const n of names) {
      if (!/\.(zip|bat)$/i.test(n)) continue;
      const p = path.join(dir, n);
      let st; try { st = fs.statSync(p); } catch { continue; }
      if (!st.isFile()) continue;
      const item = { id: origin + ':' + n, name: n, origin, size: st.size, mtime: st.mtime.toISOString(),
        version: '', files: 0, ok: false, error: '' };
      try {
        const entries = unzip(readPkgFile(p));
        const info = inspectEntries(entries);
        item.ok = info.ok; item.error = info.error || '';
        item.version = info.version || ''; item.files = entries.length;
      } catch (e) { item.error = String((e && e.message) || e); }
      out.push(item);
    }
  };
  scan(DIST_DIR, 'dist');       // build-deploy.py 生成的成品包
  scan(LAN_PKG_DIR, 'upload');  // 后台上传的包
  out.sort((a, b) => verCmp(b.version, a.version) || String(b.mtime).localeCompare(String(a.mtime)));
  return out;
}
function resolvePkg(id) {
  const s = String(id || '');
  const i = s.indexOf(':');
  if (i < 0) throw new Error('升级包标识不正确');
  const origin = s.slice(0, i), name = s.slice(i + 1);
  if (origin !== 'dist' && origin !== 'upload') throw new Error('升级包来源不正确');
  if (!name || /[\\/]/.test(name) || name.includes('..')) throw new Error('升级包文件名不合法');
  const p = path.join(origin === 'dist' ? DIST_DIR : LAN_PKG_DIR, name);
  if (!fs.existsSync(p)) throw new Error('升级包不存在：' + name);
  return { path: p, origin, name, id: origin + ':' + name };
}
async function handleLanPackages(ctx) {
  // 排序规则：能解析的在前，然后版本号从高到低。
  // 【踩过坑】原来直接返回目录遍历顺序，界面又默认选中「第一个比本机新的包」——
  // 实测一个 v9.9.9 的坏包被排在前面并自动选中，现场手一抖点「推送」就把它推了出去。
  // 固定成「版本最高优先」后，默认选中的永远是当前可用的最新版本。
  const pkgs = listPackages().sort((a, b) => {
    if (!!a.ok !== !!b.ok) return a.ok ? -1 : 1;
    return verCmp(b.version || '0', a.version || '0');
  });
  const cur = pkgs.filter(p => p.ok && verCmp(p.version, APP_VERSION) > 0);
  return sendJson(ctx.res, {
    ok: true, packages: pkgs, current: APP_VERSION,
    dist_dir: DIST_DIR, upload_dir: LAN_PKG_DIR, dist_exists: fs.existsSync(DIST_DIR),
    newest: cur.length ? cur[0].version : '',
  });
}
async function handleLanPackageUpload(ctx) {
  const req = ctx.req, res = ctx.res;
  let raw;
  try { raw = await readRawBody(req, MAX_PKG_BYTES); }
  catch (e) { return fail(res, String((e && e.message) || e), 413); }
  if (!raw || !raw.length) return fail(res, '没有收到文件内容', 400);
  let rawName = '';
  try { rawName = decodeURIComponent(String(req.headers['x-eq-filename'] || '')); } catch { rawName = String(req.headers['x-eq-filename'] || ''); }
  let name = path.basename(rawName).replace(/[\\/:*?"<>|]/g, '_').trim();
  if (!name) name = 'upload.zip';
  let buf, isBat = /\.bat$/i.test(name);
  try { buf = isBat ? extractBatPayload(raw) : raw; }
  catch (e) { return fail(res, e.message, 400); }
  let entries;
  try { entries = unzip(buf); } catch (e) { return fail(res, '文件不是有效的升级包：' + e.message, 400); }
  const info = inspectEntries(entries);
  if (!info.ok) return fail(res, '升级包校验失败：' + info.error, 400);
  if (!/\.zip$/i.test(name)) name = name.replace(/\.(bat)?$/i, '') + '.zip';
  try {
    fs.mkdirSync(LAN_PKG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LAN_PKG_DIR, name), buf);
  } catch (e) { return fail(res, '保存失败：' + e.message, 500); }
  return sendJson(res, {
    ok: true, id: 'upload:' + name, name, version: info.version, files: entries.length,
    size: buf.length, converted_from_bat: isBat,
  });
}
async function handleLanPackageDelete(ctx) {
  const origin = ctx.query.get('origin') || 'upload';
  let p;
  let pname = ctx.params.name;
  try { pname = decodeURIComponent(pname); } catch { }
  try { p = resolvePkg(origin + ':' + pname); } catch (e) { return fail(ctx.res, e.message, 404); }
  try { fs.unlinkSync(p.path); } catch (e) { return fail(ctx.res, '删除失败：' + e.message, 500); }
  return sendJson(ctx.res, { ok: true, removed: 1 });
}
// ---------- 推送升级（任意一台电脑都能当发起端） ----------
async function handleLanUpgrade(ctx) {
  const b = ctx.body || {};
  const ids = Array.isArray(b.ids) ? b.ids : [];
  if (!ids.length) return fail(ctx.res, '请先勾选要升级的电脑');
  let pkg, buf, info;
  try {
    pkg = resolvePkg(b.pkg);
    buf = readPkgFile(pkg.path);
    info = inspectEntries(unzip(buf));
  } catch (e) { return fail(ctx.res, '升级包不可用：' + e.message); }
  if (!info.ok) return fail(ctx.res, '升级包校验失败：' + info.error);

  const all = allLanClients();
  const targets = ids.map(id => all.find(c => c.id === id)).filter(Boolean);
  if (!targets.length) return fail(ctx.res, '选中的电脑不在清单里');

  const force = !!b.force;
  const skipSame = b.skip_same !== false;   // 已经同版本的默认跳过，避免白折腾
  const results = [];
  for (const c of targets) {   // 串行推送：一次只让一台机器重启，网络与日志都清爽
    const base = { id: c.id, name: c.name, host: c.host, port: c.port };
    if (isSelfTarget(c.host, c.port)) { results.push(Object.assign(base, { ok: false, error: '这就是本机 —— 已跳过（要升这一台自己，请点下面的「🖥 升级本机」）' })); continue; }
    // 没填专用令牌就用系统级共享密钥：目标端默认就认它，这才是「管理员登录即可推」的支点。
    // 原来这里在没填令牌时直接拒发，等于每加一台机器都得先去它后台抄一次令牌。
    const pre = await probeClient(c, 6000);
    if (!pre.ok) { results.push(Object.assign(base, { ok: false, from: pre.version || '', error: pre.error || '目标机不可用' })); continue; }
    if (skipSame && !force && verCmp(pre.version, info.version) === 0) {
      results.push(Object.assign(base, { ok: true, from: pre.version, to: pre.version, skipped: true, note: '本来就是 ' + pre.version + '，已跳过' }));
      continue;
    }
    const r = await httpJson(c.host, c.port || DEFAULT_PORT_, '/api/lan-upgrade/apply', {
      method: 'POST', timeout: 180000,
      headers: {
        'Content-Type': 'application/zip',
        'X-EQ-Token': c.token || LAN_CLUSTER_KEY,
        'X-EQ-From': lanName(),
        ...(force ? { 'X-EQ-Force': '1' } : {}),
      },
      body: buf,
    });
    if (r.status === 200 && r.json && r.json.ok) {
      results.push(Object.assign(base, { ok: true, from: r.json.from || pre.version, to: r.json.to || info.version,
        note: '已下发，目标机正在重启' }));
    } else {
      results.push(Object.assign(base, { ok: false, from: pre.version, code: r.status,
        error: (r.json && r.json.error) || r.error || ('HTTP ' + r.status) }));
    }
  }
  return sendJson(ctx.res, {
    ok: results.every(x => x.ok), pkg: pkg.name, version: info.version,
    results, at: new Date().toISOString(),
  });
}
// ---------- 分发中心：扫描本网段 ----------
function localSubnets() {
  const out = [];
  const ifs = os.networkInterfaces();
  for (const k in ifs) for (const a of (ifs[k] || [])) {
    if (a.family !== 'IPv4' || a.internal) continue;
    if (a.address.startsWith('169.254.')) continue;
    const p = a.address.split('.');
    if (p.length !== 4) continue;
    const pre = p.slice(0, 3).join('.');
    if (!out.includes(pre)) out.push(pre);
  }
  return out.slice(0, 4);
}
async function handleLanScan(ctx) {
  const port = parseInt(ctx.query.get('port') || DEFAULT_PORT_, 10) || DEFAULT_PORT_;
  const subnets = localSubnets();
  const hosts = [];
  for (const s of subnets) for (let i = 1; i <= 254; i++) hosts.push(s + '.' + i);
  const found = [];
  const CONC = 64;
  for (let i = 0; i < hosts.length; i += CONC) {
    const chunk = hosts.slice(i, i + CONC);
    const rs = await Promise.all(chunk.map(async (h) => {
      const t0 = Date.now();
      const r = await httpJson(h, port, '/api/version', { timeout: 700 });
      if (r.json && r.json.version) return { host: h, port, version: r.json.version, date: r.json.date || '', ms: Date.now() - t0 };
      return null;
    }));
    for (const x of rs) if (x) found.push(x);
  }
  const known = new Set(allLanClients().map(c => c.host + ':' + (c.port || DEFAULT_PORT_)));
  const self = new Set(localAddrs());
  for (const f of found) { f.known = known.has(f.host + ':' + f.port); f.self = self.has(f.host) && f.port === PORT; }
  found.sort((a, b) => a.host.localeCompare(b.host, undefined, { numeric: true }));
  return sendJson(ctx.res, { ok: true, port, subnets, scanned: hosts.length, found, at: new Date().toISOString() });
}

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

  // ---- 科室管理（后台维护清单：房间 / 用户下拉共用）----
  { method: 'GET', path: '/api/depts', handler: handleListDepts },
  { method: 'POST', path: '/api/depts', handler: handleCreateDept, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/depts\/([^/]+)$/, paramNames: ['name'], handler: handleDeleteDept, adminOnly: true },

  // ---- 温湿度点检记录（按房间 + 年月；任意登录用户可录入） ----
  { method: 'GET', path: '/api/env-records', handler: handleGetEnvRecord },
  { method: 'POST', path: '/api/env-records', handler: handleSaveEnvRecord },
  { method: 'POST', path: '/api/env-records/sign-cell', handler: handleSignEnvCell },
  { method: 'POST', path: '/api/admin/env-fill', handler: handleEnvFill, adminOnly: true },
  { method: 'GET', path: '/api/admin/env-records/export-csv', handler: handleExportEnvCsv, adminOnly: true },

  // ---- 数据备份 / 导出（管理员） ----
  // ---- 局域网远程升级（分发中心，管理员） ----
  { method: 'GET',    path: '/api/lan/clients',            handler: handleLanClients, adminOnly: true },
  { method: 'POST',   path: '/api/lan/clients',            handler: handleLanClientCreate, adminOnly: true },
  { method: 'PUT',    pattern: /^\/api\/lan\/clients\/([^/]+)$/, paramNames: ['id'], handler: handleLanClientUpdate, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/lan\/clients\/([^/]+)$/, paramNames: ['id'], handler: handleLanClientDelete, adminOnly: true },
  { method: 'POST',   path: '/api/lan/check',              handler: handleLanCheck, adminOnly: true },
  { method: 'GET',    path: '/api/lan/scan',               handler: handleLanScan, adminOnly: true },
  { method: 'GET',    path: '/api/lan/packages',           handler: handleLanPackages, adminOnly: true },
  { method: 'POST',   path: '/api/lan/packages/upload',    handler: handleLanPackageUpload, adminOnly: true, raw: true },
  { method: 'DELETE', pattern: /^\/api\/lan\/packages\/([^/]+)$/, paramNames: ['name'], handler: handleLanPackageDelete, adminOnly: true },
  { method: 'POST',   path: '/api/lan/upgrade',            handler: handleLanUpgrade, adminOnly: true },
  { method: 'POST',   path: '/api/admin/lan/self-upgrade', handler: handleLanSelfUpgrade, adminOnly: true },

  // ---- 本机作为被升级目标（令牌认证，不走管理员会话） ----
  { method: 'GET',    path: '/api/lan-upgrade/config',     handler: handleLanTargetConfig, adminOnly: true },
  { method: 'PUT',    path: '/api/lan-upgrade/config',     handler: handleLanTargetConfigPut, adminOnly: true },
  { method: 'GET',    path: '/api/lan-upgrade/ping',       handler: handleLanPing },
  { method: 'POST',   path: '/api/lan-upgrade/apply',      handler: handleLanApply, raw: true },
  { method: 'GET', path: '/api/admin/backup', handler: handleBackup, adminOnly: true },
  { method: 'GET', path: '/api/admin/export-inspections-csv', handler: handleExportCsv, adminOnly: true },
];

function matchRoute(method, p) {
  for (const r of routes) {
    if (r.method !== method) continue;
    if (r.path === p) return { handler: r.handler, params: {}, adminOnly: !!r.adminOnly, raw: !!r.raw };
    if (r.pattern) {
      const m = p.match(r.pattern);
      if (m) {
        const params = {};
        if (r.paramNames) r.paramNames.forEach((name, i) => { params[name] = m[i + 1]; });
        return { handler: r.handler, params, adminOnly: !!r.adminOnly, raw: !!r.raw };
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
    // raw:true 的路由（升级包上传）自己读原始字节，这里不能先吞掉请求流
    const body = (!route.raw && (method === 'POST' || method === 'PUT')) ? await readBody(req, res) : {};
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
