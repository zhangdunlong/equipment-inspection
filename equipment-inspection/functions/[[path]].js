// Cloudflare Pages Functions —— 设备点检巡检系统后端
// 单文件 catch-all 路由，所有 /api/* 请求在此处理。
// 移植自本地最新版 server.js（v1.37.1 / 2026-09-21：声明式路由表 + 科室管理 + 房间温湿度配置 +
// 温湿度点检（按房间+年月）一键填充/批量删除/CSV 导出 + LIMS 数据源抓取 + 整月按科室随机分派签名 +
// 模板高级编辑（改表头/整体替换检查项/复制/删除/导入）+ 数据备份 + CSV 导出 + 单台明细 +
// 多用户角色权限 + 后台用户管理）。
// 数据存于 KV 命名空间 INSPECTION_DATA（绑定名见 wrangler.toml），单键 STORE 存整个 store 对象。
// 签名去重：每条巡检记录【不】内嵌 signature_image（避免 2424 份重复导致 STORE 膨胀到 41MB），
// 读取时由 signerSignature() 按 signer_id 从签名人记录注入签名图，前端零改动。
// 静态资源（HTML/CSS/JS）与 pretty URL（/inspect、/admin、/login、/rooms 等）经 env.ASSETS 透传。

const ADMIN_COOKIE = 'admin_token';
const KV_KEY = 'STORE';

// ---------- 工具 ----------
function randHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function sha256(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}
async function buildToken(user, secret) { return user + '.' + await hmac(secret, user); }
function uuid() {
  try { return crypto.randomUUID(); } catch { return 'id-' + Date.now() + '-' + Math.random().toString(16).slice(2); }
}

// 单张签名图上限（base64 字符数）。超限一律「拒绝并报错」，绝不静默截断 —— 被截断的 base64 是坏数据。
const SIG_IMG_MAX = 2000000;   // ≈1.5MB 图片，够放下高清手写/扫描签名
// 落记录快照时用：横版优先，没有横版才退回竖版（老数据）
function pickSigImage(s) {
  if (!s) return null;
  return s.signature_image || s.signature_image_v || null;
}
function normSigDir(v) { return v === 'v' ? 'v' : (v === 'h' ? 'h' : 'auto'); }
function sigImageNorm(v) {
  if (v == null || v === '') return { value: null };
  if (typeof v !== 'string' || !/^data:image\//.test(v)) return { value: null };
  if (v.length > SIG_IMG_MAX) {
    return { error: '电子签名图过大（约 ' + Math.round(v.length / 1024) +
      'KB，上限 ' + Math.round(SIG_IMG_MAX / 1024) + 'KB）。请把图片裁小/压缩后再上传' };
  }
  return { value: v };
}

// 用户名允许中文/英文/数字及常用符号（2-32 位）。
const USERNAME_RE = /^[\u4e00-\u9fa5A-Za-z0-9._@-]{2,32}$/;
const validUsername = (s) => typeof s === 'string' && USERNAME_RE.test(s);

// ---------- 响应 / Cookie ----------
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: Object.assign({
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    }, extra),
  });
}
function getCookie(req, name) {
  const c = req.headers.get('cookie') || '';
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
  return `${ADMIN_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`;
}

// ---------- 数据存储（KV 单键 STORE） ----------
function defaultStore() {
  return { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], users: [], depts: [], envRecords: [], pepper: '', secret: '' };
}
async function loadStore(env) {
  const v = await env.INSPECTION_DATA.get(KV_KEY);
  if (v === null) return defaultStore();
  try {
    const o = JSON.parse(v);
    return Object.assign(defaultStore(), o);
  } catch {
    return defaultStore();
  }
}

// ---------- 鉴权（多用户 + 角色权限） ----------
async function getLoginUser(req, store) {
  const t = getCookie(req, ADMIN_COOKIE);
  if (!t) return null;
  const i = t.lastIndexOf('.');
  if (i < 0) return null;
  const u = t.slice(0, i), sig = t.slice(i + 1);
  if (sig !== await hmac(store.secret, u)) return null;
  const users = store.users || [];
  return users.find(x => x.username === u && x.active) || null;
}
async function isAdmin(req, store) {
  const u = await getLoginUser(req, store);
  return !!(u && u.role === 'admin');
}
// 兼容旧逻辑：无 users 数据时的默认管理员（PEPPER 生成 admin/admin123）
async function getAdmin(store) {
  if (store.admin) return store.admin;
  return { username: 'admin', password_hash: await sha256('admin123' + store.pepper) };
}
// 确保 users 初始化：首次启动 seed 一个 admin 用户
async function ensureUsers(store) {
  const users = store.users || [];
  if (users.length) return false;
  const admin = store.admin;
  const ph = (admin && admin.password_hash) || await sha256('admin123' + store.pepper);
  store.users = [{ id: 'u-admin', username: 'admin', name: '管理员', password_hash: ph, role: 'admin', active: true, created_at: new Date().toISOString() }];
  return true;
}

// ---------- 业务助手 ----------
async function deviceItems(store, dev) {
  if (!dev || !dev.template_id) return [];
  const t = (store.templates || []).find(t => t.id === dev.template_id);
  return t ? (t.items || []) : [];
}
async function readBody(req) {
  try { const text = await req.text(); return text ? JSON.parse(text) : {}; }
  catch { return {}; }
}
function statusFromBySn(bySn) {
  for (const k in bySn) if (bySn[k] === 'ng') return 'ng';
  return 'ok';
}
function buildBySn(items, status) {
  const bySn = {};
  items.forEach(it => { bySn[it.sn] = status; });
  return bySn;
}
// 日期工具
function todayStr() {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function isFutureDate(ds) { return String(ds) > todayStr(); }
function currentMonthStr() { return todayStr().slice(0, 7); }
function monthDays(month, endDay) {
  const [yy, mm] = month.split('-');
  const days = [];
  for (let day = 1; day <= endDay; day++) {
    days.push(`${yy}-${mm}-${String(day).padStart(2, '0')}`);
  }
  return days;
}
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
// 点检时间戳策略：随机落在 08:00~10:00（当天不超当前时间），无未来时间
function randMorningTime(ds) {
  const [yy, mm, dd] = String(ds).split('-').map(Number);
  const dayStart = new Date(yy, mm - 1, dd, 0, 0, 0, 0).getTime();
  const start = dayStart + 8 * 3600 * 1000;
  let end = dayStart + 10 * 3600 * 1000;
  const now = Date.now();
  if (ds === todayStr()) end = Math.min(end, now);
  if (end < start) return new Date(now).toISOString();
  return new Date(start + Math.floor(Math.random() * (end - start))).toISOString();
}
// 签名去重：从签名人记录取签名图（优先 signer_id，回退 signed_by 姓名）
function signerSignature(store, rec) {
  const signers = store.signers || [];
  let s = (rec && rec.signer_id) ? signers.find(x => x.id === rec.signer_id) : null;
  if (!s && rec && rec.signed_by) s = signers.find(x => x.name === rec.signed_by);
  return s ? (s.signature_image || null) : null;
}
// 注意：必须在写入后调用 kvset 标记 dirty，否则 finally 的 PUT 不会触发、改动丢失
async function upsertInspection(ctx, rec, extra) {
  const list = ctx.store.inspections;
  const idx = list.findIndex(r => r.device_id === rec.device_id && r.inspect_date === rec.inspect_date);
  const record = Object.assign({}, rec, extra);
  if (idx >= 0) { list[idx] = record; } else { list.push(record); }
  ctx.kvset('inspections', list);
  return idx >= 0 ? 'updated' : 'created';
}
// 校验签名人身份：返回 { signer } 或 { error, status }
async function verifySigner(store, body) {
  const signer = (store.signers || []).find(s => s.id === body.signer_id);
  if (!signer) return { error: '签名人不存在' };
  if (await sha256((body.password || '') + store.pepper) !== signer.password_hash) return { error: '签名密码错误', status: 401 };
  return { signer };
}
function roomCounts(store) {
  const c = {};
  (store.devices || []).forEach(d => {
    const loc = (d.location || '').trim();
    c[loc] = (c[loc] || 0) + 1;
  });
  return c;
}
function csvCell(v) {
  const s = v == null ? '' : String(v);
  return '"' + s.replace(/"/g, '""') + '"';
}

// ===================== API 处理器（ctx = { req, env, store, kvget, kvset, params, query, body }） =====================

// ---------- 鉴权 ----------
async function handleMe(ctx) {
  const u = await getLoginUser(ctx.req, ctx.store);
  return json({
    ok: !!u, username: u ? u.username : '', name: u ? u.name : '', role: u ? u.role : '', dept: u ? (u.dept || '') : '',
    signer_id: u ? (u.signer_id || '') : '',   // 登录人绑定的默认签名人：温湿度记录员默认选中自己
    perms: u ? (u.perms || null) : null,       // 未配置过权限的用户为 null —— 前端按默认表推有效值
  });
}
async function handleLogin(ctx) {
  const b = ctx.body;
  const users = ctx.kvget('users', []);
  const user = users.find(x => x.username === b.username && x.active);
  if (user) {
    const ph = await sha256((b.password || '') + ctx.store.pepper);
    if (ph === user.password_hash) {
      const token = await buildToken(user.username, ctx.store.secret);
      return json({ ok: true, username: user.username, name: user.name, role: user.role },
        200, { 'Set-Cookie': adminCookie(token) });
    }
  }
  return json({ error: '账号或密码错误' }, 401);
}
async function handleChangePw(ctx) {
  const b = ctx.body;
  if (!b.password || String(b.password).length < 4) return json({ error: '密码至少 4 位' }, 400);
  const me = await getLoginUser(ctx.req, ctx.store);
  if (!me) return json({ error: '未登录或登录已失效' }, 401);
  const users = ctx.kvget('users', []);
  const u = users.find(x => x.id === me.id);
  if (!u) return json({ error: '用户不存在' }, 404);
  u.password_hash = await sha256(b.password + ctx.store.pepper);
  ctx.kvset('users', users);
  return json({ ok: true });
}

// ---------- 用户管理（仅管理员） ----------
async function handleListUsers(ctx) {
  const users = ctx.kvget('users', []);
  return json(users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active, dept: u.dept || '', signer_id: u.signer_id || '', perms: u.perms || null })));
}
async function handleCreateUser(ctx) {
  const b = ctx.body;
  const username = (b.username || '').trim();
  if (!username || !b.password) return json({ error: '用户名与密码必填' }, 400);
  if (!validUsername(username)) return json({ error: '用户名只能为 2-32 位英文、数字、下划线、点、连字符（登录账号必须为 ASCII）' }, 400);
  if (String(b.password).length < 4) return json({ error: '密码至少 4 位' }, 400);
  const users = ctx.kvget('users', []);
  if (users.some(u => u.username === username)) return json({ error: '用户名已存在' }, 400);
  users.push({ id: uuid(), username, name: (b.name || '').trim() || username,
    password_hash: await sha256(b.password + ctx.store.pepper),
    role: b.role === 'admin' ? 'admin' : 'user', active: b.active === false ? false : true,
    created_at: new Date().toISOString() });
  ctx.kvset('users', users);
  return json({ ok: true });
}
async function handleUpdateUser(ctx) {
  const b = ctx.body;
  const users = ctx.kvget('users', []);
  const u = users.find(x => x.id === ctx.params.id);
  if (!u) return json({ error: '用户不存在' }, 404);
  const me = await getLoginUser(ctx.req, ctx.store);
  if (me && me.id === u.id && b.active === false) return json({ error: '不能停用当前登录账号' }, 400);
  if (b.username && b.username.trim()) {
    const u2 = b.username.trim();
    if (!validUsername(u2)) return json({ error: '用户名只能为 2-32 位英文、数字、下划线、点、连字符' }, 400);
    if (users.some(x => x.id !== u.id && x.username === u2)) return json({ error: '用户名已存在' }, 400);
    u.username = u2;
  }
  if ('name' in b) u.name = (b.name || '').trim() || u.username;
  if (b.password) {
    if (String(b.password).length < 4) return json({ error: '密码至少 4 位' }, 400);
    u.password_hash = await sha256(b.password + ctx.store.pepper);
  }
  if (b.role === 'admin' || b.role === 'user') u.role = b.role;
  if (typeof b.active === 'boolean') u.active = b.active;
  ctx.kvset('users', users);
  return json({ ok: true });
}
async function handleDeleteUser(ctx) {
  const me = await getLoginUser(ctx.req, ctx.store);
  if (me && me.id === ctx.params.id) return json({ error: '不能删除当前登录账号' }, 400);
  const users = ctx.kvget('users', []).filter(x => x.id !== ctx.params.id);
  ctx.kvset('users', users);
  return json({ ok: true });
}

// ---------- 签名人员 ----------
async function handlePublicSigners(ctx) {
  const list = ctx.kvget('signers', []);
  return json(list.filter(s => s.active).map(s => ({ id: s.id, name: s.name,
    signature_image: s.signature_image || null, signature_image_v: s.signature_image_v || null,
    sig_dir: normSigDir(s.sig_dir) })));
}
async function handleListSigners(ctx) {
  const list = ctx.kvget('signers', []);
  return json(list.map(s => ({ id: s.id, name: s.name, active: !!s.active, dept: s.dept || '',
    has_sig: !!s.signature_image, has_sig_v: !!s.signature_image_v, sig_dir: normSigDir(s.sig_dir),
    chars: (s.sig_chars || []).length })));
}
async function handleCreateSigner(ctx) {
  const b = ctx.body;
  if (!b.name || !b.password) return json({ error: '姓名与密码必填' }, 400);
  const him = sigImageNorm(b.signature_image);
  if (him.error) return json({ error: him.error }, 413);
  const vim = sigImageNorm(b.signature_image_v);
  if (vim.error) return json({ error: vim.error }, 413);
  const list = ctx.kvget('signers', []);
  list.push({ id: uuid(), name: b.name, active: true, password_hash: await sha256(b.password + ctx.store.pepper),
    dept: String(b.dept || '').trim(),
    signature_image: him.value, signature_image_v: vim.value,
    sig_chars: Array.isArray(b.sig_chars) ? b.sig_chars.map(x => sigImageNorm(x).value || '').slice(0, 12) : [],
    sig_dir: normSigDir(b.sig_dir) });
  ctx.kvset('signers', list);
  return json({ ok: true });
}
async function handleGetSignerSignature(ctx) {
  const s = (ctx.kvget('signers', [])).find(x => x.id === ctx.params.id);
  if (!s) return json({ image: null, image_h: null, image_v: null, chars: [], dir: 'h' });
  return json({ image: pickSigImage(s), image_h: s.signature_image || null, image_v: s.signature_image_v || null,
    chars: s.sig_chars || [], dir: normSigDir(s.sig_dir) });
}
async function handleUpdateSigner(ctx) {
  const b = ctx.body;
  const list = ctx.kvget('signers', []);
  const s = list.find(x => x.id === ctx.params.id);
  if (!s) return json({ error: '签名人不存在' }, 404);
  const him = ('signature_image' in b) ? sigImageNorm(b.signature_image) : {};
  if (him.error) return json({ error: him.error }, 413);
  const vim = ('signature_image_v' in b) ? sigImageNorm(b.signature_image_v) : {};
  if (vim.error) return json({ error: vim.error }, 413);
  if (typeof b.name === 'string' && b.name.trim()) s.name = b.name.trim().slice(0, 40);
  if (typeof b.active === 'boolean') s.active = b.active;
  if ('dept' in b) s.dept = String(b.dept || '').trim();
  if (b.password) s.password_hash = await sha256(b.password + ctx.store.pepper);
  if ('signature_image' in b) s.signature_image = him.value;
  if ('signature_image_v' in b) s.signature_image_v = vim.value;
  if ('sig_chars' in b && Array.isArray(b.sig_chars)) s.sig_chars = b.sig_chars.map(x => sigImageNorm(x).value || '').slice(0, 12);
  if ('sig_dir' in b) s.sig_dir = normSigDir(b.sig_dir);
  ctx.kvset('signers', list);
  return json({ ok: true });
}
async function handleDeleteSigner(ctx) {
  const list = ctx.kvget('signers', []).filter(x => x.id !== ctx.params.id);
  ctx.kvset('signers', list);
  return json({ ok: true });
}

// ---------- 模板 ----------
async function handleListTemplates(ctx) { return json(ctx.kvget('templates', [])); }
async function handleCreateTemplate(ctx) {
  const b = ctx.body;
  if (!b.key || !b.equip_name) return json({ error: '模板标识与设备名称必填' }, 400);
  const tpls = ctx.kvget('templates', []);
  const t = { id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '', source_file: '', items: [] };
  tpls.push(t); ctx.kvset('templates', tpls);
  return json(t);
}
async function handleAddTemplateItem(ctx) {
  const b = ctx.body;
  if (!b.content) return json({ error: '检查内容必填' }, 400);
  const tpls = ctx.kvget('templates', []);
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return json({ error: '模板不存在' }, 404);
  t.items = t.items || [];
  t.items.push({ sn: t.items.length + 1, content: b.content, frequency: b.frequency || '' });
  ctx.kvset('templates', tpls);
  return json({ ok: true });
}

// ---------- 设备 ----------
async function handleListDevices(ctx) { return json(ctx.kvget('devices', [])); }
async function handleCreateDevice(ctx) {
  const b = ctx.body;
  if (!b.no) return json({ error: '设备编号必填' }, 400);
  const list = ctx.kvget('devices', []);
  if (list.some(d => d.no === b.no)) return json({ error: '编号已存在' }, 400);
  const d = { id: uuid(), no: b.no, name: b.name || '', model: b.model || '',
    template_id: b.template_id || null, location: b.location || '' };
  list.push(d); ctx.kvset('devices', list);
  return json(d);
}
async function handleBatchCreateDevices(ctx) {
  const b = ctx.body;
  const count = parseInt(b.count, 10);
  if (!count || count < 1) return json({ error: '数量无效' }, 400);
  const tpls = ctx.kvget('templates', []);
  const t = b.template_id ? tpls.find(x => x.id === b.template_id) : null;
  const list = ctx.kvget('devices', []);
  let added = 0;
  for (let i = 0; i < count; i++) {
    const no = String(i + 1).padStart(3, '0');
    if (list.some(d => d.no === no)) continue;
    list.push({ id: uuid(), no, name: t ? t.equip_name : ('设备 ' + no), model: t ? (t.model || '') : '',
      template_id: t ? t.id : null, location: '' });
    added++;
  }
  ctx.kvset('devices', list);
  return json({ count: added });
}
async function handleImportDevices(ctx) {
  const b = ctx.body;
  const text = b.text || '';
  const list = ctx.kvget('devices', []);
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
  ctx.kvset('devices', list);
  return json({ added, skipped });
}
async function handleBatchDeleteDevices(ctx) {
  const ids = (ctx.body.ids || []);
  let devices = ctx.kvget('devices', []);
  const before = devices.length;
  devices = devices.filter(d => !ids.includes(d.id));
  const deleted = before - devices.length;
  ctx.kvset('devices', devices);
  ctx.kvset('inspections', ctx.kvget('inspections', []).filter(r => !ids.includes(r.device_id)));
  return json({ deleted, requested: ids.length });
}
async function handleUpdateDevice(ctx) {
  const b = ctx.body;
  const list = ctx.kvget('devices', []);
  const d = list.find(x => x.id === ctx.params.id);
  if (!d) return json({ error: '设备不存在' }, 404);
  d.no = b.no || d.no; d.name = b.name || ''; d.model = b.model || '';
  d.template_id = b.template_id || null; d.location = b.location || '';
  ctx.kvset('devices', list);
  return json(d);
}
async function handleDeleteDevice(ctx) {
  ctx.kvset('devices', ctx.kvget('devices', []).filter(x => x.id !== ctx.params.id));
  ctx.kvset('inspections', ctx.kvget('inspections', []).filter(r => r.device_id !== ctx.params.id));
  return json({ ok: true });
}

// ---------- 点检记录（查询/删除） ----------
async function handleListInspections(ctx) {
  const devId = ctx.query.get('device_id');
  const date = ctx.query.get('date');
  const devices = ctx.kvget('devices', []);
  const dmap = {}; devices.forEach(d => dmap[d.id] = d);
  let list = ctx.kvget('inspections', []);
  if (devId) list = list.filter(r => { const d = dmap[r.device_id]; return d && (String(d.no) === devId || String(d.id) === devId); });
  if (date) list = list.filter(r => r.inspect_date === date);
  list.sort((a, b) => (a.inspect_date < b.inspect_date ? 1 : -1));
  return json(list.map(r => {
    const d = dmap[r.device_id] || {};
    return { id: r.device_id + '_' + r.inspect_date, inspect_date: r.inspect_date, no: d.no || '', name: d.name || '',
      status: r.status, signed_by: r.signed_by || '', abnormal_note: r.abnormal_note || '' };
  }));
}
async function handleDeleteInspection(ctx) {
  const key = decodeURIComponent(ctx.params.id);
  const [did, ...rest] = key.split('_');
  const date = rest.join('_');
  const list = ctx.kvget('inspections', []);
  const before = list.length;
  const remaining = list.filter(r => !(String(r.device_id) === did && r.inspect_date === date));
  ctx.kvset('inspections', remaining);
  return json({ ok: before !== remaining.length });
}
async function handleBatchDeleteInspections(ctx) {
  const ids = Array.isArray(ctx.body.ids) ? ctx.body.ids.map(String) : [];
  if (!ids.length) return json({ error: '未选择要删除的记录' }, 400);
  const dropPairs = new Set(ids.map(k => {
    const i = k.indexOf('_');
    return i > 0 ? k.slice(0, i) + '|' + k.slice(i + 1) : '';
  }).filter(Boolean));
  const list = ctx.kvget('inspections', []);
  const before = list.length;
  const remaining = list.filter(r => !dropPairs.has(String(r.device_id) + '|' + r.inspect_date));
  ctx.kvset('inspections', remaining);
  return json({ ok: true, deleted: before - remaining.length });
}

// ---------- 点检操作 ----------
async function handleInspectBatch(ctx) {
  const b = ctx.body;
  if (isFutureDate(b.date)) return json({ error: '不能点检未来日期' }, 400);
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  const abnormalMap = {};
  (b.devices || []).forEach(x => { abnormalMap[x.device_id] = x.note || ''; });
  const devices = ctx.kvget('devices', []);
  for (const d of devices) {
    const items = await deviceItems(ctx.store, d);
    const isAbn = d.id in abnormalMap;
    await upsertInspection(ctx, { device_id: d.id, inspect_date: b.date },
      { status: isAbn ? 'ng' : 'ok', signed_by: signer.name, signer_id: signer.id,
        abnormal_note: isAbn ? abnormalMap[d.id] : '',
        bySn: buildBySn(items, isAbn ? 'ng' : 'ok'), signed_at: randMorningTime(b.date) });
  }
  return json({ signed: devices.length, signer: signer.name });
}
async function handleDaySign(ctx) {
  const b = ctx.body;
  if (!b.device_id || !b.date || !b.signer_id) return json({ error: '缺少参数' }, 400);
  if (isFutureDate(b.date)) return json({ error: '不能签到未来日期' }, 400);
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  const dev = ctx.kvget('devices', []).find(d => d.id === b.device_id);
  if (!dev) return json({ error: '设备不存在' }, 400);
  const items = await deviceItems(ctx.store, dev);
  const existing = ctx.kvget('inspections', []).find(r => r.device_id === b.device_id && r.inspect_date === b.date);
  let bySn = {};
  if (existing && existing.bySn) {
    bySn = existing.bySn;
  } else {
    bySn = buildBySn(items, 'ok');
  }
  const r = await upsertInspection(ctx,
    { device_id: b.device_id, inspect_date: b.date },
    { status: statusFromBySn(bySn), signed_by: signer.name, signer_id: signer.id,
      abnormal_note: (existing && existing.abnormal_note) || '',
      bySn, signed_at: new Date().toISOString() });
  return json({ ok: true, created: r === 'created' });
}
async function handleInspectMonth(ctx) {
  const b = ctx.body;
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  let created = 0, updated = 0;
  const days = b.days || {};
  for (const dd in days) {
    if (isFutureDate(dd)) continue;
    const cell = days[dd];
    const bySn = cell.bySn || {};
    const r = await upsertInspection(ctx, { device_id: b.device_id, inspect_date: dd },
      { status: statusFromBySn(bySn), signed_by: signer.name, signer_id: signer.id,
        abnormal_note: cell.abnormal_note || '',
        bySn, signed_at: new Date().toISOString() });
    if (r === 'created') created++; else updated++;
  }
  // 异常明细整体替换（按 设备+月份）
  const abnList = Array.isArray(b.abnormal) ? b.abnormal : [];
  const ABN_FIELDS = ['sn', 'freq', 'date', 'content', 'abnormal', 'handle', 'handler', 'handle_date'];
  let recs = ctx.kvget('abnormalRecords', []).filter(r => !(r.device_id === b.device_id && r.month === b.month));
  abnList.forEach(a => {
    const item = { id: a.id || uuid(), device_id: b.device_id, month: b.month };
    ABN_FIELDS.forEach(k => { if (a[k] !== undefined) item[k] = a[k]; });
    recs.push(item);
  });
  ctx.kvset('abnormalRecords', recs);
  return json({ created, updated, abnormal: abnList.length });
}

// ---------- 整月一键操作（管理员） ----------
async function handleAdminInspectMonth(ctx) {
  const b = ctx.body;
  const month = b.month;
  if (!month || !b.signer_id) return json({ error: '缺少月份或签名人' }, 400);
  if (month > currentMonthStr()) return json({ error: '不能点检未来月份的点检' }, 400);
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  const { endDay, error: endErr } = resolveEndDay(month, b.end_day);
  if (endErr) return json({ error: endErr }, 400);
  let devices = ctx.kvget('devices', []);
  if (b.device_id) devices = devices.filter(d => d.id === b.device_id);
  else if (b.room) devices = devices.filter(d => (d.location || '') === b.room);
  if (!devices.length) {
    return json({ error: b.device_id ? '找不到该设备' : (b.room ? ('房间「' + b.room + '」下没有设备') : '没有可点检的设备') }, 400);
  }
  // 按科室随机分派（可选）：设备所在房间 → 房间归属科室 → 该科室「启用且有签名图」的签名人池，
  // 每天每房间随机选一人签名；房间未设科室 / 科室下无可用签名人时，回退为授权人（fallback 计数返回前端提示）。
  const randomDept = !!b.random_dept;
  const days = monthDays(month, endDay);
  const roomAssign = {};
  if (randomDept) {
    const roomDept = {};
    ctx.kvget('rooms', []).forEach(r => { roomDept[r.name] = r.dept || ''; });
    const signers = ctx.kvget('signers', []);
    for (const room of [...new Set(devices.map(d => String(d.location || '').trim()))]) {
      const dept = roomDept[room] || '';
      const pool = dept ? signers.filter(s => s.active !== false && s.dept === dept && pickSigImage(s)) : [];
      const byDay = {};
      if (pool.length) for (const dd of days) byDay[dd] = pool[Math.floor(Math.random() * pool.length)];
      roomAssign[room] = { dept, pool, byDay };
    }
  }
  let created = 0, updated = 0, fallback = 0;
  for (const d of devices) {
    const items = await deviceItems(ctx.store, d);
    const bySn = buildBySn(items, 'ok');
    const ra = randomDept ? roomAssign[String(d.location || '').trim()] : null;
    for (const dd of days) {
      const who = (ra && ra.byDay[dd]) || signer;
      if (!(ra && ra.byDay[dd])) fallback++;
      const r = await upsertInspection(ctx, { device_id: d.id, inspect_date: dd },
        { status: 'ok', signed_by: who.name, signer_id: who.id, abnormal_note: '', bySn, signed_at: randMorningTime(dd) });
      if (r === 'created') created++; else updated++;
    }
  }
  const assignments = randomDept ? Object.entries(roomAssign).map(([room, v]) => ({
    room, dept: v.dept, people: [...new Set(v.pool.map(s => s.name))], covered: Object.keys(v.byDay).length })) : null;
  return json({ devices: devices.length, days: endDay, signer: signer.name, created, updated, room: b.room || '',
    random: randomDept, fallback, assignments });
}
async function handleAdminCancelInspectMonth(ctx) {
  const b = ctx.body;
  const month = b.month;
  if (!month) return json({ error: '缺少月份' }, 400);
  if (month > currentMonthStr()) return json({ error: '不能取消未来月份的点检' }, 400);
  const { endDay, error: endErr } = resolveEndDay(month, b.end_day);
  if (endErr) return json({ error: endErr }, 400);
  const datesToDelete = new Set(monthDays(month, endDay));
  const insp = ctx.kvget('inspections', []);
  const before = insp.length;
  const remaining = insp.filter(r => {
    if (!datesToDelete.has(r.inspect_date)) return true;
    if (b.device_id && r.device_id !== b.device_id) return true;
    return false;
  });
  ctx.kvset('inspections', remaining);
  const deleted = before - remaining.length;
  const devCount = b.device_id ? 1 : ctx.kvget('devices', []).length;
  return json({ deleted, devices: devCount, days: endDay, month });
}

// ---------- 报表 / 视图 ----------
async function handleMonthly(ctx) {
  const month = ctx.query.get('month');
  if (!month) return json({ error: '缺少 month' }, 400);
  const [yy, mm] = month.split('-');
  const dim = new Date(+yy, +mm, 0).getDate();
  const devices = ctx.kvget('devices', []);
  const insp = ctx.kvget('inspections', []);
  const out = [];
  for (const d of devices) {
    const items = await deviceItems(ctx.store, d);
    const days = {}; const signerSet = new Set();
    for (let day = 1; day <= dim; day++) {
      const dd = `${yy}-${mm}-${String(day).padStart(2, '0')}`;
      const rec = insp.find(r => r.device_id === d.id && r.inspect_date === dd);
      if (rec) {
        days[dd] = { bySn: rec.bySn || {}, signature_image: signerSignature(ctx.store, rec),
          signer_id: rec.signer_id || null,
          abnormal_note: rec.abnormal_note || '' };
        if (rec.signed_by) signerSet.add(rec.signed_by);
      }
    }
    const abn = ctx.kvget('abnormalRecords', []).filter(r => r.device_id === d.id && r.month === month);
    const tpl = d.template_id ? ctx.kvget('templates', []).find(x => x.id === d.template_id) : null;
    out.push({ id: d.id, no: d.no, name: d.name, model: d.model, location: d.location || '', items, days,
      signers: [...signerSet], abnormal: abn, note: tpl ? (tpl.note || '') : '',
      // 表头字段（后台「点检模板」里可编辑）：表单编号 / 版本 / 标题，缺省由前端回退通用值
      form_code: tpl ? (tpl.form_code || '') : '', form_rev: tpl ? (tpl.form_rev || '') : '',
      // 页眉最终值（v1.37.0）：配置(formHeads.device) > 模板自带 > 内置默认，服务端一次算好下发
      form_head: resolveFormHead(ctx, 'device', tpl).line,
      title: tpl ? (tpl.title || '') : '', title_en: tpl ? (tpl.title_en || '') : '',
      tpl_key: tpl ? (tpl.key || '') : '', tpl_name: tpl ? (tpl.equip_name || '') : '' });
  }
  // 签名人的两版图（横 / 竖）随响应去重下发：月检表签名格是高窄格 → 前端自动取竖版
  const sigAssets = {};
  ctx.kvget('signers', []).forEach(s => {
    if (!s.signature_image && !s.signature_image_v) return;
    sigAssets[s.id] = { h: s.signature_image || null, v: s.signature_image_v || null };
  });
  return json({ month, devices: out, sig_assets: sigAssets,
    // 批量打印页眉（kind=checkall）：批量打印整册的右上角编号，独立于单台设备的模板编号
    form_head_checkall: resolveFormHead(ctx, 'checkall', null).line });
}
async function handleDashboard(ctx) {
  const date = ctx.query.get('date');
  const loc = ctx.query.get('location') || '';
  const devices = ctx.kvget('devices', []).filter(d => !loc || d.location === loc);
  const dmap = {}; devices.forEach(d => dmap[d.id] = d);
  const insp = ctx.kvget('inspections', []);
  const month = date ? date.slice(0, 7) : '';
  const todayMap = {};
  let todayAbnormal = 0, monthCount = 0;
  for (const r of insp) {
    if (!dmap[r.device_id]) continue;
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
      signature_image: r ? signerSignature(ctx.store, r) : null,
      signed_at: r ? (r.signed_at || '') : '' };
  });
  const recent = insp.filter(r => date && r.inspect_date === date && dmap[r.device_id])
    .sort((a, b) => (a.signed_at < b.signed_at ? 1 : -1)).slice(0, 12)
    .map(r => { const d = dmap[r.device_id] || {};
      return { no: d.no || '', name: d.name || '', status: r.status, signer_name: r.signed_by || '',
        signature_image: signerSignature(ctx.store, r), abnormal_note: r.abnormal_note || '', signed_at: r.signed_at }; });
  return json({ total: devices.length, today_inspected: Object.keys(todayMap).length,
    today_abnormal: todayAbnormal, month_inspected: monthCount, grid, recent });
}
async function handleDeviceDetail(ctx) {
  const id = ctx.params.id;
  const date = ctx.query.get('date');
  const d = ctx.kvget('devices', []).find(x => x.id === id);
  if (!d) return json({ items: [] });
  const items = await deviceItems(ctx.store, d);
  const rec = ctx.kvget('inspections', []).find(r => r.device_id === id && r.inspect_date === date);
  const out = items.map(it => ({ sn: it.sn, content: it.content, frequency: it.frequency || '',
    status: rec ? (rec.bySn && rec.bySn[it.sn] ? rec.bySn[it.sn] : 'ok') : 'none',
    note: rec ? (rec.abnormal_note || '') : '' }));
  return json({ items: out });
}

// ===================== 系统版本 =====================
async function handleVersion(ctx) {
  return json({ version: APP_VERSION, date: APP_VERSION_DATE, readonly: true, demo: true });
}

// ===================== 房间管理 =====================
async function handleListRooms(ctx) {
  const rooms = ctx.kvget('rooms', []);
  const c = roomCounts(ctx.store);
  return json(rooms.map(r => ({ name: r.name, desc: r.desc || '', count: c[r.name] || 0,
    group: r.group || '', dept: r.dept || '',
    thermo_apparatus: r.thermo_apparatus || '', thermo_equipment: r.thermo_equipment || '',
    thermo_requirement: r.thermo_requirement || '',
    form_head: r.form_head || ''   // 温湿度表页眉的房间级覆盖（v1.37.0，空 = 用表种默认值）
  })));
}
async function handleCreateRoom(ctx) {
  const b = ctx.body;
  const name = String(b.name || '').trim();
  if (!name) return json({ error: '房间名称必填' }, 400);
  if (name.length > 40) return json({ error: '房间名称不能超过 40 字' }, 400);
  const rooms = ctx.kvget('rooms', []);
  if (rooms.some(r => r.name === name)) return json({ error: '房间「' + name + '」已存在' }, 400);
  rooms.push({ name, desc: String(b.desc || '').trim(), group: String(b.group || '').trim(), dept: String(b.dept || '').trim() });
  ctx.kvset('rooms', rooms);
  return json({ ok: true });
}
async function handleUpdateRoom(ctx) {
  const oldName = decodeURIComponent(ctx.params.id);
  const b = ctx.body;
  const rooms = ctx.kvget('rooms', []);
  const r = rooms.find(x => x.name === oldName);
  if (!r) return json({ error: '房间不存在' }, 404);
  const newName = String(b.name != null ? b.name : r.name).trim();
  if (!newName) return json({ error: '房间名称必填' }, 400);
  if (newName.length > 40) return json({ error: '房间名称不能超过 40 字' }, 400);
  if (newName !== oldName && rooms.some(x => x.name === newName)) return json({ error: '房间「' + newName + '」已存在' }, 400);
  if (b.desc != null) r.desc = String(b.desc).trim();
  if (b.group != null) r.group = String(b.group).trim();
  if (b.dept != null) r.dept = String(b.dept).trim();
  if (b.thermo_apparatus != null) r.thermo_apparatus = String(b.thermo_apparatus);
  if (b.thermo_equipment != null) r.thermo_equipment = String(b.thermo_equipment);
  if (b.thermo_requirement != null) r.thermo_requirement = String(b.thermo_requirement);
  r.name = newName;
  if (newName !== oldName) {
    const devs = ctx.kvget('devices', []);
    let moved = 0;
    devs.forEach(d => { if ((d.location || '').trim() === oldName) { d.location = newName; moved++; } });
    ctx.kvset('devices', devs);
  }
  ctx.kvset('rooms', rooms);
  return json({ ok: true });
}
async function handleDeleteRoom(ctx) {
  const name = decodeURIComponent(ctx.params.id);
  const rooms = ctx.kvget('rooms', []);
  const i = rooms.findIndex(x => x.name === name);
  if (i < 0) return json({ error: '房间不存在' }, 404);
  const c = roomCounts(ctx.store);
  if ((c[name] || 0) > 0) return json({ error: '该房间仍有 ' + c[name] + ' 台设备，请先迁移或删除设备' }, 400);
  rooms.splice(i, 1);
  ctx.kvset('rooms', rooms);
  return json({ ok: true });
}

// ===================== 科室管理 =====================
async function handleListDepts(ctx) {
  return json({ depts: ctx.kvget('depts', []) });
}
async function handleCreateDept(ctx) {
  const name = String(ctx.body.name || '').trim();
  if (!name) return json({ error: '科室名称必填' }, 400);
  if (name.length > 20) return json({ error: '科室名称不能超过 20 字' }, 400);
  const depts = ctx.kvget('depts', []);
  if (depts.includes(name)) return json({ error: '科室「' + name + '」已存在' });
  depts.push(name);
  ctx.kvset('depts', depts);
  return json({ ok: true });
}
async function handleDeleteDept(ctx) {
  const name = decodeURIComponent(ctx.params.name);
  const depts = ctx.kvget('depts', []);
  if (!depts.includes(name)) return json({ error: '科室不存在' }, 404);
  const roomCnt = ctx.kvget('rooms', []).filter(r => (r.dept || '') === name).length;
  const userCnt = ctx.kvget('users', []).filter(u => (u.dept || '') === name).length;
  if (roomCnt || userCnt) return json({ error: '该科室仍被 ' + roomCnt + ' 个房间 / ' + userCnt + ' 个用户引用，请先改派后再删除' });
  ctx.kvset('depts', depts.filter(d => d !== name));
  return json({ ok: true });
}

// ===================== 模板高级编辑 =====================
async function handleUpdateTemplate(ctx) {
  const b = ctx.body || {};
  const tpls = ctx.kvget('templates', []);
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return json({ error: '模板不存在' }, 404);
  if (b.key !== undefined) {
    const nk = String(b.key).trim();
    if (!nk) return json({ error: '模板标识 key 不能为空' });
    if (tpls.some(x => x.id !== t.id && String(x.key).trim() === nk)) return json({ error: `模板标识「${nk}」已被其它模板占用` }, 409);
    t.key = nk;
  }
  if (b.equip_name !== undefined) {
    const en = String(b.equip_name).trim();
    if (!en) return json({ error: '设备名称不能为空' });
    t.equip_name = en;
  }
  ['model', 'note', 'form_code', 'form_rev', 'title', 'title_en', 'source_file'].forEach(f => {
    if (b[f] !== undefined) t[f] = String(b[f]).trim();
  });
  ctx.kvset('templates', tpls);
  return json({ ok: true, template: t });
}
async function handleSaveTemplateItems(ctx) {
  const b = ctx.body || {};
  const raw = Array.isArray(b.items) ? b.items : [];
  const tpls = ctx.kvget('templates', []);
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return json({ error: '模板不存在' }, 404);
  const items = []; const map = {};
  for (const it of raw) {
    const content = ((it && it.content) || '').toString().trim();
    if (!content) continue;
    const frequency = ((it && it.frequency) || '').toString().trim();
    const newSn = items.length + 1;
    const rawSn = it && it.sn;
    const oldSn = (rawSn === undefined || rawSn === null || rawSn === '') ? null : Number(rawSn);
    if (oldSn !== null && !Number.isNaN(oldSn)) map[oldSn] = newSn;
    items.push({ sn: newSn, content, frequency });
  }
  if (!items.length) return json({ error: '至少保留一条检查项' });
  const devIds = new Set(ctx.kvget('devices', []).filter(d => d.template_id === t.id).map(d => d.id));
  t.items = items;
  ctx.kvset('templates', tpls);
  let migrated = 0, dropped = 0;
  if (devIds.size) {
    const insp = ctx.kvget('inspections', []);
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
    if (migrated) ctx.kvset('inspections', insp);
  }
  return json({ ok: true, count: items.length, migrated, dropped, devices: devIds.size });
}
async function handleDuplicateTemplate(ctx) {
  const b = ctx.body || {};
  const tpls = ctx.kvget('templates', []);
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return json({ error: '模板不存在' }, 404);
  let key = (b.key ? String(b.key) : (String(t.key) + '-副本')).trim();
  if (tpls.some(x => String(x.key).trim() === key)) key = key + '-' + Date.now().toString().slice(-4);
  const nt = JSON.parse(JSON.stringify(t));
  nt.id = uuid();
  nt.key = key;
  if (b.equip_name !== undefined && String(b.equip_name).trim()) nt.equip_name = String(b.equip_name).trim();
  delete nt.use_count;
  tpls.push(nt); ctx.kvset('templates', tpls);
  return json({ ok: true, template: nt });
}
async function handleDeleteTemplate(ctx) {
  const tpls = ctx.kvget('templates', []);
  const t = tpls.find(x => x.id === ctx.params.id);
  if (!t) return json({ error: '模板不存在' }, 404);
  const used = ctx.kvget('devices', []).filter(d => d.template_id === t.id).length;
  if (used) return json({ error: `该模板仍被 ${used} 台设备使用，请先给这些设备换模板` }, 409);
  ctx.kvset('templates', tpls.filter(x => x.id !== t.id));
  return json({ ok: true });
}
async function handleImportTemplate(ctx) {
  const b = ctx.body;
  if (!b.key || !b.equip_name) return json({ error: '模板标识与设备名称必填' });
  const items = Array.isArray(b.items) ? b.items : [];
  const parsed = [];
  for (const it of items) {
    const content = ((it && it.content) || '').toString().trim();
    if (!content) continue;
    parsed.push({ content, frequency: ((it && it.frequency) || '').toString().trim() });
  }
  if (parsed.length === 0) return json({ error: '未解析到任何检查项，请检查上传内容' });
  const tpls = ctx.kvget('templates', []);
  const exist = tpls.find(x => x.key === b.key);
  if (exist && !b.overwrite) return json({ error: `模板标识「${b.key}」已存在，如需覆盖其检查项请勾选"覆盖"` }, 409);
  const buildItems = () => parsed.map((p, i) => ({ sn: i + 1, content: p.content, frequency: p.frequency }));
  if (exist) {
    exist.equip_name = b.equip_name; exist.model = b.model || ''; exist.source_file = b.source_file || ''; exist.items = buildItems();
    ctx.kvset('templates', tpls);
    return json({ ok: true, updated: true, id: exist.id, key: exist.key, itemsCount: parsed.length });
  }
  const t = { id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '', source_file: b.source_file || '', items: buildItems() };
  tpls.push(t); ctx.kvset('templates', tpls);
  return json({ ok: true, updated: false, id: t.id, key: t.key, itemsCount: parsed.length });
}

// ===================== 温湿度点检记录（按房间 + 年月） =====================
const ENV_PERIODS = ['AM', 'PM', 'Night'];
const ENV_PERIOD_CN = { AM: '上午', PM: '下午', Night: '晚上' };
function allEnvRecords(ctx) { return ctx.kvget('envRecords', []); }
async function handleGetEnvRecord(ctx) {
  const room = ctx.query.get('room') || '';
  const ym = ctx.query.get('ym') || '';
  if (!room || !/^\d{4}-\d{2}$/.test(ym)) return json({ error: '缺少房间或月份' }, 400);
  const rec = allEnvRecords(ctx).find(r => r.room === room && r.ym === ym);
  if (!rec) return json({ room, ym, cells: {}, updated_at: null });
  return json(rec);
}
async function handleSignEnvCell(ctx) {
  const b = ctx.body;
  if (!b.signer_id) return json({ error: '请选择签名人' });
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  return json({ ok: true, signer_id: signer.id, name: signer.name, signature_image: pickSigImage(signer), signature_image_v: signer.signature_image_v || null });
}
async function handleSaveEnvRecord(ctx) {
  const b = ctx.body;
  const room = String(b.room || '').trim();
  const ym = String(b.ym || '').trim();
  if (!room) return json({ error: '房间必填' });
  if (!/^\d{4}-\d{2}$/.test(ym)) return json({ error: '月份格式应为 YYYY-MM' });
  const cells = (b.cells && typeof b.cells === 'object') ? b.cells : {};
  const clean = {};
  for (const k of Object.keys(cells)) {
    const m = /^(\d{1,2})_(AM|PM|Night)$/.exec(k);
    if (!m) continue;
    const day = parseInt(m[1], 10);
    if (day < 1 || day > 31) continue;
    const c = cells[k] || {};
    const sigRaw = (typeof c.signature_image === 'string') ? c.signature_image : '';
    if (sigRaw.length > SIG_IMG_MAX) {
      return json({ error: day + ' 日的签名图过大（约 ' + Math.round(sigRaw.length / 1024) +
        'KB，上限 ' + Math.round(SIG_IMG_MAX / 1024) + 'KB）。请重新上传更小的签名图' }, 413);
    }
    clean[k] = {
      temp: String(c.temp != null ? c.temp : '').slice(0, 8),
      humidity: String(c.humidity != null ? c.humidity : '').slice(0, 8),
      recorder: String(c.recorder || '').slice(0, 64),
      signature_image: sigRaw,
      strike: c.strike ? 1 : 0
    };
  }
  const list = allEnvRecords(ctx);
  let rec = list.find(r => r.room === room && r.ym === ym);
  if (rec) { rec.cells = clean; rec.updated_at = new Date().toISOString(); }
  else { rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room, ym, cells: clean, updated_at: new Date().toISOString() }; list.push(rec); }
  ctx.kvset('envRecords', list);
  return json({ ok: true, id: rec.id, updated_at: rec.updated_at });
}

// 限值解析必须与 public/env.html 的 parseLimits 保持一致（改一边就要同步另一边），
// 否则会出现「后台填进去的值，在温湿度页反而被标红」这种自相矛盾的结果。
// 房间「温湿度要求」的自由文本 → 数值范围（写法与工厂 v1.32.1 一致）：
//   温度：10℃-35℃ ／ 温度：15℃~25℃ (ASTM E23-25) ／ 温度要求：—（表示没有温度要求）
//   湿度：≤80%RH ／ 湿度：40~70%（区间写法，上下限都认）
// 多条温度标准按 mode 合成：union（默认，宽）取「下限最小/上限最大」；intersect（严）取「下限最大/上限最小」。
const ENV_TEMP_LINE_RE = /温度(?:要求)?\s*[：:]\s*(-?\d+(?:\.\d+)?)\s*(?:℃|°C|C)?\s*[-~—–～至]\s*(-?\d+(?:\.\d+)?)/g;
// 湿度支持两种写法：① 上限「湿度：≤70%RH」只取上限；② 区间「湿度：40~70%RH」同时取上下限
const ENV_HUM_RANGE_RE = /湿度(?:要求)?\s*[：:]\s*(-?\d+(?:\.\d+)?)\s*(?:%|％|%RH|RH)?\s*(?:[-~—–～至])\s*(-?\d+(?:\.\d+)?)/;
const ENV_HUM_UP_RE = /湿度(?:要求)?\s*[：:]\s*(?:≤|<=|<|不超过)\s*(\d+(?:\.\d+)?)/;
function parseEnvLimits(txt, mode) {
  const s = String(txt || '');
  const ranges = [];
  for (const m of s.matchAll(ENV_TEMP_LINE_RE)) {
    const a = parseFloat(m[1]), b = parseFloat(m[2]);
    if (Number.isFinite(a) && Number.isFinite(b) && b > a) ranges.push([a, b]);
  }
  let hMin = null, hMax = null;
  const hr = s.match(ENV_HUM_RANGE_RE);
  if (hr) { hMin = parseFloat(hr[1]); hMax = parseFloat(hr[2]); }
  else { const hu = s.match(ENV_HUM_UP_RE); if (hu) hMax = parseFloat(hu[1]); }
  if (!ranges.length && hMax == null) return null;
  let tMin = null, tMax = null;
  if (ranges.length) {
    const los = ranges.map(r => r[0]), his = ranges.map(r => r[1]);
    if (mode === 'intersect') {
      const lo = Math.max.apply(null, los), hi = Math.min.apply(null, his);
      if (hi > lo) { tMin = lo; tMax = hi; }
    }
    if (tMin == null) { tMin = Math.min.apply(null, los); tMax = Math.max.apply(null, his); }
  }
  return { tMin, tMax, hMin, hMax, stdCount: ranges.length };
}
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
  if (lim.hMax == null) return { error: '未配置湿度上限（应形如「湿度：≤80%RH」或「湿度：40~70%RH」）' };
  if (!(lim.hMax > 0)) return { error: '湿度上限写法有误' };
  const temp = safeBand(lim.tMin, lim.tMax, 0.5, 0.10);
  let hum;
  if (lim.hMin != null) {
    // 显式区间（如 40~70%）：两端留安全余量，与温度同理
    if (!(lim.hMax > lim.hMin)) return { error: '湿度区间写法有误（下限不小于上限）' };
    if (lim.hMin <= 0 || lim.hMax > 100) return { error: '湿度区间应在 0~100%RH 之间' };
    hum = safeBand(lim.hMin, lim.hMax, 2, 0.10);
  } else {
    // 只有上限（如 ≤70%）：下限取上限的一半（且不低于 30%RH），上限再退让 3~6 个点
    const hl = Math.max(30, lim.hMax * 0.5);
    const hh = lim.hMax - Math.max(3, lim.hMax * 0.06);
    hum = hh > hl ? [hl, hh]
              : [Math.max(1, lim.hMax * 0.4), Math.max(2, lim.hMax - Math.max(1, lim.hMax * 0.05))];
  }
  return { temp, hum };
}
// ===================== 温湿度预警（配置 / 阈值 / 判定） =====================
// 预警配置：defaults{tMin,tMax,hMin,hMax}（全局默认阈值，null=不判定）/ rooms{房间名:{...}}（按房间覆盖）/
//   recipients{byDept:{科室名:[用户id…]}, all:[用户id…]}
const ENV_ALERT_DEFAULTS = {
  enabled: true,
  cooldownHours: 12,
  // 阈值默认「跟着房间的温湿度要求走」，后台不必再逐个房间手配
  useRoomReq: true,
  // 一个房间列了多条温度标准时怎么合：union=并集（宽）/ intersect=交集（严）
  multiStd: 'union',
  channels: { inApp: true, banner: true },
  defaults: { tMin: 15, tMax: 30, hMin: null, hMax: 70 },
  rooms: {},
  recipients: { byDept: {}, all: [] }
};
const ENV_ALERT_KINDS = { temp_high: '温度超上限', temp_low: '温度低于下限', hum_high: '湿度超上限', hum_low: '湿度低于下限' };
const ENV_PERIOD_CN2 = { AM: '上午', PM: '下午', Night: '晚上' };
function envAlertCfgRaw(ctx) { return ctx.kvget('envAlertCfg', null) || {}; }
// 「房间有没有写要求」——空文本，或只写了 — / - / ～ 这类占位符，都算没写
function envReqText(ctx, roomName) {
  const roomObj = ctx.kvget('rooms', []).find(r => r.name === roomName) || {};
  const txt = String(roomObj.thermo_requirement || '').trim();
  const empty = !txt || /^[-—–~～/、,，\s]+$/.test(txt);
  return { roomObj, txt, empty };
}
// 房间生效阈值：
//   ① 后台「按房间覆盖」里手填的数字（最高优先，只覆盖填了的那一项）
//   ② 房间自己的「温湿度要求」自动解析（默认走这条）
//   ③ 全局默认阈值（仅当该房间压根没写要求时兜底）
// 房间要求里没写的指标 = 不判定（null），不拿全局默认去凑，否则会给没有依据的指标报预警。
function envAlertLimits(ctx, room) {
  const cfg = envAlertCfgRaw(ctx);
  const d = cfg.defaults || ENV_ALERT_DEFAULTS.defaults;
  const num = v => (v == null || v === '' || isNaN(Number(v))) ? null : Number(v);
  const o = (cfg.rooms && cfg.rooms[room]) || {};
  const { txt, empty } = envReqText(ctx, room);
  const req = (cfg.useRoomReq !== false && !empty) ? parseEnvLimits(txt, cfg.multiStd) : null;
  const base = req
    ? { tMin: req.tMin, tMax: req.tMax, hMin: req.hMin, hMax: req.hMax, src: 'room' }
    : { tMin: num(d.tMin), tMax: num(d.tMax), hMin: num(d.hMin), hMax: num(d.hMax), src: empty ? 'default' : 'off' };
  const has = f => o[f] != null && o[f] !== '' && !isNaN(Number(o[f]));
  const pick = f => has(f) ? Number(o[f]) : base[f];
  return {
    tMin: pick('tMin'), tMax: pick('tMax'), hMin: pick('hMin'), hMax: pick('hMax'),
    src: ['tMin', 'tMax', 'hMin', 'hMax'].some(has) ? 'override' : base.src,
    reqText: txt
  };
}
function mkEnvAlert(room, ym, day, period, type, value, unit, boundType, limit, exceed) {
  const r1 = n => Math.round(n * 10) / 10;
  return {
    room, ym, period, type, unit, boundType,
    date: ym + '-' + String(day).padStart(2, '0'),
    value: r1(value), limit: r1(limit), exceed: r1(exceed),
    level: '注意'
  };
}
function envBandsFromRange(rng) {
  if (!rng) return null;
  const tMin = Number(rng.tMin), tMax = Number(rng.tMax), hMin = Number(rng.hMin), hMax = Number(rng.hMax);
  if (![tMin, tMax, hMin, hMax].every(Number.isFinite)) return null;
  if (!(tMax > tMin) || !(hMax > hMin) || hMin <= 0 || hMax > 100) return null;
  return { temp: [tMin, tMax], hum: [hMin, hMax], custom: true };
}
function envCustomRange(ctx) {
  const r = (ctx.kvget('envfill', {}) || {}).range;
  return envBandsFromRange(r) ? r : null;
}
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
function envCellHasData(c) {
  if (!c) return false;
  return !!(String(c.temp || '').trim() || String(c.humidity || '').trim() || c.recorder || c.signature_image || c.strike);
}
const fmtBand = b => b[0].toFixed(1) + '~' + b[1].toFixed(1);

async function handleExportEnvCsv(ctx) {
  const room = ctx.query.get('room') || '';
  const ym = ctx.query.get('ym') || '';
  if (!room || !/^\d{4}-\d{2}$/.test(ym)) return json({ error: '缺少房间或月份' }, 400);
  const rec = allEnvRecords(ctx).find(r => r.room === room && r.ym === ym) || { cells: {} };
  const escCsv = v => { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
  const dim = new Date(+ym.slice(0, 4), +ym.slice(5, 7), 0).getDate();
  const header = ['日期', '时段', '温度(℃)', '湿度(%RH)', '记录员', '备注'];
  const rows = [];
  for (let d = 1; d <= dim; d++) {
    for (const p of ENV_PERIODS) {
      const c = rec.cells[d + '_' + p] || {};
      rows.push([ym + '-' + String(d).padStart(2, '0'), ENV_PERIOD_CN[p], c.temp || '', c.humidity || '', c.recorder || '', c.strike ? '／ 该日无需记录' : '']);
    }
  }
  const lines = [header.map(escCsv).join(',')].concat(rows.map(r => r.map(escCsv).join(',')));
  const csv = '\uFEFF' + lines.join('\r\n');
  return new Response(csv, { status: 200, headers: { 'Content-Type': 'text/csv; charset=utf-8', 'Content-Length': new TextEncoder().encode(csv).length, 'Content-Disposition': 'attachment; filename="env_' + encodeURIComponent(room) + '_' + ym + '.csv"' } });
}
async function handleEnvFill(ctx) {
  const b = ctx.body || {};
  const ym = String(b.ym || '').trim();
  if (!/^\d{4}-\d{2}$/.test(ym)) return json({ error: '月份格式应为 YYYY-MM' });
  const cur = currentMonthStr();
  if (ym > cur) return json({ error: '不能填充未来月份（' + ym + '）' });
  const [yy, mm] = ym.split('-').map(Number);
  const dim = new Date(yy, mm, 0).getDate();
  const maxDay = (ym === cur) ? Number(todayStr().slice(8, 10)) : dim;
  let endDay = (b.end_day == null || b.end_day === '') ? maxDay : parseInt(b.end_day, 10);
  if (!Number.isFinite(endDay)) endDay = maxDay;
  endDay = Math.min(Math.max(endDay, 1), maxDay);
  const { signer, error } = await verifySigner(ctx.store, b);
  if (error) return json({ error }, error === '签名密码错误' ? 401 : 400);
  const sigImg = pickSigImage(signer);
  const rooms = ctx.kvget('rooms', []);
  let targets = rooms;
  if (b.scope === 'room') {
    const name = String(b.room || '').trim();
    if (!name) return json({ error: '请选择房间' });
    const hit = rooms.filter(r => r.name === name);
    if (!hit.length) return json({ error: '房间不存在：' + name }, 404);
    targets = hit;
  }
  if (!targets.length) return json({ error: '没有可填充的房间' });
  const list = allEnvRecords(ctx);
  const detail = [], skipped = [];
  let cells = 0, days = 0, touched = 0;
  const custom = envCustomRange(ctx);
  for (const r of targets) {
    const bands = envBandsFromRange(custom) || envBands(parseEnvLimits(r.thermo_requirement));
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
        if (envCellHasData(rec && rec.cells[k])) continue;
        if (!rec) { rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room: r.name, ym, cells: {}, updated_at: null }; list.push(rec); }
        rec.cells[k] = { temp: temps[i], humidity: hums[i], recorder: signer.id, signature_image: sigImg || '', strike: 0 };
        nCells++; dayFilled = true;
      }
      if (dayFilled) nDays++;
    }
    if (nCells) { rec.updated_at = new Date().toISOString(); touched++; }
    detail.push({ room: r.name, cells: nCells, days: nDays, temp_band: fmtBand(bands.temp), hum_band: fmtBand(bands.hum) });
    cells += nCells; days += nDays;
  }
  if (cells) ctx.kvset('envRecords', list);
  return json({ ok: true, ym, end_day: endDay, cells, days, rooms: touched, range_source: custom ? 'custom' : 'room', signer: { id: signer.id, name: signer.name }, signer_has_sig: !!sigImg, detail, skipped });
}
async function handleEnvRangeGet(ctx) {
  const r = envCustomRange(ctx);
  return json({ ok: true, range: r, active: !!r });
}
async function handleEnvRangePut(ctx) {
  const b = ctx.body || {};
  const cur = ctx.kvget('envfill', {}) || {};
  if (b.range == null || (typeof b.range === 'object' && !Object.keys(b.range).length)) {
    ctx.kvset('envfill', Object.assign({}, cur, { range: null }));
    return json({ ok: true, range: null, active: false });
  }
  const r = b.range || {};
  const tMin = Number(r.tMin), tMax = Number(r.tMax), hMin = Number(r.hMin), hMax = Number(r.hMax);
  if (![tMin, tMax, hMin, hMax].every(Number.isFinite)) return json({ error: '四个数值（温度下限/上限、湿度下限/上限）都必须填写' });
  if (!(tMin > -50 && tMax < 100)) return json({ error: '温度范围超出合理区间（-50℃ ~ 100℃）' });
  if (!(tMax > tMin)) return json({ error: '温度上限必须大于下限' });
  if (!(hMin > 0 && hMax <= 100)) return json({ error: '湿度范围应为 0 ~ 100 %RH' });
  if (!(hMax > hMin)) return json({ error: '湿度上限必须大于下限' });
  const clean = { tMin, tMax, hMin, hMax };
  ctx.kvset('envfill', Object.assign({}, cur, { range: clean }));
  return json({ ok: true, range: clean, active: true });
}
async function handleEnvRecordsDelete(ctx) {
  const b = ctx.body || {};
  const items = Array.isArray(b.items) ? b.items : null;
  if (!items || !items.length) return json({ error: '请提供要删除的记录（items: [{room, ym}]）' });
  if (items.length > 200) return json({ error: '一次最多删除 200 条，请分批操作' });
  const want = new Map();
  for (const it of items) {
    const room = String(it && it.room || '').trim(), ym = String(it && it.ym || '').trim();
    if (!room || !/^\d{4}-\d{2}$/.test(ym)) return json({ error: '条目格式有误（需 {room, ym:"YYYY-MM"}）：' + JSON.stringify(it) });
    want.set(room + '@' + ym, { room, ym });
  }
  const list = allEnvRecords(ctx);
  const keep = [], deleted = [], missing = [];
  for (const rec of list) {
    const key = rec.room + '@' + rec.ym;
    if (want.has(key)) { deleted.push({ room: rec.room, ym: rec.ym, cells: Object.keys(rec.cells || {}).length }); want.delete(key); }
    else keep.push(rec);
  }
  for (const { room, ym } of want.values()) missing.push({ room, ym });
  if (deleted.length) ctx.kvset('envRecords', keep);
  return json({ ok: true, deleted, missing });
}

// ===================== LIMS 数据源（温湿度实时抓取） =====================
// 演示环境为占位配置：base 指向 <LIMS_BASE_URL>，无法连接真实 LIMS；仅在配置正确时方可启用同步。
const LIMS_DEFAULTS = {
  enabled: false,
  base: '<LIMS_BASE_URL>',
  user: '<LIMS_USER>',
  pass: '',
  interfaceId: '<LIMS_INTERFACE_ID>',
  interfaceIdTh: '<LIMS_INTERFACE_TH_ID>',
  tempWindowBudget: 90,
  recorder: 'LIMS自动导入',
  strategy: 'random',
  overwrite: false,
  roomAlias: {},
  limsRooms: [],
  auto: { enabled: false, times: ['08:35', '13:35', '19:05'], recorder: '' },
};
function limsConfig(ctx) {
  const saved = ctx.kvget('lims', null) || {};
  const cfg = Object.assign({}, LIMS_DEFAULTS, saved);
  cfg.auto = Object.assign({}, LIMS_DEFAULTS.auto, saved.auto || {});
  cfg.roomAlias = Object.assign({}, LIMS_DEFAULTS.roomAlias, saved.roomAlias || {});
  if (!Array.isArray(cfg.limsRooms) || !cfg.limsRooms.length) cfg.limsRooms = LIMS_DEFAULTS.limsRooms.slice();
  return cfg;
}
async function limsHttp(url, { method = 'GET', headers = {}, body = null, timeout = 30000 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { method, headers: Object.assign({}, headers), body: body == null ? null : JSON.stringify(body), signal: ctrl.signal });
    const text = await res.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    return { status: res.status, text, json };
  } finally { clearTimeout(t); }
}
let limsTokenCache = { token: '', base: '', user: '', at: 0 };
async function limsLogin(cfg) {
  const c = limsTokenCache;
  if (c.token && c.base === cfg.base && c.user === cfg.user && (Date.now() - c.at) < 3600000) return c.token;
  if (!/^https?:\/\//.test(cfg.base)) throw new Error('LIMS base 未配置（演示环境为占位地址，无法连接真实 LIMS）');
  const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/sys/login', { method: 'POST', body: { username: cfg.user, password: cfg.pass, captcha: '', checkKey: '' } });
  const d = r.json && (r.json.data || r.json.result);
  if (!d || !d.token) throw new Error('LIMS 登录失败：' + String(r.text || ('HTTP ' + r.status)).slice(0, 160));
  limsTokenCache = { token: d.token, base: cfg.base, user: cfg.user, at: Date.now() };
  return d.token;
}
function limsParseTime(s) {
  const m = String(s || '').match(/(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}
const limsPeriodOf = h => (h < 12 ? 'AM' : (h < 18 ? 'PM' : 'Night'));
const LIMS_PERIOD_WINDOW = { AM: ['00:00:00', '11:59:59'], PM: ['12:00:00', '17:59:59'], Night: ['18:00:00', '23:59:59'] };
async function limsFetchHumidity(cfg, token, limsRoom, ym) {
  const [yy, mm] = ym.split('-').map(Number);
  const dim = new Date(yy, mm, 0).getDate();
  const pad = n => String(n).padStart(2, '0');
  const body = { interfaceId: cfg.interfaceId, roomName: limsRoom, startDate: ym + '-01', endDate: ym + '-' + pad(dim), startTime: '', endTime: '' };
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/oapi/dataAcquisition/environment/humidityChart', { method: 'POST', headers: { 'X-Access-Token': token }, body });
      const arr = r.json && r.json.data && Array.isArray(r.json.data.result) ? r.json.data.result : [];
      return arr.map(x => ({ humidity: x.humidity, time: x.time, tm: limsParseTime(x.time) })).filter(x => x.humidity != null && x.tm);
    } catch (e) { lastErr = e; if (attempt < 2) await new Promise(res => setTimeout(res, 1200 * (attempt + 1))); }
  }
  throw lastErr || new Error('LIMS 湿度接口失败');
}
async function limsFetchEnvWindow(cfg, token, limsRoom, date, startHM, endHM) {
  const body = { interfaceId: cfg.interfaceIdTh || LIMS_DEFAULTS.interfaceIdTh, roomName: limsRoom, startDate: date, endDate: date, startTime: startHM, endTime: endHM };
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/oapi/dataAcquisition/environment/temperatureHumidityList', { method: 'POST', headers: { 'X-Access-Token': token }, body });
      const arr = r.json && r.json.data && Array.isArray(r.json.data.result) ? r.json.data.result : [];
      return arr.map(x => ({ humidity: x.humidity, temp: x.temperature, time: x.time, tm: limsParseTime(x.time) })).filter(x => (x.humidity != null || x.temp != null) && x.tm);
    } catch (e) { lastErr = e; if (attempt < 2) await new Promise(res => setTimeout(res, 1200 * (attempt + 1))); }
  }
  throw lastErr || new Error('LIMS 温湿度列表接口失败');
}
function limsPickPoint(pts, strategy, refTm) {
  if (!pts || !pts.length) return null;
  const sorted = pts.slice().sort((a, b) => a.tm - b.tm);
  switch (strategy) {
    case 'first': return sorted[0];
    case 'last': return sorted[sorted.length - 1];
    case 'min': return sorted.reduce((m, x) => (x.humidity < m.humidity ? x : m), sorted[0]);
    case 'max': return sorted.reduce((m, x) => (x.humidity > m.humidity ? x : m), sorted[0]);
    case 'avg': { const v = sorted.reduce((s, x) => s + Number(x.humidity), 0) / sorted.length; return sorted.reduce((m, x) => (Math.abs(x.humidity - v) < Math.abs(m.humidity - v) ? x : m), sorted[0]); }
    case 'nearest': { const ref = refTm instanceof Date ? refTm.getTime() : Date.now(); return sorted.reduce((m, x) => (Math.abs(x.tm - ref) < Math.abs(m.tm - ref) ? x : m), sorted[0]); }
    default: return sorted[Math.floor(Math.random() * sorted.length)];
  }
}
function limsSourceRoom(cfg, roomName) {
  for (const [lr, tr] of Object.entries(cfg.roomAlias || {})) { if (tr === roomName) return lr; }
  return (cfg.limsRooms || []).includes(roomName) ? roomName : null;
}
function limsMappedRooms(ctx) {
  const cfg = limsConfig(ctx);
  return ctx.kvget('rooms', []).map(r => r.name).filter(name => limsSourceRoom(cfg, name));
}
async function limsSyncRoom(ctx, opts) {
  const cfg = limsConfig(ctx);
  const room = String(opts.room || '').trim();
  const ym = String(opts.ym || '').trim();
  if (!room) return { error: '房间必填' };
  if (!/^\d{4}-\d{2}$/.test(ym)) return { error: '月份格式应为 YYYY-MM' };
  const cur = currentMonthStr();
  if (ym > cur) return { error: '不能抓取未来月份（' + ym + '）' };
  if (!ctx.kvget('rooms', []).some(r => r.name === room)) return { error: '房间不存在：' + room, status: 404 };
  const source = limsSourceRoom(cfg, room);
  if (!source) return { error: '该房间没有配置 LIMS 数据源（可在后台「温湿度填充 → LIMS 数据源」里维护映射）' };
  const today = todayStr();
  const curPeriod = limsPeriodOf(new Date().getHours());
  const onlyToday = opts.mode === 'day';
  if (onlyToday && ym !== cur) return { error: '「仅今天」只对当前月份有效，历史月份请用整月模式' };
  const token = await limsLogin(cfg);
  const points = await limsFetchHumidity(cfg, token, source, ym);
  const buckets = {};
  for (const p of points) {
    const ds = p.tm.getFullYear() + '-' + String(p.tm.getMonth() + 1).padStart(2, '0') + '-' + String(p.tm.getDate()).padStart(2, '0');
    if (onlyToday && ds !== today) continue;
    const k = String(p.tm.getDate()) + '_' + limsPeriodOf(p.tm.getHours());
    (buckets[k] = buckets[k] || []).push(p);
  }
  const list = allEnvRecords(ctx);
  let rec = list.find(x => x.room === room && x.ym === ym);
  if (!rec) { rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room, ym, cells: {}, updated_at: null }; list.push(rec); }
  if (!rec.cells) rec.cells = {};
  let filled = 0, skipped = 0;
  const withTemp = opts.withTemp === undefined ? !onlyToday : opts.withTemp;
  for (const k in buckets) {
    const pt = limsPickPoint(buckets[k], cfg.strategy, new Date());
    if (!pt) continue;
    if (!envCellHasData(rec.cells[k])) {
      rec.cells[k] = { temp: pt.temp != null ? Number(pt.temp).toFixed(1) : '', humidity: pt.humidity != null ? Number(pt.humidity).toFixed(1) : '', recorder: opts.recorder || cfg.recorder || '', signature_image: '', strike: 0 };
      filled++;
    } else skipped++;
  }
  if (withTemp && onlyToday) {
    const win = LIMS_PERIOD_WINDOW[curPeriod] || LIMS_PERIOD_WINDOW.AM;
    try {
      const wpts = await limsFetchEnvWindow(cfg, token, source, today, win[0], win[1]);
      const byDay = {};
      for (const p of wpts) { const dd = p.tm.getDate(); (byDay[dd] = byDay[dd] || []).push(p); }
      for (const dd in byDay) {
        const k = dd + '_' + curPeriod;
        if (!rec.cells[k]) continue;
        const pt = limsPickPoint(byDay[dd], cfg.strategy, new Date());
        if (pt && pt.temp != null) { rec.cells[k].temp = Number(pt.temp).toFixed(1); filled++; }
      }
    } catch (e) { /* 温度补抓失败不阻塞湿度结果 */ }
  }
  rec.updated_at = new Date().toISOString();
  ctx.kvset('envRecords', list);
  return { ok: true, room, source_room: source, filled_count: filled, skipped_existing: skipped, no_data: points.length === 0, temp_from_lims: withTemp };
}
async function handleLimsConfigGet(ctx) {
  const cfg = limsConfig(ctx);
  const passSet = !!cfg.pass;
  const out = Object.assign({}, cfg, { pass: '', pass_set: passSet });
  out.auto = Object.assign({}, cfg.auto);
  return json(out);
}
async function handleLimsConfigPut(ctx) {
  const b = ctx.body || {};
  const saved = ctx.kvget('lims', null) || {};
  const next = Object.assign({}, LIMS_DEFAULTS, saved);
  for (const k of ['enabled', 'base', 'user', 'pass', 'interfaceId', 'interfaceIdTh', 'recorder', 'strategy', 'overwrite']) {
    if (b[k] != null) next[k] = (k === 'enabled' || k === 'overwrite') ? !!b[k] : String(b[k]);
  }
  if (b.tempWindowBudget != null) {
    const n = Number(b.tempWindowBudget);
    next.tempWindowBudget = Number.isFinite(n) && n > 0 ? Math.min(200, Math.round(n)) : LIMS_DEFAULTS.tempWindowBudget;
  }
  if (!String(b.pass || '').trim()) next.pass = saved.pass || LIMS_DEFAULTS.pass;
  if (b.roomAlias != null && typeof b.roomAlias === 'object' && !Array.isArray(b.roomAlias)) {
    const clean = {};
    for (const [k, v] of Object.entries(b.roomAlias)) { const kk = String(k).trim(), vv = String(v).trim(); if (kk && vv) clean[kk] = vv; }
    next.roomAlias = clean;
  }
  if (b.limsRooms != null) {
    const arr = Array.isArray(b.limsRooms) ? b.limsRooms : String(b.limsRooms).split(/[\n,，]/);
    next.limsRooms = arr.map(s => String(s).trim()).filter(Boolean);
  }
  if (b.auto != null && typeof b.auto === 'object') {
    next.auto = Object.assign({}, next.auto, b.auto);
    next.auto.enabled = !!b.auto.enabled;
    if (b.auto.times != null) {
      const arr = Array.isArray(b.auto.times) ? b.auto.times : String(b.auto.times).split(/[\n,，]/);
      next.auto.times = arr.map(s => String(s).trim()).filter(s => /^\d{1,2}:\d{2}$/.test(s)).map(s => { const [h, m] = s.split(':'); return String(+h).padStart(2, '0') + ':' + m; });
    }
  }
  ctx.kvset('lims', next);
  limsTokenCache = { token: '', base: '', user: '', at: 0 };
  return json({ ok: true });
}
async function handleLimsTest(ctx) {
  const cfg = limsConfig(ctx);
  const out = { base: cfg.base, user: cfg.user };
  try {
    const token = await limsLogin(cfg);
    out.login_ok = true;
    const probeRoom = (cfg.limsRooms || [])[0] || '';
    const ym = currentMonthStr();
    const pts = await limsFetchHumidity(cfg, token, probeRoom, ym);
    out.probe_room = probeRoom; out.probe_month = ym; out.probe_points = pts.length;
    out.probe_first = pts.length ? pts[0].time : ''; out.probe_last = pts.length ? pts[pts.length - 1].time : '';
    try {
      const period = limsPeriodOf(new Date().getHours());
      const win = LIMS_PERIOD_WINDOW[period] || LIMS_PERIOD_WINDOW.AM;
      const wpts = await limsFetchEnvWindow(cfg, token, probeRoom, todayStr(), win[0], win[1]);
      const withT = wpts.filter(x => x.temp != null && x.temp !== '');
      out.temperature_available = withT.length > 0;
      if (withT.length) { out.temperature_value = String(withT[withT.length - 1].temp); out.temperature_points = withT.length; out.temperature_last_time = withT[withT.length - 1].time; }
    } catch (te) { out.temperature_available = false; out.temperature_error = String(te && te.message || te); }
    out.mapped_rooms = limsMappedRooms(ctx);
    out.ok = true;
  } catch (e) { out.ok = false; out.error = String(e && e.message || e); }
  return json(out);
}
async function handleLimsSync(ctx) {
  const b = ctx.body || {};
  let signer = null;
  if (b.signer_id) {
    const v = await verifySigner(ctx.store, b);
    if (v.error) return json({ error: v.error }, v.error === '签名密码错误' ? 401 : 400);
    signer = v.signer;
  }
  const withTemp = b.with_temp == null ? undefined : !!b.with_temp;
  const r = await limsSyncRoom(ctx, { room: b.room, ym: b.ym, mode: b.mode === 'day' ? 'day' : 'month', overwrite: b.overwrite, withTemp, signer, recorder: b.recorder });
  if (r.error) return json({ error: r.error }, r.status || 400);
  return json(r);
}
async function handleLimsSyncAll(ctx) {
  const b = ctx.body || {};
  const ym = String(b.ym || currentMonthStr()).trim();
  if (!/^\d{4}-\d{2}$/.test(ym)) return json({ error: '月份格式应为 YYYY-MM' });
  if (ym > currentMonthStr()) return json({ error: '不能抓取未来月份（' + ym + '）' });
  let signer = null;
  if (b.signer_id) {
    const v = await verifySigner(ctx.store, b);
    if (v.error) return json({ error: v.error }, v.error === '签名密码错误' ? 401 : 400);
    signer = v.signer;
  }
  const rooms = limsMappedRooms(ctx);
  if (!rooms.length) return json({ error: '没有任何房间配置了 LIMS 数据源' });
  const results = []; let filledTotal = 0;
  for (const room of rooms) {
    try {
      const r = await limsSyncRoom(ctx, { room, ym, mode: 'month', overwrite: b.overwrite, signer });
      if (r.error) results.push({ room, error: r.error });
      else { results.push({ room, source: r.source_room, filled: r.filled_count, skipped: r.skipped_existing, no_data: r.no_data, temp_from_lims: r.temp_from_lims }); filledTotal += r.filled_count; }
    } catch (e) { results.push({ room, error: String(e && e.message || e) }); }
    await new Promise(res => setTimeout(res, 300));
  }
  return json({ ok: true, ym, rooms: rooms.length, filled_total: filledTotal, results });
}

// ===================== 数据备份 / 导出（管理员） =====================
async function handleBackup(ctx) {
  const body = JSON.stringify(ctx.store, null, 2);
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': new TextEncoder().encode(body).length,
      'Content-Disposition': 'attachment; filename="kv-backup-' + todayStr() + '.json"',
    },
  });
}
async function handleExportCsv(ctx) {
  const devs = {};
  ctx.kvget('devices', []).forEach(d => { devs[d.id] = d; });
  const recs = ctx.kvget('inspections', []).slice()
    .sort((a, b) => (a.inspect_date < b.inspect_date ? 1 : a.inspect_date > b.inspect_date ? -1 : 0));
  const lines = ['设备编号,设备名称,房间,点检日期,完成时间,结果,异常备注'];
  recs.forEach(r => {
    const d = devs[r.device_id] || {};
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
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Length': new TextEncoder().encode(body).length,
      'Content-Disposition': 'attachment; filename="inspections-' + todayStr() + '.csv"',
    },
  });
}

// ===================== v1.32.1 对齐的只读接口（演示站） =====================
// GET /api/programs —— 与工厂一致：附带参与设备数与房间清单（admin.html 依赖这三个字段）
// ===================== 表单页眉（formHeads，v1.37.0 口径） =====================
// 页眉 = 打印/屏幕上表格右上角那行表单编号（如 DEMO-QR-008 Rev.A0）。4 张表来源各异，
// 上游统一成一份「按表种(kind)登记」的配置；本只读版忠实移植其解析口径与下发形状。
//   env      → 温湿度监测记录（上游原先是 env.html 里写死的常量）
//   device   → 设备日常点检记录（取模板 templates[].form_code/form_rev）
//   program  → 专项检查记录（取 programs[].form_code/form_rev）
//   checkall → 批量打印页的整册页眉（与 device 同源，但允许单独覆盖）
// 优先级：显式配置 formHeads[kind] > 载体自带（模板/检查表）> 内置默认；
//         text 非空则整行覆盖；房间级 room.form_head 只覆盖温湿度表。
const DEFAULT_FORM_HEADS = () => ({
  env:      { code: 'DEMO-QR-008', rev: 'Rev.A0' },
  device:   { code: 'DEMO-QR-032', rev: 'Rev.A1' },
  program:  { code: 'DEMO-QR-102', rev: 'Rev.A1' },
  checkall: { code: 'DEMO-QR-032', rev: 'Rev.A1' },
});
const FORM_HEAD_KINDS = [
  { kind: 'env',      name: '温湿度监测记录',   hint: '房间温湿度表（页面 /env）',                     defCode: 'DEMO-QR-008', defRev: 'Rev.A0' },
  { kind: 'device',   name: '设备日常点检记录', hint: '各设备点检表（页面 /inspect，取设备所属模板）',  defCode: 'DEMO-QR-032', defRev: 'Rev.A1' },
  { kind: 'program',  name: '专项检查记录',     hint: '专项检查表（页面 /check）',                     defCode: 'DEMO-QR-102', defRev: 'Rev.A1' },
  { kind: 'checkall', name: '批量打印页眉',     hint: '批量打印整册页眉（页面 /print-all）',            defCode: 'DEMO-QR-032', defRev: 'Rev.A1' },
];
// 读某表种（或某条具体模板 / 专项）的页眉。把「载体自带」夹在中间是有意的：
// 管理员在「模板/检查表」里填过的编号是他最直接的意图，不该被从没动过的配置项盖住。
function resolveFormHead(ctx, kind, carrier) {
  const d = DEFAULT_FORM_HEADS()[kind] || {};
  const cfg = (ctx.kvget('formHeads', {}) || {})[kind] || {};
  const pick = (a, b, c) => {
    if (a != null && String(a).trim() !== '') return String(a).trim();
    if (b != null && String(b).trim() !== '') return String(b).trim();
    return c != null ? String(c).trim() : '';
  };
  const code = pick(cfg.code, carrier && carrier.form_code, d.code);
  const rev = pick(cfg.rev, carrier && carrier.form_rev, d.rev);
  const text = String(cfg.text || '').trim();
  return { kind, code, rev, text, line: text || [code, rev].filter(Boolean).join(' ') };
}
// 温湿度页眉的「房间 → 生效文字」映射：room.form_head > formHeads.env > 内置默认
function envRoomHeadMap(ctx) {
  const base = resolveFormHead(ctx, 'env', null).line;
  const m = {};
  (ctx.kvget('rooms', []) || []).forEach(r => {
    const own = String(r.form_head || '').trim();
    m[r.name] = own || base;
  });
  return m;
}
// GET /api/form-heads —— 4 档「当前生效值」+「显式配置过的值」+ 房间级映射
async function handleGetFormHeads(ctx) {
  const cfgAll = ctx.kvget('formHeads', {}) || {};
  const items = FORM_HEAD_KINDS.map(k => {
    const r = resolveFormHead(ctx, k.kind, null);
    const cfg = cfgAll[k.kind] || {};
    return {
      kind: k.kind, name: k.name, hint: k.hint,
      code: r.code, rev: r.rev, text: r.text, line: r.line,
      cfg_code: cfg.code != null ? String(cfg.code) : '',
      cfg_rev: cfg.rev != null ? String(cfg.rev) : '',
      def_code: k.defCode, def_rev: k.defRev,
      // 该档是否会被「载体自带值」接管（如设备档取模板的 form_code）——后台要如实说明
      carrier_driven: !!(cfg.code == null || String(cfg.code).trim() === ''),
    };
  });
  return json({ items, env_room_map: envRoomHeadMap(ctx) });
}

async function handleListPrograms(ctx) {
  const dmap = {};
  ctx.kvget('devices', []).forEach(d => { dmap[d.id] = d; });
  const out = ctx.kvget('programs', []).map(p => {
    const devs = (p.device_ids || []).map(id => dmap[id]).filter(Boolean);
    return Object.assign({}, p, {
      device_count: devs.length,
      // 页眉最终值（v1.37.0）：配置(formHeads.program) > 专项自带 form_code/rev > 内置默认
      form_head: resolveFormHead(ctx, 'program', p).line,
      rooms: [...new Set(devs.map(d => String(d.location || '').trim()).filter(Boolean))],
      devices: devs.map(d => ({ id: d.id, no: d.no, name: d.name, model: d.model, location: d.location || '' }))
    });
  });
  return json(out);
}
// GET /api/check-records —— 支持 program_id / device_id / ym 三个过滤（v1.32.1）
async function handleListCheckRecords(ctx) {
  const pid = (ctx.query.get('program_id') || '').trim();
  const did = (ctx.query.get('device_id') || '').trim();
  const ym = (ctx.query.get('ym') || '').trim();
  let list = ctx.kvget('checkRecords', []);
  if (pid) list = list.filter(r => r.program_id === pid);
  if (did) list = list.filter(r => r.device_id === did);
  if (ym) list = list.filter(r => r.ym === ym);
  return json(list);
}
// GET /api/env/alerts —— 温湿度超限提醒（env-alert.js 横幅数据源）
// 工厂口径：按登录人科室过滤 + 只取近两月 + 逐格比对房间「温湿度要求」。
// 演示站差异：匿名访问时按「全部房间」计算，让未登录浏览也能看到预警横幅；已登录则严格按科室。
async function handleEnvAlerts(ctx) {
  const u = await getLoginUser(ctx.req, ctx.store);
  const dept = u ? String(u.dept || '').trim() : '';
  const rooms = dept ? ctx.kvget('rooms', []).filter(r => (r.dept || '').trim() === dept) : ctx.kvget('rooms', []);
  if (dept && !rooms.length) return json({ ok: true, hasDept: true, dept, alerts: [] });
  const roomMap = {}; rooms.forEach(r => roomMap[r.name] = r);
  const roomNames = new Set(rooms.map(r => r.name));
  const now = new Date();
  const curYm = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');
  const prev = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const prevYm = prev.getFullYear() + '-' + String(prev.getMonth() + 1).padStart(2, '0');
  const multiStd = envAlertCfgRaw(ctx).multiStd || 'union';
  const alerts = [];
  for (const rec of allEnvRecords(ctx)) {
    if (!roomNames.has(rec.room)) continue;
    if (rec.ym !== curYm && rec.ym !== prevYm) continue;
    const room = roomMap[rec.room] || {};
    const lim = parseEnvLimits(room.thermo_requirement, multiStd);
    if (!lim) continue;
    const cells = rec.cells || {};
    for (const k of Object.keys(cells)) {
      const c = cells[k];
      if (!c || c.strike) continue;
      const m = /^(\d{1,2})_(AM|PM|Night)$/.exec(k);
      const day = m ? m[1] : '?';
      const period = m ? m[2] : '';
      if (lim.tMin != null && lim.tMax != null) {
        const tv = parseFloat(c.temp);
        if (!isNaN(tv)) {
          let ex = 0, boundType = null, boundVal = 0;
          if (tv > lim.tMax) { ex = tv - lim.tMax; boundType = '上限'; boundVal = lim.tMax; }
          else if (tv < lim.tMin) { ex = lim.tMin - tv; boundType = '下限'; boundVal = lim.tMin; }
          if (ex > 0) alerts.push(mkEnvAlert(rec.room, rec.ym, day, period, '温度', tv, '℃', boundType, boundVal, ex));
        }
      }
      if (lim.hMax != null) {
        const hv = parseFloat(c.humidity);
        if (!isNaN(hv)) {
          if (hv > lim.hMax) alerts.push(mkEnvAlert(rec.room, rec.ym, day, period, '湿度', hv, '%RH', '上限', lim.hMax, hv - lim.hMax));
          else if (lim.hMin != null && hv < lim.hMin) alerts.push(mkEnvAlert(rec.room, rec.ym, day, period, '湿度', hv, '%RH', '下限', lim.hMin, lim.hMin - hv));
        }
      }
    }
  }
  const rank = { '危险': 3, '警告': 2, '注意': 1 };
  for (const a of alerts) a.level = a.exceed <= 1 ? '注意' : a.exceed <= 2 ? '警告' : '危险';
  alerts.sort((x, y) => (rank[y.level] - rank[x.level]) || (y.exceed - x.exceed));
  const counts = { 注意: 0, 警告: 0, 危险: 0 };
  alerts.forEach(a => counts[a.level]++);
  return json({ ok: true, hasDept: !!dept, dept, maxLevel: alerts.length ? alerts[0].level : null, counts, alerts });
}
// GET /api/env-alerts —— v1.30 起的预警记录列表（admin.html 温湿度预警页）
async function handleEnvAlertsList(ctx) {
  let rows = ctx.kvget('envAlerts', []);
  const status = ctx.query.get('status') || '';
  const room = ctx.query.get('room') || '';
  if (status) rows = rows.filter(a => a.status === status);
  if (room) rows = rows.filter(a => a.room === room);
  return json({ ok: true, rows: rows.slice(-500).reverse() });
}
// GET /api/notifs —— 站内通知（notify.js 期望 {ok, unread, rows}）
async function handleNotifs(ctx) {
  const u = await getLoginUser(ctx.req, ctx.store);
  if (!u) return json({ ok: true, unread: 0, rows: [] });
  const rows = ctx.kvget('notifs', []).filter(x => x.to === u.id).slice(-200).reverse();
  return json({ ok: true, unread: rows.filter(x => !x.read).length, rows });
}
// ===================== 外部系统跳转（v1.34.0 / v1.36.0 口径） =====================
// 数据：kv.links.items = [{ key, name, url, depts:[科室...], enabled }]，depts 为空 = 所有登录人员可见；
// kv.links.manual = { enabled } 控制顶栏「📖 操作手册」入口是否显示（默认显示）。
// 前端 assets/v2/core.js 的 mountNav() 读 GET /api/settings 渲染并按登录人科室过滤；取不到就静默不显示。
const LINK_URL_RE = /^https?:\/\/[^\s"'<>]+$/i;
function sanitizeLinkItem(it) {
  if (!it || typeof it !== 'object') return null;
  const key = String(it.key || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 24)
    || ('link' + Math.random().toString(36).slice(2, 8));
  const name = String(it.name || '').trim().slice(0, 40);
  const url = String(it.url || '').trim().slice(0, 200).replace(/\/+$/, '');
  const depts = (Array.isArray(it.depts) ? it.depts : []).map(x => String(x).trim()).filter(Boolean).slice(0, 20);
  return { key, name: name || key, url: LINK_URL_RE.test(url) ? url : '', depts, enabled: it.enabled !== false };
}
function externalLinks(ctx) {
  const L = ctx.kvget('links', {}) || {};
  const items = Array.isArray(L.items) ? L.items.map(sanitizeLinkItem).filter(Boolean) : [];
  const manual = (L.manual && typeof L.manual === 'object') ? { enabled: L.manual.enabled !== false } : { enabled: true };
  return { items, manual };
}
async function handleSettings(ctx) {
  // links：外部系统跳转 + 操作手册入口开关（公开可读，供前端导航使用）
  return json({ signNoPw: !!ctx.kvget('signNoPw', false), links: externalLinks(ctx) });
}
// GET /api/admin/env-alert-cfg —— 预警配置 + 各房间「生效阈值」及其来源
async function handleAdminEnvAlertCfg(ctx) {
  const cfg = Object.assign({}, ENV_ALERT_DEFAULTS, envAlertCfgRaw(ctx));
  const effective = ctx.kvget('rooms', []).map(r => {
    const { txt, empty } = envReqText(ctx, r.name);
    const parsed = (cfg.useRoomReq !== false && !empty) ? parseEnvLimits(txt, cfg.multiStd) : null;
    const L = envAlertLimits(ctx, r.name);
    return {
      name: r.name, dept: r.dept || '', requirement: txt, empty,
      parsed: parsed ? { tMin: parsed.tMin, tMax: parsed.tMax, hMin: parsed.hMin, hMax: parsed.hMax, stdCount: parsed.stdCount } : null,
      effective: { tMin: L.tMin, tMax: L.tMax, hMin: L.hMin, hMax: L.hMax }, src: L.src
    };
  });
  return json({ ok: true, cfg, effective });
}
async function handleLimsRoomStatus(ctx) {
  const room = ctx.query.get('room') || '';
  return json({ room: room, period: 'AM', today: todayStr(), is_admin: false, status_ok: true });
}
// GET /api/lims/job/:id —— LIMS 抓取任务进度（工厂是进程内任务表，演示站无任务 → 忠实返回 404）
async function handleLimsJob(ctx) {
  return json({ error: '任务不存在或已过期' }, 404);
}
// 局域网 / 日志 / 升级等管理接口：只读演示站返回安全空数据（避免前端报错）
async function handleLanEmpty(ctx) { return json([]); }
async function handleLanScan(ctx) { return json({ clients: [] }); }
async function handleLanUpgradeConfig(ctx) { return json({ enabled: false, open: false }); }
// GET /api/lan-upgrade/ping —— 目标机自述（演示站固定「不可升级」）
async function handleLanPing(ctx) {
  return json({
    ok: true, name: 'DEMO-PC', host: 'demo', version: APP_VERSION, date: APP_VERSION_DATE,
    enabled: false, open: false, engine: false, win: true, writable: false, install_dir: '.', port: 0
  });
}
async function handleAdminLogs(ctx) { return json({ logs: [] }); }

// ===================== 路由表 =====================
// adminOnly: true 表示该接口需要管理员登录（未登录返回 401）
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
  { method: 'GET', pattern: /^\/api\/inspect\/device\/([^/]+)$/, paramNames: ['id'], handler: handleDeviceDetail },
  { method: 'POST', path: '/api/inspect/day-sig', handler: handleDaySign },
  { method: 'POST', path: '/api/inspect/month', handler: handleInspectMonth },
  { method: 'GET', pattern: /^\/api\/signers\/([^/]+)\/sig$/, paramNames: ['id'], handler: handleGetSignerSignature },

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
  { method: 'PUT', pattern: /^\/api\/signers\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateSigner, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/signers\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteSigner, adminOnly: true },

  // ---- 模板 ----
  { method: 'POST', path: '/api/templates', handler: handleCreateTemplate, adminOnly: true },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleAddTemplateItem, adminOnly: true },

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

  // ---- 整月一键操作（管理员） ----
  { method: 'POST', path: '/api/admin/inspect-month', handler: handleAdminInspectMonth, adminOnly: true },
  { method: 'POST', path: '/api/admin/cancel-inspect-month', handler: handleAdminCancelInspectMonth, adminOnly: true },

  // ---- 房间管理 ----
  { method: 'GET', path: '/api/rooms', handler: handleListRooms },
  { method: 'POST', path: '/api/rooms', handler: handleCreateRoom, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/rooms\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateRoom, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/rooms\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteRoom, adminOnly: true },

  // ---- 科室管理（管理员） ----
  { method: 'GET', path: '/api/depts', handler: handleListDepts },
  { method: 'POST', path: '/api/depts', handler: handleCreateDept, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/depts\/([^/]+)$/, paramNames: ['name'], handler: handleDeleteDept, adminOnly: true },

  // ---- 模板高级编辑（管理员） ----
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateTemplate, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleSaveTemplateItems, adminOnly: true },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/duplicate$/, paramNames: ['id'], handler: handleDuplicateTemplate, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteTemplate, adminOnly: true },
  { method: 'POST', path: '/api/admin/import-template', handler: handleImportTemplate, adminOnly: true },

  // ---- 温湿度点检记录（按房间 + 年月） ----
  { method: 'GET', path: '/api/env-records', handler: handleGetEnvRecord },
  { method: 'POST', path: '/api/env-records', handler: handleSaveEnvRecord, adminOnly: true },
  { method: 'POST', path: '/api/env-records/sign-cell', handler: handleSignEnvCell },
  { method: 'POST', path: '/api/admin/env-fill', handler: handleEnvFill, adminOnly: true },
  { method: 'GET', path: '/api/admin/env-range', handler: handleEnvRangeGet, adminOnly: true },
  { method: 'PUT', path: '/api/admin/env-range', handler: handleEnvRangePut, adminOnly: true },
  { method: 'POST', path: '/api/admin/env-records/delete', handler: handleEnvRecordsDelete, adminOnly: true },
  { method: 'GET', path: '/api/admin/env-records/export-csv', handler: handleExportEnvCsv, adminOnly: true },

  // ---- LIMS 数据源（管理员） ----
  { method: 'GET', path: '/api/lims/config', handler: handleLimsConfigGet, adminOnly: true },
  { method: 'PUT', path: '/api/lims/config', handler: handleLimsConfigPut, adminOnly: true },
  { method: 'POST', path: '/api/lims/test', handler: handleLimsTest, adminOnly: true },
  { method: 'POST', path: '/api/lims/sync', handler: handleLimsSync },
  { method: 'POST', path: '/api/lims/sync-all', handler: handleLimsSyncAll, adminOnly: true },

  // ---- 数据备份 / 导出（管理员） ----
  { method: 'GET', path: '/api/admin/backup', handler: handleBackup, adminOnly: true },
  { method: 'GET', path: '/api/admin/export-inspections-csv', handler: handleExportCsv, adminOnly: true },

  // ---- v1.29.0 只读演示新增 ----
  { method: 'GET', path: '/api/programs', handler: handleListPrograms },
  { method: 'GET', path: '/api/check-records', handler: handleListCheckRecords },
  { method: 'GET', path: '/api/env/alerts', handler: handleEnvAlerts },
  { method: 'GET', path: '/api/notifs', handler: handleNotifs },
  { method: 'GET', path: '/api/settings', handler: handleSettings },
  { method: 'GET', path: '/api/admin/env-alert-cfg', handler: handleAdminEnvAlertCfg },
  { method: 'GET', path: '/api/lims/room-status', handler: handleLimsRoomStatus },
  { method: 'GET', path: '/api/lan/clients', handler: handleLanEmpty },
  { method: 'GET', path: '/api/lan/packages', handler: handleLanEmpty },
  { method: 'GET', path: '/api/lan/scan', handler: handleLanScan },
  { method: 'GET', path: '/api/lan-upgrade/config', handler: handleLanUpgradeConfig },
  { method: 'GET', path: '/api/admin/logs', handler: handleAdminLogs },

  // ---- v1.37.1 只读演示新增 ----
  { method: 'GET', path: '/api/form-heads', handler: handleGetFormHeads },

  // ---- v1.32.1 只读演示新增 ----
  { method: 'GET', path: '/api/env-alerts', handler: handleEnvAlertsList },
  { method: 'GET', path: '/api/lan-upgrade/ping', handler: handleLanPing },
  { method: 'GET', pattern: /^\/api\/lims\/job\/([^/]+)$/, paramNames: ['id'], handler: handleLimsJob },
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

// 系统版本号（与本地 server.js 保持一致）
const APP_VERSION = 'v1.37.1';
const APP_VERSION_DATE = '2026-09-21';

// ===================== 只读演示站策略 =====================
// 演示站允许「登录」：登录只做口令校验 + HMAC 签发票据（cookie），不写入任何数据，
// 因此从写入拦截里白名单放行。其余一切写方法（新增/编辑/删除/导入/备份恢复/一键操作…）仍 403。
// 演示账号见 README：admin / admin123（管理员）、demo-user / demo123（普通用户）。
const READONLY_WRITE_ALLOW = new Set(['/api/admin/login']);
// 整库导出接口含 pepper / secret / 口令哈希（可据此伪造会话），即便演示站也要求先登录，避免匿名抓取。
const READONLY_LOGIN_REQUIRED = new Set(['/api/admin/backup']);

// ===================== API 分发 =====================
async function handleApi(req, env) {
  let store = await loadStore(env);
  let dirty = false;
  // 口令 pepper / 会话 secret 的取值优先级：KV 内固化值 → Pages 环境变量 APP_PEPPER / APP_SECRET →
  // 本次请求随机（兜底；随机值每次请求都变，会导致登录校验永远不过，正式部署务必固化其一）。
  // 只读演示站：绝不回写 KV、绝不自动创建账号（演示账号已预置在 KV 的 users 中）。
  if (!store.pepper) store.pepper = env.APP_PEPPER || randHex(32);
  if (!store.secret) store.secret = env.APP_SECRET || randHex(32);
  if (!store.users) store.users = [];

  const kvget = (key, def) => (store[key] === undefined ? def : store[key]);
  const kvset = (key, val) => { store[key] = val; };

  const url = new URL(req.url);
  const p = url.pathname;
  const method = req.method;
  // ===== 只读演示站：拦截写入（例外：登录，只校验发 cookie 不落库）=====
  const isWrite = (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS');
  if (isWrite && !READONLY_WRITE_ALLOW.has(p)) {
    return json({ readonly: true, error: '演示站为只读展示模式，禁止任何写入 / 新增 / 编辑 / 删除操作' }, 403);
  }
  const ctx = { req, env, store, kvget, kvset, params: {}, query: url.searchParams, body: {}, readonly: true };
  try {
    const route = matchRoute(method, p);
    if (!route) return json({ error: '接口不存在: ' + method + ' ' + p }, 404);
    // 只读演示站：浏览类 GET 接口对访客公开（无需登录即可看数据）；
    // 但含密钥的整库导出仍要求有效登录会话。
    if (READONLY_LOGIN_REQUIRED.has(p)) {
      const me = await getLoginUser(req, store);
      if (!me) return json({ readonly: true, error: '该接口含密钥与口令哈希，请先登录后访问' }, 401);
    }
    ctx.body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
    ctx.params = route.params;
    return await route.handler(ctx);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}

// ===================== 静态文件（含 pretty URL 重写） =====================
const CLEAN = {
  '/': 'index.html',
  '/inspect': 'inspect.html',
  '/admin': 'admin.html',
  '/monthly': 'monthly.html',
  '/print-all': 'print-all.html',
  '/login': 'login.html',
  '/rooms': 'rooms.html',
};
async function serveStatic(request, env) {
  const url = new URL(request.url);
  let p = decodeURIComponent(url.pathname);
  if (p === '/' || p === '') p = '/';           // 根路径交给 ASSETS 解析 index
  // 直接按原路径（含干净 URL，如 /monthly）请求；ASSETS 会自动解析 .html
  const safe = p.replace(/\.{2,}/g, '');
  let res = await env.ASSETS.fetch(new Request(new URL(url.origin + safe + url.search), request));
  // Cloudflare ASSETS 会把 /xxx.html 规范化为 /xxx（308），跟随一次以避免循环
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get('Location');
    if (loc) {
      const lu = new URL(loc, url.origin);
      let lp = lu.pathname || '/';
      if (lp === '/' || lp === '') lp = '/';
      const lsafe = lp.replace(/\.{2,}/g, '');
      res = await env.ASSETS.fetch(new Request(new URL(url.origin + lsafe + lu.search), request));
    }
  }
  return res;
}

// ===================== 入口 =====================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  if (!url.pathname.startsWith('/api/')) {
    // 退出登录：清除登录 cookie 并回到登录页
    if (url.pathname === '/logout' && request.method === 'GET') {
      return new Response(null, {
        status: 302,
        headers: {
          'Location': '/login',
          'Set-Cookie': `${ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`,
        },
      });
    }
    // 静态资源 + pretty URL
    return serveStatic(request, env);
  }
  return await handleApi(request, env);
}
