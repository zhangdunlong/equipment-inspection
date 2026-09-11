// Cloudflare Pages Functions —— 设备点检巡检系统后端
// 单文件 catch-all 路由，所有 /api/* 请求在此处理。
// 移植自本地最新版 server.js（v1.0.0 / 2026-09-09：声明式路由表 + 房间管理 + 版本接口 +
// 数据备份 + CSV 导出 + 单台明细 + 多用户角色权限 + 后台用户管理）。
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
  return { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], users: [], pepper: '', secret: '' };
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
  return json({ ok: !!u, username: u ? u.username : '', name: u ? u.name : '', role: u ? u.role : '' });
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
  return json(users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active })));
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
  return json(list.filter(s => s.active).map(s => ({ id: s.id, name: s.name, signature_image: s.signature_image || null })));
}
async function handleListSigners(ctx) {
  const list = ctx.kvget('signers', []);
  return json(list.map(s => ({ id: s.id, name: s.name, active: !!s.active, has_sig: !!s.signature_image })));
}
async function handleCreateSigner(ctx) {
  const b = ctx.body;
  if (!b.name || !b.password) return json({ error: '姓名与密码必填' }, 400);
  const list = ctx.kvget('signers', []);
  list.push({ id: uuid(), name: b.name, active: true, password_hash: await sha256(b.password + ctx.store.pepper),
    signature_image: b.signature_image || null });
  ctx.kvset('signers', list);
  return json({ ok: true });
}
async function handleGetSignerSignature(ctx) {
  const s = (ctx.kvget('signers', [])).find(x => x.id === ctx.params.id);
  return json({ image: s ? (s.signature_image || null) : null });
}
async function handleUpdateSigner(ctx) {
  const b = ctx.body;
  const list = ctx.kvget('signers', []);
  const s = list.find(x => x.id === ctx.params.id);
  if (!s) return json({ error: '签名人不存在' }, 404);
  if (typeof b.active === 'boolean') s.active = b.active;
  if (b.password) s.password_hash = await sha256(b.password + ctx.store.pepper);
  if ('signature_image' in b) s.signature_image = b.signature_image || null;
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
  let created = 0, updated = 0;
  for (const d of devices) {
    const items = await deviceItems(ctx.store, d);
    const bySn = buildBySn(items, 'ok');
    for (const dd of monthDays(month, endDay)) {
      const r = await upsertInspection(ctx, { device_id: d.id, inspect_date: dd },
        { status: 'ok', signed_by: signer.name, signer_id: signer.id, abnormal_note: '', bySn, signed_at: randMorningTime(dd) });
      if (r === 'created') created++; else updated++;
    }
  }
  return json({ devices: devices.length, days: endDay, signer: signer.name, created, updated });
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
        days[dd] = { bySn: rec.bySn || {}, signature_image: signerSignature(ctx.store, rec), abnormal_note: rec.abnormal_note || '' };
        if (rec.signed_by) signerSet.add(rec.signed_by);
      }
    }
    const abn = ctx.kvget('abnormalRecords', []).filter(r => r.device_id === d.id && r.month === month);
    const tpl = d.template_id ? ctx.kvget('templates', []).find(x => x.id === d.template_id) : null;
    out.push({ id: d.id, no: d.no, name: d.name, model: d.model, items, days,
      signers: [...signerSet], abnormal: abn, note: tpl ? (tpl.note || '') : '' });
  }
  return json({ month, devices: out });
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
  return json({ version: APP_VERSION, date: APP_VERSION_DATE });
}

// ===================== 房间管理 =====================
async function handleListRooms(ctx) {
  const rooms = ctx.kvget('rooms', []);
  const c = roomCounts(ctx.store);
  return json(rooms.map(r => ({ name: r.name, desc: r.desc || '', count: c[r.name] || 0 })));
}
async function handleCreateRoom(ctx) {
  const b = ctx.body;
  const name = String(b.name || '').trim();
  if (!name) return json({ error: '房间名称必填' }, 400);
  if (name.length > 40) return json({ error: '房间名称不能超过 40 字' }, 400);
  const rooms = ctx.kvget('rooms', []);
  if (rooms.some(r => r.name === name)) return json({ error: '房间「' + name + '」已存在' }, 400);
  rooms.push({ name, desc: String(b.desc || '').trim() });
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
  { method: 'GET', path: '/api/signers/:id/sig', handler: handleGetSignerSignature },

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

// 系统版本号（与本地 server.js 保持一致）
const APP_VERSION = 'v1.0.0';
const APP_VERSION_DATE = '2026-09-09';

// ===================== API 分发 =====================
async function handleApi(req, env) {
  let store = await loadStore(env);
  let dirty = false;
  // 首次运行随机生成并持久化密钥（仅在 STORE 缺失时；正常部署已固化 pepper/secret）
  if (!store.pepper) { store.pepper = randHex(32); dirty = true; }
  if (!store.secret) { store.secret = randHex(32); dirty = true; }
  if (!store.users) store.users = [];
  if (await ensureUsers(store)) dirty = true;

  const kvget = (key, def) => (store[key] === undefined ? def : store[key]);
  const kvset = (key, val) => { store[key] = val; dirty = true; };

  const url = new URL(req.url);
  const p = url.pathname;
  const method = req.method;
  const ctx = { req, env, store, kvget, kvset, params: {}, query: url.searchParams, body: {} };
  try {
    const route = matchRoute(method, p);
    if (!route) return json({ error: '接口不存在: ' + method + ' ' + p }, 404);
    if (route.adminOnly && !(await isAdmin(req, store))) return json({ error: '未登录或登录已失效' }, 401);
    ctx.body = (method === 'POST' || method === 'PUT') ? await readBody(req) : {};
    ctx.params = route.params;
    return await route.handler(ctx);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  } finally {
    if (dirty) {
      try { await env.INSPECTION_DATA.put(KV_KEY, JSON.stringify(store)); } catch {}
    }
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
