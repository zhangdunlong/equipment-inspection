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
const APP_VERSION = 'v1.29.0';
const APP_VERSION_DATE = '2026-09-17';

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
// programs     = 独立检查项目定义（如「夏比冲击摩擦和风阻损耗检查」「显微镜维护记录」）
// checkRecords = 独立检查项目的记录（按 项目+设备+年月 一份，行内按 日期/周次 存各列的值）
// 这两类数据与设备点检（inspections）完全分开：属于独立项目的设备不再出现在点检大屏 / 点检作业 / 一键点检里。
let store = { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], depts: [], envRecords: [], programs: [], checkRecords: [] };

function loadStore() {
  let raw = null;
  try { raw = fs.readFileSync(DATA_FILE, 'utf8'); } catch (e) {}
  if (!raw) {
    // 开源演示版：首次启动用内置示例数据 data/sample.kv.json 做种子
    const SAMPLE = path.join(DATA_DIR, 'sample.kv.json');
    try { raw = fs.readFileSync(SAMPLE, 'utf8'); } catch (e) {}
    if (raw) {
      try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(DATA_FILE, raw);
        console.log('[初始化] 已用示例数据生成 data/kv.json');
      } catch (e) {}
    }
  }
  if (raw) {
    try {
      const o = JSON.parse(raw);
      store = Object.assign({ admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], envRecords: [], programs: [], checkRecords: [] }, o);
    } catch (e) {
      console.error('[数据] data/kv.json 解析失败，使用空数据:', e.message);
    }
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

// ===================== 独立检查项目（programs） =====================
// 「检查项目」= 一套独立的检查表（自己的表头 / 列 / 周期），与设备点检完全分开。
// 场景：同一间屋子里既有常规点检设备，也有专项检查设备（冲击机摩擦风阻、显微镜维护等），
// 后者只是恰好放在同一房间，检查内容与周期跟点检无关 → 单独立项、单独入口、单独成表。
// 归属：模板 template.program_id → 项目；设备经模板继承。program_id 为空 = 常规设备点检。
// 列的 type：number 数值 | text 文本 | choice 选择题 | conclusion 结论(√/×/) | sign 电子签名
// row_unit  ：day 每天一行 | week 每周一行
const DEFAULT_PROGRAMS = [
  {
    id: 'prg-qr102',
    device_ids: [],          // 参与本项目的设备（由下面 auto_tpl_keys 自动算出来，与设备的点检模板互不影响）
    // ★ 自动关联规则 = 按「点检模板 key」认设备，而不是把设备 id 硬编码进来。
    //   设备 id 每台机器都不一样（工厂机 / 本机 / 重装后全新生成），硬编码 id 会造成
    //   「本机看得见、工厂机升级后看不到」——2026-09-16 实测踩过，见交接文档 §2.60。
    auto_tpl_keys: ['ZBC2302N-3', 'TPS452D3-3', 'NI750'],
    name: '夏比冲击摩擦和风阻损耗检查',
    title: '夏比冲击试验机摩擦和风阻损耗日常检查记录',
    title_en: 'Daily Inspection Record of Percent Friction and Windage Loss on Charpy Impact Testing Machine',
    form_code: 'PK-JC-QR-102',
    form_rev: 'Rev.A1',
    row_unit: 'day',
    columns: [
      // span:2 —— 线下表里这一列表头跨 2 个网格列（「摩擦和风阻损耗」横跨两列），
      // 渲染时用来对齐表头行与底部判定标准的合并结构，见 check.html render() 的说明。
      { key: 'friction',   label: '摩擦和风阻损耗', label_en: 'Percent Friction and Windage Loss', type: 'number', span: 2 },
      { key: 'delta',      label: '与前次变化',     label_en: 'Different from Previous',           type: 'number' },
      { key: 'tester',     label: '检查人',         label_en: 'Tester',                            type: 'sign' },
      { key: 'conclusion', label: '结论(√/×)',      label_en: 'Conclusion',                        type: 'conclusion' },
      { key: 'remark',     label: '备注',           label_en: 'Remark',                            type: 'text' }
    ],
    side_title: '每天摩擦损耗实验前检查步骤',
    side_title_en: 'Steps for checking daily friction loss before conducting experiments',
    side_items: [
      '检查环境温湿度是否符合要求',
      '检查所选的试验机应在有效期内',
      '对摆锤和砧座进行目视检查应无明显的损坏和磨损',
      '采用一次自由摆动来检查试验机，检验试验机回零差',
      '带有显示装置的试验机必须直接在显示屏上指示出吸收能量为0',
      '对于没有对总摩擦损失进行补偿的试验机，刻度盘显示的将不是0刻度位置。这种情况下，在换算成冲击能量的时候，指针所标示的数值必须根据指针摆动的弧度对总摩擦损失按比例进行修正'
    ],
    criteria: [
      { std: 'ASTM E23', vals: ['≤设备总量程的0.4%', '≤前次测量值的10%',
        "1.手动计算公式：P=K1-K2，P'=（K3-K2）÷10÷使用机器最大量程；K1: 不安装试样情况下得到试验机仪表读数，K2: 不复位指针的情况下的空摆数据，K3: 使摆锤在无冲击和振动的情况下允许摆锤循环5次（一次向前和一次向后视为一个循环），在第6次向前摆动之前，刻度盘指针设置在所用量程的5%，第六次摆动之后，记录数值。2.自动计算：通过设备厂家自带的功能系统来进行摩擦风阻自动计算（详细操作规程见 PK-JC-WI-XN-022）"] },
      { std: 'GB/T229',  vals: ['≤设备总量程的0.5%', '/', ''] }
    ],
    row_count: 31,
    note: '维护状态为正常时，划"√"；异常时，划"×"；节假日划"/"。'
  },
  {
    id: 'prg-qr079',
    device_ids: [],
    // 自动关联规则（按模板 key）：4 台显微镜（3 台金相 + 1 台体视）。
    // 新模板若也挂到设备上，同样会被自动纳入本项目。
    auto_tpl_keys: ['PK-JC-QR-079', 'PK-JC-QR-079-Axio vert A1', 'PK-JC-QR-079-Axio observer',
      'PK-JC-QR-079-Axio scope5', 'PK-JC-QR-079-OLYMPUS SZX7'],
    name: '显微镜维护记录',
    title: '显微镜维护记录',
    title_en: 'Maintenance Record of Microscope',
    form_code: 'PK-JC-QR-079',
    form_rev: 'Rev.A0',
    row_unit: 'week',
    columns: [
      { key: 'content',  label: '内容',     label_en: 'Contents', type: 'select', def: '1,2,3', opts: ['1,2,3', '1,2,3,4', '1,2,3,5', '1,2,3,4,5'] },
      { key: 'checking', label: '检查情况', label_en: 'Checking', type: 'choice', def: '正常', opts: ['正常', '异常'] },
      { key: 'operator', label: '操作者',   label_en: 'Operator', type: 'sign' }
    ],
    row_count: 0,
    note: '备注 Remarks：\n一、操作者应在工作日每周第一天上班后 1 小时之内和检测工作开始前进行维护。\n二、内容：1.设备运行情况；2.设备状态；3.设备维护。\n一、Maintenance of microscope shall be conducted by operator within one hour after the beginning of the work on the first day of every week (workday) and before the beginning of the testing work.\n二、Content: 1 Running condition of equipment; 2 Device status; 3 Maintenance of equipment.'
  }
];

function seedPrograms() {
  const list = kvget('programs', []);
  if (Array.isArray(list) && list.length) return;
  kvset('programs', JSON.parse(JSON.stringify(DEFAULT_PROGRAMS)));
  console.log('[初始化] 已写入 ' + DEFAULT_PROGRAMS.length + ' 个内置检查项目');
}

// 按 auto_tpl_keys（模板 key）自动算出「项目 → 设备」的关联，每次启动都跑一遍。
// 为什么不能靠种子里的 device_ids：设备 id 是每台机器各自生成的 UUID，把 id 写死进代码，
// 换台机器（工厂机升级 / 重装）就全部对不上 → 项目表面存在却「没有设备」，页面自然不显示入口。
// 用模板 key 认设备则天然可移植：只要那台设备挂的是这张点检表，就属于这个检查项目。
// auto_link === false 的项目（将来若做「手工指定设备」）不参与自动计算。
function syncProgramDevices() {
  const list = kvget('programs', []);
  if (!Array.isArray(list) || !list.length) return;
  const tplKey = {};
  allTemplates().forEach(t => { tplKey[t.id] = String(t.key || ''); });
  const devs = allDevices();
  let changed = false;
  list.forEach(p => {
    // 老数据（早期种子里没有 auto_tpl_keys 字段）→ 从内置定义补齐，保证升级后也能自动关联
    const seed = DEFAULT_PROGRAMS.find(x => x.id === p.id);
    if (seed && seed.auto_tpl_keys && !p.auto_tpl_keys) {
      p.auto_tpl_keys = seed.auto_tpl_keys.slice();
      changed = true;
    }
    // 老数据的列定义缺 span（102 的「摩擦和风阻损耗」要跨 2 列）→ 按 key 从内置定义补齐
    if (seed && Array.isArray(seed.columns) && Array.isArray(p.columns)) {
      seed.columns.forEach(sc => {
        const pc = p.columns.find(x => x && x.key === sc.key);
        if (pc && sc.span && !pc.span) { pc.span = sc.span; changed = true; }
      });
    }
    if (p.auto_link === false) return;
    const keys = p.auto_tpl_keys || [];
    if (!keys.length) return;
    const ids = devs.filter(d => keys.indexOf(tplKey[d.template_id]) >= 0).map(d => d.id);
    // 防呆：按模板 key 一台都匹配不上、而库里本来有设备 → 说明这些模板 key 已不存在
    // （如 v1.24.0 清理了旧显微镜模板），此时**不能**把关联清成空，否则专项检查会整条消失。
    if (!ids.length && (p.device_ids || []).length) {
      logW('检查项目', '「' + p.name + '」模板 key 已匹配不到设备，保留原有 ' + p.device_ids.length + ' 台关联不覆盖');
      return;
    }
    if (JSON.stringify(p.device_ids || []) !== JSON.stringify(ids)) {
      p.device_ids = ids;
      changed = true;
      logI('检查项目', '「' + p.name + '」自动关联 ' + ids.length + ' 台设备');
    }
  });
  if (changed) kvset('programs', list);
}

// v1.20.0 迁移：#079「内容」列由 text/def:'1.2.3' 升级为 select/def:'1,2,3'，
// 并归一历史记录里用点号分隔的「内容」值（1.2.3 → 1,2,3）。幂等：已升级则跳过。
function migrateProgramColumns() {
  const list = kvget('programs', []);
  if (!Array.isArray(list) || !list.length) return;
  const Q79_OPTS = ['1,2,3', '1,2,3,4', '1,2,3,5', '1,2,3,4,5'];
  let changed = false;
  const p = list.find(x => x && x.id === 'prg-qr079');
  if (p && Array.isArray(p.columns)) {
    const c = p.columns.find(x => x && x.key === 'content');
    if (c) {
      const ok = c.type === 'select' && c.def === '1,2,3' &&
        Array.isArray(c.opts) && c.opts.length === Q79_OPTS.length &&
        Q79_OPTS.every((v, i) => c.opts[i] === v);
      if (!ok) {
        c.type = 'select'; c.def = '1,2,3'; c.opts = Q79_OPTS.slice();
        changed = true;
        logI('检查项目', '#079「内容」列升级为可选项（默认 1,2,3）');
      }
    }
  }
  if (!changed) return;
  const recs = kvget('checkRecords', []);
  if (Array.isArray(recs)) {
    let mc = 0;
    for (const r of recs) {
      if (!r || r.program_id !== 'prg-qr079' || !r.rows) continue;
      for (const day in r.rows) {
        if (!r.rows[day]) continue;
        const cell = r.rows[day].content;
        if (typeof cell === 'string' && /^(\d+\.)+\d+$/.test(cell)) {
          r.rows[day].content = cell.replace(/\./g, ',');
          mc++;
        }
      }
    }
    if (mc) { kvset('checkRecords', recs); logI('检查项目', '#079 历史记录归一 ' + mc + ' 个「内容」值（. → ,）'); }
  }
  kvset('programs', list);
}


// v1.22.0 迁移：#079 备注补全「4.期间核查；5.校准」（中英）——纸质表本有，早期导入缺失；
// 工厂机 prg-qr079 备注里的 U+FFFD 乱码（"3.□□备维护"）一并随整段覆写修复。
// 幂等 + 防误伤：只对"仍含旧自动文案特征（设备维护）且缺期间核查"的备注覆写，管理员后期手改过的不动。
function migrate079Notes() {
  const PROG_NOTE = [
    '备注 Remarks：',
    '一、操作者应在工作日每周第一天上班后 1 小时之内和检测工作开始前进行维护。',
    '二、内容：1.设备运行情况；2.设备状态；3.设备维护；4.期间核查；5.校准。',
    '一、Maintenance of microscope shall be conducted by operator within one hour after the beginning of the work on the first day of every week (workday) and before the beginning of the testing work.',
    '二、Content: 1 Running condition of equipment; 2 Device status; 3 Maintenance of equipment; 4 Intermediate check; 5 Calibration.',
  ].join('\n');
  const TPL_NOTE = [
    '备注 Note：',
    '一、操作者应在工作日每周第一天上班后 1 小时之内和检测工作开始前进行维护。',
    '二、内容：1.设备运行情况；2.设备状态；3.设备维护；4.期间核查；5.校准。',
    '检查情况为正常时划"√"，异常时划"×"，非检查日/节假日划"/"。',
    '一、Maintenance of microscope shall be conducted by operator within one hour after the beginning of the work on the first day of every week (workday) and before the beginning of the testing work.',
    '二、Content: 1 Running condition of equipment; 2 Device status; 3 Maintenance of equipment; 4 Intermediate check; 5 Calibration.',
  ].join('\n');
  let pc = false;
  const progs = kvget('programs', []);
  const p = progs.find(x => x && x.id === 'prg-qr079');
  if (p && typeof p.note === 'string' && p.note && p.note.indexOf('期间核查') < 0 && p.note.indexOf('设备维护') >= 0) {
    p.note = PROG_NOTE; pc = true;
    logI('检查项目', '#079 项目备注补全（4.期间核查；5.校准，中英）');
  }
  if (pc) kvset('programs', progs);
  const tpls = allTemplates();
  let tc = 0;
  for (const t of tpls) {
    if (!t || typeof t.key !== 'string' || t.key.indexOf('PK-JC-QR-079') !== 0) continue;
    if (typeof t.note === 'string' && t.note && t.note.indexOf('期间核查') < 0 && t.note.indexOf('设备维护') >= 0) {
      t.note = TPL_NOTE; tc++;
    }
  }
  if (tc) { kvset('templates', tpls); logI('模板', '#079 分型号模板备注补全（4.期间核查；5.校准）× ' + tc); }
}

// v1.24.0 迁移：清理「旧显微镜点检模板」与历史遗留的「#102 分型号模板」。
// 背景：#079 显微镜维护记录已整体改成独立检查项目（prg-qr079，周检月表），设备上再挂一张
//       PK-JC-QR-079-* 点检模板就会出现「点进去还是旧模板」的双头现象；PK-JC-QR-102-* 同理
//       早被 prg-qr102 取代，且当初就没有任何设备引用（0 台）。
// 做法：不硬删 —— 整块归档进 kv._archivedTemplates 留底，再摘掉 devices[].template_id。
//       点检记录（inspections）一律保留：那是已经签过字的凭证，不随模板清理而消失。
// 幂等：没有可清理的模板时直接返回。
function migrateDropLegacyTemplates() {
  const tpls = allTemplates();
  const legacy = t => {
    const k = String((t && t.key) || '').trim();
    return k.indexOf('PK-JC-QR-079') === 0 || k.indexOf('PK-JC-QR-102') === 0;
  };
  const victims = tpls.filter(legacy);
  if (!victims.length) return;
  const vids = new Set(victims.map(t => t.id));
  const devs = allDevices();
  const affected = devs.filter(d => d.template_id && vids.has(d.template_id));
  const hit = new Set(affected.map(d => d.id));
  // 关键：被删模板正是某些独立检查项目「自动关联」的锚点（如 prg-qr079 靠 PK-JC-QR-079-* 找设备）。
  // 删掉锚点后 syncProgramDevices 下次启动就匹配不到设备了 → 这里先把当前实际关联固化进
  // device_ids 并关掉 auto_link，专项检查的参与设备才不会在重启后凭空消失。
  const vkeys = new Set(victims.map(t => t.key));
  const progs = allPrograms();
  let pchg = false;
  progs.forEach(p => {
    if (!p || p.auto_link === false) return;
    if (!(p.auto_tpl_keys || []).some(k => vkeys.has(k))) return;
    p.auto_link = false;
    pchg = true;
    logI('检查项目', '「' + p.name + '」关联由「按模板 key 自动」固化为设备清单（' + (p.device_ids || []).length + ' 台）');
  });
  if (pchg) kvset('programs', progs);
  const arch = kvget('_archivedTemplates', []);
  arch.push({ at: new Date().toISOString(), reason: 'v1.24.0 清理旧显微镜 / 冲击分型号点检模板',
    templates: victims,
    detached: affected.map(d => ({ id: d.id, no: d.no, name: d.name, template_id: d.template_id })) });
  kvset('_archivedTemplates', arch);
  kvset('templates', tpls.filter(t => !vids.has(t.id)));
  if (affected.length) {
    kvset('devices', devs.map(d => hit.has(d.id) ? Object.assign({}, d, { template_id: null }) : d));
  }
  logI('模板', '清理旧模板 ' + victims.length + ' 张（' + victims.map(t => t.key).join('、') + '）' +
    (affected.length ? '，解除 ' + affected.length + ' 台设备的引用' : ''));
}

// ===================== 历史脏数据自愈：U+FFFD 乱码 =====================
// 现象：个别中文字被截断成替换字符 U+FFFD（1 个汉字 → 2~3 个 \uFFFD），
//       打印/显示时表现为「温控表是否正□示」这类空框。2026-09-16 用户在某台机器点检表上发现。
// 来源：早期 Excel / 备份导入链路里的编码损坏（工厂机与本机各有若干处，互不重叠），
//       事后无法从源头重导 → 按「上下文唯一的坏片段 → 正确文字」逐条还原。
// 原则：只做已核对过的精确还原，绝不猜字；还原不掉的写 warning 日志留着人工处理。
const MOJIBAKE_FIXES = [
  [/持\uFFFD+蠕变室1/g, '持久蠕变室1'],
  [/持久\uFFFD+变室1/g, '持久蠕变室1'],
  [/金相分\uFFFD+室/g, '金相分析室'],
  [/异常\uFFFD+，划/g, '异常时，划'],
  [/^\uFFFD+查所有的接线是否安全可靠$/g, '检查所有的接线是否安全可靠'],
  [/磨损损\uFFFD+/g, '磨损损耗'],
  [/温控表及试\uFFFD+机是否联机/g, '温控表及试验机是否联机'],
  [/升降系\uFFFD+是否灵活/g, '升降系统是否灵活'],
  [/^\uFFFD+验结束后，保持仪器设\uFFFD+及操作台面卫生$/g, '试验结束后，保持仪器设备及操作台面卫生'],
  [/温控表是否正\uFFFD+显示/g, '温控表是否正常显示'],
  [/维氏硬\uFFFD+设备日常维护/g, '维氏硬度设备日常维护'],
  [/^每\uFFFD+$/g, '每天'],
  [/冲\uFFFD+能量\uFFFD+时候/g, '冲击能量的时候'],
  [/必须\uFFFD+据指针摆动/g, '必须根据指针摆动'],
  [/带\uFFFD+显示装置的试验机/g, '带有显示装置的试验机'],
  [/。\uFFFD+护状态为正常时/g, '。维护状态为正常时'],
  [/设备运行\uFFFD+况/g, '设备运行情况'],
  [/LIMS自动导\uFFFD+$/g, 'LIMS自动导入'],
  // 签名人姓名（历史 inspections[].signed_by 里的残字）
  [/^张敦\uFFFD+$/g, '张敦龙'],
  [/^张\uFFFD+龙$/g, '张敦龙'],
  [/^张\uFFFD+$/g, '张敦龙'],
  [/^\uFFFD+敦龙$/g, '张敦龙']
];
function applyMojibakeFixes(s) {
  let out = s;
  MOJIBAKE_FIXES.forEach(pair => { out = out.replace(pair[0], pair[1]); });
  return out;
}
function fixMojibake() {
  if (JSON.stringify(store).indexOf('\uFFFD') < 0) return;   // 快速短路：正常启动都从这里返回
  let hits = 0;
  const left = [];
  const walk = (obj, path) => {
    if (Array.isArray(obj)) { obj.forEach((v, i) => walk(v, path + '[' + i + ']')); return; }
    if (!obj || typeof obj !== 'object') return;
    Object.keys(obj).forEach(k => {
      const v = obj[k];
      if (typeof v === 'string') {
        if (v.indexOf('\uFFFD') < 0) return;
        const fixed = applyMojibakeFixes(v);
        if (fixed !== v) { obj[k] = fixed; hits++; }
        if (fixed.indexOf('\uFFFD') >= 0) left.push(path + '.' + k + '=' + JSON.stringify(fixed).slice(0, 90));
      } else walk(v, path + '.' + k);
    });
  };
  walk(store, 'kv');
  if (hits) { scheduleSave(); logI('数据自愈', '已还原 ' + hits + ' 处历史乱码（U+FFFD）'); }
  if (left.length) logW('数据自愈', '仍有 ' + left.length + ' 处乱码未能自动还原，需人工核对：' + left.slice(0, 5).join(' ｜ '));
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
  logW('API', 'HTTP ' + status + ' ' + msg);
  return sendJson(res, { error: msg }, status);
}

// ===================== 运行日志（文件 + 内存环形缓冲） =====================
// 落盘: data/logs/app-YYYY-MM-DD.log（保留 14 天，自动清理）；内存: 最近 2000 条供后台「运行日志」即时查看。
// 用法: logI/logW/logE('标签', '内容')。关键节点一条，别在请求热路径刷屏。
const LOG_DIR = path.join(DATA_DIR, 'logs');
const LOG_KEEP_DAYS = 14;
const LOG_MEM_MAX = 2000;
let logMem = [];   // {t, level, tag, msg}
function fmtLogTs(d) {
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') +
    ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0') + ':' + String(d.getSeconds()).padStart(2, '0');
}
function logLine(level, tag, msg) {
  const d = new Date();
  const line = fmtLogTs(d) + ' [' + level + '][' + tag + '] ' + msg;
  logMem.push({ t: d.getTime(), level, tag, msg });
  if (logMem.length > LOG_MEM_MAX) logMem.splice(0, logMem.length - LOG_MEM_MAX);
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.appendFileSync(path.join(LOG_DIR, 'app-' + todayStr() + '.log'), line + '\n');
  } catch (e) { /* 日志失败绝不影响业务 */ }
  if (level === 'ERROR') console.error(line); else console.log(line);
}
const logI = (tag, msg) => logLine('INFO', tag, msg);
const logW = (tag, msg) => logLine('WARN', tag, msg);
const logE = (tag, msg) => logLine('ERROR', tag, msg);
function pruneOldLogs() {
  try {
    const cutoff = Date.now() - LOG_KEEP_DAYS * 86400 * 1000;
    for (const f of fs.readdirSync(LOG_DIR)) {
      const m = /^app-(\d{4})-(\d{2})-(\d{2})\.log$/.exec(f);
      if (!m) continue;
      if (new Date(+m[1], +m[2] - 1, +m[3], 23, 59, 59).getTime() < cutoff) {
        try { fs.unlinkSync(path.join(LOG_DIR, f)); logI('LOG', '已清理过期日志 ' + f); } catch (e) { /* ignore */ }
      }
    }
  } catch (e) { /* logs 目录不存在等，忽略 */ }
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
// ---- 功能权限（v1.9.0）：给普通用户按人开关部分管理员功能 ----
// user.perms = { key: 0|1 }；未配置的键取默认值 —— 老账号零影响（现状即默认）。
// PERM_DEF=1 的键是「现在人人都能用」的功能（如温湿度表录入），默认放开、可单独收紧。
const PERM_DEFS = {
  env_edit:      { label: '温湿度表录入',   desc: '温湿度页手动填写/保存/划线', def: 1 },
  env_fill:      { label: '温湿度一键填充', desc: '后台一键填充、LIMS 抓取/同步', def: 0 },
  env_delete:    { label: '温湿度记录删除', desc: '后台按房间+月份整表删除', def: 0 },
  tpl_edit:      { label: '点检模板管理',   desc: '新增/编辑/复制/删除点检模板', def: 0 },
  inspect_batch: { label: '批量点检操作',   desc: '一键点检、整月生成/撤销、批量删除记录', def: 0 },
  export:        { label: '数据导出备份',   desc: '下载 JSON 备份、导出点检/温湿 CSV', def: 0 },
};
const PERM_KEYS = Object.keys(PERM_DEFS);
function userHasPerm(u, key) {
  if (!u) return false;
  if (u.role === 'admin') return true;
  const d = PERM_DEFS[key];
  if (!d) return false;
  const v = u.perms ? u.perms[key] : undefined;
  return (v === undefined || v === null) ? !!d.def : !!v;
}
async function hasPerm(req, key) {
  return userHasPerm(await getLoginUser(req), key);
}
function permLabel(key) { return (PERM_DEFS[key] || {}).label || key; }
// 确保 users 初始化：首次启动 seed 一个 admin 用户（沿用原 admin 密码或默认 admin123）
async function ensureUsers() {
  const users = kvget('users', []);
  if (users && users.length) return;
  const admin = kvget('admin', null);
  const ph = (admin && admin.password_hash) || await sha256('admin123' + PEPPER);
  const seed = [{ id: 'u-admin', username: 'admin', name: '管理员', password_hash: ph, role: 'admin', active: true, created_at: new Date().toISOString() }];
  // 开源演示账号（演示数据 sample.kv.json 中 users 为空时自动创建）
  seed.push({ id: 'u-demo', username: 'demo-user', name: '演示用户', password_hash: await sha256('demo123' + PEPPER), role: 'user', active: true, created_at: new Date().toISOString(), dept: '演示科室', perms: { env_edit: 1 } });
  kvset('users', seed);
}

// ===================== 业务助手 =====================
const allDevices = () => kvget('devices', []);
const allTemplates = () => kvget('templates', []);
const allSigners = () => kvget('signers', []);
// 科室清单（后台维护）：房间与用户都从这里选。默认空数组，老库无 depts 键时不报错
const allDepts = () => kvget('depts', []);
const allInspections = () => kvget('inspections', []);
const allAbnormal = () => kvget('abnormalRecords', []);

// ---------- 独立检查项目 ----------
const allPrograms = () => kvget('programs', []);
const allCheckRecords = () => kvget('checkRecords', []);
// 设备参与哪些独立检查项目。刻意**不走** template_id：一台设备同时有自己的「常规点检」
// （挂在 PK-JC-QR-032 之类的点检模板上）和「专项检查」（如冲击机摩擦风阻、显微镜维护），
// 两者互不占用、各成一张表 —— 这正是「只是恰好放在同一个房间」的含义。
const programsOfDevice = (devId) => allPrograms().filter(p => (p.device_ids || []).indexOf(devId) >= 0);

// ---------- 检查任务（设备 × 检查表）----------
// 一台设备可能同时要跑两张表：① 自身点检模板（device，如冲击机的日常点检）
// ② 参与的独立检查项目（program，如冲击机的「摩擦和风阻损耗」、显微镜维护记录）。
// 「设备状态」大屏按任务铺卡片而不是按设备 —— 所以冲击机会出现 2 张卡、
// 显微镜（旧点检模板已清理）出现 1 张卡。两边都共用这里的状态判定，口径才一致。
function deviceJobs(dev) {
  const jobs = [];
  if (dev && dev.template_id) {
    const t = allTemplates().find(x => x.id === dev.template_id);
    if (t) jobs.push({ kind: 'device', id: t.id, name: t.equip_name || t.key || '设备点检' });
  }
  programsOfDevice(dev ? dev.id : '').forEach(p =>
    jobs.push({ kind: 'program', id: p.id, name: p.name || '专项检查', row_unit: p.row_unit || 'day' }));
  return jobs;
}
// 某天所在那一周的周一（周检项目的行键 = 周一那天的「日号」）
function weekKeyOf(dateStr) {
  const d = new Date(String(dateStr) + 'T00:00:00');
  if (isNaN(d.getTime())) return '';
  const dow = (d.getDay() + 6) % 7;      // 周一 = 0
  d.setDate(d.getDate() - dow);
  return String(d.getDate());
}
// 取独立检查项目在 dateStr 这天的行内容（week 型 → 回落到当周周一；跨月自然取不到 = 未检）
function progRowOf(prog, rec, dateStr) {
  if (!rec || !rec.rows || !dateStr) return null;
  if (String(prog.row_unit || 'day') === 'week') return rec.rows[weekKeyOf(dateStr)] || null;
  return rec.rows[String(parseInt(String(dateStr).slice(8, 10), 10))] || null;
}
// 项目行里的电子签名（大屏卡片上显示「谁签的」）
function progRowSig(row) {
  const out = { name: '', image: null };
  for (const k in (row || {})) {
    const v = row[k];
    if (v && typeof v === 'object' && v.image) { out.name = v.name || ''; out.image = v.image; break; }
  }
  return out;
}
// 项目行状态：任一「结论 / 检查情况」为异常 → ng；有实质内容 → ok；空行 → none。
// select 列的默认下拉值不算「已填」，否则周检表会永远显示成"已完成"。
function jobStatusFromRow(prog, row) {
  if (!row) return 'none';
  let has = false, ng = false;
  for (const c of (prog.columns || [])) {
    const v = row[c.key];
    if (v == null || v === '') continue;
    if (c.type === 'select') continue;
    if (c.type === 'sign') { if (v && v.image) has = true; continue; }
    has = true;
    if (c.type === 'conclusion' && v === 'abnormal') ng = true;
    if (c.type === 'choice' && v === '异常') ng = true;
  }
  return !has ? 'none' : (ng ? 'ng' : 'ok');
}

async function deviceItems(dev) {
  if (!dev || !dev.template_id) return [];
  const tpls = allTemplates();
  const t = tpls.find(t => t.id === dev.template_id);
  return t ? (t.items || []) : [];
}
// 请求体上限（字符数）。签名图的 base64 是主要体量来源，20M 对正常使用足够宽松。
const BODY_LIMIT = 64e6;   // 64MB：整份数据备份导入（如含大量签名图的 kv 可达 20~30MB）需要更大上限
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
// ---- 点检频率（v1.17.0）：决定「整月一键点检」怎么铺开 ----
// 频率写在模板的 items[].frequency 里（后台「点检模板」可编辑），常见取值：
//   「每日」「每天」  → 每个工作日都要点检（现状行为）
//   「每周」           → 周检：只在检查日（固定周一）点检，其余日期不产生记录
//   「每月」           → 月检：整月只需一次（沿用既有行为，不按天铺）
//   「」空值           → 按每日处理（老模板的 items 没有 frequency 字段时不能误判）
function freqKind(f) {
  const s = String(f == null ? '' : f);
  if (!s) return 'daily';
  if (s.indexOf('月') >= 0) return 'monthly';
  if (s.indexOf('周') >= 0) return 'weekly';
  return 'daily';
}
// 整台设备的节奏：全部检查项同频才认；混频（如「每日+每周」）回退 daily，
// 保证任何老数据都不会因为新增判定而少生成记录。
function deviceFreq(items) {
  if (!items || !items.length) return 'daily';
  const kinds = items.map(it => freqKind(it.frequency));
  if (kinds.every(k => k === 'weekly')) return 'weekly';
  if (kinds.every(k => k === 'monthly')) return 'monthly';
  return 'daily';
}
// 周检检查日口径：固定周一（周检设备「每周第一天上班后 1 小时内」维护 → 遇节假日顺延由人工处理）
const WEEKLY_CHECK_DOW = 1;
function isWeeklyCheckDay(ds) {
  const [yy, mm, dd] = String(ds).split('-').map(Number);
  return new Date(yy, mm - 1, dd).getDay() === WEEKLY_CHECK_DOW;
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
// 签名免密开关（后台「系统设置」可开）。
// 开：点检页 / 温湿度页不再要求「签名人密码」，选中签名人即可落签。
// 关（默认）：签名密码是「这个字是谁签的」的凭据 —— ISO 记录通常要求保留，
//             所以不擅自放开，由现场按自己的管理尺度决定。
const signNoPw = () => !!kvget('signNoPw', false);

async function verifySigner(body) {
  const signer = allSigners().find(s => s.id === body.signer_id);
  if (!signer) return { error: '签名人不存在' };
  if (!signNoPw() && await sha256((body.password || '') + PEPPER) !== signer.password_hash) {
    return { error: '签名密码错误', status: 401 };
  }
  return { signer };
}
// 「检查表」专用严格校验：独立检查项目（显微镜维护记录、冲击摩擦和风阻损耗检查……）里的
// 电子签名**一律要密码**，不受后台「点检 / 温湿度免密签名」开关影响 —— 免密只放开点检表与温湿度表。
// 以后新增的任何检查项目表，只要列类型是 sign，就自动走这条严格通道。
async function verifySignerStrict(body) {
  const signer = allSigners().find(s => s.id === body.signer_id);
  if (!signer) return { error: '签名人不存在' };
  if (!signer.password_hash) return { error: '该签名人还没有设置签名密码，请先在后台「签名人员」里补上' };
  if (await sha256(String(body.password == null ? '' : body.password) + PEPPER) !== signer.password_hash) {
    return { error: '签名密码错误', status: 401 };
  }
  return { signer };
}
// 密码校验通过后发一张短时授权票（内存）。保存时凭票放行 ——
// 关键点：光靠前端弹个密码框是拦不住的（改一下请求就把签名塞进去了），
// 所以「校验点」和「落库点」必须各验一次，中间用票串起来。
const sigGrants = new Map();          // token → { signer_id, exp }
const SIG_GRANT_TTL = 60 * 60 * 1000; // 一张票管 1 小时，够填完整张月表
function issueSigGrant(signerId) {
  const now = Date.now();
  for (const [k, v] of sigGrants) if (!v || v.exp < now) sigGrants.delete(k);  // 顺手清过期，避免无界增长
  const token = crypto.randomBytes(16).toString('hex');
  sigGrants.set(token, { signer_id: signerId, exp: now + SIG_GRANT_TTL });
  return token;
}
function checkSigGrant(token, signerId) {
  const g = token ? sigGrants.get(String(token)) : null;
  if (!g) return false;
  if (g.exp < Date.now()) { sigGrants.delete(String(token)); return false; }
  return g.signer_id === signerId;
}
// 与库里已存的同位置签名完全相同 → 视为「早就签过的」，重存时无需再验票
function sameSign(prev, cur) {
  return !!(prev && cur && prev.signer_id === cur.signer_id && prev.image === cur.image);
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
  return sendJson(ctx.res, {
    ok: !!u, username: u ? u.username : '', name: u ? u.name : '', role: u ? u.role : '', dept: u ? (u.dept || '') : '',
    perms: u ? (u.perms || null) : null,   // 未配置过权限的用户为 null —— 前端按默认表（PERM_DEFAULTS）推有效值
  });
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
      logI('AUTH', '登录成功: ' + user.username + (user.role === 'admin' ? '（管理员）' : ''));
      return sendJson(ctx.res, { ok: true, username: user.username, name: user.name, role: user.role },
        200, { 'Set-Cookie': adminCookie(token) });
    }
  }
  logW('AUTH', '登录失败: ' + (b.username || '?') + '（账号不存在/密码错/已停用）');
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
  return sendJson(ctx.res, users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: !!u.active, dept: u.dept || '', perms: u.perms || null })));
}
// POST /api/users —— 新增用户
async function handleCreateUser(ctx) {
  const b = ctx.body;
  const username = (b.username || '').trim();
  if (!username || !b.password) return fail(ctx.res, '用户名与密码必填');
  if (!validUsername(username)) return fail(ctx.res, '用户名需 2-32 位，可中文/英文/数字/下划线/点/@/连字符，不能含空格');
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
    if (!validUsername(u2)) return fail(ctx.res, '用户名需 2-32 位，可中文/英文/数字/下划线/点/@/连字符，不能含空格');
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
  // 功能权限（v1.9.0）：只接受已知键、值钳到 0/1；传 null 清空 = 回到默认
  if (b.perms !== undefined) {
    if (b.perms === null) delete u.perms;
    else {
      const clean = {};
      for (const k of PERM_KEYS) if (b.perms && b.perms[k] !== undefined) clean[k] = b.perms[k] ? 1 : 0;
      if (Object.keys(clean).length) u.perms = clean; else delete u.perms;
    }
  }
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
    dept: s.dept || '',   // 前端按登录人科室过滤签名人时要用；缺这个字段会让过滤把所有签名人都滤掉
    signature_image: s.signature_image || null,
    signature_image_v: s.signature_image_v || null,
    sig_dir: normSigDir(s.sig_dir) })));
}
// GET /api/signers —— 签名人管理列表（仅管理员）
async function handleListSigners(ctx) {
  const list = allSigners();
  return sendJson(ctx.res, list.map(s => ({ id: s.id, name: s.name, active: !!s.active, dept: s.dept || '',
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
    dept: String(b.dept || '').trim(),
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
  if ('dept' in b) s.dept = String(b.dept || '').trim();
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
  // 新建模板需签名人 + 签名密码授权（全局免密开关 signNoPw 开启时仅校验签名人身份）
  const sig = await verifySigner(b);
  if (sig.error) return fail(ctx.res, sig.error, sig.error === '签名密码错误' ? 401 : 400);
  const tpls = allTemplates();
  const t = { id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '', source_file: '', items: [], uploaded_by: sig.signer.id };
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
  // 导入模板需签名人 + 签名密码授权（全局免密开关 signNoPw 开启时仅校验签名人身份）
  const sig = await verifySigner(b);
  if (sig.error) return fail(ctx.res, sig.error, sig.error === '签名密码错误' ? 401 : 400);
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
    exist.uploaded_by = sig.signer.id;
    kvset('templates', tpls);
    return sendJson(ctx.res, { ok: true, updated: true, id: exist.id, key: exist.key, itemsCount: parsed.length });
  }
  const t = {
    id: uuid(), key: b.key, equip_name: b.equip_name, model: b.model || '',
    source_file: b.source_file || '', items: buildItems(), uploaded_by: sig.signer.id
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
  // name = 按名字（签名人姓名 或 设备名称，模糊匹配）；signer 保留为旧参数名，兼容老书签/脚本
  const name = (q.get('name') || q.get('signer') || '').trim();
  const room = (q.get('room') || '').trim();
  const devices = allDevices();
  const dmap = {}; devices.forEach(d => dmap[d.id] = d);
  let list = allInspections();
  if (devId) list = list.filter(r => { const d = dmap[r.device_id]; return d && (String(d.no) === devId || String(d.id) === devId); });
  if (date) list = list.filter(r => r.inspect_date === date);
  // 按名字：同时匹配「签名人姓名」与「设备名称」（任一命中即可），避免用户还要先想清"名字"指谁
  if (name) list = list.filter(r => {
    const d = dmap[r.device_id] || {};
    const k = name.toLowerCase();
    return (r.signed_by || '').toLowerCase().includes(k) || (d.name || '').toLowerCase().includes(k);
  });
  if (room) list = list.filter(r => { const d = dmap[r.device_id]; return d && (d.location || '') === room; });
  list.sort((a, b) => (a.inspect_date < b.inspect_date ? 1 : -1));
  return sendJson(ctx.res, list.map(r => {
    const d = dmap[r.device_id] || {};
    return { id: r.device_id + '_' + r.inspect_date, inspect_date: r.inspect_date, no: d.no || '', name: d.name || '', room: d.location || '',
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
  let signed = 0;
  for (const d of devices) {
    const items = await deviceItems(d);
    if (!items.length) continue;   // 无点检模板的设备（专项检查走 check.html）不参与一键点检
    signed++;
    const isAbn = d.id in abnormalMap;
    // 每台设备取该日 08:00~10:00 的随机时刻（当天不超当前时间），大屏体现自然时间差且无未来时间
    await upsertInspection({ device_id: d.id, inspect_date: b.date },
      { status: isAbn ? 'ng' : 'ok', signed_by: signer.name, signer_id: signer.id,
        signature_image: pickSigImage(signer), abnormal_note: isAbn ? abnormalMap[d.id] : '',
        bySn: buildBySn(items, isAbn ? 'ng' : 'ok'), signed_at: randMorningTime(b.date) });
  }
  return sendJson(ctx.res, { signed, signer: signer.name });
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
// POST /api/inspect/delete —— 删除单台设备指定日期（或整月）的点检内容与电子签名
// body: { device_id, dates:['YYYY-MM-DD', ...] }  或 { device_id, month:'YYYY-MM', dates? }
// 说明：这条路由是 adminOnly + perm:'inspect_batch'（管理员恒放行、普通用户须被授权），
//       因为删除不可恢复。签名图和 bySn 与记录同为一体，删记录即删签名 —— 这正是
//       此前「点检页面的签名删不掉」缺的那一步（原来只把格子清空，服务端不删记录）。
async function handleInspectDelete(ctx) {
  const b = ctx.body || {};
  const dev = allDevices().find(d => d.id === b.device_id);
  if (!dev) return fail(ctx.res, '设备不存在');
  let dates = Array.isArray(b.dates) ? b.dates.map(String).filter(Boolean) : [];
  if (!dates.length && b.month) {
    const [yy, mm] = String(b.month).split('-');
    if (!/^\d{4}$/.test(yy) || !/^\d{2}$/.test(mm)) return fail(ctx.res, '月份格式应为 YYYY-MM');
    const dim = new Date(+yy, +mm, 0).getDate();
    for (let i = 1; i <= dim; i++) dates.push(`${yy}-${mm}-${String(i).padStart(2, '0')}`);
  }
  if (!dates.length) return fail(ctx.res, '未指定要删除的日期');
  const drop = new Set(dates);
  const list = allInspections();
  const before = list.length;
  const remaining = list.filter(r => !(r.device_id === b.device_id && drop.has(String(r.inspect_date))));
  const deleted = before - remaining.length;
  let abnDeleted = 0;
  if (deleted) {
    kvset('inspections', remaining);
    // 同期异常明细一并清掉：记录没了、异常还在会让打印页出现"孤儿"异常行
    const abnAll = allAbnormal();
    const abnLeft = abnAll.filter(r => !(r.device_id === b.device_id && drop.has(String(r.date || ''))));
    abnDeleted = abnAll.length - abnLeft.length;
    if (abnDeleted) kvset('abnormalRecords', abnLeft);
    const scope = (dates.length === 1) ? dates[0] : (b.month ? b.month + ' 整月' : dates.length + ' 天');
    logI('点检', `删除点检记录：${dev.no} ${dev.name || ''} · ${scope} → 删除 ${deleted} 条（含电子签名）`);
  }
  return sendJson(ctx.res, { ok: true, deleted, abn_deleted: abnDeleted,
    device: dev.no + ' ' + (dev.name || ''), dates: dates.length });
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
  // 按科室随机分派（可选）：设备所在房间 → 房间归属科室 → 该科室「启用且有签名图」的签名人池，
  // 每天每房间随机选一人签名（贴近"当天谁当班谁点检"）。所选 signer_id + 密码作为授权人；
  // 房间未设科室 / 科室下无可用签名人时，回退为授权人（fallback 计数返回给前端提示）。
  const randomDept = !!b.random_dept;
  const days = monthDays(month, endDay);
  const roomAssign = {};
  if (randomDept) {
    const roomDept = {};
    kvget('rooms', []).forEach(r => { roomDept[r.name] = r.dept || ''; });
    const signers = allSigners();
    for (const room of [...new Set(devices.map(d => String(d.location || '').trim()))]) {
      const dept = roomDept[room] || '';
      const pool = dept ? signers.filter(s => s.active !== false && s.dept === dept && pickSigImage(s)) : [];
      const byDay = {};
      if (pool.length) for (const dd of days) byDay[dd] = pool[Math.floor(Math.random() * pool.length)];
      roomAssign[room] = { dept, pool, byDay };
    }
  }
  let created = 0, updated = 0, fallback = 0;
  let weeklyDevices = 0, dailyDevices = 0, weeklyDays = 0;
  const weeklyList = [];
  for (const d of devices) {
    const items = await deviceItems(d);
    const kind = deviceFreq(items);
    // 周检设备（模板里全部检查项都是「每周」，如洗眼器 / 金相显微镜）只在检查日生成记录，
    // 不再每天铺一条 —— 非检查日由界面/打印显示为「/」，与线下表格口径一致。
    // 其余（每日 / 每月 / 混频 / 无模板）沿用原行为，避免影响已有数据。
    const isWeekly = (kind === 'weekly');
    const ddays = isWeekly ? days.filter(isWeeklyCheckDay) : days;
    if (isWeekly) { weeklyDevices++; weeklyDays = ddays.length; weeklyList.push(d.no + ' ' + (d.name || '')); }
    else dailyDevices++;
    if (!ddays.length) continue;   // 月内还没有出现检查日（如 1 日就截止）→ 跳过该设备
    const bySn = buildBySn(items, 'ok');
    const ra = randomDept ? roomAssign[String(d.location || '').trim()] : null;
    for (const dd of ddays) {
      // 每天一条记录取该日 08:00~10:00 的随机时刻（当天不超当前时间），各天时间自然分散且无未来时间
      const who = (ra && ra.byDay[dd]) || signer;
      if (!(ra && ra.byDay[dd])) fallback++;
      const r = await upsertInspection({ device_id: d.id, inspect_date: dd },
        { status: 'ok', signed_by: who.name, signer_id: who.id, signature_image: pickSigImage(who),
          abnormal_note: '', bySn, signed_at: randMorningTime(dd) });
      if (r === 'created') created++; else updated++;
    }
  }
  const assignments = randomDept ? Object.entries(roomAssign).map(([room, v]) => ({
    room, dept: v.dept, people: [...new Set(v.pool.map(s => s.name))], covered: Object.keys(v.byDay).length })) : null;
  if (weeklyDevices) {
    logI('点检', `整月一键点检：${month} 1~${endDay} 日，${devices.length} 台（其中周检 ${weeklyDevices} 台只在周一(共 ${weeklyDays} 天)生成记录：${weeklyList.slice(0, 8).join('、')}${weeklyList.length > 8 ? ' 等' : ''}）`);
  }
  return sendJson(ctx.res, { devices: devices.length, days: endDay, signer: signer.name, created, updated, room: b.room || '',
    random: randomDept, fallback, assignments,
    // 周检识别结果（前端据此提示"周检设备只点检查日"）
    weekly_devices: weeklyDevices, weekly_days: weeklyDays, daily_devices: dailyDevices, weekly_list: weeklyList });
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
// ---------- 独立检查项目：接口 ----------
// GET /api/programs —— 项目清单（含参与设备、所在房间，供入口与选择器使用）
async function handleListPrograms(ctx) {
  const dmap = {}; allDevices().forEach(d => dmap[d.id] = d);
  const out = allPrograms().map(p => {
    const devs = (p.device_ids || []).map(id => dmap[id]).filter(Boolean);
    return Object.assign({}, p, {
      device_count: devs.length,
      rooms: [...new Set(devs.map(d => String(d.location || '').trim()).filter(Boolean))],
      devices: devs.map(d => ({ id: d.id, no: d.no, name: d.name, model: d.model, location: d.location || '' }))
    });
  });
  return sendJson(ctx.res, out);
}
// GET /api/settings —— 前端需要的少量开关（点检 / 温湿度页据此决定是否显示「签名密码」框）。
// 公开可读：它只影响 UI 是否显示输入框，真正的放行判定仍在服务端 verifySigner 里。
async function handleGetSettings(ctx) {
  return sendJson(ctx.res, { signNoPw: signNoPw() });
}
// PUT /api/admin/settings —— 管理员改开关
async function handlePutSettings(ctx) {
  const b = ctx.body || {};
  if (typeof b.signNoPw === 'boolean') {
    kvset('signNoPw', b.signNoPw);
    logI('设置', '签名免密 = ' + (b.signNoPw ? '开（点检页不再要求签名密码）' : '关（恢复密码校验）'));
  }
  return sendJson(ctx.res, { ok: true, signNoPw: signNoPw() });
}
// PUT /api/programs/:id —— 维护项目（本项目用于设置参与设备 device_ids 与表头文字）
async function handleUpdateProgram(ctx) {
  const b = ctx.body;
  const list = allPrograms();
  const p = list.find(x => x.id === ctx.params.id);
  if (!p) return fail(ctx.res, '项目不存在');
  if (Array.isArray(b.device_ids)) {
    const valid = new Set(allDevices().map(d => d.id));
    p.device_ids = b.device_ids.filter(id => valid.has(id));
    // 手工改过参与设备 → 关掉「按模板 key 自动关联」，否则下次启动会被 auto_tpl_keys 覆盖回去
    p.auto_link = false;
  }
  ['name', 'title', 'title_en', 'form_code', 'form_rev', 'note', 'row_unit', 'side_title', 'side_title_en'].forEach(k => {
    if (typeof b[k] === 'string') p[k] = b[k].trim();
  });
  if (['day', 'week'].indexOf(p.row_unit) < 0) p.row_unit = 'day';
  // 右侧说明栏逐条（空行丢弃）
  if (Array.isArray(b.side_items)) {
    p.side_items = b.side_items.map(x => String(x == null ? '' : x)).filter(x => x.trim());
  }
  // 数据列：key 只留字母数字下划线横杠（要进 dataset / 行对象键），类型白名单，span 限 1~6
  if (Array.isArray(b.columns)) {
    const COLTYPES = ['text', 'number', 'sign', 'conclusion', 'choice', 'select'];
    const cols = [];
    b.columns.forEach(c => {
      if (!c || typeof c !== 'object') return;
      const key = String(c.key || '').trim().replace(/[^\w-]/g, '');
      if (!key) return;
      const o = { key, type: COLTYPES.indexOf(c.type) >= 0 ? c.type : 'text' };
      ['label', 'label_en', 'def'].forEach(k => { if (typeof c[k] === 'string' && c[k] !== '') o[k] = c[k]; });
      if (o.type === 'select') o.opts = (Array.isArray(c.opts) ? c.opts : []).map(x => String(x)).filter(x => x !== '');
      if (+c.span > 1) o.span = Math.min(6, Math.round(+c.span));
      cols.push(o);
    });
    if (cols.length) p.columns = cols;
  }
  // 底部判定标准：{std, vals:[…]}，若 vals 声明了宽度（vals 长度 > 3 时按声明铺，否则沿用 3 列语义）
  if (Array.isArray(b.criteria)) {
    p.criteria = b.criteria.map(c => ({
      std: String((c && c.std) || '').trim(),
      vals: (Array.isArray(c && c.vals) ? c.vals : []).map(v => String(v == null ? '' : v)),
    })).filter(c => c.std || c.vals.some(v => v));
  }
  p.updated_at = new Date().toISOString();
  kvset('programs', list);
  return sendJson(ctx.res, { ok: true, program: p });
}
// GET /api/check-records?program_id=&device_id=&ym= —— 独立检查记录（登录可见）
async function handleListCheckRecords(ctx) {
  const pid = (ctx.query.get('program_id') || '').trim();
  const did = (ctx.query.get('device_id') || '').trim();
  const ym = (ctx.query.get('ym') || '').trim();
  let list = allCheckRecords();
  if (pid) list = list.filter(r => r.program_id === pid);
  if (did) list = list.filter(r => r.device_id === did);
  if (ym) list = list.filter(r => r.ym === ym);
  return sendJson(ctx.res, list);
}
// POST /api/check-records/sign —— 检查表电子签名：验签名人密码 → 发签名图 + 授权票
async function handleSignCheckCell(ctx) {
  const b = ctx.body || {};
  if (!b.signer_id) return fail(ctx.res, '请选择签名人');
  const { signer, error, status } = await verifySignerStrict(b);
  if (error) return fail(ctx.res, error, status || 400);
  return sendJson(ctx.res, { ok: true, signer_id: signer.id, name: signer.name,
    signature_image: pickSigImage(signer),
    signature_image_v: signer.signature_image_v || null,
    token: issueSigGrant(signer.id) });
}
// POST /api/check-records —— 保存某项目 + 某设备 + 某月的检查表（整份替换该组合的行）
async function handleSaveCheckRecord(ctx) {
  const b = ctx.body;
  const me = await getLoginUser(ctx.req);
  if (!me) return fail(ctx.res, '未登录', 401);
  const pid = String(b.program_id || '').trim();
  const did = String(b.device_id || '').trim();
  const ym = String(b.ym || '').trim();
  if (!pid || !did || !/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '参数不完整');
  const prog = allPrograms().find(p => p.id === pid);
  if (!prog) return fail(ctx.res, '检查项目不存在');
  if ((prog.device_ids || []).indexOf(did) < 0) return fail(ctx.res, '该设备不在本项目范围内');
  if (!allDevices().some(d => d.id === did)) return fail(ctx.res, '设备不存在');
  if (ym > currentMonthStr()) return fail(ctx.res, '不能填写未来月份');
  const rows = (b.rows && typeof b.rows === 'object' && !Array.isArray(b.rows)) ? b.rows : {};
  // 未来日期不允许填写（与点检 / 温湿度口径一致）
  const clean = {};
  for (const k in rows) {
    const day = parseInt(k, 10);
    if (!day || day < 1 || day > 31) continue;
    const dd = ym + '-' + String(day).padStart(2, '0');
    if (isFutureDate(dd)) continue;
    clean[k] = rows[k];
  }
  const list = allCheckRecords();
  const idx = list.findIndex(r => r.program_id === pid && r.device_id === did && r.ym === ym);
  // 签名格落库前的第二道闸：新签 / 改动过的签名必须带有效授权票
  // （票由 /api/check-records/sign 在密码校验通过后签发）。
  // 与库里完全一样的旧签名直接放行，避免「打开旧表改一个数字再保存」被自己的签名卡住。
  const signCols = (prog.columns || []).filter(c => c && c.type === 'sign').map(c => c.key);
  if (signCols.length) {
    const prevRows = idx >= 0 ? (list[idx].rows || {}) : {};
    for (const day in clean) {
      const cur0 = clean[day] || {};
      for (const ck2 of signCols) {
        const cur = cur0[ck2];
        if (!cur || typeof cur !== 'object' || !cur.image) continue;
        const prev = prevRows[day] ? prevRows[day][ck2] : null;
        if (sameSign(prev, cur)) continue;
        if (!checkSigGrant(cur.token, cur.signer_id)) {
          return fail(ctx.res, '签名未通过密码验证（请重新点击签名格，输入签名人密码后再保存）', 401);
        }
      }
    }
    // 票不落库：只在内存里当一次性通行证用
    for (const day in clean) {
      const cur0 = clean[day] || {};
      for (const ck2 of signCols) {
        if (cur0[ck2] && typeof cur0[ck2] === 'object') delete cur0[ck2].token;
      }
    }
  }
  const n = Object.keys(clean).length;
  // 空表不建档：整份清空后不再保留空壳记录（否则「清空后保存」会复活，与温湿度表同一坑）
  if (n === 0) {
    if (idx >= 0) { list.splice(idx, 1); kvset('checkRecords', list); }
    return sendJson(ctx.res, { ok: true, days: 0 });
  }
  let rec;
  if (idx >= 0) rec = list[idx];
  else {
    rec = { id: 'chk-' + uuid(), program_id: pid, device_id: did, ym, rows: {}, created_at: new Date().toISOString() };
    list.push(rec);
  }
  rec.rows = clean;
  rec.updated_at = new Date().toISOString();
  rec.updated_by = me.username || '';
  kvset('checkRecords', list);
  return sendJson(ctx.res, { ok: true, days: n });
}

// POST /api/admin/check-month —— 专项检查表「整月一键生成（复制上一次点检的数据）」
// 专项检查表「整月一键生成（复制上次数据）」
// 用途：独立检查项目（夏比冲击摩擦和风阻损耗 / 显微镜维护记录……）的月表，每月内容与上月高度一致，
//       一键把「上一次点检」的数据复制到目标月份，人再改差异，省掉整月重敲。
//
// 口径（都按项目既有铁律来，别改歪）：
//   · 「上一次点检」= 同项目 + 同设备 + ym 严格小于目标月份里、ym 最大的那条记录
//     （跨月查找 → 中间某个月没做也不影响，取最近的那次）
//   · 行映射：row_unit='day'  按「日号相同」对（上月 20 号 → 本月 20 号）
//             row_unit='week' 按「第几个周一」对（上月第 1 个周一 → 本月第 1 个周一）
//     —— 不能一律按序号对：day 表如果上月只填了零星几天，按序号对会把 20 号的数据挪到 3 号。
//   · **签名列（type='sign'）绝不照抄**：检查表的签名是「这个字是谁签的」的凭据，
//     照抄等于把别人的签名复制一整个月。传了 signer_id + password（走 verifySignerStrict）
//     才用该签名人重新落签，否则签名格留空，由检查表页面逐格补签。
//   · **只补空格**：目标月已有内容的日期一律不动；overwrite=true 才整份替换。
//   · 未来日期不生成；空表不建档；不能生成未来月份。
//   · 整份替换时若算出来是空的，宁可不动也不能把已有记录清空（防呆）。
function checkRowKeys(unit, month, endDay) {
  const [yy, mm] = month.split('-').map(Number);
  const dim = new Date(yy, mm, 0).getDate();
  const last = Math.min(dim, endDay);
  const out = [];
  for (let d = 1; d <= last; d++) {
    const ds = month + '-' + String(d).padStart(2, '0');
    if (unit === 'week' && !isWeeklyCheckDay(ds)) continue;   // 周检表只有周一行
    out.push(String(d));
  }
  return out;
}
// 逐单元格判断「这一行到底有没有内容」——空行不落库，与 check.html 的保存口径一致
function checkRowHasValue(row) {
  if (!row || typeof row !== 'object') return false;
  for (const k in row) {
    const v = row[k];
    if (v == null) continue;
    if (typeof v === 'string') { if (v.trim()) return true; continue; }
    if (typeof v === 'object') { if (v.image || v.signer_id) return true; continue; }
    return true;
  }
  return false;
}

async function handleAdminCheckMonth(ctx) {
  const b = ctx.body || {};
  const month = String(b.month || '').trim();
  if (!/^\d{4}-\d{2}$/.test(month)) return fail(ctx.res, '月份格式应为 YYYY-MM');
  if (month > currentMonthStr()) return fail(ctx.res, '不能生成未来月份的检查表');
  const { endDay, error: endErr } = resolveEndDay(month, b.end_day);
  if (endErr) return fail(ctx.res, endErr);

  // 签名人（可选）：只有传了才落签；检查表签名一律要密码，走严格校验
  let signer = null;
  if (b.signer_id) {
    const vs = await verifySignerStrict(b);
    if (vs.error) return fail(ctx.res, vs.error, vs.status || 400);
    signer = vs.signer;
    if (!pickSigImage(signer)) return fail(ctx.res, '该签名人还没有签名图，请先在后台「签名人员」里上传');
  }

  const dryRun = !!b.dry_run;
  const overwrite = !!b.overwrite;
  const progs = allPrograms().filter(p => (b.program_id ? p.id === b.program_id : true));
  if (!progs.length) return fail(ctx.res, b.program_id ? '专项检查表不存在' : '还没有配置任何专项检查表');
  const devs = allDevices();
  // ⚠️ dry_run 必须「只看不写」：allCheckRecords() 返回的是内存里的活引用，
  //    直接 push / 改元素会污染实时数据——就算不调 kvset，后续任何一次 scheduleSave
  //    也会把被改过的数组刷进磁盘，预览就变成了真写库。预览一律走分离副本。
  const recs = dryRun ? allCheckRecords().map(r => Object.assign({}, r)) : allCheckRecords();

  const results = [];
  const skipped = [];
  let createdN = 0, updatedN = 0, keptN = 0, rowsN = 0;

  for (const p of progs) {
    let pdevs = devs.filter(d => (p.device_ids || []).indexOf(d.id) >= 0);
    if (b.device_id) pdevs = pdevs.filter(d => d.id === b.device_id);
    else if (b.room) pdevs = pdevs.filter(d => (d.location || '') === b.room);
    if (!pdevs.length) {
      skipped.push({ program: p.name, device: '', reason: '该项目下没有匹配的设备' });
      continue;
    }
    const keys = checkRowKeys(p.row_unit, month, endDay);
    if (!keys.length) {
      skipped.push({ program: p.name, device: '', reason: '目标月份里没有可生成的日期（周检表看是否还没到周一）' });
      continue;
    }
    const cols = (p.columns || []).filter(c => c && c.key);
    const signKeys = cols.filter(c => c.type === 'sign').map(c => c.key);
    const valKeys = cols.filter(c => c.type !== 'sign').map(c => c.key);
    if (!valKeys.length && !signKeys.length) {
      skipped.push({ program: p.name, device: '', reason: '该检查表没有配数据列' });
      continue;
    }

    for (const d of pdevs) {
      const idx = recs.findIndex(r => r.program_id === p.id && r.device_id === d.id && r.ym === month);
      // 「上一次点检」：同项目同设备、目标月之前的最近一条（跨月，空月自动跳过）
      const src = recs
        .filter(r => r.program_id === p.id && r.device_id === d.id && String(r.ym) < month)
        .sort((a, x) => String(x.ym).localeCompare(String(a.ym)))[0];
      if (!src || !src.rows || !Object.keys(src.rows).length) {
        skipped.push({ program: p.name, device: d.no, reason: '没有「上一次」的记录可复制' });
        continue;
      }

      // 目标日号 → 源数据行
      const srcKeys = Object.keys(src.rows).map(Number).filter(n => !isNaN(n)).sort((a, x) => a - x);
      const srcByKey = {};
      if (p.row_unit === 'week') {
        keys.forEach((k, i) => { if (srcKeys[i] != null) srcByKey[k] = src.rows[String(srcKeys[i])]; });
      } else {
        srcKeys.forEach(sk => { if (keys.indexOf(String(sk)) >= 0) srcByKey[String(sk)] = src.rows[String(sk)]; });
      }

      const existed = idx >= 0 ? (recs[idx].rows || {}) : {};
      const next = overwrite ? {} : Object.assign({}, existed);
      let copied = 0;
      for (const k of keys) {
        if (isFutureDate(month + '-' + k.padStart(2, '0'))) continue;          // 未来日期不生成
        if (!overwrite && checkRowHasValue(existed[k])) continue;             // 只补空格
        const srow = srcByKey[k];
        if (!srow) continue;
        const row = {};
        for (const ck of valKeys) {
          const v = srow[ck];
          if (v == null) continue;
          if (typeof v === 'string') { if (!v.trim()) continue; row[ck] = v; continue; }
          if (typeof v === 'object') continue;   // 防呆：非签名列不该是对象（旧数据里可能有签名残留）
          row[ck] = v;
        }
        if (signer) for (const ck of signKeys) row[ck] = { signer_id: signer.id, name: signer.name, image: pickSigImage(signer) };
        if (Object.keys(row).length) { next[k] = row; copied++; }
      }

      // 防呆：整份替换却算出空结果 → 绝不能把已有记录清空，保持不动
      if (!Object.keys(next).length) {
        if (overwrite && Object.keys(existed).length) {
          keptN++;
          results.push({ program: p.name, program_id: p.id, device: d.no, device_id: d.id,
            action: 'kept', source_ym: src.ym, rows: Object.keys(existed).length, copied: 0,
            note: '复制结果为空，已保留原有记录不动' });
        } else {
          skipped.push({ program: p.name, device: d.no, reason: '上次记录里没有与目标月份对得上的日期' });
        }
        continue;
      }

      if (idx >= 0) {
        recs[idx].rows = next;
        recs[idx].updated_at = new Date().toISOString();
        recs[idx].updated_by = '整月一键生成（复制 ' + src.ym + '）';
        updatedN++;
      } else {
        recs.push({ id: 'chk-' + uuid(), program_id: p.id, device_id: d.id, ym: month, rows: next,
          created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
          updated_by: '整月一键生成（复制 ' + src.ym + '）' });
        createdN++;
      }
      rowsN += copied;
      results.push({ program: p.name, program_id: p.id, device: d.no, device_id: d.id,
        action: idx >= 0 ? 'updated' : 'created', source_ym: src.ym, rows: Object.keys(next).length, copied });
    }
  }

  if (!dryRun) {
    kvset('checkRecords', recs);
    logI('检查项目', `专项整月一键生成：${month} 1~${endDay} 日，新建 ${createdN} 份 / 更新 ${updatedN} 份，复制 ${rowsN} 行`
      + `，跳过 ${skipped.length} 项${signer ? '，签名人 ' + signer.name : '（未落签，签名格留空）'}`);
  }
  return sendJson(ctx.res, {
    month, end_day: endDay, dry_run: dryRun, overwrite, signer: signer ? signer.name : '',
    created: createdN, updated: updatedN, kept: keptN, rows: rowsN,
    programs: progs.length, results, skipped,
  });
}

// GET /api/dashboard —— 大屏数据
async function handleDashboard(ctx) {
  const q = ctx.query;
  const date = q.get('date');
  const loc = q.get('location') || '';
  const grp = (q.get('group') || '').trim();
  // 过滤维度（互斥，group 优先）：
  //   group=持久蠕变 → 只保留「后台房间管理里归到该分组」的房间下的设备（如 持久蠕变室1+室2）
  //   location=持久蠕变室1 → 只保留该房间设备
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
  // ===== 检查任务卡片：每张「检查表」一张卡（不是每台设备一张）=====
  const tplmap = {}; allTemplates().forEach(t => tplmap[t.id] = t);
  const progs = allPrograms(), recs = allCheckRecords();
  const jobs = []; let jobDone = 0, jobNg = 0;
  const progRecent = [];        // 项目行顺带并进「最近点检记录」，否则做了专项检查的房间看着像没干活
  devices.forEach(d => {
    const t = d.template_id ? tplmap[d.template_id] : null;
    if (t) {
      const r = todayMap[d.id];
      const st = r ? r.status : 'none';
      if (st !== 'none') jobDone++;
      if (st === 'ng') jobNg++;
      jobs.push({ device_id: d.id, no: d.no, name: d.name, model: d.model || '', location: d.location || '',
        job_kind: 'device', job_id: t.id, job_name: '设备点检', tpl_key: t.key || '',
        status: st, signed_by: r ? (r.signed_by || '') : '', signature_image: r ? (r.signature_image || null) : null,
        signed_at: r ? (r.signed_at || '') : '' });
    }
    programsOfDevice(d.id).forEach(p => {
      const rec = recs.find(x => x.program_id === p.id && x.device_id === d.id && x.ym === month);
      const row = progRowOf(p, rec, date);
      const st = jobStatusFromRow(p, row);
      if (st !== 'none') jobDone++;
      if (st === 'ng') jobNg++;
      const sg = progRowSig(row);
      jobs.push({ device_id: d.id, no: d.no, name: d.name, model: d.model || '', location: d.location || '',
        job_kind: 'program', job_id: p.id, job_name: p.name || '专项检查', tpl_key: '',
        row_unit: p.row_unit || 'day', status: st, signed_by: sg.name, signature_image: sg.image,
        signed_at: (row && rec) ? (rec.updated_at || '') : '' });
      if (row) progRecent.push({ no: d.no, name: d.name + ' · ' + (p.name || ''), status: st,
        signer_name: sg.name, signature_image: sg.image, abnormal_note: '',
        signed_at: rec ? (rec.updated_at || '') : '' });
    });
  });
  const recent = insp.filter(r => date && r.inspect_date === date && dmap[r.device_id])
    .map(r => { const d = dmap[r.device_id] || {};
      return { no: d.no || '', name: d.name || '', status: r.status, signer_name: r.signed_by || '',
        signature_image: r.signature_image || null, abnormal_note: r.abnormal_note || '', signed_at: r.signed_at }; })
    .concat(progRecent)
    .sort((a, b) => (String(a.signed_at) < String(b.signed_at) ? 1 : -1))
    .slice(0, 12);
  return sendJson(ctx.res, { total: devices.length, today_inspected: jobDone,
    today_abnormal: jobNg, month_inspected: monthCount, grid, recent,
    job_total: jobs.length, job_done: jobDone, job_abnormal: jobNg, jobs });
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
    thermo_apparatus: r.thermo_apparatus || '', thermo_equipment: r.thermo_equipment || '', thermo_requirement: r.thermo_requirement || '',
    env_range: r.env_range || null   // 每房间专属随机范围（v1.9.0，null = 未设置）
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
  // 分组只影响展示：同组房间（如 持久蠕变室1/2）在大屏与下拉里合并到组名之下，房间本身仍各自独立
  if (b.group != null) r.group = String(b.group).trim();
  // 科室：该房间归属的科室（留空 = 不限定，全员可见）
  if (b.dept != null) r.dept = String(b.dept).trim();
  // 温湿度监测配置（管理员在后台「房间管理」维护，新建月度记录时自动带出）
  if (b.thermo_apparatus != null) r.thermo_apparatus = String(b.thermo_apparatus);
  if (b.thermo_equipment != null) r.thermo_equipment = String(b.thermo_equipment);
  if (b.thermo_requirement != null) r.thermo_requirement = String(b.thermo_requirement);
  // 每房间专属「随机生成范围」（v1.9.0）：{tMin,tMax,hMin,hMax}；传 null/空对象 = 清除（回退全局范围或房间要求）
  if (b.env_range !== undefined) {
    if (!b.env_range || typeof b.env_range !== 'object') delete r.env_range;
    else {
      const er = {
        tMin: Number(b.env_range.tMin), tMax: Number(b.env_range.tMax),
        hMin: Number(b.env_range.hMin), hMax: Number(b.env_range.hMax),
      };
      const allSet = [er.tMin, er.tMax, er.hMin, er.hMax].every(Number.isFinite);
      if (!allSet) delete r.env_range;      // 四项没填全 ≈ 清除
      else {
        if (!(er.tMax > er.tMin)) return fail(ctx.res, '该房间的温度上限必须大于下限');
        if (!(er.hMax > er.hMin) || er.hMin <= 0 || er.hMax > 100) return fail(ctx.res, '该房间的湿度范围应为 0~100 且上限大于下限');
        r.env_range = er;
      }
    }
  }
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

// 温度统一保留一位小数（空值原样返回；非数字不破坏）。所有「温度写入 / 展示 / 导出」落点统一调用，保证格式一致。
function fmtTemp(v) {
  if (v === '' || v == null) return '';
  const s = String(v).trim();
  if (s === '') return '';
  const n = Number(s);
  if (!Number.isFinite(n)) return s;            // 非数字（如「—」占位）原样保留，不破坏
  return (Math.round(n * 10) / 10).toFixed(1);  // 23 → "23.0"，23.456 → "23.5"
}

// POST /api/env-records —— 新建 / 更新某房间某月记录（upsert，按 room+ym 唯一）
async function handleSaveEnvRecord(ctx) {
  // 权限：需登录且持有「温湿度表录入」（默认放开给所有登录用户，可按人收紧）
  const u = await getLoginUser(ctx.req);
  if (!u) return fail(ctx.res, '未登录或登录已失效', 401);
  if (!userHasPerm(u, 'env_edit')) return fail(ctx.res, '权限不足：温湿度录入已被管理员关闭，请联系管理员开通', 403);
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
    // 不可填写未来温湿度：未来日期的格子直接丢弃（前端同样禁填，这里做后端兜底）
    const cy = parseInt(ym.slice(0, 4), 10), cm = parseInt(ym.slice(5, 7), 10) - 1;
    const cellDate = new Date(cy, cm, day);
    const todayCut = new Date(); todayCut.setHours(0, 0, 0, 0);
    if (cellDate > todayCut) continue;
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
  // 空表不建档：新月份第一次保存时若一格数据都没有（连划线都没有），不入库。
  // 否则用户在空表上随手点一次「保存」就会生成 0 格空记录 —— 管理员删掉后下次保存又「复活」，
  // 表现就是后台「温湿度记录删除不了」。
  if (!rec && Object.keys(clean).length === 0) {
    return sendJson(ctx.res, { ok: true, id: null, created: false, empty: true, updated_at: null });
  }
  if (rec) {
    rec.cells = clean;
    rec.updated_at = new Date().toISOString();
  } else {
    rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room, ym, cells: clean, updated_at: new Date().toISOString() };
    list.push(rec);
  }
  kvset('envRecords', list);
  logI('ENV', '保存温湿记录 ' + room + '@' + ym + ' 格数=' + Object.keys(clean).length);
  evalEnvAlerts(room, ym, clean, '手动保存');
  return sendJson(ctx.res, { ok: true, id: rec.id, updated_at: rec.updated_at });
}

// GET /api/admin/logs —— 运行日志（内存环形缓冲最近 N 条，可按级别/关键字过滤）
async function handleLogsGet(ctx) {
  const level = (ctx.query.get('level') || '').toUpperCase();     // INFO/WARN/ERROR，空=全部
  const q = (ctx.query.get('q') || '').trim();
  const limit = Math.min(parseInt(ctx.query.get('limit') || '300', 10) || 300, LOG_MEM_MAX);
  let rows = logMem;
  if (['INFO', 'WARN', 'ERROR'].includes(level)) rows = rows.filter(x => x.level === level);
  if (q) rows = rows.filter(x => (x.tag + ' ' + x.msg).toLowerCase().includes(q.toLowerCase()));
  rows = rows.slice(-limit);
  // 顺带报一下落盘文件，方便要完整历史时直接去服务器拷
  let files = [];
  try { files = fs.readdirSync(LOG_DIR).filter(f => /^app-\d{4}-\d{2}-\d{2}\.log$/.test(f)).sort(); } catch (e) { /* 无日志目录 */ }
  return sendJson(ctx.res, { ok: true, total: logMem.length, returned: rows.length, files, rows });
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
// 房间「温湿度要求」的自由文本 → 数值范围。线上实测到的写法（都要认）：
//   温度：10℃-35℃ ／ 温度：15℃~25℃ (ASTM E23-25) ／ 温度要求：— （表示没有温度要求）
//   湿度：≤80%RH ／ 湿度要求：≤60% ／ 湿度：≤65%RH
// 一个房间可以列多条温度标准（冲击室 = ASTM E23-25 15~25℃ + GB/T229-2020 18~28℃），
// 按 mode 合成：union（默认，宽）取「下限最小 / 上限最大」；intersect（严）取「下限最大 / 上限最小」。
// 交集为空时退化为并集，避免把房间判成「永远超限」。
const ENV_TEMP_LINE_RE = /温度(?:要求)?\s*[：:]\s*(-?\d+(?:\.\d+)?)\s*(?:℃|°C|C)?\s*[-~—–～至]\s*(-?\d+(?:\.\d+)?)/g;
const ENV_HUM_LINE_RE = /湿度(?:要求)?\s*[：:]\s*(?:≤|<=|<|不超过)\s*(\d+(?:\.\d+)?)/;
function parseEnvLimits(txt, mode) {
  const s = String(txt || '');
  const ranges = [];
  for (const m of s.matchAll(ENV_TEMP_LINE_RE)) {
    const a = parseFloat(m[1]), b = parseFloat(m[2]);
    if (Number.isFinite(a) && Number.isFinite(b) && b > a) ranges.push([a, b]);
  }
  const h = s.match(ENV_HUM_LINE_RE);
  if (!ranges.length && !h) return null;
  let tMin = null, tMax = null;
  if (ranges.length) {
    const los = ranges.map(r => r[0]), his = ranges.map(r => r[1]);
    if (mode === 'intersect') {
      const lo = Math.max.apply(null, los), hi = Math.min.apply(null, his);
      if (hi > lo) { tMin = lo; tMax = hi; }
    }
    if (tMin == null) { tMin = Math.min.apply(null, los); tMax = Math.max.apply(null, his); }
  }
  return { tMin, tMax, hMax: h ? parseFloat(h[1]) : null, stdCount: ranges.length };
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
// 后台自定义「随机生成范围」（kv.envfill.range）→ 直接作为取值区间。
// 与 envBands 的差别：不做事后安全退让 —— 范围是管理员自己调的，填什么就在什么区间内随机（边界即硬边界）。
function envBandsFromRange(rng) {
  if (!rng) return null;
  const tMin = Number(rng.tMin), tMax = Number(rng.tMax), hMin = Number(rng.hMin), hMax = Number(rng.hMax);
  if (![tMin, tMax, hMin, hMax].every(Number.isFinite)) return null;
  if (!(tMax > tMin) || !(hMax > hMin) || hMin <= 0 || hMax > 100) return null;
  return { temp: [tMin, tMax], hum: [hMin, hMax], custom: true };
}
function envCustomRange() {
  const r = (kvget('envfill', {}) || {}).range;
  return envBandsFromRange(r) ? r : null;   // 存了但非法 ≈ 没配（回退房间要求）
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
  const custom = envCustomRange();   // 后台全局「随机生成范围」
  for (const r of targets) {
    // 取值区间优先级（v1.9.0）：房间单独范围 > 全局范围 > 房间温湿度要求解析
    const bands = envBandsFromRange(r.env_range) || envBandsFromRange(custom) || envBands(parseEnvLimits(r.thermo_requirement));
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
    range_source: custom ? 'custom' : 'room',
    signer: { id: signer.id, name: signer.name }, signer_has_sig: !!sigImg,
    detail, skipped
  });
}
// GET /api/env/alerts —— 本科室温湿度超限提醒（任意登录用户；无科室或无超限返回空）
// 仅看「本人科室」房间的温湿度记录；取最近两个月（当月优先，否则上月）；逐格比对房间
// 「综合温湿度要求」解析出的范围；超出量按等级：≤1 度=注意, ≤2=警告, >2=危险。
async function handleEnvAlerts(ctx) {
  const u = await getLoginUser(ctx.req);
  if (!u) return sendJson(ctx.res, { ok: false, alerts: [] });
  const dept = String(u.dept || '').trim();
  if (!dept) return sendJson(ctx.res, { ok: true, hasDept: false, dept: '', alerts: [] });
  const rooms = kvget('rooms', []).filter(r => (r.dept || '').trim() === dept);
  if (!rooms.length) return sendJson(ctx.res, { ok: true, hasDept: true, dept, alerts: [] });
  const roomMap = {}; rooms.forEach(r => roomMap[r.name] = r);
  const roomNames = new Set(rooms.map(r => r.name));
  // 最近两个月窗口：优先当月，否则上月（避免陈旧月份长期告警）
  const now = new Date();
  const curYm = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0');
  const prev = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const prevYm = prev.getFullYear() + '-' + String(prev.getMonth() + 1).padStart(2, '0');
  const alerts = [];
  for (const rec of allEnvRecords()) {
    if (!roomNames.has(rec.room)) continue;
    if (rec.ym !== curYm && rec.ym !== prevYm) continue;
    const room = roomMap[rec.room];
    const lim = parseEnvLimits(room.thermo_requirement);
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
        if (!isNaN(hv) && hv > lim.hMax) {
          alerts.push(mkEnvAlert(rec.room, rec.ym, day, period, '湿度', hv, '%RH', '上限', lim.hMax, hv - lim.hMax));
        }
      }
    }
  }
  const rank = { '危险': 3, '警告': 2, '注意': 1 };
  for (const a of alerts) a.level = a.exceed <= 1 ? '注意' : a.exceed <= 2 ? '警告' : '危险';
  alerts.sort((x, y) => (rank[y.level] - rank[x.level]) || (y.exceed - x.exceed));
  const counts = { 注意: 0, 警告: 0, 危险: 0 };
  alerts.forEach(a => counts[a.level]++);
  return sendJson(ctx.res, {
    ok: true, hasDept: true, dept,
    maxLevel: alerts.length ? alerts[0].level : null,
    counts, alerts
  });
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
// GET /api/admin/env-range —— 读「随机生成范围」配置（温湿度批量填充用）
async function handleEnvRangeGet(ctx) {
  const r = envCustomRange();
  return sendJson(ctx.res, { ok: true, range: r, active: !!r });
}
// PUT /api/admin/env-range —— 保存/清除「随机生成范围」
// body: { range: { tMin,tMax,hMin,hMax } } 传 null 或缺省 = 清除（回退按各房间温湿度要求生成）
async function handleEnvRangePut(ctx) {
  const b = ctx.body || {};
  const cur = kvget('envfill', {}) || {};
  if (b.range == null || (typeof b.range === 'object' && !Object.keys(b.range).length)) {
    kvset('envfill', Object.assign({}, cur, { range: null }));
    return sendJson(ctx.res, { ok: true, range: null, active: false });
  }
  const r = b.range || {};
  const tMin = Number(r.tMin), tMax = Number(r.tMax), hMin = Number(r.hMin), hMax = Number(r.hMax);
  if (![tMin, tMax, hMin, hMax].every(Number.isFinite)) return fail(ctx.res, '四个数值（温度下限/上限、湿度下限/上限）都必须填写');
  if (!(tMin > -50 && tMax < 100)) return fail(ctx.res, '温度范围超出合理区间（-50℃ ~ 100℃）');
  if (!(tMax > tMin)) return fail(ctx.res, '温度上限必须大于下限');
  if (!(hMin > 0 && hMax <= 100)) return fail(ctx.res, '湿度范围应为 0 ~ 100 %RH');
  if (!(hMax > hMin)) return fail(ctx.res, '湿度上限必须大于下限');
  const clean = { tMin, tMax, hMin, hMax };
  kvset('envfill', Object.assign({}, cur, { range: clean }));
  return sendJson(ctx.res, { ok: true, range: clean, active: true });
}
// POST /api/admin/env-records/delete —— 批量删除温湿度记录（管理员；整条删除 = 房间 + 月份的整张月表）
// body: { items: [{room, ym}, ...] } —— ym 为该房间要删的月份；条目不存在时在 missing 里回报
async function handleEnvRecordsDelete(ctx) {
  const b = ctx.body || {};
  const items = Array.isArray(b.items) ? b.items : null;
  if (!items || !items.length) return fail(ctx.res, '请提供要删除的记录（items: [{room, ym}]）');
  if (items.length > 200) return fail(ctx.res, '一次最多删除 200 条，请分批操作');
  const want = new Map();
  for (const it of items) {
    const room = String(it && it.room || '').trim(), ym = String(it && it.ym || '').trim();
    if (!room || !/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '条目格式有误（需 {room, ym:"YYYY-MM"}）：' + JSON.stringify(it));
    want.set(room + '@' + ym, { room, ym });
  }
  const list = allEnvRecords();
  const keep = [], deleted = [], missing = [];
  for (const rec of list) {
    const key = rec.room + '@' + rec.ym;
    if (want.has(key)) { deleted.push({ room: rec.room, ym: rec.ym, cells: Object.keys(rec.cells || {}).length }); want.delete(key); }
    else keep.push(rec);
  }
  for (const { room, ym } of want.values()) missing.push({ room, ym });
  if (deleted.length) {
    kvset('envRecords', keep);
    console.log('[env-records] 批量删除 ' + deleted.length + ' 条：' + deleted.map(d => d.room + '@' + d.ym).join(', '));
  }
  return sendJson(ctx.res, { ok: true, deleted_count: deleted.length, deleted, missing });
}

// ===================== LIMS 温湿度实时数据源（HANSON-LIMS oapi 直连） =====================
// 数据来源：HANSON-LIMS（JeecgBoot 低代码）「环境监测管理」的 oapi 接口：
//   POST /hanson-lcdp/sys/login                                          → data.token（JWT）
//   POST /hanson-lcdp/oapi/dataAcquisition/environment/humidityChart      → data.result=[{humidity,time}]
//   POST /hanson-lcdp/oapi/dataAcquisition/environment/temperatureHumidityList
//        → data.result=[{humidity,temperature,time}]（温湿同点配对！2026-09-15 从页面 chunk main432.js 挖出）
//   POST /hanson-lcdp/oapi/dataAcquisition/environment/temperatureChart   → data={t,h,cTime}（读"设备当前值"表，
//                                                                          该表无数据 t 恒 null，页面温度曲线也是空的；弃用）
// 实测结论（2026-09-15）：
//   · humidityChart 传 startDate=月初 / endDate=月末 可取整月 5 分钟粒度历史（每天约 288 点）；
//     startDate=endDate=同一天会返回空，所以统一按「整月区间」拉取再按日/时段筛选。
//   · temperatureHumidityList 的 endDate 必传（缺失报 5002「请选择结束日期」），同日窗口合法；
//     服务端分页钉死 pageSize=20，无论窗口多大只返回窗口内「最新 20 点」；整月 total≈4270 点。
//   · 单次接口 7~12 秒且不随窗口变小，必须串行 + 重试，不能并发轰炸。
// 温度补填策略：
//   · day 模式（抓今天/定时任务）：逐时段窗口查询（≤3 次/房间），温湿同点配对一次拿全。
//   · month 模式（补历史月）：湿度走整月全量；温度逐天逐时段窗口（12 秒/次），默认关闭，
//     仅当请求显式携带 with_temp:true 且预算（TEMP_WINDOW_BUDGET=90 次 ≈ 18 分钟）内才执行。
// 取数策略（每个「日_时段」格只落一个值）：
//   random   该时段内随机取一点（默认；定时自动填充用，模拟真实抄表）
//   nearest  取最接近触发时刻的一点（温湿度页「一键抓取」的当前时段用）
//   first/last/avg/max/min —— 其余可选，后台可配；avg 取「湿度最接近均值的真实点」以便温度配对
// 硬约束（与 /api/admin/env-fill 一致）：只补空格，已有内容（含签名、划线）一律不动；绝不生成未来日期的记录。

const LIMS_DEFAULTS = {
  enabled: true,
  base: '<LIMS_BASE_URL>',
  user: '<LIMS_USER>',
  pass: '',
  interfaceId: 'oapi:94af36b40d7f4e7db4364acd0b74fbde',
  interfaceIdTh: 'oapi:e35dbe77f46f4f7e8d82d427339898b2',   // temperatureHumidityList（温湿同点）专用
  tempWindowBudget: 90,                                      // month 模式补历史温度的窗口查询预算（次；约 12 秒/次）
  recorder: 'LIMS自动导入',                  // 未指定签名人时，记录员格显示的文本
  strategy: 'random',
  overwrite: false,                          // true = 连已有内容的格子也覆盖（慎用）
  // 别名 = LIMS源房间名 → 点检房间名。同名房间无需别名（同名直配）。
  // 注：'室温拉伸实验室' 经核查 LIMS 侧房间名就是「室温拉伸实验室」、点检房间同名，无需别名；
  //     旧默认 '室拉，高拉室' 是错误映射（会路由到不存在的房间），已移除。
  roomAlias: { '金相分析': '金相分析室', '金相制样间': '金相试样间' },
  limsRooms: ['冲击室', '室温拉伸实验室', '持久蠕变室2', '持久蠕变室1', '硬度室', '金相制样间', 'ICP-MS',
    '直读光谱（OES）', '碳硫分析（C、S）', 'ICP-OES', '金相分析（办公）', '金相分析', '化学制样', '化学分析', '氧氮氢（O、N、H）'],
  // allowShare：**显式允许**「与别的点检房间共用同一个 LIMS 数据源」的点检房间名。
  //   背景：别名若指向一个「本身也是点检房间名」的 LIMS 源（如 疲劳，弯曲室 → 冲击室），
  //   那个源已被同名房间占用，两个房间会自动填成同一份数据（工厂 9 月实锤：两房间逐格相同）。
  //   默认不生效（需人工确认）；用户认为"共用一份数据本来就应该允许"时，把房间名放这里即可放行。
  allowShare: [],
  // noFetch：「不参与抓取」的点检房间名清单。
  //   背景：抓取模块（全部同步 / 定时自动）默认对「所有配置了 LIMS 数据源的房间」一起抓，
  //   但某些房间希望整批抓取时跳过，仍可单独手动抓取。判定入口统一在 limsMappedRooms()：被 noFetch 包含的房间不进批量/自动清单。
  noFetch: [],
  // tempSource（v1.26.0）：**温度**的数据来源映射，点检房间名 → 'auto' | 'off' | LIMS 房间名。
  //   为什么单独一张表：湿度与温度在 LIMS 里不是一张传感器表。湿度走 humidityChart（每间都能有），
  //   温度只有「温湿同点」的房间才有（temperatureHumidityList）。实测金相分析室 / 金相试样间
  //   湿度满格但温度只有几格 —— 它们的 LIMS 源房间没挂温湿同点传感器。
  //   'auto'（默认，不必写）= 温度跟随湿度源（原来唯一的行为）；'off' = 这间不抓温度（留空手填）；
  //   写具体 LIMS 房间名 = 温度改从那一间取（例如多间统一指向有温湿同点传感器的「冲击室」）。
  //   注意：这张表是「点检房间 → 源」，与 roomAlias（源 → 房间）方向相反，因为一个源要能给多个房间用。
  tempSource: {},
  // unmapped（v1.26.0）：用户显式点了「（未映射 · 不抓取）」的点检房间名。
  //   为什么必须有：limsSourceRoomDetail 的第①条「同名直配」会让点检「冲击室」无条件占用 LIMS「冲击室」，
  //   于是用户想在后台把它改成「未映射」时会被顶回原值（改了 → 保存 → 刷新又回来了），
  //   而且那个源一直算「被同名房间占用」，别的房间想用它就得先勾「允许共用同一数据源」。
  //   显式进这张表 = 用户说了「这间不用任何 LIMS 源」，优先级最高，同名直配也要让路（源随之变为空闲，可自由给别的房间）。
  unmapped: [],
  // roomCheck：最近一次「房间名实测校验」结果，由 POST /api/lims/verify-rooms 写入。
  //   { at, days, base, results: [{room, verdict, points, ms, msg}] }
  //   verdict: ok=存在且有数据 / empty=房间存在但没挂设备(无数据) / no_room=该名字在 LIMS 不存在 / error=探测失败
  roomCheck: null,
  verifyDays: 7,                             // 校验时回看天数（humidityChart 单日区间恒返回 0 点，必须 ≥2 天）
  auto: { enabled: false, times: ['08:35', '13:35', '19:05'], recorder: '' },  // 定时自动填充当天时段格
};

function limsConfig() {
  const saved = kvget('lims', null) || {};
  const cfg = Object.assign({}, LIMS_DEFAULTS, saved);
  cfg.auto = Object.assign({}, LIMS_DEFAULTS.auto, saved.auto || {});
  // roomAlias（LIMS 源房间名 → 点检房间名）：
  // 只要用户保存过一次 LIMS 配置，就完全以用户保存的为准 —— 不再与内置默认合并。
  // 旧写法 Object.assign(LIMS_DEFAULTS.roomAlias, saved.roomAlias) 有个坑：用户在后台把某条改成
  // 「（未映射）」并保存后，那条内置默认会在下次加载时"复活"，表现为「改了、保存了、刷新又回来了」，
  // 怎么都删不掉 —— 用户会认为「这个错误映射一直没修」。
  cfg.roomAlias = (saved.roomAlias && typeof saved.roomAlias === 'object')
    ? Object.assign({}, saved.roomAlias)
    : Object.assign({}, LIMS_DEFAULTS.roomAlias);
  if (!Array.isArray(cfg.limsRooms) || !cfg.limsRooms.length) cfg.limsRooms = LIMS_DEFAULTS.limsRooms.slice();
  if (!Array.isArray(cfg.allowShare)) cfg.allowShare = [];
  if (!Array.isArray(cfg.noFetch)) cfg.noFetch = [];
  if (!Array.isArray(cfg.unmapped)) cfg.unmapped = [];
  if (!cfg.tempSource || typeof cfg.tempSource !== 'object' || Array.isArray(cfg.tempSource)) cfg.tempSource = {};
  if (!Number.isFinite(+cfg.verifyDays) || +cfg.verifyDays < 2) cfg.verifyDays = LIMS_DEFAULTS.verifyDays;
  return cfg;
}

// ---- LIMS HTTP 客户端（零依赖） ----
function limsHttp(url, { method = 'GET', headers = {}, body = null, timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? require('https') : http;
    const payload = body == null ? null : JSON.stringify(body);
    const h = Object.assign({}, headers);
    if (payload != null) { h['Content-Type'] = 'application/json;charset=UTF-8'; h['Content-Length'] = Buffer.byteLength(payload); }
    const req = lib.request({ hostname: u.hostname, port: u.port, path: u.pathname + u.search, method, headers: h, timeout }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', c => (data += c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) { /* 非 JSON */ }
        resolve({ status: res.statusCode, text: data, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('LIMS 请求超时（' + timeout + 'ms）')));
    req.on('error', reject);
    if (payload != null) req.write(payload);
    req.end();
  });
}

let limsTokenCache = { token: '', base: '', user: '', at: 0 };
async function limsLogin(cfg) {
  // token 缓存 60 分钟：同一进程内反复同步不必每次都登录
  const c = limsTokenCache;
  if (c.token && c.base === cfg.base && c.user === cfg.user && (Date.now() - c.at) < 60 * 60 * 1000) return c.token;
  const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/sys/login', {
    method: 'POST',
    body: { username: cfg.user, password: cfg.pass, captcha: '', checkKey: '' },
  });
  const d = r.json && (r.json.data || r.json.result);   // 注意：该 LIMS 登录返回 data 而非 result（JeecgBoot 定制）
  if (!d || !d.token) {
    const msg = String(r.text || ('HTTP ' + r.status)).slice(0, 160);
    logE('LIMS', '登录失败（' + cfg.user + ' @ ' + cfg.base + '）: ' + msg);
    throw new Error('LIMS 登录失败：' + msg);
  }
  limsTokenCache = { token: d.token, base: cfg.base, user: cfg.user, at: Date.now() };
  logI('LIMS', '登录成功（' + cfg.user + ' @ ' + cfg.base + '）');
  return d.token;
}

// 取某 LIMS 房间整月湿度时序（升序）。返回 [{humidity, time, tm}]
async function limsFetchHumidity(cfg, token, limsRoom, ym) {
  const [yy, mm] = ym.split('-').map(Number);
  const dim = new Date(yy, mm, 0).getDate();
  const pad = n => String(n).padStart(2, '0');
  const body = { interfaceId: cfg.interfaceId, roomName: limsRoom, startDate: ym + '-01', endDate: ym + '-' + pad(dim), startTime: '', endTime: '' };
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {          // LIMS 单次 7~8 秒且偶发断连，重试兜底
    try {
      const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/oapi/dataAcquisition/environment/humidityChart', {
        method: 'POST', headers: { 'X-Access-Token': token }, body,
      });
      const arr = r.json && r.json.data && Array.isArray(r.json.data.result) ? r.json.data.result : [];
      if (!arr.length && r.json && r.json.code != null && r.json.code !== 1 && !r.json.data) {
        // LIMS 明确报错（如 5000「未查询到房间设备关联」）：不再默默当「无数据」，直接把原因带给界面和日志
        const msg = 'humidityChart code=' + r.json.code + ' ' + (r.json.message || r.json.msg || '');
        logW('LIMS', '[' + limsRoom + '] ' + msg);
        const err = new Error('LIMS ' + msg);
        err.noRetry = true;   // 房间没关联设备是配置问题，重试也没用
        throw err;
      }
      logI('LIMS', 'humidityChart[' + limsRoom + '] ' + ym + ' 点数=' + arr.length);
      return arr.map(x => ({ humidity: x.humidity, time: x.time, tm: limsParseTime(x.time) })).filter(x => x.humidity != null && x.tm);
    } catch (e) {
      if (e && e.noRetry) throw e;   // 配置类错误（如房间未关联设备）重试无意义
      lastErr = e;
      if (attempt < 2) await new Promise(res => setTimeout(res, 1200 * (attempt + 1)));
    }
  }
  throw lastErr || new Error('LIMS 湿度接口失败');
}

// 取某 LIMS 房间「同一天 + 起止时刻窗口」的温湿度点（温湿同点配对，返回按时间倒序，≤20 点）。
// temperatureHumidityList：endDate 必传；服务端分页钉死 pageSize=20（窗口大时只给最新 20 点）；
// 单次约 12 秒，串行 + 重试。返回 [{humidity, temp, time, tm}]
async function limsFetchEnvWindow(cfg, token, limsRoom, date, startHM, endHM) {
  const body = { interfaceId: cfg.interfaceIdTh || LIMS_DEFAULTS.interfaceIdTh, roomName: limsRoom,
    startDate: date, endDate: date, startTime: startHM, endTime: endHM };
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/oapi/dataAcquisition/environment/temperatureHumidityList', {
        method: 'POST', headers: { 'X-Access-Token': token }, body,
      });
      const arr = r.json && r.json.data && Array.isArray(r.json.data.result) ? r.json.data.result : [];
      if (!arr.length && r.json && r.json.code != null && r.json.code !== 1 && !r.json.data) {
        const msg = 'temperatureHumidityList code=' + r.json.code + ' ' + (r.json.message || r.json.msg || '');
        logW('LIMS', '[' + limsRoom + '] ' + msg);
        const err = new Error('LIMS ' + msg);
        err.noRetry = true;
        throw err;
      }
      const withT = arr.filter(x => x.temperature != null && x.temperature !== '').length;
      logI('LIMS', 'thList[' + limsRoom + '] ' + date + ' ' + startHM + '~' + endHM + ' 点数=' + arr.length + ' 含温度=' + withT);
      return arr.map(x => ({ humidity: x.humidity, temp: x.temperature, time: x.time, tm: limsParseTime(x.time) }))
        .filter(x => (x.humidity != null || x.temp != null) && x.tm);
    } catch (e) {
      if (e && e.noRetry) throw e;   // 配置类错误（如房间未关联设备）重试无意义
      lastErr = e;
      if (attempt < 2) await new Promise(res => setTimeout(res, 1200 * (attempt + 1)));
    }
  }
  throw lastErr || new Error('LIMS 温湿度列表接口失败');
}

// 时段 → 当日窗口（与 limsPeriodOf 分桶边界一致：AM<12h、PM<18h、Night≥18h）
const LIMS_PERIOD_WINDOW = { AM: ['00:00:00', '11:59:59'], PM: ['12:00:00', '17:59:59'], Night: ['18:00:00', '23:59:59'] };

// 【已弃用并移除】temperatureChart 通道（2026-09-15）：实测全房间 t 恒为 null（读设备当前值表，LIMS 未写入），
// 页面自身温度曲线也空。温度真实来源是 temperatureHumidityList（interfaceIdTh，温湿同点配对），见 limsFetchEnvWindow。

function limsParseTime(s) {
  const m = String(s || '').match(/(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?/);
  if (m) return new Date(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}
const limsPeriodOf = h => (h < 12 ? 'AM' : (h < 18 ? 'PM' : 'Night'));

// 按策略从候选点里挑一个「落在表格里的读数」
function limsPickPoint(pts, strategy, refTm) {
  if (!pts || !pts.length) return null;
  const sorted = pts.slice().sort((a, b) => a.tm - b.tm);
  switch (strategy) {
    case 'first': return sorted[0];
    case 'last': return sorted[sorted.length - 1];
    case 'min': return sorted.reduce((m, x) => (x.humidity < m.humidity ? x : m), sorted[0]);
    case 'max': return sorted.reduce((m, x) => (x.humidity > m.humidity ? x : m), sorted[0]);
    case 'avg': {
      // avg 取「湿度最接近均值的真实点」而非虚拟均值点：保证温度与湿度来自同一时刻（温湿同点配对）
      const v = sorted.reduce((s, x) => s + Number(x.humidity), 0) / sorted.length;
      return sorted.reduce((m, x) => (Math.abs(x.humidity - v) < Math.abs(m.humidity - v) ? x : m), sorted[0]);
    }
    case 'nearest': {
      const ref = refTm instanceof Date ? refTm.getTime() : Date.now();
      return sorted.reduce((m, x) => (Math.abs(x.tm - ref) < Math.abs(m.tm - ref) ? x : m), sorted[0]);
    }
    case 'random':
    default: return sorted[Math.floor(Math.random() * sorted.length)];
  }
}

// 点检房间名 → LIMS 源房间名 的**明细版**：返回 { source, via, blocked, shared }
//   source  = 命中的 LIMS 源房间名（null = 无数据源）
//   via     = 'same'（同名直配）| 'alias'（别名）| ''
//   blocked = 因「映射冲突」被暂停的别名想借用的 LIMS 源名（用于界面/日志说明原因）
//   shared  = 该房间正在**共用**另一个点检房间的同名数据源（用户已在 allowShare 里显式允许）
// 判定顺序：① 同名直配优先 ② 别名（roomAlias：LIMS源 → 点检房间）
// ★ 防串：若别名要借用的 LIMS 源，同时又是另一个点检房间的名字（那个房间已"同名直配"占用它），
//   默认**暂停**这条别名 —— 否则两个点检房间会自动填充到同一份数据。工厂实测：点检「疲劳，弯曲室」的
//   温湿度与点检「冲击室」逐格完全相同（都以 LIMS「冲击室」为源），即由此产生。
//   但「引用同一个数据源」本身是合理需求（现场可能就没给那间装温湿度计）—— 把房间名加进
//   cfg.allowShare 即可放行，放行后两个房间会拿到同一份读数（界面会明确标出"共用"）。
function limsSourceRoomDetail(cfg, roomName) {
  const isLims = (n) => (cfg.limsRooms || []).includes(n);
  const isInspect = (n) => kvget('rooms', []).some(r => r.name === n);
  const allowShare = Array.isArray(cfg.allowShare) ? cfg.allowShare : [];
  // ⓿（v1.26.0）用户显式设成「（未映射 · 不抓取）」的房间 —— 优先级最高，连同名直配都要让路。
  //   修的就是这个死结：点检「冲击室」原本被同名直配无条件绑住 LIMS「冲击室」，既关不掉，
  //   又一直占着那个源，导致别的房间想用 LIMS「冲击室」必须先勾「允许共用」。
  if ((cfg.unmapped || []).includes(roomName)) return { source: null, via: 'unmapped', blocked: '', shared: '' };
  if (isLims(roomName)) return { source: roomName, via: 'same', blocked: '', shared: '' };   // ① 同名直配
  for (const [lr, tr] of Object.entries(cfg.roomAlias || {})) {                              // ② 别名
    // 别名值支持「一个源 → 多个点检房间」（数组）：一个 LIMS 房间的读数本来就可能要给几间共用
    const targets = Array.isArray(tr) ? tr : [tr];
    if (targets.indexOf(roomName) < 0) continue;
    // 「源是否真被同名点检房间占用」要看那个房间**自己**是否在用：若它自己也设了「未映射」，
    // 这个源就是空闲的，别名直接用即可（不必再勾「允许共用」）。
    if (lr !== roomName && isInspect(lr) && limsRoomUsesOwnSource(cfg, lr)) {
      if (!allowShare.includes(roomName)) return { source: null, via: 'alias', blocked: lr, shared: '' };
      return { source: lr, via: 'alias', blocked: '', shared: lr };                          // 用户显式允许共用
    }
    return { source: lr, via: 'alias', blocked: '', shared: '' };
  }
  return { source: null, via: '', blocked: '', shared: '' };
}
// 该点检房间是否正用着「LIMS 上的同名房间」（用于判断某个源算不算被占用）
function limsRoomUsesOwnSource(cfg, name) {
  if ((cfg.unmapped || []).includes(name)) return false;
  return (cfg.limsRooms || []).includes(name);
}
// 温度数据源（v1.26.0）：这间的温度从哪个 LIMS 房间取。
//   tempSource[房间] = 'auto'（跟随湿度源）| 'off'（不抓温度）| LIMS 房间名；未配置 = auto。
//   auto 但该房间没有湿度源时 → off（没有源可跟，自然也不抓温度）。
function limsTempSourceDetail(cfg, roomName) {
  const v = String(((cfg.tempSource || {})[roomName] == null ? '' : (cfg.tempSource || {})[roomName])).trim();
  if (v === 'off') return { mode: 'off', source: null, note: '已设为「不抓温度」（留空手填）' };
  if (v && v !== 'auto') return { mode: 'room', source: v, note: '温度取自「' + v + '」' };
  const h = limsSourceRoom(cfg, roomName);
  if (!h) return { mode: 'off', source: null, note: '该房间未映射，没有温度来源' };
  return { mode: 'auto', source: h, note: '温度跟随湿度源「' + h + '」（温湿同点）' };
}
function limsTempSource(cfg, roomName) { return limsTempSourceDetail(cfg, roomName).source; }
// 点检房间名 → LIMS 源房间名；无映射返回 null（供抓取/同步等运行逻辑使用）
function limsSourceRoom(cfg, roomName) { return limsSourceRoomDetail(cfg, roomName).source; }

// 映射体检：一次性算出「映射全貌 / 共用同一源 / 被暂停的别名 / 未映射房间 / 未被使用的 LIMS 房间 / 源名有效性」
// 供 POST /api/lims/test（后台「测试连接」）与后台映射区展示，让"房间对错"一眼可见而不是靠猜。
// 不依赖 LIMS 连通性：源名有效性取最近一次「实测校验」的结果（kv.lims.roomCheck），没校验过则留空。
function limsMapAudit() {
  const cfg = limsConfig();
  const rooms = kvget('rooms', []).map(r => r.name);
  const bySrc = {}, blocked = [], shared = [];
  const tempMapped = [], tempOff = [];
  for (const rn of rooms) {
    const d = limsSourceRoomDetail(cfg, rn);
    if (d.source) {
      (bySrc[d.source] = bySrc[d.source] || []).push({ room: rn, via: d.via });
      if (d.shared) shared.push({ room: rn, source: d.shared });
    } else if (d.blocked) blocked.push({ room: rn, source: d.blocked });
    const t = limsTempSourceDetail(cfg, rn);
    if (t.source) tempMapped.push({ room: rn, source: t.source, mode: t.mode });
    else tempOff.push({ room: rn, mode: t.mode, note: t.note });
  }
  // 源名有效性（来自最近一次实测校验）：把「名字写错 / 该房间没挂设备」直接点名
  const chk = (cfg.roomCheck && Array.isArray(cfg.roomCheck.results)) ? cfg.roomCheck.results : [];
  const vmap = {};
  chk.forEach(x => { if (x && x.room) vmap[x.room] = x.verdict; });
  const usedSources = Object.keys(bySrc);
  return {
    mapped: Object.entries(bySrc).flatMap(([s, arr]) => arr.map(x => ({ room: x.room, source: s, via: x.via }))),
    conflicts: Object.entries(bySrc).filter(([, a]) => a.length > 1).map(([source, a]) => ({ source, rooms: a.map(x => x.room) })),
    shared,                                                  // 已允许共用同一数据源的房间
    blocked_alias: blocked,                                  // 别名被暂停（该房间不自动抓取）
    can_share: blocked.map(x => ({ room: x.room, source: x.source })),   // 想共用就把它加进「允许共用」
    unmapped_rooms: rooms.filter(rn => !limsSourceRoom(cfg, rn) && !limsTempSource(cfg, rn)),
    unmapped_explicit: (cfg.unmapped || []).slice(),          // 用户显式设成「未映射 · 不抓取」的房间
    temp_mapped: tempMapped,                                  // 温度有来源的房间（auto = 跟湿度源）
    temp_off: tempOff,                                        // 不抓温度的房间（显式 off，或没源可跟）
    temp_shared: tempMapped.filter(x => x.mode === 'room'),   // 温度另指到别的 LIMS 房间的
    unused_lims_rooms: (cfg.limsRooms || []).filter(lr => !bySrc[lr]),
    check_at: (cfg.roomCheck && cfg.roomCheck.at) || '',
    invalid_sources: usedSources.filter(s => vmap[s] === 'no_room'),     // 映射用的源名在 LIMS 里不存在 → 抓不到数据
    empty_sources: usedSources.filter(s => vmap[s] === 'empty'),         // 源房间存在但没挂设备（0 点）
    unknown_sources: usedSources.filter(s => !vmap[s]),                  // 没校验过
  };
}
// 有 LIMS 数据源的点检房间清单（供「全部同步」与后台展示）
function limsMappedRooms() {
  const cfg = limsConfig();
  const skip = new Set(cfg.noFetch || []);
  // v1.26.0：只要「有湿度源 或 有温度源」就进清单 —— 否则「湿度未映射、但温度借别的房间」的配置会被整块漏掉
  return kvget('rooms', []).map(r => r.name)
    .filter(name => !skip.has(name) && (limsSourceRoom(cfg, name) || limsTempSource(cfg, name)));
}

// ---- LIMS 房间名实测校验：回答「下拉框里那些房间名，LIMS 到底有没有这间」----
// 判定指纹（2026-09-16 实测）：
//   · 名字不存在   → 20~70ms 秒回 code=5000「未查询到房间设备关联」（压根没查库）
//   · 房间存在     → 7~8 秒（真查库）返回 code=1
//   · 存在但没挂设备 → 7~8 秒 code=1 且 0 点（工厂「室温拉伸实验室」就是这种）
// ⚠ 另一个坑：humidityChart 的 startDate == endDate 时**恒返回 0 点**（所有房间都一样），
//   所以校验必须给 ≥2 天的区间，否则会把每个房间都误判成"没数据"。
async function limsProbeRoomName(cfg, token, room, days) {
  const n = Math.max(2, Math.min(31, +days || LIMS_DEFAULTS.verifyDays));
  const pad = x => String(x).padStart(2, '0');
  const end = new Date();
  const start = new Date(end.getTime() - (n - 1) * 86400000);
  const ds = d => d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  const win = ds(start) + '~' + ds(end);
  const body = { interfaceId: cfg.interfaceId, roomName: room, startDate: ds(start), endDate: ds(end), startTime: '', endTime: '' };
  const t0 = Date.now();
  try {
    const r = await limsHttp(cfg.base.replace(/\/$/, '') + '/hanson-lcdp/oapi/dataAcquisition/environment/humidityChart', {
      method: 'POST', headers: { 'X-Access-Token': token }, body,
    });
    const ms = Date.now() - t0;
    const arr = (r.json && r.json.data && Array.isArray(r.json.data.result)) ? r.json.data.result : [];
    const code = r.json ? r.json.code : null;
    const msg = (r.json && (r.json.message || r.json.msg)) || '';
    if (String(code) === '1' || String(code) === '00000') {
      return { room, verdict: arr.length ? 'ok' : 'empty', points: arr.length, ms, code, msg: '', window: win };
    }
    return { room, verdict: 'no_room', points: 0, ms, code, msg: msg || ('code=' + code), window: win };
  } catch (e) {
    return { room, verdict: 'error', points: 0, ms: Date.now() - t0, code: null, msg: String((e && e.message) || e), window: win };
  }
}
// 校验对象默认取「LIMS 源房间清单 ∪ 当前映射用到的源 ∪ 全部点检房间名」——
// 既回答"清单里的名字对不对"，也回答"哪些点检房间在 LIMS 里有同名房间"，一次跑完。
function limsVerifyCandidates(cfg) {
  return [...new Set([
    ...(cfg.limsRooms || []),
    ...limsMapAudit().mapped.map(x => x.source),
    ...kvget('rooms', []).map(r => r.name),
  ].map(s => String(s).trim()).filter(Boolean))];
}
const LIMS_VERDICT_TEXT = { ok: '存在且有数据', empty: '房间存在但无数据（未挂设备）', no_room: 'LIMS 中不存在', error: '探测失败' };

// 房间级互斥锁：同一房间同月同时只允许一个同步任务（防并发读改写丢更新）
const limsRoomLocks = new Set();
async function limsSyncRoom(opts) {
  const lkey = String(opts && opts.room || '') + '|' + String(opts && opts.ym || '');
  if (limsRoomLocks.has(lkey)) return { error: '该房间此月份已有同步任务在执行，请等它完成后再试' };
  limsRoomLocks.add(lkey);
  try { return await limsSyncRoomUnlocked(opts); }
  finally { limsRoomLocks.delete(lkey); }
}
// 核心：抓一个点检房间（整月或仅今天）并按「只补空格」合并进 envRecords
// opts: { room, ym, mode:'day'|'month', overwrite, signer, recorder }
async function limsSyncRoomUnlocked(opts) {
  const cfg = limsConfig();
  const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : null;
  const room = String(opts.room || '').trim();
  const ym = String(opts.ym || '').trim();
  if (!room) return { error: '房间必填' };
  if (!/^\d{4}-\d{2}$/.test(ym)) return { error: '月份格式应为 YYYY-MM' };
  const cur = currentMonthStr();
  if (ym > cur) return { error: '不能抓取未来月份（' + ym + '）' };
  if (!kvget('rooms', []).some(r => r.name === room)) return { error: '房间不存在：' + room, status: 404 };
  const srcDetail = limsSourceRoomDetail(cfg, room);
  const source = srcDetail.source;                       // 湿度源（可为空：该房间只借温度）
  const tDetail = limsTempSourceDetail(cfg, room);        // v1.26.0 温度源（auto/off/显式房间）
  const tempSource = tDetail.source;
  if (!source && !tempSource) {
    if (srcDetail.blocked) {
      return { error: '该房间的 LIMS 映射已暂停：它指向「' + srcDetail.blocked + '」，而那个房间本身也在用这份数据。' +
        '若要允许两个房间共用同一份读数，请在后台「LIMS 数据源」里勾选「允许与「' + srcDetail.blocked + '」共用同一数据源」并保存。' };
    }
    if (srcDetail.via === 'unmapped') {
      return { error: '房间「' + room + '」已设为「未映射 · 不抓取」（也没有另配温度源），不参与 LIMS 同步' };
    }
    return { error: '该房间没有配置 LIMS 数据源（可在后台「温湿度填充 → LIMS 数据源」里维护映射）' };
  }

  const today = todayStr();
  const curPeriod = limsPeriodOf(new Date().getHours());
  const onlyToday = opts.mode === 'day';
  // v1.27.0「只抓当前时段」：普通用户在温湿度页触发抓取时，只允许写「今天 + 当前时段」那一格。
  //   在这一层落地而不是只在 handleLimsSync 拦，是为了让任何调用方（手动/后续新入口）都受同一约束。
  const onlyPeriod = ENV_PERIODS.includes(opts.onlyPeriod) ? opts.onlyPeriod : '';
  if (onlyToday && ym !== cur) return { error: '「仅今天」只对当前月份有效，历史月份请用整月模式' };

  const token = await limsLogin(cfg);
  if (onProgress) onProgress('已登录 LIMS，拉取整月湿度…');

  // 湿度主源：整月 humidityChart（一次拉全月，day 模式也复用——成本相同还能覆盖当天全时段）
  // v1.26.0：房间可能是「只借温度」（湿度未映射）→ 这时跳过湿度主源，只逐窗抓温度。
  const points = source ? await limsFetchHumidity(cfg, token, source, ym) : [];
  const hasHum = points.length > 0;
  if (onProgress) onProgress(source ? ('湿度 ' + points.length + ' 点，分桶完成') : '该房间未映射湿度，只抓温度…');

  // 分桶：day_period → 候选点
  const buckets = {};
  for (const p of points) {
    const ds = p.tm.getFullYear() + '-' + String(p.tm.getMonth() + 1).padStart(2, '0') + '-' + String(p.tm.getDate()).padStart(2, '0');
    if (onlyToday && ds !== today) continue;
    const k = String(p.tm.getDate()) + '_' + limsPeriodOf(p.tm.getHours());
    (buckets[k] = buckets[k] || []).push(p);
  }

  // 温度来源：temperatureHumidityList（温湿同点配对，interfaceIdTh，经 limsFetchEnvWindow 逐时段窗口查询）。
  // 该接口分页锁死 pageSize=20、单次约 12 秒 → 只能用「同日 + 时段窗口」逐格查询：
  //   day 模式默认开（今天最多 3 个窗口）；month 模式默认关（历史最多 93 格逐窗太慢，
  //   需显式 with_temp 且受 tempWindowBudget 预算约束，超预算跳过并在响应中说明）。
  // v1.26.0：温度源为空（off / 未映射）时**一律不抓温度** —— 这就是「未映射状态下……不予抓取」
  const withTemp = !!tempSource && (onlyToday ? (opts.withTemp !== false) : !!opts.withTemp);
  const tempScope = opts.tempScope || (onlyToday ? 'today' : 'all');   // today=只抓当天(快)；all=历史逐窗补抓(慢，走异步任务)
  // 温度补抓：格子已有湿度但温度为空时，单独查温湿窗口把温度补上（不动湿度/签名/划线）。
  // 背景：湿度主源成功而温度窗口偶发失败时，旧逻辑因「只补空格」永远跳过该格 → 温度永久缺失（2026-09-16 工厂实锤）。
  const backfillTemp = !!tempSource && (onlyToday ? (opts.backfillTemp !== false) : !!opts.backfillTemp);

  // 合并写入（只补空格）
  const list = allEnvRecords();
  let rec = list.find(x => x.room === room && x.ym === ym);
  if (rec && !rec.cells) rec.cells = {};
  const overwrite = !!opts.overwrite;
  const signer = opts.signer || null;
  const recorderText = signer ? signer.id : (opts.recorder || cfg.recorder);
  const sigImg = signer ? (pickSigImage(signer) || '') : '';
  const filled = [], skippedExist = [], noData = [];
  const [yy, mm] = ym.split('-').map(Number);
  const maxDay = (ym === cur) ? Number(today.slice(8, 10)) : new Date(yy, mm, 0).getDate();

  // 第一步：列出真正需要填数据的格，并安排温度窗口（未来时段查了也没数据，直接跳过）
  const need = [];
  const tempWins = [];
  for (let day = 1; day <= maxDay; day++) {
    for (const period of ENV_PERIODS) {
      // 只抓当前时段 → 其它日期、其它时段连"候选"都不进（不查温度窗口，也不写库）
      if (onlyPeriod && (period !== onlyPeriod || day !== Number(today.slice(8, 10)))) continue;
      const k = day + '_' + period;
      const exist = rec && rec.cells[k];
      if (!overwrite && envCellHasData(exist)) { skippedExist.push(k); continue; }
      need.push({ day, period, k });
      if (!withTemp) continue;
      if (hasHum && !(buckets[k] || []).length) continue;   // 湿度主源该格无点 → LIMS 该时段根本没采，温度窗口必然也空，省预算
      // （只借温度的房间没有湿度主源可参照，不做这个省预算的跳格判断）
      const ds = ym + '-' + String(day).padStart(2, '0');
      if (ds === today && ENV_PERIODS.indexOf(period) > ENV_PERIODS.indexOf(curPeriod)) continue;   // 今天未来时段
      if (tempScope === 'today' && ds !== today) continue;   // 只抓当天：历史温度走单独的补抓任务（异步、预算内）
      tempWins.push({ day, period, k, ds });
    }
  }

  // 第二步：串行执行温度窗口查询（预算内），得到「温湿同点」候选
  const budget = Number(cfg.tempWindowBudget) > 0 ? Number(cfg.tempWindowBudget) : LIMS_DEFAULTS.tempWindowBudget;
  const tempRuns = tempWins.slice(0, budget);
  const tempSkippedBudget = tempWins.length - tempRuns.length;
  const tempBuckets = {};
  let winUsed = 0;
  for (const w of tempRuns) {
    try {
      const win = LIMS_PERIOD_WINDOW[w.period] || LIMS_PERIOD_WINDOW.AM;
      const wpts = await limsFetchEnvWindow(cfg, token, tempSource, w.ds, win[0], win[1]);
      winUsed++;
      const withT = wpts.filter(x => x.temp != null && x.temp !== '');
      if (withT.length) tempBuckets[w.k] = withT;
    } catch (e) {
      // 单窗口失败不阻塞：温度留空（由「补抓温度」在后续同步中自愈），但要落日志让故障可见
      logW('LIMS', '温度窗口[' + tempSource + ' ' + w.ds + ' ' + w.period + '] 失败: ' + (e && e.message || e));
    }
    await new Promise(res => setTimeout(res, 200));
  }

  // 第三步：选点写入 —— 温度窗口点（温湿配对，同一点同时取温湿度）优先，窗口无温度点则回退湿度主源（温度留空）
  let touched = false;
  for (const it of need) {
    const k = it.k;
    const tPts = tempBuckets[k] || [];
    const hPts = buckets[k] || [];
    if (!tPts.length && !hPts.length) { noData.push(k); continue; }
    // 当前时段用 nearest（最接近现在的读数），其余按配置策略
    const isCurPeriodToday = (ym === cur && it.day === Number(today.slice(8, 10)) && it.period === curPeriod);
    const strategy = (isCurPeriodToday && cfg.strategy !== 'nearest') ? 'nearest' : cfg.strategy;
    // v1.26.0：温度源与湿度源**可能不是同一间**（温度借别的房间）。
    //   同源时保持老行为：优先用「温湿同点」窗口的那个点，温度湿度取自同一时刻（配对可信）。
    //   异源时各取各的点 —— 绝不能把温度源那间的湿度当成这间的湿度写进去（否则会把数据串成别人的）。
    const sameSrc = (tempSource === source);
    let humVal = '', useTemp = '', pickTime = '';
    if (sameSrc) {
      const pick = limsPickPoint(tPts.length ? tPts : hPts, strategy);
      if (!pick) { noData.push(k); continue; }
      humVal = String(pick.humidity == null ? '' : pick.humidity);
      useTemp = (pick.temp != null && pick.temp !== '') ? String(pick.temp) : '';
      pickTime = pick.time;
    } else {
      const hPick = hPts.length ? limsPickPoint(hPts, strategy) : null;
      const tPick = tPts.length ? limsPickPoint(tPts, strategy) : null;
      humVal = hPick ? String(hPick.humidity == null ? '' : hPick.humidity) : '';
      useTemp = (tPick && tPick.temp != null && tPick.temp !== '') ? String(tPick.temp) : '';
      pickTime = (tPick && tPick.time) || (hPick && hPick.time) || '';
    }
    if (humVal === '' && useTemp === '') { noData.push(k); continue; }
    if (!rec) {
      rec = { id: 'env_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), room, ym, cells: {}, updated_at: null };
      list.push(rec);
    }
    rec.cells[k] = { temp: useTemp, humidity: humVal, recorder: recorderText, signature_image: sigImg, strike: 0 };
    filled.push({ key: k, day: it.day, period: it.period, humidity: humVal, temp: useTemp, time: pickTime, strategy: strategy + (tPts.length ? '+th' : '') });
    touched = true;
  }

  // 第四步（可选）：补抓温度 —— 只处理「有湿度、温度为空、未划线」的格子
  const filledTemp = [];
  let backfillSkippedBudget = 0;
  if (backfillTemp && rec) {
    const want = [];
    const todayDayNum = Number(today.slice(8, 10));
    for (const k of Object.keys(rec.cells)) {
      const c = rec.cells[k];
      if (!c || c.strike) continue;
      if (c.humidity === '' || c.humidity == null) continue;      // 湿度都没有的格子等主源先填
      if (c.temp !== '' && c.temp != null) continue;              // 已有温度
      const m = /^(\d{1,2})_(AM|PM|Night)$/.exec(k);
      if (!m) continue;
      const day = parseInt(m[1], 10);
      if (day > maxDay) continue;                                 // 未来日期
      if (onlyPeriod && (m[2] !== onlyPeriod || day !== todayDayNum)) continue;   // v1.27.0 只抓当前时段
      if (tempScope === 'today' && day !== todayDayNum) continue;  // 只抓当天：历史温度走单独的补抓任务（异步、预算内）
      const ds = ym + '-' + String(day).padStart(2, '0');
      if (ds === today && ENV_PERIODS.indexOf(m[2]) > ENV_PERIODS.indexOf(curPeriod)) continue;   // 今天未来时段
      want.push({ k, ds, period: m[2] });
    }
    for (const w of want) {
      if (!tempBuckets[w.k] || !tempBuckets[w.k].length) {
        if (winUsed >= budget) { backfillSkippedBudget++; continue; }   // 与第二步共用窗口预算
        try {
          const win = LIMS_PERIOD_WINDOW[w.period] || LIMS_PERIOD_WINDOW.AM;
          const wpts = await limsFetchEnvWindow(cfg, token, tempSource, w.ds, win[0], win[1]);
          winUsed++;
          const withT = wpts.filter(x => x.temp != null && x.temp !== '');
          if (withT.length) tempBuckets[w.k] = withT;
        } catch (e) {
          logW('LIMS', '补抓温度窗口[' + tempSource + ' ' + w.ds + ' ' + w.period + '] 失败: ' + (e && e.message || e));
        }
        await new Promise(res => setTimeout(res, 200));
      }
      const pts = tempBuckets[w.k] || [];
      if (!pts.length) continue;
      const isCur = (ym === cur && Number(w.k.split('_')[0]) === Number(today.slice(8, 10)) && w.period === curPeriod);
      const pick = limsPickPoint(pts, (isCur && cfg.strategy !== 'nearest') ? 'nearest' : cfg.strategy);
      if (pick && pick.temp != null && pick.temp !== '') {
        rec.cells[w.k].temp = fmtTemp(pick.temp);
        filledTemp.push({ key: w.k, temp: fmtTemp(pick.temp), time: pick.time });
        touched = true;
      }
    }
    if (want.length) logI('LIMS', '补抓温度[' + room + '@' + ym + '] 候选=' + want.length + ' 补上=' + filledTemp.length + (backfillSkippedBudget ? ' 预算跳过=' + backfillSkippedBudget : ''));
  }
  if (touched) { rec.updated_at = new Date().toISOString(); kvset('envRecords', list); }
  if (filled.length) {
    const amap = {};
    filled.forEach(f => { amap[f.key] = { temp: f.temp, humidity: f.humidity }; });
    evalEnvAlerts(room, ym, amap, 'LIMS抓取');
  }
  if (onProgress) onProgress('完成：填充 ' + filled.length + ' 格' + (filledTemp.length ? '，补温度 ' + filledTemp.length + ' 格' : ''));
  return {
    ok: true, room, ym, source_room: source, mode: onlyToday ? 'day' : 'month',
    only_period: onlyPeriod, only_period_cn: onlyPeriod ? ENV_PERIOD_CN[onlyPeriod] : '',   // v1.27.0
    temp_source: tempSource || '', temp_mode: tDetail.mode, temp_note: tDetail.note,
    filled, filled_count: filled.length,
    // 温度写入格数 = 第一步整格写入里带温度的那些 + 第四步补抓的。
    // 只数第四步会让「整月同步连温度一起填满」显示成「本次没补到温度」，用户会以为又没抓上。
    filled_temp_count: filledTemp.length + filled.filter(f => f.temp !== '').length,
    skipped_existing: skippedExist.length, no_data: noData.length,
    temp_from_lims: filled.some(f => f.temp !== '') || filledTemp.length > 0,
    temp_windows_used: winUsed,
    temp_skipped_budget: tempSkippedBudget,
    with_temp: withTemp,
    points_total: points.length,
  };
}

// ---- LIMS 管理接口 ----
// GET /api/lims/config —— 读配置（密码打码）
async function handleLimsConfigGet(ctx) {
  const cfg = limsConfig();
  const passSet = !!cfg.pass;
  const out = Object.assign({}, cfg, { pass: '', pass_set: passSet });
  out.auto = Object.assign({}, cfg.auto);
  out.map_audit = limsMapAudit();     // 顺带把映射体检带上，后台一打开就能看到"房间对错"，无需点测试连接
  return sendJson(ctx.res, out);
}
// PUT /api/lims/config —— 保存配置（pass 留空 = 不改密码）
async function handleLimsConfigPut(ctx) {
  const b = ctx.body || {};
  const saved = kvget('lims', null) || {};
  const next = Object.assign({}, LIMS_DEFAULTS, saved);
  for (const k of ['enabled', 'base', 'user', 'pass', 'interfaceId', 'interfaceIdTh', 'recorder', 'strategy', 'overwrite']) {
    if (b[k] != null) next[k] = (k === 'enabled' || k === 'overwrite') ? !!b[k] : String(b[k]);
  }
  if (b.tempWindowBudget != null) {
    const n = Number(b.tempWindowBudget);
    next.tempWindowBudget = Number.isFinite(n) && n > 0 ? Math.min(200, Math.round(n)) : LIMS_DEFAULTS.tempWindowBudget;
  }
  if (!String(b.pass || '').trim()) next.pass = saved.pass || LIMS_DEFAULTS.pass;   // 留空 = 沿用
  if (b.roomAlias != null && typeof b.roomAlias === 'object' && !Array.isArray(b.roomAlias)) {
    const clean = {};
    for (const [k, v] of Object.entries(b.roomAlias)) {
      const kk = String(k).trim();
      if (!kk) continue;
      // v1.26.0：值支持数组 —— 同一个 LIMS 源给多个点检房间共用（源空闲时是真需求；
      // 老写法 String([...]) 会变成 "A,B" 这么个不存在的房间名，两间都拿不到源）。
      const arr = [...new Set((Array.isArray(v) ? v : [v]).map(x => String(x).trim()).filter(Boolean))];
      if (!arr.length) continue;
      clean[kk] = (arr.length === 1) ? arr[0] : arr;
    }
    next.roomAlias = clean;
  }
  if (b.limsRooms != null) {
    const arr = Array.isArray(b.limsRooms) ? b.limsRooms : String(b.limsRooms).split(/[\n,，]/);
    next.limsRooms = arr.map(s => String(s).trim()).filter(Boolean);
  }
  // allowShare：显式允许「与别的点检房间共用同一个 LIMS 源」的房间名（只认已存在的点检房间）
  if (b.allowShare != null || b.allow_share != null) {
    const raw = b.allowShare != null ? b.allowShare : b.allow_share;
    const arr = Array.isArray(raw) ? raw : String(raw).split(/[\n,，]/);
    const valid = kvget('rooms', []).map(r => r.name);
    next.allowShare = [...new Set(arr.map(s => String(s).trim()).filter(s => s && valid.includes(s)))];
  }
  // noFetch：显式「不参与抓取」的点检房间名（只认已存在的点检房间）
  if (b.noFetch != null || b.no_fetch != null) {
    const raw = b.noFetch != null ? b.noFetch : b.no_fetch;
    const arr = Array.isArray(raw) ? raw : String(raw).split(/[\n,，]/);
    const valid = kvget('rooms', []).map(r => r.name);
    next.noFetch = [...new Set(arr.map(s => String(s).trim()).filter(s => s && valid.includes(s)))];
  }
  // tempSource（v1.26.0）：温度数据源映射，点检房间名 → 'off' | LIMS 房间名
  //   空值 / 'auto' 一律不落库（= 跟随湿度源，避免库里堆一堆没意义的 auto）
  if (b.tempSource != null && typeof b.tempSource === 'object' && !Array.isArray(b.tempSource)) {
    const valid = kvget('rooms', []).map(r => r.name);
    const t = {};
    for (const [k, v] of Object.entries(b.tempSource)) {
      const kk = String(k).trim();
      if (!kk || !valid.includes(kk)) continue;              // 只认已存在的点检房间
      const vv = String(v == null ? '' : v).trim();
      if (!vv || vv === 'auto') continue;                    // 跟随湿度源 = 不落库
      t[kk] = (vv === 'off') ? 'off' : vv;
    }
    next.tempSource = t;
  }
  // unmapped（v1.26.0）：用户显式点「（未映射 · 不抓取）」的房间（只认已存在的点检房间）
  if (b.unmapped != null || b.unmapped_rooms != null) {
    const raw = b.unmapped != null ? b.unmapped : b.unmapped_rooms;
    const arr = Array.isArray(raw) ? raw : String(raw).split(/[\n,，]/);
    const valid = kvget('rooms', []).map(r => r.name);
    next.unmapped = [...new Set(arr.map(x => String(x).trim()).filter(x => x && valid.includes(x)))];
  }
  if (b.verifyDays != null) {
    const n = Number(b.verifyDays);
    next.verifyDays = Number.isFinite(n) && n >= 2 ? Math.min(31, Math.round(n)) : LIMS_DEFAULTS.verifyDays;
  }
  // 保存时顺手体检：把「LIMS 中不存在」的名字直接写进运行日志（不拦截保存，只提醒）
  const vmap = {};
  ((next.roomCheck && next.roomCheck.results) || []).forEach(x => { if (x && x.room) vmap[x.room] = x.verdict; });
  const suspicious = [...(next.limsRooms || []), ...Object.keys(next.roomAlias || {})].filter(n => vmap[n] === 'no_room');
  if (suspicious.length) logW('LIMS', '保存的 LIMS 房间名里有实测「LIMS 中不存在」的：' + [...new Set(suspicious)].join('、') + '（这些源抓不到数据）');
  if (b.auto != null && typeof b.auto === 'object') {
    next.auto = Object.assign({}, next.auto, b.auto);
    next.auto.enabled = !!b.auto.enabled;
    if (b.auto.times != null) {
      const arr = Array.isArray(b.auto.times) ? b.auto.times : String(b.auto.times).split(/[\n,，]/);
      next.auto.times = arr.map(s => String(s).trim()).filter(s => /^\d{1,2}:\d{2}$/.test(s)).map(s => {
        const [h, m] = s.split(':'); return String(+h).padStart(2, '0') + ':' + m;
      });
    }
  }
  kvset('lims', next);
  limsTokenCache = { token: '', base: '', user: '', at: 0 };   // 配置变了重登
  return sendJson(ctx.res, { ok: true });
}
// POST /api/lims/test —— 连通性测试：登录 + 抽一个房间拉整月湿度 + 温度通道探测 + 映射概览
async function handleLimsTest(ctx) {
  const cfg = limsConfig();
  const out = { base: cfg.base, user: cfg.user };
  // 映射体检与 LIMS 连通性无关，先算出来 —— 否则"不在 LIMS 网段、连不上"的机器（如本机）
  // 一点「测试连接」只看到超时，完全看不出映射对不对。这些字段现在无论连不连得上都会返回。
  const aud = limsMapAudit();
  out.map_audit = aud;                       // 映射全貌（含 via: same/alias）
  out.mapped_rooms = limsMappedRooms();
  out.mapped_detail = aud.mapped;
  out.conflicts = aud.conflicts;             // 一个 LIMS 源被多个点检房间占用 → 会填成同一份数据
  out.blocked_alias = aud.blocked_alias;     // 因冲突被作废的别名（原指向 + 原因）
  out.unmapped_rooms = aud.unmapped_rooms;   // 点检房间里没有 LIMS 数据源的
  out.unmapped_lims_rooms = aud.unused_lims_rooms;
  out.room_check = cfg.roomCheck || null;    // 最近一次「房间名实测校验」结果（供界面标注 ✅/⚠/❌）
  out.allow_share = cfg.allowShare || [];
  try {
    const token = await limsLogin(cfg);
    out.login_ok = true;
    const probeRoom = (cfg.limsRooms || [])[0] || '';
    const ym = currentMonthStr();
    const pts = await limsFetchHumidity(cfg, token, probeRoom, ym);
    out.probe_room = probeRoom;
    out.probe_month = ym;
    out.probe_points = pts.length;
    out.probe_first = pts.length ? pts[0].time : '';
    out.probe_last = pts.length ? pts[pts.length - 1].time : '';
    // 温度探测：temperatureHumidityList「今天当前时段」窗口（温度真实来源）。
    // temperatureChart 已弃用——其 t 恒为 null（读的是设备当前值表，LIMS 未写入）。
    try {
      const period = limsPeriodOf(new Date().getHours());
      const win = LIMS_PERIOD_WINDOW[period] || LIMS_PERIOD_WINDOW.AM;
      const wpts = await limsFetchEnvWindow(cfg, token, probeRoom, todayStr(), win[0], win[1]);
      const withT = wpts.filter(x => x.temp != null && x.temp !== '');
      out.temperature_available = withT.length > 0;
      if (withT.length) {
        out.temperature_value = String(withT[withT.length - 1].temp);
        out.temperature_points = withT.length;
        out.temperature_last_time = withT[withT.length - 1].time;
      }
    } catch (te) {
      out.temperature_available = false;
      out.temperature_error = String(te && te.message || te);
    }
    out.ok = true;
  } catch (e) {
    out.ok = false;
    out.error = String(e && e.message || e);
  }
  return sendJson(ctx.res, out);
}
// ===================== LIMS 异步任务（避免慢接口阻塞请求导致前端假死）=====================
const limsJobs = {};
function limsJobNew(label) {
  const id = 'LJ' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const job = { id, label, status: 'running', startedAt: new Date().toISOString(), progress: '排队中…', result: null, error: null };
  limsJobs[id] = job;
  const keys = Object.keys(limsJobs);
  if (keys.length > 60) { keys.sort((a, b) => limsJobs[a].startedAt < limsJobs[b].startedAt ? -1 : 1); for (const k of keys.slice(0, keys.length - 60)) delete limsJobs[k]; }
  return job;
}
function limsJobRun(job, fn) {
  (async () => {
    try {
      const res = await fn(job);
      job.result = res;
      if (res && typeof res === 'object' && res.error && job.status === 'running') { job.status = 'error'; job.error = res.error; if (!job.progress) job.progress = '失败'; }
      else if (job.status === 'running') { job.status = 'done'; if (!job.progress) job.progress = '完成'; }
    } catch (e) { job.error = e && e.message || String(e); job.status = 'error'; }
  })();
  return job;
}

// POST /api/lims/sync —— 抓单个房间（温湿度页「一键抓取」用）。改为异步任务：立即返回 jobId，前端轮询 /api/lims/job/:id
// body: { room, ym, mode:'day'|'month', overwrite?, with_temp?, temp_scope?:'today'|'all', signer_id?, password?, recorder? }
//   temp_scope='today'（默认，快）：仅抓当天温度；'all'（慢，异步）：历史温度逐窗补抓
async function handleLimsSync(ctx) {
  const b = ctx.body || {};
  let signer = null;
  if (b.signer_id) {
    const v = await verifySigner(b);
    if (v.error) return fail(ctx.res, v.error, v.error === '签名密码错误' ? 401 : 400);
    signer = v.signer;
  }
  if (!b.room || !/^\d{4}-\d{2}$/.test(String(b.ym || ''))) return fail(ctx.res, '房间与月份必填', 400);
  // 已配置「不抓取」的房间，即使是手动单个抓取也不允许（配置即「该房间不参与 LIMS 同步」）
  const cfg0 = limsConfig();
  if ((cfg0.noFetch || []).includes(b.room)) {
    return fail(ctx.res, '房间「' + b.room + '」已配置为「不抓取」，不参与 LIMS 同步', 409);
  }
  // v1.27.0 抓取范围收敛（普通用户只能抓「今天 + 当前时段」那一格）：
  //   为什么放在服务端：界面上把按钮文案改掉只是提示，能被人绕过去；
  //   真正拦住"改一下请求体就抓整月"的是这里 —— 越权请求进来也只落到那一格。
  //   管理员不受限（后台仍需按房间/整月补历史），保持原行为。
  const u = await getLoginUser(ctx.req);
  const isAdmin = !!(u && u.role === 'admin');
  const curM = currentMonthStr();
  const curP = limsPeriodOf(new Date().getHours());
  const ym = String(b.ym || '').trim();
  let mode = b.mode === 'day' ? 'day' : 'month';
  let onlyPeriod = '';
  let withTemp = b.with_temp == null ? undefined : !!b.with_temp;
  let tempScope = b.temp_scope || 'today';
  // 未显式给 backfill_temp 时跟随 with_temp：说了要温度就顺带把「有湿度缺温度」的格子补上
  let backfillTemp = b.backfill_temp == null ? !!b.with_temp : !!b.backfill_temp;
  if (!isAdmin) {
    if (ym !== curM) {
      return fail(ctx.res, '普通用户只能抓取当前时段（' + curM + ' 今天 ' + ENV_PERIOD_CN[curP] + '）；' +
        '历史月份的温湿度请让管理员在后台抓取或补填', 403);
    }
    mode = 'day'; onlyPeriod = curP;
    withTemp = true; tempScope = 'today'; backfillTemp = true;   // 当前时段就一个窗口，该抓的都抓上
    logI('LIMS', '普通用户 ' + ((u && u.username) || '?') + ' 抓取「' + b.room + '」→ 限制为 ' + curM + ' ' + ENV_PERIOD_CN[curP] + ' 时段');
  }
  const job = limsJobNew('抓取 ' + b.room + ' ' + ym + (onlyPeriod ? ' ' + ENV_PERIOD_CN[onlyPeriod] + '时段' : ''));
  limsJobRun(job, async (jb) => {
    jb.progress = '登录 LIMS…';
    return await limsSyncRoom({ room: b.room, ym, mode, overwrite: b.overwrite, onlyPeriod,
      withTemp, tempScope, backfillTemp,
      signer, recorder: b.recorder, onProgress: m => { jb.progress = m; } });
  });
  return sendJson(ctx.res, { ok: true, jobId: job.id, scope: onlyPeriod ? ('day:' + onlyPeriod) : 'month' });
}

// POST /api/lims/sync-all —— 抓全部有映射的房间（整月，串行，异步任务）
async function handleLimsSyncAll(ctx) {
  const b = ctx.body || {};
  const ym = String(b.ym || currentMonthStr()).trim();
  if (!/^\d{4}-\d{2}$/.test(ym)) return fail(ctx.res, '月份格式应为 YYYY-MM');
  if (ym > currentMonthStr()) return fail(ctx.res, '不能抓取未来月份（' + ym + '）');
  let signer = null;
  if (b.signer_id) {
    const v = await verifySigner(b);
    if (v.error) return fail(ctx.res, v.error, v.error === '签名密码错误' ? 401 : 400);
    signer = v.signer;
  }
  const aud = limsMapAudit();
  const rooms = limsMappedRooms();
  if (!rooms.length) return fail(ctx.res, '没有任何房间配置了 LIMS 数据源');
  if (aud.conflicts.length) logW('LIMS', '多个点检房间共用一个 LIMS 源（会填成同一份数据）：' + aud.conflicts.map(c => '「' + c.source + '」← ' + c.rooms.join('、')).join('；'));
  if (aud.blocked_alias.length) logW('LIMS', '以下房间的 LIMS 映射已暂停（未在允许共用的名单里），本次不会同步：' + aud.blocked_alias.map(x => x.room + '（原指向「' + x.source + '」）').join('、'));
  if (aud.invalid_sources.length) logW('LIMS', '映射用到的 LIMS 源名实测「LIMS 中不存在」，这些房间必然抓不到数据：' + aud.invalid_sources.join('、'));
  if (aud.empty_sources.length) logW('LIMS', '映射用到的 LIMS 源房间实测无数据（未挂温湿度计）：' + aud.empty_sources.join('、'));
  const job = limsJobNew('整月同步 ' + ym);
  limsJobRun(job, async (jb) => {
    const results = []; let filledTotal = 0, tempFilledTotal = 0;
    for (let i = 0; i < rooms.length; i++) {
      const room = rooms[i];
      jb.progress = '同步 ' + room + '（' + (i + 1) + '/' + rooms.length + '）';
      try {
        // v1.26.0：整月同步**默认连温度一起抓**（含把「有湿度但缺温度」的格子补上）。
        //   旧默认 with_temp 缺省 = false，是「一键抓整月温湿度却拿不到温度」的直接原因；
        //   后台那两个按钮（同步整月 / 补全房间历史温度）也已按用户要求合并成一个。
        const r = await limsSyncRoom({ room, ym, mode: 'month', overwrite: b.overwrite,
          withTemp: b.with_temp == null ? true : !!b.with_temp,
          tempScope: b.temp_scope || 'all',
          backfillTemp: b.backfill_temp == null ? true : !!b.backfill_temp, signer });
        if (r.error) results.push({ room, error: r.error });
        else {
          results.push({ room, source: r.source_room, temp_source: r.temp_source, temp_mode: r.temp_mode,
            filled: r.filled_count, temp_filled: r.filled_temp_count, skipped: r.skipped_existing,
            no_data: r.no_data, temp_from_lims: r.temp_from_lims, temp_skipped_budget: r.temp_skipped_budget });
          filledTotal += r.filled_count; tempFilledTotal += r.filled_temp_count;
        }
      } catch (e) { results.push({ room, error: String(e && e.message || e) }); }
      await new Promise(res => setTimeout(res, 300));   // 温和限速，别轰炸 LIMS
    }
    jb.progress = '完成';
    return { ok: true, ym, rooms: rooms.length, filled_total: filledTotal, temp_filled_total: tempFilledTotal, results, map_audit: aud };
  });
  return sendJson(ctx.res, { ok: true, jobId: job.id });
}

// GET /api/lims/room-status?room=X —— 某房间能不能抓（供温湿度页决定「⬇ LIMS 抓取」按钮是否可点）
//   v1.26.0：房间「未映射」「不抓取」「映射被暂停」「LIMS 停用」时，按钮直接禁用并写明原因 ——
//   也就是「未映射状态下应无法选择、不予抓取」在界面上的落点（不再让用户点完才吃一个 409）。
async function handleLimsRoomStatus(ctx) {
  const cfg = limsConfig();
  const room = String(ctx.query.get('room') || '').trim();
  const detail = limsSourceRoomDetail(cfg, room);
  const t = limsTempSourceDetail(cfg, room);
  const noFetch = (cfg.noFetch || []).includes(room);
  let fetchable = true, reason = '';
  if (!cfg.enabled) { fetchable = false; reason = '后台已停用 LIMS 数据源'; }
  else if (noFetch) { fetchable = false; reason = '该房间已设为「不抓取」，需手工填写'; }
  else if (detail.blocked) { fetchable = false; reason = '映射已暂停：指向「' + detail.blocked + '」，需在后台勾选「允许共用同一数据源」'; }
  else if (!detail.source && !t.source) {
    fetchable = false;
    reason = (detail.via === 'unmapped') ? '该房间已设为「未映射 · 不抓取」，需手工填写' : '该房间未映射 LIMS 数据源';
  }
  // v1.27.0：把「服务器今天 / 当前时段 / 调用者是否管理员」一并给前端 ——
  //   前端据此把按钮写成「⬇ 抓取当前时段·下午」并在非本月时直接禁用，
  //   时段口径只此一处（limsPeriodOf），前端不自己算，免得两边边界不一致。
  const u0 = await getLoginUser(ctx.req);
  const cp = limsPeriodOf(new Date().getHours());
  return sendJson(ctx.res, {
    room, enabled: !!cfg.enabled, fetchable, reason,
    humid_source: detail.source || '', via: detail.via || '', unmapped: detail.via === 'unmapped', no_fetch: noFetch,
    temp_source: t.source || '', temp_mode: t.mode, temp_note: t.note,
    role: (u0 && u0.role) || '', is_admin: !!(u0 && u0.role === 'admin'),
    today: todayStr(), cur_month: currentMonthStr(),
    cur_period: cp, cur_period_cn: ENV_PERIOD_CN[cp],
  });
}

// POST /api/lims/verify-rooms —— 逐个实测「房间名在 LIMS 里到底存不存在」（异步任务）
// body: { rooms?: string[] }  默认 = limsRooms ∪ 当前映射用到的源 ∪ 全部点检房间名（去重）
// 结果落盘 kv.lims.roomCheck，后台一打开就能看到 ✅/⚠/❌，不必每次重跑（每次约 7~8 秒/房间）。
async function handleLimsVerifyRooms(ctx) {
  const cfg = limsConfig();
  const b = ctx.body || {};
  const list = (Array.isArray(b.rooms) && b.rooms.length)
    ? [...new Set(b.rooms.map(s => String(s).trim()).filter(Boolean))]
    : limsVerifyCandidates(cfg);
  if (!list.length) return fail(ctx.res, '没有需要校验的房间名', 400);
  const days = Math.max(2, Math.min(31, +(b.days || cfg.verifyDays) || LIMS_DEFAULTS.verifyDays));
  const job = limsJobNew('房间名实测校验（' + list.length + ' 个 · 回看 ' + days + ' 天）');
  limsJobRun(job, async (jb) => {
    jb.progress = '登录 LIMS…';
    const token = await limsLogin(cfg);
    const results = [];
    for (let i = 0; i < list.length; i++) {
      jb.progress = '校验「' + list[i] + '」（' + (i + 1) + '/' + list.length + '，每个约 8 秒）';
      results.push(await limsProbeRoomName(cfg, token, list[i], days));
    }
    const at = new Date().toISOString();
    const saved = Object.assign({}, kvget('lims', null) || {});
    // 全量校验（未指定 rooms）= 直接覆盖；只校验个别名字（如「加入清单」时的单个核实）= 合并进旧结果，
    // 否则加一个名字就会把之前 20 多个房间的校验结论全洗掉。
    const isFull = !(Array.isArray(b.rooms) && b.rooms.length);
    let merged = results;
    if (!isFull) {
      const mmap = {};
      ((saved.roomCheck && saved.roomCheck.results) || []).forEach(x => { if (x && x.room) mmap[x.room] = x; });
      results.forEach(x => { mmap[x.room] = x; });
      merged = Object.values(mmap);
    }
    saved.roomCheck = { at, days, base: cfg.base, results: merged, full: isFull };
    kvset('lims', saved);
    const bad = results.filter(x => x.verdict === 'no_room');
    const empty = results.filter(x => x.verdict === 'empty');
    const errs = results.filter(x => x.verdict === 'error');
    if (bad.length) logW('LIMS', '房间名实测：以下名字在 LIMS 中不存在（写错或该房间未在 LIMS 登记）→ ' + bad.map(x => x.room).join('、'));
    if (empty.length) logW('LIMS', '房间名实测：以下房间在 LIMS 存在但回看 ' + days + ' 天无数据（未挂温湿度计）→ ' + empty.map(x => x.room).join('、'));
    if (errs.length) logW('LIMS', '房间名实测：以下房间探测失败 → ' + errs.map(x => x.room + '(' + x.msg + ')').join('、'));
    jb.progress = '完成';
    return {
      ok: true, at, days, base: cfg.base, total: results.length, full: isFull,
      ok_count: results.filter(x => x.verdict === 'ok').length,
      empty_count: empty.length, bad_count: bad.length, error_count: errs.length,
      bad_list: bad.map(x => x.room), empty_list: empty.map(x => x.room),
      results, all_results: merged,
    };
  });
  return sendJson(ctx.res, { ok: true, jobId: job.id });
}

// GET /api/lims/job/:id —— 轮询异步任务状态（前端进度条用）
async function handleLimsJob(ctx) {
  const job = limsJobs[ctx.params.id];
  if (!job) return fail(ctx.res, '任务不存在或已过期', 404);
  return sendJson(ctx.res, { id: job.id, label: job.label, status: job.status, progress: job.progress, startedAt: job.startedAt, result: job.result, error: job.error });
}

// ---- LIMS 定时自动填充（服务内置，无需外部计划任务） ----
// 到点后对当天做一次 limsSyncRoom（mode=day，只补空格）：
// 早上的跑填上午格、午后的跑填下午格、晚上的跑填晚上格 —— 更早的时段已填过会被自动跳过。
// 结果摘要写入 kv.lims.lastAuto 供后台查看；进程内存去重，同一时刻槽一天只跑一次。
const limsAutoStateKey = (day, slot) => day + '@' + slot;
let limsAutoLastKey = '';
let limsAutoRunning = false;
async function limsAutoTick() {
  if (limsAutoRunning) return;
  const cfg = limsConfig();
  if (!cfg.enabled || !cfg.auto || !cfg.auto.enabled) return;
  const times = cfg.auto.times || [];
  const now = new Date();
  const nowMin = now.getHours() * 60 + now.getMinutes();
  const dayKey = todayStr();
  const slot = times.find(t => {
    const [h, m] = String(t).split(':').map(Number);
    if (!Number.isFinite(h) || !Number.isFinite(m)) return false;
    const s = h * 60 + m;
    return nowMin >= s && nowMin < s + 5 && limsAutoStateKey(dayKey, t) !== limsAutoLastKey;
  });
  if (!slot) return;
  limsAutoLastKey = limsAutoStateKey(dayKey, slot);
  limsAutoRunning = true;
  const startedAt = new Date().toISOString();
  const aud0 = limsMapAudit();
  console.log('[LIMS自动] ' + startedAt + ' 触发时段 ' + slot + '，房间 ' + limsMappedRooms().join('/'));
  // 映射异常写运行日志：否则用户只能看到「某房间的数据跟另一个房间一模一样」却找不到原因
  if (aud0.conflicts.length) logW('LIMS', '多个点检房间共用一个 LIMS 源（会填成同一份数据）：' + aud0.conflicts.map(c => '「' + c.source + '」← ' + c.rooms.join('、')).join('；'));
  if (aud0.blocked_alias.length) logW('LIMS', '以下房间的 LIMS 映射已暂停（未在允许共用的名单里），不会自动填充：' + aud0.blocked_alias.map(x => x.room + '（原指向「' + x.source + '」）').join('、'));
  if (aud0.invalid_sources.length) logW('LIMS', '映射用到的 LIMS 源名实测「LIMS 中不存在」，这些房间抓不到数据：' + aud0.invalid_sources.join('、'));
  const results = [];
  try {
    for (const room of limsMappedRooms()) {
      try {
        const r = await limsSyncRoom({ room, ym: currentMonthStr(), mode: 'day', recorder: cfg.auto.recorder || cfg.recorder });
        results.push(r.error ? { room, error: r.error } : { room, filled: r.filled_count, skipped: r.skipped_existing, temp_from_lims: r.temp_from_lims });
      } catch (e) {
        results.push({ room, error: String(e && e.message || e) });
      }
      await new Promise(res => setTimeout(res, 300));
    }
  } finally {
    limsAutoRunning = false;
    const c = kvget('lims', {}) || {};
    kvset('lims', Object.assign({}, c, { lastAuto: { at: new Date().toISOString(), slot, results } }));
    const okN = results.filter(r => !r.error && r.filled > 0).length;
    console.log('[LIMS自动] 完成：成功 ' + okN + '/' + results.length + ' 房间');
  }
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

// POST /api/admin/restore —— 导入数据备份（整份替换内存数据并落盘；导入前自动备份当前数据，可回滚）
async function handleRestore(ctx) {
  const incoming = ctx.body;
  if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming))
    return fail(ctx.res, '备份数据必须是 JSON 对象（即「下载数据备份」得到的 kv-backup-*.json 内容）', 400);
  const KNOWN = ['admin', 'devices', 'templates', 'signers', 'inspections', 'abnormalRecords', 'rooms', 'depts', 'envRecords', 'users', 'lims', 'lanUpgrade', 'lanClients', 'envfill'];
  if (!KNOWN.some(k => k in incoming)) return fail(ctx.res, '备份数据缺少已知字段，可能不是有效的数据备份文件', 400);
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const bak = path.join(DATA_DIR, 'kv-restore-backup-' + ts + '.json');
  try { fs.writeFileSync(bak, JSON.stringify(store, null, 2), 'utf8'); } catch (e) { return fail(ctx.res, '备份当前数据失败：' + e.message, 500); }
  const defaults = { admin: null, devices: [], templates: [], signers: [], inspections: [], abnormalRecords: [], rooms: [], depts: [], envRecords: [] };
  store = Object.assign({}, defaults, incoming);
  try {
    await fs.promises.mkdir(DATA_DIR, { recursive: true });
    await fs.promises.writeFile(DATA_FILE, JSON.stringify(store, null, 2), 'utf8');
  } catch (e) { return fail(ctx.res, '写入数据失败：' + e.message, 500); }
  scheduleSave();
  logI('SYSTEM', '后台「导入数据备份」整份替换了数据（已自动备份至 ' + path.basename(bak) + '）');
  return sendJson(ctx.res, { ok: true, backup: path.basename(bak), counts: {
    devices: (store.devices || []).length, rooms: (store.rooms || []).length, users: (store.users || []).length,
    inspections: (store.inspections || []).length, signers: (store.signers || []).length } });
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
// ===================== 温湿度预警提醒（v1.21.0）=====================
// 配置结构（kv.envAlertCfg）：enabled / cooldownHours / channels{inApp,banner} /
//   defaults{tMin,tMax,hMin,hMax}（全局默认阈值，null=不判定）/ rooms{房间名:{...}}（按房间覆盖）/
//   recipients{byDept:{科室名:[用户id…]}, all:[用户id…]}
// 接收人匹配规则：触发房间 → room.dept 得科室 → 通知 byDept[科室] 勾选人员 ∪ all 跨科室人员；
//   房间未设科室 → 仅 all 跨科室人员收到。只通知在册且未停用的用户。
const ENV_ALERT_DEFAULTS = {
  enabled: true,
  cooldownHours: 12,
  // v1.25.0：阈值默认「跟着房间的温湿度要求走」，后台不必再逐个房间手配
  useRoomReq: true,
  // 一个房间列了多条温度标准时（如冲击室 ASTM E23-25 与 GB/T229-2020 各一个范围）怎么合：
  //   union = 并集（宽，只要有一条标准容得下就不报）/ intersect = 交集（严，要同时满足所有标准）
  multiStd: 'union',
  channels: { inApp: true, banner: true },
  defaults: { tMin: 15, tMax: 30, hMin: null, hMax: 70 },
  rooms: {},
  recipients: { byDept: {}, all: [] }
};
const ENV_ALERT_KINDS = { temp_high: '温度超上限', temp_low: '温度低于下限', hum_high: '湿度超上限', hum_low: '湿度低于下限' };
const ENV_PERIOD_CN2 = { AM: '上午', PM: '下午', Night: '晚上' };
function envAlertCfgRaw() { return kvget('envAlertCfg', null) || {}; }
// 「房间有没有写要求」——空文本，或只写了 — / - / ～ 这类占位符，都算没写
function envReqText(roomName) {
  const roomObj = kvget('rooms', []).find(r => r.name === roomName) || {};
  const txt = String(roomObj.thermo_requirement || '').trim();
  const empty = !txt || /^[-—–~～/、,，\s]+$/.test(txt);
  return { roomObj, txt, empty };
}
// 房间生效阈值（v1.25.0 起的口径）：
//   ① 后台「按房间覆盖」里手填的数字（最高优先，只覆盖填了的那一项）
//   ② 房间自己的「温湿度要求」自动解析（默认走这条，后台无需配置）
//   ③ 全局默认阈值（仅当该房间压根没写要求时兜底）
// 房间要求里没写的指标（如硬度室没写湿度、金相试样间温度写「—」）= 不判定（null），
// 不再拿全局默认去凑——否则会给没有依据的指标报预警。
function envAlertLimits(room) {
  const cfg = envAlertCfgRaw();
  const d = cfg.defaults || ENV_ALERT_DEFAULTS.defaults;
  const num = v => (v == null || v === '' || isNaN(Number(v))) ? null : Number(v);
  const o = (cfg.rooms && cfg.rooms[room]) || {};
  const { txt, empty } = envReqText(room);
  const req = (cfg.useRoomReq !== false && !empty) ? parseEnvLimits(txt, cfg.multiStd) : null;
  const base = req
    ? { tMin: req.tMin, tMax: req.tMax, hMin: null, hMax: req.hMax, src: 'room' }
    : { tMin: num(d.tMin), tMax: num(d.tMax), hMin: num(d.hMin), hMax: num(d.hMax), src: empty ? 'default' : 'off' };
  const has = f => o[f] != null && o[f] !== '' && !isNaN(Number(o[f]));
  const pick = f => has(f) ? Number(o[f]) : base[f];
  return {
    tMin: pick('tMin'), tMax: pick('tMax'), hMin: pick('hMin'), hMax: pick('hMax'),
    src: ['tMin', 'tMax', 'hMin', 'hMax'].some(has) ? 'override' : base.src,
    reqText: txt
  };
}
// 对刚写入/保存的格子做阈值判定并生成预警+站内通知（去重：同房+同格+同指标 未确认的不重报；已确认的在冷却期内不重报）
function evalEnvAlerts(room, ym, cells, source) {
  try {
    const cfg = Object.assign({}, ENV_ALERT_DEFAULTS, envAlertCfgRaw());
    if (!cfg.enabled) return { skipped: 'disabled' };
    const roomObj = kvget('rooms', []).find(r => r.name === room) || {};
    const dept = roomObj.dept || '';
    const L = envAlertLimits(room);
    const alerts = kvget('envAlerts', []);
    const notifs = kvget('notifs', []);
    const users = kvget('users', []);
    const activeById = {}; users.forEach(u => { activeById[u.id] = u; });
    const ids = [];
    const push = id => { if (id && activeById[id] && activeById[id].active !== false && !ids.includes(id)) ids.push(id); };
    ((cfg.recipients && cfg.recipients.all) || []).forEach(push);
    ((cfg.recipients && cfg.recipients.byDept && cfg.recipients.byDept[dept]) || []).forEach(push);
    const now = Date.now();
    const cooldownMs = (Number(cfg.cooldownHours) > 0 ? Number(cfg.cooldownHours) : 12) * 3600 * 1000;
    let raised = 0, suppressed = 0;
    for (const k of Object.keys(cells || {})) {
      const c = cells[k] || {};
      if (c.strike) continue;
      const m = /^(\d{1,2})_(AM|PM|Night)$/.exec(k); if (!m) continue;
      const t = parseFloat(c.temp), h = parseFloat(c.humidity);
      const checks = [];
      if (Number.isFinite(t)) {
        if (L.tMax != null && t > L.tMax) checks.push(['temp_high', t]);
        if (L.tMin != null && t < L.tMin) checks.push(['temp_low', t]);
      }
      if (Number.isFinite(h)) {
        if (L.hMax != null && h > L.hMax) checks.push(['hum_high', h]);
        if (L.hMin != null && h < L.hMin) checks.push(['hum_low', h]);
      }
      for (const [kind, val] of checks) {
        const prev = alerts.find(a => a.room === room && a.ym === ym && a.key === k && a.kind === kind);
        if (prev && (prev.status === 'open' || (now - new Date(prev.at).getTime()) < cooldownMs)) { suppressed++; continue; }
        const alert = { id: 'al_' + now.toString(36) + Math.random().toString(36).slice(2, 6), room, dept, ym, key: k, day: parseInt(m[1], 10), period: m[2], kind, value: val,
          limits: { tMin: L.tMin, tMax: L.tMax, hMin: L.hMin, hMax: L.hMax, src: L.src }, source: source || '', at: new Date().toISOString(), status: 'open', ack_by: null, ack_at: null };
        alerts.push(alert);
        raised++;
        const limTxt = (kind.indexOf('temp') === 0) ? (kind === 'temp_high' ? '≤' + L.tMax : '≥' + L.tMin) : (kind === 'hum_high' ? '≤' + L.hMax : '≥' + L.hMin);
        const msg = '【' + room + '】' + alert.day + '日' + (ENV_PERIOD_CN2[m[2]] || m[2]) + ' ' + ENV_ALERT_KINDS[kind] + '：当前 ' + val + '（限 ' + limTxt + '）';
        logW('预警', msg + ' [' + (source || '') + ']');
        for (const uid of ids) {
          notifs.push({ id: 'nt_' + now.toString(36) + Math.random().toString(36).slice(2, 6), to: uid, alert_id: alert.id, title: '🌡 温湿度预警：' + room, body: msg, at: alert.at, read: 0 });
        }
      }
    }
    if (raised) kvset('envAlerts', alerts.slice(-2000));
    if (raised && ids.length) kvset('notifs', notifs.slice(-4000));
    return { raised, suppressed, notified: ids.length };
  } catch (e) { logE('预警', '判定失败: ' + (e && e.message || e)); return { error: String(e && e.message || e) }; }
}
// GET /api/admin/env-alert-cfg —— 读配置（管理员）
async function handleEnvAlertCfgGet(ctx) {
  const cfg = Object.assign({}, ENV_ALERT_DEFAULTS, envAlertCfgRaw());
  // 顺带回传「自动抓取结果」：后台要能一眼看出每个房间的阈值是从哪来的、抓到了什么
  const effective = kvget('rooms', []).map(r => {
    const { txt, empty } = envReqText(r.name);
    const parsed = (cfg.useRoomReq !== false && !empty) ? parseEnvLimits(txt, cfg.multiStd) : null;
    const L = envAlertLimits(r.name);
    return {
      name: r.name, dept: r.dept || '', requirement: txt, empty,
      parsed: parsed ? { tMin: parsed.tMin, tMax: parsed.tMax, hMax: parsed.hMax, stdCount: parsed.stdCount } : null,
      effective: { tMin: L.tMin, tMax: L.tMax, hMin: L.hMin, hMax: L.hMax }, src: L.src
    };
  });
  return sendJson(ctx.res, { ok: true, cfg, effective });
}
// PUT /api/admin/env-alert-cfg —— 清洗保存（管理员）
async function handleEnvAlertCfgPut(ctx) {
  const b = ctx.body || {};
  const num = v => (v === '' || v == null || isNaN(Number(v))) ? null : Number(v);
  const next = {
    enabled: b.enabled !== false,
    useRoomReq: b.useRoomReq !== false,
    multiStd: b.multiStd === 'intersect' ? 'intersect' : 'union',
    cooldownHours: Math.max(1, Number(b.cooldownHours) || 12),
    channels: { inApp: !!(b.channels && b.channels.inApp), banner: !!(b.channels && b.channels.banner) },
    defaults: {
      tMin: num(b.defaults && b.defaults.tMin), tMax: num(b.defaults && b.defaults.tMax),
      hMin: num(b.defaults && b.defaults.hMin), hMax: num(b.defaults && b.defaults.hMax)
    },
    rooms: {},
    recipients: { byDept: {}, all: [] }
  };
  if (b.rooms && typeof b.rooms === 'object') {
    for (const rk of Object.keys(b.rooms)) {
      const o = b.rooms[rk] || {};
      if (!o || typeof o !== 'object') continue;
      if (!['tMin', 'tMax', 'hMin', 'hMax'].some(f => o[f] != null && o[f] !== '')) continue;
      next.rooms[String(rk)] = { tMin: num(o.tMin), tMax: num(o.tMax), hMin: num(o.hMin), hMax: num(o.hMax) };
    }
  }
  const users = kvget('users', []);
  const uids = new Set(users.map(u => u.id));
  const cleanIds = arr => Array.isArray(arr) ? [...new Set(arr.map(String).filter(x => uids.has(x)))] : [];
  if (b.recipients && typeof b.recipients === 'object') {
    if (b.recipients.byDept && typeof b.recipients.byDept === 'object') {
      for (const dk of Object.keys(b.recipients.byDept)) next.recipients.byDept[String(dk)] = cleanIds(b.recipients.byDept[dk]);
    }
    next.recipients.all = cleanIds(b.recipients.all);
  }
  kvset('envAlertCfg', next);
  logI('预警', '预警配置已更新' + (next.enabled ? '' : '（已停用）'));
  return sendJson(ctx.res, { ok: true, cfg: next });
}
// GET /api/env-alerts —— 预警列表（admin 全部；普通用户限本科室房间）
async function handleEnvAlertsList(ctx) {
  const u = await getLoginUser(ctx.req);
  if (!u) return fail(ctx.res, '未登录或登录已失效', 401);
  let rows = kvget('envAlerts', []);
  if (u.role !== 'admin') {
    const dept = u.dept || '';
    const roomNames = new Set(kvget('rooms', []).filter(r => (r.dept || '') === dept).map(r => r.name));
    rows = rows.filter(a => roomNames.has(a.room));
  }
  const status = ctx.query.get('status') || '';
  const room = ctx.query.get('room') || '';
  if (status) rows = rows.filter(a => a.status === status);
  if (room) rows = rows.filter(a => a.room === room);
  return sendJson(ctx.res, { ok: true, rows: rows.slice(-500).reverse() });
}
// POST /api/env-alerts/ack —— 确认预警（admin 或被通知人）
async function handleEnvAlertAck(ctx) {
  const u = await getLoginUser(ctx.req);
  if (!u) return fail(ctx.res, '未登录或登录已失效', 401);
  const b = ctx.body || {};
  const ids = Array.isArray(b.ids) ? b.ids.map(String) : [];
  if (!ids.length) return fail(ctx.res, '缺少 ids');
  const alerts = kvget('envAlerts', []);
  const notifs = kvget('notifs', []);
  const myAlertIds = new Set(u.role === 'admin' ? [] : notifs.filter(x => x.to === u.id).map(x => x.alert_id));
  let n = 0;
  for (const a of alerts) {
    if (!ids.includes(a.id) || a.status !== 'open') continue;
    if (u.role !== 'admin' && !myAlertIds.has(a.id)) continue;
    a.status = 'acked'; a.ack_by = u.name || u.username; a.ack_at = new Date().toISOString(); n++;
  }
  if (n) kvset('envAlerts', alerts);
  return sendJson(ctx.res, { ok: true, acked: n });
}
// GET /api/notifs —— 我的站内通知
async function handleNotifsList(ctx) {
  const u = await getLoginUser(ctx.req);
  if (!u) return fail(ctx.res, '未登录或登录已失效', 401);
  const rows = kvget('notifs', []).filter(x => x.to === u.id).slice(-200).reverse();
  return sendJson(ctx.res, { ok: true, unread: rows.filter(x => !x.read).length, rows });
}
// POST /api/notifs/read —— 标记已读 {ids:[…]} 或 {all:true}
async function handleNotifsRead(ctx) {
  const u = await getLoginUser(ctx.req);
  if (!u) return fail(ctx.res, '未登录或登录已失效', 401);
  const b = ctx.body || {};
  const notifs = kvget('notifs', []);
  let n = 0;
  for (const x of notifs) {
    if (x.to !== u.id || x.read) continue;
    if (b.all || (Array.isArray(b.ids) && b.ids.includes(x.id))) { x.read = 1; n++; }
  }
  if (n) kvset('notifs', notifs);
  return sendJson(ctx.res, { ok: true, read: n });
}
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
  { method: 'GET', path: '/api/env/alerts', handler: handleEnvAlerts },

  // ---------- 独立检查项目（与设备点检分开的专项检查） ----------
  { method: 'GET', path: '/api/programs', handler: handleListPrograms },
  { method: 'GET', path: '/api/settings', handler: handleGetSettings },
  { method: 'PUT', path: '/api/admin/settings', handler: handlePutSettings, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/programs\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateProgram, adminOnly: true },
  { method: 'GET', path: '/api/check-records', handler: handleListCheckRecords },
  { method: 'POST', path: '/api/check-records', handler: handleSaveCheckRecord },
  { method: 'POST', path: '/api/check-records/sign', handler: handleSignCheckCell },

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

  // ---- 模板（写操作可授权给「点检模板管理」用户） ----
  { method: 'POST', path: '/api/templates', handler: handleCreateTemplate, adminOnly: true, perm: 'tpl_edit' },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleAddTemplateItem, adminOnly: true, perm: 'tpl_edit' },
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateTemplate, adminOnly: true, perm: 'tpl_edit' },
  { method: 'PUT', pattern: /^\/api\/templates\/([^/]+)\/items$/, paramNames: ['id'], handler: handleSaveTemplateItems, adminOnly: true, perm: 'tpl_edit' },
  { method: 'POST', pattern: /^\/api\/templates\/([^/]+)\/duplicate$/, paramNames: ['id'], handler: handleDuplicateTemplate, adminOnly: true, perm: 'tpl_edit' },
  { method: 'DELETE', pattern: /^\/api\/templates\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteTemplate, adminOnly: true, perm: 'tpl_edit' },
  { method: 'POST', path: '/api/admin/import-template', handler: handleImportTemplate, adminOnly: true, perm: 'tpl_edit' },

  // ---- 设备 ----
  { method: 'POST', path: '/api/devices', handler: handleCreateDevice, adminOnly: true },
  { method: 'POST', path: '/api/devices/batch', handler: handleBatchCreateDevices, adminOnly: true },
  { method: 'POST', path: '/api/devices/import', handler: handleImportDevices, adminOnly: true },
  { method: 'POST', path: '/api/devices/batch-delete', handler: handleBatchDeleteDevices, adminOnly: true },
  { method: 'PUT', pattern: /^\/api\/devices\/([^/]+)$/, paramNames: ['id'], handler: handleUpdateDevice, adminOnly: true },
  { method: 'DELETE', pattern: /^\/api\/devices\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteDevice, adminOnly: true },

  // ---- 点检记录（删除类可授权给「批量点检操作」用户） ----
  { method: 'GET', path: '/api/inspections', handler: handleListInspections, adminOnly: true },
  { method: 'POST', path: '/api/inspections/batch-delete', handler: handleBatchDeleteInspections, adminOnly: true, perm: 'inspect_batch' },
  { method: 'DELETE', pattern: /^\/api\/inspections\/([^/]+)$/, paramNames: ['id'], handler: handleDeleteInspection, adminOnly: true, perm: 'inspect_batch' },

  // ---- 点检操作 ----
  { method: 'POST', path: '/api/inspect/batch', handler: handleInspectBatch, adminOnly: true, perm: 'inspect_batch' },
  { method: 'POST', path: '/api/inspect/day-sig', handler: handleDaySign },
  { method: 'POST', path: '/api/inspect/month', handler: handleInspectMonth },
  { method: 'POST', path: '/api/inspect/delete', handler: handleInspectDelete, adminOnly: true, perm: 'inspect_batch' },
  { method: 'GET', pattern: /^\/api\/inspect\/device\/([^/]+)$/, paramNames: ['id'], handler: handleDeviceDetail },

  // ---- 整月一键操作（可授权给「批量点检操作」用户） ----
  { method: 'POST', path: '/api/admin/inspect-month', handler: handleAdminInspectMonth, adminOnly: true, perm: 'inspect_batch' },
  { method: 'POST', path: '/api/admin/cancel-inspect-month', handler: handleAdminCancelInspectMonth, adminOnly: true, perm: 'inspect_batch' },
  { method: 'POST', path: '/api/admin/check-month', handler: handleAdminCheckMonth, adminOnly: true, perm: 'inspect_batch' },

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
  // ---- 温湿度预警（v1.21.0）----
  { method: 'GET', path: '/api/admin/env-alert-cfg', handler: handleEnvAlertCfgGet, adminOnly: true },
  { method: 'PUT', path: '/api/admin/env-alert-cfg', handler: handleEnvAlertCfgPut, adminOnly: true },
  { method: 'GET', path: '/api/env-alerts', handler: handleEnvAlertsList },
  { method: 'POST', path: '/api/env-alerts/ack', handler: handleEnvAlertAck },
  { method: 'GET', path: '/api/notifs', handler: handleNotifsList },
  { method: 'POST', path: '/api/notifs/read', handler: handleNotifsRead },
  { method: 'POST', path: '/api/admin/env-fill', handler: handleEnvFill, adminOnly: true, perm: 'env_fill' },
  { method: 'GET', path: '/api/admin/env-range', handler: handleEnvRangeGet, adminOnly: true, perm: 'env_fill' },
  { method: 'PUT', path: '/api/admin/env-range', handler: handleEnvRangePut, adminOnly: true, perm: 'env_fill' },
  { method: 'POST', path: '/api/admin/env-records/delete', handler: handleEnvRecordsDelete, adminOnly: true, perm: 'env_delete' },
  { method: 'GET', path: '/api/admin/env-records/export-csv', handler: handleExportEnvCsv, adminOnly: true, perm: 'export' },

  // ---- LIMS 温湿度实时数据源 ----
  { method: 'GET',  path: '/api/lims/config',   handler: handleLimsConfigGet, adminOnly: true },
  { method: 'PUT',  path: '/api/lims/config',   handler: handleLimsConfigPut, adminOnly: true },
  { method: 'POST', path: '/api/lims/test',     handler: handleLimsTest,      adminOnly: true },
  { method: 'GET',  path: '/api/lims/room-status', handler: handleLimsRoomStatus, perm: 'env_fill' },    // 某房间能不能抓（温湿度页按钮用）
  { method: 'POST', path: '/api/lims/verify-rooms', handler: handleLimsVerifyRooms, adminOnly: true },   // 房间名实测校验（异步）
  { method: 'POST', path: '/api/lims/sync',     handler: handleLimsSync, adminOnly: true, perm: 'env_fill' },   // 温湿度页「一键抓取」
  { method: 'POST', path: '/api/lims/sync-all', handler: handleLimsSyncAll, adminOnly: true, perm: 'env_fill' },
  { method: 'GET',  pattern: /^\/api\/lims\/job\/([^/]+)$/, paramNames: ['id'], handler: handleLimsJob, adminOnly: true, perm: 'env_fill' },   // 异步任务进度轮询

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
  { method: 'POST', path: '/api/admin/restore', handler: handleRestore, adminOnly: true },
  { method: 'GET', path: '/api/admin/logs', handler: handleLogsGet, adminOnly: true },
  { method: 'GET', path: '/api/admin/export-inspections-csv', handler: handleExportCsv, adminOnly: true },
];

function matchRoute(method, p) {
  for (const r of routes) {
    if (r.method !== method) continue;
    if (r.path === p) return { handler: r.handler, params: {}, adminOnly: !!r.adminOnly, perm: r.perm || null, raw: !!r.raw };
    if (r.pattern) {
      const m = p.match(r.pattern);
      if (m) {
        const params = {};
        if (r.paramNames) r.paramNames.forEach((name, i) => { params[name] = m[i + 1]; });
        return { handler: r.handler, params, adminOnly: !!r.adminOnly, perm: r.perm || null, raw: !!r.raw };
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
    if (route.adminOnly) {
      const u = await getLoginUser(req);
      if (!u) return fail(res, '未登录或登录已失效', 401);
      // adminOnly + perm：管理员永远放行；普通用户持有对应功能权限也放行（v1.9.0 权限细化）
      if (!(u.role === 'admin' || (route.perm && userHasPerm(u, route.perm)))) {
        const why = route.perm ? '权限不足：该操作需要「' + permLabel(route.perm) + '」权限，请让管理员在 用户管理→权限 里勾选'
                               : '权限不足：该操作仅管理员可用';
        logW('AUTH', '权限不足: ' + u.username + ' 调用 ' + method + ' ' + p);
        return fail(res, why, 403);
      }
    }
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
  // 浏览器会无条件请求 /favicon.ico；不给就会在控制台留一条 404（回归测试会误判成 JS 报错）
  // 用与页面 <link rel="icon"> 同款的内联闪电图标应答，顺带让所有页面都有标签页图标
  if (p === '/favicon.ico') {
    // 统一回这枚中性内联 SVG 闪电图标（与各页 <link rel="icon"> 同款），不依赖任何图片文件，永不 500
    res.writeHead(200, { 'Content-Type': 'image/svg+xml; charset=utf-8', 'Cache-Control': 'public, max-age=86400' });
    res.end("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='#0f1b2d'/><path d='M18 4 L9 18 h6 l-2 10 9-14 h-6 z' fill='#38bdf8'/></svg>");
    return;
  }
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
ensureConfig(); // 首次启动随机生成并载入密钥（持久化到 data/config.json）
fixMojibake(); // 先还原历史乱码（U+FFFD），避免脏字符被后续逻辑当成正常内容
seedRooms(); // 老数据文件首次升级时从设备位置推导房间列表
seedPrograms(); // 首次启动写入内置的独立检查项目（冲击摩擦风阻 / 显微镜维护）
syncProgramDevices(); // 每次启动按模板 key 自动关联项目设备（不写死设备 id，保证换机器可用）
migrateProgramColumns(); // v1.20.0：#079「内容」列升级为可选项 + 历史值归一（幂等）
migrate079Notes(); // v1.22.0：#079 备注补全「4.期间核查；5.校准」（幂等，乱码随覆写修复）
migrateDropLegacyTemplates(); // v1.24.0：清理旧显微镜 / 冲击分型号点检模板（归档留底，幂等）
pruneOldLogs(); // 启动时清理超过保留期的日志文件
logI('SYS', '服务启动 ' + APP_VERSION + '，端口 ' + PORT + '，数据文件 ' + DATA_FILE);
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

// LIMS 定时自动填充：每 30 秒看一次配置的时刻表（到点后 5 分钟窗口内触发一次）
setInterval(() => { limsAutoTick().catch(e => console.error('[LIMS自动]', e && e.message)); }, 30 * 1000);
