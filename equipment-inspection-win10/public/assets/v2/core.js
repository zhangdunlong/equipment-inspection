/* ==========================================================================
   v2 前端内核 · 设备点检系统
   统一提供：请求 / 提示 / 转义 / 日期 / 会话 / 导航 / 骨架屏 / 防抖 / 图标
   目标：消除各页重复的样板代码，并补齐原版缺失的错误处理与可访问性
   ========================================================================== */
(function (g) {
  'use strict';

  /* ---------- DOM ---------- */
  const $  = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.prototype.slice.call((r || document).querySelectorAll(s));

  /* ---------- 转义（防存储型 XSS） ---------- */
  const ESC_MAP = { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' };
  function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/[&<>"']/g, c => ESC_MAP[c]);
  }

  /* ---------- 请求 ---------- */
  // 统一 JSON 请求：非 2xx / 网络异常都返回 { __error: '…' }，调用方不 try/catch 也不会静默崩溃
  async function api(path, opt) {
    let res;
    try {
      res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opt || {}));
    } catch (e) {
      return { __error: '网络异常，请检查与服务端的连接' };
    }
    if (res.status === 401 || res.status === 403) {
      // 会话过期：统一跳登录并带上原地址
      location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
      return { __error: '登录已过期' };
    }
    let data;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok) return { __error: (data && (data.error || data.message)) || ('请求失败（HTTP ' + res.status + '）') };
    return data;
  }

  /* ---------- Toast（队列化，不再互相顶掉） ---------- */
  let toastHost = null;
  function ensureHost() {
    if (toastHost) return toastHost;
    toastHost = document.createElement('div');
    toastHost.className = 'toast-host';
    document.body.appendChild(toastHost);
    return toastHost;
  }
  function toast(msg, type, ms) {
    const host = ensureHost();
    const el = document.createElement('div');
    el.className = 'toast' + (type ? ' ' + type : '');
    el.setAttribute('role', 'status');
    el.textContent = msg;
    host.appendChild(el);
    while (host.children.length > 3) host.removeChild(host.firstChild);   // 最多同时 3 条
    setTimeout(() => {
      el.classList.add('out');
      setTimeout(() => el.remove(), 220);
    }, ms || 2600);
  }

  /* ---------- 日期（一律本地时区，避免 GMT+8 把「今天」算成昨天） ---------- */
  const p2 = n => String(n).padStart(2, '0');
  const localToday = () => { const d = new Date(); return `${d.getFullYear()}-${p2(d.getMonth()+1)}-${p2(d.getDate())}`; };
  const thisMonth  = () => { const d = new Date(); return `${d.getFullYear()}-${p2(d.getMonth()+1)}`; };
  const daysInMonth = (yy, mm) => new Date(+yy, +mm, 0).getDate();
  function fmtTime(s) {
    if (!s) return '';
    const d = new Date(s);
    if (isNaN(d.getTime())) return '';
    return `${d.getFullYear()}-${p2(d.getMonth()+1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
  }
  function fmtHM(s) {
    if (!s) return '';
    const d = new Date(s);
    if (isNaN(d.getTime())) return '';
    return `${p2(d.getHours())}:${p2(d.getMinutes())}`;
  }

  /* ---------- 防抖 / 节流 ---------- */
  function debounce(fn, wait) {
    let t = null;
    return function () {
      const args = arguments, self = this;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(self, args), wait || 250);
    };
  }

  /* ---------- 会话（房间选择） ---------- */
  const SS_KEY = 'selected_room';
  const session = {
    get room() { try { return sessionStorage.getItem(SS_KEY) || ''; } catch (e) { return ''; } },
    set room(v) { try { v ? sessionStorage.setItem(SS_KEY, v) : sessionStorage.removeItem(SS_KEY); } catch (e) { } }
  };

  /* ---------- 房间模型 ---------- */
  // 分组合并视图用的 token：__GROUP__<分组名>
  const GRP_TP = '__GROUP__';
  const isGroupTok = n => String(n).indexOf(GRP_TP) === 0;
  const tokGroup   = n => String(n).slice(GRP_TP.length);

  /* ---------- 导航（当前页高亮由脚本统一处理，避免各页硬编码 active 漏改） ---------- */
  function mountNav(opts) {
    const o = opts || {};
    const nav = $('[data-nav]');
    if (!nav) return;
    const me = o.me || {};
    const links = [
      { href: '/rooms.html',  text: '房间' },
      { href: '/index.html',  text: '设备大屏' },
      { href: '/inspect.html',text: '点检作业' },
      { href: '/env.html',       text: '温湿度' }
    ];
    // 内置操作手册（v1.35.0）：新窗口打开，所有登录人员可见；排在站内导航之后、外链之前
    const manualLink = { href: '/manual', text: '📖 操作手册' };
    if (me.role === 'admin') links.push({ href: '/admin', text: '管理后台' });
    const here = location.pathname.split('/').pop();
    const box = nav.querySelector('.links');
    box.innerHTML =
      links.map(l => `<a href="${l.href}"${l.href.indexOf(here) >= 0 ? ' aria-current="page"' : ''}>${esc(l.text)}</a>`).join('');
    box.insertAdjacentHTML('beforeend', '<a href="/logout">退出</a>');
    // 外部系统快捷入口（v1.34.0）：LIMS 对所有登录人员可见；力学工具箱仅「力学」科室 + 管理员
    // 数据源 GET /api/settings → links（可用后台/kv 覆盖地址）；取不到就静默不显示，绝不影响导航
    api('/api/settings').then(st => {
      // 外部系统跳转：后台可配（名称/地址/可见科室/启用）
      // 可见规则：depts 为空 = 所有登录人员；非空 = 仅这些科室；管理员恒可见已启用项
      const items = ((st && st.links && st.links.items) || []).filter(x => x && x.enabled && x.url);
      const mine = items.filter(x => {
        if (me.role === 'admin') return true;
        const d = x.depts || [];
        return !d.length || (me.dept && d.indexOf(me.dept) >= 0);
      });
      // 操作手册入口：后台可配显示/隐藏（v1.36.0；默认显示），data-origin 用相对路径即可
      const manualOn = !(st && st.links && st.links.manual) || st.links.manual.enabled !== false;
      if (!mine.length && !manualOn) return;
      const logout = box.querySelector('a[href="/logout"]');
      if (!logout) return;
      const manHtml = manualOn
        ? '<a class="man" href="' + manualLink.href + '" target="_blank" rel="noopener" title="新窗口打开操作手册">' + esc(manualLink.text) + '</a>'
        : '';
      if (!mine.length) { logout.insertAdjacentHTML('beforebegin', manHtml); return; }
      logout.insertAdjacentHTML('beforebegin', manHtml + '<span class="sep" aria-hidden="true"></span>' + mine.map(e =>
        `<a class="ext" href="${esc(e.url)}" target="_blank" rel="noopener" title="在新窗口打开：${esc(e.name)}">${esc(e.name)}<span class="ar">↗</span></a>`).join(''));
    }).catch(() => { });

    const tg = nav.querySelector('.nav-toggle');
    if (tg) tg.addEventListener('click', () => {
      const box = nav.querySelector('.links');
      const open = box.classList.toggle('open');
      tg.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    // 版本号
    api('/api/version').then(v => {
      if (v && v.version) $$('[data-appver]').forEach(e => e.textContent = v.version);
    }).catch(() => { });
  }

  /* ---------- 骨架屏 ---------- */
  function skeleton(host, rows, h) {
    host.innerHTML = Array.from({ length: rows || 3 })
      .map(() => `<div class="skel" style="height:${h || 16}px;margin-bottom:8px"></div>`).join('');
  }

  /* ---------- 当前登录用户 ---------- */
  async function me() { return api('/api/admin/me'); }

  /* ---------- 图标集（v1.29.0）
   * 全站统一线性图标：24×24 网格 / 1.8 描边 / 圆头圆角 / currentColor 着色。
   * 描边与填充样式集中在 theme.css 的 `svg.ic`，所以只要走 icon() 出来的图标，
   * 尺寸、线宽、圆头、配色语言必然一致 —— 不再出现 emoji 跨平台渲染不一致的问题。
   * 用法：CORE.icon('creep', 18)            → 18px
   *       CORE.icon('thermo', 13, 'muted')  → 追加类名
   */
  const ICONS = {
    /* 蠕变：应变–时间曲线（一次蠕变段→稳态平台→加速段），坐标轴淡显做层次 */
    creep:     '<path d="M3.4 3.6V20.6H20.6" opacity=".5"/><path d="M3.6 19.8C3.9 17 5.6 13.2 7.2 12.4C9.6 11.6 12.6 11.9 15.4 11.2C17.4 11 18.6 7.6 20.4 4.6"/>',
    /* 独立房间：单间平面（门 + 地平线）—— 与蠕变曲线同线宽同网格，一眼区分「分组区域 / 独立房间」 */
    rooms:     '<path d="M6.6 20.6V6A2 2 0 0 1 8.6 4H15.4A2 2 0 0 1 17.4 6V20.6"/><path d="M3.6 20.6H20.4"/><path d="M14.4 12.2V13.8"/>',
    thermo:    '<path d="M14.4 14.6V4.5a2.4 2.4 0 0 0-4.8 0v10.1a4.2 4.2 0 1 0 4.8 0Z"/><path d="M12 8.4h2"/>',
    layers:    '<path d="M12 2.8 2.8 7.2 12 11.6 21.2 7.2Z"/><path d="M2.8 12 12 16.4 21.2 12"/><path d="M2.8 16.6 12 21 21.2 16.6"/>',
    clipboard: '<path d="M9 4.4H6.6A1.8 1.8 0 0 0 4.8 6.2V19.4A1.8 1.8 0 0 0 6.6 21.2H17.4A1.8 1.8 0 0 0 19.2 19.4V6.2A1.8 1.8 0 0 0 17.4 4.4H15"/><path d="M9.4 2.8h5.2a1.1 1.1 0 0 1 1.1 1.1v1.6a1.1 1.1 0 0 1-1.1 1.1H9.4a1.1 1.1 0 0 1-1.1-1.1V3.9A1.1 1.1 0 0 1 9.4 2.8Z"/><path d="M9 14.2l2.2 2.2 4-4.4"/>',
    device:    '<rect x="8" y="8" width="8" height="8" rx="1.4"/><path d="M10 4.6V8M14 4.6V8M10 16v3.4M14 16v3.4M4.6 10H8M4.6 14H8M16 10h3.4M16 14h3.4"/>',
    grid:      '<rect x="3.6" y="3.6" width="7.2" height="7.2" rx="1.6"/><rect x="13.2" y="3.6" width="7.2" height="7.2" rx="1.6"/><rect x="3.6" y="13.2" width="7.2" height="7.2" rx="1.6"/><rect x="13.2" y="13.2" width="7.2" height="7.2" rx="1.6"/>',
    undo:      '<path d="M4 8.8h12.2a4.6 4.6 0 0 1 0 9.2H10.4"/><path d="M8.2 4.4 4 8.8 8.2 13.2"/>',
    building:  '<path d="M3.4 20.6V10.2l4.4-2.9v2.9l4.4-2.9v2.9l4.4-2.9V20.6Z"/>',
    alert:     '<path d="M12 4.2 21 19.8H3Z"/><path d="M12 10.4v3.6M12 17h.01"/>',
    search:    '<circle cx="10.6" cy="10.6" r="6.2"/><path d="M15.2 15.2 20.4 20.4"/>',
    clear:     '<circle cx="12" cy="12" r="8.4"/><path d="M9.2 9.2 14.8 14.8M14.8 9.2 9.2 14.8"/>',
    chev:      '<path d="M9.4 5.6 15.8 12 9.4 18.4"/>',
    menu:      '<path d="M4 7h16M4 12h16M4 17h16"/>',
    unlock:    '<rect x="3.8" y="10.4" width="16.4" height="9.8" rx="2"/><path d="M7.6 10.4V7.6a4.4 4.4 0 0 1 8.6-1.1"/>'
  };
  function icon(name, size, cls) {
    const body = ICONS[name];
    if (!body) return '';
    const s = size || 18;
    return '<svg class="ic' + (cls ? ' ' + cls : '') + '" viewBox="0 0 24 24" width="' + s + '" height="' + s +
      '" aria-hidden="true" focusable="false">' + body + '</svg>';
  }

  g.CORE = {
    $, $$, esc, api, toast,
    p2, localToday, thisMonth, daysInMonth, fmtTime, fmtHM,
    debounce, session,
    GRP_TP, isGroupTok, tokGroup,
    ICONS, icon,
    mountNav, skeleton, me
  };
})(window);
