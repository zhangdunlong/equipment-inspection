/* 科室可见性（v1.3.3）
 * v1.3.3：横幅图标改用 v2 内核（CORE.icon）的统一线性图标集，去掉 🔓/🏢 emoji
 *         （emoji 跨平台渲染不一致，且与 v1.29.0 的全站线性图标语言冲突）；
 *         容器里有 core.js 才出图标，没有则退化为纯文字，不影响老页面。
 * 规则（对老数据完全兼容）：
 *   - 管理员（role=admin）        → 永远看全部房间
 *   - 普通用户 且 设了科室         → 只看到「本科室」的房间
 *   - 普通用户 且 未设科室（老账号）→ 看全部房间（不因升级而丢可见范围）
 * 用法：
 *   await DEPT.load();                 // 拉一次当前登录信息
 *   const list = DEPT.filterRooms(rooms);
 *   DEPT.banner(el);                   // 可选：渲染「当前科室」提示条
 */
(function (g) {
  g.DEPT = {
    me: null,
    loaded: false,
    async load() {
      try {
        this.me = await fetch('/api/admin/me').then(function (r) { return r.json(); });
      } catch (e) {
        this.me = { ok: false };
      }
      this.loaded = true;
      return this.me;
    },
    get dept() { return (this.me && this.me.dept) || ''; },
    get isAdmin() { return !!(this.me && this.me.role === 'admin'); },
    get loggedIn() { return !!(this.me && this.me.ok); },
    // 是否不受科室限制（管理员 / 未设科室的老账号）
    canSeeAll() { return this.isAdmin || !this.dept; },
    // 房间是否对本用户可见
    canSeeRoom(r) {
      if (this.canSeeAll()) return true;
      return String((r && r.dept) || '') === this.dept;
    },
    // 过滤房间列表（保持原顺序）
    filterRooms(list) {
      if (!Array.isArray(list)) return [];
      if (this.canSeeAll()) return list;
      var self = this;
      return list.filter(function (r) { return self.canSeeRoom(r); });
    },
    // 在给定容器里渲染「当前科室」提示条；容器为空则不动。返回是否渲染了
    // 图标走 v2 内核的统一线性图标集（CORE.icon）；旧页面没有 core.js 时退化为纯文字
    banner(el, opt) {
      if (!el) return false;
      var o = opt || {};
      if (this.canSeeAll()) {
        if (this.isAdmin) {
          el.innerHTML = '<div class="dept-bar admin">' + ic('unlock') + '管理员：可见全部房间' +
            (this.dept ? '（本人科室：' + esc(this.dept) + '）' : '') +
            '<a href="/admin?tab=room">房间 / 科室管理 →</a></div>';
          el.style.display = '';
          return true;
        }
        el.style.display = 'none';
        return false;
      }
      var n = (typeof o.count === 'number') ? o.count : null;
      el.innerHTML = '<div class="dept-bar">' + ic('rooms') + '当前科室：<b>' + esc(this.dept) + '</b>' +
        '，仅显示本科室的房间' +
        (n === null ? '' : '（' + n + ' 间）') +
        '<span class="tip">如需查看其他科室，请联系管理员调整账号科室</span></div>';
      el.style.display = '';
      return true;
    }
  };
  // 统一图标：有 v2 内核就用线性图标，否则返回空串（老页面退化为纯文字，不报错）
  function ic(name) { return (g.CORE && g.CORE.icon) ? g.CORE.icon(name, 16) : ''; }
  function esc(s) {
    return (s == null ? '' : String(s)).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
})(window);
