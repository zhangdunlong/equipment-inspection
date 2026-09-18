// 温湿度预警 · 站内通知组件（v1.21.0 初版 / v1.24.0 修 UI 遮挡 + 补 head 引入场景 / v1.30.1 点击横幅/条目直达对应房间温湿度页）
// 用法：在页面 </body> 前 <script src="/assets/notify.js"></script>
// 效果：铃铛（未读红点）+ 下拉通知列表；顶部预警横幅（未读预警时显示，可关闭）
//
// v1.24.0 变更：
//   ① 用户反馈「右上角小铃铛遮住别的按钮」：原实现把铃铛 position:fixed 钉在 top:14/right:18，
//      正好压在顶部导航的版本号 / 菜单按钮 / 退出上。现在：页面有顶部导航
//      （.app-nav 或 nav.nav）→ 铃铛作为导航内的一项「内联」摆放；没有导航才退回浮动，
//      且让开导航高度。通知面板与顶部预警横幅的 top 同样按导航底边动态计算
//      （横幅原来整条压在导航上）。
//   ② env.html 是在 <head> 里引入本文件的，原代码直接 document.body.appendChild 会抛错
//      （那时 body 还是 null）→ 铃铛在温湿度页从来就没出现过。改为等 DOM 就绪再挂载。
(function () {
  var css = document.createElement('style');
  css.textContent =
    // 基础样式 = 内联摆放（导航里的一项）
    '#ntBell{position:relative;z-index:10000;flex:none;width:34px;height:34px;border-radius:9px;' +
    'border:1px solid rgba(255,255,255,.25);background:rgba(255,255,255,.08);cursor:pointer;font-size:16px;' +
    'display:flex;align-items:center;justify-content:center;color:inherit}' +
    '#ntBell:hover{background:rgba(255,255,255,.16)}' +
    // 没有导航的页面才浮动（并让开导航高度，避免压住内容）
    '#ntBell.nt-float{position:fixed;top:calc(var(--nav-h,52px) + 10px);right:14px;border-radius:50%}' +
    '#ntBell .nt-dot{position:absolute;top:-4px;right:-4px;min-width:17px;height:17px;border-radius:9px;background:#e5484d;' +
    'color:#fff;font-size:11px;line-height:17px;text-align:center;padding:0 4px;font-weight:700;display:none}' +
    '#ntPanel{position:fixed;top:64px;right:14px;z-index:9991;width:380px;max-width:92vw;max-height:60vh;overflow:auto;' +
    'background:#fff;color:#1c2430;border:1px solid #d5dbe3;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,.25);display:none;font-size:13px}' +
    '#ntPanel .nt-h{display:flex;align-items:center;padding:9px 12px;border-bottom:1px solid #e7ebf0;font-weight:700}' +
    '#ntPanel .nt-h button{margin-left:auto;border:0;background:none;color:#0a66c2;cursor:pointer;font-size:12px}' +
    '#ntPanel .nt-i{padding:8px 12px;border-bottom:1px solid #f0f2f5}' +
    '#ntPanel .nt-i.unread{background:#fff7e6}' +
    '#ntPanel .nt-i .t{font-weight:600}' +
    '#ntPanel .nt-i .b{margin-top:2px;color:#444}' +
    '#ntPanel .nt-i .tm{margin-top:2px;color:#98a2b3;font-size:11px}' +
    '#ntBanner{position:fixed;top:0;left:0;right:0;z-index:9998;background:#b42318;color:#fff;padding:7px 40px 7px 14px;' +
    'font-size:13px;display:none;cursor:pointer}' +
    '#ntBanner b{font-weight:700}' +
    '#ntBanner .x{position:absolute;right:12px;top:6px;cursor:pointer;font-size:15px}' +
    '@media print{#ntBell,#ntPanel,#ntBanner{display:none !important}}';
  if (document.head) document.head.appendChild(css);

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

ready(function () {
  // v1.30.3 引入版本自检；v1.31.0 修复「更新提示一直弹」：
  //   旧实现拿手写常量 NOTIFY_VER 对比 /api/version，发版忘改常量就永久误报（v1.30.5 起实锤，
  //   常量停在 v1.30.4 而服务端已是 v1.30.5，每次轮询都弹、刷新也没用）。
  //   现改为：页面启动时记一次服务端版本 bootVer，之后每次 poll 再取当前版本对比 ——
  //   不一致说明服务端已重启升版、本标签页还跑着旧代码，才提示刷新；刷新后 bootVer 自然跟上不再弹。
  //   代价：只改文件不升版的修复不会触发提示（此类仍按 Ctrl+Shift+R 强刷）。
  var bootVer = null;
  fetch('/api/version').then(function (r) { return r.ok ? r.json() : null; })
    .then(function (v) { bootVer = (v && v.version) ? v.version : null; }).catch(function () { });
  function checkUpgrade() {
    if (!bootVer) return;   // 启动版本还没拿到（或拿不到）就不误报
    fetch('/api/version').then(function (r) { return r.ok ? r.json() : null; }).then(function (v) {
      if (v && v.version && v.version !== bootVer) showUpgrade(v.version);
    }).catch(function () {});
  }
  function showUpgrade(ver) {
    var el = document.getElementById('ntUpgrade'); if (el) return;
    el = document.createElement('div'); el.id = 'ntUpgrade';
    el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;background:#1f6feb;color:#fff;padding:6px 40px 6px 14px;font-size:13px;cursor:pointer';
    el.innerHTML = '🔄 系统已更新到 ' + esc(ver) + '，点击此处刷新以加载新功能<span style="position:absolute;right:12px;top:5px">✕</span>';
    el.addEventListener('click', function (e) { if (e.target.tagName === 'SPAN') { el.style.display = 'none'; return; } location.reload(true); });
    document.body.appendChild(el);
  }
  if (document.getElementById('ntBell')) return;
    // 顶部导航：优先新版 .app-nav，其次旧版 nav.nav
    var nav = document.querySelector('.app-nav[data-nav]') || document.querySelector('nav.nav');

    var banner = document.createElement('div'); banner.id = 'ntBanner';
    document.body.appendChild(banner);
    var bell = document.createElement('div'); bell.id = 'ntBell'; bell.title = '温湿度预警通知';
    bell.setAttribute('role', 'button'); bell.setAttribute('tabindex', '0'); bell.setAttribute('aria-label', '温湿度预警通知');
    bell.innerHTML = '🔔<span class="nt-dot"></span>';
    if (nav) {
      // 内联进导航：优先插在「菜单按钮」前，否则插在最后一个元素（退出）前
      var tg = nav.querySelector('.nav-toggle');
      if (tg) nav.insertBefore(bell, tg);
      else if (nav.lastElementChild) nav.insertBefore(bell, nav.lastElementChild);
      else nav.appendChild(bell);
      bell.className = 'nt-inline';
    } else {
      document.body.appendChild(bell);
      bell.className = 'nt-float';
    }
    var panel = document.createElement('div'); panel.id = 'ntPanel';
    panel.innerHTML = '<div class="nt-h">🌡 温湿度预警通知<button id="ntReadAll">全部标为已读</button></div><div id="ntList"></div>';
    document.body.appendChild(panel);

    // 弹层 / 横幅一律贴着导航底边摆放，避免盖住导航里的按钮
    function navBottom() {
      if (!nav) return 0;
      var r = nav.getBoundingClientRect();
      return r && r.height ? Math.round(r.bottom) : 0;
    }
    function place() {
      var b = navBottom();
      panel.style.top = (b + 8) + 'px';
      banner.style.top = b + 'px';
    }
    place();
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, { passive: true });

    var unread = 0, items = [];
    function esc(s) { return (s == null ? '' : String(s)).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
    function fmt(t) { return String(t || '').replace('T', ' ').slice(0, 16); }
    // v1.30.1：从通知里取出房间名，用于「点进去直达该房间温湿度页」
    //   body 形如 【房间名】…；title 形如 🌡 温湿度预警：房间名
    function roomOf(n) {
      var b = (n && n.body) || '';
      var m = b.match(/^\s*【\s*([^】]+?)\s*】/);
      if (m) return m[1];
      var t = (n && n.title) || '';
      var i = t.indexOf('：');
      if (i >= 0) return t.slice(i + 1).trim();
      return '';
    }
    function gotoRoom(room) {
      if (room) location.href = '/env.html?room=' + encodeURIComponent(room);
    }

    function render() {
      var dot = bell.querySelector('.nt-dot');
      dot.style.display = unread > 0 ? '' : 'none';
      dot.textContent = unread > 99 ? '99+' : unread;
      var lst = document.getElementById('ntList');
      if (!items.length) { lst.innerHTML = '<div class="nt-i" style="color:#98a2b3">暂无通知</div>'; return; }
      lst.innerHTML = items.map(function (n) {
        return '<div class="nt-i' + (n.read ? '' : ' unread') + '" data-id="' + esc(n.id) + '">' +
          '<div class="t">' + esc(n.title) + '</div><div class="b">' + esc(n.body) + '</div>' +
          '<div class="tm">' + fmt(n.at) + (n.read ? '' : ' · <b style="color:#b42318">未读</b>') + '</div></div>';
      }).join('');
      lst.querySelectorAll('.nt-i').forEach(function (el) {
        el.addEventListener('click', function () {
          var id = el.getAttribute('data-id');
          var n = items.filter(function (x) { return String(x.id) === String(id); })[0];
          var room = roomOf(n);
          markRead([id]);
          gotoRoom(room);
        });
      });
    }
    function markRead(ids) {
      fetch('/api/notifs/read', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids: ids }) })
        .then(function (r) { return r.json(); }).then(function () { poll(); });
    }
    function poll() {
      checkUpgrade();
      fetch('/api/notifs').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
        if (!j || !j.ok) return;
        items = j.rows || []; unread = j.unread || 0;
        render();
        var unreadAlerts = items.filter(function (n) { return !n.read; });
        if (unreadAlerts.length) {
          if (banner.style.display !== 'block') place();
          banner.innerHTML = '🚨 <b>温湿度预警</b>：您有 ' + unreadAlerts.length + ' 条未读预警（最新：' + esc(unreadAlerts[0].body) + '）<span class="x">✕</span>';
          banner.style.display = 'block';
        } else { banner.style.display = 'none'; }
      }).catch(function () { });
    }
    function toggle() {
      var open = panel.style.display !== 'block';
      if (open) place();
      panel.style.display = open ? 'block' : 'none';
      if (open) poll();
    }
    bell.addEventListener('click', toggle);
    bell.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });
    panel.querySelector('#ntReadAll').addEventListener('click', function () { markRead(items.filter(function (n) { return !n.read; }).map(function (n) { return n.id; })); });
    banner.addEventListener('click', function (e) {
      if (e.target.className === 'x') { banner.style.display = 'none'; return; }
      var unreadAlerts = items.filter(function (n) { return !n.read; });
      // 优先取「能解析出房间名的未读告警」跳转；避免首条未读是非环境类通知时 roomOf 返空、点了不跳
      var firstEnv = unreadAlerts.filter(function (n) { return roomOf(n); })[0] || unreadAlerts[0];
      var room = roomOf(firstEnv);
      markRead(unreadAlerts.map(function (n) { return n.id; }));
      gotoRoom(room);
    });
    document.addEventListener('click', function (e) {
      if (panel.style.display === 'block' && !panel.contains(e.target) && e.target !== bell && !bell.contains(e.target)) panel.style.display = 'none';
    });
    poll();
    setInterval(poll, 60000);
  });
})();
