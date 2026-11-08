/* ==========================================================================
   assets/icons.js · 全站统一线性图标（v1.44.7 新增，抽成 v1/v2 共用）
   --------------------------------------------------------------------------
   为什么要有这个文件：
     1) 原来图标只在 v2 的 assets/v2/core.js 里（rooms.html 在用），
        而 admin / env / check / login 走的是 v1 的 style.css，没有图标助手；
        于是这些页面的按钮只能拿 emoji（🔍 💾 🖨 🌡 …）当图标 ——
        emoji 是**字体渲染**出来的，不同 Windows / 投屏机器字形不一致，
        而且和旁边真正的矢量图标摆在一起时粗细、基线、颜色都对不齐。
     2) 本文件不依赖 CORE，v1、v2 页面都能直接用：
          <script src="/assets/icons.js"></script>
          UI.icon('save', 15)        → 返回 <svg class="ic">…</svg> 字符串
     3) 规格集中在一处：24×24 网格 / 1.8 描边 / 圆头圆角 / currentColor 着色，
        描边样式由 style.css 或 theme.css 里的 `svg.ic` 统一控制（两套都加了同一条规则）。

   静态标记里不想手写一长串 SVG 时，用 data-ic 自动注入（本文件末尾的 hydrate）：
        <button class="btn" data-ic="save">保存</button>
   渐进增强：脚本没加载成功时按钮文字照常显示，功能不受影响。
   ========================================================================== */
(function (w) {
  'use strict';

  var ICONS = {
    /* ---------- 业务图形（沿用 v1.29.0 的设计语言：同一网格、同一线宽）---------- */
    creep:     '<path d="M3.4 3.6V20.6H20.6" opacity=".5"/><path d="M3.6 19.8C3.9 17 5.6 13.2 7.2 12.4C9.6 11.6 12.6 11.9 15.4 11.2C17.4 11 18.6 7.6 20.4 4.6"/>',
    rooms:     '<path d="M6.6 20.6V6A2 2 0 0 1 8.6 4H15.4A2 2 0 0 1 17.4 6V20.6"/><path d="M3.6 20.6H20.4"/><path d="M14.4 12.2V13.8"/>',
    thermo:    '<path d="M14.4 14.6V4.5a2.4 2.4 0 0 0-4.8 0v10.1a4.2 4.2 0 1 0 4.8 0Z"/><path d="M12 8.4h2"/>',
    layers:    '<path d="M12 2.8 2.8 7.2 12 11.6 21.2 7.2Z"/><path d="M2.8 12 12 16.4 21.2 12"/><path d="M2.8 16.6 12 21 21.2 16.6"/>',
    clipboard: '<path d="M9 4.4H6.6A1.8 1.8 0 0 0 4.8 6.2V19.4A1.8 1.8 0 0 0 6.6 21.2H17.4A1.8 1.8 0 0 0 19.2 19.4V6.2A1.8 1.8 0 0 0 17.4 4.4H15"/><path d="M9.4 2.8h5.2a1.1 1.1 0 0 1 1.1 1.1v1.6a1.1 1.1 0 0 1-1.1 1.1H9.4a1.1 1.1 0 0 1-1.1-1.1V3.9A1.1 1.1 0 0 1 9.4 2.8Z"/><path d="M9 14.2l2.2 2.2 4-4.4"/>',
    device:    '<rect x="8" y="8" width="8" height="8" rx="1.4"/><path d="M10 4.6V8M14 4.6V8M10 16v3.4M14 16v3.4M4.6 10H8M4.6 14H8M16 10h3.4M16 14h3.4"/>',
    grid:      '<rect x="3.6" y="3.6" width="7.2" height="7.2" rx="1.6"/><rect x="13.2" y="3.6" width="7.2" height="7.2" rx="1.6"/><rect x="3.6" y="13.2" width="7.2" height="7.2" rx="1.6"/><rect x="13.2" y="13.2" width="7.2" height="7.2" rx="1.6"/>',
    building:  '<path d="M3.4 20.6V10.2l4.4-2.9v2.9l4.4-2.9v2.9l4.4-2.9V20.6Z"/>',
    alert:     '<path d="M12 4.2 21 19.8H3Z"/><path d="M12 10.4v3.6M12 17h.01"/>',
    undo:      '<path d="M4 8.8h12.2a4.6 4.6 0 0 1 0 9.2H10.4"/><path d="M8.2 4.4 4 8.8 8.2 13.2"/>',

    /* ---------- 操作类 ---------- */
    search:    '<circle cx="11" cy="11" r="6.4"/><path d="M15.8 15.8 20.6 20.6"/>',
    save:      '<path d="M5 6a2 2 0 0 1 2-2h9.2L20 7.8V18a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2Z"/><path d="M8.4 4.2v4.4h6.2V4.2"/><path d="M8 19.8v-5h8v5"/>',
    print:     '<path d="M7.2 8.6V4.4h9.6v4.2"/><path d="M7.2 17.2H5.4A1.8 1.8 0 0 1 3.6 15.4v-4.2a1.8 1.8 0 0 1 1.8-1.8h13.2a1.8 1.8 0 0 1 1.8 1.8v4.2a1.8 1.8 0 0 1-1.8 1.8h-1.8"/><rect x="7.2" y="14" width="9.6" height="6" rx="1.4"/>',
    refresh:   '<path d="M19.6 9.4A8 8 0 1 0 20 12"/><path d="M20.4 4.2v5.2H15.2"/>',
    swap:      '<path d="M4.4 8.6h13"/><path d="M14.2 5.2l3.4 3.4-3.4 3.4"/><path d="M19.6 15.4h-13"/><path d="M9.8 12l-3.4 3.4 3.4 3.4"/>',
    expand:    '<path d="M4 9V4.6h4.4"/><path d="M20 9V4.6h-4.4"/><path d="M4 15v4.4h4.4"/><path d="M20 15v4.4h-4.4"/>',
    pin:       '<path d="M12 21.2s6.6-6.1 6.6-11a6.6 6.6 0 1 0-13.2 0c0 4.9 6.6 11 6.6 11Z"/><circle cx="12" cy="10" r="2.4"/>',
    wrench:    '<path d="M15.1 4.2a4.8 4.8 0 0 0-4.2 8.1l-6.6 6.6a1.9 1.9 0 1 0 2.7 2.7l6.6-6.6a4.8 4.8 0 0 0 5.9-6.4l-2.8 2.8-2.5-.6-.6-2.5Z"/>',
    download:  '<path d="M12 4v10.6"/><path d="M7.8 10.6 12 14.8l4.2-4.2"/><path d="M4.6 17.4v1.2a1.8 1.8 0 0 0 1.8 1.8h11.2a1.8 1.8 0 0 0 1.8-1.8v-1.2"/>',
    upload:    '<path d="M12 20V9.4"/><path d="M7.8 13.6 12 9.4l4.2 4.2"/><path d="M4.6 6.6V5.4a1.8 1.8 0 0 1 1.8-1.8h11.2a1.8 1.8 0 0 1 1.8 1.8v1.2"/>',
    sign:      '<path d="M4 20l1-4.2L15.6 5.2a2 2 0 0 1 2.8 0l.4.4a2 2 0 0 1 0 2.8L8.2 19Z"/><path d="M14.2 6.6l3.2 3.2"/>',
    dash:      '<path d="M5 12h14"/>',
    bolt:      '<path d="M13.4 2.6 5.6 13.4h5.2l-.8 8 8-10.8h-5.2Z"/>',
    doc:       '<path d="M13.4 3.6H7.2A1.8 1.8 0 0 0 5.4 5.4v13.2a1.8 1.8 0 0 0 1.8 1.8h9.6a1.8 1.8 0 0 0 1.8-1.8V8.4Z"/><path d="M13.4 3.6v4.8h5.2"/><path d="M8.8 13h6.4M8.8 16.4h4.4"/>',

    /* ---------- 导航 / 指示 ---------- */
    chevron_down:  '<path d="M6.4 9.4 12 15l5.6-5.6"/>',
    chevron_right: '<path d="M9.4 5.6 15.4 12l-6 6.4"/>',
    chevron_left:  '<path d="M14.6 5.6 8.6 12l6 6.4"/>',
    external:   '<path d="M14 4.6h5.4V10"/><path d="M19.4 4.6 11 13"/><path d="M18 14v4.4a1.8 1.8 0 0 1-1.8 1.8H5.6a1.8 1.8 0 0 1-1.8-1.8V7.8A1.8 1.8 0 0 1 5.6 6H10"/>',
    menu:       '<path d="M4 7h16"/><path d="M4 12h16"/><path d="M4 17h16"/>',
    home:       '<path d="M4 10.6 12 4l8 6.6"/><path d="M6.2 12.4v6a1.4 1.4 0 0 0 1.4 1.4h8.8a1.4 1.4 0 0 0 1.4-1.4v-6"/>',
    book:       '<path d="M12 6.4S10.4 4.6 5.4 4.6v13c5 0 6.6 1.8 6.6 1.8s1.6-1.8 6.6-1.8v-13C13.6 4.6 12 6.4 12 6.4Z"/><path d="M12 6.4v13"/>',
    link:       '<path d="M10.4 13.6a3.6 3.6 0 0 0 5.2 0l2.6-2.6a3.7 3.7 0 0 0-5.2-5.2l-1.4 1.4"/><path d="M13.6 10.4a3.6 3.6 0 0 0-5.2 0l-2.6 2.6a3.7 3.7 0 0 0 5.2 5.2l1.4-1.4"/>',

    /* ---------- 通用控件 ---------- */
    plus:       '<path d="M12 5.4v13.2"/><path d="M5.4 12h13.2"/>',
    minus:      '<path d="M5.4 12h13.2"/>',
    check:      '<path d="M5 12.6 9.6 17.2 19 6.8"/>',
    x:          '<path d="M6.4 6.4 17.6 17.6"/><path d="M17.6 6.4 6.4 17.6"/>',
    pencil:     '<path d="M4.6 19.4h3.2L18.2 9a1.9 1.9 0 0 0 0-2.7l-.5-.5a1.9 1.9 0 0 0-2.7 0L4.6 16.2Z"/>',
    trash:      '<path d="M4.8 6.8h14.4"/><path d="M9.4 6.8V5.2a1.4 1.4 0 0 1 1.4-1.4h2.4a1.4 1.4 0 0 1 1.4 1.4v1.6"/><path d="M6.6 6.8 7.4 19a1.6 1.6 0 0 0 1.6 1.5h6a1.6 1.6 0 0 0 1.6-1.5l.8-12.2"/><path d="M10.4 10.6v6M13.6 10.6v6"/>',
    clock:      '<circle cx="12" cy="12" r="8.2"/><path d="M12 7.4V12l3.4 2"/>',
    calendar:   '<rect x="4.4" y="5.6" width="15.2" height="14.4" rx="1.8"/><path d="M4.4 10h15.2"/><path d="M8.6 3.4v4M15.4 3.4v4"/>',
    list:       '<path d="M9 6.4h10.4M9 12h10.4M9 17.6h10.4"/><path d="M4.8 6.4h.01M4.8 12h.01M4.8 17.6h.01"/>',
    filter:     '<path d="M4.2 5.6h15.6l-6 7.2v5.6l-3.6 1.8v-7.4Z"/>',
    info:       '<circle cx="12" cy="12" r="8.2"/><path d="M12 11v5.4M12 7.8h.01"/>',
    user:       '<circle cx="12" cy="8.2" r="3.6"/><path d="M4.8 20.2a7.2 7.2 0 0 1 14.4 0"/>',
    gear:       '<circle cx="12" cy="12" r="3.2"/><path d="M12 2.8v2.4M12 18.8v2.4M4.5 12H2.1M21.9 12h-2.4M6.7 6.7 4.9 4.9M19.1 19.1l-1.8-1.8M17.3 6.7l1.8-1.8M4.9 19.1l1.8-1.8"/>',
    eye:        '<path d="M2.6 12S6.4 6.4 12 6.4 21.4 12 21.4 12 17.6 17.6 12 17.6 2.6 12 2.6 12Z"/><circle cx="12" cy="12" r="2.8"/>',
    lock:       '<rect x="5.4" y="10.4" width="13.2" height="9.4" rx="1.8"/><path d="M8.6 10.4V7.8a3.4 3.4 0 0 1 6.8 0v2.6"/>',
    db:         '<ellipse cx="12" cy="6.2" rx="7" ry="2.8"/><path d="M5 6.2v11.6c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8V6.2"/><path d="M5 12c0 1.5 3.1 2.8 7 2.8s7-1.3 7-2.8"/>'
  };

  function icon(name, size, cls) {
    var body = ICONS[name];
    if (!body) return '';
    var s = size || 18;
    return '<svg class="ic' + (cls ? ' ' + cls : '') + '" viewBox="0 0 24 24" width="' + s + '" height="' + s +
      '" aria-hidden="true" focusable="false">' + body + '</svg>';
  }

  w.UI = { icon: icon, ICONS: ICONS };

  /* ---------- data-ic 自动注入（渐进增强）----------
     静态标记写 <button data-ic="save">保存</button>，脚本加载成功后
     在元素开头插入对应 SVG；脚本没加载时按钮文字照常显示，功能不受影响。 */
  function hydrate() {
    var nodes = document.querySelectorAll('[data-ic]');
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      if (el.getAttribute('data-ic-done')) continue;
      var name = el.getAttribute('data-ic');
      var size = parseInt(el.getAttribute('data-ic-size'), 10) || 15;
      var svg = icon(name, size);
      if (!svg) continue;                       // 名字写错就不动它（便于排查）
      el.insertAdjacentHTML('afterbegin', svg);
      el.setAttribute('data-ic-done', '1');
    }
  }
  w.UI.hydrate = hydrate;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', hydrate);
  else hydrate();
})(window);