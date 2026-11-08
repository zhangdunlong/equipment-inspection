/* 签名格右键菜单（通用组件，v1.44.2）
 * 为什么做成共用脚本：点检表（inspect.html）与温湿度表（env.html）的签名区要**完全一致**，
 * 各写一份必然随改动漂移（本项目已多次吃过「两处口径不一致」的亏）。
 *
 * 用法：
 *   <script src="/assets/sig-menu.js"></script>
 *   SigMenu.show(e.clientX, e.clientY, [
 *     { icon:'🖊', label:'选择签名', run:()=>{ ... } },
 *     { icon:'🗑', label:'删除签名', danger:true, disabled:!hasSig, run:()=>{ ... } }
 *   ]);
 *
 * 行为：点在菜单外 / 按 Esc / 滚动页面都会自动关闭；贴边会自动翻转，不会跑出屏幕。
 */
(function () {
  var box = null;

  // 注入样式（幂等）
  if (!document.getElementById('sigmenu_style')) {
    var st = document.createElement('style');
    st.id = 'sigmenu_style';
    st.textContent = [
      '.sigmenu{position:fixed;z-index:10000;min-width:150px;padding:5px;background:#fff;',
      'border:1px solid #e2e6ee;border-radius:10px;box-shadow:0 8px 26px rgba(16,24,40,.18);',
      'font-size:13px;line-height:1.5;user-select:none}',
      '.sigmenu-i{display:flex;align-items:center;gap:8px;width:100%;padding:7px 10px;border:0;',
      'background:transparent;border-radius:7px;text-align:left;font:inherit;color:#1f2531;cursor:pointer}',
      '.sigmenu-i:hover{background:#eef4ff}',
      '.sigmenu-i .ic{width:16px;text-align:center;flex:none}',
      '.sigmenu-i.danger{color:#b42318}',
      '.sigmenu-i.danger:hover{background:#fee4e2}',
      '.sigmenu-i.dis{color:#98a2b3;cursor:not-allowed;background:transparent}',
      '.sigmenu-sep{height:1px;margin:4px 6px;background:#eef0f4}'
    ].join('');
    (document.head || document.getElementsByTagName('head')[0]).appendChild(st);
  }

  function close() {
    if (box && box.parentNode) box.parentNode.removeChild(box);
    box = null;
    document.removeEventListener('click', onDoc, true);
    document.removeEventListener('keydown', onKey, true);
    window.removeEventListener('scroll', close, true);
    window.removeEventListener('resize', close, true);
  }
  function onDoc(e) { if (box && !box.contains(e.target)) close(); }
  function onKey(e) { if (e.key === 'Escape' || e.keyCode === 27) close(); }

  function show(x, y, items) {
    close();
    if (!items || !items.length) return;
    box = document.createElement('div');
    box.className = 'sigmenu';
    box.setAttribute('role', 'menu');
    items.forEach(function (it) {
      if (it.sep) {
        var sp = document.createElement('div'); sp.className = 'sigmenu-sep'; box.appendChild(sp); return;
      }
      var b = document.createElement('button');
      b.type = 'button';
      b.className = 'sigmenu-i' + (it.danger ? ' danger' : '') + (it.disabled ? ' dis' : '');
      b.setAttribute('role', 'menuitem');
      b.innerHTML = '<span class="ic">' + (it.icon || '') + '</span><span></span>';
      b.lastChild.textContent = it.label;
      if (it.disabled) {
        b.disabled = true;
        b.title = it.disabledTip || '';
      } else {
        b.addEventListener('click', function () { close(); try { it.run(); } catch (e) { } });
      }
      box.appendChild(b);
    });
    // 先放到屏幕外量尺寸，再按实际大小定位（避免贴边被裁掉）
    box.style.left = '-9999px';
    box.style.top = '-9999px';
    document.body.appendChild(box);
    var r = box.getBoundingClientRect();
    var left = Math.max(8, Math.min(x, window.innerWidth - r.width - 8));
    var top = Math.max(8, Math.min(y, window.innerHeight - r.height - 8));
    box.style.left = left + 'px';
    box.style.top = top + 'px';
    // 延后一帧再挂外部关闭监听，否则本次右键的后续 click 会立刻关掉它
    setTimeout(function () {
      document.addEventListener('click', onDoc, true);
      document.addEventListener('keydown', onKey, true);
      window.addEventListener('scroll', close, true);
      window.addEventListener('resize', close, true);
    }, 0);
  }

  window.SigMenu = { show: show, close: close };
})();
