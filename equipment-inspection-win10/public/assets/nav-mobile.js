/* 开源补丁（v1.42.0）：旧 `.nav` 的移动端折叠开关。 */
(function () {
  if (window.__NAVMOBILE__) return; window.__NAVMOBILE__ = true;
  function init() {
    var nav = document.querySelector('nav.nav');
    if (!nav) return;
    var btn = nav.querySelector('.nav-toggle');
    if (!btn) return;
    function setOpen(v) {
      if (v) { nav.classList.add('nav-open'); } else { nav.classList.remove('nav-open'); }
      btn.setAttribute('aria-expanded', v ? 'true' : 'false');
    }
    btn.addEventListener('click', function (e) {
      e.preventDefault(); e.stopPropagation();
      setOpen(!nav.classList.contains('nav-open'));
    });
    // 点菜单以外的区域收起（与 .app-nav 的手感保持一致）
    document.addEventListener('click', function (e) {
      if (!nav.classList.contains('nav-open')) return;
      if (nav.contains(e.target)) return;
      setOpen(false);
    });
    // 视口变宽回桌面时收起，避免残留 class 影响断点以上的布局
    window.addEventListener('resize', function () { if (window.innerWidth > 760) setOpen(false); });
    // 打印前收起，免得把展开的菜单印出来
    window.addEventListener('beforeprint', function () { setOpen(false); });
  }
  if (document.readyState !== 'loading') init();
  document.addEventListener('DOMContentLoaded', init);
})();
