/* 签名图方向自适应（v1.3.0）
 *
 * 背景：同一个签名人可以同时保存两版电子签名——
 *   signature_image    横版（横排拼装）
 *   signature_image_v  竖版（竖排拼装）
 * 用途不同：
 *   设备维护保养记录（DEMO-QR-001）的每日签名格是「高窄格」（约 28×100px）→ 必须用竖版
 *   温湿度监测记录（DEMO-QR-008）的记录员栏、大屏卡片是「横向格」        → 用横版
 *
 * 用法：渲染时把两版都写进 data 属性，渲染完调用 SIGFIT.fit(容器)
 *   <img class="sigthumb"${SIGFIT.attrs(h, v)}>
 *   SIGFIT.fit();           // 按所在格子真实宽高比自动挑一版
 * 打印前会自动再算一次（beforeprint）。
 */
(function (w) {
  function clean(s) { return String(s == null ? '' : s).replace(/"/g, '&quot;'); }
  // 取指定方向的签名；缺哪版就用另一版兜底
  function pick(o, dir) {
    o = o || {};
    var h = o.signature_image || o.image_h || o.h || '';
    var v = o.signature_image_v || o.image_v || o.v || '';
    return dir === 'v' ? (v || h) : (h || v);
  }
  // 生成 img 上的 data 属性（横/竖各一）
  function attrs(h, v) {
    h = h || ''; v = v || '';
    if (!v) v = h;
    if (!h) h = v;
    return ' data-sh="' + clean(h) + '" data-sv="' + clean(v) + '"';
  }
  // 遍历页面上所有带 data-sh 的签名图，按容器形状决定显示哪一版
  function fit(root) {
    var list = (root || document).querySelectorAll('img[data-sh]');
    for (var i = 0; i < list.length; i++) {
      var img = list[i];
      var h = img.getAttribute('data-sh') || '', v = img.getAttribute('data-sv') || '';
      if (!h) h = v;
      if (!v) v = h;
      var box = (img.closest && img.closest('td,th,li,div,span')) || img.parentNode;
      var r = box && box.getBoundingClientRect ? box.getBoundingClientRect() : null;
      // 高窄格（宽高比 < 1.15）用竖版，其余用横版
      var wantV = !!(r && r.width > 0 && r.height > 0 && (r.width / r.height) < 1.15);
      var src = wantV ? v : h;
      if (src && img.getAttribute('src') !== src) img.setAttribute('src', src);
    }
  }
  w.SIGFIT = { pick: pick, attrs: attrs, fit: fit };
  w.addEventListener('beforeprint', function () { fit(); });
  if (w.matchMedia) {
    try {
      var mq = w.matchMedia('print');
      if (mq.addEventListener) mq.addEventListener('change', function (e) { if (e.matches) fit(); });
    } catch (e) { /* 老浏览器忽略 */ }
  }
})(window);
