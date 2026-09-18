/* 科室温湿度超限登录提醒（v1.13.0 / v1.30.4 每条超限记录可点击直达对应房间温湿度页）
 * 用法：在页面放一个 <div id="env_alert"></div>（可选），并引入本脚本：
 *   <script src="/assets/dept.js"></script>
 *   <script src="/assets/env-alert.js"></script>
 * 行为：本科室人员登录后，自动拉 /api/env/alerts，把超范围的温湿度记录以分级横幅展示。
 * 等级：超出 ≤1 度=注意(黄) / ≤2=警告(橙) / >2=危险(红)。无科室或无超限则不显示。
 * v1.30.4：每条 <li> 整行可点 → /env.html?room=房间名；头部「去温湿度记录」也带上首条房间。
 */
(function () {
  function esc(s) {
    return (s == null ? '' : String(s)).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  var PERIOD = { AM: '上午', PM: '下午', Night: '晚上' };
  var LV_CLASS = { '注意': 'lv-notice', '警告': 'lv-warn', '危险': 'lv-danger' };
  var LV_ICON = { '注意': 'ℹ️', '警告': '⚠️', '危险': '🛑' };

  // 注入样式（幂等）
  if (!document.getElementById('env_alert_style')) {
    var st = document.createElement('style');
    st.id = 'env_alert_style';
    st.textContent = [
      '.env-alert{margin:10px 0;padding:10px 14px 12px;border-radius:10px;position:relative;box-shadow:0 4px 14px rgba(0,0,0,.08);font-size:13px;line-height:1.6}',
      '.env-alert-注意{background:#fff8e1;border:1px solid #ffe08a;color:#7a5b00}',
      '.env-alert-警告{background:#fff1e0;border:1px solid #ffb061;color:#8a4400}',
      '.env-alert-危险{background:#ffeaea;border:1px solid #ff9a9a;color:#a30000}',
      '.env-alert .ea-head{font-weight:700;margin-bottom:6px}',
      '.env-alert .ea-list{margin:0;padding-left:0;list-style:none}',
      '.env-alert .ea-list li{padding:3px 0;border-top:1px dashed rgba(0,0,0,.08)}',
      '.env-alert .ea-list li:first-child{border-top:none}',
      '.env-alert .ea-more{opacity:.7;font-style:italic}',
      '.env-alert .ea-x{position:absolute;top:6px;right:10px;border:none;background:transparent;font-size:18px;line-height:1;cursor:pointer;opacity:.6}',
      '.env-alert .ea-x:hover{opacity:1}',
      '.env-alert .ea-lv{display:inline-block;min-width:52px;text-align:center;font-weight:700;border-radius:6px;padding:1px 6px;margin-right:6px;font-size:12px}',
      '.env-alert .lv-notice{background:#ffe9a8;color:#7a5b00}',
      '.env-alert .lv-warn{background:#ffb061;color:#5a2d00}',
      '.env-alert .lv-danger{background:#ff6b6b;color:#fff}',
      '.env-alert a{color:inherit;text-decoration:underline;font-weight:700}',
      '.env-alert .ea-list li[data-earoom]{cursor:pointer;border-radius:6px}',
      '.env-alert .ea-list li[data-earoom]:hover{background:rgba(0,0,0,.05)}',
      '.env-alert .ea-list li[data-earoom]:focus-visible{outline:2px solid #0a66c2;outline-offset:1px}'
    ].join('');
    (document.head || document.getElementsByTagName('head')[0]).appendChild(st);
  }

  function render(data) {
    var box = document.getElementById('env_alert');
    if (!box) {
      box = document.createElement('div');
      box.id = 'env_alert';
      box.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;padding:8px';
      document.body.appendChild(box);
    }
    if (!data || !data.ok || !data.alerts || !data.alerts.length) {
      box.innerHTML = ''; box.style.display = 'none'; return;
    }
    var a = data.alerts, c = data.counts || {};
    var wrap = document.createElement('div');
    wrap.className = 'env-alert env-alert-' + (data.maxLevel || '注意');
    var items = a.slice(0, 12).map(function (it) {
      var p = PERIOD[it.period] || it.period || '';
      // v1.30.4：整行可点 —— data-earoom 带原始房间名（不用 data-room，避免与
      // rooms.html 等页面「[data-room]→index.html」的全局点击委托冲突被覆盖）
      return '<li data-earoom="' + esc(it.room) + '" tabindex="0" role="button" aria-label="打开 ' + esc(it.room) + ' 的温湿度记录"><span class="ea-lv ' + LV_CLASS[it.level] + '">' + LV_ICON[it.level] + it.level + '</span>'
        + '<b>' + esc(it.room) + '</b> · ' + esc(it.date) + ' ' + p + ' · ' + esc(it.type) + ' '
        + it.value + it.unit + '（' + esc(it.boundType) + it.limit + it.unit + '，超出 ' + it.exceed + it.unit + '）</li>';
    }).join('');
    if (a.length > 12) items += '<li class="ea-more">…另有 ' + (a.length - 12) + ' 项，详见温湿度记录页</li>';
    wrap.innerHTML = '<button class="ea-x" onclick="this.parentNode.style.display=\'none\'">×</button>'
      + '<div class="ea-head">' + LV_ICON[data.maxLevel] + ' <b>本科室（' + esc(data.dept) + '）温湿度超限提醒</b> · 共 ' + a.length + ' 项'
      + '（<span class="' + LV_CLASS['危险'] + '">危险 ' + (c['危险'] || 0) + '</span> / <span class="' + LV_CLASS['警告'] + '">警告 ' + (c['警告'] || 0) + '</span> / <span class="' + LV_CLASS['注意'] + '">注意 ' + (c['注意'] || 0) + '</span>）'
      + ' · <a href="/env.html?room=' + encodeURIComponent(a.length ? (a[0].room || '') : '') + '" target="_blank" rel="noopener">去温湿度记录 →</a></div>'
      + '<ul class="ea-list">' + items + '</ul>';
    // v1.30.4：点整条 → 直达该房间温湿度页（键盘 Enter/空格 同样可触发）
    Array.prototype.forEach.call(wrap.querySelectorAll('li[data-earoom]'), function (li) {
      var go = function () { location.href = '/env.html?room=' + encodeURIComponent(li.getAttribute('data-earoom')); };
      li.addEventListener('click', go);
      li.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
    });
    box.innerHTML = '';
    box.appendChild(wrap);
    box.style.display = '';
  }

  function init() {
    if (!window.DEPT) { render(null); return; }
    Promise.resolve(DEPT.loaded ? DEPT.me : DEPT.load()).then(function () {
      if (!DEPT.dept) { render(null); return; }
      fetch('/api/env/alerts', { credentials: 'same-origin' })
        .then(function (r) { return r.json(); })
        .then(render)
        .catch(function () { render(null); });
    }).catch(function () { render(null); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
