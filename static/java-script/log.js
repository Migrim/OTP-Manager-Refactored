(function () {
  function init() {
    const bodyEl = document.getElementById('logsBody');
    const searchInput = document.getElementById('searchInput');
    const liveBtn = document.getElementById('liveBtn');
    const resetBtn = document.getElementById('resetBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const lastUpdatedEl = document.getElementById('lastUpdated');
    const sourcesWrap = document.getElementById('types');
    const dayLabel = document.getElementById('dayLabel');
    const dayPicker = document.getElementById('dayPicker');
    const dayDropdown = document.getElementById('dayDropdown');
    const dayHidden = document.getElementById('dayHidden');
    const dayForm = document.getElementById('dayForm');
    const tableScroll = document.getElementById('tableScroll');
    const levelChecks = [...document.querySelectorAll('.lvl')];

    function fmtDay(iso) {
      const m = String(iso || '').trim().match(/^(\d{4})-(\d{2})-(\d{2})$/);
      if (!m) return iso;
      return `${m[3]}-${m[2]}-${m[1]}`;
    }

    if (dayDropdown) {
      dayDropdown.querySelectorAll('.dropdown-item').forEach(item => {
        const iso = item.textContent.trim();
        const m = iso.match(/^(\d{4})-(\d{2})-(\d{2})$/);
        if (m) item.textContent = fmtDay(iso);
      });
    }

    if (dayLabel) {
      const iso = dayLabel.textContent.trim();
      dayLabel.dataset.raw = iso;
      dayLabel.textContent = fmtDay(iso);
      if (dayHidden && !dayHidden.value) dayHidden.value = iso;
    }

    if (!tableScroll) return;

    const LEVELS = ['DEBUG','INFO','WARN','ERROR','CRITICAL'];

    let live = true;
    let lastUpdateTime = null;
    let raw = [];
    let filtered = [];
    let toastTimer = null;

    function showToast(msg) {
      const t = document.getElementById('toast');
      if (!t) return;
      t.textContent = msg;
      t.classList.add('show');
      clearTimeout(toastTimer);
      toastTimer = setTimeout(() => t.classList.remove('show'), 1600);
    }

    function setLive(state, announce) {
      if (live === state) return;
      live = state;
      liveBtn.classList.toggle('on', live);
      liveBtn.innerHTML = live ? `<i class="fa-solid fa-play"></i> Live` : `<i class="fa-solid fa-pause"></i> Paused`;
      if (announce) alert(live ? 'Live resumed' : 'Live Update paused');
      if (live) tableScroll.scrollTop = tableScroll.scrollHeight;
    }

    function isAtBottom(el) {
      return el.scrollHeight - el.clientHeight - el.scrollTop <= 2;
    }

    tableScroll.addEventListener('scroll', () => {
      if (isAtBottom(tableScroll)) setLive(true, true);
      else setLive(false, true);
    });

    function parseLine(line) {
      const s = line.trim();
      const m = s.match(/^(?:\[\]\:\s*)?(?:(\d{4}-\d{2}-\d{2})\s+)?(\d{2}:\d{2}:\d{2})\s+\[(INFO|ERROR|WARNING|WARN|DEBUG|CRITICAL)\]\s+\[([^\]]+)\]:\s*(.*)$/);
      if (!m) return null;
      const lvl = m[3] === 'WARNING' ? 'WARN' : m[3];
      const ts = (m[1] ? m[1] + ' ' : '') + m[2];
      return { ts, level: lvl, source: m[4], message: m[5] };
    }

    function levelBadge(level) {
      const l = level.toUpperCase();
      const cls = { INFO: 'info', WARN: 'warn', ERROR: 'error', DEBUG: 'debug', CRITICAL: 'critical' }[l] || 'info';
      return `<span class="badge ${cls}">${l}</span>`;
    }

    function buildSourceFilters() {
      const uniques = Array.from(new Set(raw.map(r => r.source))).sort((a, b) => a.localeCompare(b));
      sourcesWrap.innerHTML = uniques.map(src => `
        <label class="chk">
          <input type="checkbox" class="srcf" value="${src}">
          <span>${src}</span>
        </label>
      `).join('');
      document.querySelectorAll('.srcf').forEach(c => c.addEventListener('change', applyFilters));
    }

    function renderRows(rows) {
      bodyEl.innerHTML = rows.map(r => `
        <tr>
          <td class="ts">${r.ts}</td>
          <td class="lvl">${levelBadge(r.level)}</td>
          <td class="msg">${r.message}</td>
          <td class="src">${r.source}</td>
        </tr>
      `).join('');
      if (live) tableScroll.scrollTop = tableScroll.scrollHeight;
    }

    function applyFilters() {
      const q = searchInput.value.trim().toLowerCase();
      const lvlSel = new Set(levelChecks.filter(c => c.checked).map(c => c.value));
      const srcSel = new Set([...document.querySelectorAll('.srcf')].filter(c => c.checked).map(c => c.value));
      filtered = raw.filter(r => {
        if (lvlSel.size && !lvlSel.has(r.level)) return false;
        if (srcSel.size && !srcSel.has(r.source)) return false;
        if (q && !(`${r.ts} ${r.level} ${r.source} ${r.message}`.toLowerCase().includes(q))) return false;
        return true;
      });
      renderRows(filtered);
      updateCounts();
    }

    function updateCounts() {
      LEVELS.forEach(l => {
        const n = filtered.filter(r => r.level === l).length;
        const el = document.getElementById(`count-${l.toLowerCase()}`);
        if (el) el.textContent = n;
      });
    }

    async function loadLogs() {
      const dayParam = (dayHidden && dayHidden.value) || (dayLabel && dayLabel.dataset.raw) || (dayLabel && dayLabel.textContent) || '';
      const res = await fetch(`/api/logs?day=${encodeURIComponent(dayParam)}`);
      if (!res.ok) return;
      const data = await res.json();
      const parsed = data.logs.map(l => parseLine(l)).filter(Boolean);
      raw = parsed;
      lastUpdateTime = Date.now();
      buildSourceFilters();
      applyFilters();
      updateLastUpdated();
    }

    function updateLastUpdated() {
      if (!lastUpdateTime) return;
      const s = Math.floor((Date.now() - lastUpdateTime) / 1000);
      let txt = 'just now';
      if (s >= 60) {
        const m = Math.floor(s / 60);
        txt = `${m} min${m !== 1 ? 's' : ''} ago`;
      } else if (s > 0) {
        txt = `${s} second${s !== 1 ? 's' : ''} ago`;
      }
      lastUpdatedEl.textContent = `Last updated ${txt}`;
    }

    searchInput.addEventListener('input', applyFilters);
    levelChecks.forEach(c => c.addEventListener('change', applyFilters));
    resetBtn.addEventListener('click', () => {
      searchInput.value = '';
      levelChecks.forEach(c => c.checked = false);
      document.querySelectorAll('.srcf').forEach(c => c.checked = false);
      applyFilters();
    });
    refreshBtn.addEventListener('click', loadLogs);
    liveBtn.addEventListener('click', () => setLive(!live, true));

    document.querySelectorAll('.filter-section').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.toggle;
        btn.classList.toggle('open');
        document.getElementById(id).classList.toggle('open');
      });
    });

    dayPicker.addEventListener('click', () => dayDropdown.classList.toggle('open'));
    dayDropdown.addEventListener('click', e => {
      const it = e.target.closest('.dropdown-item');
      if (!it) return;
      const raw = it.dataset.day || it.textContent.trim().replace(/^(\d{2})-(\d{2})-(\d{4})$/, '$3-$2-$1');
      dayLabel.dataset.raw = raw;
      dayLabel.textContent = fmtDay(raw);
      dayHidden.value = raw;
      dayDropdown.classList.remove('open');
      dayForm.submit();
    });

    document.querySelectorAll('.filter-body').forEach(el => el.classList.add('open'));
    document.querySelectorAll('.filter-section').forEach(el => el.classList.add('open'));

    loadLogs();
    setInterval(() => { if (live) loadLogs(); }, 5000);
    setInterval(updateLastUpdated, 1000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
