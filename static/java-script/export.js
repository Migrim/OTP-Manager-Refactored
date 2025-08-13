document.addEventListener('DOMContentLoaded', () => {
  const moreBtn = document.getElementById('moreBtn');
  const menu = document.getElementById('moreMenu');
  const logsBody = document.getElementById('logsBody');
  if (!moreBtn || !menu || !logsBody) return;

  function closeMenu() {
    if (menu.hasAttribute('hidden')) return;
    menu.setAttribute('hidden', '');
    document.removeEventListener('mousedown', outsideClose, true);
    document.removeEventListener('keydown', keyClose, true);
  }

  function toggleMenu() {
    if (menu.hasAttribute('hidden')) {
      const r = moreBtn.getBoundingClientRect();
      menu.style.top = `${r.bottom + 6 + window.scrollY}px`;
      menu.style.left = `${r.right - menu.offsetWidth + window.scrollX}px`;
      menu.removeAttribute('hidden');
      document.addEventListener('mousedown', outsideClose, true);
      document.addEventListener('keydown', keyClose, true);
    } else {
      closeMenu();
    }
  }

  function outsideClose(e) {
    if (!menu.contains(e.target) && e.target !== moreBtn) closeMenu();
  }

  function keyClose(e) {
    if (e.key === 'Escape') closeMenu();
  }

  function tableToText() {
    const rows = [...logsBody.querySelectorAll('tr')];
    return rows.map(tr => {
      const t = tr.querySelector('td.ts')?.textContent?.trim() || '';
      const l = tr.querySelector('td.lvl')?.textContent?.trim() || '';
      const m = tr.querySelector('td.msg')?.textContent?.trim() || '';
      const s = tr.querySelector('td.src')?.textContent?.trim() || '';
      return `${t}\t${l}\t${m}\t${s}`;
    }).join('\n');
  }

  function download(ext) {
    const day = (document.getElementById('dayLabel')?.textContent || 'logs').replace(/\s+/g, '_');
    const content = tableToText();
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${day}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    closeMenu();
  }

  moreBtn.addEventListener('click', toggleMenu);

  menu.addEventListener('click', e => {
    const btn = e.target.closest('.menu-item');
    if (!btn) return;
    const ext = btn.getAttribute('data-ext') || 'txt';
    download(ext);
  });
});