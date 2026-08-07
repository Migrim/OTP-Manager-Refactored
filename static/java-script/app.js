/* OTP Manager — shared app shell (theme, sidebar, toasts, drawers, cmdk) */
(function () {
  "use strict";

  const ICONS = {
    home: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M3.5 11L12 3.5 20.5 11" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M5.5 9.5V20a1 1 0 001 1h11a1 1 0 001-1V9.5" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
    plus: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    users: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="9" cy="8" r="3.2" stroke="currentColor" stroke-width="1.8"/><path d="M2.5 20c1-3.6 3.7-5.5 6.5-5.5s5.5 1.9 6.5 5.5M16 8.2a3 3 0 110 5.9M21.5 20c-.7-2.5-2.2-4.2-4-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    building: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="4" y="3" width="11" height="18" rx="1" stroke="currentColor" stroke-width="1.8"/><path d="M15 9h5v12h-5M7.5 7h1M11 7h1M7.5 11h1M11 11h1M7.5 15h1M11 15h1" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    settings: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.8"/><path d="M19.4 13.5a7.6 7.6 0 000-3l2-1.5-2-3.4-2.3.9a7.6 7.6 0 00-2.6-1.5L14 2.5h-4l-.5 2.5a7.6 7.6 0 00-2.6 1.5l-2.3-.9-2 3.4 2 1.5a7.6 7.6 0 000 3l-2 1.5 2 3.4 2.3-.9c.8.7 1.7 1.2 2.6 1.5l.5 2.6h4l.5-2.6a7.6 7.6 0 002.6-1.5l2.3.9 2-3.4-2-1.5z" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>',
    search: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="11" cy="11" r="7" stroke="currentColor" stroke-width="2"/><path d="M21 21l-4.3-4.3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
    sun: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="4.5" stroke="currentColor" stroke-width="1.8"/><path d="M12 2v2.5M12 19.5V22M4.2 4.2l1.8 1.8M18 18l1.8 1.8M2 12h2.5M19.5 12H22M4.2 19.8L6 18M18 6l1.8-1.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    moon: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M20 14.5A8.5 8.5 0 119.5 4a7 7 0 0010.5 10.5z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>',
    logout: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M9 21H5a1 1 0 01-1-1V4a1 1 0 011-1h4M16 17l5-5-5-5M21 12H9" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    chevron: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    keysm: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><circle cx="8" cy="15" r="3.2" stroke="currentColor" stroke-width="1.8"/><path d="M10.3 12.7L19 4M15.5 8.2l2.3 2.3M18.2 5.5l2.3 2.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    searchBig: '<svg width="36" height="36" viewBox="0 0 24 24" fill="none"><circle cx="10.5" cy="10.5" r="7" stroke="currentColor" stroke-width="1.6"/><path d="M20 20l-4.3-4.3" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>',
    arrowUp: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 19V5M5 12l7-7 7 7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    collapse: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><rect x="3" y="4.5" width="18" height="15" rx="3" stroke="currentColor" stroke-width="1.6"/><path d="M9.5 4.5v15" stroke="currentColor" stroke-width="1.6"/></svg>',
    info: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 11v5.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="12" cy="8" r="1" fill="currentColor"/></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M5 13l4.5 4.5L19.5 7" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    xmark: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
    logs: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    refresh: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 12a8 8 0 0113.9-5.4M20 12a8 8 0 01-13.9 5.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M18 3v4h-4M6 21v-4h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    globe: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18" stroke="currentColor" stroke-width="1.6"/></svg>',
    shield: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><circle cx="12" cy="12" r="1" fill="currentColor"/></svg>',
    calendar: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="3.5" y="5" width="17" height="16" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M3.5 9.5h17M8 3v3.5M16 3v3.5" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>',
    play: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4l14 8-14 8V4z"/></svg>',
    pause: '<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="5" y="4" width="5" height="16" rx="1"/><rect x="14" y="4" width="5" height="16" rx="1"/></svg>',
    dots: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="12" cy="19" r="1.8"/></svg>',
    database: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><ellipse cx="12" cy="5.5" rx="8" ry="3" stroke="currentColor" stroke-width="1.7"/><path d="M4 5.5v13c0 1.7 3.6 3 8 3s8-1.3 8-3v-13" stroke="currentColor" stroke-width="1.7"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3" stroke="currentColor" stroke-width="1.7"/></svg>',
    wrench: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M14.7 6.3a4 4 0 00-5.3 4.9L3 17.6 6.4 21l6.4-6.4a4 4 0 004.9-5.3l-2.6 2.6-2.8-.8-.8-2.8 2.2-2z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/></svg>',
    backup: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M7 18a4.5 4.5 0 01-.5-9 5.5 5.5 0 0110.6-1.7A4 4 0 0117 15" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"/><path d="M12 11v8M9 16l3 3 3-3" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    terminal: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M7 9.5l3.5 3-3.5 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M13 15.5h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    power: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M12 3.5v8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M7.2 5.8a8 8 0 105.6-1.3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    copy: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><rect x="8" y="8" width="12" height="12" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M4 16V5a1 1 0 011-1h11" stroke="currentColor" stroke-width="1.8"/></svg>',
    edit: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M4 20l1-4.2L15.5 5.3a1.5 1.5 0 012.2 0l1 1a1.5 1.5 0 010 2.2L8.2 19 4 20z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>',
    trash: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    exportIco: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4.5-4.5M12 15l4.5-4.5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2.5a1.5 1.5 0 001.5 1.5h13a1.5 1.5 0 001.5-1.5V17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    pin: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M12 21s6-5.6 6-10.6A6 6 0 006 10.4C6 15.4 12 21 12 21z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><circle cx="12" cy="10.2" r="2" stroke="currentColor" stroke-width="1.5"/></svg>',
    pinFilled: '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M12 21s6-5.6 6-10.6A6 6 0 006 10.4C6 15.4 12 21 12 21z"/></svg>',
    warn: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3l10 18H2L12 3z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 10v4M12 17h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    lock: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><rect x="5" y="10.5" width="14" height="10" rx="2" stroke="#fff" stroke-width="1.8"/><path d="M8 10.5V8a4 4 0 018 0v2.5" stroke="#fff" stroke-width="1.8"/><circle cx="12" cy="15.3" r="1.3" fill="#fff"/></svg>',
    lockBig: '<svg width="36" height="36" viewBox="0 0 24 24" fill="none"><rect x="4.5" y="10.5" width="15" height="10.5" rx="2.4" stroke="currentColor" stroke-width="1.5"/><path d="M7.7 10.5V8a4.3 4.3 0 018.6 0v2.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="12" cy="14.9" r="1.35" fill="currentColor"/><path d="M12 16.25v2.1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>',
    eye: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M1.5 12S5 5 12 5s10.5 7 10.5 7-3.5 7-10.5 7S1.5 12 1.5 12z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.6"/></svg>',
    eyeOff: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M3 3l18 18M10.6 10.7a3 3 0 004 4M7 6.4C4.4 8 2.5 12 2.5 12S6 19 12 19c2 0 3.6-.5 4.9-1.3M17.5 15.6C20 14 21.5 12 21.5 12S18.7 6.7 13.6 5.4" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    github: '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 00-3.16 19.49c.5.09.68-.22.68-.48 0-.24-.01-1.02-.01-1.85-2.5.46-3.15-.61-3.35-1.17-.11-.29-.6-1.17-1.02-1.41-.35-.19-.85-.65-.01-.66.79-.01 1.35.72 1.54 1.02.9 1.52 2.34 1.09 2.91.83.09-.65.35-1.09.64-1.34-2.24-.25-4.59-1.12-4.59-4.96 0-1.1.39-1.99 1.03-2.69-.1-.26-.45-1.28.1-2.66 0 0 .84-.27 2.75 1.02a9.4 9.4 0 015 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.66.64.7 1.03 1.59 1.03 2.69 0 3.85-2.35 4.71-4.6 4.96.36.31.68.92.68 1.85 0 1.34-.01 2.42-.01 2.75 0 .27.18.58.69.48A10 10 0 0012 2z"/></svg>',
  };

  function setCookie(name, value) {
    document.cookie = name + "=" + encodeURIComponent(value) + "; path=/; max-age=31536000; SameSite=Lax";
  }
  function getCookie(name) {
    const m = document.cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
    return m ? decodeURIComponent(m[1]) : null;
  }

  function hydrateIcons(root) {
    (root || document).querySelectorAll("[data-icon]").forEach(el => {
      const name = el.getAttribute("data-icon");
      if (ICONS[name]) { el.innerHTML = ICONS[name]; el.removeAttribute("data-icon"); }
    });
  }

  let toastEl = null, toastTimer = null;
  function toast(msg) {
    if (toastEl) toastEl.remove();
    toastEl = document.createElement("div");
    toastEl.className = "toast";
    toastEl.textContent = msg;
    document.body.appendChild(toastEl);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { if (toastEl) { toastEl.remove(); toastEl = null; } }, 2200);
  }

  function copyText(text, label) {
    if (!text) return;
    const done = () => toast(label !== undefined ? label : "Copied: " + text);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, done);
    } else {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); } catch (e) {}
      ta.remove(); done();
    }
  }

  /* overlays: any element with class .overlay; open/close helpers */
  function openOverlay(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.classList.add("open");
    const first = el.querySelector("input:not([type=hidden]):not([disabled]), select, textarea");
    if (first) setTimeout(() => first.focus(), 60);
  }
  function closeOverlay(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("open");
  }
  function closeAllOverlays() {
    document.querySelectorAll(".overlay.open").forEach(el => el.classList.remove("open"));
  }
  document.addEventListener("click", e => {
    const ov = e.target.closest(".overlay");
    if (ov && e.target === ov) ov.classList.remove("open");
    const closer = e.target.closest("[data-close-overlay]");
    if (closer) {
      const ov2 = closer.closest(".overlay");
      if (ov2) ov2.classList.remove("open");
    }
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeAllOverlays();
  });

  /* digits with staggered flip-in animation (pass animate:false to update quietly) */
  function digitsHTML(code, animate) {
    if (animate === false) {
      return (code || "").split("").map(ch => '<span class="digit" style="animation:none">' + ch + "</span>").join("");
    }
    return (code || "").split("").map((ch, i) =>
      '<span class="digit" style="animation-delay:' + (i * 30) + 'ms">' + ch + "</span>"
    ).join("");
  }

  /* subtle animation for a code refreshing in place (as opposed to the section's initial load-in) */
  function digitsHTMLUpdate(code) {
    return (code || "").split("").map((ch, i) =>
      '<span class="digit digit-update" style="animation-delay:' + (i * 25) + 'ms">' + ch + "</span>"
    ).join("");
  }

  function ringSVG(size, radius, strokeWidth) {
    const c = 2 * Math.PI * radius;
    return '<svg class="ring" width="' + size + '" height="' + size + '" viewBox="0 0 36 36">' +
      '<circle class="ring-bg" cx="18" cy="18" r="' + radius + '" fill="none" stroke-width="' + strokeWidth + '"></circle>' +
      '<circle class="ring-fg" cx="18" cy="18" r="' + radius + '" fill="none" stroke-width="' + strokeWidth + '" stroke-linecap="round" stroke-dasharray="' + c.toFixed(2) + '" stroke-dashoffset="0"></circle></svg>';
  }
  function setRing(svg, remaining, period) {
    const fg = svg.querySelector(".ring-fg");
    if (!fg) return;
    const c = parseFloat(fg.getAttribute("stroke-dasharray"));
    fg.style.strokeDashoffset = (c * (1 - remaining / (period || 30))).toFixed(2);
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  async function fetchJSON(url, opts) {
    const o = Object.assign({ headers: {} }, opts || {});
    o.headers["X-Requested-With"] = "XMLHttpRequest";
    if (o.body && typeof o.body === "object" && !(o.body instanceof FormData)) {
      o.headers["Content-Type"] = "application/json";
      o.body = JSON.stringify(o.body);
    }
    const res = await fetch(url, o);
    let data = null;
    try { data = await res.json(); } catch (e) {}
    if (!res.ok) {
      const msg = (data && (data.error || data.message)) || ("Request failed (" + res.status + ")");
      throw new Error(msg);
    }
    return data;
  }

  /* ---------- ghost-text autocomplete ---------- */

  const IS_MAC = /Mac|iPhone|iPod|iPad/.test(navigator.platform || navigator.userAgent || "");
  const COPY_KEY_LABEL = IS_MAC ? "&#8984;C" : "Ctrl+C";

  function attachAutocomplete(input, getCandidates, hintEl) {
    if (!input || input.dataset.acBound) return;
    input.dataset.acBound = "1";

    const wrap = document.createElement("span");
    wrap.className = "ac-wrap";
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);
    const ghost = document.createElement("div");
    ghost.className = "ac-ghost";
    ghost.setAttribute("aria-hidden", "true");
    wrap.appendChild(ghost);
    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.tabIndex = -1;
    clearBtn.setAttribute("aria-label", "Clear search");
    clearBtn.innerHTML = ICONS.xmark;
    if (hintEl) {
      clearBtn.className = "ac-clear-slot";
      hintEl.parentNode.insertBefore(clearBtn, hintEl.nextSibling);
    } else {
      clearBtn.className = "ac-clear";
      wrap.classList.add("ac-has-clear");
      wrap.appendChild(clearBtn);
    }

    let current = null; // { text, code }

    function normalize(cand) {
      if (cand == null) return null;
      if (typeof cand === "object") {
        const text = cand.text == null ? "" : String(cand.text);
        return text ? { text: text, code: cand.code || null } : null;
      }
      const text = String(cand);
      return text ? { text: text, code: null } : null;
    }

    function bestMatch(value) {
      const q = value.toLowerCase();
      let best = null;
      (getCandidates() || []).forEach(raw => {
        const cand = normalize(raw);
        if (!cand) return;
        if (!cand.text.toLowerCase().startsWith(q)) return;
        if (!best || cand.text.length < best.text.length) best = cand;
      });
      return best;
    }

    function updateClearVisibility() {
      const has = !!input.value;
      clearBtn.style.display = has ? "flex" : "none";
      if (hintEl) hintEl.style.display = has ? "none" : "";
    }

    function renderGhost() {
      const value = input.value;
      current = value ? bestMatch(value) : null;
      updateClearVisibility();
      const remainder = current && current.text.length > value.length ? current.text.slice(value.length) : "";
      if (!current || (!remainder && !current.code)) { ghost.innerHTML = ""; return; }
      let html = '<span class="ac-typed">' + escapeHtml(value) + "</span>";
      if (remainder) html += '<span class="ac-suggest">' + escapeHtml(remainder) + "</span>";
      if (current.code) html += '<span class="ac-code">' + COPY_KEY_LABEL + " &middot; " + escapeHtml(current.code) + "</span>";
      if (remainder) html += '<span class="ac-tabhint">Tab &#8677;</span>';
      ghost.innerHTML = html;
    }

    function acceptSuggestion() {
      if (!current || current.text.length <= input.value.length) return;
      input.value = current.text;
      ghost.innerHTML = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }

    input.addEventListener("input", renderGhost);
    input.addEventListener("focus", renderGhost);
    input.addEventListener("blur", () => { ghost.innerHTML = ""; });
    input.addEventListener("keydown", e => {
      const hasRemainder = current && current.text.length > input.value.length;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "c" && current && current.code && input.selectionStart === input.selectionEnd) {
        e.preventDefault();
        copyText(current.code, "Copied code: " + current.code);
      } else if (e.key === "Tab" && hasRemainder && !e.shiftKey) {
        e.preventDefault();
        acceptSuggestion();
      } else if (e.key === "Escape" && current) {
        current = null;
        ghost.innerHTML = "";
      }
    });
    clearBtn.addEventListener("mousedown", e => e.preventDefault());
    clearBtn.addEventListener("click", () => {
      input.value = "";
      current = null;
      ghost.innerHTML = "";
      updateClearVisibility();
      input.focus();
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });

    updateClearVisibility();

    return { refresh: renderGhost };
  }

  /* ---------- theme / accent / sidebar ---------- */

  function applyTheme(dark) {
    document.documentElement.classList.toggle("dark-mode", dark);
    setCookie("theme", dark ? "dark" : "light");
    const btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.querySelector(".side-ico").innerHTML = dark ? ICONS.sun : ICONS.moon;
      btn.querySelector(".side-label").textContent = dark ? "Light Mode" : "Dark Mode";
    }
  }
  function applyAccent(color) {
    document.documentElement.style.setProperty("--accent", color);
    setCookie("accent", color);
  }
  function toggleSidebar() {
    const closed = document.documentElement.classList.toggle("sidebar-closed");
    setCookie("sidebar", closed ? "closed" : "open");
  }

  /* ---------- sidebar profile menu ---------- */

  function closeProfileMenu() {
    const el = document.querySelector(".sidebar-profile.open");
    if (el) el.classList.remove("open");
  }
  document.addEventListener("click", e => {
    const btn = e.target.closest("#profile-btn");
    if (btn) {
      const wrap = btn.closest(".sidebar-profile");
      const wasOpen = wrap.classList.contains("open");
      closeProfileMenu();
      if (!wasOpen) wrap.classList.add("open");
      return;
    }
    if (!e.target.closest(".profile-menu")) closeProfileMenu();
  });
  document.addEventListener("keydown", e => {
    if (e.key === "Escape") closeProfileMenu();
  });

  /* ---------- soft navigation (keeps the sidebar mounted across page loads) ---------- */

  const SOFT_NAV_EXCLUDE = new Set(["/server", "/logout"]);
  let pageLeaveHandlers = [];
  function onPageLeave(fn) { pageLeaveHandlers.push(fn); }
  function runPageLeaveHandlers() {
    const handlers = pageLeaveHandlers;
    pageLeaveHandlers = [];
    handlers.forEach(fn => { try { fn(); } catch (e) {} });
  }

  function softNavLinkFor(target) {
    const a = target.closest(".sidebar a[href]");
    if (!a || a.target || a.hasAttribute("download")) return null;
    let url;
    try { url = new URL(a.href, location.href); } catch (e) { return null; }
    if (url.origin !== location.origin) return null;
    if (SOFT_NAV_EXCLUDE.has(url.pathname)) return null;
    return a;
  }

  function setNavProgress(active) {
    const bar = document.getElementById("nav-progress");
    if (!bar) return;
    if (active) {
      bar.classList.add("loading");
      bar.style.width = "0%";
      requestAnimationFrame(() => { bar.style.width = "70%"; });
    } else {
      bar.style.width = "100%";
      setTimeout(() => { bar.classList.remove("loading"); bar.style.width = "0%"; }, 200);
    }
  }

  let navSeq = 0;
  async function softNavigate(href, push) {
    const seq = ++navSeq;
    setNavProgress(true);
    try {
      const res = await fetch(href, { headers: { "X-Requested-With": "XMLHttpRequest" } });
      if (seq !== navSeq) return;
      if (!res.ok) { location.href = href; return; }
      const html = await res.text();
      if (seq !== navSeq) return;
      const doc = new DOMParser().parseFromString(html, "text/html");
      const newMain = doc.querySelector("main");
      const newNav = doc.querySelector(".sidebar nav");
      if (!newMain || !newNav) { location.href = href; return; }

      runPageLeaveHandlers();
      closeProfileMenu();

      const curMain = document.querySelector("main");
      curMain.className = newMain.className;
      curMain.innerHTML = newMain.innerHTML;

      const curNav = document.querySelector(".sidebar nav");
      const oldDot = curNav.querySelector("#update-dot");
      const dotVisible = !!oldDot && oldDot.style.display !== "none";
      curNav.innerHTML = newNav.innerHTML;
      const newDot = curNav.querySelector("#update-dot");
      if (newDot && dotVisible) newDot.style.display = "inline-block";

      const pageScripts = document.getElementById("page-scripts");
      if (pageScripts) {
        pageScripts.innerHTML = "";
        doc.querySelectorAll("#page-scripts script").forEach(old => {
          const s = document.createElement("script");
          s.async = false;
          if (old.src) s.src = old.src; else s.textContent = old.textContent;
          pageScripts.appendChild(s);
        });
      }

      document.title = doc.title;
      hydrateIcons();
      if (push) history.pushState({ softNav: true }, "", href);
    } catch (e) {
      location.href = href;
    } finally {
      setNavProgress(false);
    }
  }

  document.addEventListener("click", e => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (SOFT_NAV_EXCLUDE.has(location.pathname)) return;
    const a = softNavLinkFor(e.target);
    if (!a) return;
    const url = new URL(a.href, location.href);
    if (url.pathname === location.pathname && url.search === location.search) { e.preventDefault(); return; }
    e.preventDefault();
    softNavigate(a.href, true);
  });

  window.addEventListener("popstate", () => {
    if (!document.querySelector(".sidebar")) return;
    softNavigate(location.href, false);
  });

  /* ---------- command palette ---------- */

  const cmdk = {
    el: null, input: null, results: null, foot: null,
    items: [], index: 0, secrets: null, fetchedAt: 0, open: false, closeTimer: null,
    baseRemaining: 30, ticking: false, refreshing: false,
  };

  function cmdkMount() {
    cmdk.el = document.getElementById("cmdk");
    if (!cmdk.el) return;
    cmdk.input = cmdk.el.querySelector("input");
    cmdk.results = cmdk.el.querySelector(".cmdk-results");
    cmdk.foot = cmdk.el.querySelector(".cmdk-foot");
    cmdk.input.addEventListener("input", cmdkRender);
    cmdk.el.addEventListener("mousedown", e => { if (e.target === cmdk.el) cmdkClose(); });
  }
  async function cmdkOpen() {
    if (!cmdk.el) return;
    clearTimeout(cmdk.closeTimer);
    cmdk.open = true;
    cmdk.input.value = "";
    cmdk.index = 0;
    cmdk.el.classList.remove("closing");
    cmdk.el.classList.add("mounted", "opening");
    setTimeout(() => cmdk.input.focus(), 40);
    cmdkRender();
    if (!cmdk.secrets || Date.now() - cmdk.fetchedAt > 15000) {
      try {
        cmdk.secrets = await fetchJSON("/api/secrets");
        cmdk.fetchedAt = Date.now();
        cmdk.baseRemaining = cmdk.secrets.length ? Math.max(0, Math.min(30, cmdk.secrets[0].seconds_remaining)) : 30;
        cmdkRender();
      } catch (e) { /* not critical */ }
    }
    if (!cmdk.ticking) { cmdk.ticking = true; requestAnimationFrame(cmdkTick); }
  }
  async function cmdkRefreshCodes() {
    if (cmdk.refreshing) return;
    cmdk.refreshing = true;
    try {
      cmdk.secrets = await fetchJSON("/api/secrets");
      cmdk.fetchedAt = Date.now();
      cmdk.baseRemaining = cmdk.secrets.length ? Math.max(0, Math.min(30, cmdk.secrets[0].seconds_remaining)) : 30;
      cmdkRender();
    } catch (e) { /* not critical */ } finally { cmdk.refreshing = false; }
  }
  function cmdkTick() {
    if (!cmdk.open) { cmdk.ticking = false; return; }
    const rings = cmdk.results ? cmdk.results.querySelectorAll(".ring") : [];
    if (rings.length) {
      const remaining = Math.max(0, cmdk.baseRemaining - (Date.now() - cmdk.fetchedAt) / 1000);
      rings.forEach(svg => setRing(svg, remaining, 30));
      if (remaining <= 0) cmdkRefreshCodes();
    }
    requestAnimationFrame(cmdkTick);
  }
  function cmdkClose() {
    if (!cmdk.el || !cmdk.open) return;
    cmdk.open = false;
    cmdk.el.classList.remove("opening");
    cmdk.el.classList.add("closing");
    cmdk.closeTimer = setTimeout(() => cmdk.el.classList.remove("mounted", "closing"), 220);
  }
  function cmdkRender() {
    if (!cmdk.el) return;
    const q = cmdk.input.value.trim().toLowerCase();
    cmdk.items = [];
    if (!q) {
      cmdk.results.innerHTML = '<div class="cmdk-hint">Type to search companies, names, emails, or codes</div>';
      cmdk.foot.style.display = "none";
      return;
    }
    cmdk.foot.style.display = "flex";
    const secrets = cmdk.secrets || [];
    const secretHits = secrets.filter(s =>
      (s.name || "").toLowerCase().includes(q) ||
      (s.company_name || "").toLowerCase().includes(q) ||
      ((s.email && s.email !== "none") ? s.email.toLowerCase() : "").includes(q) ||
      (s.current_code || "").includes(q)
    ).slice(0, 8).map(s => ({
      type: "secret", id: s.id, title: s.name,
      subtitle: (s.company_name || "") + (s.email && s.email !== "none" ? " · " + s.email : ""),
      badge: s.current_code || "", icon: "keysm",
    }));
    const companies = [...new Set(secrets.map(s => s.company_name).filter(Boolean))].sort();
    const companyHits = companies.filter(n => n.toLowerCase().includes(q)).slice(0, 6).map(n => ({
      type: "company", name: n, title: n, subtitle: "Company", badge: "", icon: "building",
    }));
    cmdk.items = secretHits.concat(companyHits);
    if (cmdk.index >= cmdk.items.length) cmdk.index = 0;
    if (!cmdk.items.length) {
      cmdk.results.innerHTML = '<div class="cmdk-hint">No results</div>';
      return;
    }
    cmdk.results.innerHTML = cmdk.items.map((r, i) =>
      '<div class="cmdk-row' + (i === cmdk.index ? " active" : "") + '" data-idx="' + i + '">' +
      '<span class="ico">' + (ICONS[r.icon] || "") + "</span>" +
      '<div class="cmdk-main"><div class="cmdk-title">' + escapeHtml(r.title) + '</div>' +
      '<div class="cmdk-sub">' + escapeHtml(r.subtitle) + "</div></div>" +
      '<span class="cmdk-badge-wrap">' + (r.badge ? ringSVG(20, 13, 2.5) : "") +
      '<span class="cmdk-badge">' + escapeHtml(r.badge) + "</span></span></div>"
    ).join("");
    cmdk.results.querySelectorAll(".cmdk-row").forEach(row => {
      row.addEventListener("click", () => cmdkSelect(cmdk.items[+row.dataset.idx]));
      row.addEventListener("mousemove", () => {
        const i = +row.dataset.idx;
        if (i !== cmdk.index) { cmdk.index = i; cmdkHighlight(); }
      });
    });
  }
  function cmdkHighlight() {
    cmdk.results.querySelectorAll(".cmdk-row").forEach((row, i) =>
      row.classList.toggle("active", i === cmdk.index));
  }
  function cmdkSelect(r) {
    if (!r) return;
    cmdkClose();
    if (r.type === "secret") window.location.href = "/?q=" + encodeURIComponent(r.title);
    else if (r.type === "company") window.location.href = "/?company=" + encodeURIComponent(r.name);
  }

  document.addEventListener("keydown", e => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (cmdk.open) cmdkClose(); else cmdkOpen();
      return;
    }
    if (!cmdk.open) return;
    if (e.key === "Escape") { cmdkClose(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); if (cmdk.items.length) { cmdk.index = (cmdk.index + 1) % cmdk.items.length; cmdkHighlight(); } }
    else if (e.key === "ArrowUp") { e.preventDefault(); if (cmdk.items.length) { cmdk.index = (cmdk.index - 1 + cmdk.items.length) % cmdk.items.length; cmdkHighlight(); } }
    else if (e.key === "Enter") { if (cmdk.items[cmdk.index]) cmdkSelect(cmdk.items[cmdk.index]); }
  });

  /* ---------- boot ---------- */

  document.addEventListener("DOMContentLoaded", () => {
    hydrateIcons();
    cmdkMount();

    const themeBtn = document.getElementById("theme-toggle");
    if (themeBtn) {
      applyTheme(document.documentElement.classList.contains("dark-mode"));
      themeBtn.addEventListener("click", () =>
        applyTheme(!document.documentElement.classList.contains("dark-mode")));
    }
    document.querySelectorAll("[data-toggle-sidebar]").forEach(b =>
      b.addEventListener("click", toggleSidebar));

    document.querySelectorAll(".flash-msg").forEach(el => {
      toast(el.textContent.trim());
      el.remove();
    });
  });

  window.App = {
    ICONS, toast, copyText, hydrateIcons, digitsHTML, digitsHTMLUpdate, ringSVG, setRing, escapeHtml,
    fetchJSON, openOverlay, closeOverlay, closeAllOverlays, applyAccent, setCookie, getCookie,
    cmdkOpen, attachAutocomplete, onPageLeave,
  };
})();
