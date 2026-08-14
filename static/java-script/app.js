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
    send: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M4 12h15M13 6l7 6-7 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    collapse: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><rect x="3" y="4.5" width="18" height="15" rx="3" stroke="currentColor" stroke-width="1.6"/><path d="M9.5 4.5v15" stroke="currentColor" stroke-width="1.6"/></svg>',
    info: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/><path d="M12 11v5.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/><circle cx="12" cy="8" r="1" fill="currentColor"/></svg>',
    check: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M5 13l4.5 4.5L19.5 7" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    xmark: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6L6 18" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/></svg>',
    logs: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 6h16M4 12h16M4 18h10" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>',
    refresh: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M4 12a8 8 0 0113.9-5.4M20 12a8 8 0 01-13.9 5.4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M18 3v4h-4M6 21v-4h4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    sparkle: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2l2.4 7.6L22 12l-7.6 2.4L12 22l-2.4-7.6L2 12l7.6-2.4L12 2z" fill="currentColor"/></svg>',
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
    lock: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><rect x="5" y="10.5" width="14" height="10" rx="2" stroke="currentColor" stroke-width="1.8"/><path d="M8 10.5V8a4 4 0 018 0v2.5" stroke="currentColor" stroke-width="1.8"/><circle cx="12" cy="15.3" r="1.3" fill="currentColor"/></svg>',
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

  const TOAST_MAX = 4;
  const TOAST_ICON = { success: "check", error: "xmark", info: "info" };
  let toastViewport = null;
  let activeConfirmToast = null;

  /* FLIP-style reflow: only toasts whose position actually changes get an animation */
  function snapshotToastRects(exclude) {
    if (!toastViewport) return null;
    const rects = new Map();
    for (const child of toastViewport.children) {
      if (child === exclude) continue;
      rects.set(child, child.getBoundingClientRect());
    }
    return rects;
  }
  function playToastReflow(rects) {
    if (!rects) return;
    rects.forEach((firstRect, el) => {
      if (!el.parentNode) return;
      const dy = firstRect.top - el.getBoundingClientRect().top;
      if (Math.abs(dy) < 0.5) return;
      el.style.transition = "none";
      el.style.transform = "translateY(" + dy + "px)";
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          el.style.transition = "transform 0.32s cubic-bezier(.22,1,.36,1)";
          el.style.transform = "";
          el.addEventListener("transitionend", function te(e) {
            if (e.propertyName !== "transform") return;
            el.style.transition = "";
            el.removeEventListener("transitionend", te);
          });
        });
      });
    });
  }

  function mountToast(className, replaceEl) {
    if (!toastViewport) {
      toastViewport = document.createElement("div");
      toastViewport.className = "toast-viewport";
      document.body.appendChild(toastViewport);
    }
    const rects = snapshotToastRects(replaceEl);
    if (replaceEl && replaceEl.parentNode) replaceEl.remove();
    while (toastViewport.children.length >= TOAST_MAX) {
      toastViewport.firstElementChild.remove();
    }
    const el = document.createElement("div");
    el.className = className;
    toastViewport.appendChild(el);
    playToastReflow(rects);
    return el;
  }
  function closeToast(el) {
    if (el === activeConfirmToast) activeConfirmToast = null;
    if (!el.parentNode || el.classList.contains("leaving")) return;
    el.classList.add("leaving");
    el.addEventListener("animationend", () => {
      const rects = snapshotToastRects(el);
      el.remove();
      playToastReflow(rects);
    }, { once: true });
  }
  function toast(msg, type) {
    const el = mountToast("toast" + (type ? " " + type : ""));
    const icoName = TOAST_ICON[type] || "info";
    el.innerHTML =
      '<span class="toast-ico">' + ICONS[icoName] + "</span>" +
      '<span class="toast-msg"></span>' +
      '<button class="toast-close" type="button" aria-label="Dismiss">' + ICONS.xmark + "</button>";
    el.querySelector(".toast-msg").textContent = msg;

    let timer;
    const dismiss = () => { clearTimeout(timer); closeToast(el); };
    timer = setTimeout(dismiss, 2600);
    el.addEventListener("mouseenter", () => clearTimeout(timer));
    el.addEventListener("mouseleave", () => { timer = setTimeout(dismiss, 1600); });
    el.querySelector(".toast-close").addEventListener("click", dismiss);
  }

  /* persistent yes/no -> type-to-confirm toast; stays until resolved */
  function confirmToast(message, opts) {
    opts = opts || {};
    const confirmWord = (opts.confirmWord || "CONFIRM").toUpperCase();
    const el = mountToast("toast confirm", activeConfirmToast);
    activeConfirmToast = el;
    el.innerHTML =
      '<div class="toast-confirm-head">' +
        '<span class="toast-ico">' + (opts.icon || ICONS.warn) + "</span>" +
        '<div class="toast-confirm-msg"></div>' +
      "</div>" +
      '<div class="toast-confirm-actions">' +
        '<button type="button" class="toast-btn" data-act="no"><span class="toast-btn-ico">' + ICONS.xmark + '</span>' + (opts.noLabel || "No") + '</button>' +
        '<button type="button" class="toast-btn danger" data-act="yes"><span class="toast-btn-ico">' + (opts.yesIcon || ICONS.trash) + '</span>' + (opts.yesLabel || "Yes") + '</button>' +
      "</div>";
    el.querySelector(".toast-confirm-msg").textContent = message;

    const cancel = () => {
      closeToast(el);
      if (opts.onCancel) opts.onCancel();
    };

    el.querySelector('[data-act="no"]').addEventListener("click", cancel);

    el.querySelector('[data-act="yes"]').addEventListener("click", () => {
      if (opts.simple) {
        (async () => {
          try {
            await opts.onConfirm();
            closeToast(el);
          } catch (err) {
            closeToast(el);
            toast(err.message, "error");
          }
        })();
        return;
      }
      const msgEl = el.querySelector(".toast-confirm-msg");
      const actionsEl = el.querySelector(".toast-confirm-actions");
      const siblingRects = snapshotToastRects();

      msgEl.classList.add("toast-swap-out");
      actionsEl.classList.add("toast-swap-out");

      actionsEl.addEventListener("animationend", () => {
        msgEl.textContent = "Type " + confirmWord + " to delete";
        msgEl.classList.remove("toast-swap-out");
        void msgEl.offsetWidth;
        msgEl.classList.add("toast-swap-in");

        actionsEl.outerHTML =
          '<div class="toast-confirm-bar toast-swap-in">' +
            '<button type="button" class="toast-bar-btn cancel" data-act="cancel" aria-label="Cancel">' + ICONS.xmark + "</button>" +
            '<input type="text" class="toast-input" autocomplete="off" spellcheck="false" placeholder="' + confirmWord + '">' +
            '<button type="button" class="toast-bar-btn submit" data-act="submit" disabled aria-label="Confirm delete">' + ICONS.send + "</button>" +
          "</div>";
        playToastReflow(siblingRects);

        const bar = el.querySelector(".toast-confirm-bar");
        const input = bar.querySelector(".toast-input");
        const submitBtn = bar.querySelector('[data-act="submit"]');
        input.focus();
        input.addEventListener("input", () => {
          submitBtn.disabled = input.value.trim().toUpperCase() !== confirmWord;
        });
        const submit = async () => {
          if (submitBtn.disabled) return;
          submitBtn.disabled = true;
          input.disabled = true;
          try {
            await opts.onConfirm();
            closeToast(el);
          } catch (err) {
            closeToast(el);
            toast(err.message, "error");
          }
        };
        bar.querySelector('[data-act="cancel"]').addEventListener("click", cancel);
        input.addEventListener("keydown", (e) => {
          if (e.key === "Enter") submit();
          else if (e.key === "Escape") cancel();
        });
        submitBtn.addEventListener("click", submit);
      }, { once: true });
    });
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

  /* ---------- full-page empty state (icon, heading, description, actions, animated bg) ---------- */

  function emptyVaultHTML(opts) {
    const actions = (opts.actions || []).map(a =>
      '<button class="' + (a.primary ? "btn-accent lg" : "btn-outline lg") + '" data-empty-act="' + escapeHtml(a.act) + '" type="button">' +
      '<span style="width:14px;height:14px;display:flex">' + (ICONS[a.icon] || "") + "</span>" + escapeHtml(a.label) + "</button>"
    ).join("");
    return '<div class="empty-vault"><canvas class="empty-vault-bg"></canvas>' +
      '<div class="empty-vault-inner">' +
      '<div class="empty-vault-text">' +
      '<span class="empty-vault-icon">' + (ICONS[opts.icon] || "") + "</span>" +
      "<h1 class=\"empty-vault-title\">" + escapeHtml(opts.title) + "</h1>" +
      '<p class="empty-vault-desc">' + escapeHtml(opts.desc) + "</p>" +
      "</div>" +
      '<div class="empty-vault-actions">' + actions + "</div>" +
      "</div></div>";
  }

  let emptyBgRaf = null;
  let emptyBgCleanup = null;
  function emptyBgStop() {
    if (emptyBgRaf) cancelAnimationFrame(emptyBgRaf);
    emptyBgRaf = null;
    if (emptyBgCleanup) { emptyBgCleanup(); emptyBgCleanup = null; }
  }
  function emptyBgStart(canvas, holeScale) {
    if (!canvas) return;
    holeScale = holeScale || 1;
    const ctx = canvas.getContext("2d");
    const fs = 13;
    const ramp = ".'`^:;~=+*ox%O0#@".split("");
    const accent = getCookie("accent") || "#a15c93";
    const style = (window.APP_USER_SETTINGS && window.APP_USER_SETTINGS.bg_animation_style) || "turbulence";
    const rawIntensity = window.APP_USER_SETTINGS && window.APP_USER_SETTINGS.bg_animation_intensity;
    const intensity = Number.isFinite(rawIntensity) ? Math.max(0, Math.min(200, rawIntensity)) / 100 : 1;
    let cols = 0, rows = 0;
    const resize = () => {
      canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight;
      cols = Math.ceil(canvas.width / fs); rows = Math.ceil(canvas.height / fs);
    };
    resize();
    window.addEventListener("resize", resize);
    emptyBgCleanup = () => window.removeEventListener("resize", resize);

    /* shared by contours/streaks: fades intensity out toward the center, where content sits.
       Elliptical radial falloff with a cubic smoothstep gives a soft, round vignette edge
       instead of the boxy/diamond seam a straight linear falloff produces on the coarse grid. */
    function clearAt(x, y) {
      const cx = cols / 2, cy = rows / 2;
      const rx = cols * 0.21 * holeScale, ry = rows * 0.33 * holeScale;
      const d = Math.hypot((x - cx) / rx, (y - cy) / ry);
      const t = Math.min(1, Math.max(0, (d - 0.6) / (1.3 - 0.6)));
      return t * t * (3 - 2 * t);
    }
    function put(x, y, v) {
      v *= intensity;
      if (v < 0.1) return;
      const n = Math.min(ramp.length - 1, Math.floor(v * (ramp.length - 1)));
      if (n < 1) return;
      ctx.fillStyle = accent + Math.min(255, Math.floor(18 + v * 190)).toString(16).padStart(2, "0");
      ctx.fillText(ramp[n], x * fs, y * fs + fs);
    }
    function drawContours(ts) {
      const t = ts / 1000 * 0.4;
      const cx = cols / 2, cy = rows / 2;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const fx = x * 0.5, fy = y * 0.9;
          const field = Math.sin(fx * 0.16 + t * 0.8) + Math.sin(fy * 0.15 - t * 0.6)
                      + Math.sin((fx + fy) * 0.11 + t * 1.1) + Math.sin(Math.hypot(fx - cx * 0.5, fy - cy) * 0.13 - t * 0.9);
          let v = 1 - Math.abs(((field / 4) * 3) % 1 - 0.5) * 2;
          v = Math.pow(Math.max(0, v), 3.2) * clearAt(x, y);
          put(x, y, v);
        }
      }
    }
    function drawStreaks(ts) {
      const t = ts / 1000 * 0.45;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < cols; x++) {
          const u = x * 0.5 + y * 0.9;
          let v = Math.sin(u * 0.22 - t * 2.0 + Math.sin(y * 0.11 + t * 0.7) * 1.6) * 0.6 + Math.sin(u * 0.07 + t * 0.9) * 0.4;
          v = Math.pow((v + 1) / 2, 2.2) * clearAt(x, y);
          put(x, y, v);
        }
      }
    }
    function drawTurbulence(ts) {
      const t = ts / 1000 * 0.62;
      const w = Math.max(12, Math.round(cols * 0.22));
      const noise = (x, y) => {
        let v = 0;
        v += Math.sin(x * 0.31 + Math.cos(y * 0.19 - t * 1.1) * 2.2 + t * 0.9);
        v += Math.sin(y * 0.24 - t * 1.7 + Math.sin(x * 0.41 + t * 0.6) * 1.8) * 0.9;
        v += Math.sin((x * 0.6 + y * 0.33) - t * 2.3) * 0.55;
        v += Math.sin(Math.hypot(x - w * 0.5, (y % 34) - 17) * 0.55 - t * 2.6) * 0.7;
        return v / 3.15;
      };
      for (let y = 0; y < rows; y++) {
        for (let bx = 0; bx < w; bx++) {
          const edgeFade = Math.min(1, (w - bx) / (w * 0.62));
          const v = Math.max(0, Math.min(1, (noise(bx, y) + 0.35) * 1.35)) * edgeFade * intensity;
          if (v < 0.08) continue;
          const n = Math.min(ramp.length - 1, Math.floor(v * (ramp.length - 1)));
          if (n < 1) continue;
          const a = Math.floor(22 + Math.pow(v, 0.8) * 200);
          ctx.fillStyle = accent + Math.min(255, a).toString(16).padStart(2, "0");
          const ch = ramp[n];
          ctx.fillText(ch, bx * fs, y * fs + fs);
          ctx.fillText(ch, (cols - 1 - bx) * fs, y * fs + fs);
        }
      }
    }
    const drawFrame = style === "contours" ? drawContours : style === "streaks" ? drawStreaks : drawTurbulence;

    let last = 0;
    const draw = (ts) => {
      emptyBgRaf = requestAnimationFrame(draw);
      if (ts - last < 32) return;
      last = ts;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.font = fs + "px ui-monospace, SFMono-Regular, Menlo, monospace";
      drawFrame(ts);
    };
    emptyBgRaf = requestAnimationFrame(draw);
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

  /* ---------- ascii style picker (login background) ---------- */

  const ASCII_STYLE_KEY = "otp-login-ascii-style";
  const ASCII_STYLES = [
    { value: "off", label: "Off" },
    { value: "matrix", label: "Matrix rain" },
    { value: "starfield", label: "Starfield warp" },
    { value: "wave", label: "Plasma wave" },
    { value: "ripple", label: "Ripple pulse" },
  ];
  const ASCII_RAMP = " .:-=+*#%@".split("");
  const ASCII_RAIN_CHARS = "01アイウエオカキクケコサシスセソ$#%&+=<>~*".split("");
  const ASCII_PREVIEW_FONT = 5;

  function asciiStyleGet() {
    try { return localStorage.getItem(ASCII_STYLE_KEY) || "ripple"; } catch (e) { return "ripple"; }
  }
  function asciiStyleSet(style) {
    try { localStorage.setItem(ASCII_STYLE_KEY, style); } catch (e) {}
  }
  function asciiAccentColor() {
    return (getComputedStyle(document.documentElement).getPropertyValue("--accent") || "#a15c93").trim();
  }
  function asciiBgColor() {
    return (getComputedStyle(document.documentElement).getPropertyValue("--app-bg") || "#fafafa").trim();
  }

  function asciiOptListHTML(selected) {
    return ASCII_STYLES.map(s => {
      const thumb = s.value === "off"
        ? '<span class="ascii-thumb ascii-thumb-off">&ndash;</span>'
        : '<canvas class="ascii-thumb" data-preview="' + s.value + '"></canvas>';
      return '<label class="ascii-opt' + (s.value === selected ? " selected" : "") + '" data-style="' + s.value + '">' +
        '<input type="radio" name="asciiStyle" value="' + s.value + '"' + (s.value === selected ? " checked" : "") + '>' +
        thumb + '<span class="ascii-opt-name">' + s.label + "</span></label>";
    }).join("");
  }

  function asciiPreviewInitState(canvas, style) {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    const pCols = Math.floor(canvas.width / ASCII_PREVIEW_FONT);
    const pRows = Math.floor(canvas.height / ASCII_PREVIEW_FONT);
    const state = { canvas, ctx: canvas.getContext("2d"), cols: pCols, rows: pRows, lastTick: 0 };
    if (style === "matrix") {
      state.drops = new Array(pCols).fill(0).map(() => Math.floor(Math.random() * -20));
    } else if (style === "starfield") {
      state.stars = [];
      for (let i = 0; i < 22; i++) state.stars.push({ a: Math.random() * Math.PI * 2, r: Math.random() * 16, speed: 0.6 + Math.random() * 1.4 });
    }
    return state;
  }

  function asciiDrawPreviewMatrix(s) {
    const ctx = s.ctx, accent = asciiAccentColor(), w = s.canvas.width, h = s.canvas.height;
    ctx.fillStyle = asciiBgColor() + "30";
    ctx.fillRect(0, 0, w, h);
    ctx.font = ASCII_PREVIEW_FONT + "px ui-monospace, SFMono-Regular, Menlo, monospace";
    for (let i = 0; i < s.cols; i++) {
      const ch = ASCII_RAIN_CHARS[Math.floor(Math.random() * ASCII_RAIN_CHARS.length)];
      ctx.fillStyle = accent + (s.drops[i] < 1 ? "ff" : "4a");
      ctx.fillText(ch, i * ASCII_PREVIEW_FONT, s.drops[i] * ASCII_PREVIEW_FONT);
      if (s.drops[i] * ASCII_PREVIEW_FONT > h && Math.random() > 0.93) s.drops[i] = 0;
      s.drops[i]++;
    }
  }
  function asciiDrawPreviewStarfield(s) {
    const ctx = s.ctx, accent = asciiAccentColor(), w = s.canvas.width, h = s.canvas.height;
    ctx.fillStyle = asciiBgColor() + "30";
    ctx.fillRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2;
    ctx.font = ASCII_PREVIEW_FONT + "px ui-monospace, SFMono-Regular, Menlo, monospace";
    for (let i = 0; i < s.stars.length; i++) {
      const st = s.stars[i];
      st.r += st.speed;
      if (st.r > Math.max(cx, cy) * 1.3) { st.r = 4; st.a = Math.random() * Math.PI * 2; }
      const x = cx + Math.cos(st.a) * st.r;
      const y = cy + Math.sin(st.a) * st.r * 0.7;
      const ch = st.r > 20 ? "*" : st.r > 9 ? "+" : ".";
      ctx.fillStyle = accent + (st.r > 20 ? "ff" : st.r > 9 ? "aa" : "55");
      ctx.fillText(ch, x, y);
    }
  }
  function asciiDrawPreviewWave(s, ts) {
    const ctx = s.ctx, accent = asciiAccentColor();
    ctx.fillStyle = asciiBgColor();
    ctx.fillRect(0, 0, s.canvas.width, s.canvas.height);
    ctx.font = ASCII_PREVIEW_FONT + "px ui-monospace, SFMono-Regular, Menlo, monospace";
    const t = ts / 700;
    for (let ry = 0; ry < s.rows; ry++) {
      for (let rx = 0; rx < s.cols; rx++) {
        const v = Math.sin(rx * 0.5 + t) + Math.cos(ry * 0.5 + t * 1.3) + Math.sin((rx + ry) * 0.3 + t * 0.8);
        const n = Math.max(0, Math.min(ASCII_RAMP.length - 1, Math.floor((v + 3) / 6 * ASCII_RAMP.length)));
        if (n === 0) continue;
        ctx.fillStyle = accent + Math.floor(20 + (n / ASCII_RAMP.length) * 60).toString(16).padStart(2, "0");
        ctx.fillText(ASCII_RAMP[n], rx * ASCII_PREVIEW_FONT, ry * ASCII_PREVIEW_FONT + ASCII_PREVIEW_FONT);
      }
    }
  }
  function asciiDrawPreviewRipple(s, ts) {
    const ctx = s.ctx, accent = asciiAccentColor();
    ctx.fillStyle = asciiBgColor();
    ctx.fillRect(0, 0, s.canvas.width, s.canvas.height);
    ctx.font = ASCII_PREVIEW_FONT + "px ui-monospace, SFMono-Regular, Menlo, monospace";
    const cx = s.cols / 2, cy = s.rows / 2;
    const maxD = Math.hypot(cx, cy);
    const t = ts / 900;
    for (let ry = 0; ry < s.rows; ry++) {
      for (let rx = 0; rx < s.cols; rx++) {
        const d = Math.hypot(rx - cx, (ry - cy) * 1.6);
        const wave = Math.sin(d * 0.7 - t * 2.2);
        const fade = Math.max(0, 1 - d / maxD);
        const v = (wave * 0.5 + 0.5) * fade;
        const n = Math.floor(v * (ASCII_RAMP.length - 1));
        if (n <= 0) continue;
        ctx.fillStyle = accent + Math.floor(v * 200).toString(16).padStart(2, "0");
        ctx.fillText(ASCII_RAMP[n], rx * ASCII_PREVIEW_FONT, ry * ASCII_PREVIEW_FONT + ASCII_PREVIEW_FONT);
      }
    }
  }

  /* Renders the style list (with animated thumbnails) into `container` and wires
     selection. Animation only runs between start()/stop() so callers can pause it
     while the picker is hidden (e.g. a closed dropdown). */
  function asciiMountStylePicker(container, opts) {
    opts = opts || {};
    container.innerHTML = asciiOptListHTML(asciiStyleGet());

    const canvases = {};
    container.querySelectorAll(".ascii-thumb[data-preview]").forEach(el => {
      canvases[el.getAttribute("data-preview")] = el;
    });

    let previews = null;
    let frame = null;
    function tick(ts) {
      frame = requestAnimationFrame(tick);
      if (previews.matrix && ts - previews.matrix.lastTick > 90) { previews.matrix.lastTick = ts; asciiDrawPreviewMatrix(previews.matrix); }
      if (previews.starfield && ts - previews.starfield.lastTick > 55) { previews.starfield.lastTick = ts; asciiDrawPreviewStarfield(previews.starfield); }
      if (previews.wave && ts - previews.wave.lastTick > 70) { previews.wave.lastTick = ts; asciiDrawPreviewWave(previews.wave, ts); }
      if (previews.ripple && ts - previews.ripple.lastTick > 70) { previews.ripple.lastTick = ts; asciiDrawPreviewRipple(previews.ripple, ts); }
    }
    function start() {
      if (frame) return;
      // (re)measure now: the container may have been hidden (e.g. a closed
      // dropdown) at mount time, when offsetWidth/offsetHeight would read 0.
      previews = {};
      Object.keys(canvases).forEach(style => { previews[style] = asciiPreviewInitState(canvases[style], style); });
      frame = requestAnimationFrame(tick);
    }
    function stop() { if (frame) { cancelAnimationFrame(frame); frame = null; } }

    function markSelected(style) {
      container.querySelectorAll(".ascii-opt").forEach(opt => {
        opt.classList.toggle("selected", opt.getAttribute("data-style") === style);
      });
    }
    container.querySelectorAll("input[name=asciiStyle]").forEach(r => {
      r.addEventListener("change", () => {
        asciiStyleSet(r.value);
        markSelected(r.value);
        if (opts.onChange) opts.onChange(r.value);
      });
    });

    return { start, stop };
  }

  /* ---------- empty-page background style picker (settings preview) ---------- */

  const EMPTY_BG_STYLES = [
    { value: "contours", label: "Topography" },
    { value: "streaks", label: "Streaks" },
    { value: "turbulence", label: "Turbulence" },
  ];
  const EMPTY_BG_RAMP = ".'`^:;~=+*ox%O0#@".split("");
  const EMPTY_BG_PREVIEW_FONT = 5;

  function emptyBgPreviewInitState(canvas) {
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    return {
      canvas, ctx: canvas.getContext("2d"), lastTick: 0,
      cols: Math.floor(canvas.width / EMPTY_BG_PREVIEW_FONT),
      rows: Math.floor(canvas.height / EMPTY_BG_PREVIEW_FONT),
    };
  }
  function emptyBgPreviewPut(s, x, y, v, accent) {
    if (v < 0.1) return;
    const n = Math.min(EMPTY_BG_RAMP.length - 1, Math.floor(v * (EMPTY_BG_RAMP.length - 1)));
    if (n < 1) return;
    s.ctx.fillStyle = accent + Math.min(255, Math.floor(18 + v * 190)).toString(16).padStart(2, "0");
    s.ctx.fillText(EMPTY_BG_RAMP[n], x * EMPTY_BG_PREVIEW_FONT, y * EMPTY_BG_PREVIEW_FONT + EMPTY_BG_PREVIEW_FONT);
  }
  function emptyBgPreviewBegin(s) {
    s.ctx.clearRect(0, 0, s.canvas.width, s.canvas.height);
    s.ctx.font = EMPTY_BG_PREVIEW_FONT + "px ui-monospace, SFMono-Regular, Menlo, monospace";
  }

  function emptyBgDrawContoursPreview(s, ts, intensity) {
    emptyBgPreviewBegin(s);
    const accent = asciiAccentColor(), t = ts / 1000 * 0.4, cols = s.cols, rows = s.rows, cx = cols / 2, cy = rows / 2;
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const fx = x * 0.5, fy = y * 0.9;
        const field = Math.sin(fx * 0.16 + t * 0.8) + Math.sin(fy * 0.15 - t * 0.6)
                    + Math.sin((fx + fy) * 0.11 + t * 1.1) + Math.sin(Math.hypot(fx - cx * 0.5, fy - cy) * 0.13 - t * 0.9);
        let v = 1 - Math.abs(((field / 4) * 3) % 1 - 0.5) * 2;
        v = Math.pow(Math.max(0, v), 3.2) * intensity;
        emptyBgPreviewPut(s, x, y, v, accent);
      }
    }
  }
  function emptyBgDrawStreaksPreview(s, ts, intensity) {
    emptyBgPreviewBegin(s);
    const accent = asciiAccentColor(), t = ts / 1000 * 0.45, cols = s.cols, rows = s.rows;
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const u = x * 0.5 + y * 0.9;
        let v = Math.sin(u * 0.22 - t * 2.0 + Math.sin(y * 0.11 + t * 0.7) * 1.6) * 0.6 + Math.sin(u * 0.07 + t * 0.9) * 0.4;
        v = Math.pow((v + 1) / 2, 2.2) * intensity;
        emptyBgPreviewPut(s, x, y, v, accent);
      }
    }
  }
  function emptyBgDrawTurbulencePreview(s, ts, intensity) {
    emptyBgPreviewBegin(s);
    const accent = asciiAccentColor(), t = ts / 1000 * 0.62, cols = s.cols, rows = s.rows;
    const noise = (x, y) => {
      let v = 0;
      v += Math.sin(x * 0.31 + Math.cos(y * 0.19 - t * 1.1) * 2.2 + t * 0.9);
      v += Math.sin(y * 0.24 - t * 1.7 + Math.sin(x * 0.41 + t * 0.6) * 1.8) * 0.9;
      v += Math.sin((x * 0.6 + y * 0.33) - t * 2.3) * 0.55;
      v += Math.sin(Math.hypot(x - cols * 0.5, y - rows * 0.5) * 0.55 - t * 2.6) * 0.7;
      return v / 3.15;
    };
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const v = Math.max(0, Math.min(1, (noise(x, y) + 0.35) * 1.35)) * intensity;
        emptyBgPreviewPut(s, x, y, v, accent);
      }
    }
  }

  function emptyBgOptListHTML(selected) {
    return EMPTY_BG_STYLES.map(s =>
      '<label class="ascii-opt' + (s.value === selected ? " selected" : "") + '" data-style="' + s.value + '">' +
      '<input type="radio" name="bgAnimStyle" value="' + s.value + '"' + (s.value === selected ? " checked" : "") + '>' +
      '<canvas class="ascii-thumb" data-bg-preview="' + s.value + '"></canvas>' +
      '<span class="ascii-opt-name">' + s.label + "</span></label>"
    ).join("");
  }

  /* Same shape as asciiStyle.mount, but selection/persistence is left to the caller
     since this style is saved server-side via the settings form, not localStorage. */
  function emptyBgMountStylePicker(container, selected, onChange) {
    container.innerHTML = emptyBgOptListHTML(selected);

    const canvases = {};
    container.querySelectorAll("canvas[data-bg-preview]").forEach(el => {
      canvases[el.getAttribute("data-bg-preview")] = el;
    });

    let previews = null;
    let frame = null;
    let intensity = 1;
    function tick(ts) {
      frame = requestAnimationFrame(tick);
      if (previews.contours && ts - previews.contours.lastTick > 70) { previews.contours.lastTick = ts; emptyBgDrawContoursPreview(previews.contours, ts, intensity); }
      if (previews.streaks && ts - previews.streaks.lastTick > 70) { previews.streaks.lastTick = ts; emptyBgDrawStreaksPreview(previews.streaks, ts, intensity); }
      if (previews.turbulence && ts - previews.turbulence.lastTick > 70) { previews.turbulence.lastTick = ts; emptyBgDrawTurbulencePreview(previews.turbulence, ts, intensity); }
    }
    function start() {
      if (frame) return;
      previews = {};
      Object.keys(canvases).forEach(style => { previews[style] = emptyBgPreviewInitState(canvases[style]); });
      frame = requestAnimationFrame(tick);
    }
    function stop() { if (frame) { cancelAnimationFrame(frame); frame = null; } }
    function setIntensity(v) { intensity = v; }

    container.querySelectorAll("input[name=bgAnimStyle]").forEach(r => {
      r.addEventListener("change", () => {
        container.querySelectorAll(".ascii-opt").forEach(opt => {
          opt.classList.toggle("selected", opt.getAttribute("data-style") === r.value);
        });
        if (onChange) onChange(r.value);
      });
    });

    return { start, stop, setIntensity };
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
  function accentRelLuminance(hex) {
    hex = hex.replace("#", "");
    if (hex.length === 3) hex = hex.split("").map(c => c + c).join("");
    const num = parseInt(hex, 16);
    const r = (num >> 16 & 255) / 255, g = (num >> 8 & 255) / 255, b = (num & 255) / 255;
    const lin = c => c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  }
  function accentForeground(color) {
    return accentRelLuminance(color) > 0.179 ? "#16181d" : "#ffffff";
  }
  function applyAccent(color) {
    document.documentElement.style.setProperty("--accent", color);
    document.documentElement.style.setProperty("--accent-fg", accentForeground(color));
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

  function hasUnsavedSettings() {
    try { return sessionStorage.getItem("otp-settings-dirty") === "1"; } catch (e) { return false; }
  }
  function clearSettingsDirty() {
    try { sessionStorage.removeItem("otp-settings-dirty"); } catch (e) {}
    const dot = document.querySelector("#settings-dirty-dot");
    if (dot) dot.style.display = "none";
  }
  function confirmLeaveUnsaved() {
    if (!hasUnsavedSettings()) return Promise.resolve(true);
    return new Promise(resolve => {
      confirmToast("You have unsaved settings changes. Leave without saving?", {
        simple: true,
        noLabel: "Stay",
        yesLabel: "Leave without saving",
        yesIcon: ICONS.logout,
        onCancel: () => resolve(false),
        onConfirm: async () => { clearSettingsDirty(); resolve(true); },
      });
    });
  }
  window.addEventListener("beforeunload", e => {
    if (!hasUnsavedSettings()) return;
    e.preventDefault();
    e.returnValue = "";
  });

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
  let currentHref = location.href;
  async function softNavigate(href, push) {
    if (!(await confirmLeaveUnsaved())) {
      if (!push) history.pushState({ softNav: true }, "", currentHref);
      return;
    }
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
      try {
        const newSettingsDot = curNav.querySelector("#settings-dirty-dot");
        if (newSettingsDot && sessionStorage.getItem("otp-settings-dirty") === "1") newSettingsDot.style.display = "inline-block";
      } catch (e) {}
      if (sidebarPinned.secrets) sidebarPinnedRender();
      sidebarPinnedFetch();

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
      currentHref = href;
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
    if ((e.metaKey || e.ctrlKey || (!IS_MAC && e.altKey)) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (cmdk.open) cmdkClose(); else cmdkOpen();
      return;
    }
    if (!cmdk.open) return;
    if (e.key === "Escape") { cmdkClose(); return; }
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "c" && cmdk.input.selectionStart === cmdk.input.selectionEnd) {
      const item = cmdk.items[cmdk.index];
      if (item && item.badge) {
        e.preventDefault();
        copyText(item.badge, "Copied code: " + item.badge);
      }
      return;
    }
    if (e.key === "ArrowDown") { e.preventDefault(); if (cmdk.items.length) { cmdk.index = (cmdk.index + 1) % cmdk.items.length; cmdkHighlight(); } }
    else if (e.key === "ArrowUp") { e.preventDefault(); if (cmdk.items.length) { cmdk.index = (cmdk.index - 1 + cmdk.items.length) % cmdk.items.length; cmdkHighlight(); } }
    else if (e.key === "Enter") { if (cmdk.items[cmdk.index]) cmdkSelect(cmdk.items[cmdk.index]); }
  });

  /* ---------- idle code obfuscation (replaces the old full-panel blur) ---------- */

  const SCRAMBLE_DIGITS = "0123456789";
  function scrambleDigits(len) {
    let s = "";
    for (let i = 0; i < len; i++) s += SCRAMBLE_DIGITS[(Math.random() * SCRAMBLE_DIGITS.length) | 0];
    return s;
  }

  let idleHidden = false;
  let idleArmTimer = null;
  let scrambleInterval = null;

  function obscureDigits() {
    const leaves = [];
    document.querySelectorAll("[data-obscure-group] .digit").forEach(d => leaves.push(d));
    return leaves;
  }

  function obscureTick() {
    obscureDigits().forEach(el => {
      if (el.dataset.real === undefined) el.dataset.real = el.textContent;
      el.textContent = scrambleDigits(el.dataset.real.length || 1);
    });
  }

  function restoreObscured() {
    document.querySelectorAll("[data-obscure-group] .digit[data-real]").forEach(el => {
      el.textContent = el.dataset.real;
      delete el.dataset.real;
    });
  }

  function setIdleHidden(v) {
    if (idleHidden === v) return;
    idleHidden = v;
    document.documentElement.classList.toggle("idle-hidden", v);
    if (v) {
      obscureTick();
      scrambleInterval = setInterval(obscureTick, 80);
    } else {
      clearInterval(scrambleInterval);
      scrambleInterval = null;
      restoreObscured();
    }
  }

  function idleDelaySeconds() {
    const raw = window.APP_USER_SETTINGS && window.APP_USER_SETTINGS.blur_on_inactive_delay;
    return [0, 10, 30, 60].includes(raw) ? raw : 60;
  }

  function armIdleGuard() {
    setIdleHidden(false);
    clearTimeout(idleArmTimer);
    idleArmTimer = setTimeout(() => setIdleHidden(true), idleDelaySeconds() * 1000);
  }

  function initIdleGuard() {
    if (!document.documentElement.classList.contains("blur-on-inactive")) return;
    if (idleDelaySeconds() === 0) {
      /* "Instant" hides only when the window/tab loses focus, not on mouse idle */
      window.addEventListener("blur", () => setIdleHidden(true));
      window.addEventListener("focus", () => setIdleHidden(false));
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) setIdleHidden(true);
      });
      if (document.hidden || !document.hasFocus()) setIdleHidden(true);
      return;
    }
    const events = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];
    events.forEach(ev => window.addEventListener(ev, armIdleGuard, { passive: true }));
    armIdleGuard();
  }

  /* ---------- sidebar pinned secrets ---------- */

  const sidebarPinned = { secrets: null, fetchedAt: 0, baseRemaining: 30, refreshing: false };

  function sidebarPinnedRender() {
    const el = document.getElementById("sidebar-pinned");
    if (!el) return;
    const list = sidebarPinned.secrets || [];
    el.innerHTML = list.map(s =>
      '<button class="sidebar-pin-row" data-pin-id="' + s.id + '" type="button" title="' + escapeHtml(s.name) + '">' +
      '<span class="sidebar-pin-name">' + escapeHtml(s.name) + "</span>" +
      (s.current_code
        ? '<span class="sidebar-pin-code" data-obscure-group>' + digitsHTML(s.current_code, false) + "</span>"
        : '<span class="sidebar-pin-error" title="Can\'t generate OTP code #ERR-004"><span class="ico">' + ICONS.warn + "</span> error</span>") +
      "</button>"
    ).join("");
  }

  async function sidebarPinnedFetch() {
    if (sidebarPinned.refreshing || !document.getElementById("sidebar-pinned")) return;
    sidebarPinned.refreshing = true;
    try {
      const [pinnedIds, secrets] = await Promise.all([
        fetchJSON("/api/user-pinned"),
        fetchJSON("/api/secrets"),
      ]);
      const idSet = new Set((pinnedIds || []).map(String));
      sidebarPinned.secrets = (secrets || []).filter(s => idSet.has(String(s.id)));
      sidebarPinned.fetchedAt = Date.now();
      sidebarPinned.baseRemaining = sidebarPinned.secrets.length
        ? Math.max(0, Math.min(30, sidebarPinned.secrets[0].seconds_remaining)) : 30;
      sidebarPinnedRender();
    } catch (e) { /* not critical */ } finally { sidebarPinned.refreshing = false; }
  }

  document.addEventListener("click", e => {
    const row = e.target.closest(".sidebar-pin-row");
    if (!row) return;
    const secret = (sidebarPinned.secrets || []).find(s => String(s.id) === row.getAttribute("data-pin-id"));
    if (secret && secret.current_code) copyText(secret.current_code, "Copied code: " + secret.current_code);
  });

  setInterval(() => {
    if (!document.getElementById("sidebar-pinned")) return;
    const remaining = sidebarPinned.baseRemaining - (Date.now() - sidebarPinned.fetchedAt) / 1000;
    if (!sidebarPinned.fetchedAt || remaining <= 0) sidebarPinnedFetch();
  }, 1000);

  /* ---------- shared "add / edit company" drawer (templates/_company_drawer.html) ----------
     Any page that includes that partial can call App.companyDrawer.open(...) and get the
     exact same markup/behavior — one place to change if the drawer ever needs to adjust. */
  const companyDrawer = (function () {
    let editingId = null;
    let webAccessOn = false;
    let onDone = null;
    let bound = false;
    let checkTimer = null;
    let checkToken = 0;

    function bind() {
      if (bound) return;
      const webBtn = document.getElementById("company-webaccess");
      const submitBtn = document.getElementById("company-submit");
      const nameInput = document.getElementById("company-name");
      const kdnrInput = document.getElementById("company-kdnr");
      const kdnrFillBtn = document.getElementById("company-kdnr-fill");
      if (!webBtn || !submitBtn) return;
      bound = true;
      webBtn.addEventListener("click", () => {
        webAccessOn = !webAccessOn;
        webBtn.classList.toggle("on", webAccessOn);
      });
      if (kdnrFillBtn && kdnrInput) {
        kdnrFillBtn.addEventListener("click", () => {
          kdnrInput.value = guessedKdnr();
          updateKdnrFillState();
          scheduleCheck();
        });
        kdnrInput.addEventListener("input", updateKdnrFillState);
      }
      nameInput.addEventListener("input", () => { hideFieldError("name"); scheduleCheck(); });
      if (kdnrInput) kdnrInput.addEventListener("input", () => { hideFieldError("kdnr"); scheduleCheck(); });
      submitBtn.addEventListener("click", submit);
    }

    function updateSubmitState() {
      const submitBtn = document.getElementById("company-submit");
      if (!submitBtn) return;
      submitBtn.disabled = !!document.querySelector("#company-overlay .input-error-x.show");
    }

    function hideFieldError(field) {
      const el = document.getElementById("company-" + field + "-error");
      const pop = document.getElementById("company-" + field + "-popover");
      if (el) el.classList.remove("show");
      if (pop) pop.textContent = "";
      updateSubmitState();
    }

    function clearFieldErrors() {
      checkToken++;
      clearTimeout(checkTimer);
      hideFieldError("name");
      hideFieldError("kdnr");
    }

    function showFieldError(field, message) {
      const el = document.getElementById("company-" + field + "-error");
      const pop = document.getElementById("company-" + field + "-popover");
      if (!el || !pop) { toast(message, "error"); return; }
      pop.textContent = message;
      el.classList.add("show");
      updateSubmitState();
    }

    /* debounced live duplicate check while typing — hits /api/check-company so the
       red X (and its popover) appears without waiting for a submit round-trip */
    function scheduleCheck() {
      clearTimeout(checkTimer);
      checkTimer = setTimeout(runCheck, 350);
    }

    async function runCheck() {
      const token = ++checkToken;
      const name = document.getElementById("company-name").value.trim();
      const kdnr = document.getElementById("company-kdnr").value.trim();
      if (!name && !kdnr) return;
      const params = new URLSearchParams();
      if (name) params.set("name", name);
      if (kdnr) params.set("kundennummer", kdnr);
      if (editingId != null) params.set("exclude_id", editingId);
      let data;
      try {
        data = await fetchJSON("/api/check-company?" + params.toString());
      } catch (e) { return; }
      if (token !== checkToken) return;
      if (name && data.name_taken) showFieldError("name", 'A company named "' + name + '" already exists');
      if (kdnr && data.kundennummer_taken) showFieldError("kdnr", 'Kundennummer "' + kdnr + '" is already in use');
    }

    /* mirrors the "CO-" + (1000 + c.id) placeholder shown for companies without a
       customer number (see companies.html) — predicts the id a new company will get
       by looking at ids already present in the DOM (company select, companies table). */
    function guessNextCompanyId() {
      const ids = [];
      document.querySelectorAll("#add-company option[value]").forEach(o => {
        const v = parseInt(o.value, 10);
        if (!Number.isNaN(v)) ids.push(v);
      });
      document.querySelectorAll("[data-view]").forEach(el => {
        const v = parseInt(el.getAttribute("data-view"), 10);
        if (!Number.isNaN(v)) ids.push(v);
      });
      return ids.length ? Math.max(...ids) + 1 : 1;
    }

    function guessedKdnr() {
      return "CO-" + (1000 + guessNextCompanyId());
    }

    function updateKdnrFillState() {
      const kdnrInput = document.getElementById("company-kdnr");
      const kdnrFillBtn = document.getElementById("company-kdnr-fill");
      if (!kdnrInput || !kdnrFillBtn) return;
      const alreadyCorrect = kdnrInput.value.trim() === guessedKdnr();
      kdnrFillBtn.disabled = alreadyCorrect;
      kdnrFillBtn.title = alreadyCorrect
        ? "Already set to the auto-generated customer number"
        : "Fill in the next auto-generated customer number";
    }

    async function submit() {
      clearFieldErrors();
      const name = document.getElementById("company-name").value.trim();
      if (!name) { toast("Please enter a name", "error"); return; }
      const fd = new FormData();
      fd.append("name", name);
      fd.append("kundennummer", document.getElementById("company-kdnr").value.trim());
      fd.append("password", document.getElementById("company-password").value);
      if (webAccessOn) fd.append("login_enabled", "on");
      const isEdit = editingId != null;
      if (isEdit) fd.append("company_id", editingId);
      try {
        const data = await fetchJSON(isEdit ? "/api/edit-company" : "/api/create-company", { method: "POST", body: fd });
        closeOverlay("company-overlay");
        if (onDone) onDone(data.company, isEdit);
      } catch (err) {
        if (/kundennummer/i.test(err.message)) showFieldError("kdnr", err.message);
        else if (/name/i.test(err.message)) showFieldError("name", err.message);
        else toast(err.message, "error");
      }
    }

    function open(company, onSuccess) {
      if (!document.getElementById("company-overlay")) return;
      bind();
      clearFieldErrors();
      editingId = company ? company.id : null;
      onDone = onSuccess || null;
      document.getElementById("company-drawer-title").textContent = company ? "Edit Company" : "Add Company";
      const sub = document.getElementById("company-drawer-sub");
      sub.style.display = company ? "block" : "none";
      if (company) sub.textContent = "Manage details for " + company.name;
      document.getElementById("company-name").value = company ? company.name : "";
      document.getElementById("company-kdnr").value = company ? (company.kundennummer || "") : "";
      updateKdnrFillState();
      document.getElementById("company-password").value = "";
      document.getElementById("company-password").placeholder = company ? "Leave empty to keep current password" : "Optional — leave empty to skip";
      webAccessOn = company ? !!company.login_enabled : false;
      document.getElementById("company-webaccess").classList.toggle("on", webAccessOn);
      document.getElementById("company-submit").textContent = company ? "Save changes" : "Add Company";
      openOverlay("company-overlay");
    }

    return { open };
  })();

  /* ---------- boot ---------- */

  document.addEventListener("DOMContentLoaded", () => {
    hydrateIcons();
    const searchKbd = document.getElementById("home-search-kbd");
    if (searchKbd) searchKbd.innerHTML = IS_MAC ? "&#8984;K" : "Alt+K";
    const copyHint = document.getElementById("cmdk-copy-hint");
    if (copyHint) copyHint.innerHTML = COPY_KEY_LABEL + " Copy code";
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

    sidebarPinnedFetch();
    initIdleGuard();
  });

  window.App = {
    ICONS, toast, confirmToast, copyText, hydrateIcons, digitsHTML, digitsHTMLUpdate, ringSVG, setRing, escapeHtml,
    fetchJSON, openOverlay, closeOverlay, closeAllOverlays, applyAccent, setCookie, getCookie,
    cmdkOpen, attachAutocomplete, onPageLeave, emptyVaultHTML, emptyBgStart, emptyBgStop, companyDrawer,
    asciiStyle: { get: asciiStyleGet, set: asciiStyleSet, mount: asciiMountStylePicker },
    emptyBgStyle: { mount: emptyBgMountStylePicker },
  };
})();
