// split_view.js — drives desktop split UI, pagination, draggable divider
(function () {
  if (window._split_view_loaded) return;
  window._split_view_loaded = true;

  // Hybrid mobile detection (user-agent + touch + width)
  function isMobile() {
    try {
      const ua = navigator.userAgent || "";
      const mobileUA = /Mobi|Android|iPhone|iPad|iPod/i.test(ua);
      const touchCap = ('ontouchstart' in window) || (navigator.maxTouchPoints && navigator.maxTouchPoints > 0);
      return mobileUA || (touchCap && window.innerWidth < 1024);
    } catch (e) {
      return window.innerWidth < 900;
    }
  }

  const leftPane = () => document.querySelector(".pane-left");
  const rightPane = () => document.querySelector(".pane-right");
  const frame = () => document.getElementById("viewerFrame");
  const divider = () => document.getElementById("splitDivider");

  function getSavedPct() {
    try { return parseInt(localStorage.getItem("split_pos_pct"), 10) || 40; } catch { return 40; }
  }
  function savePct(p) { try { localStorage.setItem("split_pos_pct", String(p)); } catch {} }

  function setSplit(pct) {
    const lp = leftPane(), rp = rightPane();
    if (!lp || !rp) return;
    lp.style.width = pct + "%";
    rp.style.display = "block";
    savePct(pct);
  }

  function showInboxOnly() {
    const lp = leftPane(), rp = rightPane();
    if (!lp || !rp) return;
    lp.style.width = "100%";
    rp.style.display = "none";
  }

  async function fetchAndReplace(url) {
    const opts = { headers: { "X-Requested-With": "XMLHttpRequest" } };
    const res = await fetch(url, opts);
    if (!res.ok) throw new Error("fetch failed");
    const text = await res.text();
    const doc = new DOMParser().parseFromString(text, "text/html");
    const newBody = doc.querySelector("#inboxBody");
    const newPager = doc.querySelector("#inboxPager");
    if (newBody) {
      const cur = document.querySelector("#inboxBody");
      cur.parentNode.replaceChild(newBody, cur);
    }
    if (newPager) {
      const curp = document.querySelector("#inboxPager");
      curp.parentNode.replaceChild(newPager, curp);
    }
    // rebind handlers after DOM swap
    bindInboxHandlers();
  }

  function bindInboxHandlers() {
    const rows = document.querySelectorAll("tr.inbox-row");
    rows.forEach(r => {
      // ensure no native anchor behavior
      r.removeAttribute("href");
      r.removeAttribute("onclick");

      // avoid duplicate listeners
      r.onclick = null;
      r.addEventListener("click", (ev) => {
        try {
          if (isMobile()) {
            // allow normal navigation on mobile to full page
            const url = r.dataset.href;
            if (url) window.location.href = url;
            return;
          }

          ev.preventDefault();
          ev.stopPropagation();
          ev.stopImmediatePropagation();

          // open split
          const url = r.dataset.href;
          if (!url) return;
          const pct = getSavedPct();
          setSplit(pct);
          // set frame src
          const f = frame();
          if (f) f.src = url;
        } catch (err) { console.error(err); }
      }, { capture: true });
    });

    // pagination links
    const pager = document.querySelectorAll("a.page-nav");
    pager.forEach(a => {
      a.onclick = null;
      a.addEventListener("click", async (ev) => {
        try {
          const url = a.dataset.url;
          if (isMobile()) { if (url) window.location.href = url; return; }
          ev.preventDefault(); ev.stopPropagation(); ev.stopImmediatePropagation();
          await fetchAndReplace(url);
          // when paging, keep right pane as-is (user requested), do not close viewer
        } catch (err) {
          // fallback to normal nav if ajax fails
          const url = a.dataset.url;
          if (url) window.location.href = url;
        }
      }, { capture: true });
    });
  }

  // draggable divider
  function enableDrag() {
    const d = divider();
    if (!d) return;
    const lp = leftPane();
    if (!lp) return;

    let dragging = false;
    let startX = 0;
    let startWidth = 0;

    d.addEventListener("mousedown", (ev) => {
      if (isMobile()) return;
      dragging = true;
      startX = ev.clientX;
      startWidth = lp.getBoundingClientRect().width;
      document.body.style.userSelect = "none";
    });

    window.addEventListener("mousemove", (ev) => {
      if (!dragging) return;
      ev.preventDefault();
      const total = lp.parentElement.getBoundingClientRect().width;
      const newWidth = startWidth + (ev.clientX - startX);
      let pct = Math.round((newWidth / total) * 100);
      if (pct < 20) pct = 20;
      if (pct > 80) pct = 80;
      setSplit(pct);
    });

    window.addEventListener("mouseup", () => {
      if (dragging) {
        dragging = false;
        document.body.style.userSelect = "";
      }
    });

    // enable touch for drag too
    d.addEventListener("touchstart", (ev) => {
      if (isMobile()) return;
      dragging = true;
      startX = ev.touches[0].clientX;
      startWidth = lp.getBoundingClientRect().width;
    }, { passive: true });

    window.addEventListener("touchmove", (ev) => {
      if (!dragging) return;
      const total = lp.parentElement.getBoundingClientRect().width;
      const newWidth = startWidth + (ev.touches[0].clientX - startX);
      let pct = Math.round((newWidth / total) * 100);
      if (pct < 20) pct = 20;
      if (pct > 80) pct = 80;
      setSplit(pct);
    }, { passive: true });

    window.addEventListener("touchend", () => { dragging = false; });
  }

  // expose backToInbox for iframe
  window.backToInbox = function () {
    try {
      if (isMobile()) { history.back(); return; }
      const rp = rightPane();
      const lp = leftPane();
      if (!rp || !lp) return;
      rp.style.display = "none";
      lp.style.width = "100%";
      const saved = parseInt(localStorage.getItem("split_pos_pct") || "40", 10);
      lp.scrollTop = lp.dataset.scrollPos ? parseInt(lp.dataset.scrollPos, 10) : 0;
      document.activeElement && document.activeElement.blur();
    } catch (e) { console.error(e); }
  };

  // initial
  window.addEventListener("DOMContentLoaded", () => {
    try {
      // if mobile, ensure no split
      if (isMobile()) {
        showInboxOnly();
      } else {
        // restore saved split width if right pane should be visible
        const pct = getSavedPct();
        const savedViewer = false; // viewer empty until user clicks
        const lp = leftPane();
        const rp = rightPane();
        lp.style.width = "100%";
        rp.style.display = "none";
        // enable drag
        enableDrag();
      }

      // bind inbox handlers (rows + pager)
      bindInboxHandlers();
    } catch (e) {
      console.error(e);
    }
  });

})();
