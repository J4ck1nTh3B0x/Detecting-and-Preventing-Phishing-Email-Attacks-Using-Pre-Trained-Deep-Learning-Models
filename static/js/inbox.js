document.addEventListener("DOMContentLoaded", () => {

  /* --- 1. Reload Button (now triggers real Gmail sync with spinning icon) --- */
  const reloadBtn = document.getElementById("reloadBtn");
  if (reloadBtn) {
    reloadBtn.addEventListener("click", async () => {
      reloadBtn.disabled = true;
      reloadBtn.innerHTML = "Reload"; // simple reload icon
      reloadBtn.classList.add("spin"); // start spinning

      try {
        const res = await fetch("/api/force_sync", { method: "POST" });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        console.log("Sync result:", data);
        reloadBtn.innerHTML = "Reloading...";
        setTimeout(() => {
        const url = new URL(window.location.href);
        window.location.href = url.toString(); // preserves all parameters including label
      }, 1200);
      } catch (err) {
        console.error("Mail sync failed:", err);
        reloadBtn.innerHTML = "Retry";
        alert("Mail sync failed. Check server logs.");
      } finally {
        reloadBtn.classList.remove("spin"); // stop spinning
        reloadBtn.disabled = false;
      }
    });
  }


  /* --- 2. Pagination Buttons --- */
  document.querySelectorAll(".pager button[data-url]").forEach(btn => {
    if (!btn.disabled) {
      btn.addEventListener("click", () => {
        const url = btn.getAttribute("data-url");
        if (url) window.location.href = url;
      });
    }
  });

  /* --- 3. Click on Mail Row (instant navigation) --- */
  document.querySelectorAll(".inbox-row").forEach(row => {
    row.addEventListener("click", e => {
      const href = row.dataset.href;
      if (href) {
        // navigate immediately on click
        window.location.href = href;
      }
    });
  });

  /* --- 4. "Per Page" Dropdown --- */
  const perPageSelect = document.getElementById("perPageSelect");
  if (perPageSelect) {
    perPageSelect.addEventListener("change", () => {
      const perPage = perPageSelect.value;
      const params = new URLSearchParams(window.location.search);

      // Preserve label filter if exists
      const labelFilter = params.get("label");
      if (labelFilter) params.set("label", labelFilter);

      setTimeout(() => {
        const url = new URL(window.location.href);
        if (url.searchParams.get("label") === "") {
          url.searchParams.delete("label");
        }
        window.location.href = url.toString();
      }, 1200);
      
      params.set("page", 1);
      
      // Clean empty label
      const label = params.get("label");
      if (!label) params.delete("label");
      
      window.location.search = params.toString();      
    });
  }


  /* --- 5. Theme Toggle Safety (if not handled by theme.js) --- */
  const themeToggle = document.getElementById("themeToggle");
  if (themeToggle && typeof window.toggleTheme !== "function") {
    themeToggle.addEventListener("click", () => {
      const html = document.documentElement;
      const current = html.getAttribute("data-theme") || "light";
      const next = current === "light" ? "dark" : "light";
      html.setAttribute("data-theme", next);
    });
  }

// --- Live auto-refresh of mail counters ---
async function pollLiveStatus() {
  try {
    const res = await fetch("/api/live_status");
    if (!res.ok) return;
    const data = await res.json();

    const liveBox = document.getElementById("liveStatus");
    const liveText = document.getElementById("liveStatusText");
    const totalMail = document.getElementById("totalMailCount");

    if (!liveBox || !liveText || !totalMail) return;

    // update text
    if (data.status === "idle") {
      liveBox.style.display = "none";
    } else {
      liveBox.style.display = "inline-flex";
      liveText.textContent = data.status_text;
    }

    // update counters live if changed - format as "cached / total"
    if (typeof data.total_mails === "number") {
      const cached = data.total_mails;
      const gmailTotal = data.gmail_total;

      let displayText, tooltipText;
      if (gmailTotal !== null && gmailTotal !== undefined) {
        displayText = `${cached} / ${gmailTotal}`;
        tooltipText = `Emails cached locally: ${cached}\nTotal emails in Gmail: ${gmailTotal}\n\nThe first number shows how many emails are stored locally and available for analysis.\nThe second number shows your total Gmail account size.`;
      } else {
        displayText = cached.toString();
        tooltipText = `Emails cached locally: ${cached}\n\nGmail account total not available.\nThis shows how many emails are stored locally and available for analysis.`;
      }

      totalMail.textContent = displayText;
      totalMail.title = tooltipText;
    }

  } catch (err) {
    console.warn("Live status update failed:", err);
  }
}

// Poll live status every 2 seconds to match inbox polling
setInterval(pollLiveStatus, 2000);

// --- Live inbox polling: update counts, rows and pager without reload ---
let _inboxCacheKey = "";

function escapeHtml(s) {
  if (!s && s !== 0) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function pollInbox() {
  try {
    // preserve current query params so we poll with the same filter/page/per_page/q
    const url = new URL(window.location.href);
    const params = new URLSearchParams(url.search);
    // call backend endpoint that returns minimal inbox JSON
    const fetchUrl = `/api/inbox_data?${params.toString()}`;
    const res = await fetch(fetchUrl, { cache: "no-store" });
    if (!res.ok) return;
    const json = await res.json();

    // json should contain: { total: N, total_pages, page, messages: [...], prev_url, next_url }
    const liveBox = document.getElementById("liveStatus");
    const liveText = document.getElementById("liveStatusText");

    // update live status visibility if backend exposes it
    if (json.status && liveBox && liveText) {
      if (json.status === "idle") {
        liveBox.style.display = "none";
      } else {
        liveBox.style.display = "inline-flex";
        liveText.textContent = json.status_text || (json.status === "syncing" ? "Syncing..." : "Classifying...");
      }
    }

    // build a cache key to compare if rows changed
    const key = JSON.stringify({
      page: json.page,
      total: json.total,
      messages_summary: json.messages ? json.messages.map(m => ({ id: m.id, label: m.prediction_label, subject: m.subject })).slice(0, 200) : []
    });

    if (key === _inboxCacheKey) {
      // no visible change
      return;
    }
    _inboxCacheKey = key;

    // preserve vertical scroll
    const scrollY = window.scrollY;

    // render rows
    const tbody = document.querySelector("#inboxTable tbody");
    if (tbody) {
      let rowsHtml = "";
      if (Array.isArray(json.messages)) {
        for (const m of json.messages) {
          const label = (m.prediction_label || "").toLowerCase();
          const badgeClass = label === "safe" ? "safe" : label === "phish" ? "phish" : label === "maybephish" ? "suspicious" : "unknown";
          const labelText = escapeHtml((m.prediction_label || "N/A").toUpperCase());
          rowsHtml += `<tr class="inbox-row" data-href="${escapeHtml(m.url || ('/message/' + m.id))}">` +
                      `<td>${escapeHtml(m.subject || "(No Subject)")}</td>` +
                      `<td>${escapeHtml(m.sender || "")}</td>` +
                      `<td>${escapeHtml(m.date || "")}</td>` +
                      `<td><span class="badge ${badgeClass}">${labelText}</span></td>` +
                      `</tr>`;
        }
      }
      tbody.innerHTML = rowsHtml;

      // reattach click handlers for new rows
      document.querySelectorAll(".inbox-row").forEach(row => {
        row.removeEventListener("click", row._eh);
        const fn = () => { const href = row.dataset.href; if (href) window.location.href = href; };
        row._eh = fn;
        row.addEventListener("click", fn);
      });
    }

    // update pager text and prev/next buttons
    const pagerSpan = document.querySelector(".pager span");
    if (pagerSpan && typeof json.page !== "undefined") {
      pagerSpan.textContent = `Page ${json.page} / ${json.total_pages} (Total: ${json.total})`;
    }
    const prevBtn = document.getElementById("prevBtn");
    const nextBtn = document.getElementById("nextBtn");
    if (prevBtn) {
      if (json.prev_url) {
        prevBtn.disabled = false;
        prevBtn.setAttribute("data-url", json.prev_url);
      } else {
        prevBtn.disabled = true;
        prevBtn.removeAttribute("data-url");
      }
    }
    if (nextBtn) {
      if (json.next_url) {
        nextBtn.disabled = false;
        nextBtn.setAttribute("data-url", json.next_url);
      } else {
        nextBtn.disabled = true;
        nextBtn.removeAttribute("data-url");
      }
    }

    // restore scroll position
    window.scrollTo(0, scrollY);

  } catch (err) {
    console.warn("pollInbox error:", err);
  }
}

// Poll inbox every 2 seconds for near real-time updates
setInterval(pollInbox, 2000);
// Initial fetch
pollInbox();



});
