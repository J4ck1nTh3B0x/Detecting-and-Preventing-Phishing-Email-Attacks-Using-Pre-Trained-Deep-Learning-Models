/* message.js — attachment preview, raw toggle, iframe load, theme persistence
   Patched: improved media preview (uses fetch->blob), auto-play on user click,
   better sizing, error handling, close-on-backdrop/click/escape, no hard-coded mime assumptions.
*/

document.addEventListener("DOMContentLoaded", () => {
  const containerEl = document.querySelector(".container");
  const isPhishView = !!(containerEl && containerEl.dataset && containerEl.dataset.isPhish === "1");
  function showPhishWarningOverlay(message, onContinue, onCancel) {
    try {
      if (!document.body) return;

      const existing = document.getElementById("phishWarningOverlay");
      if (existing && existing.parentNode) {
        existing.parentNode.removeChild(existing);
      }

      const overlay = document.createElement("div");
      overlay.id = "phishWarningOverlay";
      overlay.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,0.85);display:flex;align-items:center;justify-content:center;";

      const box = document.createElement("div");
      box.style.cssText = "max-width:520px;width:90%;background:#b71c1c;color:#fff;border-radius:10px;box-shadow:0 10px 35px rgba(0,0,0,0.7);padding:20px 22px;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;text-align:left;border:2px solid #ffeb3b;";

      const title = document.createElement("h2");
      title.textContent = "Danger: Phishing Content";
      title.style.margin = "0 0 10px 0";
      title.style.fontSize = "20px";

      const msgEl = document.createElement("p");
      msgEl.textContent = message || "This email is flagged as PHISHING/MAYBEPHISHING. It may contain fake login pages, malware attachments, or links that steal your data.";
      msgEl.style.margin = "0 0 10px 0";
      msgEl.style.fontSize = "14px";

      const list = document.createElement("ul");
      list.style.margin = "0 0 12px 18px";
      list.style.padding = "0";
      list.style.fontSize = "13px";
      [
        "Only continue if you fully trust the sender.",
        "Do not enter passwords, banking info, or personal data.",
        "Do not open links or attachments you are not expecting."
      ].forEach(t => {
        const li = document.createElement("li");
        li.textContent = t;
        li.style.marginBottom = "4px";
        list.appendChild(li);
      });

      const btnRow = document.createElement("div");
      btnRow.style.cssText = "display:flex;justify-content:flex-end;gap:10px;margin-top:10px;flex-wrap:wrap;";

      const cancelBtn = document.createElement("button");
      cancelBtn.textContent = "Go back";
      cancelBtn.style.cssText = "padding:8px 14px;border-radius:6px;border:none;background:#263238;color:#fff;font-size:13px;cursor:pointer;";

      const continueBtn = document.createElement("button");
      continueBtn.textContent = "I understand, continue";
      continueBtn.style.cssText = "padding:8px 14px;border-radius:6px;border:none;background:#ffeb3b;color:#000;font-weight:600;font-size:13px;cursor:pointer;";

      cancelBtn.onclick = () => {
        try { document.body.removeChild(overlay); } catch (_) {}
        if (typeof onCancel === "function") onCancel();
      };

      continueBtn.onclick = () => {
        try { document.body.removeChild(overlay); } catch (_) {}
        if (typeof onContinue === "function") onContinue();
      };

      btnRow.appendChild(cancelBtn);
      btnRow.appendChild(continueBtn);

      box.appendChild(title);
      box.appendChild(msgEl);
      box.appendChild(list);
      box.appendChild(btnRow);
      overlay.appendChild(box);
      document.body.appendChild(overlay);
    } catch (_) {}
  }

  if (isPhishView) {
    try { 
      // Reset any previous safe-click decisions so warnings always apply on phish views
      localStorage.removeItem("safe_click_allow"); 
      delete window._safe_click_modal_open;

      // Always show a strong warning whenever opening a phishing/maybephishing email
      showPhishWarningOverlay(
        "You are viewing an email flagged as PHISHING/MAYBEPHISHING. It may contain malicious links or attachments.",
        () => {
          // user explicitly accepted the risk; nothing else needed here
        },
        () => {
          // user aborted: go back to inbox (or previous page)
          window.history.back();
        }
      );
    } catch (_) {}
  }

  /* ============================
     NAVIGATION BUTTONS
  ============================ */
  
  const backBtn = document.getElementById("backInboxBtn");
  if (backBtn) {
    backBtn.addEventListener("click", (e) => {
      e.preventDefault();
      // prefer parent split-view handler if available
      try {
        if (window.parent && typeof window.parent.backToInbox === "function") {
          window.parent.backToInbox();
          return;
        }
      } catch (_) { /* ignore cross-origin */ }

      // Attempt to preserve explicit URL params first
      try {
        const params = new URLSearchParams(window.location.search);
        const per = params.get("per_page");
        const label = params.get("label");
        const q = params.get("q");

        // If current URL already has meaningful params, go back preserving them
        const out = new URLSearchParams();
        if (per) out.set("per_page", per);
        if (label) out.set("label", label);
        if (q) out.set("q", q);

        if (out.toString()) {
          window.location.href = "/?" + out.toString();
          return;
        }
      } catch (_) { /* ignore URL parsing errors */ }

      // Fallback to saved UI state in localStorage if present
      try {
        const st = JSON.parse(localStorage.getItem("inbox_state") || "{}");
        const params2 = new URLSearchParams();
        if (st.page) params2.set("page", st.page);
        if (st.per_page) params2.set("per_page", st.per_page);
        if (st.q) params2.set("q", st.q);
        const q2 = params2.toString();
        window.location.href = "/"+(q2 ? ("?"+q2) : "");
        return;
      } catch (_) {
        // last-resort fallback
        window.location.href = "/";
      }
    });
  }


  const toggleRawBtn = document.getElementById("toggleRawBtn");
  const rawBox = document.getElementById("rawBox");
  if (toggleRawBtn && rawBox) {
    toggleRawBtn.addEventListener("click", (e) => {
      e.preventDefault();
      const show = rawBox.style.display !== "block";
      rawBox.style.display = show ? "block" : "none";
      toggleRawBtn.textContent = show ? "Hide Raw" : "Show Raw";
    });
  }

  const rescanBtn = document.getElementById("rescanBtn");
  if (rescanBtn) {
    rescanBtn.addEventListener("click", async (e) => {
      e.preventDefault();
      const orig = rescanBtn.textContent;
      rescanBtn.disabled = true;
      rescanBtn.textContent = "Rescanning...";
      try {
        const r = await fetch(`/api/rescan/${encodeURIComponent(rescanBtn.dataset?.msg || "")}`, { method: "POST" });
        const j = await r.json().catch(() => null);
        if (!j || !j.ok) alert("Rescan failed");
        else location.reload();
      } catch (err) {
        alert("Rescan error");
      } finally {
        rescanBtn.disabled = false;
        rescanBtn.textContent = orig;
      }
    });
  }

  /* ============================
     IFRAME RENDER LOAD & THEME SYNC
  ============================ */

  const frame = document.getElementById("renderFrame");
  if (frame) {
    const msgId = frame.dataset.msg;
    // use /email_html/ endpoint if available; fallback to /render/
    const tryUrl = (p) => fetch(p, { method: "GET", credentials: "same-origin", mode: "same-origin" })
                         .then(r => r.ok ? p : Promise.reject())
                         .catch(() => Promise.reject());
    (async () => {
      const candidates = [
        `/email_html/${encodeURIComponent(msgId)}`,
        `/render/${encodeURIComponent(msgId)}`
      ];
      for (const c of candidates) {
        try {
          const ok = await tryUrl(c);
          frame.src = ok;
          break;
        } catch (_) { /* try next */ }
      }
    })();

    frame.addEventListener("load", () => {
      try {
        const doc = frame.contentDocument || frame.contentWindow.document;
        if (!doc) return;
        // force links in the iframe to open safely
        Array.from(doc.querySelectorAll("a[href]")).forEach(a => {
          a.setAttribute("target", "_blank");
          a.setAttribute("rel", "noopener noreferrer");
        });
        // apply theme from parent (postMessage also supported in render.html)
        try {
          const parentTheme = document.documentElement.getAttribute("data-theme");
          if (parentTheme) frame.contentWindow.postMessage({ type: "themeSync", theme: parentTheme }, "*");
        } catch (_) { /* ignore */ }

        // auto-resize (best-effort)
        setTimeout(() => {
          try {
            const h = Math.max(doc.body.scrollHeight, doc.documentElement.scrollHeight, doc.body.offsetHeight);
            frame.style.height = (h > 0 ? h + 30 : 400) + "px";
          } catch (_) {
            frame.style.minHeight = "400px";
          }
        }, 150);
      } catch (err) {
        frame.style.minHeight = "400px";
      }
    });
  }

  /* ============================
     PREVIEW/MODAL SYSTEM
  ============================ */

  const modal = document.getElementById("previewModal");
  const backdrop = document.getElementById("previewBackdrop");
  const content = document.getElementById("previewContent");
  const container = document.getElementById("previewContainer");
  
  // utility to clear object URLs created
  const createdURLs = new Set();
  
  function revokeAll() {
    for (const u of createdURLs) {
      try { URL.revokeObjectURL(u); } catch (_) {}
    }
    createdURLs.clear();
  }

  function showModal() {
    if (!modal) return;
    modal.style.display = "block";
    // ensure backdrop visible
    if (backdrop) backdrop.style.display = "block";
    // lock focus to modal
    document.body.style.overflow = "hidden";
  }

  function hideModal() {
    if (!modal) return;
    modal.style.display = "none";
    if (backdrop) backdrop.style.display = "none";
    container.innerHTML = "";
    revokeAll();
    document.body.style.overflow = "";
  }

  if (backdrop) {
    backdrop.addEventListener("click", hideModal);
  }

  // close with Escape
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") hideModal();
  });

  // clicking outside preview content (on modal) closes
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) hideModal();
    });
  }

  // preview buttons
  const previewButtons = Array.from(document.querySelectorAll(".preview-btn") || []);

  async function fetchBlob(url) {
    try {
      const resp = await fetch(url, { credentials: "same-origin", mode: "same-origin" });
      if (!resp.ok) throw new Error(`${resp.status}`);
      const blob = await resp.blob();
      return blob;
    } catch (err) {
      throw err;
    }
  }

  function makeCenteredWrapper(el) {
    // content wrapper to control sizing and centering
    const wrapper = document.createElement("div");
    wrapper.style.maxWidth = "90vw";
    wrapper.style.maxHeight = "90vh";
    wrapper.style.width = "auto";
    wrapper.style.height = "auto";
    wrapper.style.display = "flex";
    wrapper.style.alignItems = "center";
    wrapper.style.justifyContent = "center";
    wrapper.style.overflow = "auto";
    if (el) wrapper.appendChild(el);
    return wrapper;
  }

  previewButtons.forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.preventDefault();

      const msgId = btn.dataset.msg;
      const attachmentId = btn.dataset.attachment;
      const filename = (btn.dataset.filename || "").toLowerCase();

      if (isPhishView && !btn._phishPreviewAllowed) {
        showPhishWarningOverlay(
          "You are about to PREVIEW an attachment from a PHISHING/MAYBEPHISHING email. The file may contain malware or sensitive data.",
          () => {
            btn._phishPreviewAllowed = true;
            btn.click();
          },
          () => {}
        );
        return;
      }
      btn._phishPreviewAllowed = false;

      if (!msgId || !attachmentId) return alert("Attachment info missing");

      container.innerHTML = "";
      showModal();

      // Create loading indicator
      const loading = document.createElement("div");
      loading.textContent = "Loading preview...";
      loading.style.color = "rgba(255,255,255,0.9)";
      loading.style.padding = "10px 16px";
      loading.style.borderRadius = "6px";
      loading.style.background = "rgba(0,0,0,0.5)";
      loading.style.textAlign = "center";
      container.appendChild(loading);

      const url = `/preview_attachment/${encodeURIComponent(msgId)}/${encodeURIComponent(attachmentId)}`;

      try {
        const response = await fetch(url, { 
          credentials: "same-origin", 
          mode: "same-origin" 
        });
        
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const blob = await response.blob();
        const mime = blob.type || "";
        const blobUrl = URL.createObjectURL(blob);
        createdURLs.add(blobUrl);

        // remove loading
        container.innerHTML = "";

        // Check if this is an HTML response (likely a converted Office document)
        const isHtmlResponse = mime === "text/html" || 
          response.headers.get('content-type')?.includes('text/html') ||
          filename.endsWith('.html');
        // Handle HTML responses (converted Office documents)
        if (isHtmlResponse) {
          const iframe = document.createElement("iframe");
          iframe.srcdoc = await blob.text();
          iframe.style.width = "90vw";
          iframe.style.height = "80vh";
          iframe.style.border = "1px solid #ddd";
          iframe.style.borderRadius = "6px";
          iframe.style.background = "#fff";
          iframe.style.overflow = "auto";
          
          // Add some basic styles to the document
          iframe.onload = function() {
            try {
              const style = iframe.contentDocument.createElement('style');
              style.textContent = `
                body { 
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                  line-height: 1.6;
                  color: #333;
                  padding: 20px;
                  max-width: 100%;
                  margin: 0 auto;
                }
                table {
                  border-collapse: collapse;
                  width: 100%;
                  margin: 15px 0;
                }
                th, td {
                  border: 1px solid #ddd;
                  padding: 8px 12px;
                  text-align: left;
                }
                th {
                  background-color: #f5f5f5;
                  font-weight: 600;
                }
                .slide {
                  margin-bottom: 30px;
                  padding: 15px;
                  border-left: 4px solid #4a90e2;
                  background-color: #f9f9f9;
                }
                img {
                  max-width: 100%;
                  height: auto;
                }
              `;
              iframe.contentDocument.head.appendChild(style);
            } catch (e) {
              console.error('Error styling document preview:', e);
            }
          };
          
          container.appendChild(iframe);
        }
        // Handle PDF files
        else if (mime === "application/pdf" || filename.endsWith(".pdf")) {
          const iframe = document.createElement("iframe");
          iframe.src = blobUrl;
          iframe.style.width = "90vw";
          iframe.style.height = "80vh";
          iframe.style.border = "none";
          iframe.style.borderRadius = "6px";
          iframe.style.background = "#fff";
          container.appendChild(iframe);
        }
        // Handle images
        else if (mime.startsWith("image/") || filename.match(/\.(png|jpe?g|gif|webp|bmp)$/i)) {
          const img = document.createElement("img");
          img.src = blobUrl;
          img.style.maxWidth = "100%";
          img.style.maxHeight = "90vh";
          img.style.display = "block";
          img.style.objectFit = "contain";
          img.alt = filename || "image";
          const wrap = makeCenteredWrapper(img);
          container.appendChild(wrap);
        }
        // Handle videos
        else if (mime.startsWith("video/") || filename.match(/\.(mp4|webm|mov|mkv|ogv)$/i)) {
          const video = document.createElement("video");
          video.controls = true;
          video.src = blobUrl;
          video.style.maxWidth = "100%";
          video.style.maxHeight = "90vh";
          video.style.display = "block";
          video.setAttribute("playsinline", "");
          video.autoplay = false;
          const wrap = makeCenteredWrapper(video);
          container.appendChild(wrap);
        }
        // Handle audio - using same structure as video preview
        else if (mime.startsWith("audio/") || filename.match(/\.(mp3|wav|m4a|ogg|flac)$/i)) {
          const audioContainer = document.createElement("div");
          audioContainer.style.width = "100%";
          audioContainer.style.padding = "20px";
          audioContainer.style.textAlign = "center";
          
          const audio = document.createElement("audio");
          audio.controls = true;
          audio.src = blobUrl;
          audio.style.width = "100%";
          audio.style.minWidth = "400px";  // Make it wider
          audio.style.maxWidth = "800px";
          audio.style.display = "block";
          audio.style.margin = "0 auto";
          audio.autoplay = false;
          
          audioContainer.appendChild(audio);
          container.appendChild(audioContainer);
        }
        // Fallback for unsupported file types
        else {
          const info = document.createElement("div");
          info.style.color = "var(--text, #000)";
          info.style.padding = "20px";
          info.style.textAlign = "center";
          
          const message = document.createElement("p");
          message.textContent = "No inline preview available for this file type.";
          message.style.marginBottom = "15px";
          info.appendChild(message);
          
          container.appendChild(info);
        }
      } catch (err) {
        console.error("Preview error:", err);
        container.innerHTML = "";
        
        const errorContainer = document.createElement("div");
        errorContainer.style.padding = "20px";
        errorContainer.style.textAlign = "center";
        errorContainer.style.color = "#dc3545";
        
        const errorIcon = document.createElement("div");
        errorIcon.style.fontSize = "48px";
        errorIcon.style.marginBottom = "15px";
        
        const errorTitle = document.createElement("h3");
        errorTitle.textContent = "Preview Unavailable";
        errorTitle.style.margin = "0 0 10px 0";
        
        const errorMessage = document.createElement("p");
        errorMessage.textContent = `Could not load the preview. ${err.message || 'Please try again later.'}`;
        errorMessage.style.margin = "0 0 15px 0";
        
        errorContainer.appendChild(errorIcon);
        errorContainer.appendChild(errorTitle);
        errorContainer.appendChild(errorMessage);
        
        container.appendChild(errorContainer);
      } finally {
        if (loading && loading.parentNode === container) {
          container.removeChild(loading);
        }
      }
    });
  });

  // Intercept attachment downloads on phishing messages
  const downloadLinks = Array.from(document.querySelectorAll("a.download-attachment") || []);
  downloadLinks.forEach(a => {
    a.addEventListener("click", (ev) => {
      if (!isPhishView) return; // normal behavior for non-phish

      if (a._phishDownloadAllowed) {
        a._phishDownloadAllowed = false;
        return;
      }

      ev.preventDefault();
      ev.stopPropagation();

      showPhishWarningOverlay(
        "You are about to DOWNLOAD an attachment from a PHISHING/MAYBEPHISHING email. Files may contain ransomware, keyloggers, or other malware.",
        () => {
          a._phishDownloadAllowed = true;
          a.click();
        },
        () => {}
      );
    });
  });

  // Ensure risk table links also trigger safe-click confirmation
  const riskLinks = Array.from(document.querySelectorAll(".warn-link") || []);
  riskLinks.forEach(a => {
    if (a._riskClickBound) return; // use different flag to avoid conflicts
    a._riskClickBound = true;
    a.addEventListener("click", (ev) => {
      if (isPhishView) {
        // Force confirmation even if user previously chose "remember choice"
        const originalAllow = localStorage.getItem("safe_click_allow");
        localStorage.removeItem("safe_click_allow");
        // Re-bind safe_click handler for this click
        setTimeout(() => {
          if (originalAllow) localStorage.setItem("safe_click_allow", originalAllow);
        }, 100);
      }
    });
  });

// Override functionality
const overrideBtn = document.getElementById("overrideBtn");
const overrideModal = document.getElementById("overrideModal");
const overrideBackdrop = document.getElementById("overrideBackdrop");
const overrideCancel = document.getElementById("overrideCancel");
const overrideToSafe = document.getElementById("overrideToSafe");
const overrideToPhish = document.getElementById("overrideToPhish");

function showOverrideModal(ev) {
  if (!overrideModal) return;
  
  if (ev) {
    ev.preventDefault();
    ev.stopPropagation();
  }
  
  overrideModal.style.display = "block";
  overrideModal.style.zIndex = "2147483647";
  
  const content = overrideModal.querySelector('#overrideContent');
  if (content) {
    content.style.zIndex = "2147483647";
  }
}

function hideOverrideModal() {
  if (overrideModal) {
    overrideModal.style.display = "none";
  }
}

if (overrideBtn) {
  const newBtn = overrideBtn.cloneNode(true);
  overrideBtn.parentNode.replaceChild(newBtn, overrideBtn);
  
  newBtn.addEventListener("click", (ev) => {
    showOverrideModal(ev);
  });
  
  newBtn.addEventListener("touchstart", (ev) => {
    showOverrideModal(ev);
  }, { passive: true });
}

if (overrideBackdrop) {
  const newBackdrop = overrideBackdrop.cloneNode(true);
  overrideBackdrop.parentNode.replaceChild(newBackdrop, overrideBackdrop);
  
  newBackdrop.addEventListener("click", (ev) => {
    ev.stopPropagation();
    hideOverrideModal();
  });
}

if (overrideCancel) {
  overrideCancel.addEventListener("click", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    hideOverrideModal();
  });
}

async function submitOverride(label) {
  const msgId = overrideBtn?.dataset?.msg;
  if (!msgId) {
    alert("Missing message id");
    return;
  }

  try {
    // Include msg_id in URL path and label in request body
    const res = await fetch(`/api/override_label/${encodeURIComponent(msgId)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        label: label,
        score: label === 'safe' ? 0.0 : 1.0
      })
    });

    if (!res.ok) {
      const error = await res.json().catch(() => ({}));
      throw new Error(error.error || "Failed to update classification");
    }

    hideOverrideModal();
    window.location.reload();
  } catch (err) {
    console.error("Override error:", err);
    alert(`Error updating classification: ${err.message}`);
  }
}

if (overrideToSafe) {
  overrideToSafe.addEventListener("click", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    submitOverride("safe");
  });
}

if (overrideToPhish) {
  overrideToPhish.addEventListener("click", (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    submitOverride("phish");
  });
}

}); // Close DOMContentLoaded
