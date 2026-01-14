// safe_click.js — intercepts external links inside email iframe and risk table
// ensures user confirmation before browsing potentially unsafe URLs

(function() {
    if (window._safe_click_loaded) return;
    window._safe_click_loaded = true;

    function isExternalLink(a) {
        if (!a || !a.href) return false;
        const u = a.href.toLowerCase();
        return u.startsWith("http://") || u.startsWith("https://") || u.startsWith("mailto:");
    }

    function showModal(url, callback) {
        // prevent duplicate modals
        if (window._safe_click_modal_open) return;
        window._safe_click_modal_open = true;

        // remove any lingering overlay (defensive)
        try {
            const prev = document.getElementById("safeClickOverlay");
            if (prev && prev.parentNode) prev.parentNode.removeChild(prev);
        } catch {}

        const overlay = document.createElement("div");
        overlay.id = "safeClickOverlay";
        overlay.style.cssText = `
            position:fixed;inset:0;z-index:2147483647;
            background:rgba(0,0,0,0.85);
            display:flex;align-items:center;justify-content:center;
        `;

        const box = document.createElement("div");
        box.style.cssText = `
            max-width:520px;width:90%;
            background:#b71c1c;color:#fff;
            border-radius:10px;
            box-shadow:0 10px 35px rgba(0,0,0,0.7);
            padding:20px 22px;
            font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
            text-align:left;
            border:2px solid #ffeb3b;
        `;

        const msg = document.createElement("div");
        msg.style.marginBottom = "10px";
        msg.style.fontSize = "14px";
        msg.textContent = "Danger: You are about to open an external link which may be unsafe. Attackers often use fake login pages or malicious downloads.";

        const label = document.createElement("label");
        label.style.cssText = "display:flex;align-items:center;font-size:13px;margin:0 0 12px 0;";

        const check = document.createElement("input");
        check.type = "checkbox";
        check.style.marginRight = "6px";
        label.appendChild(check);
        label.appendChild(document.createTextNode("Remember choice"));

        const row = document.createElement("div");
        row.style.cssText = "display:flex;justify-content:flex-end;gap:10px;margin-top:8px;flex-wrap:wrap;";

        const btnCancel = document.createElement("button");
        btnCancel.textContent = "Go back";
        btnCancel.style.cssText = `
            padding:8px 14px;border-radius:6px;border:none;
            background:#263238;color:#fff;font-size:13px;cursor:pointer;
        `;

        const btnOK = document.createElement("button");
        btnOK.textContent = "I understand, open link";
        btnOK.style.cssText = `
            padding:8px 14px;border-radius:6px;border:none;
            background:#ffeb3b;color:#000;font-weight:600;font-size:13px;cursor:pointer;
        `;

        btnCancel.onclick = () => {
            try { document.body.removeChild(overlay); } catch {}
            window._safe_click_modal_open = false;
        };
        btnOK.onclick = () => {
            if (check.checked) localStorage.setItem("safe_click_allow", "1");
            try { document.body.removeChild(overlay); } catch {}
            window._safe_click_modal_open = false;
            callback();
        };

        row.appendChild(btnCancel);
        row.appendChild(btnOK);
        box.appendChild(msg);
        box.appendChild(label);
        box.appendChild(row);
        overlay.appendChild(box);
        document.body.appendChild(overlay);
    }

    function protectLinks(doc) {
        const allow = localStorage.getItem("safe_click_allow") === "1";
        const links = doc.querySelectorAll("a[href]");

        links.forEach(a => {
            if (!isExternalLink(a)) return;

            // enforce new tab
            a.setAttribute("target", "_blank");
            a.setAttribute("rel", "noopener noreferrer");

            // confirmation handler
            if (a._safeClickBound) return; // avoid duplicate binding when re-applying
            a._safeClickBound = true;
            a.addEventListener("click", e => {
                if (e.ctrlKey || e.metaKey || allow) return;
                e.preventDefault();
                e.stopPropagation();
                const url = a.href;
                showModal(url, () => window.open(url, "_blank"));
            }, { capture: true });
        });
    }

    function initIframeWatcher() {
        const frame = document.getElementById("renderFrame");
        if (!frame) return;

        function apply() {
            try {
                const doc = frame.contentDocument || frame.contentWindow.document;
                if (!doc) return;
                protectLinks(doc);
            } catch {}
        }

        frame.addEventListener("load", apply);

        // for any later DOM changes (rare in sanitized mail)
        const observer = new MutationObserver(apply);
        try {
            observer.observe(frame, { attributes: true, childList: false });
        } catch {}
    }

    function initRiskTable() {
        const risks = document.querySelectorAll(".warn-link");
        risks.forEach(a => {
            a.setAttribute("target", "_blank");
            a.setAttribute("rel", "noopener noreferrer");
            
            // Apply safe-click protection to risk table links
            if (a._safeClickBound) return;
            a._safeClickBound = true;
            a.addEventListener("click", e => {
                const allow = localStorage.getItem("safe_click_allow") === "1";
                if (e.ctrlKey || e.metaKey || allow) return;
                e.preventDefault();
                e.stopPropagation();
                const url = a.href;
                showModal(url, () => window.open(url, "_blank"));
            }, { capture: true });
        });
    }

    document.addEventListener("DOMContentLoaded", () => {
        initIframeWatcher();
        initRiskTable();
    });
})();