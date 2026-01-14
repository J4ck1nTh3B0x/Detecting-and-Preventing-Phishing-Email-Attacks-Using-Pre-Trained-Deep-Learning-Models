// theme.js — Global synchronized theme controller
(function () {
	if (window._theme_js_loaded) return;
	window._theme_js_loaded = true;

	const STORAGE_KEY = "app_theme";
	const CHANNEL_NAME = "theme_sync";
	const channel = new BroadcastChannel(CHANNEL_NAME);

	function getSystemPreference() {
		try {
			if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches)
				return "dark";
		} catch {}
		return "light";
	}

	function applyTheme(theme, propagate = true) {
		if (!theme) return;
		document.documentElement.setAttribute("data-theme", theme);
		localStorage.setItem(STORAGE_KEY, theme);

		if (propagate) {
			try {
				channel.postMessage({ theme });
			} catch {}
		}
	}

	async function fetchServerTheme() {
		try {
			const res = await fetch("/api/get_theme");
			if (!res.ok) return null;
			const data = await res.json();
			if (data && data.theme) return data.theme;
		} catch {}
		return null;
	}

	async function setServerTheme(theme) {
		try {
			await fetch("/api/set_theme", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ theme }),
			});
		} catch {}
	}

	async function initTheme() {
		let localTheme = localStorage.getItem(STORAGE_KEY);
		let serverTheme = await fetchServerTheme();

		let finalTheme = serverTheme || localTheme || getSystemPreference();
		applyTheme(finalTheme, false);
		localStorage.setItem(STORAGE_KEY, finalTheme);

		// Keep iframe or embedded contexts consistent
		if (window.top !== window && window.top.postMessage) {
			window.top.postMessage({ theme: finalTheme, source: "iframe" }, "*");
		}
	}

	function toggleTheme() {
		const current = document.documentElement.getAttribute("data-theme") || "light";
		const next = current === "dark" ? "light" : "dark";
		applyTheme(next);
		setServerTheme(next);
	}

	// Watch for manual toggles via theme buttons
	document.addEventListener("DOMContentLoaded", () => {
		initTheme();

		const btn = document.getElementById("themeToggle");
		if (btn) {
			btn.addEventListener("click", e => {
				e.preventDefault();
				toggleTheme();
			});
		}
	});

	// React to system theme changes
	try {
		window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", e => {
			const newTheme = e.matches ? "dark" : "light";
			applyTheme(newTheme);
			setServerTheme(newTheme);
		});
	} catch {}

	// Receive cross-tab theme updates
	channel.addEventListener("message", ev => {
		if (ev.data && ev.data.theme) {
			applyTheme(ev.data.theme, false);
			setServerTheme(ev.data.theme);
		}
	});

	// Receive theme sync messages from iframes
	window.addEventListener("message", ev => {
		if (ev.data && ev.data.theme && ev.data.source === "iframe") {
			applyTheme(ev.data.theme, false);
			setServerTheme(ev.data.theme);
		}
	});
})();
