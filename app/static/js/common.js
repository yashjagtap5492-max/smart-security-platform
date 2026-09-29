/* ==========================================================================
   common.js
   Shared across every page: API wrapper, toasts, formatting helpers,
   app-shell interactions (sidebar/user menu), and the reusable OTP input.

   IMPORTANT: this file never invents endpoints or data. It only wraps
   fetch() with consistent error/session handling for the real Flask APIs.
   ========================================================================== */

const Security = (() => {

  /* ------------------------------------------------------------------ */
  /* API wrapper                                                         */
  /* ------------------------------------------------------------------ */

  /**
   * apiRequest wraps fetch() to the Flask backend.
   * - Always sends/receives JSON and includes the session cookie.
   * - Normalizes every outcome into { ok, status, data, error }.
   * - On 401, fires a "security:session-expired" event so any page can react.
   */
  async function apiRequest(path, { method = "GET", body = null } = {}) {
    let response;
    try {
      response = await fetch(path, {
        method,
        credentials: "same-origin",
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (networkError) {
      return { ok: false, status: 0, data: null, error: "network" };
    }

    let data = null;
    const text = await response.text();
    if (text) {
      try { data = JSON.parse(text); } catch (_) { data = null; }
    }

    if (response.status === 401) {
      document.dispatchEvent(new CustomEvent("security:session-expired"));
      return { ok: false, status: 401, data, error: "unauthorized" };
    }

    if (!response.ok) {
      const errorKind =
        response.status === 403 ? "forbidden" :
        response.status === 404 ? "not_found" :
        response.status === 400 ? "validation" :
        response.status >= 500 ? "server" : "unknown";
      return { ok: false, status: response.status, data, error: errorKind };
    }

    return { ok: true, status: response.status, data, error: null };
  }

  function friendlyErrorMessage(result, fallback = "Something went wrong. Please try again.") {
    if (result.error === "network") return "Can't reach the server. Check your connection and try again.";
    if (result.error === "server") return "The server ran into a problem on its end. Please try again shortly.";
    if (result.error === "forbidden") return "You don't have permission to do that.";
    if (result.error === "not_found") return "That resource couldn't be found.";
    if (result.data && (result.data.message || result.data.error)) {
      return result.data.message || result.data.error;
    }
    return fallback;
  }

  /* ------------------------------------------------------------------ */
  /* Toasts                                                               */
  /* ------------------------------------------------------------------ */

  function ensureToastRegion() {
    let region = document.getElementById("toast-region");
    if (!region) {
      region = document.createElement("div");
      region.id = "toast-region";
      region.setAttribute("aria-live", "polite");
      document.body.appendChild(region);
    }
    return region;
  }

  function toast(message, kind = "default", duration = 4200) {
    const region = ensureToastRegion();
    const el = document.createElement("div");
    el.className = `toast toast-${kind}`;
    el.textContent = message;
    region.appendChild(el);
    setTimeout(() => {
      el.style.opacity = "0";
      el.style.transition = "opacity 160ms ease";
      setTimeout(() => el.remove(), 180);
    }, duration);
  }

  /* ------------------------------------------------------------------ */
  /* Session expiry                                                       */
  /* ------------------------------------------------------------------ */

  let sessionExpiredHandled = false;
  document.addEventListener("security:session-expired", () => {
    if (sessionExpiredHandled) return;
    sessionExpiredHandled = true;
    toast("Your session has expired. Redirecting to sign in…", "warning", 3000);
    setTimeout(() => {
      const next = encodeURIComponent(window.location.pathname);
      window.location.href = `/login?next=${next}`;
    }, 1200);
  });

  /* ------------------------------------------------------------------ */
  /* Formatting helpers                                                   */
  /* ------------------------------------------------------------------ */

  function riskBadgeClass(level) {
    if (!level) return "badge-neutral";
    return `badge-${String(level).toLowerCase()}`;
  }

  function statusBadgeClass(status) {
    if (!status) return "badge-neutral";
    return `badge-${String(status).toLowerCase()}`;
  }

  function formatDateTime(value) {
    if (!value) return "—";
    const d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    return d.toLocaleString(undefined, {
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  }

  function relativeTime(value) {
    if (!value) return "—";
    const d = new Date(value);
    if (isNaN(d.getTime())) return String(value);
    const diffMs = Date.now() - d.getTime();
    const mins = Math.round(diffMs / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.round(hrs / 24);
    if (days < 30) return `${days}d ago`;
    return formatDateTime(value);
  }

  function titleCase(value) {
    if (!value) return "—";
    return String(value).toLowerCase().replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  /* ------------------------------------------------------------------ */
  /* Button loading state                                                 */
  /* ------------------------------------------------------------------ */

  function setButtonLoading(button, isLoading) {
    if (!button) return;
    button.disabled = isLoading;
    button.classList.toggle("is-loading", isLoading);
  }

  /* ------------------------------------------------------------------ */
  /* Password visibility toggle                                          */
  /* ------------------------------------------------------------------ */

  function initPasswordToggles(root = document) {
    root.querySelectorAll("[data-toggle-password]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const targetId = btn.getAttribute("data-toggle-password");
        const input = document.getElementById(targetId);
        if (!input) return;
        const showing = input.type === "text";
        input.type = showing ? "password" : "text";
        btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
        btn.innerHTML = showing ? ICONS.eye : ICONS.eyeOff;
      });
    });
  }

  const ICONS = {
    eye: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1.5 12s4-7.5 10.5-7.5S22.5 12 22.5 12s-4 7.5-10.5 7.5S1.5 12 1.5 12Z"/><circle cx="12" cy="12" r="3"/></svg>',
    eyeOff: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3l18 18M10.6 10.6a3 3 0 0 0 4.24 4.24M6.2 6.6C3.9 8.1 2 12 2 12s3.5 7 10 7c2 0 3.7-.5 5-1.3M17.9 17.9C20 16.4 22 12 22 12s-1.1-2.2-3.2-4.1"/></svg>',
  };

  /* ------------------------------------------------------------------ */
  /* OTP input (6-digit, auto-advance, paste support)                    */
  /* ------------------------------------------------------------------ */

  function initOtpGroup(container, { onComplete } = {}) {
    if (!container) return null;
    const digits = Array.from(container.querySelectorAll(".otp-digit"));

    function getValue() { return digits.map((d) => d.value).join(""); }
    function clearError() { digits.forEach((d) => d.classList.remove("has-error")); }
    function setError() { digits.forEach((d) => d.classList.add("has-error")); }
    function reset() { digits.forEach((d) => { d.value = ""; }); digits[0].focus(); clearError(); }

    digits.forEach((digit, i) => {
      digit.addEventListener("input", () => {
        digit.value = digit.value.replace(/[^0-9]/g, "").slice(-1);
        clearError();
        if (digit.value && i < digits.length - 1) digits[i + 1].focus();
        if (getValue().length === digits.length && onComplete) onComplete(getValue());
      });
      digit.addEventListener("keydown", (e) => {
        if (e.key === "Backspace" && !digit.value && i > 0) digits[i - 1].focus();
        if (e.key === "ArrowLeft" && i > 0) digits[i - 1].focus();
        if (e.key === "ArrowRight" && i < digits.length - 1) digits[i + 1].focus();
      });
      digit.addEventListener("paste", (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData.getData("text") || "").replace(/[^0-9]/g, "").slice(0, digits.length);
        pasted.split("").forEach((ch, idx) => { if (digits[idx]) digits[idx].value = ch; });
        const last = Math.min(pasted.length, digits.length) - 1;
        if (last >= 0) digits[last].focus();
        if (getValue().length === digits.length && onComplete) onComplete(getValue());
      });
    });

    return { getValue, setError, clearError, reset };
  }

  function startCountdown(el, seconds, onExpire) {
    let remaining = seconds;
    const render = () => {
      const m = String(Math.floor(remaining / 60)).padStart(2, "0");
      const s = String(remaining % 60).padStart(2, "0");
      if (el) el.textContent = `${m}:${s}`;
    };
    render();
    const timer = setInterval(() => {
      remaining -= 1;
      render();
      if (remaining <= 0) {
        clearInterval(timer);
        if (onExpire) onExpire();
      }
    }, 1000);
    return () => clearInterval(timer);
  }

  /* ------------------------------------------------------------------ */
  /* App shell: sidebar drawer + user menu                                */
  /* ------------------------------------------------------------------ */

  function initShell() {
    const menuBtn = document.querySelector("[data-menu-toggle]");
    const sidebar = document.querySelector(".sidebar");
    const scrim = document.querySelector(".sidebar-scrim");
    if (menuBtn && sidebar) {
      const close = () => { sidebar.classList.remove("is-open"); scrim && scrim.classList.remove("is-open"); };
      menuBtn.addEventListener("click", () => {
        sidebar.classList.add("is-open");
        scrim && scrim.classList.add("is-open");
      });
      scrim && scrim.addEventListener("click", close);
    }

    const userChip = document.querySelector("[data-user-menu-toggle]");
    const userPanel = document.querySelector("[data-user-menu-panel]");
    if (userChip && userPanel) {
      userChip.addEventListener("click", (e) => {
        e.stopPropagation();
        userPanel.classList.toggle("is-open");
      });
      document.addEventListener("click", (e) => {
        if (!userPanel.contains(e.target)) userPanel.classList.remove("is-open");
      });
    }

    document.querySelectorAll("[data-logout]").forEach((logoutBtn) => {
      logoutBtn.addEventListener("click", async () => {
        await apiRequest("/logout", { method: "POST" });
        // Even if the API call failed, still send the user to login —
        // the session is likely already gone client-side.
        window.location.href = "/login";
      });
    });
  }

  /* ------------------------------------------------------------------ */
  /* Field-level validation helper                                       */
  /* ------------------------------------------------------------------ */

  function showFieldError(input, errorEl, message) {
    if (errorEl) { errorEl.textContent = message; errorEl.classList.toggle("is-visible", !!message); }
    if (input) input.classList.toggle("has-error", !!message);
  }

  return {
    apiRequest, friendlyErrorMessage, toast,
    riskBadgeClass, statusBadgeClass, formatDateTime, relativeTime, titleCase, escapeHtml,
    setButtonLoading, initPasswordToggles, initOtpGroup, startCountdown, initShell, showFieldError,
  };
})();

document.addEventListener("DOMContentLoaded", () => {
  Security.initShell();
  Security.initPasswordToggles();
});
