/* ==========================================================================
   auth.js — login, register, and the "verify 2FA" step during login.
   Uses only: POST /login, POST /2fa/verify, POST /register, POST /password-security
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  initLoginForm();
  initRegisterForm();
});

/* -------------------------------------------------------------------- */
/* LOGIN                                                                  */
/* -------------------------------------------------------------------- */

function initLoginForm() {
  const form = document.getElementById("login-form");
  if (!form) return;

  const identifierInput = document.getElementById("login-identifier");
  const passwordInput = document.getElementById("login-password");
  const submitBtn = document.getElementById("login-submit");
  const banner = document.getElementById("login-banner");

  const twoFaSection = document.getElementById("login-2fa");
  const otpContainer = document.getElementById("login-otp-group");
  const otpBanner = document.getElementById("login-2fa-banner");
  const otpVerifyBtn = document.getElementById("login-2fa-verify");
  const otpBackBtn = document.getElementById("login-2fa-back");
  const countdownEl = document.getElementById("login-2fa-countdown");

  let otp = null;
  let stopCountdown = null;

  function showBanner(el, message, kind = "banner-error") {
    if (!el) return;
    el.textContent = message;
    el.className = `banner ${kind}`;
    el.style.display = message ? "flex" : "none";
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    showBanner(banner, "");

    const identifier = identifierInput.value.trim();
    const password = passwordInput.value;

    if (!identifier || !password) {
      showBanner(banner, "Enter your email or username and your password.");
      return;
    }

    Security.setButtonLoading(submitBtn, true);
    const result = await Security.apiRequest("/login", {
      method: "POST",
      body: { identifier, password },
    });
    Security.setButtonLoading(submitBtn, false);

    if (!result.ok) {
      if (result.status === 401 || result.error === "validation") {
        showBanner(banner, "That email/username or password isn't right.");
      } else {
        showBanner(banner, Security.friendlyErrorMessage(result, "We couldn't sign you in. Please try again."));
      }
      return;
    }

    const data = result.data || {};

    if (data.requires_2fa) {
      form.style.display = "none";
      twoFaSection.style.display = "block";
      otp = Security.initOtpGroup(otpContainer, {
        onComplete: (code) => submitTwoFactor(code),
      });
      otpContainer.querySelector(".otp-digit").focus();
      stopCountdown = Security.startCountdown(countdownEl, 300, () => {
        showBanner(otpBanner, "This code has expired. Request a new one from your authenticator app.", "banner-warning");
      });
      return;
    }

    Security.toast("Signed in.", "success");
    const params = new URLSearchParams(window.location.search);
    window.location.href = params.get("next") || "/dashboard";
  });

  async function submitTwoFactor(code) {
    showBanner(otpBanner, "");
    Security.setButtonLoading(otpVerifyBtn, true);
    const result = await Security.apiRequest("/2fa/verify", {
      method: "POST",
      body: { code },
    });
    Security.setButtonLoading(otpVerifyBtn, false);

    if (!result.ok) {
      otp.setError();
      showBanner(otpBanner, "That code isn't valid. Check your authenticator app and try again.");
      return;
    }

    if (stopCountdown) stopCountdown();
    Security.toast("Signed in.", "success");
    const params = new URLSearchParams(window.location.search);
    window.location.href = params.get("next") || "/dashboard";
  }

  if (otpVerifyBtn) {
    otpVerifyBtn.addEventListener("click", () => {
      if (otp && otp.getValue().length === 6) submitTwoFactor(otp.getValue());
      else showBanner(otpBanner, "Enter all 6 digits from your authenticator app.");
    });
  }

  if (otpBackBtn) {
    otpBackBtn.addEventListener("click", () => {
      if (stopCountdown) stopCountdown();
      twoFaSection.style.display = "none";
      form.style.display = "";
      passwordInput.value = "";
      passwordInput.focus();
    });
  }
}

/* -------------------------------------------------------------------- */
/* REGISTER                                                               */
/* -------------------------------------------------------------------- */

function initRegisterForm() {
  const form = document.getElementById("register-form");
  if (!form) return;

  const usernameInput = document.getElementById("register-username");
  const emailInput = document.getElementById("register-email");
  const passwordInput = document.getElementById("register-password");
  const confirmInput = document.getElementById("register-confirm");
  const submitBtn = document.getElementById("register-submit");
  const banner = document.getElementById("register-banner");
  const confirmError = document.getElementById("register-confirm-error");

  const strengthWrap = document.getElementById("pw-strength");
  const strengthLabel = document.getElementById("pw-strength-label-text");
  const requirementItems = strengthWrap ? strengthWrap.parentElement.querySelectorAll(".pw-requirements li") : [];

  let strengthTimer = null;

  function updateLocalRequirementHints(password) {
    // Lightweight, purely client-side hints for immediate feedback only.
    // The authoritative score/strength/warnings always come from
    // POST /password-security below — this never substitutes for it.
    const rules = {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      symbol: /[^A-Za-z0-9]/.test(password),
    };
    requirementItems.forEach((li) => {
      const rule = li.getAttribute("data-rule");
      li.classList.toggle("is-met", !!rules[rule]);
    });
  }

  async function checkPasswordStrength(password) {
    if (!password) {
      if (strengthWrap) strengthWrap.dataset.level = "";
      if (strengthLabel) strengthLabel.textContent = "";
      return;
    }
    const result = await Security.apiRequest("/password-security", {
      method: "POST",
      body: { password },
    });
    if (!result.ok || !result.data) {
      if (strengthLabel) strengthLabel.textContent = "Couldn't check strength right now";
      return;
    }
    const level = (result.data.strength || "").toLowerCase().replace(/\s+/g, "_");
    if (strengthWrap) strengthWrap.dataset.level = level;
    if (strengthLabel) strengthLabel.textContent = Security.titleCase(result.data.strength || "");
  }

  if (passwordInput) {
    passwordInput.addEventListener("input", () => {
      const password = passwordInput.value;
      updateLocalRequirementHints(password);
      clearTimeout(strengthTimer);
      strengthTimer = setTimeout(() => checkPasswordStrength(password), 350);
    });
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    banner.style.display = "none";
    Security.showFieldError(confirmInput, confirmError, "");

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirm = confirmInput.value;

    if (password !== confirm) {
      Security.showFieldError(confirmInput, confirmError, "Passwords don't match.");
      return;
    }

    Security.setButtonLoading(submitBtn, true);
    const result = await Security.apiRequest("/register", {
      method: "POST",
      body: { username, email, password },
    });
    Security.setButtonLoading(submitBtn, false);

    if (!result.ok) {
      banner.className = "banner banner-error";
      banner.style.display = "flex";
      banner.textContent = Security.friendlyErrorMessage(
        result,
        "We couldn't create your account. Double-check your details and try again."
      );
      return;
    }

    banner.className = "banner banner-success";
    banner.style.display = "flex";
    banner.textContent = "Account created. Redirecting to sign in…";
    setTimeout(() => { window.location.href = "/login"; }, 1200);
  });
}
