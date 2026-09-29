/* ==========================================================================
   two-factor.js — enabling 2FA from the profile/security-settings page.
   Uses only: POST /2fa/setup, POST /2fa/verify
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  const root = document.getElementById("twofa-setup");
  if (!root) return;

  const stepStart = root.querySelector("[data-step='start']");
  const stepSetup = root.querySelector("[data-step='setup']");
  const stepVerify = root.querySelector("[data-step='verify']");
  const stepDone = root.querySelector("[data-step='done']");

  const enableBtn = document.getElementById("twofa-enable-btn");
  const qrImg = document.getElementById("twofa-qr");
  const qrFallback = document.getElementById("twofa-qr-fallback");
  const manualKey = document.getElementById("twofa-manual-key");
  const setupBanner = document.getElementById("twofa-setup-banner");
  const continueBtn = document.getElementById("twofa-continue-btn");

  const otpContainer = document.getElementById("twofa-otp-group");
  const verifyBtn = document.getElementById("twofa-verify-btn");
  const verifyBanner = document.getElementById("twofa-verify-banner");

  let otp = null;

  function showStep(step) {
    [stepStart, stepSetup, stepVerify, stepDone].forEach((s) => { if (s) s.style.display = "none"; });
    if (step) step.style.display = "block";
  }

  function showBanner(el, message, kind = "banner-error") {
    if (!el) return;
    el.textContent = message;
    el.className = `banner ${kind}`;
    el.style.display = message ? "flex" : "none";
  }

  if (enableBtn) {
    enableBtn.addEventListener("click", async () => {
      showBanner(setupBanner, "");
      Security.setButtonLoading(enableBtn, true);
      const result = await Security.apiRequest("/2fa/setup", { method: "POST" });
      Security.setButtonLoading(enableBtn, false);

      if (!result.ok) {
        showBanner(setupBanner, Security.friendlyErrorMessage(result, "Couldn't start 2FA setup. Try again."));
        return;
      }

      const data = result.data || {};
      // Never place the raw secret in the URL, localStorage, or the console.
      if (data.qr_code) {
        qrImg.src = data.qr_code.startsWith("data:") ? data.qr_code : `data:image/png;base64,${data.qr_code}`;
        qrImg.style.display = "block";
        qrFallback.style.display = "none";
      } else if (data.provisioning_uri) {
        qrFallback.style.display = "block";
        qrImg.style.display = "none";
      }
      if (manualKey) manualKey.textContent = data.secret || "Unavailable — use the QR code above";

      showStep(stepSetup);
    });
  }

  if (continueBtn) {
    continueBtn.addEventListener("click", () => {
      showStep(stepVerify);
      otp = Security.initOtpGroup(otpContainer, { onComplete: (code) => verifyCode(code) });
      otpContainer.querySelector(".otp-digit").focus();
    });
  }

  async function verifyCode(code) {
    showBanner(verifyBanner, "");
    Security.setButtonLoading(verifyBtn, true);
    const result = await Security.apiRequest("/2fa/verify", { method: "POST", body: { code } });
    Security.setButtonLoading(verifyBtn, false);

    if (!result.ok) {
      otp.setError();
      showBanner(verifyBanner, "That code isn't valid. Check the time on your device and try again.");
      return;
    }

    showStep(stepDone);
    Security.toast("Two-factor authentication is now enabled.", "success");
  }

  if (verifyBtn) {
    verifyBtn.addEventListener("click", () => {
      if (otp && otp.getValue().length === 6) verifyCode(otp.getValue());
      else showBanner(verifyBanner, "Enter all 6 digits from your authenticator app.");
    });
  }
});
