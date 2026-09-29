document.addEventListener("DOMContentLoaded", () => {

    const home = document.getElementById("settings-home");

    const views = document.querySelectorAll(".settings-view");

    const openButtons =
        document.querySelectorAll("[data-open-view]");

    const backButtons =
        document.querySelectorAll("[data-back]");

    const searchInput =
        document.getElementById("settings-search");

    const searchResults =
        document.getElementById("settings-search-results");


    let currentView = "home";


    function showView(viewName) {

        currentView = viewName;

        if (viewName === "home") {

            home.classList.add("active");

            views.forEach(view => {

                if (view !== home) {
                    view.classList.remove("active");
                }

            });

        } else {

            home.classList.remove("active");

            views.forEach(view => {

                view.classList.toggle(
                    "active",
                    view.dataset.view === viewName
                );

            });

        }

        window.scrollTo({
            top: 0,
            behavior: "smooth"
        });

        searchResults.classList.remove("visible");

        searchInput.value = "";

        history.replaceState(
            null,
            "",
            viewName === "home"
                ? window.location.pathname
                : `${window.location.pathname}#${viewName}`
        );

        if (viewName === "security") {
            loadSecurityScore();
        }

        if (viewName === "twofa") {
            loadTwoFactorStatus();
        }

    }


    openButtons.forEach(button => {

        button.addEventListener("click", () => {

            const target =
                button.dataset.openView;

            if (target) {
                showView(target);
            }

        });

    });


    backButtons.forEach(button => {

        button.addEventListener("click", () => {

            showView("home");

        });

    });


    const initialView =
        window.location.hash.substring(1);

    const validViews = [
        "profile",
        "account",
        "security",
        "password",
        "twofa",
        "activity",
        "alerts",
        "preferences"
    ];


    if (validViews.includes(initialView)) {
        showView(initialView);
    }


    /*
     * SEARCH
     */

    const searchableRows =
        Array.from(
            document.querySelectorAll(
                ".settings-row"
            )
        );


    searchInput.addEventListener(
        "input",
        () => {

            const query =
                searchInput.value
                    .trim()
                    .toLowerCase();


            searchResults.innerHTML = "";


            if (!query) {

                searchResults.classList.remove(
                    "visible"
                );

                return;

            }


            const matches =
                searchableRows.filter(row => {

                    const text =
                        (
                            row.innerText +
                            " " +
                            row.dataset.search
                        ).toLowerCase();

                    return text.includes(query);

                });


            if (!matches.length) {

                searchResults.innerHTML = `
                    <div class="search-result">
                        <div>
                            <strong>No settings found</strong>
                            <small>Try another search term.</small>
                        </div>
                    </div>
                `;

                searchResults.classList.add(
                    "visible"
                );

                return;

            }


            matches.forEach(row => {

                const clone =
                    document.createElement("button");

                clone.className =
                    "search-result";

                const content =
                    row.querySelector(
                        ".row-content"
                    );

                clone.innerHTML = `
                    <span class="row-icon">
                        ${row.querySelector(".row-icon")?.textContent || "•"}
                    </span>

                    <span>
                        <strong>
                            ${content?.querySelector("strong")?.textContent || ""}
                        </strong>

                        <small>
                            ${content?.querySelector("small")?.textContent || ""}
                        </small>
                    </span>
                `;


                clone.addEventListener(
                    "click",
                    () => {

                        showView(
                            row.dataset.openView
                        );

                    }
                );


                searchResults.appendChild(
                    clone
                );

            });


            searchResults.classList.add(
                "visible"
            );

        }
    );


    document.addEventListener(
        "click",
        event => {

            if (
                !event.target.closest(
                    ".settings-search-wrapper"
                )
            ) {

                searchResults.classList.remove(
                    "visible"
                );

            }

        }
    );


    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "/" &&
                document.activeElement !== searchInput
            ) {

                event.preventDefault();

                searchInput.focus();

            }

            if (
                event.key === "Escape" &&
                currentView !== "home"
            ) {

                showView("home");

            }

        }
    );


    /*
     * BUTTON LOADING
     */

    function setLoading(button, loading) {

        if (!button) return;


        if (loading) {

            button.dataset.originalText =
                button.textContent;

            button.textContent =
                "Please wait...";

            button.disabled = true;

        } else {

            button.disabled = false;

            button.textContent =
                button.dataset.originalText ||
                button.textContent;

        }

    }


    /*
     * MESSAGE
     */

    function message(element, text, type) {

        if (!element) return;

        element.textContent = text;

        element.className =
            `inline-message ${type}`;

    }


    /*
     * PROFILE UPDATE
     */

    const profileForm =
        document.getElementById(
            "profile-update-form"
        );


    if (profileForm) {

        profileForm.addEventListener(
            "submit",
            async event => {

                event.preventDefault();


                const username =
                    document
                        .getElementById(
                            "profile-username"
                        )
                        .value
                        .trim();


                const email =
                    document
                        .getElementById(
                            "profile-email"
                        )
                        .value
                        .trim();


                const output =
                    document.getElementById(
                        "profile-message"
                    );


                const button =
                    document.getElementById(
                        "profile-save"
                    );


                if (!username || !email) {

                    message(
                        output,
                        "Username and email are required.",
                        "error"
                    );

                    return;

                }


                setLoading(button, true);


                try {

                    const response =
                        await fetch(
                            "/profile/update",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body: JSON.stringify({
                                    username,
                                    email
                                })
                            }
                        );


                    const data =
                        await response.json();


                    if (!response.ok) {

                        throw new Error(
                            data.error ||
                            "Unable to update profile."
                        );

                    }


                    message(
                        output,
                        data.message ||
                        "Profile updated successfully.",
                        "success"
                    );


                } catch (error) {

                    message(
                        output,
                        error.message,
                        "error"
                    );

                } finally {

                    setLoading(
                        button,
                        false
                    );

                }

            }
        );

    }


    /*
     * PASSWORD SHOW / HIDE
     */

    document
        .querySelectorAll(
            ".password-toggle"
        )
        .forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    const input =
                        document.getElementById(
                            button.dataset.target
                        );


                    if (!input) return;


                    if (
                        input.type ===
                        "password"
                    ) {

                        input.type = "text";

                        button.textContent =
                            "Hide";

                    } else {

                        input.type =
                            "password";

                        button.textContent =
                            "Show";

                    }

                }
            );

        });


    /*
     * PASSWORD STRENGTH
     */

    const newPassword =
        document.getElementById(
            "new-password"
        );

    const meter =
        document.getElementById(
            "password-meter"
        );

    const strength =
        document.getElementById(
            "password-strength"
        );


    function passwordScore(value) {

        let score = 0;


        if (value.length >= 8)
            score += 20;

        if (value.length >= 12)
            score += 15;

        if (/[a-z]/.test(value))
            score += 15;

        if (/[A-Z]/.test(value))
            score += 15;

        if (/[0-9]/.test(value))
            score += 15;

        if (/[^A-Za-z0-9]/.test(value))
            score += 20;


        return Math.min(
            score,
            100
        );

    }


    if (newPassword) {

        newPassword.addEventListener(
            "input",
            () => {

                const score =
                    passwordScore(
                        newPassword.value
                    );


                meter.style.width =
                    `${score}%`;


                meter.className =
                    "meter-fill";


                if (score < 40) {

                    meter.classList.add(
                        "weak"
                    );

                    strength.textContent =
                        "Weak";

                } else if (score < 65) {

                    meter.classList.add(
                        "fair"
                    );

                    strength.textContent =
                        "Fair";

                } else if (score < 85) {

                    meter.classList.add(
                        "good"
                    );

                    strength.textContent =
                        "Good";

                } else {

                    meter.classList.add(
                        "strong"
                    );

                    strength.textContent =
                        "Strong";

                }

            }
        );

    }


    /*
     * PASSWORD CHANGE
     */

    const passwordForm =
        document.getElementById(
            "password-form"
        );


    if (passwordForm) {

        passwordForm.addEventListener(
            "submit",
            async event => {

                event.preventDefault();


                const currentPassword =
                    document.getElementById(
                        "current-password"
                    ).value;


                const newPasswordValue =
                    document.getElementById(
                        "new-password"
                    ).value;


                const confirmPassword =
                    document.getElementById(
                        "confirm-password"
                    ).value;


                const output =
                    document.getElementById(
                        "password-message"
                    );


                const button =
                    document.getElementById(
                        "password-save"
                    );


                if (
                    !currentPassword ||
                    !newPasswordValue ||
                    !confirmPassword
                ) {

                    message(
                        output,
                        "Complete all password fields.",
                        "error"
                    );

                    return;

                }


                if (
                    newPasswordValue.length < 8
                ) {

                    message(
                        output,
                        "New password must contain at least 8 characters.",
                        "error"
                    );

                    return;

                }


                if (
                    newPasswordValue !==
                    confirmPassword
                ) {

                    message(
                        output,
                        "New passwords do not match.",
                        "error"
                    );

                    return;

                }


                if (
                    currentPassword ===
                    newPasswordValue
                ) {

                    message(
                        output,
                        "New password must be different from your current password.",
                        "error"
                    );

                    return;

                }


                setLoading(
                    button,
                    true
                );


                try {

                    const response =
                        await fetch(
                            "/settings/password",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body: JSON.stringify({

                                    current_password:
                                        currentPassword,

                                    new_password:
                                        newPasswordValue,

                                    confirm_password:
                                        confirmPassword

                                })
                            }
                        );


                    const data =
                        await response.json();


                    if (!response.ok) {

                        throw new Error(
                            data.error ||
                            "Unable to change password."
                        );

                    }


                    passwordForm.reset();

                    meter.style.width =
                        "0%";

                    strength.textContent =
                        "Enter a password";


                    message(
                        output,
                        data.message ||
                        "Password changed successfully.",
                        "success"
                    );


                } catch (error) {

                    message(
                        output,
                        error.message,
                        "error"
                    );

                } finally {

                    setLoading(
                        button,
                        false
                    );

                }

            }
        );

    }


    /*
     * 2FA STATUS
     */

    async function loadTwoFactorStatus() {

        const homeStatus =
            document.getElementById(
                "home-twofa-status"
            );

        const badge =
            document.getElementById(
                "twofa-detail-badge"
            );

        const title =
            document.getElementById(
                "twofa-detail-title"
            );

        const description =
            document.getElementById(
                "twofa-detail-description"
            );

        const action =
            document.getElementById(
                "twofa-action"
            );


        try {

            const response =
                await fetch(
                    "/2fa/status"
                );


            const data =
                await response.json();


            if (!response.ok) {
                throw new Error();
            }


            const twofa =
                data.two_factor || {};


            if (twofa.enabled) {

                if (homeStatus) {
                    homeStatus.textContent =
                        "Enabled";

                    homeStatus.className =
                        "row-value status-safe";
                }


                if (badge) {

                    badge.textContent =
                        "Protected";

                    badge.classList.add(
                        "enabled"
                    );

                }


                if (title) {

                    title.textContent =
                        "Two-factor authentication is enabled";

                }


                if (description) {

                    description.textContent =
                        "Your account has an additional authentication layer enabled.";

                }


                if (action) {

                    action.textContent =
                        "Disable 2FA";

                    action.dataset.enabled =
                        "true";

                }

            } else {

                if (homeStatus) {

                    homeStatus.textContent =
                        "Not enabled";

                    homeStatus.className =
                        "row-value";

                }


                if (badge) {

                    badge.textContent =
                        "Not enabled";

                    badge.classList.remove(
                        "enabled"
                    );

                }


                if (title) {

                    title.textContent =
                        "Protect your account with 2FA";

                }


                if (description) {

                    description.textContent =
                        "Use an additional verification factor when signing in.";

                }


                if (action) {

                    action.textContent =
                        "Set up 2FA";

                    action.dataset.enabled =
                        "false";

                }

            }

        } catch {

            if (homeStatus) {

                homeStatus.textContent =
                    "Unavailable";

            }

            if (title) {

                title.textContent =
                    "Unable to check 2FA status";

            }

        }

    }


    const twofaAction =
        document.getElementById(
            "twofa-action"
        );


    if (twofaAction) {

        twofaAction.addEventListener(
            "click",
            async () => {

                if (
                    twofaAction.dataset.enabled !==
                    "true"
                ) {

                    window.location.href =
                        "/2fa";

                    return;

                }


                const confirmed =
                    window.confirm(
                        "Disable two-factor authentication?"
                    );


                if (!confirmed) return;


                setLoading(
                    twofaAction,
                    true
                );


                try {

                    const response =
                        await fetch(
                            "/2fa/disable",
                            {
                                method: "POST"
                            }
                        );


                    const data =
                        await response.json();


                    if (!response.ok) {

                        throw new Error(
                            data.error ||
                            "Unable to disable 2FA."
                        );

                    }


                    await loadTwoFactorStatus();

                } catch (error) {

                    alert(
                        error.message
                    );

                } finally {

                    setLoading(
                        twofaAction,
                        false
                    );

                }

            }
        );

    }


    /*
     * SECURITY SCORE
     */

    async function loadSecurityScore() {

        const score =
            document.getElementById(
                "security-score"
            );

        const status =
            document.getElementById(
                "security-score-status"
            );


        if (!score || !status) return;


        try {

            const response =
                await fetch(
                    "/dashboard/data"
                );


            const data =
                await response.json();


            const value =
                data?.security_score ??
                data?.security?.score ??
                data?.security_score?.score;


            if (
                typeof value ===
                "number"
            ) {

                score.textContent =
                    Math.round(value);

                status.textContent =
                    value >= 80
                        ? "Good protection"
                        : value >= 60
                            ? "Needs improvement"
                            : "Action recommended";

            } else {

                score.textContent =
                    "—";

                status.textContent =
                    "Security data unavailable";

            }

        } catch {

            score.textContent =
                "—";

            status.textContent =
                "Unable to load score";

        }

    }


    /*
     * ACTIVITY
     */

    document
        .getElementById(
            "activity-open"
        )
        ?.addEventListener(
            "click",
            () => {

                window.location.href =
                    "/activity";

            }
        );


    /*
     * ALERTS
     */

    document
        .getElementById(
            "alerts-open"
        )
        ?.addEventListener(
            "click",
            () => {

                window.location.href =
                    "/alerts";

            }
        );


    /*
     * INITIAL DATA
     */

    loadTwoFactorStatus();

});