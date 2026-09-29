(() => {
    "use strict";

    const form = document.getElementById("pw-analyze-form");
    const input = document.getElementById("pw-analyze-input");
    const submitButton = document.getElementById("pw-analyze-submit");
    const errorBox = document.getElementById("pw-analyze-error");

    const emptyState = document.getElementById("pw-analyze-empty");
    const resultsCard = document.getElementById("pw-analyze-results");

    const scoreValue = document.getElementById("pw-score-value");
    const scoreBadge = document.getElementById("pw-score-badge");
    const strengthValue = document.getElementById("pw-strength-value");

    const metricGrid = document.getElementById("pw-metric-grid");
    const checksList = document.getElementById("pw-checks-list");

    const warningsWrap = document.getElementById("pw-warnings-wrap");
    const warningsList = document.getElementById("pw-warnings-list");

    const generator = document.getElementById("pw-generator");
    const generatedPasswords = document.getElementById("generated-passwords");
    const generateMoreButton = document.getElementById("generate-more-btn");
    const generatorMessage = document.getElementById("generator-message");

    const eyeButton = document.getElementById("password-eye-btn");
    const eyeOpen = document.getElementById("eye-open");
    const eyeClosed = document.getElementById("eye-closed");

    let currentPasswordStyle = null;

    function escapeHTML(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function showError(message) {
        if (!errorBox) return;

        errorBox.textContent = message;
        errorBox.style.display = "block";
    }

    function hideError() {
        if (!errorBox) return;

        errorBox.textContent = "";
        errorBox.style.display = "none";
    }

    function setLoading(loading) {
        if (!submitButton) return;

        submitButton.disabled = loading;

        const label = submitButton.querySelector(".btn-label");
        const spinner = submitButton.querySelector(".spinner");

        if (label) {
            label.textContent = loading
                ? "Analyzing..."
                : "Analyze password";
        }

        if (spinner) {
            spinner.style.display = loading
                ? "inline-block"
                : "none";
        }
    }

    function formatNumber(value, decimals = 1) {
        const number = Number(value);

        if (!Number.isFinite(number)) {
            return "—";
        }

        return number.toFixed(decimals);
    }

    function formatCheckName(name) {
        return String(name)
            .replaceAll("_", " ")
            .replace(/\b\w/g, letter => letter.toUpperCase());
    }

    function getRiskClass(risk) {
        const value = String(risk || "").toUpperCase();

        if (value === "LOW") return "risk-low";
        if (value === "MEDIUM") return "risk-medium";
        if (value === "HIGH") return "risk-high";
        if (value === "CRITICAL") return "risk-critical";

        return "risk-medium";
    }

    function renderScore(data) {
        if (scoreValue) {
            const score = Math.max(
                0,
                Math.min(100, Number(data.score) || 0)
            );

            scoreValue.textContent = Math.round(score);
        }

        if (scoreBadge) {
            const risk = data.risk_level || "UNKNOWN";

            scoreBadge.textContent = risk;
            scoreBadge.className =
                `risk-badge ${getRiskClass(risk)}`;
        }

        if (strengthValue) {
            strengthValue.textContent =
                data.strength || "Unknown";
        }
    }

    function renderMetrics(data) {
        if (!metricGrid) return;

        const metrics = [
            {
                label: "Entropy",
                value: `${formatNumber(data.entropy, 1)} bits`
            },
            {
                label: "Length",
                value: `${data.length ?? "—"} characters`
            },
            {
                label: "Character space",
                value: data.character_space ?? "—"
            },
            {
                label: "Unique ratio",
                value: `${formatNumber(
                    Number(data.unique_ratio) * 100,
                    1
                )}%`
            },
            {
                label: "Dictionary risk",
                value: data.dictionary_risk ?? "—"
            }
        ];

        metricGrid.innerHTML = metrics.map(metric => `
            <div class="security-metric">
                <span class="security-metric-label">
                    ${escapeHTML(metric.label)}
                </span>

                <strong class="security-metric-value">
                    ${escapeHTML(metric.value)}
                </strong>
            </div>
        `).join("");
    }

    function renderChecks(checks) {
        if (!checksList) return;

        if (!checks || typeof checks !== "object") {
            checksList.innerHTML = `
                <div class="security-check">
                    <span class="security-check-name">
                        No security checks available
                    </span>

                    <span class="security-check-status">
                        —
                    </span>
                </div>
            `;

            return;
        }

        const entries = Object.entries(checks);

        if (!entries.length) {
            checksList.innerHTML = `
                <div class="security-check">
                    <span class="security-check-name">
                        No security checks available
                    </span>

                    <span class="security-check-status">
                        —
                    </span>
                </div>
            `;

            return;
        }

        checksList.innerHTML = entries.map(([name, value]) => {
            const passed =
                value === true ||
                value === "true" ||
                value === 1;

            return `
                <div class="security-check">

                    <span class="security-check-name">
                        ${escapeHTML(formatCheckName(name))}
                    </span>

                    <span class="security-check-status ${passed ? "pass" : "fail"}">
                        ${passed ? "Passed" : "Needs attention"}
                    </span>

                </div>
            `;
        }).join("");
    }

    function renderWarnings(warnings) {
        if (!warningsWrap || !warningsList) return;

        if (!Array.isArray(warnings) || warnings.length === 0) {
            warningsWrap.style.display = "none";
            warningsList.innerHTML = "";
            return;
        }

        warningsWrap.style.display = "block";

        warningsList.innerHTML = warnings.map(warning => `
            <div class="security-warning">
                ${escapeHTML(warning)}
            </div>
        `).join("");
    }

    function renderAnalysis(data) {
        if (!data) return;

        if (emptyState) {
            emptyState.style.display = "none";
        }

        if (resultsCard) {
            resultsCard.style.display = "block";
        }

        renderScore(data);
        renderMetrics(data);
        renderChecks(data.checks);
        renderWarnings(data.warnings);

        if (generator) {
            generator.style.display = "block";
        }
    }

    function detectPasswordStyle(password) {
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasNumbers = /[0-9]/.test(password);
        const hasSymbols = /[^A-Za-z0-9]/.test(password);

        return {
            length: Math.max(
                12,
                Math.min(24, password.length)
            ),
            hasLower,
            hasUpper,
            hasNumbers,
            hasSymbols
        };
    }

    function secureRandom(max) {
        if (
            window.crypto &&
            window.crypto.getRandomValues
        ) {
            const array = new Uint32Array(1);

            window.crypto.getRandomValues(array);

            return array[0] % max;
        }

        return Math.floor(Math.random() * max);
    }

    function randomChar(characters) {
        return characters[
            secureRandom(characters.length)
        ];
    }

    function shuffle(array) {
        const result = [...array];

        for (let i = result.length - 1; i > 0; i--) {
            const j = secureRandom(i + 1);

            [
                result[i],
                result[j]
            ] = [
                result[j],
                result[i]
            ];
        }

        return result;
    }

    function generateSmartPassword(style) {
        const lower =
            "abcdefghijklmnopqrstuvwxyz";

        const upper =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        const numbers =
            "0123456789";

        const symbols =
            "!@#$%^&*_-+=?";

        const pool =
            `${lower}${upper}${numbers}${symbols}`;

        const targetLength = Math.max(
            16,
            Math.min(
                24,
                style.length + 4
            )
        );

        const characters = [];

        if (style.hasLower) {
            characters.push(
                randomChar(lower)
            );
        }

        if (style.hasUpper) {
            characters.push(
                randomChar(upper)
            );
        }

        if (style.hasNumbers) {
            characters.push(
                randomChar(numbers)
            );
        }

        if (style.hasSymbols) {
            characters.push(
                randomChar(symbols)
            );
        }

        if (!style.hasLower) {
            characters.push(
                randomChar(lower)
            );
        }

        if (!style.hasUpper) {
            characters.push(
                randomChar(upper)
            );
        }

        if (!style.hasNumbers) {
            characters.push(
                randomChar(numbers)
            );
        }

        if (!style.hasSymbols) {
            characters.push(
                randomChar(symbols)
            );
        }

        while (characters.length < targetLength) {
            characters.push(
                randomChar(pool)
            );
        }

        return shuffle(characters).join("");
    }

    function calculateLocalStrength(password) {
        let score = 0;

        if (password.length >= 12) score += 25;
        if (password.length >= 16) score += 15;
        if (/[a-z]/.test(password)) score += 15;
        if (/[A-Z]/.test(password)) score += 15;
        if (/[0-9]/.test(password)) score += 15;
        if (/[^A-Za-z0-9]/.test(password)) score += 15;

        return Math.min(100, score);
    }

    function generatePasswordCards() {
        if (!generatedPasswords || !currentPasswordStyle) {
            return;
        }

        generatedPasswords.innerHTML = "";

        const passwords = new Set();

        while (passwords.size < 4) {
            passwords.add(
                generateSmartPassword(
                    currentPasswordStyle
                )
            );
        }

        passwords.forEach(password => {
            const score =
                calculateLocalStrength(password);

            const row =
                document.createElement("div");

            row.className =
                "generated-password-row";

            const value =
                document.createElement("div");

            value.className =
                "generated-password-value";

            value.textContent = password;

            const scoreElement =
                document.createElement("div");

            scoreElement.className =
                "generated-password-score";

            scoreElement.textContent =
                `${score}/100`;

            const copyButton =
                document.createElement("button");

            copyButton.type = "button";

            copyButton.className =
                "copy-password-button";

            copyButton.textContent = "Copy";

            copyButton.dataset.password =
                password;

            copyButton.addEventListener(
                "click",
                async () => {
                    const copied =
                        await copyToClipboard(
                            password
                        );

                    if (copied) {
                        copyButton.textContent =
                            "Copied";

                        setTimeout(() => {
                            copyButton.textContent =
                                "Copy";
                        }, 1500);
                    } else {
                        copyButton.textContent =
                            "Copy failed";

                        setTimeout(() => {
                            copyButton.textContent =
                                "Copy";
                        }, 1500);
                    }
                }
            );

            row.appendChild(value);
            row.appendChild(scoreElement);
            row.appendChild(copyButton);

            generatedPasswords.appendChild(row);
        });

        if (generatorMessage) {
            generatorMessage.textContent =
                "Suggestions are generated locally in your browser and are not sent to an external service.";
        }
    }

    async function copyToClipboard(password) {
        try {
            if (
                navigator.clipboard &&
                window.isSecureContext
            ) {
                await navigator.clipboard.writeText(
                    password
                );

                return true;
            }
        } catch (error) {
        }

        try {
            const textarea =
                document.createElement("textarea");

            textarea.value = password;

            textarea.style.position = "fixed";
            textarea.style.left = "-9999px";

            document.body.appendChild(
                textarea
            );

            textarea.focus();
            textarea.select();

            const copied =
                document.execCommand("copy");

            textarea.remove();

            return copied;
        } catch (error) {
            return false;
        }
    }

    async function analyzePassword(password) {
        const response = await fetch(
            "/password-security",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",

                    "Accept":
                        "application/json"
                },

                credentials: "same-origin",

                body: JSON.stringify({
                    password: password
                })
            }
        );

        let result;

        try {
            result = await response.json();
        } catch (error) {
            throw new Error(
                "The server returned an invalid response."
            );
        }

        if (!response.ok) {
            throw new Error(
                result?.error ||
                "Password analysis failed."
            );
        }

        if (
            !result ||
            result.success !== true
        ) {
            throw new Error(
                result?.error ||
                "Unable to analyze password."
            );
        }

        if (
            !result.security ||
            !result.security.password
        ) {
            throw new Error(
                "Security analysis data was not returned."
            );
        }

        return result.security.password;
    }

    if (form && input) {
        form.addEventListener(
            "submit",
            async event => {
                event.preventDefault();

                hideError();

                const password =
                    input.value;

                if (!password) {
                    showError(
                        "Please enter a password to analyze."
                    );

                    input.focus();

                    return;
                }

                setLoading(true);

                try {
                    const analysis =
                        await analyzePassword(
                            password
                        );

                    renderAnalysis(
                        analysis
                    );

                    currentPasswordStyle =
                        detectPasswordStyle(
                            password
                        );

                    generatePasswordCards();

                } catch (error) {
                    console.error(
                        "Password analysis error:",
                        error
                    );

                    showError(
                        error.message ||
                        "Unable to analyze password."
                    );

                } finally {
                    setLoading(false);
                }
            }
        );
    }

    if (generateMoreButton) {
        generateMoreButton.addEventListener(
            "click",
            () => {
                generateMoreButton.disabled =
                    true;

                generateMoreButton.textContent =
                    "Generating...";

                setTimeout(() => {
                    generatePasswordCards();

                    generateMoreButton.disabled =
                        false;

                    generateMoreButton.textContent =
                        "Generate new suggestions";
                }, 200);
            }
        );
    }

    if (
        eyeButton &&
        input &&
        eyeOpen &&
        eyeClosed
    ) {
        eyeButton.addEventListener(
            "click",
            () => {
                const showing =
                    input.type === "text";

                if (showing) {
                    input.type = "password";

                    eyeOpen.style.display =
                        "block";

                    eyeClosed.style.display =
                        "none";

                    eyeButton.setAttribute(
                        "aria-label",
                        "Show password"
                    );

                    eyeButton.setAttribute(
                        "title",
                        "Show password"
                    );

                } else {
                    input.type = "text";

                    eyeOpen.style.display =
                        "none";

                    eyeClosed.style.display =
                        "block";

                    eyeButton.setAttribute(
                        "aria-label",
                        "Hide password"
                    );

                    eyeButton.setAttribute(
                        "title",
                        "Hide password"
                    );
                }
            }
        );
    }
})();