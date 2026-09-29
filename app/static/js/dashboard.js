document.addEventListener("DOMContentLoaded", () => {
    initializeDashboardApplication();
});

const DashboardState = {
    score: null,
    summary: null,
    profile: null,
    loading: false,
    lastUpdated: null
};

async function initializeDashboardApplication() {
    try {
        await Promise.all([
            renderUserDashboard(),
            renderActivityPage(),
            renderProfilePage(),
            renderAnalystDashboard(),
            renderAdminDashboard()
        ]);
    } catch (error) {
        console.error("Dashboard initialization error:", error);
    }
}

function clamp(value, min = 0, max = 100) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return min;
    }

    return Math.max(min, Math.min(max, number));
}

function safeText(value, fallback = "—") {
    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {
        return fallback;
    }

    return String(value);
}

function escapeHtml(value) {
    if (window.Security && typeof Security.escapeHtml === "function") {
        return Security.escapeHtml(safeText(value, ""));
    }

    return safeText(value, "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function titleCase(value) {
    if (!value) {
        return "—";
    }

    return String(value)
        .toLowerCase()
        .replaceAll("_", " ")
        .replace(/\b\w/g, char => char.toUpperCase());
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return safeText(value);
    }

    return date.toLocaleString();
}

function relativeTime(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return "—";
    }

    const seconds =
        Math.floor(
            (Date.now() - date.getTime()) / 1000
        );

    if (seconds < 60) {
        return "Just now";
    }

    const minutes =
        Math.floor(seconds / 60);

    if (minutes < 60) {
        return `${minutes} min ago`;
    }

    const hours =
        Math.floor(minutes / 60);

    if (hours < 24) {
        return `${hours} hr ago`;
    }

    const days =
        Math.floor(hours / 24);

    if (days < 30) {
        return `${days} day${days === 1 ? "" : "s"} ago`;
    }

    return formatDate(value);
}

function riskClass(level) {
    const normalized =
        String(level || "")
            .toLowerCase()
            .replaceAll("_", "-");

    if (
        normalized === "low" ||
        normalized === "secure"
    ) {
        return "risk-low";
    }

    if (
        normalized === "medium" ||
        normalized === "monitor"
    ) {
        return "risk-medium";
    }

    if (
        normalized === "high" ||
        normalized === "at-risk"
    ) {
        return "risk-high";
    }

    if (
        normalized === "critical" ||
        normalized === "critical-risk"
    ) {
        return "risk-critical";
    }

    return "risk-neutral";
}

function riskBadge(level) {
    const text =
        titleCase(level || "Unknown");

    return `
        <span class="badge ${riskClass(level)}">
            ${escapeHtml(text)}
        </span>
    `;
}

function getApiError(result, fallback) {
    if (
        window.Security &&
        typeof Security.friendlyErrorMessage === "function"
    ) {
        return Security.friendlyErrorMessage(
            result,
            fallback
        );
    }

    return fallback;
}

function setText(id, value, fallback = "—") {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        value === undefined ||
        value === null ||
        value === ""
            ? fallback
            : value;
}

function setDisplay(id, visible) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.style.display =
        visible ? "" : "none";
}

function setProgress(id, value) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.style.width =
        `${clamp(value)}%`;
}

function paintScoreGauge(
    svgElement,
    score,
    radius = 80
) {
    if (!svgElement) {
        return;
    }

    const circumference =
        2 * Math.PI * radius;

    const normalized =
        clamp(score);

    const offset =
        circumference -
        (normalized / 100) *
        circumference;

    svgElement.style.strokeDasharray =
        circumference;

    svgElement.style.strokeDashoffset =
        offset;

    if (normalized >= 80) {
        svgElement.style.stroke =
            "var(--risk-low, #16834b)";
    } else if (normalized >= 60) {
        svgElement.style.stroke =
            "var(--accent, #2563eb)";
    } else if (normalized >= 40) {
        svgElement.style.stroke =
            "var(--risk-medium, #936b00)";
    } else {
        svgElement.style.stroke =
            "var(--risk-critical, #b42318)";
    }
}

function calculateOpenAlerts(alerts) {
    if (!Array.isArray(alerts)) {
        return 0;
    }

    return alerts.filter(
        alert =>
            String(
                alert.status || "OPEN"
            ).toUpperCase() === "OPEN"
    ).length;
}

function getLatestPrediction(predictions) {
    if (
        !Array.isArray(predictions) ||
        predictions.length === 0
    ) {
        return null;
    }

    return [...predictions].sort(
        (a, b) => {
            const first =
                new Date(
                    a.predicted_at || 0
                ).getTime();

            const second =
                new Date(
                    b.predicted_at || 0
                ).getTime();

            return second - first;
        }
    )[0];
}

function calculateMlConfidence(prediction) {
    if (!prediction) {
        return null;
    }

    if (
        prediction.confidence !== undefined
    ) {
        const value =
            Number(prediction.confidence);

        if (value <= 1) {
            return Math.round(value * 100);
        }

        return Math.round(value);
    }

    return null;
}

function renderMlCard(
    prediction,
    container
) {
    if (!container) {
        return;
    }

    if (!prediction) {
        container.innerHTML = `
            <div class="not-implemented">
                <strong>ML risk assessment</strong>
                <p>
                    No machine-learning prediction
                    is available yet.
                </p>
            </div>
        `;

        return;
    }

    const score =
        clamp(prediction.risk_score);

    const level =
        prediction.risk_level ||
        "UNKNOWN";

    const confidence =
        calculateMlConfidence(
            prediction
        );

    const reason =
        prediction.prediction_reason ||
        "No prediction reason was recorded.";

    container.innerHTML = `
        <div class="ml-card-head">
            <div>
                <h3>ML risk assessment</h3>
                <p class="muted">
                    RandomForest Security Risk Model
                </p>
            </div>

            ${riskBadge(level)}
        </div>

        <div class="ml-score-panel">

            <div class="ml-main-score">
                <strong>
                    ${Math.round(score)}
                </strong>

                <span>
                    / 100 risk score
                </span>
            </div>

            <div class="ml-confidence">

                <div class="ml-confidence-head">
                    <span>Model confidence</span>

                    <strong>
                        ${
                            confidence !== null
                                ? confidence + "%"
                                : "N/A"
                        }
                    </strong>
                </div>

                <div class="ml-confidence-bar">
                    <span
                        style="
                            width:
                            ${
                                confidence !== null
                                    ? clamp(confidence)
                                    : 0
                            }%
                        "
                    ></span>
                </div>

            </div>

        </div>

        <div class="ml-analysis">

            <div>
                <span>Risk level</span>
                <strong>
                    ${escapeHtml(
                        titleCase(level)
                    )}
                </strong>
            </div>

            <div>
                <span>Model</span>
                <strong>
                    RandomForest
                </strong>
            </div>

            <div>
                <span>Prediction time</span>
                <strong>
                    ${escapeHtml(
                        formatDate(
                            prediction.predicted_at
                        )
                    )}
                </strong>
            </div>

        </div>

        <div class="ml-reason">
            <span>Prediction information</span>
            <p>
                ${escapeHtml(reason)}
            </p>
        </div>

        <div class="ml-disclaimer">
            This prediction is a statistical
            security assessment and should be
            considered together with rule-based
            security checks.
        </div>
    `;
}

async function renderUserDashboard() {
    const root =
        document.getElementById(
            "dashboard-root"
        );

    if (!root) {
        return;
    }

    const skeleton =
        document.getElementById(
            "dashboard-skeleton"
        );

    const errorBox =
        document.getElementById(
            "dashboard-error"
        );

    try {
        const [
            scoreResult,
            summaryResult,
            profileResult
        ] = await Promise.all([
            Security.apiRequest(
                "/security-score"
            ),
            Security.apiRequest(
                "/security/summary"
            ),
            Security.apiRequest(
                "/profile"
            )
        ]);

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (
            !scoreResult.ok &&
            !summaryResult.ok
        ) {
            if (errorBox) {
                errorBox.style.display = "block";
                errorBox.textContent =
                    getApiError(
                        scoreResult,
                        "Unable to load your security dashboard."
                    );
            }

            return;
        }

        const scoreResponse =
            scoreResult.data || {};

        const summary =
            summaryResult.data || {};

        const security =
            summary.security_score ||
            scoreResponse.security ||
            {};

        const alerts =
            Array.isArray(
                summary.recent_alerts
            )
                ? summary.recent_alerts
                : [];

        const logins =
            Array.isArray(
                summary.recent_logins
            )
                ? summary.recent_logins
                : [];

        const predictions =
            Array.isArray(
                summary.ml_predictions
            )
                ? summary.ml_predictions
                : [];

        DashboardState.score =
            security;

        DashboardState.summary =
            summary;

        DashboardState.profile =
            profileResult.data || {};

        DashboardState.lastUpdated =
            new Date();

        const overall =
            security.overall_score;

        const passwordScore =
            security.password_score;

        const loginScore =
            security.login_security_score;

        const riskLevel =
            security.risk_level ||
            "UNKNOWN";

        const latestPrediction =
            getLatestPrediction(
                predictions
            );

        setText(
            "score-gauge-number",
            overall !== undefined &&
            overall !== null
                ? Math.round(overall)
                : "—"
        );

        const gaugeValue =
            document.getElementById(
                "score-gauge-value"
            );

        paintScoreGauge(
            gaugeValue,
            overall
        );

        setText(
            "password-score",
            passwordScore !== undefined
                ? Math.round(passwordScore)
                : "—"
        );

        setText(
            "login-score",
            loginScore !== undefined
                ? Math.round(loginScore)
                : "—"
        );

        setProgress(
            "password-progress",
            passwordScore
        );

        setProgress(
            "login-progress",
            loginScore
        );

        const scoreStatus =
            document.getElementById(
                "score-status"
            );

        if (scoreStatus) {
            scoreStatus.textContent =
                titleCase(riskLevel);
        }

        const riskCallout =
            document.getElementById(
                "risk-callout"
            );

        if (riskCallout) {
            riskCallout.className =
                `risk-callout ${riskClass(
                    riskLevel
                )}`;

            riskCallout.innerHTML = `
                <div class="risk-callout-icon">
                    ${riskIcon()}
                </div>

                <div class="risk-callout-body">

                    <h4>
                        Security status:
                        ${escapeHtml(
                            titleCase(
                                riskLevel
                            )
                        )}
                    </h4>

                    <p>
                        Your current security
                        assessment is based on
                        password security, login
                        activity, alerts and
                        account protection.
                    </p>

                </div>
            `;
        }

        renderScoreBreakdown(
            security
        );

        renderMlCard(
            latestPrediction,
            document.getElementById(
                "ml-card"
            )
        );

        renderDashboardAlerts(
            alerts
        );

        renderDashboardLogins(
            logins
        );

        setText(
            "last-assessed",
            security.calculated_at
                ? formatDate(
                    security.calculated_at
                )
                : "—"
        );

        setText(
            "last-login",
            logins.length
                ? formatDate(
                    logins[0].event_time
                )
                : "—"
        );

        setText(
            "alert-count",
            calculateOpenAlerts(
                alerts
            )
        );

        setText(
            "ml-risk-score",
            latestPrediction
                ? Math.round(
                    latestPrediction.risk_score
                )
                : "—"
        );

        setText(
            "ml-risk-level",
            latestPrediction
                ? titleCase(
                    latestPrediction.risk_level
                )
                : "—"
        );

        const twoFactor =
            DashboardState.profile
                ?.two_factor_enabled;

        setText(
            "two-factor-status",
            twoFactor
                ? "Enabled"
                : "Not enabled"
        );

        if (errorBox) {
            errorBox.style.display = "none";
        }

    } catch (error) {

        console.error(
            "User dashboard error:",
            error
        );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (errorBox) {
            errorBox.style.display = "block";
            errorBox.textContent =
                "Something went wrong while loading the security dashboard.";
        }
    }
}

function renderScoreBreakdown(
    security
) {
    const breakdown =
        document.getElementById(
            "score-breakdown"
        );

    if (!breakdown) {
        return;
    }

    const rows = [
        {
            label: "Password security",
            value: security.password_score
        },
        {
            label: "Login security",
            value: security.login_security_score
        },
        {
            label: "Overall protection",
            value: security.overall_score
        }
    ];

    const available =
        rows.filter(
            row =>
                row.value !== undefined &&
                row.value !== null
        );

    if (!available.length) {
        breakdown.innerHTML = `
            <p class="muted">
                Security breakdown is not available yet.
            </p>
        `;

        return;
    }

    breakdown.innerHTML =
        available.map(
            row => {

                const value =
                    clamp(row.value);

                return `
                    <div class="score-row">

                        <div class="score-row-top">
                            <span>
                                ${escapeHtml(
                                    row.label
                                )}
                            </span>

                            <strong>
                                ${Math.round(
                                    value
                                )}
                            </strong>
                        </div>

                        <div class="score-row-bar">
                            <span
                                style="
                                    width:
                                    ${value}%
                                "
                            ></span>
                        </div>

                    </div>
                `;
            }
        ).join("");
}

function renderDashboardAlerts(
    alerts
) {
    const container =
        document.getElementById(
            "alerts-list"
        );

    if (!container) {
        return;
    }

    if (
        !Array.isArray(alerts) ||
        alerts.length === 0
    ) {
        container.innerHTML = `
            <div class="empty-state">
                <strong>No recent security alerts</strong>
                <p>
                    Your account has no recent
                    security alerts.
                </p>
            </div>
        `;

        return;
    }

    container.innerHTML =
        alerts.slice(0, 6)
            .map(
                alert => {

                    const severity =
                        alert.severity ||
                        "LOW";

                    const status =
                        alert.status ||
                        "OPEN";

                    return `
                        <div class="alert-item">

                            <div class="alert-severity-rail
                                ${riskClass(
                                    severity
                                )}">
                            </div>

                            <div class="alert-body">

                                <div class="alert-head">

                                    <strong>
                                        ${escapeHtml(
                                            titleCase(
                                                alert.alert_type ||
                                                "Security Alert"
                                            )
                                        )}
                                    </strong>

                                    ${riskBadge(
                                        severity
                                    )}

                                </div>

                                <p class="alert-desc">
                                    ${escapeHtml(
                                        alert.description ||
                                        "Security event detected."
                                    )}
                                </p>

                                <div class="alert-meta">

                                    <span>
                                        ${escapeHtml(
                                            titleCase(
                                                status
                                            )
                                        )}
                                    </span>

                                    <span>
                                        ${escapeHtml(
                                            formatDate(
                                                alert.created_at
                                            )
                                        )}
                                    </span>

                                </div>

                            </div>

                        </div>
                    `;
                }
            )
            .join("");
}

function renderDashboardLogins(
    logins
) {
    const tbody =
        document.getElementById(
            "activity-tbody"
        );

    if (!tbody) {
        return;
    }

    if (
        !Array.isArray(logins) ||
        logins.length === 0
    ) {
        tbody.innerHTML = `
            <tr>
                <td
                    colspan="6"
                    class="empty-state"
                >
                    No login activity recorded.
                </td>
            </tr>
        `;

        return;
    }

    tbody.innerHTML =
        logins.slice(0, 10)
            .map(
                event => {

                    const success =
                        Boolean(
                            event.success
                        );

                    const risk =
                        Number(
                            event.risk_score || 0
                        );

                    let level = "LOW";

                    if (risk >= 80) {
                        level = "CRITICAL";
                    } else if (risk >= 60) {
                        level = "HIGH";
                    } else if (risk >= 30) {
                        level = "MEDIUM";
                    }

                    return `
                        <tr>

                            <td>
                                <span
                                    class="
                                        status-dot
                                        ${
                                            success
                                                ? "ok"
                                                : "fail"
                                        }
                                    "
                                ></span>

                                ${
                                    success
                                        ? "Success"
                                        : "Failed"
                                }
                            </td>

                            <td>
                                ${escapeHtml(
                                    event.event_type ||
                                    "LOGIN"
                                )}
                            </td>

                            <td class="mono">
                                ${escapeHtml(
                                    event.ip_address ||
                                    "Unknown"
                                )}
                            </td>

                            <td>
                                ${escapeHtml(
                                    event.device_info ||
                                    "Unknown"
                                )}
                            </td>

                            <td>
                                ${riskBadge(level)}
                                <span class="mono text-xs">
                                    ${Math.round(
                                        risk
                                    )}
                                </span>
                            </td>

                            <td>
                                ${escapeHtml(
                                    formatDate(
                                        event.event_time
                                    )
                                )}
                            </td>

                        </tr>
                    `;
                }
            )
            .join("");
}

function riskIcon() {
    return `
        <svg
            width="22"
            height="22"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="1.8"
        >
            <path
                d="M12 3 4 6v5c0 5
                3.4 8.7 8 10
                4.6-1.3 8-5
                8-10V6l-8-3Z"
            />

            <path
                d="M12 8v4"
            />

            <path
                d="M12 16h.01"
            />
        </svg>
    `;
}

async function renderActivityPage() {
    const tbody =
        document.getElementById(
            "activity-tbody"
        );

    if (!tbody) {
        return;
    }

    const skeleton =
        document.getElementById(
            "activity-skeleton"
        );

    const empty =
        document.getElementById(
            "activity-empty"
        );

    const errorBox =
        document.getElementById(
            "activity-error"
        );

    const table =
        document.getElementById(
            "activity-table"
        );

    try {

        const result =
            await Security.apiRequest(
                "/security/summary"
            );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (!result.ok) {

            if (errorBox) {
                errorBox.style.display = "block";
                errorBox.textContent =
                    getApiError(
                        result,
                        "Unable to load login activity."
                    );
            }

            return;
        }

        const data =
            result.data || {};

        const events =
            Array.isArray(
                data.recent_logins
            )
                ? data.recent_logins
                : [];

        if (!events.length) {

            if (empty) {
                empty.style.display = "flex";
            }

            if (table) {
                table.style.display = "none";
            }

            return;
        }

        if (table) {
            table.style.display = "block";
        }

        tbody.innerHTML =
            events.map(
                event => {

                    const success =
                        Boolean(
                            event.success
                        );

                    return `
                        <tr>

                            <td data-label="Time">
                                ${escapeHtml(
                                    formatDate(
                                        event.event_time
                                    )
                                )}
                            </td>

                            <td data-label="Result">

                                <span
                                    class="
                                        status-dot
                                        ${
                                            success
                                                ? "ok"
                                                : "fail"
                                        }
                                    "
                                ></span>

                                ${
                                    success
                                        ? "Success"
                                        : "Failed"
                                }

                            </td>

                            <td
                                data-label="IP address"
                                class="mono"
                            >
                                ${escapeHtml(
                                    event.ip_address ||
                                    "—"
                                )}
                            </td>

                            <td data-label="Device">
                                ${escapeHtml(
                                    event.device_info ||
                                    "—"
                                )}
                            </td>

                            <td data-label="Risk">

                                ${riskBadge(
                                    calculateRiskLevel(
                                        event.risk_score
                                    )
                                )}

                                <span class="mono text-xs">
                                    ${
                                        event.risk_score ??
                                        ""
                                    }
                                </span>

                            </td>

                        </tr>
                    `;
                }
            ).join("");

    } catch (error) {

        console.error(
            "Activity page error:",
            error
        );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (errorBox) {
            errorBox.style.display = "block";
            errorBox.textContent =
                "Unable to load login activity.";
        }
    }
}

function calculateRiskLevel(
    score
) {
    const value =
        Number(score || 0);

    if (value >= 80) {
        return "CRITICAL";
    }

    if (value >= 60) {
        return "HIGH";
    }

    if (value >= 30) {
        return "MEDIUM";
    }

    return "LOW";
}

async function renderProfilePage() {
    const root =
        document.getElementById(
            "profile-root"
        );

    if (!root) {
        return;
    }

    const skeleton =
        document.getElementById(
            "profile-skeleton"
        );

    const errorBox =
        document.getElementById(
            "profile-error"
        );

    try {

        const [
            profileResult,
            summaryResult
        ] = await Promise.all([
            Security.apiRequest(
                "/profile"
            ),
            Security.apiRequest(
                "/security/summary"
            )
        ]);

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (!profileResult.ok) {

            if (errorBox) {
                errorBox.style.display = "block";
                errorBox.textContent =
                    getApiError(
                        profileResult,
                        "Unable to load your profile."
                    );
            }

            return;
        }

        const profile =
            profileResult.data || {};

        const summary =
            summaryResult.data || {};

        DashboardState.profile =
            profile;

        setText(
            "profile-username",
            profile.username
        );

        setText(
            "profile-email",
            profile.email
        );

        setText(
            "profile-role",
            titleCase(profile.role)
        );

        setText(
            "profile-created",
            profile.created_at
                ? formatDate(
                    profile.created_at
                )
                : "—"
        );

        const twoFaBadge =
            document.getElementById(
                "profile-2fa-badge"
            );

        const enabled =
            Boolean(
                profile.two_factor_enabled
            );

        if (twoFaBadge) {
            twoFaBadge.textContent =
                enabled
                    ? "Enabled"
                    : "Not enabled";

            twoFaBadge.className =
                `badge ${
                    enabled
                        ? "risk-low"
                        : "risk-medium"
                }`;
        }

        const setup =
            document.getElementById(
                "twofa-setup"
            );

        const already =
            document.getElementById(
                "twofa-already-enabled"
            );

        if (enabled) {

            if (setup) {
                setup.style.display = "none";
            }

            if (already) {
                already.style.display = "block";
            }
        }

        const recommendations =
            summary.recommendations;

        const recommendationList =
            document.getElementById(
                "recommendation-list"
            );

        if (recommendationList) {

            if (
                Array.isArray(
                    recommendations
                ) &&
                recommendations.length
            ) {

                recommendationList.innerHTML =
                    recommendations.map(
                        item => {

                            const text =
                                typeof item === "string"
                                    ? item
                                    : (
                                        item.message ||
                                        item.description ||
                                        "Security recommendation"
                                    );

                            return `
                                <li>
                                    <span>
                                        ${escapeHtml(
                                            text
                                        )}
                                    </span>
                                </li>
                            `;
                        }
                    ).join("");

            } else {

                recommendationList.innerHTML = `
                    <li class="muted">
                        No recommendations are
                        currently available.
                    </li>
                `;
            }
        }

    } catch (error) {

        console.error(
            "Profile page error:",
            error
        );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (errorBox) {
            errorBox.style.display = "block";
            errorBox.textContent =
                "Unable to load profile information.";
        }
    }
}

async function renderAnalystDashboard() {
    const root =
        document.getElementById(
            "analyst-root"
        );

    if (!root) {
        return;
    }

    const skeleton =
        document.getElementById(
            "analyst-skeleton"
        );

    const errorBox =
        document.getElementById(
            "analyst-error"
        );

    try {

        const result =
            await Security.apiRequest(
                "/security/summary"
            );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (!result.ok) {

            if (errorBox) {
                errorBox.style.display = "block";

                errorBox.textContent =
                    result.status === 403
                        ? "Analyst access is required."
                        : getApiError(
                            result,
                            "Unable to load analyst dashboard."
                        );
            }

            return;
        }

        const data =
            result.data || {};

        setText(
            "stat-total-users",
            data.total_users
        );

        setText(
            "stat-active-alerts",
            data.active_alerts ??
            data.open_alerts
        );

        setText(
            "stat-critical-alerts",
            data.critical_alerts
        );

        setText(
            "stat-high-risk-accounts",
            data.high_risk_accounts
        );

        const events =
            data.recent_events ||
            data.recent_suspicious_events ||
            [];

        const list =
            document.getElementById(
                "analyst-events-list"
            );

        if (list) {

            if (!events.length) {

                list.innerHTML = `
                    <div class="empty-state">
                        No suspicious activity
                        is currently available.
                    </div>
                `;

            } else {

                list.innerHTML =
                    events.map(
                        event => `
                            <div class="alert-item">

                                <div class="alert-body">

                                    <div class="alert-head">

                                        <strong>
                                            ${escapeHtml(
                                                event.alert_type ||
                                                event.type ||
                                                "Security event"
                                            )}
                                        </strong>

                                        ${riskBadge(
                                            event.severity
                                        )}

                                    </div>

                                    <p class="alert-desc">
                                        ${escapeHtml(
                                            event.description ||
                                            ""
                                        )}
                                    </p>

                                    <span class="alert-meta">
                                        ${escapeHtml(
                                            formatDate(
                                                event.created_at ||
                                                event.timestamp
                                            )
                                        )}
                                    </span>

                                </div>

                            </div>
                        `
                    ).join("");
            }
        }

    } catch (error) {

        console.error(
            "Analyst dashboard error:",
            error
        );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (errorBox) {
            errorBox.style.display = "block";
            errorBox.textContent =
                "Unable to load analyst dashboard.";
        }
    }
}

async function renderAdminDashboard() {
    const root =
        document.getElementById(
            "admin-root"
        );

    if (!root) {
        return;
    }

    const skeleton =
        document.getElementById(
            "admin-skeleton"
        );

    const errorBox =
        document.getElementById(
            "admin-error"
        );

    try {

        const result =
            await Security.apiRequest(
                "/security/summary"
            );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (!result.ok) {

            if (errorBox) {
                errorBox.style.display = "block";

                errorBox.textContent =
                    result.status === 403
                        ? "Administrator access is required."
                        : getApiError(
                            result,
                            "Unable to load administrator dashboard."
                        );
            }

            return;
        }

        const data =
            result.data || {};

        setText(
            "admin-total-users",
            data.total_users
        );

        setText(
            "admin-total-alerts",
            data.total_alerts
        );

        setText(
            "admin-open-alerts",
            data.open_alerts ??
            data.active_alerts
        );

        setText(
            "admin-critical-alerts",
            data.critical_alerts
        );

        setText(
            "admin-ml-predictions",
            data.ml_predictions_count
        );

        setText(
            "admin-avg-score",
            data.average_security_score
        );

        const notice =
            document.getElementById(
                "admin-missing-data-notice"
            );

        if (
            notice &&
            (
                data.total_users === undefined ||
                data.total_alerts === undefined
            )
        ) {
            notice.style.display = "block";
            notice.textContent =
                "Some system-wide statistics are not currently returned by the backend API.";
        }

    } catch (error) {

        console.error(
            "Admin dashboard error:",
            error
        );

        if (skeleton) {
            skeleton.style.display = "none";
        }

        if (errorBox) {
            errorBox.style.display = "block";
            errorBox.textContent =
                "Unable to load administrator dashboard.";
        }
    }
}

function setupDashboardRefresh() {
    const button =
        document.getElementById(
            "refresh-dashboard"
        );

    if (!button) {
        return;
    }

    button.addEventListener(
        "click",
        async () => {

            if (
                DashboardState.loading
            ) {
                return;
            }

            DashboardState.loading =
                true;

            button.disabled = true;

            const original =
                button.innerHTML;

            button.innerHTML =
                "Refreshing...";

            try {
                await renderUserDashboard();
            } finally {

                DashboardState.loading =
                    false;

                button.disabled =
                    false;

                button.innerHTML =
                    original;
            }
        }
    );
}

function setupAutoRefresh() {
    if (
        !document.getElementById(
            "dashboard-root"
        )
    ) {
        return;
    }

    setInterval(
        () => {
            if (
                !document.hidden &&
                !DashboardState.loading
            ) {
                renderUserDashboard();
            }
        },
        60000
    );
}

function setupDashboardInteractions() {
    setupDashboardRefresh();
    setupAutoRefresh();

    document.addEventListener(
        "visibilitychange",
        () => {

            if (
                !document.hidden &&
                document.getElementById(
                    "dashboard-root"
                )
            ) {
                renderUserDashboard();
            }
        }
    );
}

setupDashboardInteractions();