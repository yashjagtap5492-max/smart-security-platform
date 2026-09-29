document.addEventListener("DOMContentLoaded", () => {
    initializeAlertsPage();
});

const AlertsState = {
    alerts: [],
    loading: false
};

async function initializeAlertsPage() {
    await loadAlerts();

    const refreshButton =
        document.getElementById("refresh-alerts");

    if (refreshButton) {
        refreshButton.addEventListener(
            "click",
            loadAlerts
        );
    }
}

async function loadAlerts() {
    if (AlertsState.loading) {
        return;
    }

    AlertsState.loading = true;

    showLoadingState();

    try {
        const result =
            await Security.apiRequest(
                "/security/summary"
            );

        if (!result.ok) {
            showError(
                Security.friendlyErrorMessage(
                    result,
                    "Unable to load security alerts."
                )
            );

            return;
        }

        const data =
            result.data || {};

        const alerts =
            Array.isArray(
                data.recent_alerts
            )
                ? data.recent_alerts
                : [];

        AlertsState.alerts = alerts;

        renderAlertSummary(alerts);
        renderAlerts(alerts);

    } catch (error) {
        console.error(
            "Alerts loading error:",
            error
        );

        showError(
            "Something went wrong while loading security alerts."
        );

    } finally {
        AlertsState.loading = false;
        hideLoadingState();
    }
}

function renderAlertSummary(alerts) {
    const total =
        alerts.length;

    const open =
        alerts.filter(
            alert =>
                String(
                    alert.status || "OPEN"
                ).toUpperCase() === "OPEN"
        ).length;

    const critical =
        alerts.filter(
            alert =>
                String(
                    alert.severity || ""
                ).toUpperCase() === "CRITICAL"
        ).length;

    setText(
        "total-alerts",
        total
    );

    setText(
        "open-alerts",
        open
    );

    setText(
        "critical-alerts",
        critical
    );
}

function renderAlerts(alerts) {
    const container =
        document.getElementById(
            "alerts-container"
        );

    const list =
        document.getElementById(
            "alerts-list"
        );

    const empty =
        document.getElementById(
            "alerts-empty"
        );

    if (!container || !list) {
        return;
    }

    if (!alerts.length) {
        container.style.display = "none";

        if (empty) {
            empty.style.display = "flex";
        }

        return;
    }

    if (empty) {
        empty.style.display = "none";
    }

    container.style.display = "";

    list.innerHTML =
        alerts
            .map(
                alert =>
                    createAlertCard(alert)
            )
            .join("");
}

function createAlertCard(alert) {
    const id =
        alert.id;

    const severity =
        String(
            alert.severity || "LOW"
        ).toUpperCase();

    const status =
        String(
            alert.status || "OPEN"
        ).toUpperCase();

    const alertType =
        alert.alert_type ||
        "Security Alert";

    const description =
        alert.description ||
        "A security event was detected.";

    const createdAt =
        alert.created_at;

    const isOpen =
        status === "OPEN";

    return `
        <article
            class="security-alert-card
            severity-${escapeHtml(
                severity.toLowerCase()
            )}"
            data-alert-id="${escapeHtml(id)}"
        >

            <div class="alert-card-header">

                <div class="alert-title-area">

                    <div
                        class="alert-severity-indicator
                        severity-${escapeHtml(
                            severity.toLowerCase()
                        )}"
                    ></div>

                    <div>

                        <h3>
                            ${escapeHtml(
                                formatAlertType(
                                    alertType
                                )
                            )}
                        </h3>

                        <p class="alert-time">
                            ${escapeHtml(
                                formatDate(
                                    createdAt
                                )
                            )}
                        </p>

                    </div>

                </div>


                <div class="alert-badges">

                    <span
                        class="alert-badge
                        severity-${escapeHtml(
                            severity.toLowerCase()
                        )}"
                    >
                        ${escapeHtml(
                            severity
                        )}
                    </span>

                    <span
                        class="alert-badge
                        status-${escapeHtml(
                            status.toLowerCase()
                        )}"
                    >
                        ${escapeHtml(
                            status
                        )}
                    </span>

                </div>

            </div>


            <div class="alert-card-body">

                <p>
                    ${escapeHtml(
                        description
                    )}
                </p>

            </div>


            <div class="alert-card-footer">

                <div class="alert-meta">

                    <span>
                        Alert ID:
                    </span>

                    <code>
                        #${escapeHtml(id)}
                    </code>

                </div>


                ${
                    isOpen
                        ? `
                            <button
                                type="button"
                                class="btn btn-secondary
                                resolve-alert-btn"
                                data-alert-id="${escapeHtml(
                                    id
                                )}"
                            >
                                Resolve Alert
                            </button>
                        `
                        : `
                            <span class="resolved-label">
                                Alert resolved
                            </span>
                        `
                }

            </div>

        </article>
    `;
}

document.addEventListener(
    "click",
    async event => {

        const button =
            event.target.closest(
                ".resolve-alert-btn"
            );

        if (!button) {
            return;
        }

        const alertId =
            button.dataset.alertId;

        if (!alertId) {
            return;
        }

        await resolveAlert(
            alertId,
            button
        );
    }
);

async function resolveAlert(
    alertId,
    button
) {
    if (
        button.disabled
    ) {
        return;
    }

    const originalText =
        button.textContent;

    button.disabled = true;

    button.textContent =
        "Resolving...";

    try {

        const result =
            await Security.apiRequest(
                `/security/alerts/${encodeURIComponent(
                    alertId
                )}/resolve`,
                {
                    method: "POST"
                }
            );

        if (!result.ok) {
            showError(
                Security.friendlyErrorMessage(
                    result,
                    "Unable to resolve this alert."
                )
            );

            return;
        }

        showSuccess(
            "Security alert resolved successfully."
        );

        await loadAlerts();

    } catch (error) {

        console.error(
            "Alert resolution error:",
            error
        );

        showError(
            "Unable to resolve the security alert."
        );

    } finally {

        button.disabled = false;

        button.textContent =
            originalText;
    }
}

function formatAlertType(type) {
    return String(type)
        .replaceAll("_", " ")
        .replace(/\b\w/g, char =>
            char.toUpperCase()
        );
}

function formatDate(value) {
    if (!value) {
        return "Unknown time";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString();
}

function escapeHtml(value) {
    if (
        window.Security &&
        typeof Security.escapeHtml === "function"
    ) {
        return Security.escapeHtml(
            String(value ?? "")
        );
    }

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function setText(
    id,
    value
) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        value ?? "0";
}

function showLoadingState() {
    const loading =
        document.getElementById(
            "alerts-loading"
        );

    const container =
        document.getElementById(
            "alerts-container"
        );

    const empty =
        document.getElementById(
            "alerts-empty"
        );

    if (loading) {
        loading.style.display = "flex";
    }

    if (container) {
        container.style.display = "none";
    }

    if (empty) {
        empty.style.display = "none";
    }
}

function hideLoadingState() {
    const loading =
        document.getElementById(
            "alerts-loading"
        );

    if (loading) {
        loading.style.display = "none";
    }
}

function showError(message) {
    const error =
        document.getElementById(
            "alerts-error"
        );

    if (!error) {
        return;
    }

    error.textContent =
        message;

    error.style.display =
        "block";
}

function showSuccess(message) {
    if (
        window.Security &&
        typeof Security.showToast === "function"
    ) {
        Security.showToast(
            message,
            "success"
        );

        return;
    }

    const region =
        document.getElementById(
            "toast-region"
        );

    if (!region) {
        return;
    }

    const toast =
        document.createElement(
            "div"
        );

    toast.className =
        "toast toast-success";

    toast.textContent =
        message;

    region.appendChild(toast);

    setTimeout(
        () => toast.remove(),
        3500
    );
}