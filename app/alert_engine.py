from datetime import datetime, timedelta
from app.models import db, SecurityAlert


SEVERITY_WEIGHT = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def create_security_alert(
    user_id,
    alert_type,
    severity,
    description
):
    existing_alert = SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.alert_type == alert_type,
        SecurityAlert.status == "OPEN"
    ).first()

    if existing_alert:
        current_weight = SEVERITY_WEIGHT.get(
            existing_alert.severity,
            1
        )

        new_weight = SEVERITY_WEIGHT.get(
            severity,
            1
        )

        if new_weight > current_weight:
            existing_alert.severity = severity

        if description:
            existing_alert.description = description

        db.session.commit()
        return existing_alert

    alert = SecurityAlert(
        user_id=user_id,
        alert_type=alert_type,
        severity=severity,
        description=description,
        status="OPEN"
    )

    db.session.add(alert)
    db.session.commit()

    return alert


def determine_severity(risk_score):
    if risk_score >= 85:
        return "CRITICAL"

    if risk_score >= 65:
        return "HIGH"

    if risk_score >= 35:
        return "MEDIUM"

    return "LOW"


def build_alert_description(risk_result):
    reasons = risk_result.get("reasons", [])

    if not reasons:
        return "Suspicious security activity detected"

    return " | ".join(
        dict.fromkeys(reasons)
    )


def create_risk_alert(user_id, risk_result):
    risk_score = float(
        risk_result.get("risk_score", 0)
    )

    risk_level = risk_result.get(
        "risk_level",
        "LOW"
    )

    severity = determine_severity(
        risk_score
    )

    if severity == "LOW":
        return None

    description = build_alert_description(
        risk_result
    )

    return create_security_alert(
        user_id=user_id,
        alert_type="SUSPICIOUS_LOGIN",
        severity=severity,
        description=description
    )


def create_bruteforce_alert(
    user_id,
    failed_attempts,
    time_window_minutes=15
):
    if failed_attempts < 3:
        return None

    if failed_attempts >= 10:
        severity = "CRITICAL"
    elif failed_attempts >= 6:
        severity = "HIGH"
    else:
        severity = "MEDIUM"

    description = (
        f"{failed_attempts} failed login attempts "
        f"detected within the last "
        f"{time_window_minutes} minutes"
    )

    return create_security_alert(
        user_id=user_id,
        alert_type="BRUTE_FORCE",
        severity=severity,
        description=description
    )


def create_new_device_alert(
    user_id,
    device_info
):
    description = (
        f"Login detected from a new device: "
        f"{device_info or 'Unknown device'}"
    )

    return create_security_alert(
        user_id=user_id,
        alert_type="NEW_DEVICE",
        severity="MEDIUM",
        description=description
    )


def create_new_ip_alert(
    user_id,
    ip_address
):
    description = (
        f"Login detected from an unfamiliar "
        f"IP address: {ip_address or 'Unknown'}"
    )

    return create_security_alert(
        user_id=user_id,
        alert_type="NEW_IP",
        severity="MEDIUM",
        description=description
    )


def resolve_alert(alert):
    if not alert:
        return None

    alert.status = "RESOLVED"
    alert.resolved_at = datetime.utcnow()

    db.session.commit()

    return alert


def get_open_alerts(user_id):
    return SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.status == "OPEN"
    ).order_by(
        SecurityAlert.created_at.desc()
    ).all()


def get_recent_alerts(
    user_id,
    hours=24
):
    since = datetime.utcnow() - timedelta(
        hours=hours
    )

    return SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.created_at >= since
    ).order_by(
        SecurityAlert.created_at.desc()
    ).all()


def get_alert_summary(user_id):
    alerts = get_open_alerts(user_id)

    summary = {
        "total": len(alerts),
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0
    }

    for alert in alerts:
        severity = alert.severity.lower()

        if severity in summary:
            summary[severity] += 1

    return summary