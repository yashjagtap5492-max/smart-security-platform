import math
import re
from datetime import datetime, timedelta

from app.models import (
    db,
    User,
    LoginEvent,
    SecurityAlert,
    SecurityScore
)


def calculate_password_score(password):
    if not password:
        return 0.0

    password = str(password)
    score = 0.0
    length = len(password)

    if length >= 8:
        score += 15
    if length >= 10:
        score += 10
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10

    if re.search(r"[a-z]", password):
        score += 10

    if re.search(r"[A-Z]", password):
        score += 10

    if re.search(r"\d", password):
        score += 10

    if re.search(r"[^A-Za-z0-9]", password):
        score += 15

    unique_ratio = len(set(password)) / length

    if unique_ratio >= 0.70:
        score += 5

    if unique_ratio >= 0.85:
        score += 5

    common_patterns = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "admin",
        "welcome",
        "letmein"
    ]

    lowered = password.lower()

    if any(pattern in lowered for pattern in common_patterns):
        score -= 30

    if re.search(r"(.)\1{2,}", password):
        score -= 10

    if re.search(r"(123|234|345|456|567|678|789)", password):
        score -= 10

    return round(max(0.0, min(score, 100.0)), 2)


def calculate_password_entropy(password):
    if not password:
        return 0.0

    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"\d", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0:
        return 0.0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)


def calculate_login_security_score(user_id):
    since = datetime.utcnow() - timedelta(hours=24)

    events = LoginEvent.query.filter(
        LoginEvent.user_id == user_id,
        LoginEvent.event_time >= since
    ).all()

    if not events:
        return 70.0

    total_events = len(events)

    failed_events = [
        event for event in events
        if not event.success
    ]

    high_risk_events = [
        event for event in events
        if float(event.risk_score or 0) >= 60
    ]

    critical_events = [
        event for event in events
        if float(event.risk_score or 0) >= 85
    ]

    score = 100.0

    failure_ratio = len(failed_events) / total_events

    score -= min(failure_ratio * 45, 45)

    score -= min(len(high_risk_events) * 8, 25)

    score -= min(len(critical_events) * 12, 25)

    unique_ips = {
        event.ip_address
        for event in events
        if event.ip_address
    }

    if len(unique_ips) >= 3:
        score -= 10

    if len(unique_ips) >= 5:
        score -= 10

    return round(max(score, 0.0), 2)


def calculate_alert_score(user_id):
    alerts = SecurityAlert.query.filter(
        SecurityAlert.user_id == user_id,
        SecurityAlert.status == "OPEN"
    ).all()

    penalty = 0

    severity_penalties = {
        "LOW": 5,
        "MEDIUM": 12,
        "HIGH": 25,
        "CRITICAL": 40
    }

    for alert in alerts:
        penalty += severity_penalties.get(
            alert.severity,
            5
        )

    return round(
        max(100.0 - min(penalty, 100), 0.0),
        2
    )


def calculate_two_factor_score(user):
    return 100.0 if user.two_factor_enabled else 35.0


def calculate_overall_score(
    password_score,
    login_security_score,
    alert_score,
    two_factor_score
):
    weights = {
        "password": 0.30,
        "login": 0.30,
        "alerts": 0.20,
        "two_factor": 0.20
    }

    score = (
        password_score * weights["password"] +
        login_security_score * weights["login"] +
        alert_score * weights["alerts"] +
        two_factor_score * weights["two_factor"]
    )

    return round(
        max(0.0, min(score, 100.0)),
        2
    )


def get_risk_level(score):
    if score >= 85:
        return "LOW"

    if score >= 65:
        return "MEDIUM"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


def get_score_status(score):
    if score >= 85:
        return "SECURE"

    if score >= 65:
        return "MONITOR"

    if score >= 40:
        return "AT_RISK"

    return "CRITICAL_RISK"


def calculate_user_security_score(
    user_id,
    password_score=0.0
):
    user = db.session.get(User, user_id)

    if not user:
        return None

    password_score = max(
        0.0,
        min(float(password_score), 100.0)
    )

    login_score = calculate_login_security_score(
        user_id
    )

    alert_score = calculate_alert_score(
        user_id
    )

    two_factor_score = calculate_two_factor_score(
        user
    )

    overall_score = calculate_overall_score(
        password_score,
        login_score,
        alert_score,
        two_factor_score
    )

    risk_level = get_risk_level(
        overall_score
    )

    status = get_score_status(
        overall_score
    )

    security_score = SecurityScore.query.filter_by(
        user_id=user_id
    ).order_by(
        SecurityScore.calculated_at.desc()
    ).first()

    if security_score:
        security_score.password_score = password_score
        security_score.login_security_score = login_score
        security_score.overall_score = overall_score
        security_score.risk_level = risk_level
    else:
        security_score = SecurityScore(
            user_id=user_id,
            password_score=password_score,
            login_security_score=login_score,
            overall_score=overall_score,
            risk_level=risk_level
        )

        db.session.add(security_score)

    db.session.commit()

    return {
        "user_id": user_id,
        "password_score": password_score,
        "login_security_score": login_score,
        "alert_score": alert_score,
        "two_factor_score": two_factor_score,
        "overall_score": overall_score,
        "risk_level": risk_level,
        "status": status
    }


def get_security_score(user_id):
    score = SecurityScore.query.filter_by(
        user_id=user_id
    ).order_by(
        SecurityScore.calculated_at.desc()
    ).first()

    if not score:
        return None

    return {
        "id": score.id,
        "user_id": score.user_id,
        "password_score": float(score.password_score),
        "login_security_score": float(
            score.login_security_score
        ),
        "overall_score": float(
            score.overall_score
        ),
        "risk_level": score.risk_level,
        "calculated_at": (
            score.calculated_at.isoformat()
            if score.calculated_at
            else None
        )
    }