from datetime import datetime

from flask import (
    Blueprint,
    request,
    jsonify,
    session,
    render_template
)

from app.models import (
    db,
    User,
    LoginEvent,
    SecurityAlert,
    MLRiskPrediction,
    SecurityScore,
    TwoFactorAuth
)

from app.security_engine import analyze_login_risk

from app.score_engine import calculate_user_security_score

from app.alert_engine import (
    create_risk_alert,
    create_security_alert,
    get_recent_alerts,
    get_alert_summary
)

from app.password_analyzer import analyze_password

from app.two_factor import (
    setup_two_factor,
    verify_totp
)

from ml.risk_model import predict_risk

import bcrypt


main = Blueprint("main", __name__)


def _current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    return db.session.get(User, user_id)


def calculate_ml_risk_score(ml_result):
    probabilities = ml_result.get(
        "probabilities",
        {}
    )

    weights = {
        "LOW": 10,
        "MEDIUM": 40,
        "HIGH": 70,
        "CRITICAL": 95
    }

    score = sum(
        float(probabilities.get(level, 0))
        * weight
        / 100
        for level, weight in weights.items()
    )

    return round(
        max(
            0.0,
            min(score, 100.0)
        ),
        2
    )


def get_ml_risk_prediction(
    user_id,
    current_risk_score
):
    events = LoginEvent.query.filter_by(
        user_id=user_id
    ).all()

    failed_attempts = sum(
        1
        for event in events
        if not event.success
    )

    unique_ips = len({
        event.ip_address
        for event in events
        if event.ip_address
    })

    unique_devices = len({
        event.device_info
        for event in events
        if event.device_info
    })

    high_risk_events = sum(
        1
        for event in events
        if float(event.risk_score or 0) >= 60
    )

    total_events = len(events)

    failure_ratio = (
        failed_attempts / total_events
        if total_events
        else 0.0
    )

    unusual_activity = int(
        current_risk_score >= 30
    )

    login_frequency = total_events

    user = db.session.get(
        User,
        user_id
    )

    account_age_days = 365

    if user and user.created_at:
        account_age_days = max(
            1,
            (
                datetime.utcnow()
                - user.created_at
            ).days
        )

    ml_result = predict_risk(
        failed_attempts=failed_attempts,
        unique_ips=max(
            1,
            unique_ips
        ),
        new_devices=max(
            0,
            unique_devices - 1
        ),
        high_risk_events=high_risk_events,
        unusual_activity=unusual_activity,
        login_frequency=login_frequency,
        failure_ratio=failure_ratio,
        account_age_days=account_age_days
    )

    ml_result["risk_score"] = (
        calculate_ml_risk_score(
            ml_result
        )
    )

    return ml_result


def save_ml_prediction(
    user_id,
    ml_result
):
    prediction = MLRiskPrediction(
        user_id=user_id,
        risk_score=ml_result["risk_score"],
        risk_level=ml_result["risk_level"],
        prediction_reason=str(
            ml_result["probabilities"]
        ),
        model_name=(
            "RandomForest Security Risk Model"
        )
    )

    db.session.add(prediction)
    db.session.commit()

    return prediction


def build_password_security_response(
    password_analysis
):
    return {
        "score": float(
            password_analysis.get(
                "score",
                0
            )
        ),
        "risk_level": password_analysis.get(
            "risk_level",
            "CRITICAL"
        ),
        "strength": password_analysis.get(
            "strength",
            "VERY_WEAK"
        ),
        "entropy": float(
            password_analysis.get(
                "entropy",
                0
            )
        ),
        "length": int(
            password_analysis.get(
                "length",
                0
            )
        ),
        "character_space": int(
            password_analysis.get(
                "character_space",
                0
            )
        ),
        "unique_ratio": float(
            password_analysis.get(
                "unique_ratio",
                0
            )
        ),
        "dictionary_risk": int(
            password_analysis.get(
                "dictionary_risk",
                0
            )
        ),
        "checks": password_analysis.get(
            "checks",
            {}
        ),
        "warnings": password_analysis.get(
            "warnings",
            []
        )
    }


def create_password_security_alert(
    user_id,
    password_score
):
    if password_score >= 85:
        return None

    if password_score >= 65:
        severity = "LOW"
    elif password_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "HIGH"

    description = (
        f"Password security score is "
        f"{password_score}/100"
    )

    return create_security_alert(
        user_id=user_id,
        alert_type="WEAK_PASSWORD",
        severity=severity,
        description=description
    )


@main.route(
    "/",
    methods=["GET"]
)
def index():
    return jsonify({
        "success": True,
        "message": (
            "Smart Security Platform API is running"
        )
    }), 200


@main.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "GET":
        return render_template(
            "register.html"
        )

    data = request.get_json(
        silent=True
    ) or {}

    username = data.get(
        "username",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    if (
        not username
        or not email
        or not password
    ):
        return jsonify({
            "success": False,
            "error": (
                "Username, email and password "
                "are required"
            )
        }), 400

    password_analysis = analyze_password(
        password
    )

    password_security = (
        build_password_security_response(
            password_analysis
        )
    )

    password_score = (
        password_security["score"]
    )

    if password_score < 40:
        return jsonify({
            "success": False,
            "error": (
                "Password does not meet "
                "the security requirements"
            ),
            "security": {
                "password": password_security
            }
        }), 400

    existing_user = User.query.filter(
        (User.email == email)
        |
        (User.username == username)
    ).first()

    if existing_user:
        return jsonify({
            "success": False,
            "error": (
                "Username or email already exists"
            )
        }), 409

    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        role="USER",
        two_factor_enabled=False,
        is_active=True
    )

    db.session.add(user)
    db.session.commit()

    calculate_user_security_score(
        user.id,
        password_score
    )

    create_password_security_alert(
        user.id,
        password_score
    )

    return jsonify({
        "success": True,
        "message": "Registration successful",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        },
        "security": {
            "password": password_security
        }
    }), 201


@main.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "GET":
        return render_template(
            "login.html"
        )

    data = request.get_json(
        silent=True
    ) or {}

    identifier = data.get(
        "identifier",
        data.get("email", "")
    )

    password = data.get(
        "password",
        ""
    )

    if (
        not isinstance(identifier, str)
        or not isinstance(password, str)
    ):
        return jsonify({
            "success": False,
            "error": (
                "Email and password are required"
            )
        }), 400

    identifier = identifier.strip()

    if not identifier or not password:
        return jsonify({
            "success": False,
            "error": (
                "Email and password are required"
            )
        }), 400

    user = User.query.filter(
        (User.email == identifier.lower())
        |
        (User.username == identifier)
    ).first()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Invalid email or password"
            )
        }), 401

    if not user.is_active:
        return jsonify({
            "success": False,
            "error": (
                "Account is currently inactive"
            )
        }), 403

    ip_address = request.remote_addr

    device_info = (
        request.user_agent.platform
        or "Unknown"
    )

    password_valid = bcrypt.checkpw(
        password.encode("utf-8"),
        user.password_hash.encode("utf-8")
    )

    risk_result = analyze_login_risk(
        user.id,
        ip_address,
        device_info
    )

    login_event = LoginEvent(
        user_id=user.id,
        event_type="LOGIN",
        ip_address=ip_address,
        user_agent=request.headers.get(
            "User-Agent"
        ),
        device_info=device_info,
        success=password_valid,
        risk_score=risk_result[
            "risk_score"
        ]
    )

    db.session.add(login_event)
    db.session.commit()

    ml_result = get_ml_risk_prediction(
        user.id,
        risk_result["risk_score"]
    )

    save_ml_prediction(
        user.id,
        ml_result
    )

    create_risk_alert(
        user.id,
        risk_result
    )

    if not password_valid:
        return jsonify({
            "success": False,
            "error": (
                "Invalid email or password"
            ),
            "security": {
                "rule_based_risk": {
                    "score": risk_result[
                        "risk_score"
                    ],
                    "level": risk_result[
                        "risk_level"
                    ],
                    "reasons": risk_result[
                        "reasons"
                    ]
                },
                "ml_risk": ml_result
            }
        }), 401

    two_factor = TwoFactorAuth.query.filter_by(
        user_id=user.id
    ).first()

    two_factor_required = (
        user.two_factor_enabled
        and two_factor
        and two_factor.is_enabled
        and bool(two_factor.secret_key)
    )

    if two_factor_required:

        session.clear()

        session["pending_2fa_user_id"] = user.id
        session["pending_2fa_username"] = (
            user.username
        )
        session["pending_2fa_role"] = (
            user.role
        )

        return jsonify({
            "success": True,
            "message": (
                "Two-factor authentication required"
            ),
            "requires_2fa": True,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            },
            "security": {
                "rule_based_risk": {
                    "score": risk_result[
                        "risk_score"
                    ],
                    "level": risk_result[
                        "risk_level"
                    ],
                    "reasons": risk_result[
                        "reasons"
                    ]
                },
                "ml_risk": ml_result
            }
        }), 200

    session.clear()

    session["user_id"] = user.id
    session["username"] = user.username
    session["role"] = user.role

    return jsonify({
        "success": True,
        "message": "Login successful",
        "requires_2fa": False,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        },
        "security": {
            "rule_based_risk": {
                "score": risk_result[
                    "risk_score"
                ],
                "level": risk_result[
                    "risk_level"
                ],
                "reasons": risk_result[
                    "reasons"
                ]
            },
            "ml_risk": ml_result
        }
    }), 200


@main.route(
    "/dashboard",
    methods=["GET"]
)
def dashboard():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    if user.role == "ADMIN":
        return render_template(
            "admin-dashboard.html",
            active_nav="admin",
            current_user=user
        )

    if user.role == "ANALYST":
        return render_template(
            "analyst-dashboard.html",
            active_nav="analyst",
            current_user=user
        )

    return render_template(
        "dashboard.html",
        active_nav="dashboard",
        current_user=user
    )


@main.route(
    "/alerts",
    methods=["GET"]
)
def alerts_page():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    return render_template(
        "alerts.html",
        active_nav="alerts",
        current_user=user
    )


@main.route(
    "/activity",
    methods=["GET"]
)
def activity_page():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    return render_template(
        "activity.html",
        active_nav="activity",
        current_user=user
    )


@main.route(
    "/password-security",
    methods=["GET"]
)
def password_security_page():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    return render_template(
        "password-security.html",
        active_nav="password",
        current_user=user
    )


@main.route(
    "/profile",
    methods=["GET"]
)
def profile():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    return render_template(
        "profile.html",
        active_nav="profile",
        current_user=user
    )


@main.route(
    "/settings",
    methods=["GET"]
)
def settings_page():

    user = _current_user()

    if not user:
        return render_template(
            "login.html"
        )

    return render_template(
        "profile.html",
        active_nav="profile",
        current_user=user
    )


@main.route(
    "/profile/update",
    methods=["POST"]
)
def update_profile():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    username = str(
        data.get(
            "username",
            ""
        )
    ).strip()

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip().lower()

    if not username or not email:
        return jsonify({
            "success": False,
            "error": (
                "Username and email are required"
            )
        }), 400

    username_exists = User.query.filter(
        User.username == username,
        User.id != user.id
    ).first()

    if username_exists:
        return jsonify({
            "success": False,
            "error": "Username already exists"
        }), 409

    email_exists = User.query.filter(
        User.email == email,
        User.id != user.id
    ).first()

    if email_exists:
        return jsonify({
            "success": False,
            "error": "Email already exists"
        }), 409

    user.username = username
    user.email = email

    session["username"] = username

    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Profile updated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "two_factor_enabled": (
                user.two_factor_enabled
            )
        }
    }), 200


@main.route(
    "/settings/password",
    methods=["POST"]
)
def change_password():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required"
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    current_password = data.get(
        "current_password",
        ""
    )

    new_password = data.get(
        "new_password",
        ""
    )

    confirm_password = data.get(
        "confirm_password",
        ""
    )

    if not current_password:
        return jsonify({
            "success": False,
            "error": "Current password is required"
        }), 400

    if not new_password:
        return jsonify({
            "success": False,
            "error": "New password is required"
        }), 400

    if new_password != confirm_password:
        return jsonify({
            "success": False,
            "error": "New passwords do not match"
        }), 400

    if current_password == new_password:
        return jsonify({
            "success": False,
            "error": (
                "New password must be different "
                "from the current password"
            )
        }), 400

    valid_current_password = bcrypt.checkpw(
        current_password.encode("utf-8"),
        user.password_hash.encode("utf-8")
    )

    if not valid_current_password:
        return jsonify({
            "success": False,
            "error": "Current password is incorrect"
        }), 401

    password_analysis = analyze_password(
        new_password
    )

    password_security = (
        build_password_security_response(
            password_analysis
        )
    )

    password_score = password_security["score"]

    if password_score < 40:
        return jsonify({
            "success": False,
            "error": (
                "New password is too weak"
            ),
            "security": {
                "password": password_security
            }
        }), 400

    user.password_hash = bcrypt.hashpw(
        new_password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    db.session.commit()

    calculate_user_security_score(
        user.id,
        password_score
    )

    create_password_security_alert(
        user.id,
        password_score
    )

    return jsonify({
        "success": True,
        "message": "Password changed successfully",
        "security": {
            "password": password_security
        }
    }), 200


@main.route(
    "/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "success": True,
        "message": "Logout successful"
    }), 200


@main.route(
    "/security/summary",
    methods=["GET"]
)
def security_summary():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Authentication required"
            )
        }), 401

    alerts = get_recent_alerts(
        user.id,
        hours=24
    )

    events = LoginEvent.query.filter_by(
        user_id=user.id
    ).order_by(
        LoginEvent.event_time.desc()
    ).limit(20).all()

    predictions = MLRiskPrediction.query.filter_by(
        user_id=user.id
    ).order_by(
        MLRiskPrediction.predicted_at.desc()
    ).limit(10).all()

    security_score = SecurityScore.query.filter_by(
        user_id=user.id
    ).order_by(
        SecurityScore.calculated_at.desc()
    ).first()

    return jsonify({
        "success": True,

        "summary": get_alert_summary(
            user.id
        ),

        "security_score": (
            {
                "overall_score": float(
                    security_score.overall_score
                ),
                "password_score": float(
                    security_score.password_score
                ),
                "login_security_score": float(
                    security_score.login_security_score
                ),
                "risk_level": (
                    security_score.risk_level
                ),
                "calculated_at": (
                    security_score.calculated_at.isoformat()
                    if security_score.calculated_at
                    else None
                )
            }
            if security_score
            else None
        ),

        "recent_alerts": [
            alert.to_dict()
            for alert in alerts
        ],

        "recent_logins": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "success": event.success,
                "risk_score": float(
                    event.risk_score or 0
                ),
                "ip_address": event.ip_address,
                "device_info": event.device_info,
                "event_time": (
                    event.event_time.isoformat()
                    if event.event_time
                    else None
                )
            }
            for event in events
        ],

        "ml_predictions": [
            {
                "id": prediction.id,
                "risk_score": float(
                    prediction.risk_score
                ),
                "risk_level": (
                    prediction.risk_level
                ),
                "prediction_reason": (
                    prediction.prediction_reason
                ),
                "model_name": (
                    prediction.model_name
                ),
                "predicted_at": (
                    prediction.predicted_at.isoformat()
                    if prediction.predicted_at
                    else None
                )
            }
            for prediction in predictions
        ]
    }), 200


@main.route(
    "/security/alerts/<int:alert_id>/resolve",
    methods=["POST"]
)
def resolve_security_alert(alert_id):

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Authentication required"
            )
        }), 401

    alert = SecurityAlert.query.filter_by(
        id=alert_id,
        user_id=user.id
    ).first()

    if not alert:
        return jsonify({
            "success": False,
            "error": (
                "Security alert not found"
            )
        }), 404

    alert.status = "RESOLVED"
    alert.resolved_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        "success": True,
        "message": (
            "Security alert resolved"
        ),
        "alert": alert.to_dict()
    }), 200


@main.route(
    "/security-score",
    methods=["GET"]
)
def security_score():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Authentication required"
            )
        }), 401

    existing_score = SecurityScore.query.filter_by(
        user_id=user.id
    ).order_by(
        SecurityScore.calculated_at.desc()
    ).first()

    password_score = (
        float(existing_score.password_score)
        if existing_score
        else 0.0
    )

    result = calculate_user_security_score(
        user.id,
        password_score
    )

    return jsonify({
        "success": True,
        "security": result
    }), 200


@main.route(
    "/password-security",
    methods=["POST"]
)
def password_security():

    data = request.get_json(
        silent=True
    ) or {}

    password = data.get(
        "password",
        ""
    )

    if not password:
        return jsonify({
            "success": False,
            "error": "Password is required"
        }), 400

    analysis = analyze_password(
        password
    )

    return jsonify({
        "success": True,
        "security": {
            "password": (
                build_password_security_response(
                    analysis
                )
            )
        }
    }), 200


@main.route(
    "/2fa/setup",
    methods=["POST"]
)
def setup_2fa():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required"
        }), 401

    existing_2fa = TwoFactorAuth.query.filter_by(
        user_id=user.id
    ).first()

    if (
        existing_2fa
        and existing_2fa.is_enabled
    ):
        return jsonify({
            "success": False,
            "error": "2FA is already enabled"
        }), 400

    setup = setup_two_factor(
        user.username
    )

    if existing_2fa:

        two_factor = existing_2fa

        two_factor.secret_key = (
            setup["secret"]
        )

        two_factor.method = "TOTP"

        two_factor.is_enabled = False

    else:

        two_factor = TwoFactorAuth(
            user_id=user.id,
            method="TOTP",
            secret_key=setup["secret"],
            is_enabled=False
        )

        db.session.add(
            two_factor
        )

    db.session.commit()

    return jsonify({
        "success": True,
        "message": (
            "2FA setup generated"
        ),
        "two_factor": {
            "method": "TOTP",
            "qr_code": setup["qr_code"],
            "provisioning_uri": (
                setup["provisioning_uri"]
            )
        }
    }), 200


@main.route(
    "/2fa/verify",
    methods=["POST"]
)
def verify_2fa():

    pending_user_id = session.get(
        "pending_2fa_user_id"
    )

    if pending_user_id:

        user = db.session.get(
            User,
            pending_user_id
        )

    else:

        user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Authentication required"
            )
        }), 401

    data = request.get_json(
        silent=True
    ) or {}

    verification_code = str(
        data.get(
            "code",
            ""
        )
    ).strip()

    verification_code = (
        verification_code
        .replace(" ", "")
        .replace("-", "")
    )

    if not verification_code:
        return jsonify({
            "success": False,
            "error": (
                "Verification code is required"
            )
        }), 400

    if (
        len(verification_code) != 6
        or not verification_code.isdigit()
    ):
        return jsonify({
            "success": False,
            "error": (
                "Verification code must "
                "contain 6 digits"
            )
        }), 400

    two_factor = TwoFactorAuth.query.filter_by(
        user_id=user.id
    ).first()

    if not two_factor:
        return jsonify({
            "success": False,
            "error": (
                "2FA setup has not been started"
            )
        }), 404

    if not two_factor.secret_key:
        return jsonify({
            "success": False,
            "error": (
                "2FA configuration is incomplete"
            )
        }), 400

    valid_code = verify_totp(
        two_factor.secret_key,
        verification_code
    )

    if not valid_code:
        return jsonify({
            "success": False,
            "error": (
                "Invalid or expired "
                "verification code"
            )
        }), 401

    if pending_user_id:

        session.clear()

        session["user_id"] = user.id
        session["username"] = user.username
        session["role"] = user.role

        return jsonify({
            "success": True,
            "message": (
                "Two-factor authentication "
                "successful"
            ),
            "requires_2fa": False,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }), 200

    if two_factor.is_enabled:
        return jsonify({
            "success": False,
            "error": (
                "2FA is already enabled"
            )
        }), 400

    two_factor.is_enabled = True
    user.two_factor_enabled = True

    db.session.commit()

    return jsonify({
        "success": True,
        "message": (
            "Two-factor authentication "
            "enabled successfully"
        ),
        "two_factor": {
            "enabled": True,
            "method": two_factor.method,
            "type": "TOTP"
        }
    }), 200


@main.route(
    "/2fa/status",
    methods=["GET"]
)
def two_factor_status():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required"
        }), 401

    two_factor = TwoFactorAuth.query.filter_by(
        user_id=user.id
    ).first()

    return jsonify({
        "success": True,
        "two_factor": {
            "enabled": bool(
                user.two_factor_enabled
            ),
            "configured": bool(
                two_factor
                and two_factor.secret_key
            ),
            "method": (
                two_factor.method
                if two_factor
                else None
            )
        }
    }), 200


@main.route(
    "/2fa/disable",
    methods=["POST"]
)
def disable_2fa():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": "Authentication required"
        }), 401

    two_factor = TwoFactorAuth.query.filter_by(
        user_id=user.id
    ).first()

    if not two_factor:
        return jsonify({
            "success": False,
            "error": "2FA is not configured"
        }), 404

    two_factor.is_enabled = False
    user.two_factor_enabled = False

    db.session.commit()

    return jsonify({
        "success": True,
        "message": (
            "Two-factor authentication disabled"
        )
    }), 200


@main.route(
    "/dashboard/data",
    methods=["GET"]
)
def dashboard_data():

    user = _current_user()

    if not user:
        return jsonify({
            "success": False,
            "error": (
                "Authentication required"
            )
        }), 401

    alerts = get_recent_alerts(
        user.id,
        hours=24
    )

    events = LoginEvent.query.filter_by(
        user_id=user.id
    ).order_by(
        LoginEvent.event_time.desc()
    ).limit(20).all()

    score = SecurityScore.query.filter_by(
        user_id=user.id
    ).order_by(
        SecurityScore.calculated_at.desc()
    ).first()

    predictions = MLRiskPrediction.query.filter_by(
        user_id=user.id
    ).order_by(
        MLRiskPrediction.predicted_at.desc()
    ).limit(10).all()

    return jsonify({
        "success": True,

        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "two_factor_enabled": (
                user.two_factor_enabled
            )
        },

        "security": {
            "overall_score": (
                float(score.overall_score)
                if score
                else 0
            ),
            "password_score": (
                float(score.password_score)
                if score
                else 0
            ),
            "login_security_score": (
                float(
                    score.login_security_score
                )
                if score
                else 0
            ),
            "risk_level": (
                score.risk_level
                if score
                else "CRITICAL"
            )
        },

        "alerts": {
            "summary": get_alert_summary(
                user.id
            ),
            "recent": [
                alert.to_dict()
                for alert in alerts
            ]
        },

        "login_activity": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "success": event.success,
                "risk_score": float(
                    event.risk_score or 0
                ),
                "ip_address": event.ip_address,
                "device_info": event.device_info,
                "event_time": (
                    event.event_time.isoformat()
                    if event.event_time
                    else None
                )
            }
            for event in events
        ],

        "ml": [
            {
                "id": prediction.id,
                "risk_score": float(
                    prediction.risk_score
                ),
                "risk_level": (
                    prediction.risk_level
                ),
                "model_name": (
                    prediction.model_name
                ),
                "prediction_reason": (
                    prediction.prediction_reason
                ),
                "predicted_at": (
                    prediction.predicted_at.isoformat()
                    if prediction.predicted_at
                    else None
                )
            }
            for prediction in predictions
        ]
    }), 200