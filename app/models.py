from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(
        db.Enum("USER", "ANALYST", "ADMIN"),
        default="USER"
    )

    two_factor_enabled = db.Column(
        db.Boolean,
        default=False
    )

    is_active = db.Column(
        db.Boolean,
        default=True
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp()
    )


class SecurityScore(db.Model):
    __tablename__ = "security_scores"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    password_score = db.Column(
        db.Numeric(5, 2),
        default=0.00,
        nullable=False
    )

    login_security_score = db.Column(
        db.Numeric(5, 2),
        default=0.00,
        nullable=False
    )

    overall_score = db.Column(
        db.Numeric(5, 2),
        default=0.00,
        nullable=False
    )

    risk_level = db.Column(
        db.String(20),
        default="LOW",
        nullable=False
    )

    calculated_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        nullable=False
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "security_scores",
            lazy=True,
            cascade="all, delete-orphan"
        )
    )


class LoginEvent(db.Model):
    __tablename__ = "login_events"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    event_type = db.Column(
        db.String(50),
        nullable=False
    )

    ip_address = db.Column(
        db.String(45)
    )

    user_agent = db.Column(
        db.Text
    )

    device_info = db.Column(
        db.String(255)
    )

    success = db.Column(
        db.Boolean,
        default=False
    )

    risk_score = db.Column(
        db.Numeric(5, 2),
        default=0.00
    )

    event_time = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        nullable=False,
        index=True
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "login_events",
            lazy=True
        )
    )


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    alert_type = db.Column(
        db.String(100),
        nullable=False,
        index=True
    )

    severity = db.Column(
        db.Enum(
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ),
        default="LOW",
        nullable=False,
        index=True
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    status = db.Column(
        db.Enum(
            "OPEN",
            "RESOLVED"
        ),
        default="OPEN",
        nullable=False,
        index=True
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        nullable=False,
        index=True
    )

    resolved_at = db.Column(
        db.DateTime,
        nullable=True
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "security_alerts",
            lazy="dynamic",
            cascade="all, delete-orphan"
        )
    )

    @property
    def is_open(self):
        return self.status == "OPEN"

    @property
    def is_critical(self):
        return self.severity == "CRITICAL"

    @property
    def age_seconds(self):
        created = self.created_at or datetime.utcnow()

        return max(
            0,
            int(
                (
                    datetime.utcnow() - created
                ).total_seconds()
            )
        )

    def resolve(self):
        self.status = "RESOLVED"
        self.resolved_at = datetime.utcnow()

    def reopen(self):
        self.status = "OPEN"
        self.resolved_at = None

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "description": self.description,
            "status": self.status,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "resolved_at": (
                self.resolved_at.isoformat()
                if self.resolved_at
                else None
            ),
            "is_open": self.is_open,
            "is_critical": self.is_critical
        }


class MLRiskPrediction(db.Model):
    __tablename__ = "ml_risk_predictions"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        index=True
    )

    risk_score = db.Column(
        db.Numeric(5, 2),
        nullable=False
    )

    risk_level = db.Column(
        db.Enum(
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL"
        ),
        nullable=False
    )

    prediction_reason = db.Column(
        db.Text,
        nullable=True
    )

    model_name = db.Column(
        db.String(100),
        nullable=False
    )

    predicted_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        nullable=False,
        index=True
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "ml_risk_predictions",
            lazy=True,
            cascade="all, delete-orphan"
        )
    )


class TwoFactorAuth(db.Model):
    __tablename__ = "two_factor_auth"

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE"
        ),
        nullable=False,
        unique=True,
        index=True
    )

    method = db.Column(
        db.String(30),
        nullable=False,
        default="TOTP"
    )

    secret_key = db.Column(
        db.String(255),
        nullable=True
    )

    is_enabled = db.Column(
        db.Boolean,
        nullable=False,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    updated_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp()
    )

    user = db.relationship(
        "User",
        backref=db.backref(
            "two_factor_auth",
            uselist=False
        )
    )