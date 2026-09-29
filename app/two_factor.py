import base64
import hashlib
import io
import secrets
import time
from typing import Optional

import pyotp
import qrcode

ISSUER_NAME = "Smart Security Platform"
OTP_DIGITS = 6
OTP_INTERVAL = 30
BACKUP_CODE_COUNT = 10


def generate_secret() -> str:
    return pyotp.random_base32()


def create_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(
        secret,
        digits=OTP_DIGITS,
        interval=OTP_INTERVAL
    )


def generate_provisioning_uri(
    secret: str,
    username: str
) -> str:
    if not secret:
        raise ValueError(
            "2FA secret is required"
        )

    if not username:
        raise ValueError(
            "Username is required"
        )

    return create_totp(
        secret
    ).provisioning_uri(
        name=username,
        issuer_name=ISSUER_NAME
    )


def generate_qr_code(
    provisioning_uri: str
) -> str:
    if not provisioning_uri:
        raise ValueError(
            "Provisioning URI is required"
        )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4
    )

    qr.add_data(
        provisioning_uri
    )

    qr.make(
        fit=True
    )

    image = qr.make_image(
        fill_color="black",
        back_color="white"
    )

    buffer = io.BytesIO()

    image.save(
        buffer,
        format="PNG"
    )

    return base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")


def generate_backup_codes(
    count: int = BACKUP_CODE_COUNT
) -> list[str]:
    if count <= 0:
        raise ValueError(
            "Backup code count must be positive"
        )

    codes = set()

    while len(codes) < count:
        raw_code = secrets.token_hex(5).upper()

        formatted_code = (
            f"{raw_code[:5]}-"
            f"{raw_code[5:]}"
        )

        codes.add(
            formatted_code
        )

    return sorted(codes)


def hash_backup_code(
    backup_code: str
) -> str:
    normalized = (
        str(backup_code)
        .replace("-", "")
        .strip()
        .upper()
    )

    return hashlib.sha256(
        normalized.encode("utf-8")
    ).hexdigest()


def verify_backup_code(
    backup_code: str,
    stored_hashes: list[str]
) -> Optional[int]:
    if not backup_code:
        return None

    supplied_hash = hash_backup_code(
        backup_code
    )

    for index, stored_hash in enumerate(
        stored_hashes
    ):
        if secrets.compare_digest(
            supplied_hash,
            stored_hash
        ):
            return index

    return None


def verify_totp(
    secret: str,
    verification_code: str
) -> bool:
    if not secret or not verification_code:
        return False

    code = (
        str(verification_code)
        .strip()
        .replace(" ", "")
        .replace("-", "")
    )

    if (
        len(code) != OTP_DIGITS
        or not code.isdigit()
    ):
        return False

    totp = create_totp(
        secret
    )

    return bool(
        totp.verify(
            code,
            valid_window=1
        )
    )


def get_current_code(
    secret: str
) -> Optional[str]:
    if not secret:
        return None

    return create_totp(
        secret
    ).now()


def get_seconds_remaining(
    secret: str
) -> int:
    if not secret:
        return 0

    totp = create_totp(
        secret
    )

    return int(
        totp.interval
        - (
            totp.timecode(
                pyotp.utils.datetime.datetime.now(
                    pyotp.utils.datetime.timezone.utc
                )
            )
            % totp.interval
        )
    )


def setup_two_factor(
    username: str
) -> dict:
    secret = generate_secret()

    uri = generate_provisioning_uri(
        secret,
        username
    )

    qr_code = generate_qr_code(
        uri
    )

    backup_codes = generate_backup_codes()

    return {
        "secret": secret,
        "provisioning_uri": uri,
        "qr_code": qr_code,
        "backup_codes": backup_codes
    }