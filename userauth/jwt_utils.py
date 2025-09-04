import uuid
import jwt
from datetime import datetime, timedelta, timezone
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings



def _now():
    return datetime.now(timezone.utc)


def create_access_jwt_for_user(user, session_id):
    now = _now()
    # exp = now + timedelta(minutes=settings.ACCESS_TOKEN_TTL_MINUTES)
    exp = now + api_settings.ACCESS_TOKEN_LIFETIME
    payload = {
        "iss": settings.JWT_ISSUER,
        "sub": str(user.id),
        "user_id": user.id,
        "sid": str(session_id),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

def decode_jwt_noverify(token):
    """We verify exp and other checks ourselves in auth class."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM], options={"verify_exp": False})
