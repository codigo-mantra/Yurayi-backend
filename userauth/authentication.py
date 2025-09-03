from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import RevokedToken, Session
from .jwt_utils import decode_jwt_noverify

User = get_user_model()

class BearerJWTAuthentication(BaseAuthentication):
    """
    Reads Authorization: Bearer <access_jwt>
    Validates expiry, revocation (JTI), and session state in DB.
    """

    keyword = "Bearer"

    def authenticate(self, request):
        auth = request.META.get("HTTP_AUTHORIZATION", "")
        if not auth or not auth.startswith(f"{self.keyword} "):
            return None

        token = auth.split(" ", 1)[1].strip()
        try:
            payload = decode_jwt_noverify(token)
        except Exception:
            raise AuthenticationFailed("Invalid access token")

        # Expiry
        exp_ts = payload.get("exp")
        if not exp_ts or timezone.now() >= timezone.datetime.fromtimestamp(exp_ts, tz=timezone.utc):
            raise AuthenticationFailed("Access token expired")

        # Revoked JTI?
        jti = payload.get("jti")
        if jti and RevokedToken.objects.filter(jti=jti, expires_at__gt=timezone.now()).exists():
            raise AuthenticationFailed("Token revoked")

        # Session checks
        sid = payload.get("sid")
        if not sid:
            raise AuthenticationFailed("Missing session")
        try:
            session = Session.objects.get(pk=sid)
        except Session.DoesNotExist:
            raise AuthenticationFailed("Invalid session")

        if session.revoked:
            raise AuthenticationFailed("Session revoked")

        # Optional hardening: bind UA/IP (uncomment to enforce)
        # ua = (request.META.get("HTTP_USER_AGENT") or "")[:1000]
        # ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR")
        # if session.user_agent and session.user_agent != ua:
        #     raise AuthenticationFailed("Device changed")
        # if session.ip_address and session.ip_address != ip:
        #     raise AuthenticationFailed("IP changed")

        # Touch
        session.last_used_at = timezone.now()
        session.save(update_fields=["last_used_at"])

        # Resolve user
        user_id = payload.get("user_id")
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            raise AuthenticationFailed("User not found")

        return (user, None)
