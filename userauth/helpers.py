
from datetime import datetime, timedelta, timezone
import jwt
import uuid, logging
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse
from typing import Optional
from userauth.models import UserProfile
from userauth.jwt_utils import create_access_jwt_for_user


# module logger
logger = logging.getLogger(__name__)

# def create_access_jwt_for_user(user, session_id):
#     """
#     Creates JWT access token valid for 7 days
    
#     Args:
#         user: User model instance
#         session_id: Session ID (int or str)
    
#     Returns:
#         str: Encoded JWT token
#     """
#     now = datetime.now(timezone.utc)
#     exp = now + timedelta(days=7)

#     payload = {
#         "iss": settings.JWT_ISSUER,
#         "sub": str(user.id),
#         "user_id": user.id,
#         "sid": str(session_id),
#         "iat": int(now.timestamp()),
#         "exp": int(exp.timestamp()),
#         "jti": str(uuid.uuid4()),
#     }
#     return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_noverify(token):
    """
    Decode JWT without verifying expiration
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Decoded payload
    """
    return jwt.decode(
        token, 
        settings.JWT_SECRET, 
        algorithms=[settings.JWT_ALGORITHM], 
        options={"verify_exp": False}
    )


def set_auth_cookies(response: HttpResponse, access_token: str, refresh_token: str) -> HttpResponse:
    """
    Sets authentication cookies on the response object.
    Automatically uses environment-specific settings from Django settings.
    
    Args:
        response: Django Response object
        access_token: JWT access token string
        refresh_token: Refresh token string
    
    Returns:
        HttpResponse: Response with cookies set
    
    Example:
        from userauth.utils import set_auth_cookies
        
        resp = Response({"user": user_data})
        resp = set_auth_cookies(resp, access_token, refresh_token)
        return resp
    """
    clear_auth_cookies(response)
    # Set refresh token cookie
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=settings.ACCESS_TOKEN_LIFETIME,
        httponly=settings.REFRESH_COOKIE_HTTPONLY,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
        path=settings.REFRESH_COOKIE_PATH,
    )
    
    # Set access token cookie
    response.set_cookie(
        key=settings.ACCESS_COOKIE_NAME,
        value=access_token,
        max_age=settings.ACCESS_TOKEN_LIFETIME,
        httponly=settings.ACCESS_COOKIE_HTTPONLY,
        secure=settings.ACCESS_COOKIE_SECURE,
        samesite=settings.ACCESS_COOKIE_SAMESITE,
        domain=settings.COOKIE_DOMAIN,
        path=settings.ACCESS_COOKIE_PATH,
    )
    
    return response


def clear_auth_cookies(response: HttpResponse) -> HttpResponse:
    """
    Clears authentication cookies from the response.
    Useful for logout endpoints.
    
    Args:
        response: Django Response object
    
    Returns:
        HttpResponse: Response with cookies deleted
    
    Example:
        from userauth.utils import clear_auth_cookies
        
        resp = Response({"message": "Logged out successfully"})
        resp = clear_auth_cookies(resp)
        return resp
    """
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )
    
    response.delete_cookie(
        key=settings.ACCESS_COOKIE_NAME,
        path=settings.ACCESS_COOKIE_PATH,
        domain=settings.COOKIE_DOMAIN,
    )
    
    return response


def create_tokens_for_user(user, session):
    """
    Creates both access and refresh tokens for a user.
    Also saves refresh token to database.
    
    Args:
        user: User model instance
        session: Session model instance
    
    Returns:
        tuple: (access_token, refresh_token)
    
    Example:
        access, refresh = create_tokens_for_user(user, session)
    """
    from userauth.models import RefreshToken  # Import here to avoid circular imports
    
    # Create access token
    access_token = create_access_jwt_for_user(user, session_id=session.id)
    
    # Generate refresh token
    refresh_token = str(uuid.uuid4())
    
    # Save refresh token to database
    expires_at = timezone.now() + timedelta(days=settings.ACCESS_TOKEN_LIFETIME)
    RefreshToken.objects.create(
        token=refresh_token,
        user=user,
        session=session,
        expires_at=expires_at
    )
    
    return access_token, refresh_token

def get_profile_s3_key(user, base_s3_key=None):
    try:
        s3_key = None
        user_profile = UserProfile.objects.filter(user = user).first()
        if user_profile and user_profile.profile_image:
            
            if base_s3_key:
                s3_key = f'media/{user.s3_storage_id}/{base_s3_key}'
            else:
                s3_key = user_profile.profile_image.s3_key
    except Exception as e:
        logger.error(f'Exception while get profile image s3-key for user: {user.email} as {e}')
    finally:
        return s3_key