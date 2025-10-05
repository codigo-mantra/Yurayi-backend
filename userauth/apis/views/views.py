import re, os
import uuid
import logging
import secrets
from django.shortcuts import get_object_or_404
from datetime import datetime, timezone
from rest_framework.exceptions import NotAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from allauth.socialaccount.models import SocialAccount
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny,IsAuthenticated
from allauth.exceptions import ImmediateHttpResponse
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework_simplejwt.authentication import JWTAuthentication
from userauth.apis.helpers.jwt_tokens import JWTTokenHandler
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from allauth.socialaccount.helpers import complete_social_login
from memory_room.models import UserMapper
from dj_rest_auth.views import (
    PasswordResetView,
    PasswordResetConfirmView,
    PasswordChangeView,
)
from rest_framework_simplejwt.settings import api_settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from userauth.jwt_utils import create_access_jwt_for_user, decode_jwt_noverify


from userauth.models import UserProfile, NewsletterSubscriber, UserAddress,Session, RefreshToken, RevokedToken, YurayiPolicy
from timecapsoul.utils import send_html_email
from userauth.apis.serializers.serializers import  (
    RegistrationSerializer, UserProfileUpdateSerializer, GoogleAccessTokenSerializer, ContactUsSerializer,PasswordResetConfirmSerializer,
    CustomPasswordResetSerializer, CustomPasswordResetConfirmSerializer,CustomPasswordChangeSerializer,JWTTokenSerializer,ForgotPasswordSerializer, NewsletterSubscriberSerializer,UserProfileUpdateSerializer,UserAddressSerializer, 
    YurayiPolicySerializer,SessionSerializer,RevokeUserSession
    )
from memory_room.signals import create_user_mapper
from userauth.serializers import LoginSerializer
from allauth.account.utils import perform_login
from memory_room.notification_service import NotificationService
from memory_room.notification_message import NOTIFICATIONS
from userauth.tasks import send_html_email_task

# module logger
logger = logging.getLogger(__name__)

REFRESH_TTL_DAYS = settings.REFRESH_TOKEN_TTL_DAYS

# jwt token handler
jwtTokens = JWTTokenHandler()
User = get_user_model()
EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"

GOOGLE_CLIENT_ID = settings.GOOGLE_OAUTH_CLIENT_ID 

class ContactUsAPIView(APIView):
    def post(self, request):
        logger.info("ContactUsAPIView.post called")
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data.get('email')
            logger.debug("ContactUs form valid")
            send_html_email_task.apply_async(
                kwargs={
                    "subject": 'We’ve received your message',
                    "to_email": email,
                    "template_name": 'userauth/contact_us.html',
                    "context": {'first_name': serializer._validated_data.get('first_name')},
                }
            )

            return Response({"message": "Contact request submitted successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GoogleAuthView(APIView):
    permission_classes = [AllowAny]
    serializer_class = GoogleAccessTokenSerializer

    def post(self, request, *args, **kwargs):
        logger.info("GoogleAuthView.post called")
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request, 'view': self}
        )
        serializer.is_valid(raise_exception=True)
        city = serializer.validated_data.get('city')
        country = serializer.validated_data.get('country')
        latitude = serializer.validated_data.get('latitude')
        longitude = serializer.validated_data.get('longitude')

        sociallogin = serializer.save()
        user = sociallogin.user

        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        try:
            perform_login(request, user, email_verification='optional')
            is_new_user = getattr(serializer, 'is_new_user', False)
        except ImmediateHttpResponse as e:
            logger.warning("ImmediateHttpResponse during Google login")
            return e.response

        if is_new_user:
            send_html_email_task.apply_async(
                kwargs={
                    "subject": 'Welcome to Yurayi',
                    "to_email": user.email,
                    "template_name": 'userauth/registeration_confirmation.html',
                    "context": {'email': user.email},
                }
            )
            create_user_mapper(user) # create user mapper
            

        # Track device/session
        device_name = ''
        # Extract IP and User-Agent
        ua = (request.META.get("HTTP_USER_AGENT") or None)
        ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR") or None

        # Assign unique placeholders if missing
        if not ua:
            ua = f"custom-ua-{uuid.uuid4()}"
        if not ip:
            ip = f"custom-ip-{uuid.uuid4()}"
        # session = Session.objects.create(user=user, name=device_name, user_agent=ua, ip_address=ip)
        match = re.search(r"\((.*?)\)", ua)
        if match:
            os_info = match.group(1).split(";")[0].strip()
            device_name = os_info
        
        try:
            active_sessions = Session.objects.filter(user = user, revoked = False)
            previous_session = active_sessions.filter(
                user=user,
                revoked = False,
                user_agent=ua,
                ip_address=ip,
                name = device_name,
                city = city, 
                country = country,
                latitude = latitude,
                longitude = longitude
            ).first()
            if previous_session is None:
                session_count = active_sessions.count() 
              
                if session_count > 5:
                    serializer =  SessionSerializer(active_sessions, many=True)
                    response = {
                        'active_session_count': session_count,
                        'active_sessions': serializer.data,
                        'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user),
                        "session_error": "Maximum session limit reached. Please logout from other devices first."
                    }
                    return Response(response)
                
                session = Session.objects.create(
                    user=user,
                    user_agent=ua,
                    name = device_name,
                    ip_address=ip,
                    city = city, 
                    country = country,
                    latitude = latitude,
                    longitude = longitude
                )
                logger.info(f'New Session create for user {user.email}')
                
            else:
                session = previous_session
        except Exception as e:
            logger.error(f'Exception while creating user sesion as {e} for user: {user.email}')
            raise

        access = create_access_jwt_for_user(user, session_id=session.id)
        refresh_value = _gen_refresh_value()
        from django.utils import timezone 
        expires_at = timezone.now() + timezone.timedelta(days=REFRESH_TTL_DAYS)
        RefreshToken.objects.create(token=refresh_value, user=user, session=session, expires_at=expires_at)

        resp = Response({
            "access": access,
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            'is_new_user': is_new_user,
            
        })

        resp.set_cookie(
            settings.REFRESH_COOKIE_NAME,
            refresh_value,
            httponly=settings.REFRESH_COOKIE_HTTPONLY,
            secure=settings.REFRESH_COOKIE_SECURE,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
            max_age=int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            domain=settings.COOKIE_DOMAIN,
            path=settings.REFRESH_COOKIE_PATH,
        )

        #  Set access cookie
        resp.set_cookie(
            settings.ACCESS_COOKIE_NAME,
            access,
            httponly=settings.ACCESS_COOKIE_HTTPONLY,
            secure=settings.ACCESS_COOKIE_SECURE,
            samesite=settings.ACCESS_COOKIE_SAMESITE,
            max_age=settings.ACCESS_TOKEN_LIFETIME,
            domain=settings.COOKIE_DOMAIN,
            path=settings.ACCESS_COOKIE_PATH,
        )

        return resp

    
class GenerateJWTTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logger.info("GenerateJWTTokenView.get called")
        tokens = JWTTokenSerializer.get_token(request.user)
        return Response(tokens)


class RegistrationView(APIView):
    def post(self, request):
        logger.info(f'RegistrationView is called ')
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # other related info like location
        city = serializer.validated_data.get('city')
        country = serializer.validated_data.get('country')
        latitude = serializer.validated_data.get('latitude')
        longitude = serializer.validated_data.get('longitude')
        device_name = serializer.validated_data.get('device_name')
        logger.info(f'RegistrationView is called  requested data is valid and  user location received')
        
        
        user = serializer.save()
        logger.info(f"new user register as {user.email}")
        
        send_html_email_task.apply_async(
            kwargs={
                "subject": 'Welcome to Yurayi',
                "to_email": user.email,
                "template_name": 'userauth/registeration_confirmation.html',
                "context": {'email': user.email},
            }
        )
        create_user_mapper(user) # create user mapper
        
        logger.info(f'RegistrationView in new user created as {user.email}')
        
            
        # Extract IP and User-Agent
        ua = (request.META.get("HTTP_USER_AGENT") or None)
        ip_address = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR") or None

        # Assign unique placeholders if missing
        if not ua:
            ua = f"custom-ua-{uuid.uuid4()}"
        if not ip_address:
            ip_address = f"custom-ip-{uuid.uuid4()}"
            
        match = re.search(r"\((.*?)\)", ua)
        if match:
            os_info = match.group(1).split(";")[0].strip()
            device_name = os_info
            
        session = Session.objects.create(
            user=user,
            name=device_name,
            user_agent=ua,
            ip_address=ip_address,
            city = city, 
            country = country,
            latitude = latitude,
            longitude = longitude
        )

        access = create_access_jwt_for_user(user, session_id=session.id)
        refresh_value = _gen_refresh_value()
        from django.utils import timezone 
        expires_at = timezone.now() + timezone.timedelta(days=REFRESH_TTL_DAYS)
        RefreshToken.objects.create(token=refresh_value, user=user, session=session, expires_at=expires_at)

        resp = Response({
            "access": access,
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
        })

        resp.set_cookie(
            settings.REFRESH_COOKIE_NAME,
            refresh_value,
            httponly=settings.REFRESH_COOKIE_HTTPONLY,
            secure=settings.REFRESH_COOKIE_SECURE,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
            max_age=int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            domain=settings.COOKIE_DOMAIN,
            path=settings.REFRESH_COOKIE_PATH,
        )

        #  Set access cookie
        resp.set_cookie(
            settings.ACCESS_COOKIE_NAME,
            access,
            httponly=settings.ACCESS_COOKIE_HTTPONLY,
            secure=settings.ACCESS_COOKIE_SECURE,
            samesite=settings.ACCESS_COOKIE_SAMESITE,
            max_age=settings.ACCESS_TOKEN_LIFETIME,
            domain=settings.COOKIE_DOMAIN,
            path=settings.ACCESS_COOKIE_PATH,
        )
        logger.info(f'RegistrationView response data served to {user.email}')
        return resp
        
def _gen_refresh_value():
    return secrets.token_urlsafe(48)



class LoginView(APIView):
    
    def post(self, request):
        logger.info("LoginView.post called")
        return self._handle_username_email_login(request)

    def _handle_username_email_login(self, request):
        serializer = LoginSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        
        identifier = serializer.validated_data.get('identifier')
        password = serializer.validated_data.get('password')
        city = serializer.validated_data.get('city')
        country = serializer.validated_data.get('country')
        latitude = serializer.validated_data.get('latitude')
        longitude = serializer.validated_data.get('longitude')
        device_name = serializer.validated_data.get('device_name')


        if not identifier or not password:
            return Response({'error': 'Both identifier and password are required.'}, status=400)

        if re.fullmatch(EMAIL_REGEX, identifier):
            user = User.objects.filter(email__iexact=identifier).first()
        else:
            user = User.objects.filter(username__iexact=identifier).first()

        if not user:
            logger.info("Login failed: user not found")
            return Response( {"error": "Invalid Credentials. Please try again."},status=400)


        if not user.check_password(password):
            logger.info("Login failed: bad password")
            return Response( {"error": "Invalid Credentials. Please try again."},status=400)


        if not user.is_active:
            logger.info("Login failed: inactive user")
            return Response({'error': 'Account inactive. Contact support to reactivate.'}, status=403)
        
        # Extract IP and User-Agent
        ua = (request.META.get("HTTP_USER_AGENT") or None)
        ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR") or None

        # Assign unique placeholders if missing
        if not ua:
            ua = f"custom-ua-{uuid.uuid4()}"
        if not ip:
            ip = f"custom-ip-{uuid.uuid4()}"
        match = re.search(r"\((.*?)\)", ua)
        if match:
            os_info = match.group(1).split(";")[0].strip()
            device_name = os_info
        
        try:
            active_sessions = Session.objects.filter(user = user, revoked = False)
            previous_session = active_sessions.filter(
                user=user,
                revoked = False,
                user_agent=ua,
                ip_address=ip,
                name = device_name,
                city = city, 
                country = country,
                latitude = latitude,
                longitude = longitude
            ).first()
            if previous_session is None:
                session_count = active_sessions.count() 
              
                if session_count > 5:
                    serializer =  SessionSerializer(active_sessions, many=True)
                    response = {
                        'active_session_count': session_count,
                        'active_sessions': serializer.data,
                        'uidb64': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user),
                        "session_error": "Maximum session limit reached. Please logout from other devices first."
                    }
                    return Response(response)
                
                session = Session.objects.create(
                    user=user,
                    user_agent=ua,
                    name = device_name,
                    ip_address=ip,
                    city = city, 
                    country = country,
                    latitude = latitude,
                    longitude = longitude
                )
                logger.info(f'New Session create for user {user.email}')
                
            else:
                session = previous_session
        except Exception as e:
            logger.error(f'Exception while creating user sesion as {e} for user: {user.email}')
            raise
            
        access = create_access_jwt_for_user(user, session_id=session.id)
        refresh_value = _gen_refresh_value()
        from django.utils import timezone 
        expires_at = timezone.now() + timezone.timedelta(days=REFRESH_TTL_DAYS)
        RefreshToken.objects.create(token=refresh_value, user=user, session=session, expires_at=expires_at)

        resp = Response({
            "access": access,
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
        })

        resp.set_cookie(
            settings.REFRESH_COOKIE_NAME,
            refresh_value,
            httponly=settings.REFRESH_COOKIE_HTTPONLY,
            secure=settings.REFRESH_COOKIE_SECURE,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
            max_age=int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            domain=settings.COOKIE_DOMAIN,
            path=settings.REFRESH_COOKIE_PATH,
        )

        #  Set access cookie
        resp.set_cookie(
            settings.ACCESS_COOKIE_NAME,
            access,
            httponly=settings.ACCESS_COOKIE_HTTPONLY,
            secure=settings.ACCESS_COOKIE_SECURE,
            samesite=settings.ACCESS_COOKIE_SAMESITE,
            max_age=settings.ACCESS_TOKEN_LIFETIME,
            domain=settings.COOKIE_DOMAIN,
            path=settings.ACCESS_COOKIE_PATH,
        )
        logger.info("Login success")
        return resp


    def _issue_tokens(self, user):
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }, status=200)
   

class SecuredView(APIView):
    """
    Base API view that authenticates users via access token in cookies.
    Provides `self.current_user`, `self.session`, and `self.token_payload`.
    """

    permission_classes = []  # disable DRF auth; we do cookie-based auth manually

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)

        import datetime
        from datetime import datetime, timezone
        # Validate IP and User-Agent
        ua = (request.META.get("HTTP_USER_AGENT") or None)
        ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR") or None


        token = request.COOKIES.get(settings.ACCESS_COOKIE_NAME)
        if not token:
            logger.warning("Access token missing")
            return self.unauthorized("Access token missing")

        try:
            payload = decode_jwt_noverify(token)
        except Exception:
            logger.warning("Invalid access token")
            return self.unauthorized("Invalid access token")

        # check expiry
        exp_ts = payload.get("exp")

        if not exp_ts or datetime.now(timezone.utc) >= datetime.fromtimestamp(exp_ts, tz=timezone.utc):
            logger.warning("Access token expired")
            return self.unauthorized("Access token expired")

        # check revoked tokens
        jti = payload.get("jti")
        # if jti and RevokedToken.objects.filter(jti=jti, expires_at__gt=timezone.now()).exists():
        from django.utils import timezone

        if jti and RevokedToken.objects.filter(
                jti=jti,
                expires_at__gt=timezone.now()
            ).exists():
            logger.warning("Token has been revoked")
            return self.unauthorized("Token has been revoked")

        # check session
        sid = payload.get("sid")
        self.session = None
        if sid:
            try:
                session = Session.objects.get(pk=sid)
                if session.user_agent != ua or session.ip_address != ip:
                    logger.warning(f"Session hijack attempt. Expected ua={session.user_agent}, ip={session.ip_address}; got ua={ua}, ip={ip}")
                    return self.unauthorized("Session invalid for this device")
                
                if session.revoked:
                    logger.warning("Session revoked")
                    return self.unauthorized("Session revoked")
                session.last_used_at = timezone.now()
                session.save(update_fields=["last_used_at"])
                self.session = session
            except Session.DoesNotExist:
                logger.warning("Invalid session")
                return self.unauthorized("Invalid session")

        # fetch user
        user_id = payload.get("user_id")
        self.current_user = get_object_or_404(User, id=user_id)
        logger.debug("Authenticated user in SecuredView.initial")
        self.token_payload = payload
        
    def get_current_user(self, request):
        try:
            if self.current_user is None:
                raise NotAuthenticated()
            else:
                return self.current_user
        except Exception as e:
            logger.exception("Exception while getting current user")
            pass
                
            
    def unauthorized(self, message):
        logger.warning("Unauthorized access")
        raise NotAuthenticated()
        # return Response({"detail": message}, status=status.HTTP_401_UNAUTHORIZED)


  
from rest_framework import permissions
class LogoutView(APIView):
    """
    POST /auth/logout/
    Clears cookies and revokes tokens/session if they exist.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        logger.info("LogoutView.post called")
        # Get access token from cookie (consistent with ProfileView)
        token_value = request.COOKIES.get(settings.ACCESS_COOKIE_NAME)
        from django.utils import timezone
        from datetime import datetime

        
        if token_value:
            try:
                payload = decode_jwt_noverify(token_value)
                jti = payload.get("jti")
                sid = payload.get("sid")
                
                # Revoke the token
                if jti:
                    exp_ts = payload.get("exp")
                    if exp_ts:
                        exp = timezone.make_aware(datetime.fromtimestamp(exp_ts))
                        RevokedToken.objects.update_or_create(jti=jti, defaults={"expires_at": exp})
                
                # Clear user session
                if sid:
                    try:
                        session = Session.objects.get(pk=sid)
                    except Exception as e:
                        pass
                    else:
                        session.revoked = True
                        session.save()
                        refresh_token = RefreshToken.objects.filter(session = session).update(revoked=True, last_used_at=timezone.now())
            except Exception:
                # Token invalid, but still proceed with logout
                logger.warning("Invalid token during logout; proceeding anyway")
                pass
       
        # Clear cookies and respond
        resp = Response({"detail": "Logged out"})
        
        # Clear refresh cookie
        resp.delete_cookie(
            settings.REFRESH_COOKIE_NAME,
            path=settings.REFRESH_COOKIE_PATH,
            domain=settings.COOKIE_DOMAIN,
        )
        # Clear access cookie
        resp.delete_cookie(
            settings.ACCESS_COOKIE_NAME,
            path=settings.ACCESS_COOKIE_PATH,
            domain=settings.COOKIE_DOMAIN,
        )
        
        logger.info("Logout success")
        return resp
    
class CustomPasswordResetView(PasswordResetView):
    serializer_class = CustomPasswordResetSerializer

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    serializer_class = CustomPasswordResetConfirmSerializer

class CustomPasswordChangeView(SecuredView):
    
    def post(self, request, format=None):
        user = self.get_current_user(request)
        logger.info(f"CustomPasswordChangeView called by {user.email}")
        serializer = CustomPasswordChangeSerializer(data = request.data, context = {'user': user})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(f"CustomPasswordChangeView password changed successfully {user.email}")
        return Response(status=status.HTTP_200_OK)
        
        

# Base class for authenticated users      
# class SecuredView(APIView):
#     authentication_classes   = [JWTAuthentication] # authentication classes
#     permission_classes       = [IsAuthenticated]   # permission classes
    
#     # get the current user from user token
#     def get_current_user(self, request):
#         """get current user from token"""
#         token = request.headers['Authorization'][7:]
#         user  = jwtTokens.get_user_from_token(token=token)
#         return user

class NewSecuredView(APIView):

    # def get_current_user(self, request):
        # """Retrieve the current user from query parameter or header token"""
        # token = request.GET.get('token')  # from query parameter

        # if not token and 'Authorization' in request.headers:
        #     auth_header = request.headers.get('Authorization')
        #     if auth_header.startswith('Bearer '):
        #         token = auth_header[7:]  # Remove 'Bearer ' prefix

        # if token:
        #     try:
        #         user = jwtTokens.get_user_from_token(token=token)
        #         return user
        #     except Exception as e:
        #         # Token is invalid/expired
        #         return None
        # return None
    
    def get_current_user(self, request):
        """Retrieve the current user from query parameter, headers, or POST body"""
        token = None

        #  1. First check query params (GET)
        token = request.GET.get("token")

        #  2. Then check POST body (JSON/form-data)
        if not token:
            token = request.data.get("token")

        if not token and "Authorization" in request.headers:
            auth_header = request.headers.get("Authorization")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
        

        if not token:
            raise serializers.ValidationError({'Token': 'Access token is required'})

        #  4. Validate and return user
        if token:
            try:
                user = jwtTokens.get_user_from_token(token=token)
                return user
            except Exception:
                return None
        return None

    def get(self, request):
        """Example GET method using the token logic"""
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        
        # Proceed with authorized logic
        return Response({'message': f'Hello {user.username}'})

class DashboardAPIView(SecuredView):

    def get(self, request, format=None):
        logger.info("DashboardAPIView.get called")
        user   = self.current_user
        if user is None:
            raise NotAuthenticated()
        user_mapper = UserMapper.objects.get_or_create(user = user)
        user_profile = UserProfile.objects.get(user = user)
        response = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'profile_pic': user_profile.profile_image.s3_url if user_profile.profile_image else None,
            'last_login': user.last_login,
            'free_storage_limit': 0,
        }

        return Response(response,status=status.HTTP_200_OK)



class ForgotPasswordView(APIView):
    def post(self, request):
        logger.info("ForgotPasswordView.post called")
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(email=serializer.validated_data["email"])
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_url = f"{settings.FRONTEND_URL}reset-password/{uidb64}/{token}/"

        # Use shared email sending function
        send_html_email_task.apply_async(
            kwargs={
                "subject": "Reset Your Yurayi Password",
                "to_email": user.email,
                "template_name": "userauth/reset_password_email.html",
                "context": {
                    "user":user.username if user.username else user.email,
                    "reset_url": reset_url,
            },
            }
        )

        logger.info("Password reset email sent")
        return Response({"detail": "We’ve emailed you a password reset link. Please check your inbox."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with uidb64 and token.
    """

    def post(self, request):
        logger.info("PasswordResetConfirmView.post called")
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  
        
        # create password chage notification here 
        notif = NotificationService.create_notification_with_key(
            notification_key='password_updated',
            user=user,
        )
        # # Track device/session
        device_name = ''
        ua = (request.META.get("HTTP_USER_AGENT") or "")[:1000]
        ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR")
        session = Session.objects.create(user=user, name=device_name, user_agent=ua, ip_address=ip)

        access = create_access_jwt_for_user(user, session_id=session.id)
        refresh_value = _gen_refresh_value()
        from django.utils import timezone 
        expires_at = timezone.now() + timezone.timedelta(days=REFRESH_TTL_DAYS)
        RefreshToken.objects.create(token=refresh_value, user=user, session=session, expires_at=expires_at)

        resp = Response({
            "access": access,
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
        })

        resp.set_cookie(
            settings.REFRESH_COOKIE_NAME,
            refresh_value,
            httponly=settings.REFRESH_COOKIE_HTTPONLY,
            secure=settings.REFRESH_COOKIE_SECURE,
            samesite=settings.REFRESH_COOKIE_SAMESITE,
            max_age=int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            domain=settings.COOKIE_DOMAIN,
            path=settings.REFRESH_COOKIE_PATH,
        )

        #  Set access cookie
        resp.set_cookie(
            settings.ACCESS_COOKIE_NAME,
            access,
            httponly=settings.ACCESS_COOKIE_HTTPONLY,
            secure=settings.ACCESS_COOKIE_SECURE,
            samesite=settings.ACCESS_COOKIE_SAMESITE,
            max_age=settings.ACCESS_TOKEN_LIFETIME,
            domain=settings.COOKIE_DOMAIN,
            path=settings.ACCESS_COOKIE_PATH,
        )
        logger.info("Password updated and tokens issued")
        return resp


class NewsletterSubscribeAPIView(APIView):
    def post(self, request):
        logger.info("NewsletterSubscribeAPIView.post called")
        email = request.data.get("email")
        if not email:
            return Response({"email": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        subscriber, created = NewsletterSubscriber.objects.get_or_create(
            email=email,
            defaults={"is_active": True}
        )
        message = "Successfully subscribed."
        send_html_email_task.apply_async(
            kwargs={
                "subject":'Thank you for email subscription',
                "to_email": email,
                "template_name": 'userauth/new_letter_subscription.html',
                "context": {'email': str(email)},
            }
        )


        serializer = NewsletterSubscriberSerializer(subscriber)
        return Response({
            "message": message,
            "data": serializer.data
        }, status=status.HTTP_200_OK)


class UserProfileUpdateView(SecuredView):
    """
    Handles retrieving and updating the authenticated user's profile.
    Includes nested updates to UserProfile and UserAddress.
    """
    parser_classes = [MultiPartParser, FormParser]


    def get(self, request):
        logger.info("UserProfileUpdateView.get called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        serializer = UserProfileUpdateSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        logger.info("UserProfileUpdateView.patch called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            notif = NotificationService.create_notification_with_key(
                notification_key='profile_updated',
                user=user,
            )
            logger.info("Profile updated")
            return Response({
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserAddressListCreateView(SecuredView):
    def get(self, request):
        logger.info("UserAddressListCreateView.get called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        addresses = UserAddress.objects.filter(user=user)
        serializer = UserAddressSerializer(addresses, many=True)
        return Response(serializer.data)

    def post(self, request):
        logger.info("UserAddressListCreateView.post called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        serializer = UserAddressSerializer(data=request.data, context={'user': user})
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserAddressDetailView(SecuredView):
    def get_object(self, pk, user):
        try:
            return UserAddress.objects.get(pk=pk, user=user)
        except UserAddress.DoesNotExist:
            return None

    def get(self, request, pk):
        logger.info("UserAddressDetailView.get called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserAddressSerializer(address)
        return Response(serializer.data)

    def put(self, request, pk):
        logger.info("UserAddressDetailView.put called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserAddressSerializer(address, data=request.data, context={'request': request}, partial = True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        logger.info("UserAddressDetailView.delete called")
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        address.delete()
        return Response({"detail": "Address deleted."}, status=status.HTTP_204_NO_CONTENT)


class UserQueriesAPIView(SecuredView):
    def post(self, request):
        user = self.get_current_user(request)
        logger.info(f"UserQueriesAPIView called by {user.email}")
        
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.validated_data['user'] = user
            serializer.save()
            email = serializer.validated_data.get('email')
            logger.debug("ContactUs form valid")
            send_html_email_task.apply_async(
                kwargs={
                    "subject": 'We’ve received your message',
                    "to_email": email,
                    "template_name": 'userauth/contact_us.html',
                    "context": {'first_name': serializer._validated_data.get('first_name')},
                }
            )
            logger.info(f"UserQueriesAPIView successfully submitted by {user.email}")
            return Response({"message": "Contact request submitted successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class YurayiPolicyView(APIView):
    def get(self, request):
        name = self.request.query_params.get("name") 
        if name:
            queryset = queryset.filter(name__icontains=name, is_deleted = False)
        else:
            queryset = YurayiPolicy.objects.filter(is_deleted = False)
        data = YurayiPolicySerializer(queryset, many=True).data
            
        return Response(data)
    
class SessionListAPIView(SecuredView):
    """List all active sessions of the current user"""

    def get(self, request):
        user  = self.get_current_user(request)
        logger.info(f"SessionListAPIView called by {user.email}")
        
        
        sessions = Session.objects.filter(user=user, revoked=False)
        serializer = SessionSerializer(sessions, many=True)
        response = {
            'current_session_id': self.session.id,
            'others_sessions': serializer.data
        }
        logger.info(f"SessionListAPIView all session served to {user.email}")
        return Response(response, status=status.HTTP_200_OK)
    


class SessionDeleteAPIView(SecuredView):
    """Revoke a specific session"""

    def delete(self, request, session_id):
        user  = self.get_current_user(request)
        logger.info(f"SessionDeleteAPIView called by {user.email} session-id: {session_id}")
        from django.utils import timezone

        session = get_object_or_404(Session, id=session_id, user=user, revoked=False)
        session.revoked = True
        session.last_used_at = timezone.now()
        session.save()
        logger.info(f"SessionDeleteAPIView revoked successfully for {user.email} session-id: {session_id}")
        return Response({"detail": "Session revoked successfully"}, status=status.HTTP_200_OK)


class SessionClearOthersAPIView(SecuredView):
    """Revoke all sessions except the current one"""

    def post(self, request):
        from django.utils import timezone

        user  = self.get_current_user(request)
        logger.info(f"SessionClearOthersAPIView called by {user.email}")
        current_session_id = request.data.get('current_session_id', None)
        if not current_session_id:
            raise ValidationError({'current_session_id': "Current session id is required"})
        
        sessions = Session.objects.filter(user=user, revoked=False).exclude(id=current_session_id)
        count = sessions.update(revoked=True, last_used_at=timezone.now())
        logger.info(f"SessionClearOthersAPIView {count} sessions revoked by {user.email}")
        return Response({"detail": f"{count} sessions revoked (except current)"}, status=status.HTTP_200_OK)


class RevokeOldUserSession(APIView):
    
    def post(self, request, format=None):
        try:
            serializer = RevokeUserSession(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors)
            user = serializer.validated_data.get('user')
            session_id = serializer.validated_data.get('session_id')
            # city = serializer.validated_data.get('city')
            # country = serializer.validated_data.get('country')
            # latitude = serializer.validated_data.get('latitude')
            # longitude = serializer.validated_data.get('longitude')
            # device_name = serializer.validated_data.get('device_name')
            
            
            # # Extract IP and User-Agent
            # ua = (request.META.get("HTTP_USER_AGENT") or None)
            # ip = request.META.get("REMOTE_ADDR") or request.META.get("HTTP_X_FORWARDED_FOR") or None
            # match = re.search(r"\((.*?)\)", ua)
            # if match:
            #     os_info = match.group(1).split(";")[0].strip()
            #     device_name = os_info

            # session = Session.objects.create(
            #     user=user,
            #     user_agent=ua,
            #     name = device_name,
            #     ip_address=ip,
            #     city = city, 
            #     country = country,
            #     latitude = latitude,
            #     longitude = longitude
            # )
            # access = create_access_jwt_for_user(user, session_id=session.id)
            # refresh_value = _gen_refresh_value()
            # from django.utils import timezone 
            # expires_at = timezone.now() + timezone.timedelta(days=REFRESH_TTL_DAYS)
            # RefreshToken.objects.create(token=refresh_value, user=user, session=session, expires_at=expires_at)

            # resp = Response({
            #     "access": access,
            #     "user": {
            #         "username": user.username,
            #         "email": user.email,
            #         "first_name": user.first_name,
            #         "last_name": user.last_name,
            #     },
            # })

            # resp.set_cookie(
            #     settings.REFRESH_COOKIE_NAME,
            #     refresh_value,
            #     httponly=settings.REFRESH_COOKIE_HTTPONLY,
            #     secure=settings.REFRESH_COOKIE_SECURE,
            #     samesite=settings.REFRESH_COOKIE_SAMESITE,
            #     max_age=int(api_settings.ACCESS_TOKEN_LIFETIME.total_seconds()),
            #     domain=settings.COOKIE_DOMAIN,
            #     path=settings.REFRESH_COOKIE_PATH,
            # )

            # #  Set access cookie
            # resp.set_cookie(
            #     settings.ACCESS_COOKIE_NAME,
            #     access,
            #     httponly=settings.ACCESS_COOKIE_HTTPONLY,
            #     secure=settings.ACCESS_COOKIE_SECURE,
            #     samesite=settings.ACCESS_COOKIE_SAMESITE,
            #     max_age=settings.ACCESS_TOKEN_LIFETIME,
            #     domain=settings.COOKIE_DOMAIN,
            #     path=settings.ACCESS_COOKIE_PATH,
            # )
            logger.info(f"Session logout success for session-id: {session_id} by user: {user.email}")
            return Response(status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f'Exception while logout user session for session-id: ')
            return Response(status=status.HTTP_400_BAD_REQUEST)
        