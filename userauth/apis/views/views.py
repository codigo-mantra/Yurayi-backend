import re, os
import secrets
from django.shortcuts import get_object_or_404
from datetime import datetime, timezone
from rest_framework.exceptions import NotAuthenticated

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


from userauth.models import UserProfile, NewsletterSubscriber, UserAddress,Session, RefreshToken, RevokedToken
from timecapsoul.utils import send_html_email
from userauth.apis.serializers.serializers import  (
    RegistrationSerializer, UserProfileUpdateSerializer, GoogleAccessTokenSerializer, ContactUsSerializer,PasswordResetConfirmSerializer,
    CustomPasswordResetSerializer, CustomPasswordResetConfirmSerializer,CustomPasswordChangeSerializer,JWTTokenSerializer,ForgotPasswordSerializer, NewsletterSubscriberSerializer,UserProfileUpdateSerializer,UserAddressSerializer
    )

from userauth.serializers import LoginSerializer
from allauth.account.utils import perform_login
from memory_room.notification_service import NotificationService
from memory_room.notification_message import NOTIFICATIONS
from userauth.tasks import send_html_email_task

REFRESH_TTL_DAYS = settings.REFRESH_TOKEN_TTL_DAYS

# jwt token handler
jwtTokens = JWTTokenHandler()
User = get_user_model()
EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"

GOOGLE_CLIENT_ID = settings.GOOGLE_OAUTH_CLIENT_ID 

class ContactUsAPIView(APIView):
    def post(self, request):
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data.get('email')
            print(serializer._validated_data.get('first_name'))
            send_html_email(
                subject='We’ve received your message',
                to_email=email,
                template_name='userauth/contact_us.html',
                context={'first_name': serializer._validated_data.get('first_name')},
                
            )
            return Response({"message": "Contact request submitted successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GoogleAuthView(APIView):
    permission_classes = [AllowAny]
    serializer_class = GoogleAccessTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data,
            context={'request': request, 'view': self}
        )
        serializer.is_valid(raise_exception=True)

        sociallogin = serializer.save()
        user = sociallogin.user

        if not user.is_active:
            raise serializers.ValidationError("This account is inactive.")

        try:
            perform_login(request, user, email_verification='optional')
            is_new_user = getattr(serializer, 'is_new_user', False)
        except ImmediateHttpResponse as e:
            return e.response

        if is_new_user:
            send_html_email(
                subject='Welcome to Yurayi',
                to_email=user.email,
                template_name='userauth/registeration_confirmation.html',
                context={'email': user.email},
            )

        # refresh = RefreshToken.for_user(user)

        # return Response({
        #     'access': str(refresh.access_token),
        #     'refresh': str(refresh),
        #     'user': {
        #         'id': user.id,
        #         'email': user.email,
        #         'username': user.username,
        #         'first_name': user.first_name,
        #         'last_name': user.last_name,
        #     },
        #     'is_new_user': is_new_user
        # })
        
        # Track device/session
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
            'is_new_user': is_new_user
            
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
        tokens = JWTTokenSerializer.get_token(request.user)
        return Response(tokens)


class RegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        device_name = serializer.validated_data.get('device_name')
        user = serializer.save()
        
        # send_html_email(
        #     subject='Welcome to Yurayi',
        #     to_email=user.email,
        #     template_name='userauth/registeration_confirmation.html',
        #     context={'email': user.email},
        # )
        send_html_email_task.apply_async(
            kwargs={
                "subject": 'Welcome to Yurayi',
                "to_email": user.email,
                "template_name": 'userauth/registeration_confirmation.html',
                "context": {'email': user.email},
            }
        )
        

        # # refresh = RefreshToken.for_user(user)
        # profile = UserProfile.objects.get(user = user)
            
        # Track device/session
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

        return resp

        #     return Response({
        #         "message": "Registration successful.",
        #         "refresh": str(refresh),
        #         "access": str(refresh.access_token),
        #         "user": {
        #             "email": user.email,
        #             'username': user.username,
        #             'profile_image': profile.profile_image.s3_url if profile.profile_image else None,
        #             'created_at': user.created_at,
        #         }
        #     }, status=status.HTTP_201_CREATED)
        
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def _gen_refresh_value():
    return secrets.token_urlsafe(48)


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

        token = request.COOKIES.get(settings.ACCESS_COOKIE_NAME)
        if not token:
            return self.unauthorized("Access token missing")

        try:
            payload = decode_jwt_noverify(token)
        except Exception:
            return self.unauthorized("Invalid access token")

        # check expiry
        exp_ts = payload.get("exp")

        if not exp_ts or datetime.now(timezone.utc) >= datetime.fromtimestamp(exp_ts, tz=timezone.utc):
            return self.unauthorized("Access token expired")

        # check revoked tokens
        jti = payload.get("jti")
        # if jti and RevokedToken.objects.filter(jti=jti, expires_at__gt=timezone.now()).exists():
        from django.utils import timezone

        if jti and RevokedToken.objects.filter(
                jti=jti,
                expires_at__gt=timezone.now()
            ).exists():
            return self.unauthorized("Token has been revoked")

        # check session
        sid = payload.get("sid")
        self.session = None
        if sid:
            try:
                session = Session.objects.get(pk=sid)
                if session.revoked:
                    return self.unauthorized("Session revoked")
                session.last_used_at = timezone.now()
                session.save(update_fields=["last_used_at"])
                self.session = session
            except Session.DoesNotExist:
                return self.unauthorized("Invalid session")

        # fetch user
        user_id = payload.get("user_id")
        self.current_user = get_object_or_404(User, id=user_id)
        self.token_payload = payload
        
    def get_current_user(self, request):
        try:
            if self.current_user is None:
                raise NotAuthenticated()
            else:
                return self.current_user
        except Exception as e:
            print(f'Exception while getting user as: {e} ')
            pass
                
            
    def unauthorized(self, message):
        raise NotAuthenticated()
        # return Response({"detail": message}, status=status.HTTP_401_UNAUTHORIZED)



class LoginView(APIView):
    
    def post(self, request):
        return self._handle_username_email_login(request)

    def _handle_username_email_login(self, request):
        serializer = LoginSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        
        identifier = serializer.validated_data.get('identifier')
        password = serializer.validated_data.get('password')
        device_name = serializer.validated_data.get('device_name')


        if not identifier or not password:
            return Response({'error': 'Both identifier and password are required.'}, status=400)

        if re.fullmatch(EMAIL_REGEX, identifier):
            user = User.objects.filter(email__iexact=identifier).first()
        else:
            user = User.objects.filter(username__iexact=identifier).first()

        if not user:
            return Response( {"error": "Invalid Credentials. Please try again."},status=400)


        if not user.check_password(password):
            return Response( {"error": "Invalid Credentials. Please try again."},status=400)


        if not user.is_active:
            return Response({'error': 'Account inactive. Contact support to reactivate.'}, status=403)
        
        # # Track device/session
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
   
  
from rest_framework import permissions
class LogoutView(APIView):
    """
    POST /auth/logout/
    Clears cookies and revokes tokens/session if they exist.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
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
        
        return resp
    
class CustomPasswordResetView(PasswordResetView):
    serializer_class = CustomPasswordResetSerializer

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    serializer_class = CustomPasswordResetConfirmSerializer

class CustomPasswordChangeView(PasswordChangeView):
    serializer_class = CustomPasswordChangeSerializer


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
        user   = self.current_user
        if user is None:
            raise NotAuthenticated()
        user_mapper = UserMapper.objects.get(user = user)
        user_profile = UserProfile.objects.get(user = user)
        response = {
            'first_name': user.first_name,
            'last_name': user.last_name,
            'email': user.email,
            'profile_pic': user_profile.profile_image.s3_url if user_profile.profile_image else None,
            'last_login': user.last_login,
            'free_storage_limit': user_mapper.current_storage,
        }

        return Response(response,status=status.HTTP_200_OK)



class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = User.objects.get(email=serializer.validated_data["email"])
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)

        reset_url = f"{settings.FRONTEND_URL}reset-password/{uidb64}/{token}/"

        # Use shared email sending function
        send_html_email(
            subject="Reset Your Yurayi Password",
            to_email=user.email,
            template_name="userauth/reset_password_email.html",
            context={
                "user": user,
                "reset_url": reset_url,
            },
            
        )

        return Response({"detail": "We’ve emailed you a password reset link. Please check your inbox."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with uidb64 and token.
    """

    def post(self, request):
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
        return resp


class NewsletterSubscribeAPIView(APIView):
    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"email": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        subscriber, created = NewsletterSubscriber.objects.get_or_create(
            email=email,
            defaults={"is_active": True}
        )
        message = "Successfully subscribed."
        
        send_html_email(
            subject='Thank you for email subscription',
            to_email=email,
            template_name='userauth/new_letter_subscription.html',
            context={'email': str(email)},
           
        )


        serializer = NewsletterSubscriberSerializer(subscriber)
        return Response({
            "message": message,
            "data": serializer.data
        }, status=status.HTTP_200_OK)
from rest_framework.parsers import MultiPartParser, FormParser

class UserProfileUpdateView(SecuredView):
    """
    Handles retrieving and updating the authenticated user's profile.
    Includes nested updates to UserProfile and UserAddress.
    """
    parser_classes = [MultiPartParser, FormParser]


    def get(self, request):
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        serializer = UserProfileUpdateSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
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
            return Response({
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserAddressListCreateView(SecuredView):
    def get(self, request):
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        addresses = UserAddress.objects.filter(user=user)
        serializer = UserAddressSerializer(addresses, many=True)
        return Response(serializer.data)

    def post(self, request):
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
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserAddressSerializer(address)
        return Response(serializer.data)

    def put(self, request, pk):
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
        user = self.current_user
        if user is None:
            raise NotAuthenticated()
        
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        address.delete()
        return Response({"detail": "Address deleted."}, status=status.HTTP_204_NO_CONTENT)
