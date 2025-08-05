import re, os
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from allauth.socialaccount.models import SocialAccount

from rest_framework.exceptions import ValidationError
from rest_framework.permissions import AllowAny,IsAuthenticated

from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from rest_framework_simplejwt.authentication import JWTAuthentication
from userauth.apis.helpers.jwt_tokens import JWTTokenHandler
from django.core.mail import send_mail
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

from memory_room.models import UserMapper
from dj_rest_auth.views import (
    PasswordResetView,
    PasswordResetConfirmView,
    PasswordChangeView,
)
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from userauth.models import UserProfile, NewsletterSubscriber, UserAddress
from timecapsoul.utils import send_html_email
from userauth.apis.serializers.serializers import  (
    RegistrationSerializer, UserProfileUpdateSerializer, GoogleIDTokenSerializer, ContactUsSerializer,PasswordResetConfirmSerializer,
    CustomPasswordResetSerializer, CustomPasswordResetConfirmSerializer,CustomPasswordChangeSerializer,JWTTokenSerializer,ForgotPasswordSerializer, NewsletterSubscriberSerializer,UserProfileUpdateSerializer,UserAddressSerializer
    )


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
                subject='Thank for contacting us', 
                to_email=email,
                template_name='userauth/contact_us.html',
                context={'first_name': serializer._validated_data.get('first_name')},
                
            )
            return Response({"message": "Contact request submitted successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class GoogleAuthView(SocialLoginView):
#     adapter_class = GoogleOAuth2Adapter
#     # callback_url = settings.GOOGLE_OAUTH_CALLBACK_URL
#     client_class = OAuth2Client
#     permission_classes = [AllowAny]
#     serializer_class = GoogleIDTokenSerializer  


#     def get_response(self):
#         # Generate JWT tokens manually
#         user = self.user
#         refresh = RefreshToken.for_user(user)
#         data = {
#             'access': str(refresh.access_token),
#             'refresh': str(refresh),
#             'user': {
#                 'id': user.id,
#                 'email': user.email,
#                 'username': user.username,
#                 'first_name': user.first_name,
#                 'last_name': user.last_name,
#             }
#         }
#         return Response(data=data, status=status.HTTP_200_OK)
       
    
#     def post(self, request, *args, **kwargs):
#         try:
#             return super().post(request, *args, **kwargs)
#         except OAuth2Error as e:
#             raise ValidationError({"detail": str(e)})


class GoogleAuthView(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter
    client_class = OAuth2Client
    permission_classes = [AllowAny]
    serializer_class = GoogleIDTokenSerializer

    def post(self, request, *args, **kwargs):
        self.is_new_user = False  # default

        try:
            response = super().post(request, *args, **kwargs)

            if self.is_new_user:
                user = self.user
                # Send registration email
                send_html_email(
                    subject='Thank you for registering on Yurayi',
                    to_email=user.email,
                    template_name='userauth/registeration_confirmation.html',
                    context={'email': user.email},
                )

            return response

        except OAuth2Error as e:
            raise ValidationError({"detail": str(e)})

    def login(self):
        # Called during login process by dj-rest-auth
        ret = super().login()
        self.is_new_user = not SocialAccount.objects.filter(user=self.user).exists()
        return ret

    def get_response(self):
        user = self.user
        refresh = RefreshToken.for_user(user)
        data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'is_new_user': self.is_new_user
        }

        return Response(data=data, status=status.HTTP_200_OK)



    
class GenerateJWTTokenView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tokens = JWTTokenSerializer.get_token(request.user)
        return Response(tokens)


class RegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.save()
            send_html_email(
                subject='Thank you for registration on Yurayi',
                to_email=user.email,
                template_name='userauth/registeration_confirmation.html',
                context={'email': user.email},
            )

            refresh = RefreshToken.for_user(user)
            profile = UserProfile.objects.get(user = user)

            return Response({
                "message": "Registration successful.",
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "user": {
                    "email": user.email,
                    'username': user.username,
                    'profile_image': profile.profile_image.s3_url if profile.profile_image else None,
                    'created_at': user.created_at,
                }
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        return self._handle_username_email_login(request)

    def _handle_username_email_login(self, request):
        identifier = request.data.get('identifier')
        password = request.data.get('password')

        if not identifier or not password:
            return Response({'error': 'Both identifier and password are required.'}, status=400)

        if re.fullmatch(EMAIL_REGEX, identifier):
            user = User.objects.filter(email__iexact=identifier).first()
        else:
            user = User.objects.filter(username__iexact=identifier).first()

        if not user:
            # return Response({'error': 'Login credentials are invalid. Please use valid credentials to login in dashboard'}, status=404)
            return Response( {"error": "Invalid login credentials. Please check your credentials and try again."},status=400)


        if not user.check_password(password):
            return Response( {"error": "Invalid login credentials. Please check your credentials and try again."},status=400)


        if not user.is_active:
            return Response({'error': 'Account inactive. Contact support to reactivate.'}, status=403)

        return self._issue_tokens(user)

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
    
class CustomPasswordResetView(PasswordResetView):
    serializer_class = CustomPasswordResetSerializer

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    serializer_class = CustomPasswordResetConfirmSerializer

class CustomPasswordChangeView(PasswordChangeView):
    serializer_class = CustomPasswordChangeSerializer


# Base class for authenticated users      
class SecuredView(APIView):
    authentication_classes   = [JWTAuthentication] # authentication classes
    permission_classes       = [IsAuthenticated]   # permission classes
    
    # get the current user from user token
    def get_current_user(self, request):
        """get current user from token"""
        token = request.headers['Authorization'][7:]
        user  = jwtTokens.get_user_from_token(token=token)
        return user

class NewSecuredView(APIView):

    def get_current_user(self, request):
        """Retrieve the current user from query parameter or header token"""
        token = request.GET.get('token')  # from query parameter

        if not token and 'Authorization' in request.headers:
            auth_header = request.headers.get('Authorization')
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix

        if token:
            try:
                user = jwtTokens.get_user_from_token(token=token)
                return user
            except Exception as e:
                # Token is invalid/expired
                return None
        return None

    def get(self, request):
        """Example GET method using the token logic"""
        user = self.get_current_user(request)
        if not user:
            return Response({'detail': 'Invalid or missing token.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Proceed with authorized logic
        return Response({'message': f'Hello {user.username}'})

class DashboardAPIView(SecuredView):

    def get(self, request, format=None):
        user   = self.get_current_user(request)
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
            subject="Reset Your Password",
            to_email=user.email,
            template_name="userauth/reset_password_email.html",
            context={
                "user": user,
                "reset_url": reset_url,
            },
            
        )

        return Response({"detail": "Password reset email sent."}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    """
    Confirm password reset with uidb64 and token.
    """

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  

        # Issue JWT tokens after password reset
        refresh = RefreshToken.for_user(user)
        return Response({
            "detail": "Password has been reset successfully.",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": {
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }, status=status.HTTP_200_OK)


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

class UserProfileUpdateView(SecuredView):
    """
    Handles retrieving and updating the authenticated user's profile.
    Includes nested updates to UserProfile and UserAddress.
    """

    def get(self, request):
        user = self.get_current_user(request)
        serializer = UserProfileUpdateSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request):
        user = self.get_current_user(request)
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class UserAddressListCreateView(SecuredView):
    def get(self, request):
        user = self.get_current_user(request)
        addresses = UserAddress.objects.filter(user=user)
        serializer = UserAddressSerializer(addresses, many=True)
        return Response(serializer.data)

    def post(self, request):
        user = self.get_current_user(request)
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
        user = self.get_current_user(request)
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserAddressSerializer(address)
        return Response(serializer.data)

    def put(self, request, pk):
        user = self.get_current_user(request)
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserAddressSerializer(address, data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        user = self.get_current_user(request)
        address = self.get_object(pk, user)
        if not address:
            return Response({"detail": "Address not found."}, status=status.HTTP_404_NOT_FOUND)

        address.delete()
        return Response({"detail": "Address deleted."}, status=status.HTTP_204_NO_CONTENT)
