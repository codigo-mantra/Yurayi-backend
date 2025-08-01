
from django.urls import path, include
from django.urls import include, path, re_path


from userauth.apis.views.views import (
    LoginView, RegistrationView, 
    GoogleAuthView, GenerateJWTTokenView, ContactUsAPIView,UserProfileUpdateView,
    CustomPasswordResetView,CustomPasswordChangeView,CustomPasswordResetConfirmView, DashboardAPIView,ForgotPasswordView, PasswordResetConfirmView, NewsletterSubscribeAPIView,UserAddressListCreateView,UserAddressDetailView
    
)
from rest_framework_simplejwt.views import TokenVerifyView



urlpatterns = [
    path('news-letter/subscription/', NewsletterSubscribeAPIView.as_view(), name='newsletter-subscribe'),
    path('contact-us/', ContactUsAPIView.as_view(), name='contact-us'),
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/update/', UserProfileUpdateView.as_view(), name='profile-update'),
    path('user/dashboard/', DashboardAPIView.as_view(), name='user-dashboard'),


    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),
    path('generate-jwt/', GenerateJWTTokenView.as_view(), name='generate-jwt'),

    # google auth urls(login, registeration)
    path("google/auth/", GoogleAuthView.as_view(), name="google_login"),

    # password reset
    path('password/reset/', ForgotPasswordView.as_view(), name='password_reset'),
    path('password/reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password/change/', CustomPasswordChangeView.as_view(), name='password_change'),

    path('user/addresses/', UserAddressListCreateView.as_view(), name='user-address-list-create'),
    path('user/addresses/<int:pk>/', UserAddressDetailView.as_view(), name='user-address-detail'),

    path("rest/auth/", include("dj_rest_auth.urls")),
    # re_path(r"^api/v1/auth/accounts/", include("allauth.urls")),
    # path("auth/registration/", include("dj_rest_auth.registration.urls")),
    # path('generate-jwt/', GenerateJWTTokenView.as_view(), name='generate-jwt'),

    # path("api/v1/auth/google/callback/",GoogleLoginCallback.as_view(),name="google_login_callback",),
    # path('api/token/refresh/', get_refresh_view().as_view(), name='token_refresh'),



    



]
