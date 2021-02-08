from django.urls import path
from django.conf.urls import url
from rest_framework_simplejwt.views import (TokenRefreshView,)

from .views import *

urlpatterns = [
    path('all/', Get_users.as_view(),name='Get_All_users'),
    path('user/<int:pk>', User_Crud.as_view(),name='Users_crud'),
    path('add-user/', Add_User.as_view(),name='Add_user'),
    path('login/', AuthenticateAPIView.as_view(),name='Login'),
    path('update-password/<int:pk>', UpdatePassword.as_view(),name='Update-Password'),

    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),name="request-reset-email"),
    path('password-reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', SetNewPasswordAPIView.as_view(), name='password-reset-complete')

]