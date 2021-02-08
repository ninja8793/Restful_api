from django.shortcuts import redirect
from .serializers import *
from rest_framework import generics,status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ValidationError
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg import openapi
import jwt
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util
from .models import User
from django.http import HttpResponsePermanentRedirect
import os
from django.conf import settings
from django.core.mail import send_mail
import traceback

import pdb

class CustomRedirect(HttpResponsePermanentRedirect):

    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']

class AuthenticateAPIView(generics.GenericAPIView):
    serializer_class = AuthenticateUserSerializer

    def post(self, request, **kwargs):
        authenticate_serializer = self.serializer_class(data=request.data)
        if not authenticate_serializer.is_valid():
            raise ValidationError(authenticate_serializer.errors)

        return Response({
            'user_data': authenticate_serializer.data,
            'status': status.HTTP_200_OK
        })

class Get_users(generics.GenericAPIView):
    serializer_class = NewUserSerializer
    queryset = ''
    permission_classes = (IsAuthenticated,)
    v = ''
    def get(self,request):
        obj = User.objects.filter(softdelete=False).all()
        serializer = GetUserSerializer(obj,many=True)

        ### Sessions store
        num_visits = request.session.get('num_visits', 1)
        request.session['num_visits'] = num_visits + 1
        print("You have visited this API >>>",num_visits)
        return Response(data=serializer.data, status=status.HTTP_200_OK)

class User_Crud(generics.GenericAPIView):
    serializer_class = NewUserSerializer
    queryset = ''
    permission_classes = (IsAuthenticated,)
    def get(self,request,pk):
        try:
            obj = User.objects.filter(pk=pk,softdelete=False).get()
            serializer = GetUserSerializer(obj)
            return Response(data=serializer.data, status=status.HTTP_200_OK)
        except:
            return Response('OOPS User Not Found.', status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        try:
            obj = User.objects.filter(pk=pk,softdelete=False).get()
            serializer = UpdateUserSerializer(instance=obj,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
        except:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        try:
            obj = User.objects.get(pk=pk)
            # obj.softdelete = True
            # obj.save()
            obj.delete()
            return Response('User Deleted Successfully .....!!',status=status.HTTP_200_OK)
        except:
            return Response('OOPS User Not Found.', status=status.HTTP_404_NOT_FOUND)

class Add_User(generics.GenericAPIView):
    serializer_class = NewUserSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        token = RefreshToken.for_user(user).access_token

        return Response(user_data, status=status.HTTP_201_CREATED)

class UpdatePassword(generics.GenericAPIView):
    serializer_class = UpdatePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def patch(self,request, *args, **kwargs):
        self.object = self.request.user
        serializer = self.serializer_class(data=request.data,context={"db": str(request.user.id)})

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            if request.data['new_password'] == request.data['confirm_password']:
                self.object.set_password(serializer.data.get("new_password"))
                self.object.save()
                return Response('Password updated successfully', status=status.HTTP_200_OK)
            else:
                raise Exception('New Password and Confirm Password must be same, try again')
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email', '')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})

            redirect_url = request.data.get('redirect_url', '')
            absurl = 'http://'+current_site + relativeLink
            email_body = 'Hello, \n Use link below to reset your password  \n' +absurl+redirect_url
            data = {'email_body': email_body, 'to_email': user.email,'email_subject': 'Reset your passsword'}
            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url','')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'},status=status.HTTP_400_BAD_REQUEST)

            return Response({"user":user.email,"token":token,"uidb64":uidb64},status=status.HTTP_202_ACCEPTED)

            # current_site = get_current_site(request=request).domain
            # relativeLink = reverse('password-reset-complete')
            # absurl = 'http://' + current_site + relativeLink
            # return redirect(absurl,kwargs={'uidb64': uidb64, 'token': token})

        except DjangoUnicodeDecodeError as identifier:
            try:
                if not PasswordResetTokenGenerator().check_token(user):
                    return Response({'error': 'Token is not valid, please request a new one'},status=status.HTTP_400_BAD_REQUEST)

            except UnboundLocalError as e:
                return Response({'error': 'Token is not valid, please request a new one'},
                                status=status.HTTP_400_BAD_REQUEST)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)










