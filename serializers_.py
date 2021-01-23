from rest_framework import serializers
from .models import User
import logging
from tenant.models import User as TenantUser
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
"""
    Custom User model is used in order to accomodate the following
    AmccAdmin
    OrgAdmin
    AmWeb
    IdbAdmin=models.BooleanField(default=False)
    AppUser(**This user will only have a user only role)
    As of now all users have App User role. In build V2, this functionality will change. 
"""

logger = logging.getLogger('django')


class SaveUserSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(
        max_length=45, min_length=6, write_only=True, style={'input_type': 'password'}
    )

    class Meta:
        model = User
        fields = [
            'email', 'password', 'mobile_number', 'is_amcc_user', 'is_idb_user',
            'is_org_cc_user', 'is_am_web_user', 'is_app_user', 'organization_id', 'status_id', 'unique_identifier',
            'is_seeded_user'
        ]

        def validate(self, attrs):
            email = attrs.get('email', '')
            if not password.isalnum():
                raise serializers.ValidationError(
                    'The password need to include atleast a number ')
            return super().validate(attrs)

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        user = self.Meta.model(**validated_data)
        if password is not None:
            user.set_password(password)
        user.save()
        return user


class AuthenticateUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=10, min_length=6, write_only=True, style={'input_type': 'password'})
    is_amcc_user = serializers.BooleanField(read_only=True)
    is_idb_user = serializers.BooleanField(read_only=True)
    is_org_cc_user = serializers.BooleanField(read_only=True)
    is_am_web_user = serializers.BooleanField(read_only=True)
    mobile_number = serializers.CharField(
        max_length=15, min_length=6, read_only=True)
    is_app_user = serializers.BooleanField(read_only=True)
    organization_id = serializers.PrimaryKeyRelatedField(read_only=True)
    status_id = serializers.PrimaryKeyRelatedField(read_only=True)


    class Meta:
        model = User
        fields = [
            'user_id', 'email','password', 'unique_identifier', 'tokens', 'mobile_number', 'is_amcc_user', 'is_idb_user',
            'is_org_cc_user', 'is_am_web_user', 'is_app_user', 'is_seeded_user', 'organization_id', 'status_id'
        ]

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)
        if not user:
            logger.error("Invalid User Credentials, Unauthorized User" )
            raise AuthenticationFailed('Invalid Credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('User is disabled/inactive')
        
        if (self.initial_data['page'] == 'is_amcc_user') and (user.is_amcc_user== True):
            logger.info("Amcc User Login Successful")
        elif (self.initial_data['page'] == 'is_org_cc_user') and (user.is_org_cc_user== True):
            logger.info("OrgCC User Login Successful")
        elif (self.initial_data['page'] == 'is_am_web_user') and (user.is_am_web_user== True):
            logger.info("Web User Login Successful")
        elif (self.initial_data['page'] == 'is_idb_user') and (user.is_idb_user== True):
            logger.info("IDB User Login Successful")
        elif (self.initial_data['page'] == 'is_app_user') and (user.is_app_user== True):
            logger.info("App User Login Successful")
        else:
            logger.error("Invalid User role while authenticating user")
            raise serializers.ValidationError('Invalid User role, please try again')

        return {
            'user_id': user.user_id,
            'email': user.email,
            'unique_identifier': user.unique_identifier,
            'mobile_number': user.mobile_number,
            'is_amcc_user': user.is_amcc_user,
            'is_org_cc_user': user.is_org_cc_user,
            'is_am_web_user':  user.is_am_web_user,
            'is_super_user':  user.is_super_user,
            'is_seeded_user': user.is_seeded_user,
            'is_idb_user': user.is_idb_user,
            'is_app_user': user.is_app_user,
            'organization_id': user.organization_id,
            'tokens': user.tokens,
        }

class ChangePasswordSerializer(serializers.Serializer):
    model = User

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=10, max_length=100, required=True)

    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=10, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(user_id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()
            return (user)
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)
        return super().validate(attrs)
