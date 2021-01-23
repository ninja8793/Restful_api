from django.contrib.auth.models import User, Group
from .models import new_user
from rest_framework import serializers
from django.contrib.auth.hashers import make_password
import pdb

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']

class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']

class NewUserSerializer(serializers.ModelSerializer):
    # password = serializers.CharField(max_length=45, min_length=6, write_only=True, style={'input_type': 'password'})
    class Meta:
        model = new_user
        fields = ["username", "age", "phone_number", "email", "password"]

    # def create(self, validated_data):
    #     password = validated_data.pop('password', None)
    #     password = make_password(password)
    #     user = self.Meta.model(**validated_data)
    #     if password is not None:
    #         password = make_password(password)
    #     user.save()
    #     return user

class GetUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = new_user
        fields = ["username", "age", "phone_number", "email", "password"]

class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = new_user
        fields = ["username", "age", "phone_number", "email", "password"]