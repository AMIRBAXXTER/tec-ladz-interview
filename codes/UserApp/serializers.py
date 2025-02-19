from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from rest_framework import serializers
from .models import CustomUser
from .utils import check_phone


class LoginRequestSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=11)

    def validate_phone_number(self, value):
        return check_phone(value, self)


class LoginVerifySerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=11)
    password = serializers.CharField(max_length=128)


class RegisterOTPCheckSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=11)
    code = serializers.CharField(max_length=6)

    def validate_phone_number(self, value):
        return check_phone(value)


class RegisterVerifySerializer(serializers.ModelSerializer):
    is_manager = serializers.BooleanField(default=False)
    class Meta:
        model = CustomUser
        fields = ['phone_number', 'first_name', 'last_name', 'email', 'password', 'is_manager']
        extra_kwargs = {'password': {'write_only': True}}

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value


class CustomUserSerializer(serializers.ModelSerializer):
    successful_logins = serializers.IntegerField(read_only=True)
    class Meta:
        model = CustomUser
        include = ['__all__', 'successful_logins']
        exclude = ['password']


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['first_name', 'last_name', 'email', 'profile_picture']
