from rest_framework import serializers, status
from rest_framework.response import Response
from django.core.cache import cache
from .models import CustomUser


def check_phone(phone_number, self=None):
    message = []
    if len(phone_number) != 11:
        message.append('phone number must be 11 digit')
    if not phone_number.startswith('09'):
        message.append('phone number must start with 09')
    if not phone_number.isdigit():
        message.append('phone number must include only digits')
    if message:
        raise serializers.ValidationError(message)
    return phone_number


def check_block_status(request, is_registered=True):
    if is_registered:
        user = CustomUser.get_or_none(phone_number=request.data.get('phone_number'))
        if user and not user.is_active:
            return Response({'message': 'User is blocked'}, status=status.HTTP_403_FORBIDDEN)
    blocked_ip_key = f'blocked_ip_{request.META.get("REMOTE_ADDR")}'
    is_blocked = cache.get(blocked_ip_key)
    if is_blocked:
        return Response({'message': 'IP is blocked'}, status=status.HTTP_400_BAD_REQUEST)
