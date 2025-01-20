from django.contrib.auth import authenticate
from django.core.cache import cache

from .models import CustomUser, OTP
from .tasks import unblock_user


class FailedLoginMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST' and request.path == '/login-verify/':
            phone_number = request.POST.get('phone_number')
            password = request.POST.get('password')
            user = authenticate(request, phone_number=phone_number, password=password)
            ip = request.META.get('REMOTE_ADDR')

            if user is None:
                user = CustomUser.get_or_none(phone_number=phone_number)

                if user:
                    user_key = f'failed_login_tries_{phone_number}'
                    user_attempts = int(cache.get(user_key, 0))
                    if user_attempts == 1:
                        cache.expire(user_key, 15 * 60)
                    elif user_attempts >= 4:
                        user.is_active = False
                        user.save()
                        unblock_user.apply_async(args=[user.id], countdown=15 * 60)
                    cache.incr(user_key)
                else:
                    ip_key = f'failed_login_tries_{ip}'
                    ip_attempts = int(cache.get(ip_key, 0))
                    if ip_attempts == 0:
                        cache.expire(ip_key, 15 * 60)
                    elif ip_attempts >= 4:
                        blocked_ip_key = f'blocked_ip_{ip}'
                        cache.set(blocked_ip_key, True, countdown=60 * 60)
                        cache.delete(ip_key)
                    cache.incr(ip_key)

        response = self.get_response(request)
        return response


class FailedRegisterMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == 'POST' and request.path == '/register-otp-check/':
            phone_number = request.POST.get('phone_number')
            ip = request.META.get('REMOTE_ADDR')
            otp = request.POST.get('code')
            blocked_ip_key = f'blocked_ip_{ip}'
            is_blocked = cache.get(blocked_ip_key)
            if not is_blocked:
                registered_otp = OTP.get_or_none(phone_number=phone_number)
                if registered_otp is not None and registered_otp.otp != otp:
                    ip_key = f'failed_register_tries_{ip}'
                    ip_attempts = int(cache.get(ip_key, 0))
                    if ip_attempts == 0:
                        cache.expire(ip_key, 15 * 60)
                    elif ip_attempts >= 4:
                        cache.set(blocked_ip_key, True, countdown=60 * 60)
                    cache.incr(ip_key)

        response = self.get_response(request)

        return response
