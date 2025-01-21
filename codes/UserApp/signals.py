from django.contrib.auth import user_logged_in
from django.dispatch import receiver
from .models import UserLogins


@receiver(user_logged_in)
def increment_successful_logins(sender, request, user, **kwargs):
    user_logins, created = UserLogins.objects.get_or_create(user=user)
    user_logins.successful_logins += 1
    user_logins.save()