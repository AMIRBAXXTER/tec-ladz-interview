from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin, Group
from django.db import models
from django.utils import timezone
import random

from .mixins import GetOrNoneMixin


# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('The phone number must be set')
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password, **extra_fields):
        user = self.create_user(phone_number, password, **extra_fields)
        user.is_manager = True
        user.is_superuser = True
        manager_group, created = Group.objects.get_or_create(name='manager')
        user.groups.add(manager_group)
        user.save(using=self._db)
        return user


class CustomUser(AbstractBaseUser, PermissionsMixin, GetOrNoneMixin):
    phone_number = models.CharField(max_length=11, unique=True, verbose_name='شماره تماس')
    first_name = models.CharField(max_length=255, verbose_name='نام')
    last_name = models.CharField(max_length=255, verbose_name='نام خانوادگی')
    email = models.EmailField(max_length=255, unique=True, verbose_name='ایمیل')
    profile_picture = models.ImageField(upload_to='profile_pictures', null=True, blank=True,
                                        verbose_name='تصویر پروفایل')
    is_superuser = models.BooleanField(default=False)
    is_manager = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'phone_number'

    def __str__(self):
        return self.phone_number

    objects = CustomUserManager()


class UserLogins(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    successful_logins = models.IntegerField(default=0)


class OTP(models.Model, GetOrNoneMixin):
    phone_number = models.CharField(max_length=11, null=True, verbose_name='شماره تماس')
    otp = models.CharField(max_length=6, null=True, blank=True, verbose_name='کد تایید')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.phone_number

    def save(self, *args, **kwargs):
        old_otp = OTP.get_or_none(phone_number=self.phone_number)
        if old_otp:
            old_otp.delete()
        self.otp = str(random.randint(100000, 999999))
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() - self.created_at < timezone.timedelta(minutes=5)
