# Generated by Django 5.1.5 on 2025-01-20 17:56

import UserApp.mixins
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='OTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone_number', models.CharField(max_length=11, null=True, verbose_name='شماره تماس')),
                ('otp', models.CharField(blank=True, max_length=6, null=True, verbose_name='کد تایید')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            bases=(models.Model, UserApp.mixins.GetOrNoneMixin),
        ),
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('phone_number', models.CharField(max_length=11, unique=True, verbose_name='شماره تماس')),
                ('first_name', models.CharField(max_length=255, verbose_name='نام')),
                ('last_name', models.CharField(max_length=255, verbose_name='نام خانوادگی')),
                ('email', models.EmailField(max_length=255, unique=True, verbose_name='ایمیل')),
                ('profile_picture', models.ImageField(blank=True, null=True, upload_to='profile_pictures', verbose_name='تصویر پروفایل')),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_manager', models.BooleanField(default=False)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
            bases=(models.Model, UserApp.mixins.GetOrNoneMixin),
        ),
    ]
