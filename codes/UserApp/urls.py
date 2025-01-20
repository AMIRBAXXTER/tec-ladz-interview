from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import *

app_name = 'UserApp'

manager_router = DefaultRouter()
manager_router.register('', UsersManagement, basename='users')

urlpatterns = [
    path('login-request/', LoginRequest.as_view(), name='login request'),
    path('login-verify/', LoginVerify.as_view(), name='login verify'),
    path('register-otp-check/', RegisterOTPCheck.as_view(), name='register otp check'),
    path('register-verify/', RegisterVerify.as_view(), name='register verify'),
    path('users-management/', include(manager_router.urls), name='users management'),
    path('users-list-with-logins-count/', UsersListWithLoginsCount.as_view(), name='users list with logins count'),
    path('update/', UserUpdate.as_view(), name='update'),
]
