from django.core.cache import cache
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase
from rest_framework import status
from .models import CustomUser, OTP


class UserTestCase(APITestCase):

    def setUp(self):
        self.user = CustomUser.objects.create_user(phone_number='09123456789', first_name='john', last_name='doe',
                                                   email='ychag@example.com', password='12345678', )
        self.superuser = CustomUser.objects.create_superuser(phone_number='09123456780', first_name='jack',
                                                             last_name='doe', email='abcde@example.com',
                                                             password='12345678', )

    def tearDown(self):
        cache.clear()

    def test_login_request_user_exist(self):
        response = self.client.post('/login-request/', {'phone_number': '09123456789'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message': 'User exists and can login'})

    def test_login_request_user_not_exist(self):
        response = self.client.post('/login-request/', {'phone_number': '09123456781'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message': 'otp sent to user'})

    def test_login_verify_user_exist(self):
        response = self.client.post('/login-verify/', {'phone_number': '09123456789', 'password': '12345678'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Token.objects.get(user=self.user).key, response.data['token'])

    def test_login_verify_with_wrong_password(self):
        for _ in range(4):
            response = self.client.post('/login-verify/', {'phone_number': '09123456789', 'password': '123456789'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {'message': 'User is blocked'})

    def test_login_verify_user_not_exist(self):
        for _ in range(4):
            response = self.client.post('/login-verify/', {'phone_number': '09123456781', 'password': '12345678'})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data, {'message': 'IP is blocked'})

    def test_register_otp_check(self):
        response = self.client.post('/login-request/', {'phone_number': '09123456785'})
        otp = OTP.objects.get(phone_number='09123456785').otp
        response = self.client.post('/register-otp-check/', {'phone_number': '09123456785', 'code': otp})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, {'message': 'OTP verified'})

    def test_register_verify(self):
        user_data = {'phone_number': '09123456793', 'first_name': 'test', 'last_name': 'test',
                     'email': 'asdfg@example.com',  'password': 'AbA@12345'}
        response = self.client.post('/register-verify/', user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(CustomUser.objects.filter(phone_number='09123456793').exists(), True)
