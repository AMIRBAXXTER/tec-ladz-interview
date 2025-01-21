from drf_spectacular.utils import extend_schema, OpenApiResponse, OpenApiParameter, OpenApiExample
from django.contrib.auth.signals import user_logged_in
from rest_framework import status, viewsets, generics
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CustomUser, OTP
from .permissions import IsManager, IsOwner
from .serializers import *
from .tasks import send_sms
from .utils import check_block_status


# Create your views here.


class LoginRequest(APIView):

    @extend_schema(
        request=LoginRequestSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="User exists and can login or OTP sent",
                examples=[
                    OpenApiExample(
                        'Existing User',
                        value={'message': 'User exists and can login'},
                        status_codes=[status.HTTP_200_OK]
                    ),
                    OpenApiExample(
                        'OTP Sent',
                        value={'message': 'otp sent to user'},
                        response_only=True,
                        status_codes=[status.HTTP_200_OK]
                    )
                ]
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid request payload",
                examples=[
                    OpenApiExample(
                        'Invalid Payload',
                        value={'phone_number': ['This field is required.']},
                        response_only=True,
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    )
                ]
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                description="User is blocked",
                examples=[
                    OpenApiExample(
                        'Blocked User',
                        value={'message': 'User is blocked'},
                        response_only=True,
                        status_codes=[status.HTTP_403_FORBIDDEN]
                    )
                ]
            ),
        },
        summary='Login or generate OTP',
        description=(
                "This endpoint is used for user login. If the user exists, "
                "they can login. If not, an OTP will be sent to their phone number."
        )
    )
    def post(self, request):

        response = check_block_status(request)
        if response:
            return response

        serializer = LoginRequestSerializer(data=request.data)
        if serializer.is_valid():
            sv = serializer.validated_data
            user = CustomUser.get_or_none(phone_number=sv['phone_number'])
            if user:
                return Response({'message': 'User exists and can login'}, status=status.HTTP_200_OK)
            new_otp = OTP.objects.create(phone_number=sv['phone_number'])
            send_sms.apply_async(args=[new_otp.phone_number, 'Your OTP is: ' + new_otp.otp])
            return Response({'message': 'otp sent to user'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginVerify(APIView):
    @extend_schema(
        request=LoginVerifySerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="Successful login, token generated",
                examples=[
                    OpenApiExample(
                        'Successful Login',
                        value={'token': 'some_token_value_here'},
                        status_codes=[status.HTTP_200_OK]
                    )
                ]
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid request payload",
                examples=[
                    OpenApiExample(
                        'Invalid Payload',
                        value={'phone_number': ['This field is required.'], 'password': ['This field is required.']},
                        response_only=True,
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    )
                ]
            ),
            status.HTTP_404_NOT_FOUND: OpenApiResponse(
                description="User not found or incorrect credentials",
                examples=[
                    OpenApiExample(
                        'Incorrect Credentials',
                        value={'error': 'Phone number or password is wrong'},
                        status_codes=[status.HTTP_404_NOT_FOUND]
                    )
                ]
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                description="User is blocked",
                examples=[
                    OpenApiExample(
                        'Blocked User',
                        value={'error': 'User is blocked'},
                        response_only=True,
                        status_codes=[status.HTTP_403_FORBIDDEN]
                    )
                ]
            ),
        },
        summary='Verify user login and generate authentication token',
        description=(
                "This endpoint is used for verifying a user's phone number and password. "
                "If the credentials are correct, a token will be returned for authentication. "
                "If the user is blocked, or the credentials are incorrect, an appropriate error message will be returned."
        )
    )
    def post(self, request):

        response = check_block_status(request)
        if response:
            return response

        serializer = LoginVerifySerializer(data=request.data)
        if serializer.is_valid():
            sv = serializer.validated_data
            user = authenticate(request, username=sv['phone_number'], password=sv['password'])

            if not user:
                return Response({'error': 'Phone number or password is wrong'}, status=status.HTTP_404_NOT_FOUND)

            token, created = Token.objects.get_or_create(user=user)

            if created:
                user_logged_in.send(sender=user.__class__, request=request, user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterOTPCheck(APIView):
    @extend_schema(
        request=RegisterOTPCheckSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="OTP verified successfully",
                examples=[
                    OpenApiExample(
                        'Successful OTP Verification',
                        value={'message': 'OTP verified'},
                        status_codes=[status.HTTP_200_OK]
                    )
                ]
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid request or OTP",
                examples=[
                    OpenApiExample(
                        'Incorrect OTP',
                        value={'message': 'OTP is not correct'},
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    ),
                    OpenApiExample(
                        'No OTP Exists',
                        value={'massage': 'no OTP exists'},
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    ),
                    OpenApiExample(
                        'Invalid Payload',
                        value={'phone_number': ['This field is required.'], 'code': ['This field is required.']},
                        response_only=True,
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    )
                ]
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                description="User is blocked",
                examples=[
                    OpenApiExample(
                        'Blocked User',
                        value={'error': 'User is blocked'},
                        response_only=True,
                        status_codes=[status.HTTP_403_FORBIDDEN]
                    )
                ]
            ),
        },
        summary='Verify OTP for registration',
        description=(
                "This endpoint verifies the OTP (One-Time Password) sent to the user's phone number. "
                "It checks the validity of the OTP and confirms the user's registration process."
        )
    )
    def post(self, request):

        response = check_block_status(request, is_registered=False)
        if response:
            return response

        serializer = RegisterOTPCheckSerializer(data=request.data)
        if serializer.is_valid():
            sv = serializer.validated_data
            otp = OTP.get_or_none(phone_number=sv['phone_number'])
            if otp:
                if otp.otp == sv['code'] and otp.is_valid:
                    otp.delete()
                    return Response({'message': 'OTP verified'}, status=status.HTTP_200_OK)

                return Response({'message': 'OTP is not correct'}, status=status.HTTP_400_BAD_REQUEST)
            return Response({'massage': 'no OTP exists'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterVerify(APIView):
    @extend_schema(
        request=RegisterVerifySerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                description="User created successfully",
                examples=[
                    OpenApiExample(
                        'User Creation Success',
                        value={'message': 'User created',
                               'user': {'phone_number': '123456789', 'first_name': 'John', 'last_name': 'Doe',
                                        'email': 'john.doe@example.com', 'password': '********', 'is_manager': False}},
                        status_codes=[status.HTTP_200_OK]
                    )
                ]
            ),
            status.HTTP_400_BAD_REQUEST: OpenApiResponse(
                description="Invalid request payload",
                examples=[
                    OpenApiExample(
                        'Invalid Data',
                        value={'phone_number': ['This field must be unique.'], 'email': ['This field is required.']},
                        response_only=True,
                        status_codes=[status.HTTP_400_BAD_REQUEST]
                    )
                ]
            ),
            status.HTTP_403_FORBIDDEN: OpenApiResponse(
                description="User is blocked",
                examples=[
                    OpenApiExample(
                        'Blocked User',
                        value={'error': 'User is blocked'},
                        response_only=True,
                        status_codes=[status.HTTP_403_FORBIDDEN]
                    )
                ]
            ),
        },
        summary='Register a new user',
        description=(
                "This endpoint is for registering a new user with details like phone number, first name, last name, email, "
                "and password. If the `is_manager` flag is set, the user will be created as a superuser."
        )
    )
    def post(self, request):

        response = check_block_status(request, is_registered=False)
        if response:
            return response

        serializer = RegisterVerifySerializer(data=request.data)
        if serializer.is_valid():
            sv = serializer.validated_data
            user_data = {'phone_number': sv['phone_number'],
                         'first_name': sv['first_name'],
                         'last_name': sv['last_name'],
                         'email': sv['email'],
                         'password': sv['password'],
                         }
            if sv['is_manager']:
                CustomUser.objects.create_superuser(**user_data)
            CustomUser.objects.create_user(**user_data)
            return Response({'message': 'User created', 'user': serializer.data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersManagement(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsManager]

    def destroy(self, request, *args, **kwargs):
        return Response({'message': 'Method delete is not allowed'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class UsersListWithLoginsCount(generics.ListAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsManager]

    def get_queryset(self):
        users = CustomUser.objects.raw("""
                SELECT *, ul.successful_logins
                FROM "UserApp_customuser" u
                LEFT JOIN "UserApp_userlogins" ul ON u.id = ul.user_id
                ORDER BY successful_logins DESC
            """)
        return users


class UserUpdate(generics.UpdateAPIView):
    permission_classes = [IsAuthenticated, IsOwner]
    serializer_class = UserUpdateSerializer

    def get_object(self):
        return self.request.user
