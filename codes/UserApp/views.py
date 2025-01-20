from django.db import connection
from rest_framework import status, viewsets, generics
from rest_framework.authtoken.models import Token
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from .models import CustomUser, OTP
from .utils import check_block_status
from .tasks import send_sms
from .permissions import IsManager


# Create your views here.


class LoginRequest(APIView):
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
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterOTPCheck(APIView):
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
    def post(self, request):

        response = check_block_status(request, is_registered=False)
        if response:
            return response

        serializer = RegisterVerifySerializer(data=request.data)
        if serializer.is_valid():
            sv = serializer.validated_data
            user = CustomUser.objects.create(
                phone_number=sv['phone_number'],
                first_name=sv['first_name'],
                last_name=sv['last_name'],
            )
            password = sv['password']
            user.set_password(password)
            user.save()
            return Response({'message': 'User created', 'user': serializer.data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UsersManagement(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsManager]

    def destroy(self, request, *args, **kwargs):
        return Response({'message': 'Not allowed to delete'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


class UsersListWithLoginsCount(generics.ListAPIView):
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated, IsManager]

    def get_queryset(self):
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT users.id, users.phone_number, users.first_name, users.last_name, users.email, users.profile_picture, users.is_superuser, users.is_manager, COUNT(logins.id) as logins_count
                FROM users
                LEFT JOIN logins ON users.id = logins.user_id
                GROUP BY users.id
                ORDER BY logins_count DESC
            """)
            return cursor.fetchall()


class UserUpdate(APIView):

    def put(self, request):
        serializer = UserUpdateSerializer(instance=request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User updated'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
