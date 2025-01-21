# مستندات سیستم ثبت نام و احراز هویت با استفاده از DRF

این مستندات به تفصیل ساختار و عملکرد API احراز هویت کاربر پیاده‌سازی شده با استفاده از Django REST Framework (DRF) را شرح می‌دهد. این توضیحات شامل بررسی اجزای اصلی پروژه، از جمله مدل‌ها، سریالایزرها، نماها (views)، URLها و Middlewareها است که عملکرد صحیح و ایمن سیستم را تضمین می‌کند. این مستندات می‌تواند به شما کمک کند تا API را به درستی استفاده کنید یا آن را به سیستم‌های دیگر یکپارچه کنید.

## توضیحات کلی

این پروژه برای مدیریت احراز هویت کاربران طراحی شده است و شامل ویژگی‌هایی مانند ثبت‌نام کاربر، ورود، تأیید OTP، و مدیریت داده‌های کاربران است. این سیستم به طور ویژه برای امنیت بیشتر از کدهای OTP (رمز یکبار مصرف) استفاده می‌کند و قابلیت‌های مختلفی برای مدیریت کاربران توسط مدیران فراهم می‌آورد.

## ساختار پروژه

### 1. مدل‌ها (`models.py`)

- **CustomUser**: این مدل از مدل پیش‌فرض کاربر Django (User) گسترش یافته و فیلدهای اضافی نظیر شماره تلفن، ایمیل، تصویر پروفایل و نقش‌های مختلف کاربری (مانند کاربر فوق‌العاده، مدیر) را شامل می‌شود.
- **OTP**: مدل OTP برای ذخیره و مدیریت کدهای یکبار مصرف مورد استفاده در فرآیندهای احراز هویت کاربر و تأیید هویت در مراحل ثبت‌نام و ورود به سیستم طراحی شده است.
- **UserLogins**: این مدل برای پیگیری تعداد دفعات ورود موفق هر کاربر به سیستم مورد استفاده قرار می‌گیرد.

### 2. سریالایزرها (`serializers.py`)

- **LoginRequestSerializer**: وظیفه این سریالایزر، اعتبارسنجی درخواست‌های ورود کاربران است که در آن شماره تلفن ورودی کاربر بررسی می‌شود.
- **LoginVerifySerializer**: این سریالایزر برای بررسی صحت داده‌های ورودی در فرآیند ورود شامل شماره تلفن و رمز عبور طراحی شده است.
- **RegisterOTPCheckSerializer**: برای تأیید کد OTP ارسال شده در طول فرآیند ثبت‌نام استفاده می‌شود.
- **RegisterVerifySerializer**: این سریالایزر مسئول بررسی و پردازش اطلاعات در مراحل نهایی ثبت‌نام کاربر است.
- **CustomUserSerializer**: این سریالایزر برای سریالیز کردن اطلاعات کاربر به جز رمز عبور طراحی شده است.
- **UserUpdateSerializer**: وظیفه این سریالایزر به‌روزرسانی اطلاعات کاربر شامل نام، ایمیل و تصویر پروفایل است.

### 3. URLها (`urls.py`)

این فایل مسئول تعریف مسیرهای مختلف برای دسترسی به API‌های مختلف است:
- `login-request/`: این مسیر مسئول مدیریت درخواست‌های اولیه ورود است که شامل ارسال OTP در صورت نیاز به کاربر می‌شود.
- `login-verify/`: این مسیر وظیفه تأیید اعتبار اطلاعات ورودی (شماره تلفن و رمز عبور) را بر عهده دارد.
- `register-otp-check/`: این مسیر برای بررسی کد OTP دریافتی در فرآیند ثبت‌نام طراحی شده است.
- `register-verify/`: مسیر نهایی ثبت‌نام که برای تکمیل فرآیند ثبت‌نام کاربر از آن استفاده می‌شود.
- `users-management/`: این مسیر برای مدیریت داده‌های کاربران و دسترسی‌های مختلف آن‌ها، به‌ویژه برای مدیران سیستم، طراحی شده است.
- `users-list-with-logins-count/`: این مسیر فهرستی از کاربران به همراه تعداد دفعات ورود موفق آن‌ها را نمایش می‌دهد.
- `user-update/`: این مسیر به کاربران اجازه می‌دهد تا اطلاعات پروفایل خود را به‌روزرسانی کنند.

### 4. نماها (`views.py`)

نماها مسئول پیاده‌سازی لاجیک API‌ها در قالب کلاس‌های DRF هستند:
- **LoginRequest**: این نما درخواست ورود کاربر را می‌پذیرد و در صورتی که کاربر قبلاً ثبت‌نام نکرده باشد، یک OTP برای وی ارسال می‌کند.
- **LoginVerify**: این نما مسئول تأیید اطلاعات ورود (شماره تلفن و رمز عبور) است و در صورت موفقیت توکن به کاربر باز می‌گرداند.
- **RegisterOTPCheck**: این نما برای بررسی و تأیید OTP در مرحله ثبت‌نام طراحی شده است.
- **RegisterVerify**: پس از تأیید OTP، این نما اطلاعات کاربر را پردازش کرده و ثبت‌نام را تکمیل می‌کند.
- **UsersManagement**: این نما برای انجام عملیات CRUD (ایجاد، خواندن، به‌روزرسانی و حذف) بر روی داده‌های کاربران، به‌ویژه برای مدیران سیستم طراحی شده است.
- **UsersListWithLoginsCount**: این نما فهرستی از کاربران را همراه با تعداد ورودهای موفق آن‌ها برمی‌گرداند.
- **UserUpdate**: این نما به کاربران اجازه می‌دهد تا اطلاعات پروفایل خود را به‌روزرسانی کنند.

### 5. Middleware (`middleware.py`)

- **FailedLoginMiddleware**: این middleware برای پیگیری تلاش‌های ناموفق ورود به سیستم طراحی شده است و به‌منظور جلوگیری از حملات brute-force، پس از چندین تلاش ناموفق، دسترسی کاربر یا IP را مسدود می‌کند.
- **FailedRegisterMiddleware**: این middleware تلاش‌های ناموفق برای تأیید OTP در طول فرآیند ثبت‌نام را مانیتور می‌کند و پس از چندین تلاش ناموفق، IP کاربران را مسدود می‌کند.

## روند کاری

### 1. ورود به سیستم:
   - **مرحله اول**: کاربر شماره تلفن خود را به نقطه پایانی `login-request/` ارسال می‌کند. در صورت ثبت‌نام بودن کاربر، یک OTP به وی ارسال می‌شود.
   - **مرحله دوم**: کاربر پس از دریافت OTP آن را به همراه شماره تلفن و رمز عبور خود در نقطه پایانی `login-verify/` ارسال می‌کند و در صورت تأیید موفقیت‌آمیز، یک توکن دسترسی دریافت می‌کند.

### 2. ثبت‌نام:
   - **مرحله اول**: در هنگام ثبت‌نام، کاربر کدی OTP دریافت می‌کند که آن را باید در مرحله بعدی تأیید کند.
   - **مرحله دوم**: کاربر پس از دریافت و تأیید OTP، اطلاعات خود را به همراه OTP در نقطه پایانی `register-verify/` ارسال می‌کند و حساب کاربری وی ایجاد می‌شود.

### 3. مدیریت کاربران:
   - مدیران می‌توانند از طریق نقطه پایانی `users-management/` عملیات CRUD را برای مدیریت حساب‌های کاربری انجام دهند.
   - کاربران معمولی نیز می‌توانند از نقطه پایانی `user-update/` برای به‌روزرسانی اطلاعات پروفایل خود استفاده کنند.

## نتیجه‌گیری

این API به کاربران امکان ثبت‌نام و ورود ایمن با استفاده از تأیید هویت OTP را فراهم می‌کند و ابزار مناسبی برای مدیران سیستم برای مدیریت کاربران و داده‌های آن‌ها است. علاوه بر این، استفاده از middleware ها برای نظارت و مسدودسازی تلاش‌های ناموفق، امنیت بیشتری به سیستم اضافه می‌کند. این مستندات به عنوان راهنمایی جامع برای توسعه‌دهندگان جهت استفاده صحیح از API و یکپارچه‌سازی آن با سایر سیستم‌ها به کار می‌رود.





# README for User Authentication API with Django REST Framework

This document details the structure and functionality of a user authentication API implemented using Django REST Framework (DRF). It covers the main components of the application, such as models, serializers, views, URLs, and middleware, providing a comprehensive understanding of the project's functionality.

## Overview

The project is structured to handle user authentication with features like user registration, login, OTP verification, and user management. It leverages DRF's capabilities to ensure secure and efficient handling of user data.

## Project Structure

### 1. Models (`models.py`)

- **CustomUser**: Extends Django's user model to include fields like phone number, email, profile picture, and roles (superuser, manager).
- **OTP**: Manages One-Time Passwords for verifying user identities during registration and login.
- **UserLogins**: Tracks the number of successful logins for each user.

### 2. Serializers (`serializers.py`)

- **LoginRequestSerializer**: Validates login requests by checking the phone number's format.
- **LoginVerifySerializer**: Validates login credentials, including phone number and password.
- **RegisterOTPCheckSerializer**: Validates the OTP sent during the registration process.
- **RegisterVerifySerializer**: Validates and processes data during user registration.
- **CustomUserSerializer**: Serializes user information, excluding passwords.
- **UserUpdateSerializer**: Handles updates to user information such as name, email, and profile picture.

### 3. URLs (`urls.py`)

Defines routes for API endpoints:
- `login-request/`: Handles initial login requests.
- `login-verify/`: Verifies user credentials post-login attempt.
- `register-otp-check/`: Checks and verifies the OTP during registration.
- `register-verify/`: Completes the user registration process.
- `users-management/`: Manages user data through a router, primarily for admin use.
- `users-list-with-logins-count/`: Lists users along with their login counts.
- `user-update/`: Allows users to update their profile information.

### 4. Views (`views.py`)

Implements API endpoints using DRF's view classes:
- **LoginRequest**: Initiates a login attempt, sending an OTP if the user is not yet registered.
- **LoginVerify**: Verifies user login by checking credentials and returns a token if successful.
- **RegisterOTPCheck**: Validates OTP for user registration.
- **RegisterVerify**: Completes the user registration with validated data.
- **UsersManagement**: Handles CRUD operations for user records.
- **UsersListWithLoginsCount**: Retrieves a sorted list of users based on login activity.
- **UserUpdate**: Allows authenticated users to update their own profile.

### 5. Middleware (`middleware.py`)

- **FailedLoginMiddleware**: Tracks failed login attempts to prevent brute-force attacks, blocking users or IPs after multiple failures.
- **FailedRegisterMiddleware**: Monitors failed OTP verifications during registration, blocking IPs after several incorrect attempts.

## Functionality

1. **Login Sequence**:
   - **Step 1**: User sends a phone number to `login-request/`. If they are registered, an OTP is generated and sent.
   - **Step 2**: User verifies their login with the OTP via `login-verify/`, receiving a token upon success.

2. **Registration Sequence**:
   - **Step 1**: User receives an OTP during registration via `register-otp-check/`.
   - **Step 2**: User submits verified data, including OTP, to `register-verify/` to create an account.

3. **User Management**:
   - Admins can manage user accounts through `users-management/`, excluding deletion.
   - Regular users can update their profiles via `user-update/`.

## Conclusion

This API facilitates secure user registration and login using OTP verification, with robust management features for administrators. The inclusion of custom middleware enhances security by monitoring and mitigating unauthorized attempts. This documentation serves as a guide to understanding and utilizing the API effectively for both development and integration purposes.