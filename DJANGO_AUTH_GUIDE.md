# 🔐 Simple Guide: Converting Your Node.js Auth to Django

## Part 1: How Your Node.js Authentication Works (Simplified)

### The Big Picture
Think of authentication like a **two-key system** at a hotel:

1. **Refresh Token** (7 days) = Your room key card - stored safely in your wallet (browser cookie)
2. **Access Token** (15 minutes) = Temporary guest pass - shown to staff when needed

### Step-by-Step Flow

#### 🆕 When a User Registers:
1. User enters: name, email, password
2. Server scrambles the password (called "hashing") so no one can read it
3. Server saves user to database with scrambled password
4. Server creates **2 tokens**:
   - **Refresh Token**: "This person is user #5, valid for 7 days"
   - **Access Token**: "Contains the refresh token, valid for 15 minutes"
5. Server sends refresh token as a **cookie** (hidden, automatic)
6. Server sends access token to **frontend** (visible, manual)

#### 🔑 When a User Logs In:
1. User enters: email, password
2. Server finds user by email
3. Server checks if password matches the scrambled one
4. If correct: creates the same 2 tokens as registration
5. Sends them back the same way

#### 🛡️ When User Accesses Protected Pages:
1. Frontend sends access token with every request
2. Server checks: "Is this access token valid?"
   - **If YES**: Allow access
   - **If NO or EXPIRED**: Check the refresh token cookie
     - If refresh token valid: Create new access token
     - If refresh token invalid: User must log in again

#### 🚪 When User Logs Out:
1. Server deletes the refresh token cookie
2. Frontend discards the access token
3. User must log in again

---

## Part 2: What Data is Used

### User Database Fields
```
- id: Unique number for each user (auto-generated)
- name: User's full name
- email: User's email (must be unique)
- password: Scrambled/hashed password (never stored as plain text!)
- bio: User description (optional)
- avatarUrl: Profile picture link (optional)
- createdAt: When user registered
- updatedAt: When user last updated profile
```

### Tokens Explained Simply
**Tokens are like encrypted messages that contain information**

**Refresh Token contains:**
- userId: Which user this token belongs to
- Expiry: 7 days from creation

**Access Token contains:**
- refreshToken: The whole refresh token inside it!
- Expiry: 15 minutes from creation

**Secret Key:**
- Both tokens are encrypted using a secret password (AUTH_SECRET)
- Only the server knows this secret, so tokens can't be faked

---

## Part 3: Django Implementation (Step-by-Step)

### Step 1: Create Your Django Project

```bash
# Create a new Django project
mkdir my_auth_project
cd my_auth_project

# Create virtual environment
python -m venv venv

# Activate it
# On Mac/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install Django and required packages
pip install django djangorestframework djangorestframework-simplejwt django-cors-headers
```

### Step 2: Start Django Project

```bash
# Create project
django-admin startproject config .

# Create authentication app
python manage.py startapp authentication
```

### Step 3: Configure Settings (`config/settings.py`)

Add these to your settings:

```python
# At the top
from datetime import timedelta
import os

# In INSTALLED_APPS list, add:
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Add these:
    'rest_framework',
    'corsheaders',
    'authentication',
]

# In MIDDLEWARE list, add (near the top):
MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # Add this
    'django.middleware.security.SecurityMiddleware',
    # ... rest of middleware
]

# At the bottom of the file, add:

# Allow frontend to access API
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:5173",  # Your React app URL
]

# REST Framework configuration
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'authentication.authentication.CustomJWTAuthentication',
    ],
}

# JWT Settings (matches your Node.js setup)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),  # Like your Node.js
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),     # Like your Node.js
    'ROTATE_REFRESH_TOKENS': False,
    'BLACKLIST_AFTER_ROTATION': False,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_COOKIE': 'refreshToken',  # Same name as Node.js
    'AUTH_COOKIE_SECURE': True,     # Same as Node.js
    'AUTH_COOKIE_HTTP_ONLY': True,  # Same as Node.js
    'AUTH_COOKIE_SAMESITE': 'None',
}

# Secret key for tokens (CHANGE THIS!)
SECRET_KEY = 'your-secret-key-here-make-it-long-and-random'
```

### Step 4: Create User Model (`authentication/models.py`)

```python
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

class UserManager(BaseUserManager):
    """Manages user creation"""
    
    def create_user(self, email, name, password=None):
        if not email:
            raise ValueError('Users must have an email')
        if not name:
            raise ValueError('Users must have a name')
        
        user = self.model(
            email=self.normalize_email(email),
            name=name,
        )
        user.set_password(password)  # This automatically hashes the password
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    """User model - matches your Node.js user structure"""
    
    email = models.EmailField(unique=True, max_length=255)
    name = models.CharField(max_length=255)
    bio = models.TextField(blank=True, null=True)
    avatar_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Django requires these fields
    is_active = models.BooleanField(default=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'  # Login with email instead of username
    REQUIRED_FIELDS = ['name']
    
    def __str__(self):
        return self.email
    
    class Meta:
        db_table = 'users'
```

Update `config/settings.py` to use custom user:

```python
# Add at the bottom
AUTH_USER_MODEL = 'authentication.User'
```

### Step 5: Create Custom JWT Authentication (`authentication/authentication.py`)

This handles the two-token system like your Node.js code:

```python
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.conf import settings

class CustomJWTAuthentication(JWTAuthentication):
    """
    Custom authentication that works like your Node.js system:
    1. Check access token in header
    2. If expired, check refresh token in cookie
    3. If refresh valid, create new access token
    """
    
    def authenticate(self, request):
        # Get access token from header (like Node.js)
        header = self.get_header(request)
        
        if header is None:
            return None
        
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        
        # Try to validate access token
        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
            return (user, validated_token)
            
        except Exception:
            # Access token expired, check refresh token in cookie
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])
            
            if not refresh_token:
                return None
            
            try:
                # Validate refresh token
                refresh = RefreshToken(refresh_token)
                user = self.get_user(refresh.access_token)
                
                # Create new access token
                new_access = refresh.access_token
                
                # Store new access token in request for response
                request.new_access_token = str(new_access)
                
                return (user, new_access)
                
            except Exception:
                return None
        
        return None
```

### Step 6: Create Serializers (`authentication/serializers.py`)

Serializers convert Python objects to JSON (like validation in Node.js):

```python
from rest_framework import serializers
from .models import User

class UserSerializer(serializers.ModelSerializer):
    """Converts User object to JSON (without password)"""
    
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'bio', 'avatar_url', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class RegisterSerializer(serializers.ModelSerializer):
    """Validates registration data"""
    
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        error_messages={'min_length': 'Password must be at least 8 characters long'}
    )
    
    class Meta:
        model = User
        fields = ['name', 'email', 'password']
    
    def validate_email(self, value):
        """Check if email already exists"""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "This email is already registered. Please try logging in instead."
            )
        return value
    
    def create(self, validated_data):
        """Create user with hashed password"""
        user = User.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        return user

class LoginSerializer(serializers.Serializer):
    """Validates login data"""
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

class ChangeEmailSerializer(serializers.Serializer):
    """Validates email change"""
    
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

class ChangePasswordSerializer(serializers.Serializer):
    """Validates password change"""
    
    current_password = serializers.CharField(write_only=True, min_length=8)
    new_password = serializers.CharField(write_only=True, min_length=8)
```

### Step 7: Create Views/Routes (`authentication/views.py`)

Views handle requests (like your Node.js router):

```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.conf import settings
from .models import User
from .serializers import (
    UserSerializer, 
    RegisterSerializer, 
    LoginSerializer,
    ChangeEmailSerializer,
    ChangePasswordSerializer
)

class RegisterView(APIView):
    """Register new user - matches your Node.js register"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        # Validate input data
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create user (password is automatically hashed)
        user = serializer.save()
        
        # Create tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Prepare response
        response = Response({
            'accessToken': access_token,
            'user': UserSerializer(user).data
        }, status=status.HTTP_201_CREATED)
        
        # Set refresh token as httpOnly cookie (like Node.js)
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=str(refresh),
            max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        return response

class LoginView(APIView):
    """Login user - matches your Node.js login"""
    permission_classes = [AllowAny]
    
    def post(self, request):
        # Validate input
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        
        # Find user
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'error': 'Invalid email or password. Please try again.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Check password
        if not user.check_password(password):
            return Response(
                {'error': 'Invalid email or password. Please try again.'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Create tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Prepare response
        response = Response({
            'accessToken': access_token,
            'user': UserSerializer(user).data
        })
        
        # Set refresh token cookie
        response.set_cookie(
            key=settings.SIMPLE_JWT['AUTH_COOKIE'],
            value=str(refresh),
            max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
            secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
            httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
            samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
        )
        
        return response

class LogoutView(APIView):
    """Logout user - matches your Node.js logout"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        response = Response({'message': 'Logged out successfully'})
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
        return response

class CurrentUserView(APIView):
    """Get current logged-in user - matches your Node.js currentUser"""
    permission_classes = [AllowAny]
    
    def get(self, request):
        if request.user.is_authenticated:
            # Check if we have a new access token from auth middleware
            new_access_token = getattr(request, 'new_access_token', None)
            
            return Response({
                'accessToken': new_access_token if new_access_token else None,
                'currentUser': UserSerializer(request.user).data
            })
        
        return Response({
            'accessToken': None,
            'currentUser': None
        })

class ChangeEmailView(APIView):
    """Change user email - matches your Node.js changeEmail"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangeEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Verify current password
        if not request.user.check_password(serializer.validated_data['password']):
            return Response(
                {'error': 'Invalid password'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Update email
        request.user.email = serializer.validated_data['email']
        request.user.save()
        
        return Response({'success': True})

class ChangePasswordView(APIView):
    """Change user password - matches your Node.js changePassword"""
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Verify current password
        if not request.user.check_password(serializer.validated_data['current_password']):
            return Response(
                {'error': 'Invalid password'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Set new password (automatically hashed)
        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        
        return Response({'success': True})
```

### Step 8: Create URLs (`authentication/urls.py`)

Create this new file:

```python
from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    CurrentUserView,
    ChangeEmailView,
    ChangePasswordView,
)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('current-user/', CurrentUserView.as_view(), name='current-user'),
    path('change-email/', ChangeEmailView.as_view(), name='change-email'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),
]
```

Update `config/urls.py`:

```python
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')),  # Add this
]
```

### Step 9: Create and Run Database

```bash
# Create database tables
python manage.py makemigrations
python manage.py migrate

# Create admin user (optional)
python manage.py createsuperuser
```

### Step 10: Run Server

```bash
python manage.py runserver
```

Your API is now running at: `http://localhost:8000`

---

## Part 4: Node.js vs Django Comparison

| Concept | Node.js (Your Project) | Django Equivalent |
|---------|------------------------|-------------------|
| **Password Hashing** | `bcrypt.hash(password, 12)` | `user.set_password(password)` |
| **Password Verification** | `bcrypt.compare(password, hash)` | `user.check_password(password)` |
| **Creating Tokens** | `jwt.sign(payload, secret, options)` | `RefreshToken.for_user(user)` |
| **Verifying Tokens** | `jwt.verify(token, secret)` | `RefreshToken(token)` |
| **Routes/Endpoints** | tRPC router procedures | Django Views (APIView) |
| **Validation** | Zod schemas | Django Serializers |
| **Database Models** | Drizzle ORM tables | Django Models |
| **Protected Routes** | `protectedProcedure` | `permission_classes = [IsAuthenticated]` |
| **Public Routes** | `publicProcedure` | `permission_classes = [AllowAny]` |
| **Database Queries** | `db.query.usersTable.findFirst()` | `User.objects.get()` |
| **Setting Cookies** | `res.cookie('name', value, options)` | `response.set_cookie(key, value, options)` |

---

## Testing Your API

### Register a User
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{"name": "John Doe", "email": "john@example.com", "password": "password123"}'
```

### Login
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"email": "john@example.com", "password": "password123"}' \
  -c cookies.txt
```

### Get Current User (with access token)
```bash
curl -X GET http://localhost:8000/api/auth/current-user/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -b cookies.txt
```

### Logout
```bash
curl -X POST http://localhost:8000/api/auth/logout/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -b cookies.txt
```

---

## Key Differences Summary

### What's the Same:
✅ Two-token system (access + refresh)
✅ Same token lifetimes (15 min + 7 days)
✅ Password hashing (secure)
✅ Cookie-based refresh tokens
✅ Header-based access tokens
✅ Same user fields

### What's Different:
🔄 Django uses built-in features for auth (Node.js uses external libraries)
🔄 Django has more "magic" (automatic features)
🔄 Node.js requires more manual setup
🔄 Django uses classes (Views), Node.js uses functions (procedures)

---

## Need Help?

Common issues:

1. **CORS errors**: Make sure `CORS_ALLOWED_ORIGINS` includes your frontend URL
2. **Cookie not being set**: Check `SECURE=True` requires HTTPS (use `False` for local development)
3. **Token expired**: This is normal, the refresh token should auto-renew it
4. **Can't login**: Make sure password is at least 8 characters

---

## Quick Start Checklist

- [ ] Install Django and packages
- [ ] Create project and app
- [ ] Update settings.py
- [ ] Create User model
- [ ] Create authentication classes
- [ ] Create serializers
- [ ] Create views
- [ ] Create URLs
- [ ] Run migrations
- [ ] Test with Postman or curl

---

**You now have the exact same authentication system in Django! 🎉**
