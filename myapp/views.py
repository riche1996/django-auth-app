from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse, HttpResponse
from django.utils.html import escape
from django.utils import timezone
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as PasswordValidationError
import json
import logging
from datetime import timedelta

# Set up logging for security events
logger = logging.getLogger(__name__)


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """Handle user login with username/ID"""
    if request.method == "POST":
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password:
            messages.error(request, 'Please provide both username and password.')
            return redirect('login')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, f'Welcome back, {escape(user.username)}!')
            logger.info(f"Successful login for user: {user.username}")
            return redirect('home')
        else:
            # Generic error message to prevent user enumeration
            messages.error(request, 'Invalid login credentials.')
            logger.warning(f"Failed login attempt for username: {username}")
            return redirect('login')

    return render(request, 'login.html')


@require_http_methods(["GET", "POST"])
@csrf_protect
def signup_view(request):
    """Handle user registration"""
    if request.method == "POST":
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        password_confirm = request.POST.get('password_confirm', '')

        if not all([username, email, password, password_confirm]):
            messages.error(request, 'All fields are required.')
            return redirect('signup')

        if password != password_confirm:
            messages.error(request, 'Passwords do not match.')
            return redirect('signup')

        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
            return redirect('signup')

        # Use Django's built-in password validation
        try:
            validate_password(password)
        except PasswordValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return redirect('signup')

        # Generic error message to prevent user enumeration
        if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
            messages.error(request, 'Registration failed. Please try different credentials.')
            return redirect('signup')

        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            logger.info(f"New user registered: {username}")
            messages.success(request, 'Account created successfully! Please login.')
            return redirect('login')
        except Exception as e:
            logger.error(f"Registration error for username {username}: {str(e)}")
            messages.error(request, 'An error occurred during registration. Please try again.')
            return redirect('signup')

    return render(request, 'signup.html')


@login_required(login_url='login')
def home(request):
    """Home page for logged-in users"""
    return render(request, 'home.html', {'user': request.user})


@login_required(login_url='login')
def profile_view(request):
    """User profile page - requires authentication"""
    return render(request, 'profile.html', {'user': request.user})


@require_http_methods(["POST"])
@csrf_protect
def logout_view(request):
    """Handle user logout"""
    username = request.user.username
    logout(request)
    logger.info(f"User logged out: {username}")
    messages.success(request, 'You have been logged out successfully.')
    return redirect('login')


def about(request):
    return render(request, 'about.html')


# ============ ADDITIONAL FIXED ENDPOINTS ============

@login_required(login_url='login')
def user_api(request, user_id):
    """API endpoint to get user data"""
    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid user ID'}, status=400)
    
    # Authorization check to prevent IDOR
    if request.user.id != user_id_int:
        logger.warning(f"Unauthorized user API access attempt by {request.user.username} for user {user_id}")
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    try:
        user = User.objects.get(id=user_id_int)
        return JsonResponse({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'last_login': str(user.last_login) if user.last_login else None
        })
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found'}, status=404)


@login_required(login_url='login')
def search_users(request):
    """Search users by query"""
    query = request.GET.get('q', '').strip()
    if not query:
        return render(request, 'search_results.html', {'query': '', 'users': []})
    
    # Limit search query length to prevent abuse
    if len(query) > 50:
        query = query[:50]
    
    users = User.objects.filter(username__icontains=query)[:10]  # Limit results
    
    return render(request, 'search_results.html', {
        'query': escape(query),
        'users': users
    })


@login_required(login_url='login')
@require_http_methods(["POST"])
@csrf_protect
def delete_account(request):
    """Delete user account"""
    user_id = request.user.id
    username = request.user.username
    
    if request.user.is_authenticated:
        request.user.delete()
        logger.info(f"Account deleted: {username} (ID: {user_id})")
        messages.success(request, 'Your account has been deleted successfully.')
        return redirect('login')
    return redirect('login')


@login_required(login_url='login')
@csrf_protect
def change_password(request):
    """Change user password"""
    if request.method == "POST":
        old_password = request.POST.get('old_password', '')
        new_password = request.POST.get('new_password', '')
        
        if not old_password or not new_password:
            messages.error(request, 'Both current and new passwords are required.')
            return render(request, 'change_password.html')
        
        # Verify old password
        if not request.user.check_password(old_password):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'change_password.html')
        
        # Use Django's built-in password validation
        try:
            validate_password(new_password, user=request.user)
        except PasswordValidationError as e:
            for error in e.messages:
                messages.error(request, error)
            return render(request, 'change_password.html')
        
        request.user.set_password(new_password)
        request.user.save()
        
        # Re-authenticate user to maintain session after password change
        user = authenticate(username=request.user.username, password=new_password)
        if user:
            login(request, user)
        
        logger.info(f"Password changed for user: {request.user.username}")
        messages.success(request, 'Password changed successfully.')
        return redirect('profile')
    
    return render(request, 'change_password.html')


@login_required(login_url='login')
@staff_member_required
@require_http_methods(["GET"])
@csrf_protect
def export_data(request):
    """Export anonymized user statistics - Admin only with comprehensive security"""
    
    # Enhanced logging with IP address and user agent
    client_ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR'))
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    # Log security-critical action with comprehensive details
    logger.warning(
        f"SECURITY AUDIT: Data export accessed by admin user '{request.user.username}' "
        f"(ID: {request.user.id}) from IP: {client_ip}, User-Agent: {user_agent}"
    )
    
    # Additional authorization check for superuser only
    if not request.user.is_superuser:
        logger.error(
            f"SECURITY VIOLATION: Non-superuser staff member '{request.user.username}' "
            f"attempted data export from IP: {client_ip}"
        )
        return JsonResponse({'error': 'Superuser access required for data export'}, status=403)
    
    # Data minimization - export only aggregated, non-sensitive statistics
    users = User.objects.all()
    
    # Generate anonymized summary statistics instead of individual user data
    export_data = {
        'export_metadata': {
            'timestamp': str(timezone.now()),
            'exported_by': request.user.username,
            'export_type': 'aggregated_statistics'
        },
        'user_statistics': {
            'total_users': users.count(),
            'active_users': users.filter(is_active=True).count(),
            'inactive_users': users.filter(is_active=False).count(),
            'staff_users': users.filter(is_staff=True).count(),
            'superusers': users.filter(is_superuser=True).count(),
        },
        'registration_trends': {
            'users_last_30_days': users.filter(
                date_joined__gte=timezone.now() - timedelta(days=30)
            ).count(),
            'users_last_7_days': users.filter(
                date_joined__gte=timezone.now() - timedelta(days=7)
            ).count(),
        }
    }
    
    return JsonResponse(export_data)


@login_required(login_url='login')
@require_http_methods(["POST"])
@csrf_protect
def update_email(request, user_id):
    """Update user email"""
    try:
        user_id_int = int(user_id)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid user ID'}, status=400)
    
    # Authorization check to prevent IDOR
    if request.user.id != user_id_int:
        logger.warning(f"Unauthorized email update attempt by {request.user.username} for user {user_id}")
        return JsonResponse({'error': 'Unauthorized'}, status=403)
    
    new_email = request.POST.get('email', '').strip()
    
    if not new_email:
        return JsonResponse({'error': 'Email is required'}, status=400)
    
    # Validate email format
    try:
        validate_email(new_email)
    except ValidationError:
        return JsonResponse({'error': 'Invalid email format'}, status=400)
    
    # Check if email already exists
    if User.objects.filter(email=new_email).exclude(id=user_id_int).exists():
        return JsonResponse({'error': 'Email already in use'}, status=400)
    
    old_email = request.user.email
    request.user.email = new_email
    request.user.save()
    
    logger.info(f"Email updated for user {request.user.username}: {old_email} -> {new_email}")
    
    return JsonResponse({'status': 'updated'})