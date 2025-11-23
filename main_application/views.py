"""
MediSphere Hospital Management System - Authentication and Business logic  Views
File: main_application/views.py
"""

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from functools import wraps
from main_application.models import User, AuditLog


# =============================================================================
# CUSTOM DECORATORS FOR ROLE-BASED ACCESS CONTROL
# =============================================================================

def role_required(*allowed_roles):
    """
    Decorator to restrict access based on user roles.
    
    Usage:
        @role_required('DOCTOR', 'CLINICAL_OFFICER')
        def doctor_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to access this page.')
                return redirect('login')
            
            # Superusers can access everything
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user has required role
            if request.user.role and request.user.role.name in allowed_roles:
                return view_func(request, *args, **kwargs)
            
            # Access denied
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
        
        return wrapper
    return decorator


def department_required(*allowed_departments):
    """
    Decorator to restrict access based on user departments.
    
    Usage:
        @department_required('LABORATORY', 'RADIOLOGY')
        def lab_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to access this page.')
                return redirect('login')
            
            # Superusers can access everything
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user has required department
            if request.user.department and request.user.department.name in allowed_departments:
                return view_func(request, *args, **kwargs)
            
            # Access denied
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard')
        
        return wrapper
    return decorator


def permission_required(permission_field):
    """
    Decorator to check specific role permissions.
    
    Usage:
        @permission_required('can_prescribe')
        def prescription_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, 'Please login to access this page.')
                return redirect('login')
            
            # Superusers can access everything
            if request.user.is_superuser:
                return view_func(request, *args, **kwargs)
            
            # Check if user's role has the required permission
            if request.user.role and getattr(request.user.role, permission_field, False):
                return view_func(request, *args, **kwargs)
            
            # Access denied
            messages.error(request, f'You do not have {permission_field.replace("_", " ")} permission.')
            return redirect('dashboard')
        
        return wrapper
    return decorator


# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================

def login_view(request):
    """
    Handle user login and redirect to appropriate dashboard based on role.
    """
    # Redirect if already logged in
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get('remember_me')
        
        # Authenticate user
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            if user.is_active:
                login(request, user)
                
                # Set session expiry
                if not remember_me:
                    request.session.set_expiry(0)  # Session expires when browser closes
                else:
                    request.session.set_expiry(1209600)  # 2 weeks
                
                # Log the login
                AuditLog.objects.create(
                    user=user,
                    action_type='LOGIN',
                    model_name='User',
                    object_id=user.id,
                    object_repr=str(user),
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
                )
                
                # Success message
                messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
                
                # Redirect to appropriate dashboard or next page
                next_url = request.GET.get('next')
                if next_url:
                    return redirect(next_url)
                
                return redirect('dashboard')
            else:
                messages.error(request, 'Your account has been deactivated. Please contact administration.')
        else:
            messages.error(request, 'Invalid username or password. Please try again.')
    
    context = {
        'page_title': 'Login - MediSphere Hospital'
    }
    return render(request, 'auth/login.html', context)


@login_required
def logout_view(request):
    """
    Handle user logout.
    """
    # Log the logout
    AuditLog.objects.create(
        user=request.user,
        action_type='LOGOUT',
        model_name='User',
        object_id=request.user.id,
        object_repr=str(request.user),
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
    )
    
    username = request.user.get_full_name() or request.user.username
    logout(request)
    messages.success(request, f'You have been logged out successfully. See you soon, {username}!')
    return redirect('login')


@login_required
def dashboard_view(request):
    """
    Main dashboard that redirects users to their role-specific dashboard.
    """
    user = request.user
    
    # Superuser/Admin dashboard
    if user.is_superuser:
        return redirect('admin_dashboard')
    
    # Role-based dashboard routing
    if user.role:
        role_name = user.role.name
        
        # Medical Staff
        if role_name == 'MEDICAL_SUPERINTENDENT':
            return redirect('superintendent_dashboard')
        elif role_name in ['DOCTOR', 'CLINICAL_OFFICER']:
            return redirect('doctor_dashboard')
        elif role_name == 'NURSE':
            return redirect('nurse_dashboard')
        
        # Diagnostic Services
        elif role_name == 'LAB_TECHNICIAN':
            return redirect('lab_dashboard')
        elif role_name == 'RADIOLOGIST':
            return redirect('radiology_dashboard')
        
        # Pharmacy
        elif role_name == 'PHARMACIST':
            return redirect('pharmacy_dashboard')
        
        # Administrative
        elif role_name == 'RECEPTIONIST':
            return redirect('reception_dashboard')
        elif role_name == 'CASHIER':
            return redirect('billing_dashboard')
        elif role_name == 'NHIF_OFFICER':
            return redirect('nhif_dashboard')
        elif role_name == 'IT_ADMIN':
            return redirect('admin_dashboard')
    
    # Default fallback dashboard
    return redirect('default_dashboard')


# =============================================================================
# ROLE-SPECIFIC DASHBOARD VIEWS (Placeholders)
# =============================================================================

@login_required
@role_required('MEDICAL_SUPERINTENDENT')
def superintendent_dashboard(request):
    """Medical Superintendent Dashboard"""
    context = {
        'page_title': 'Medical Superintendent Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/superintendent.html', context)


@login_required
@role_required('DOCTOR', 'CLINICAL_OFFICER')
def doctor_dashboard(request):
    """Doctor/Clinical Officer Dashboard"""
    context = {
        'page_title': 'Doctor Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/doctor.html', context)


@login_required
@role_required('NURSE')
def nurse_dashboard(request):
    """Nurse Dashboard"""
    context = {
        'page_title': 'Nurse Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/nurse.html', context)


@login_required
@role_required('LAB_TECHNICIAN')
def lab_dashboard(request):
    """Laboratory Dashboard"""
    context = {
        'page_title': 'Laboratory Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/lab.html', context)


@login_required
@role_required('RADIOLOGIST')
def radiology_dashboard(request):
    """Radiology Dashboard"""
    context = {
        'page_title': 'Radiology Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/radiology.html', context)


@login_required
@role_required('PHARMACIST')
def pharmacy_dashboard(request):
    """Pharmacy Dashboard"""
    context = {
        'page_title': 'Pharmacy Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/pharmacy.html', context)


@login_required
@role_required('RECEPTIONIST')
def reception_dashboard(request):
    """Reception Dashboard"""
    context = {
        'page_title': 'Reception Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/reception.html', context)


@login_required
@role_required('CASHIER')
def billing_dashboard(request):
    """Billing/Cashier Dashboard"""
    context = {
        'page_title': 'Billing Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/billing.html', context)


@login_required
@role_required('NHIF_OFFICER')
def nhif_dashboard(request):
    """NHIF Officer Dashboard"""
    context = {
        'page_title': 'NHIF Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/nhif.html', context)


@login_required
def admin_dashboard(request):
    """Admin/IT Dashboard"""
    if not (request.user.is_superuser or (request.user.role and request.user.role.name == 'IT_ADMIN')):
        messages.error(request, 'Access denied.')
        return redirect('dashboard')
    
    context = {
        'page_title': 'Admin Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/admin.html', context)


@login_required
def default_dashboard(request):
    """Default dashboard for users without specific roles"""
    context = {
        'page_title': 'Dashboard',
        'user': request.user
    }
    return render(request, 'dashboards/default.html', context)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def error_404(request, exception):
    return render(request, 'errors/404.html', status=404)

def error_500(request):
    return render(request, 'errors/500.html', status=500)

def error_403(request, exception):
    return render(request, 'errors/403.html', status=403)

def error_400(request, exception):
    return render(request, 'errors/400.html', status=400)
