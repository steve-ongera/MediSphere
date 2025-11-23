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
from django.utils import timezone



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

"""
MediSphere Hospital Management System - Password Reset Views
File: main_application/views/password_views.py
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from main_application.models import User, AuditLog, SMSLog
import random
import string

User = get_user_model()


# =============================================================================
# PASSWORD RESET REQUEST VIEW
# =============================================================================

def forgot_password_view(request):
    """
    Password reset request page.
    User enters email or username to receive reset link.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        identifier = request.POST.get('identifier', '').strip()  # Email or username
        
        if not identifier:
            messages.error(request, 'Please enter your email or username.')
            return render(request, 'auth/forgot_password.html')
        
        # Try to find user by email or username
        user = None
        try:
            if '@' in identifier:
                # Looks like email
                user = User.objects.get(email__iexact=identifier, is_active=True)
            else:
                # Looks like username
                user = User.objects.get(username__iexact=identifier, is_active=True)
        except User.DoesNotExist:
            # Don't reveal whether user exists or not (security best practice)
            messages.success(
                request, 
                'If an account exists with that information, a password reset link has been sent.'
            )
            return redirect('forgot_password')
        
        if user:
            # Generate password reset token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            
            # Build reset URL
            reset_url = request.build_absolute_uri(
                reverse('password_reset_confirm', kwargs={'uidb64': uid, 'token': token})
            )
            
            # Send email
            if user.email:
                try:
                    subject = 'Password Reset - MediSphere Hospital'
                    message = render_to_string('auth/password_reset_email.html', {
                        'user': user,
                        'reset_url': reset_url,
                        'hospital_name': 'MediSphere Hospital'
                    })
                    
                    send_mail(
                        subject,
                        message,
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                        html_message=message
                    )
                    
                    # Log the action
                    AuditLog.objects.create(
                        user=user,
                        action_type='VIEW',
                        model_name='User',
                        object_id=user.id,
                        object_repr=f'Password reset requested for {user.username}',
                        ip_address=get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
                    )
                    
                except Exception as e:
                    messages.error(request, 'Error sending email. Please contact IT support.')
                    return render(request, 'auth/forgot_password.html')
            
            # Send SMS if phone number exists
            if user.phone_number:
                send_password_reset_sms(user, reset_url)
            
            messages.success(
                request,
                'Password reset instructions have been sent to your email and phone.'
            )
            return redirect('login')
    
    context = {
        'page_title': 'Forgot Password - MediSphere Hospital'
    }
    return render(request, 'auth/forgot_password.html', context)


# =============================================================================
# PASSWORD RESET CONFIRM VIEW
# =============================================================================

def password_reset_confirm_view(request, uidb64, token):
    """
    Verify the password reset token and allow user to set new password.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    try:
        # Decode the user ID
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    # Verify the token
    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            
            # Validate passwords
            if not password1 or not password2:
                messages.error(request, 'Please enter both password fields.')
                return render(request, 'auth/password_reset_confirm.html', {
                    'validlink': True,
                    'page_title': 'Reset Password'
                })
            
            if password1 != password2:
                messages.error(request, 'Passwords do not match.')
                return render(request, 'auth/password_reset_confirm.html', {
                    'validlink': True,
                    'page_title': 'Reset Password'
                })
            
            if len(password1) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
                return render(request, 'auth/password_reset_confirm.html', {
                    'validlink': True,
                    'page_title': 'Reset Password'
                })
            
            # Set the new password
            user.set_password(password1)
            user.save()
            
            # Log the password change
            AuditLog.objects.create(
                user=user,
                action_type='UPDATE',
                model_name='User',
                object_id=user.id,
                object_repr=f'Password reset completed for {user.username}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
            )
            
            messages.success(
                request,
                'Your password has been reset successfully! You can now login with your new password.'
            )
            return redirect('login')
        
        context = {
            'validlink': True,
            'user': user,
            'page_title': 'Reset Password - MediSphere Hospital'
        }
        return render(request, 'auth/password_reset_confirm.html', context)
    else:
        # Invalid or expired token
        messages.error(
            request,
            'This password reset link is invalid or has expired. Please request a new one.'
        )
        return redirect('forgot_password')


# =============================================================================
# CHANGE PASSWORD VIEW (For Logged-in Users)
# =============================================================================

@login_required
def change_password_view(request):
    """
    Allow logged-in users to change their password.
    """
    if request.method == 'POST':
        old_password = request.POST.get('old_password')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        
        # Verify old password
        if not request.user.check_password(old_password):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'auth/change_password.html', {
                'page_title': 'Change Password'
            })
        
        # Validate new passwords
        if not password1 or not password2:
            messages.error(request, 'Please enter both new password fields.')
            return render(request, 'auth/change_password.html', {
                'page_title': 'Change Password'
            })
        
        if password1 != password2:
            messages.error(request, 'New passwords do not match.')
            return render(request, 'auth/change_password.html', {
                'page_title': 'Change Password'
            })
        
        if len(password1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'auth/change_password.html', {
                'page_title': 'Change Password'
            })
        
        if old_password == password1:
            messages.error(request, 'New password must be different from current password.')
            return render(request, 'auth/change_password.html', {
                'page_title': 'Change Password'
            })
        
        # Set the new password
        request.user.set_password(password1)
        request.user.save()
        
        # Log the password change
        AuditLog.objects.create(
            user=request.user,
            action_type='UPDATE',
            model_name='User',
            object_id=request.user.id,
            object_repr=f'Password changed for {request.user.username}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
        )
        
        # Update session to prevent logout
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, request.user)
        
        messages.success(request, 'Your password has been changed successfully!')
        return redirect('dashboard')
    
    context = {
        'page_title': 'Change Password - MediSphere Hospital'
    }
    return render(request, 'auth/change_password.html', context)


# =============================================================================
# PASSWORD RESET VIA OTP (Alternative Method)
# =============================================================================

def forgot_password_otp_view(request):
    """
    Alternative password reset using OTP sent to phone.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        action = request.POST.get('action')
        
        # Step 1: Send OTP
        if action == 'send_otp':
            phone_number = request.POST.get('phone_number', '').strip()
            
            if not phone_number:
                messages.error(request, 'Please enter your phone number.')
                return render(request, 'auth/forgot_password_otp.html')
            
            # Find user by phone number
            try:
                user = User.objects.get(phone_number=phone_number, is_active=True)
            except User.DoesNotExist:
                messages.error(request, 'No account found with this phone number.')
                return render(request, 'auth/forgot_password_otp.html')
            
            # Generate OTP
            otp = ''.join(random.choices(string.digits, k=6))
            
            # Store OTP in session (in production, use Redis or database)
            request.session['reset_otp'] = otp
            request.session['reset_user_id'] = user.id
            request.session['otp_timestamp'] = timezone.now().isoformat()
            
            # Send OTP via SMS
            send_otp_sms(user, otp)
            
            messages.success(request, f'OTP has been sent to {phone_number}')
            
            context = {
                'show_otp_form': True,
                'phone_number': phone_number,
                'page_title': 'Verify OTP'
            }
            return render(request, 'auth/forgot_password_otp.html', context)
        
        # Step 2: Verify OTP
        elif action == 'verify_otp':
            entered_otp = request.POST.get('otp', '').strip()
            stored_otp = request.session.get('reset_otp')
            user_id = request.session.get('reset_user_id')
            
            if not stored_otp or not user_id:
                messages.error(request, 'Session expired. Please try again.')
                return redirect('forgot_password_otp')
            
            if entered_otp != stored_otp:
                messages.error(request, 'Invalid OTP. Please try again.')
                context = {
                    'show_otp_form': True,
                    'phone_number': request.POST.get('phone_number'),
                    'page_title': 'Verify OTP'
                }
                return render(request, 'auth/forgot_password_otp.html', context)
            
            # OTP verified, show password reset form
            context = {
                'show_password_form': True,
                'user_id': user_id,
                'page_title': 'Reset Password'
            }
            return render(request, 'auth/forgot_password_otp.html', context)
        
        # Step 3: Reset Password
        elif action == 'reset_password':
            user_id = request.session.get('reset_user_id')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            
            if not user_id:
                messages.error(request, 'Session expired. Please try again.')
                return redirect('forgot_password_otp')
            
            if password1 != password2:
                messages.error(request, 'Passwords do not match.')
                context = {
                    'show_password_form': True,
                    'user_id': user_id,
                    'page_title': 'Reset Password'
                }
                return render(request, 'auth/forgot_password_otp.html', context)
            
            if len(password1) < 8:
                messages.error(request, 'Password must be at least 8 characters long.')
                context = {
                    'show_password_form': True,
                    'user_id': user_id,
                    'page_title': 'Reset Password'
                }
                return render(request, 'auth/forgot_password_otp.html', context)
            
            # Reset password
            user = User.objects.get(id=user_id)
            user.set_password(password1)
            user.save()
            
            # Clear session
            request.session.pop('reset_otp', None)
            request.session.pop('reset_user_id', None)
            request.session.pop('otp_timestamp', None)
            
            # Log the action
            AuditLog.objects.create(
                user=user,
                action_type='UPDATE',
                model_name='User',
                object_id=user.id,
                object_repr=f'Password reset via OTP for {user.username}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:300]
            )
            
            messages.success(request, 'Password reset successful! You can now login.')
            return redirect('login')
    
    context = {
        'page_title': 'Forgot Password - MediSphere Hospital'
    }
    return render(request, 'auth/forgot_password_otp.html', context)


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


def send_password_reset_sms(user, reset_url):
    """Send password reset link via SMS"""
    try:
        from main_application.models import HospitalSettings
        settings = HospitalSettings.load()
        
        if settings.sms_enabled:
            message = f"MediSphere Hospital: Password reset link: {reset_url}"
            
            # Log SMS (actual sending would use SMS gateway API)
            SMSLog.objects.create(
                patient=None,  # This is for staff, not patients
                phone_number=user.phone_number,
                sms_type='GENERAL',
                message=message,
                status='SENT'
            )
            
            # TODO: Integrate with actual SMS gateway (Africa's Talking, Twilio, etc.)
            # Example:
            # send_sms_via_gateway(user.phone_number, message)
            
    except Exception as e:
        pass  # Fail silently for SMS


def send_otp_sms(user, otp):
    """Send OTP via SMS"""
    try:
        from main_application.models import HospitalSettings
        settings = HospitalSettings.load()
        
        if settings.sms_enabled:
            message = f"MediSphere Hospital: Your password reset OTP is: {otp}. Valid for 10 minutes."
            
            # Log SMS
            SMSLog.objects.create(
                patient=None,
                phone_number=user.phone_number,
                sms_type='GENERAL',
                message=message,
                status='SENT'
            )
            
            # TODO: Integrate with actual SMS gateway
            
    except Exception as e:
        pass  # Fail silently

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
