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


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Sum, Count, Avg, Q, F
from django.db.models.functions import TruncDate, TruncMonth
from django.utils import timezone
from django.http import HttpResponse
from datetime import timedelta, datetime
import json
from decimal import Decimal
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill
from openpyxl.utils import get_column_letter

from .models import (
    Patient, PatientVisit, Consultation, Invoice, Payment,
    Drug, DrugStock, LabOrder, RadiologyOrder, Admission,
    User, Department, NHIFClaim, Prescription, Surgery
)


@login_required
def admin_dashboard(request):
    """Enhanced Admin/IT Dashboard with Analytics"""
    if not (request.user.is_superuser or (request.user.role and request.user.role.name == 'IT_ADMIN')):
        messages.error(request, 'Access denied.')
        return redirect('dashboard')
    
    # Get filter parameters
    period = request.GET.get('period', '30')  # Default 30 days
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    
    # Calculate date range
    if start_date and end_date:
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        except ValueError:
            start_date = timezone.now().date() - timedelta(days=int(period))
            end_date = timezone.now().date()
    else:
        end_date = timezone.now().date()
        start_date = end_date - timedelta(days=int(period))
    
    # ========== KEY STATISTICS ==========
    total_patients = Patient.objects.filter(is_active=True).count()
    total_staff = User.objects.filter(is_active_staff=True).count()
    
    # Period-specific stats
    visits_in_period = PatientVisit.objects.filter(
        visit_date__gte=start_date,
        visit_date__lte=end_date
    )
    total_visits = visits_in_period.count()
    
    # Revenue statistics
    revenue_data = Invoice.objects.filter(
        invoice_date__date__gte=start_date,
        invoice_date__date__lte=end_date
    ).aggregate(
        total_revenue=Sum('total_amount'),
        total_paid=Sum('amount_paid'),
        total_pending=Sum('balance')
    )
    
    total_revenue = revenue_data['total_revenue'] or Decimal('0.00')
    total_paid = revenue_data['total_paid'] or Decimal('0.00')
    total_pending = revenue_data['total_pending'] or Decimal('0.00')
    
    # Payment methods breakdown
    payment_methods = Payment.objects.filter(
        payment_date__date__gte=start_date,
        payment_date__date__lte=end_date,
        status='COMPLETED'
    ).values('payment_method').annotate(
        total=Sum('amount'),
        count=Count('id')
    ).order_by('-total')
    
    payment_labels = [pm['payment_method'] for pm in payment_methods]
    payment_totals = [float(pm['total']) for pm in payment_methods]
    
    # ========== PATIENT ANALYTICS ==========
    
    # Patient registrations trend (last 30 days)
    registration_trend = Patient.objects.filter(
        registration_date__date__gte=start_date,
        registration_date__date__lte=end_date
    ).annotate(
        date=TruncDate('registration_date')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    reg_dates = [rt['date'].strftime('%Y-%m-%d') for rt in registration_trend]
    reg_counts = [rt['count'] for rt in registration_trend]
    
    # Patient demographics - Age groups (Database-agnostic approach)
    from collections import Counter
    
    active_patients = Patient.objects.filter(is_active=True)
    age_group_counter = Counter()
    
    for patient in active_patients:
        age = patient.age
        if age < 1:
            age_group_counter['Infant (0-1)'] += 1
        elif age < 13:
            age_group_counter['Child (1-12)'] += 1
        elif age < 18:
            age_group_counter['Teen (13-17)'] += 1
        elif age < 65:
            age_group_counter['Adult (18-64)'] += 1
        else:
            age_group_counter['Elderly (65+)'] += 1
    
    age_group_labels = list(age_group_counter.keys())
    age_group_counts = list(age_group_counter.values())
    
    # Gender distribution
    gender_dist = Patient.objects.filter(is_active=True).values('gender').annotate(
        count=Count('id')
    )
    gender_labels = [g['gender'] for g in gender_dist]
    gender_counts = [g['count'] for g in gender_dist]
    
    # ========== VISIT ANALYTICS ==========
    
    # Daily visits trend
    daily_visits = visits_in_period.annotate(
        date=TruncDate('visit_date')
    ).values('date').annotate(
        count=Count('id')
    ).order_by('date')
    
    visit_dates = [dv['date'].strftime('%Y-%m-%d') for dv in daily_visits]
    visit_counts = [dv['count'] for dv in daily_visits]
    
    # Visit types distribution
    visit_types = visits_in_period.values('visit_type').annotate(
        count=Count('id')
    ).order_by('-count')
    
    visit_type_labels = [vt['visit_type'] for vt in visit_types]
    visit_type_counts = [vt['count'] for vt in visit_types]
    
    # Visit status distribution
    visit_status = visits_in_period.values('status').annotate(
        count=Count('id')
    ).order_by('-count')
    
    visit_status_labels = [vs['status'] for vs in visit_status]
    visit_status_counts = [vs['count'] for vs in visit_status]
    
    # Average wait time
    completed_visits = visits_in_period.filter(exit_time__isnull=False)
    if completed_visits.exists():
        avg_wait_time = sum([v.wait_time_minutes for v in completed_visits]) / completed_visits.count()
    else:
        avg_wait_time = 0
    
    # ========== REVENUE ANALYTICS ==========
    
    # Daily revenue trend
    daily_revenue = Invoice.objects.filter(
        invoice_date__date__gte=start_date,
        invoice_date__date__lte=end_date
    ).annotate(
        date=TruncDate('invoice_date')
    ).values('date').annotate(
        revenue=Sum('total_amount'),
        paid=Sum('amount_paid')
    ).order_by('date')
    
    revenue_dates = [dr['date'].strftime('%Y-%m-%d') for dr in daily_revenue]
    revenue_amounts = [float(dr['revenue'] or 0) for dr in daily_revenue]
    revenue_paid = [float(dr['paid'] or 0) for dr in daily_revenue]
    
    # Revenue by service type
    revenue_by_service = Invoice.objects.filter(
        invoice_date__date__gte=start_date,
        invoice_date__date__lte=end_date
    ).values('items__item_type').annotate(
        total=Sum(F('items__quantity') * F('items__unit_price'))
    ).order_by('-total')
    
    service_labels = [rs['items__item_type'] or 'OTHER' for rs in revenue_by_service]
    service_amounts = [float(rs['total'] or 0) for rs in revenue_by_service]
    
    # Top revenue generating departments
    top_departments = Consultation.objects.filter(
        consultation_start__date__gte=start_date,
        consultation_start__date__lte=end_date
    ).values('doctor__department__name').annotate(
        revenue=Sum('consultation_fee'),
        count=Count('id')
    ).order_by('-revenue')[:5]
    
    dept_labels = [td['doctor__department__name'] or 'N/A' for td in top_departments]
    dept_revenue = [float(td['revenue'] or 0) for td in top_departments]
    
    # ========== PHARMACY ANALYTICS ==========
    
    # Low stock medications
    low_stock = Drug.objects.filter(is_active=True).annotate(
        current_stock=Sum('stock_records__quantity')
    ).filter(
        current_stock__lte=F('reorder_level')
    ).order_by('current_stock')[:10]
    
    # Top selling medications
    top_medicines = Prescription.objects.filter(
        prescribed_at__date__gte=start_date,
        prescribed_at__date__lte=end_date
    ).values('items__drug__name').annotate(
        quantity=Sum('items__dispensed_quantity'),
        revenue=Sum(F('items__dispensed_quantity') * F('items__drug__unit_price'))
    ).order_by('-quantity')[:10]
    
    medicine_labels = [tm['items__drug__name'] for tm in top_medicines]
    medicine_quantities = [tm['quantity'] or 0 for tm in top_medicines]
    medicine_revenue = [float(tm['revenue'] or 0) for tm in top_medicines]
    
    # Expiring stock (next 90 days)
    expiring_soon = DrugStock.objects.filter(
        expiry_date__lte=timezone.now().date() + timedelta(days=90),
        expiry_date__gt=timezone.now().date(),
        quantity__gt=0
    ).select_related('drug').order_by('expiry_date')[:10]
    
    # ========== LAB & RADIOLOGY ANALYTICS ==========
    
    # Lab tests ordered
    lab_tests = LabOrder.objects.filter(
        ordered_at__date__gte=start_date,
        ordered_at__date__lte=end_date
    ).values('test__category').annotate(
        count=Count('id')
    ).order_by('-count')
    
    lab_labels = [lt['test__category'] for lt in lab_tests]
    lab_counts = [lt['count'] for lt in lab_tests]
    
    # Lab turnaround time
    completed_labs = LabOrder.objects.filter(
        ordered_at__date__gte=start_date,
        ordered_at__date__lte=end_date,
        status='COMPLETED',
        result__isnull=False
    ).select_related('result')
    
    if completed_labs.exists():
        total_tat = sum([
            (lab.result.result_date - lab.ordered_at).total_seconds() / 3600 
            for lab in completed_labs
        ])
        avg_lab_tat = total_tat / completed_labs.count()
    else:
        avg_lab_tat = 0
    
    # Radiology tests
    radiology_tests = RadiologyOrder.objects.filter(
        ordered_at__date__gte=start_date,
        ordered_at__date__lte=end_date
    ).values('test__modality').annotate(
        count=Count('id')
    ).order_by('-count')
    
    rad_labels = [rt['test__modality'] for rt in radiology_tests]
    rad_counts = [rt['count'] for rt in radiology_tests]
    
    # ========== INPATIENT ANALYTICS ==========
    
    # Active admissions
    active_admissions = Admission.objects.filter(status='ACTIVE').count()
    
    # Bed occupancy by ward
    from .models import Ward
    ward_occupancy = Ward.objects.filter(is_active=True).annotate(
        occupied=Count('beds', filter=Q(beds__is_occupied=True)),
        available=Count('beds', filter=Q(beds__is_occupied=False, beds__is_available=True))
    )
    
    ward_labels = [w.name for w in ward_occupancy]
    ward_occupied = [w.occupied for w in ward_occupancy]
    ward_available = [w.available for w in ward_occupancy]
    
    # Average length of stay
    discharged_admissions = Admission.objects.filter(
        admission_datetime__date__gte=start_date,
        discharge_datetime__date__lte=end_date,
        status='DISCHARGED'
    )
    
    if discharged_admissions.exists():
        avg_los = sum([adm.length_of_stay for adm in discharged_admissions]) / discharged_admissions.count()
    else:
        avg_los = 0
    
    # ========== NHIF ANALYTICS ==========
    
    # NHIF claims status
    nhif_claims = NHIFClaim.objects.filter(
        created_at__date__gte=start_date,
        created_at__date__lte=end_date
    ).values('status').annotate(
        count=Count('id'),
        amount=Sum('claimed_amount')
    )
    
    nhif_status_labels = [nc['status'] for nc in nhif_claims]
    nhif_status_counts = [nc['count'] for nc in nhif_claims]
    nhif_status_amounts = [float(nc['amount'] or 0) for nc in nhif_claims]
    
    # ========== STAFF PERFORMANCE ==========
    
    # Top performing doctors by consultations
    top_doctors = Consultation.objects.filter(
        consultation_start__date__gte=start_date,
        consultation_start__date__lte=end_date
    ).values('doctor__first_name', 'doctor__last_name').annotate(
        count=Count('id'),
        revenue=Sum('consultation_fee')
    ).order_by('-count')[:10]
    
    doctor_labels = [f"Dr. {td['doctor__first_name']} {td['doctor__last_name']}" for td in top_doctors]
    doctor_counts = [td['count'] for td in top_doctors]
    doctor_revenue = [float(td['revenue'] or 0) for td in top_doctors]
    
    # Department performance
    dept_performance = Department.objects.filter(is_active=True).annotate(
        staff_count=Count('staff', filter=Q(staff__is_active_staff=True)),
        visits=Count('staff__consultations', filter=Q(
            staff__consultations__consultation_start__date__gte=start_date,
            staff__consultations__consultation_start__date__lte=end_date
        ))
    ).order_by('-visits')
    
    # ========== SURGICAL ANALYTICS ==========
    
    surgeries_performed = Surgery.objects.filter(
        start_time__date__gte=start_date,
        start_time__date__lte=end_date,
        status='COMPLETED'
    ).count()
    
    surgery_types = Surgery.objects.filter(
        start_time__date__gte=start_date,
        start_time__date__lte=end_date
    ).values('surgery_type').annotate(
        count=Count('id')
    )
    
    surgery_type_labels = [st['surgery_type'] for st in surgery_types]
    surgery_type_counts = [st['count'] for st in surgery_types]
    
    # ========== HANDLE EXCEL EXPORT ==========
    if request.GET.get('export') == 'excel':
        return export_dashboard_to_excel(
            start_date, end_date, total_patients, total_staff, total_visits,
            total_revenue, total_paid, total_pending, active_admissions,
            surgeries_performed, low_stock, expiring_soon, visit_types,
            payment_methods, top_medicines, top_doctors, ward_occupancy
        )
    
    context = {
        'page_title': 'Admin Dashboard',
        'user': request.user,
        
        # Filter parameters
        'period': period,
        'start_date': start_date,
        'end_date': end_date,
        
        # Key Statistics
        'total_patients': total_patients,
        'total_staff': total_staff,
        'total_visits': total_visits,
        'total_revenue': total_revenue,
        'total_paid': total_paid,
        'total_pending': total_pending,
        'active_admissions': active_admissions,
        'surgeries_performed': surgeries_performed,
        'avg_wait_time': round(avg_wait_time, 1),
        'avg_lab_tat': round(avg_lab_tat, 1),
        'avg_los': round(avg_los, 1),
        
        # Patient Analytics
        'reg_dates': json.dumps(reg_dates),
        'reg_counts': json.dumps(reg_counts),
        'age_group_labels': json.dumps(age_group_labels),
        'age_group_counts': json.dumps(age_group_counts),
        'gender_labels': json.dumps(gender_labels),
        'gender_counts': json.dumps(gender_counts),
        
        # Visit Analytics
        'visit_dates': json.dumps(visit_dates),
        'visit_counts': json.dumps(visit_counts),
        'visit_type_labels': json.dumps(visit_type_labels),
        'visit_type_counts': json.dumps(visit_type_counts),
        'visit_status_labels': json.dumps(visit_status_labels),
        'visit_status_counts': json.dumps(visit_status_counts),
        
        # Revenue Analytics
        'revenue_dates': json.dumps(revenue_dates),
        'revenue_amounts': json.dumps(revenue_amounts),
        'revenue_paid': json.dumps(revenue_paid),
        'payment_labels': json.dumps(payment_labels),
        'payment_totals': json.dumps(payment_totals),
        'service_labels': json.dumps(service_labels),
        'service_amounts': json.dumps(service_amounts),
        'dept_labels': json.dumps(dept_labels),
        'dept_revenue': json.dumps(dept_revenue),
        
        # Pharmacy Analytics
        'low_stock': low_stock,
        'expiring_soon': expiring_soon,
        'medicine_labels': json.dumps(medicine_labels),
        'medicine_quantities': json.dumps(medicine_quantities),
        'medicine_revenue': json.dumps(medicine_revenue),
        
        # Lab & Radiology
        'lab_labels': json.dumps(lab_labels),
        'lab_counts': json.dumps(lab_counts),
        'rad_labels': json.dumps(rad_labels),
        'rad_counts': json.dumps(rad_counts),
        
        # Inpatient Analytics
        'ward_labels': json.dumps(ward_labels),
        'ward_occupied': json.dumps(ward_occupied),
        'ward_available': json.dumps(ward_available),
        
        # NHIF Analytics
        'nhif_status_labels': json.dumps(nhif_status_labels),
        'nhif_status_counts': json.dumps(nhif_status_counts),
        'nhif_status_amounts': json.dumps(nhif_status_amounts),
        
        # Staff Performance
        'doctor_labels': json.dumps(doctor_labels),
        'doctor_counts': json.dumps(doctor_counts),
        'doctor_revenue': json.dumps(doctor_revenue),
        'dept_performance': dept_performance,
        
        # Surgery Analytics
        'surgery_type_labels': json.dumps(surgery_type_labels),
        'surgery_type_counts': json.dumps(surgery_type_counts),
    }
    
    return render(request, 'dashboards/admin_dashboard.html', context)


def export_dashboard_to_excel(start_date, end_date, total_patients, total_staff, 
                               total_visits, total_revenue, total_paid, total_pending,
                               active_admissions, surgeries_performed, low_stock, 
                               expiring_soon, visit_types, payment_methods, 
                               top_medicines, top_doctors, ward_occupancy):
    """Export dashboard data to Excel"""
    
    wb = openpyxl.Workbook()
    
    # Define styles
    header_fill = PatternFill(start_color='3498db', end_color='3498db', fill_type='solid')
    header_font = Font(color='FFFFFF', bold=True, size=12)
    title_font = Font(bold=True, size=14, color='2980b9')
    
    # ========== SUMMARY SHEET ==========
    ws_summary = wb.active
    ws_summary.title = 'Summary'
    
    # Title
    ws_summary['A1'] = 'MediSphere Hospital - Dashboard Report'
    ws_summary['A1'].font = title_font
    ws_summary['A2'] = f'Period: {start_date} to {end_date}'
    
    # Key Metrics
    ws_summary['A4'] = 'Key Performance Indicators'
    ws_summary['A4'].font = Font(bold=True, size=12)
    
    metrics = [
        ('Total Patients', total_patients),
        ('Total Staff', total_staff),
        ('Total Visits', total_visits),
        ('Total Revenue (KES)', float(total_revenue)),
        ('Amount Paid (KES)', float(total_paid)),
        ('Pending Amount (KES)', float(total_pending)),
        ('Active Admissions', active_admissions),
        ('Surgeries Performed', surgeries_performed),
    ]
    
    row = 5
    for metric, value in metrics:
        ws_summary[f'A{row}'] = metric
        ws_summary[f'B{row}'] = value
        row += 1
    
    # ========== VISIT TYPES SHEET ==========
    ws_visits = wb.create_sheet('Visit Types')
    ws_visits['A1'] = 'Visit Type'
    ws_visits['B1'] = 'Count'
    ws_visits['A1'].fill = header_fill
    ws_visits['B1'].fill = header_fill
    ws_visits['A1'].font = header_font
    ws_visits['B1'].font = header_font
    
    row = 2
    for vt in visit_types:
        ws_visits[f'A{row}'] = vt['visit_type']
        ws_visits[f'B{row}'] = vt['count']
        row += 1
    
    # ========== PAYMENT METHODS SHEET ==========
    ws_payments = wb.create_sheet('Payment Methods')
    ws_payments['A1'] = 'Payment Method'
    ws_payments['B1'] = 'Total Amount (KES)'
    ws_payments['C1'] = 'Count'
    for cell in ['A1', 'B1', 'C1']:
        ws_payments[cell].fill = header_fill
        ws_payments[cell].font = header_font
    
    row = 2
    for pm in payment_methods:
        ws_payments[f'A{row}'] = pm['payment_method']
        ws_payments[f'B{row}'] = float(pm['total'])
        ws_payments[f'C{row}'] = pm['count']
        row += 1
    
    # ========== TOP MEDICINES SHEET ==========
    ws_meds = wb.create_sheet('Top Medicines')
    ws_meds['A1'] = 'Medicine'
    ws_meds['B1'] = 'Quantity Dispensed'
    ws_meds['C1'] = 'Revenue (KES)'
    for cell in ['A1', 'B1', 'C1']:
        ws_meds[cell].fill = header_fill
        ws_meds[cell].font = header_font
    
    row = 2
    for med in top_medicines:
        ws_meds[f'A{row}'] = med['items__drug__name']
        ws_meds[f'B{row}'] = med['quantity'] or 0
        ws_meds[f'C{row}'] = float(med['revenue'] or 0)
        row += 1
    
    # ========== LOW STOCK SHEET ==========
    ws_stock = wb.create_sheet('Low Stock')
    ws_stock['A1'] = 'Medicine'
    ws_stock['B1'] = 'Current Stock'
    ws_stock['C1'] = 'Reorder Level'
    for cell in ['A1', 'B1', 'C1']:
        ws_stock[cell].fill = header_fill
        ws_stock[cell].font = header_font
    
    row = 2
    for drug in low_stock:
        ws_stock[f'A{row}'] = drug.name
        ws_stock[f'B{row}'] = drug.current_stock
        ws_stock[f'C{row}'] = drug.reorder_level
        row += 1
    
    # ========== EXPIRING STOCK SHEET ==========
    ws_expiry = wb.create_sheet('Expiring Stock')
    ws_expiry['A1'] = 'Medicine'
    ws_expiry['B1'] = 'Batch Number'
    ws_expiry['C1'] = 'Quantity'
    ws_expiry['D1'] = 'Expiry Date'
    ws_expiry['E1'] = 'Days to Expiry'
    for cell in ['A1', 'B1', 'C1', 'D1', 'E1']:
        ws_expiry[cell].fill = header_fill
        ws_expiry[cell].font = header_font
    
    row = 2
    for stock in expiring_soon:
        ws_expiry[f'A{row}'] = stock.drug.name
        ws_expiry[f'B{row}'] = stock.batch_number
        ws_expiry[f'C{row}'] = stock.quantity
        ws_expiry[f'D{row}'] = stock.expiry_date.strftime('%Y-%m-%d')
        ws_expiry[f'E{row}'] = stock.days_to_expiry
        row += 1
    
    # ========== TOP DOCTORS SHEET ==========
    ws_doctors = wb.create_sheet('Top Doctors')
    ws_doctors['A1'] = 'Doctor'
    ws_doctors['B1'] = 'Consultations'
    ws_doctors['C1'] = 'Revenue (KES)'
    for cell in ['A1', 'B1', 'C1']:
        ws_doctors[cell].fill = header_fill
        ws_doctors[cell].font = header_font
    
    row = 2
    for doc in top_doctors:
        ws_doctors[f'A{row}'] = f"Dr. {doc['doctor__first_name']} {doc['doctor__last_name']}"
        ws_doctors[f'B{row}'] = doc['count']
        ws_doctors[f'C{row}'] = float(doc['revenue'] or 0)
        row += 1
    
    # ========== WARD OCCUPANCY SHEET ==========
    ws_wards = wb.create_sheet('Ward Occupancy')
    ws_wards['A1'] = 'Ward'
    ws_wards['B1'] = 'Occupied Beds'
    ws_wards['C1'] = 'Available Beds'
    ws_wards['D1'] = 'Total Beds'
    ws_wards['E1'] = 'Occupancy Rate (%)'
    for cell in ['A1', 'B1', 'C1', 'D1', 'E1']:
        ws_wards[cell].fill = header_fill
        ws_wards[cell].font = header_font
    
    row = 2
    for ward in ward_occupancy:
        ws_wards[f'A{row}'] = ward.name
        ws_wards[f'B{row}'] = ward.occupied
        ws_wards[f'C{row}'] = ward.available
        ws_wards[f'D{row}'] = ward.total_beds
        ws_wards[f'E{row}'] = ward.occupancy_rate
        row += 1
    
    # Auto-adjust column widths for all sheets
    for ws in wb.worksheets:
        for column in ws.columns:
            max_length = 0
            column_letter = get_column_letter(column[0].column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(cell.value)
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            ws.column_dimensions[column_letter].width = adjusted_width
    
    # Create response
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = f'attachment; filename=dashboard_report_{start_date}_{end_date}.xlsx'
    
    wb.save(response)
    return response


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
