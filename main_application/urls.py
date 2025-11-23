"""
MediSphere Hospital Management System - URL Configuration
File: main_application/urls.py
"""

from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
     # =========================================================================
    # PASSWORD MANAGEMENT
    # =========================================================================
    # Email-based password reset
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    
    # OTP-based password reset (alternative)
    path('forgot-password-otp/', views.forgot_password_otp_view, name='forgot_password_otp'),
    
    # Change password (for logged-in users)
    path('change-password/', views.change_password_view, name='change_password'),
    
    # Main Dashboard (Router)
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Role-Specific Dashboards
    path('dashboard/superintendent/', views.superintendent_dashboard, name='superintendent_dashboard'),
    path('dashboard/doctor/', views.doctor_dashboard, name='doctor_dashboard'),
    path('dashboard/nurse/', views.nurse_dashboard, name='nurse_dashboard'),
    path('dashboard/laboratory/', views.lab_dashboard, name='lab_dashboard'),
    path('dashboard/radiology/', views.radiology_dashboard, name='radiology_dashboard'),
    path('dashboard/pharmacy/', views.pharmacy_dashboard, name='pharmacy_dashboard'),
    path('dashboard/reception/', views.reception_dashboard, name='reception_dashboard'),
    path('dashboard/billing/', views.billing_dashboard, name='billing_dashboard'),
    path('dashboard/nhif/', views.nhif_dashboard, name='nhif_dashboard'),
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/default/', views.default_dashboard, name='default_dashboard'),
]