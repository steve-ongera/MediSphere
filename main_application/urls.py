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
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/<uidb64>/<token>/', views.password_reset_confirm_view, name='password_reset_confirm'),
    path('forgot-password-otp/', views.forgot_password_otp_view, name='forgot_password_otp'),
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
    
    # Main patient management views
    path('patients/', views.patients_list, name='patients-list'),
    path('patients/create/', views.patients_create, name='patients-create'),
    path('patients/<str:patient_number>/', views.patients_detail, name='patients-detail'),
    path('patients/<str:patient_number>/edit/', views.patients_update, name='patients-update'),
    path('patients/<str:patient_number>/delete/', views.patients_delete, name='patients-delete'),
    path('patients/api/search/', views.patient_search_api, name='patient-search-api'),
    
    # Visit Registration
    path('visits/register/', views.visits_register, name='visits-register'),
    path('visits/triage/queue/', views.triage_queue, name='triage-queue'),
    path('visits/', views.visits_list, name='visits-list'),
    path('visits/<str:visit_number>/', views.visits_detail, name='visits-detail'),
    path('visits/queue/consultation/', views.patient_queue, name='patient-queue'),
    path('visits/api/patient-search/', views.patient_search_for_visit, name='patient-search-for-visit'),
    path('visits/api/statistics/', views.visit_statistics, name='visit-statistics'),
    path('visits/api/<str:visit_number>/status/', views.visit_update_status, name='visit-update-status'),
    
    path('inventory/', views.drug_inventory_list, name='drug-inventory'),
    path('drug/create/', views.drug_create, name='drug-create'),
    path('drug/<int:drug_id>/delete/', views.drug_delete, name='drug-delete'),
    path('drug/<int:drug_id>/add-stock/', views.add_stock, name='add-stock'),
    path('ajax/drug/<int:drug_id>/', views.drug_detail_ajax, name='drug-detail-ajax'),
    path('ajax/update-drug/<int:drug_id>/', views.drug_update_ajax, name='drug-update-ajax'),
    path('reports/low-stock/', views.low_stock_report, name='low-stock-report'),
    path('reports/expiring/', views.expiring_stock_report, name='expiring-stock-report'),
  
]