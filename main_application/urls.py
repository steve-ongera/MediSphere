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
    path('dashboard/reception/', views.receptionist_dashboard_view, name='reception_dashboard'),
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
    
    # =============================================================================
    # CONSULTATIONS
    # =============================================================================
    path('consultations/', views.consultation_list, name='consultation-list'),
    path('consultations/new/', views.consultation_create, name='consultation-create'),
    path('consultations/<int:consultation_id>/', views.consultation_detail, name='consultation-detail'),
    path('consultations/<int:consultation_id>/update/', views.consultation_update, name='consultation-update'),
    path('consultations/<int:consultation_id>/complete/', views.consultation_complete, name='consultation-complete'),
    
    # =============================================================================
    # CLINICAL NOTES
    # =============================================================================
    path('clinical-notes/', views.clinical_notes_list, name='clinical-notes-list'),
    path('clinical-notes/new/', views.clinical_note_create, name='clinical-note-create'),
    path('clinical-notes/<int:note_id>/', views.clinical_note_detail, name='clinical-note-detail'),
    path('clinical-notes/<int:note_id>/update/', views.clinical_note_update, name='clinical-note-update'),
    path('clinical-notes/<int:note_id>/delete/', views.clinical_note_delete, name='clinical-note-delete'),
    
    # =============================================================================
    # AJAX ENDPOINTS
    # =============================================================================
    path('ajax/patient-search/', views.patient_search_ajax, name='patient-search-ajax'),
    path('ajax/visit-search/', views.visit_search_ajax, name='visit-search-ajax'),
    
    path('dashboard/receptionist/', views.receptionist_dashboard_view, name='receptionist_dashboard'),
    
    path('patients/register/',  views.receptionist_register_patient_view,  name='receptionist_register_patient'),
    path('patients/records/', views.receptionist_patient_records_view,  name='receptionist_patient_records'),
    path('patients/search/',  views.receptionist_search_patient_view,  name='receptionist_search_patient'),
    path('patients/<int:patient_id>/', views.receptionist_patient_detail_view,  name='receptionist_patient_detail'),
    path('patients/<int:patient_id>/edit/', views.receptionist_edit_patient_view, name='receptionist_edit_patient'),
    path('queue/', views.receptionist_queue_management_view, name='receptionist_queue_management'),
    path('queue/create-visit/', views.receptionist_create_visit_view,  name='receptionist_create_visit'),
    path('queue/create-visit/<int:patient_id>/',  views.receptionist_create_visit_view,  name='receptionist_create_visit_for_patient'),
    path('queue/print-ticket/<int:visit_id>/',  views.receptionist_print_queue_ticket_view, name='receptionist_print_queue_ticket'),

    path('appointments/schedule/',  views.receptionist_schedule_appointment_view,  name='receptionist_schedule_appointment'),
    path('appointments/', views.receptionist_view_appointments_view, name='receptionist_view_appointments'),
    path('appointments/<int:appointment_id>/', views.receptionist_appointment_detail_view,  name='receptionist_appointment_detail'),
    path('appointments/<int:appointment_id>/update-status/', views.receptionist_update_appointment_status_view, name='receptionist_update_appointment_status'),
    path('appointments/<int:appointment_id>/cancel/', views.receptionist_cancel_appointment_view,  name='receptionist_cancel_appointment'),
    path('appointments/<int:appointment_id>/check-in/', views.receptionist_check_in_patient_view, name='receptionist_check_in_patient'),
    path('reports/daily/', views.receptionist_daily_report_view, name='receptionist_daily_report'),
  
]