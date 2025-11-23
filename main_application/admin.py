"""
MediSphere Hospital Management System - Django Admin Configuration
Professional admin interface with search, filters, and actions
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count, Sum
from django.utils import timezone
from .models import *


# =============================================================================
# CUSTOM ADMIN ACTIONS
# =============================================================================

@admin.action(description='Mark selected as active')
def make_active(modeladmin, request, queryset):
    queryset.update(is_active=True)

@admin.action(description='Mark selected as inactive')
def make_inactive(modeladmin, request, queryset):
    queryset.update(is_active=False)

@admin.action(description='Mark payments as completed')
def mark_payment_completed(modeladmin, request, queryset):
    queryset.update(status='COMPLETED')


# =============================================================================
# USER MANAGEMENT
# =============================================================================

class StaffProfileInline(admin.StackedInline):
    model = StaffProfile
    can_delete = False
    verbose_name_plural = 'Staff Profile'
    fk_name = 'user'
    extra = 0


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (StaffProfileInline,)
    list_display = ['username', 'get_full_name', 'email', 'role', 'department', 'is_active_staff', 'is_staff']
    list_filter = ['role', 'department', 'is_active_staff', 'is_staff', 'is_superuser']
    search_fields = ['username', 'first_name', 'last_name', 'email']
    ordering = ['last_name', 'first_name']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Hospital Information', {
            'fields': ('role', 'department', 'phone_number', 'is_active_staff')
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('role', 'department')


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ['name', 'can_prescribe', 'can_admit_patients', 'can_access_billing', 'can_manage_inventory']
    list_filter = ['can_prescribe', 'can_admit_patients']
    search_fields = ['name', 'description']


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'location', 'phone_extension', 'is_active', 'staff_count']
    list_filter = ['is_active']
    search_fields = ['name', 'location']
    actions = [make_active, make_inactive]
    
    def staff_count(self, obj):
        return obj.staff.count()
    staff_count.short_description = 'Staff Count'


@admin.register(StaffProfile)
class StaffProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'staff_number', 'id_number', 'specialization', 'hire_date']
    list_filter = ['hire_date', 'gender']
    search_fields = ['user__first_name', 'user__last_name', 'staff_number', 'id_number', 'specialization']
    date_hierarchy = 'hire_date'
    readonly_fields = ['created_at', 'updated_at']


# =============================================================================
# PATIENT MANAGEMENT
# =============================================================================

@admin.register(Patient)
class PatientAdmin(admin.ModelAdmin):
    list_display = ['patient_number', 'full_name', 'age', 'age_group', 'gender', 'phone_number', 'nhif_status', 'registration_date']
    list_filter = ['gender', 'nhif_status', 'blood_group', 'registration_date']
    search_fields = ['patient_number', 'first_name', 'last_name', 'id_number', 'phone_number', 'nhif_number']
    readonly_fields = ['patient_number', 'registration_date', 'age', 'age_group', 'created_at', 'updated_at']
    date_hierarchy = 'registration_date'
    
    fieldsets = (
        ('Patient Identification', {
            'fields': ('patient_number', 'first_name', 'middle_name', 'last_name', 'date_of_birth', 'gender', 'id_number')
        }),
        ('Contact Information', {
            'fields': ('phone_number', 'alternate_phone', 'email', 'county', 'sub_county', 'ward', 'village', 'postal_address')
        }),
        ('Next of Kin', {
            'fields': ('next_of_kin_name', 'next_of_kin_relationship', 'next_of_kin_phone', 'next_of_kin_address')
        }),
        ('Medical Information', {
            'fields': ('blood_group', 'allergies', 'chronic_conditions')
        }),
        ('NHIF Information', {
            'fields': ('nhif_status', 'nhif_number', 'nhif_principal_name')
        }),
        ('System Information', {
            'fields': ('registered_by', 'registration_date', 'is_active', 'notes', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('registered_by')


@admin.register(PatientVisit)
class PatientVisitAdmin(admin.ModelAdmin):
    list_display = ['visit_number', 'patient_link', 'visit_type', 'visit_date', 'status', 'priority_level', 'queue_number', 'wait_time']
    list_filter = ['visit_type', 'status', 'visit_date', 'priority_level']
    search_fields = ['visit_number', 'patient__first_name', 'patient__last_name', 'patient__patient_number']
    readonly_fields = ['visit_number', 'queue_number', 'wait_time_minutes', 'created_at', 'updated_at']
    date_hierarchy = 'visit_date'
    
    fieldsets = (
        ('Visit Information', {
            'fields': ('visit_number', 'patient', 'visit_type', 'visit_date', 'arrival_time', 'queue_number', 'priority_level')
        }),
        ('Visit Details', {
            'fields': ('chief_complaint', 'status', 'is_referral', 'referring_facility', 'referral_notes')
        }),
        ('Exit Information', {
            'fields': ('exit_time', 'exit_notes'),
            'classes': ('collapse',)
        }),
    )
    
    def patient_link(self, obj):
        url = reverse('admin:medisphere_patient_change', args=[obj.patient.id])
        return format_html('<a href="{}">{}</a>', url, obj.patient.full_name)
    patient_link.short_description = 'Patient'
    
    def wait_time(self, obj):
        minutes = obj.wait_time_minutes
        hours = minutes // 60
        mins = minutes % 60
        if hours > 0:
            return f"{hours}h {mins}m"
        return f"{mins}m"
    wait_time.short_description = 'Wait Time'
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('patient')


# =============================================================================
# TRIAGE & VITALS
# =============================================================================

@admin.register(TriageAssessment)
class TriageAssessmentAdmin(admin.ModelAdmin):
    list_display = ['visit', 'emergency_level', 'temperature', 'blood_pressure', 'pulse', 'oxygen_saturation', 'bmi', 'assessment_time']
    list_filter = ['emergency_level', 'assessment_time']
    search_fields = ['visit__patient__first_name', 'visit__patient__last_name', 'visit__visit_number']
    readonly_fields = ['assessment_time', 'bmi']
    date_hierarchy = 'assessment_time'
    
    fieldsets = (
        ('Visit Information', {
            'fields': ('visit', 'nurse', 'emergency_level')
        }),
        ('Vital Signs', {
            'fields': ('temperature', 'pulse', 'systolic_bp', 'diastolic_bp', 'respiratory_rate', 'oxygen_saturation')
        }),
        ('Measurements', {
            'fields': ('weight', 'height', 'bmi')
        }),
        ('Assessment', {
            'fields': ('chief_complaint', 'pain_scale', 'triage_notes')
        }),
    )
    
    def blood_pressure(self, obj):
        return f"{obj.systolic_bp}/{obj.diastolic_bp}"
    blood_pressure.short_description = 'BP (mmHg)'


# =============================================================================
# CLINICAL WORKFLOW
# =============================================================================

@admin.register(Consultation)
class ConsultationAdmin(admin.ModelAdmin):
    list_display = ['visit', 'doctor', 'consultation_start', 'consultation_end', 'admission_required', 'consultation_fee']
    list_filter = ['admission_required', 'referral_required', 'consultation_start']
    search_fields = ['visit__patient__first_name', 'visit__patient__last_name', 'visit__visit_number', 'final_diagnosis']
    readonly_fields = ['consultation_fee', 'created_at', 'updated_at']
    date_hierarchy = 'consultation_start'
    
    fieldsets = (
        ('Consultation Details', {
            'fields': ('visit', 'doctor', 'consultation_start', 'consultation_end', 'consultation_fee')
        }),
        ('Clinical Assessment', {
            'fields': ('chief_complaint', 'history_of_illness', 'past_medical_history', 'physical_examination')
        }),
        ('Diagnosis', {
            'fields': ('provisional_diagnosis', 'final_diagnosis', 'differential_diagnosis')
        }),
        ('Treatment & Follow-up', {
            'fields': ('treatment_plan', 'follow_up_instructions', 'follow_up_date')
        }),
        ('Outcome', {
            'fields': ('admission_required', 'referral_required', 'referral_facility')
        }),
    )


@admin.register(ClinicalNote)
class ClinicalNoteAdmin(admin.ModelAdmin):
    list_display = ['visit', 'note_type', 'clinician', 'subject', 'created_at']
    list_filter = ['note_type', 'created_at']
    search_fields = ['visit__patient__first_name', 'visit__patient__last_name', 'subject', 'content']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'


# =============================================================================
# LABORATORY
# =============================================================================

@admin.register(LabTest)
class LabTestAdmin(admin.ModelAdmin):
    list_display = ['test_code', 'name', 'category', 'price', 'turnaround_time_hours', 'requires_fasting', 'is_active']
    list_filter = ['category', 'requires_fasting', 'is_active']
    search_fields = ['test_code', 'name', 'description']
    actions = [make_active, make_inactive]


@admin.register(LabOrder)
class LabOrderAdmin(admin.ModelAdmin):
    list_display = ['order_number', 'visit', 'test', 'ordered_by', 'status', 'priority', 'ordered_at']
    list_filter = ['status', 'priority', 'ordered_at', 'test__category']
    search_fields = ['order_number', 'visit__patient__first_name', 'visit__patient__last_name']
    readonly_fields = ['order_number', 'ordered_at']
    date_hierarchy = 'ordered_at'
    
    fieldsets = (
        ('Order Information', {
            'fields': ('order_number', 'visit', 'test', 'ordered_by', 'ordered_at')
        }),
        ('Sample Details', {
            'fields': ('clinical_notes', 'sample_collected_at', 'sample_collected_by')
        }),
        ('Status', {
            'fields': ('status', 'priority')
        }),
    )


@admin.register(LabResult)
class LabResultAdmin(admin.ModelAdmin):
    list_display = ['lab_order', 'technician', 'result_value', 'is_abnormal', 'verified', 'result_date']
    list_filter = ['is_abnormal', 'result_date']
    search_fields = ['lab_order__order_number', 'lab_order__visit__patient__first_name']
    readonly_fields = ['result_date']
    date_hierarchy = 'result_date'
    
    def verified(self, obj):
        if obj.verified_by:
            return format_html('<span style="color: green;">✓ Verified</span>')
        return format_html('<span style="color: orange;">Pending</span>')
    verified.short_description = 'Verification'


# =============================================================================
# RADIOLOGY
# =============================================================================

@admin.register(RadiologyTest)
class RadiologyTestAdmin(admin.ModelAdmin):
    list_display = ['test_code', 'name', 'modality', 'price', 'estimated_duration_minutes', 'requires_contrast', 'is_active']
    list_filter = ['modality', 'requires_contrast', 'is_active']
    search_fields = ['test_code', 'name', 'description']
    actions = [make_active, make_inactive]


@admin.register(RadiologyOrder)
class RadiologyOrderAdmin(admin.ModelAdmin):
    list_display = ['order_number', 'visit', 'test', 'ordered_by', 'status', 'priority', 'ordered_at']
    list_filter = ['status', 'priority', 'ordered_at', 'test__modality']
    search_fields = ['order_number', 'visit__patient__first_name', 'visit__patient__last_name']
    readonly_fields = ['order_number', 'ordered_at']
    date_hierarchy = 'ordered_at'


@admin.register(RadiologyResult)
class RadiologyResultAdmin(admin.ModelAdmin):
    list_display = ['radiology_order', 'radiologist', 'has_image', 'verified', 'result_date']
    list_filter = ['result_date']
    search_fields = ['radiology_order__order_number', 'findings', 'impression']
    readonly_fields = ['result_date']
    date_hierarchy = 'result_date'
    
    def has_image(self, obj):
        if obj.image_file:
            return format_html('<span style="color: green;">✓</span>')
        return format_html('<span style="color: red;">✗</span>')
    has_image.short_description = 'Image'
    
    def verified(self, obj):
        if obj.verified_by:
            return format_html('<span style="color: green;">✓ Verified</span>')
        return format_html('<span style="color: orange;">Pending</span>')
    verified.short_description = 'Verification'


# =============================================================================
# PHARMACY
# =============================================================================

@admin.register(DrugCategory)
class DrugCategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'drug_count']
    search_fields = ['name', 'description']
    
    def drug_count(self, obj):
        return obj.drugs.count()
    drug_count.short_description = 'Drugs'


@admin.register(Drug)
class DrugAdmin(admin.ModelAdmin):
    list_display = ['drug_code', 'name', 'generic_name', 'category', 'form', 'strength', 'unit_price', 'current_stock', 'stock_status', 'is_active']
    list_filter = ['category', 'form', 'requires_prescription', 'is_active']
    search_fields = ['drug_code', 'name', 'generic_name', 'brand_name']
    actions = [make_active, make_inactive]
    
    fieldsets = (
        ('Drug Information', {
            'fields': ('drug_code', 'name', 'generic_name', 'brand_name', 'category', 'form', 'strength')
        }),
        ('Pricing & Inventory', {
            'fields': ('unit_price', 'reorder_level')
        }),
        ('Details', {
            'fields': ('description', 'contraindications', 'side_effects', 'requires_prescription', 'is_active')
        }),
    )
    
    def stock_status(self, obj):
        stock = obj.current_stock
        if stock == 0:
            return format_html('<span style="color: red;">Out of Stock</span>')
        elif obj.needs_reorder:
            return format_html('<span style="color: orange;">Low Stock</span>')
        return format_html('<span style="color: green;">In Stock</span>')
    stock_status.short_description = 'Stock Status'


@admin.register(DrugStock)
class DrugStockAdmin(admin.ModelAdmin):
    list_display = ['drug', 'batch_number', 'quantity', 'expiry_date', 'days_to_expiry', 'expiry_status', 'received_date']
    list_filter = ['expiry_date', 'received_date']
    search_fields = ['drug__name', 'batch_number', 'supplier_name']
    readonly_fields = ['received_date', 'created_at', 'days_to_expiry', 'is_expired']
    date_hierarchy = 'received_date'
    
    def expiry_status(self, obj):
        if obj.is_expired:
            return format_html('<span style="color: red;">Expired</span>')
        elif obj.days_to_expiry <= 30:
            return format_html('<span style="color: orange;">Expiring Soon</span>')
        return format_html('<span style="color: green;">Valid</span>')
    expiry_status.short_description = 'Status'


@admin.register(Prescription)
class PrescriptionAdmin(admin.ModelAdmin):
    list_display = ['prescription_number', 'visit', 'prescribed_by', 'status', 'prescribed_at', 'item_count']
    list_filter = ['status', 'prescribed_at']
    search_fields = ['prescription_number', 'visit__patient__first_name', 'visit__patient__last_name']
    readonly_fields = ['prescription_number', 'prescribed_at']
    date_hierarchy = 'prescribed_at'
    
    def item_count(self, obj):
        return obj.items.count()
    item_count.short_description = 'Items'


class PrescriptionItemInline(admin.TabularInline):
    model = PrescriptionItem
    extra = 1
    readonly_fields = ['dispensed_at']


@admin.register(PrescriptionItem)
class PrescriptionItemAdmin(admin.ModelAdmin):
    list_display = ['prescription', 'drug', 'quantity', 'dispensed_quantity', 'dosage', 'dispensed_by', 'dispensed_at']
    list_filter = ['dispensed_at']
    search_fields = ['prescription__prescription_number', 'drug__name']
    readonly_fields = ['dispensed_at']


# =============================================================================
# INPATIENT MANAGEMENT
# =============================================================================

@admin.register(Ward)
class WardAdmin(admin.ModelAdmin):
    list_display = ['name', 'ward_type', 'total_beds', 'occupied_beds', 'available_beds', 'occupancy_rate', 'is_active']
    list_filter = ['ward_type', 'is_active']
    search_fields = ['name', 'location']
    actions = [make_active, make_inactive]
    
    def occupancy_rate(self, obj):
        rate = obj.occupancy_rate
        color = 'green' if rate < 70 else 'orange' if rate < 90 else 'red'
        return format_html(f'<span style="color: {color};">{rate}%</span>')
    occupancy_rate.short_description = 'Occupancy'


@admin.register(Bed)
class BedAdmin(admin.ModelAdmin):
    list_display = ['ward', 'bed_number', 'status', 'is_occupied', 'daily_rate']
    list_filter = ['ward', 'status', 'is_occupied']
    search_fields = ['ward__name', 'bed_number']


@admin.register(Admission)
class AdmissionAdmin(admin.ModelAdmin):
    list_display = ['admission_number', 'patient', 'bed', 'admission_datetime', 'status', 'length_of_stay', 'admitting_doctor']
    list_filter = ['status', 'admission_type', 'admission_datetime']
    search_fields = ['admission_number', 'patient__first_name', 'patient__last_name']
    readonly_fields = ['admission_number', 'created_at', 'updated_at', 'length_of_stay']
    date_hierarchy = 'admission_datetime'
    
    fieldsets = (
        ('Admission Details', {
            'fields': ('admission_number', 'visit', 'patient', 'admission_type', 'admission_datetime', 'bed', 'admitting_doctor')
        }),
        ('Medical Information', {
            'fields': ('admission_diagnosis', 'admission_notes', 'status')
        }),
        ('Discharge Information', {
            'fields': ('discharge_datetime', 'discharge_diagnosis', 'discharge_summary', 'discharge_instructions', 'discharged_by'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ProgressNote)
class ProgressNoteAdmin(admin.ModelAdmin):
    list_display = ['admission', 'doctor', 'note_date', 'created_at']
    list_filter = ['note_date']
    search_fields = ['admission__patient__first_name', 'admission__patient__last_name']
    readonly_fields = ['created_at']
    date_hierarchy = 'note_date'


@admin.register(NursingNote)
class NursingNoteAdmin(admin.ModelAdmin):
    list_display = ['admission', 'nurse', 'shift', 'note_datetime']
    list_filter = ['shift', 'note_datetime']
    search_fields = ['admission__patient__first_name', 'admission__patient__last_name']
    readonly_fields = ['created_at']
    date_hierarchy = 'note_datetime'


@admin.register(MedicationAdministrationRecord)
class MedicationAdministrationRecordAdmin(admin.ModelAdmin):
    list_display = ['admission', 'prescription_item', 'scheduled_datetime', 'status', 'administered_by', 'administered_datetime']
    list_filter = ['status', 'scheduled_datetime']
    search_fields = ['admission__patient__first_name', 'prescription_item__drug__name']
    readonly_fields = ['created_at']
    date_hierarchy = 'scheduled_datetime'


# =============================================================================
# THEATRE/SURGERY
# =============================================================================

@admin.register(TheatreRoom)
class TheatreRoomAdmin(admin.ModelAdmin):
    list_display = ['name', 'room_number', 'location', 'is_available', 'is_active']
    list_filter = ['is_available', 'is_active']
    search_fields = ['name', 'room_number', 'location']


@admin.register(Surgery)
class SurgeryAdmin(admin.ModelAdmin):
    list_display = ['surgery_number', 'patient', 'procedure_name', 'scheduled_datetime', 'surgeon', 'status', 'duration']
    list_filter = ['status', 'surgery_type', 'scheduled_datetime']
    search_fields = ['surgery_number', 'patient__first_name', 'patient__last_name', 'procedure_name']
    readonly_fields = ['surgery_number', 'created_at', 'updated_at', 'duration_minutes']
    date_hierarchy = 'scheduled_datetime'
    
    fieldsets = (
        ('Surgery Details', {
            'fields': ('surgery_number', 'admission', 'patient', 'procedure_name', 'surgery_type', 'scheduled_datetime', 'theatre_room')
        }),
        ('Medical Team', {
            'fields': ('surgeon', 'assistant_surgeon', 'anaesthetist')
        }),
        ('Medical Information', {
            'fields': ('pre_op_diagnosis', 'post_op_diagnosis', 'procedure_notes', 'anaesthesia_notes')
        }),
        ('Timing', {
            'fields': ('start_time', 'end_time', 'duration_minutes', 'status')
        }),
        ('Billing', {
            'fields': ('surgery_fee', 'anaesthesia_fee', 'theatre_fee')
        }),
    )
    
    def duration(self, obj):
        if obj.duration_minutes:
            hours = obj.duration_minutes // 60
            mins = obj.duration_minutes % 60
            return f"{hours}h {mins}m" if hours > 0 else f"{mins}m"
        return "-"
    duration.short_description = 'Duration'


# =============================================================================
# BILLING & PAYMENTS
# =============================================================================

class InvoiceItemInline(admin.TabularInline):
    model = InvoiceItem
    extra = 0
    readonly_fields = ['created_at', 'line_total']
    
    def line_total(self, obj):
        return f"KES {obj.line_total:,.2f}"
    line_total.short_description = 'Total'


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ['invoice_number', 'patient', 'invoice_date', 'total_amount', 'amount_paid', 'balance', 'status']
    list_filter = ['status', 'invoice_date']
    search_fields = ['invoice_number', 'patient__first_name', 'patient__last_name']
    readonly_fields = ['invoice_number', 'invoice_date', 'subtotal', 'total_amount', 'balance', 'created_at', 'updated_at']
    date_hierarchy = 'invoice_date'
    inlines = [InvoiceItemInline]
    
    fieldsets = (
        ('Invoice Information', {
            'fields': ('invoice_number', 'visit', 'patient', 'invoice_date', 'due_date', 'status')
        }),
        ('Amounts', {
            'fields': ('subtotal', 'discount', 'tax', 'total_amount', 'amount_paid', 'balance')
        }),
        ('NHIF', {
            'fields': ('nhif_coverage_amount', 'patient_copay'),
            'classes': ('collapse',)
        }),
        ('Notes', {
            'fields': ('notes',),
            'classes': ('collapse',)
        }),
    )


@admin.register(InvoiceItem)
class InvoiceItemAdmin(admin.ModelAdmin):
    list_display = ['invoice', 'item_type', 'description', 'quantity', 'unit_price', 'line_total']
    list_filter = ['item_type', 'created_at']
    search_fields = ['invoice__invoice_number', 'description']
    readonly_fields = ['created_at']


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['payment_number', 'invoice', 'payment_method', 'amount', 'status', 'payment_date', 'received_by']
    list_filter = ['payment_method', 'status', 'payment_date']
    search_fields = ['payment_number', 'invoice__invoice_number', 'mpesa_receipt_number']
    readonly_fields = ['payment_number', 'created_at']
    date_hierarchy = 'payment_date'
    actions = [mark_payment_completed]
    
    fieldsets = (
        ('Payment Information', {
            'fields': ('payment_number', 'invoice', 'payment_method', 'amount', 'payment_date', 'received_by', 'status')
        }),
        ('M-Pesa Details', {
            'fields': ('mpesa_receipt_number', 'mpesa_phone_number', 'mpesa_transaction_id'),
            'classes': ('collapse',)
        }),
        ('Other Details', {
            'fields': ('reference_number', 'notes'),
            'classes': ('collapse',)
        }),
    )


@admin.register(MpesaTransaction)
class MpesaTransactionAdmin(admin.ModelAdmin):
    list_display = ['checkout_request_id', 'patient', 'phone_number', 'amount', 'status', 'mpesa_receipt_number', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['checkout_request_id', 'merchant_request_id', 'phone_number', 'mpesa_receipt_number']
    readonly_fields = ['created_at', 'updated_at']
    date_hierarchy = 'created_at'


@admin.register(Receipt)
class ReceiptAdmin(admin.ModelAdmin):
    list_display = ['receipt_number', 'payment', 'issued_date', 'issued_by']
    list_filter = ['issued_date']
    search_fields = ['receipt_number', 'payment__payment_number']
    readonly_fields = ['receipt_number', 'issued_date']
    date_hierarchy = 'issued_date'


# =============================================================================
# NHIF MANAGEMENT
# =============================================================================

@admin.register(NHIFScheme)
class NHIFSchemeAdmin(admin.ModelAdmin):
    list_display = ['code', 'name', 'scheme_type', 'coverage_amount', 'copay_percentage', 'is_active']
    list_filter = ['scheme_type', 'is_active']
    search_fields = ['code', 'name']
    actions = [make_active, make_inactive]


@admin.register(NHIFClaim)
class NHIFClaimAdmin(admin.ModelAdmin):
    list_display = ['claim_number', 'patient', 'claim_type', 'claimed_amount', 'approved_amount', 'status', 'submitted_at']
    list_filter = ['status', 'claim_type', 'created_at']
    search_fields = ['claim_number', 'patient__first_name', 'patient__last_name']
    readonly_fields = ['claim_number', 'created_at', 'updated_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Claim Information', {
            'fields': ('claim_number', 'visit', 'patient', 'invoice', 'claim_type', 'scheme')
        }),
        ('Amounts', {
            'fields': ('claimed_amount', 'approved_amount', 'status')
        }),
        ('Verification', {
            'fields': ('verified_by', 'verified_at', 'submitted_by', 'submitted_at')
        }),
        ('Response', {
            'fields': ('rejection_reason', 'nhif_response_date', 'notes'),
            'classes': ('collapse',)
        }),
    )


# =============================================================================
# NOTIFICATIONS & MESSAGING
# =============================================================================

@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['recipient', 'notification_type', 'title', 'is_read', 'created_at']
    list_filter = ['notification_type', 'is_read', 'created_at']
    search_fields = ['recipient__username', 'title', 'message']
    readonly_fields = ['created_at', 'read_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Notification Details', {
            'fields': ('recipient', 'notification_type', 'title', 'message', 'link_url')
        }),
        ('Status', {
            'fields': ('is_read', 'read_at', 'created_at')
        }),
    )


@admin.register(SMSLog)
class SMSLogAdmin(admin.ModelAdmin):
    list_display = ['patient', 'phone_number', 'sms_type', 'status', 'sent_at', 'created_at']
    list_filter = ['sms_type', 'status', 'created_at']
    search_fields = ['patient__first_name', 'patient__last_name', 'phone_number', 'message']
    readonly_fields = ['sent_at', 'created_at']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('SMS Details', {
            'fields': ('patient', 'phone_number', 'sms_type', 'message')
        }),
        ('Status', {
            'fields': ('status', 'external_id', 'sent_at', 'created_at')
        }),
    )


# =============================================================================
# HOSPITAL SETTINGS
# =============================================================================

@admin.register(HospitalSettings)
class HospitalSettingsAdmin(admin.ModelAdmin):
    list_display = ['hospital_name', 'hospital_phone', 'hospital_email', 'mpesa_environment', 'sms_enabled']
    
    fieldsets = (
        ('Hospital Information', {
            'fields': ('hospital_name', 'hospital_address', 'hospital_phone', 'hospital_email')
        }),
        ('Financial Settings', {
            'fields': ('default_consultation_fee', 'emergency_surcharge', 'tax_rate')
        }),
        ('M-Pesa Configuration', {
            'fields': ('mpesa_shortcode', 'mpesa_passkey', 'mpesa_consumer_key', 'mpesa_consumer_secret', 'mpesa_environment'),
            'classes': ('collapse',)
        }),
        ('SMS Configuration', {
            'fields': ('sms_enabled', 'sms_api_key', 'sms_sender_id'),
            'classes': ('collapse',)
        }),
    )
    
    def has_add_permission(self, request):
        # Only allow one instance
        return not HospitalSettings.objects.exists()
    
    def has_delete_permission(self, request, obj=None):
        # Don't allow deletion
        return False


# =============================================================================
# AUDIT LOG
# =============================================================================

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'user', 'action_type', 'model_name', 'object_repr', 'ip_address']
    list_filter = ['action_type', 'model_name', 'timestamp']
    search_fields = ['user__username', 'model_name', 'object_repr', 'changes']
    readonly_fields = ['timestamp', 'user', 'action_type', 'model_name', 'object_id', 'object_repr', 'changes', 'ip_address', 'user_agent']
    date_hierarchy = 'timestamp'
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False


# =============================================================================
# APPOINTMENTS
# =============================================================================

@admin.register(Appointment)
class AppointmentAdmin(admin.ModelAdmin):
    list_display = ['appointment_number', 'patient', 'doctor', 'appointment_datetime', 'duration_minutes', 'status', 'sms_reminder_sent']
    list_filter = ['status', 'appointment_datetime', 'sms_reminder_sent']
    search_fields = ['appointment_number', 'patient__first_name', 'patient__last_name', 'reason']
    readonly_fields = ['appointment_number', 'created_at', 'updated_at', 'sms_reminder_sent_at']
    date_hierarchy = 'appointment_datetime'
    
    fieldsets = (
        ('Appointment Details', {
            'fields': ('appointment_number', 'patient', 'doctor', 'appointment_datetime', 'duration_minutes', 'appointment_type')
        }),
        ('Details', {
            'fields': ('reason', 'status', 'notes')
        }),
        ('Reminders', {
            'fields': ('sms_reminder_sent', 'sms_reminder_sent_at'),
            'classes': ('collapse',)
        }),
    )


# =============================================================================
# CUSTOM ADMIN SITE CONFIGURATION
# =============================================================================

class MediSphereAdminSite(admin.AdminSite):
    site_header = 'MediSphere Hospital Management System'
    site_title = 'MediSphere Admin'
    index_title = 'Hospital Administration Dashboard'
    
    def index(self, request, extra_context=None):
        """Custom dashboard with statistics"""
        extra_context = extra_context or {}
        
        # Get today's statistics
        today = timezone.now().date()
        
        extra_context['today_visits'] = PatientVisit.objects.filter(visit_date=today).count()
        extra_context['today_admissions'] = Admission.objects.filter(admission_datetime__date=today).count()
        extra_context['pending_lab_orders'] = LabOrder.objects.filter(status__in=['ORDERED', 'RECEIVED', 'IN_PROGRESS']).count()
        extra_context['pending_radiology_orders'] = RadiologyOrder.objects.filter(status__in=['ORDERED', 'SCHEDULED', 'IN_PROGRESS']).count()
        extra_context['pending_prescriptions'] = Prescription.objects.filter(status='PENDING').count()
        extra_context['active_admissions'] = Admission.objects.filter(status='ACTIVE').count()
        extra_context['pending_invoices'] = Invoice.objects.filter(status__in=['PENDING', 'PARTIALLY_PAID']).count()
        extra_context['today_revenue'] = Payment.objects.filter(
            payment_date__date=today, 
            status='COMPLETED'
        ).aggregate(total=Sum('amount'))['total'] or 0
        
        return super().index(request, extra_context)


# Uncomment below if you want to use custom admin site
# admin_site = MediSphereAdminSite(name='medisphere_admin')
# Then register all models to admin_site instead of admin.site


# =============================================================================
# ADMIN DASHBOARD CUSTOMIZATION
# =============================================================================

# Customize the admin interface
admin.site.site_header = 'MediSphere Hospital Management'
admin.site.site_title = 'MediSphere Admin'
admin.site.index_title = 'Hospital Administration'


# =============================================================================
# INLINE ADMIN CLASSES FOR BETTER ORGANIZATION
# =============================================================================

class LabOrderInline(admin.TabularInline):
    model = LabOrder
    extra = 0
    fields = ['test', 'status', 'ordered_by', 'ordered_at']
    readonly_fields = ['ordered_at']
    can_delete = False
    show_change_link = True


class RadiologyOrderInline(admin.TabularInline):
    model = RadiologyOrder
    extra = 0
    fields = ['test', 'status', 'ordered_by', 'ordered_at']
    readonly_fields = ['ordered_at']
    can_delete = False
    show_change_link = True


class PrescriptionInlineForVisit(admin.TabularInline):
    model = Prescription
    extra = 0
    fields = ['prescription_number', 'prescribed_by', 'status', 'prescribed_at']
    readonly_fields = ['prescription_number', 'prescribed_at']
    can_delete = False
    show_change_link = True


# Enhanced PatientVisit Admin with inlines
class PatientVisitEnhancedAdmin(PatientVisitAdmin):
    inlines = [LabOrderInline, RadiologyOrderInline, PrescriptionInlineForVisit]


# Re-register with inlines
admin.site.unregister(PatientVisit)
admin.site.register(PatientVisit, PatientVisitEnhancedAdmin)


# =============================================================================
# CUSTOM FILTERS
# =============================================================================

class TodayVisitsFilter(admin.SimpleListFilter):
    title = 'visit date'
    parameter_name = 'visit_date'
    
    def lookups(self, request, model_admin):
        return (
            ('today', 'Today'),
            ('yesterday', 'Yesterday'),
            ('this_week', 'This Week'),
            ('this_month', 'This Month'),
        )
    
    def queryset(self, request, queryset):
        today = timezone.now().date()
        
        if self.value() == 'today':
            return queryset.filter(visit_date=today)
        elif self.value() == 'yesterday':
            yesterday = today - timezone.timedelta(days=1)
            return queryset.filter(visit_date=yesterday)
        elif self.value() == 'this_week':
            week_start = today - timezone.timedelta(days=today.weekday())
            return queryset.filter(visit_date__gte=week_start)
        elif self.value() == 'this_month':
            return queryset.filter(visit_date__year=today.year, visit_date__month=today.month)


class StockLevelFilter(admin.SimpleListFilter):
    title = 'stock level'
    parameter_name = 'stock_level'
    
    def lookups(self, request, model_admin):
        return (
            ('out_of_stock', 'Out of Stock'),
            ('low_stock', 'Low Stock'),
            ('in_stock', 'In Stock'),
        )
    
    def queryset(self, request, queryset):
        if self.value() == 'out_of_stock':
            return queryset.filter(current_stock=0)
        elif self.value() == 'low_stock':
            return queryset.filter(current_stock__lte=models.F('reorder_level'), current_stock__gt=0)
        elif self.value() == 'in_stock':
            return queryset.filter(current_stock__gt=models.F('reorder_level'))


# =============================================================================
# SUMMARY REPORTS IN ADMIN
# =============================================================================

class DailySummaryReport(admin.ModelAdmin):
    """Custom admin view for daily summary reports"""
    change_list_template = 'admin/daily_summary.html'
    
    def changelist_view(self, request, extra_context=None):
        today = timezone.now().date()
        
        # Calculate daily statistics
        response = super().changelist_view(request, extra_context)
        
        if hasattr(response, 'context_data'):
            response.context_data['summary'] = {
                'total_visits': PatientVisit.objects.filter(visit_date=today).count(),
                'emergency_visits': PatientVisit.objects.filter(visit_date=today, visit_type='EMERGENCY').count(),
                'new_admissions': Admission.objects.filter(admission_datetime__date=today).count(),
                'discharges': Admission.objects.filter(discharge_datetime__date=today).count(),
                'lab_tests_completed': LabResult.objects.filter(result_date__date=today).count(),
                'prescriptions_dispensed': PrescriptionItem.objects.filter(dispensed_at__date=today).count(),
                'revenue': Payment.objects.filter(payment_date__date=today, status='COMPLETED').aggregate(
                    total=Sum('amount'))['total'] or 0,
            }
        
        return response


# =============================================================================
# EXPORT ACTIONS
# =============================================================================

@admin.action(description='Export selected to CSV')
def export_to_csv(modeladmin, request, queryset):
    import csv
    from django.http import HttpResponse
    
    meta = modeladmin.model._meta
    field_names = [field.name for field in meta.fields]
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename={meta}.csv'
    
    writer = csv.writer(response)
    writer.writerow(field_names)
    
    for obj in queryset:
        writer.writerow([getattr(obj, field) for field in field_names])
    
    return response


# Add export action to key admin classes
PatientAdmin.actions = [export_to_csv]
PatientVisitAdmin.actions = [export_to_csv]
InvoiceAdmin.actions = [export_to_csv]
PaymentAdmin.actions = [export_to_csv, mark_payment_completed]


# =============================================================================
# ADMIN LIST DISPLAY CUSTOMIZATIONS
# =============================================================================

# Color-coded status displays
def colored_status(status, color_map):
    """Helper function to display colored status"""
    color = color_map.get(status, 'black')
    return format_html(
        '<span style="color: {}; font-weight: bold;">{}</span>',
        color,
        status
    )


# Add to various admin classes
def visit_status_colored(obj):
    color_map = {
        'WAITING': 'orange',
        'TRIAGE': 'blue',
        'CONSULTATION': 'purple',
        'COMPLETED': 'green',
        'CANCELLED': 'red',
    }
    return colored_status(obj.status, color_map)

visit_status_colored.short_description = 'Status'


def payment_status_colored(obj):
    color_map = {
        'PENDING': 'orange',
        'COMPLETED': 'green',
        'FAILED': 'red',
        'REVERSED': 'gray',
    }
    return colored_status(obj.status, color_map)

payment_status_colored.short_description = 'Status'


# =============================================================================
# MASS UPDATE ACTIONS
# =============================================================================

@admin.action(description='Mark as completed')
def mark_completed(modeladmin, request, queryset):
    count = queryset.update(status='COMPLETED')
    modeladmin.message_user(request, f'{count} items marked as completed.')


@admin.action(description='Mark as cancelled')
def mark_cancelled(modeladmin, request, queryset):
    count = queryset.update(status='CANCELLED')
    modeladmin.message_user(request, f'{count} items marked as cancelled.')


# Add these actions to relevant admins
LabOrderAdmin.actions = [mark_completed, mark_cancelled, export_to_csv]
RadiologyOrderAdmin.actions = [mark_completed, mark_cancelled, export_to_csv]


# =============================================================================
# PERFORMANCE OPTIMIZATIONS
# =============================================================================

# Add select_related and prefetch_related to improve query performance
def optimize_queryset(admin_class):
    """Decorator to add select_related to admin queryset"""
    original_get_queryset = admin_class.get_queryset
    
    def get_queryset(self, request):
        qs = original_get_queryset(self, request)
        # Add select_related for foreign keys
        if hasattr(self.model, 'patient'):
            qs = qs.select_related('patient')
        if hasattr(self.model, 'visit'):
            qs = qs.select_related('visit', 'visit__patient')
        if hasattr(self.model, 'user'):
            qs = qs.select_related('user')
        return qs
    
    admin_class.get_queryset = get_queryset
    return admin_class


# Apply optimization to key admin classes
PatientVisitAdmin = optimize_queryset(PatientVisitAdmin)
ConsultationAdmin = optimize_queryset(ConsultationAdmin)
LabOrderAdmin = optimize_queryset(LabOrderAdmin)
RadiologyOrderAdmin = optimize_queryset(RadiologyOrderAdmin)


# =============================================================================
# READONLY PERMISSIONS FOR CERTAIN ROLES
# =============================================================================

class ReadOnlyAdminMixin:
    """Mixin to make admin readonly for non-superusers"""
    
    def has_add_permission(self, request):
        if not request.user.is_superuser:
            return False
        return super().has_add_permission(request)
    
    def has_delete_permission(self, request, obj=None):
        if not request.user.is_superuser:
            return False
        return super().has_delete_permission(request, obj)
    
    def has_change_permission(self, request, obj=None):
        if not request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)


# Apply readonly to audit log and settings
class AuditLogReadOnlyAdmin(ReadOnlyAdminMixin, AuditLogAdmin):
    pass


# Re-register with readonly
admin.site.unregister(AuditLog)
admin.site.register(AuditLog, AuditLogReadOnlyAdmin)


# =============================================================================
# ADMIN INTERFACE ENHANCEMENTS
# =============================================================================

# Enable autocomplete for foreign keys in admin
PatientAdmin.search_fields = ['patient_number', 'first_name', 'last_name', 'phone_number', 'id_number']
UserAdmin.search_fields = ['username', 'first_name', 'last_name', 'email']
DrugAdmin.search_fields = ['drug_code', 'name', 'generic_name']

# Add autocomplete_fields to speed up form loading
PatientVisitAdmin.autocomplete_fields = ['patient']
ConsultationAdmin.autocomplete_fields = ['visit', 'doctor']
LabOrderAdmin.autocomplete_fields = ['visit', 'test', 'ordered_by']
PrescriptionAdmin.autocomplete_fields = ['visit', 'prescribed_by']
AdmissionAdmin.autocomplete_fields = ['patient', 'visit', 'bed', 'admitting_doctor']


# =============================================================================
# CUSTOM ADMIN ACTIONS FOR BUSINESS LOGIC
# =============================================================================

@admin.action(description='Send appointment reminders')
def send_appointment_reminders(modeladmin, request, queryset):
    """Send SMS reminders for appointments"""
    tomorrow = timezone.now().date() + timezone.timedelta(days=1)
    appointments = queryset.filter(
        appointment_datetime__date=tomorrow,
        sms_reminder_sent=False
    )
    
    count = 0
    for appointment in appointments:
        # Logic to send SMS would go here
        SMSLog.objects.create(
            patient=appointment.patient,
            phone_number=appointment.patient.phone_number,
            sms_type='APPOINTMENT',
            message=f'Reminder: You have an appointment tomorrow at {appointment.appointment_datetime.strftime("%I:%M %p")} with Dr. {appointment.doctor.last_name}',
            status='PENDING'
        )
        appointment.sms_reminder_sent = True
        appointment.sms_reminder_sent_at = timezone.now()
        appointment.save()
        count += 1
    
    modeladmin.message_user(request, f'{count} appointment reminders queued.')


AppointmentAdmin.actions = [send_appointment_reminders, export_to_csv]


@admin.action(description='Generate NHIF claim forms')
def generate_nhif_claims(modeladmin, request, queryset):
    """Generate NHIF claim forms for selected invoices"""
    count = 0
    for invoice in queryset:
        if invoice.patient.nhif_status == 'ACTIVE' and not hasattr(invoice, 'nhif_claim'):
            # Create NHIF claim
            NHIFClaim.objects.create(
                visit=invoice.visit,
                patient=invoice.patient,
                invoice=invoice,
                claim_type='OUTPATIENT',
                claimed_amount=invoice.total_amount,
                status='DRAFT'
            )
            count += 1
    
    modeladmin.message_user(request, f'{count} NHIF claims generated.')


InvoiceAdmin.actions = [generate_nhif_claims, export_to_csv]


# =============================================================================
# HELP TEXT AND DOCUMENTATION
# =============================================================================

# Add help text to admin site
admin.site.site_url = '/dashboard/'  # Link to main application dashboard

   