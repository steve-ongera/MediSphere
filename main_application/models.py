"""
MediSphere Hospital Management System - Complete Models
Production-ready Django models for Kenyan Level 4/5 Hospital
Includes: M-Pesa Integration, NHIF Support, Complete Patient Journey
"""

from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.utils import timezone
from django.db.models import Sum, Count, Q, F, Avg
from decimal import Decimal
import uuid


# =============================================================================
# USER MANAGEMENT & ACCESS CONTROL
# =============================================================================

class Role(models.Model):
    """User roles for access control"""
    ROLE_CHOICES = [
        ('MEDICAL_SUPERINTENDENT', 'Medical Superintendent'),
        ('DOCTOR', 'Doctor'),
        ('CLINICAL_OFFICER', 'Clinical Officer'),
        ('NURSE', 'Nurse'),
        ('LAB_TECHNICIAN', 'Lab Technician'),
        ('RADIOLOGIST', 'Radiologist'),
        ('PHARMACIST', 'Pharmacist'),
        ('RECEPTIONIST', 'Receptionist'),
        ('CASHIER', 'Cashier'),
        ('NHIF_OFFICER', 'NHIF Officer'),
        ('IT_ADMIN', 'IT Admin'),
    ]
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    description = models.TextField(blank=True)
    can_prescribe = models.BooleanField(default=False)
    can_admit_patients = models.BooleanField(default=False)
    can_access_billing = models.BooleanField(default=False)
    can_manage_inventory = models.BooleanField(default=False)
    can_view_reports = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.get_name_display()


class Department(models.Model):
    """Hospital departments"""
    DEPARTMENT_CHOICES = [
        ('REGISTRATION', 'Registration'),
        ('TRIAGE', 'Triage'),
        ('OUTPATIENT', 'Outpatient'),
        ('INPATIENT', 'Inpatient'),
        ('LABORATORY', 'Laboratory'),
        ('RADIOLOGY', 'Radiology'),
        ('PHARMACY', 'Pharmacy'),
        ('BILLING', 'Billing'),
        ('NHIF_DESK', 'NHIF Desk'),
        ('THEATRE', 'Theatre'),
        ('MATERNITY', 'Maternity'),
        ('PAEDIATRICS', 'Paediatrics'),
        ('ADMINISTRATION', 'Administration'),
    ]
    
    name = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES, unique=True)
    description = models.TextField(blank=True)
    location = models.CharField(max_length=200, blank=True)
    phone_extension = models.CharField(max_length=10, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.get_name_display()


class User(AbstractUser):
    """Extended user model for staff"""
    role = models.ForeignKey(Role, on_delete=models.PROTECT, null=True, blank=True, related_name='users')
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True, blank=True, related_name='staff')
    phone_number = models.CharField(max_length=15, blank=True)
    is_active_staff = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['last_name', 'first_name']
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.role.name if self.role else 'No Role'})"


class StaffProfile(models.Model):
    """Extended staff information"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    staff_number = models.CharField(max_length=20, unique=True)
    id_number = models.CharField(max_length=20, unique=True, validators=[
        RegexValidator(regex=r'^\d{7,8}$', message='ID number must be 7-8 digits')
    ])
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=[('MALE', 'Male'), ('FEMALE', 'Female')])
    address = models.TextField()
    emergency_contact_name = models.CharField(max_length=200)
    emergency_contact_phone = models.CharField(max_length=15)
    
    specialization = models.CharField(max_length=200, blank=True, help_text="For doctors and specialists")
    license_number = models.CharField(max_length=50, blank=True, help_text="Medical license/registration number")
    hire_date = models.DateField(default=timezone.now)
    
    photo = models.ImageField(upload_to='staff_photos/', null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['user__last_name']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.staff_number}"


# =============================================================================
# PATIENT MANAGEMENT
# =============================================================================

class Patient(models.Model):
    """Core patient record - handles non-unique ID numbers (children sharing parent's ID)"""
    GENDER_CHOICES = [
        ('MALE', 'Male'),
        ('FEMALE', 'Female'),
        ('OTHER', 'Other'),
    ]
    
    AGE_GROUP_CHOICES = [
        ('INFANT', 'Infant (0-1 year)'),
        ('CHILD', 'Child (1-12 years)'),
        ('TEEN', 'Teenager (13-17 years)'),
        ('ADULT', 'Adult (18-64 years)'),
        ('ELDERLY', 'Elderly (65+ years)'),
    ]
    
    NHIF_STATUS_CHOICES = [
        ('NONE', 'Not Registered'),
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('CIVIL_SERVANT', 'Civil Servant'),
    ]
    
    # Unique identifier for the system
    patient_number = models.CharField(max_length=20, unique=True, editable=False, db_index=True)
    
    # Personal Information
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100)
    date_of_birth = models.DateField()
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    
    # ID Number - NOT UNIQUE (multiple children can share parent's ID)
    id_number = models.CharField(max_length=20, blank=True, db_index=True, 
                                  help_text="Can be shared among family members (children)")
    
    # Contact Information
    phone_number = models.CharField(max_length=15, validators=[
        RegexValidator(regex=r'^(\+?254|0)?[17]\d{8}$', message='Enter a valid Kenyan phone number')
    ])
    alternate_phone = models.CharField(max_length=15, blank=True)
    email = models.EmailField(blank=True)
    county = models.CharField(max_length=100)
    sub_county = models.CharField(max_length=100, blank=True)
    ward = models.CharField(max_length=100, blank=True)
    village = models.CharField(max_length=100, blank=True)
    postal_address = models.CharField(max_length=200, blank=True)
    
    # Next of Kin
    next_of_kin_name = models.CharField(max_length=200)
    next_of_kin_relationship = models.CharField(max_length=50)
    next_of_kin_phone = models.CharField(max_length=15)
    next_of_kin_address = models.TextField(blank=True)
    
    # Medical Information
    blood_group = models.CharField(max_length=5, blank=True, choices=[
        ('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'),
        ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-'),
    ])
    allergies = models.TextField(blank=True, help_text="List all known allergies")
    chronic_conditions = models.TextField(blank=True, help_text="Diabetes, Hypertension, etc.")
    
    # NHIF Information
    nhif_status = models.CharField(max_length=20, choices=NHIF_STATUS_CHOICES, default='NONE')
    nhif_number = models.CharField(max_length=20, blank=True)
    nhif_principal_name = models.CharField(max_length=200, blank=True, help_text="For dependents")
    
    # System fields
    registration_date = models.DateTimeField(auto_now_add=True)
    registered_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='patients_registered')
    is_active = models.BooleanField(default=True)
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-registration_date']
        indexes = [
            models.Index(fields=['patient_number']),
            models.Index(fields=['id_number']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['last_name', 'first_name']),
            models.Index(fields=['nhif_number']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.patient_number:
            today = timezone.now().date()
            count = Patient.objects.filter(registration_date__date=today).count() + 1
            self.patient_number = f"PAT{today.strftime('%Y%m%d')}{count:04d}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.patient_number} - {self.full_name}"
    
    @property
    def full_name(self):
        middle = f" {self.middle_name}" if self.middle_name else ""
        return f"{self.first_name}{middle} {self.last_name}"
    
    @property
    def age(self):
        today = timezone.now().date()
        age = today.year - self.date_of_birth.year
        if today.month < self.date_of_birth.month or (today.month == self.date_of_birth.month and today.day < self.date_of_birth.day):
            age -= 1
        return age
    
    @property
    def age_group(self):
        age = self.age
        if age < 1:
            return 'INFANT'
        elif age < 13:
            return 'CHILD'
        elif age < 18:
            return 'TEEN'
        elif age < 65:
            return 'ADULT'
        else:
            return 'ELDERLY'
    
    @property
    def formatted_phone(self):
        """Format phone number to 254XXXXXXXXX for M-Pesa"""
        phone = self.phone_number.replace('+', '').replace(' ', '')
        if phone.startswith('0'):
            return f"254{phone[1:]}"
        elif phone.startswith('254'):
            return phone
        elif phone.startswith('7') or phone.startswith('1'):
            return f"254{phone}"
        return phone


class PatientVisit(models.Model):
    """Individual patient visits/encounters"""
    VISIT_TYPE_CHOICES = [
        ('OUTPATIENT', 'Outpatient'),
        ('EMERGENCY', 'Emergency'),
        ('INPATIENT', 'Inpatient'),
        ('REFERRAL', 'Referral'),
        ('AMBULANCE', 'Ambulance'),
    ]
    
    STATUS_CHOICES = [
        ('WAITING', 'Waiting'),
        ('TRIAGE', 'In Triage'),
        ('CONSULTATION', 'In Consultation'),
        ('LABORATORY', 'Lab Tests Pending'),
        ('RADIOLOGY', 'Radiology Pending'),
        ('PHARMACY', 'Pharmacy Pending'),
        ('BILLING', 'At Billing'),
        ('ADMITTED', 'Admitted'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    # Unique visit identifier
    visit_number = models.CharField(max_length=20, unique=True, editable=False, db_index=True)
    
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='visits')
    visit_type = models.CharField(max_length=20, choices=VISIT_TYPE_CHOICES)
    visit_date = models.DateField(default=timezone.now)
    arrival_time = models.DateTimeField(default=timezone.now)
    
    # Queue Management
    queue_number = models.PositiveIntegerField(editable=False)
    priority_level = models.IntegerField(default=3, validators=[MinValueValidator(1), MaxValueValidator(5)],
                                         help_text="1=Critical, 2=Emergency, 3=Urgent, 4=Normal, 5=Low")
    
    # Visit details
    chief_complaint = models.TextField(help_text="Patient's main complaint")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='WAITING')
    
    # Referral information
    is_referral = models.BooleanField(default=False)
    referring_facility = models.CharField(max_length=200, blank=True)
    referral_notes = models.TextField(blank=True)
    
    # Exit information
    exit_time = models.DateTimeField(null=True, blank=True)
    exit_notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['priority_level', 'arrival_time']
        indexes = [
            models.Index(fields=['visit_number']),
            models.Index(fields=['patient', 'visit_date']),
            models.Index(fields=['status', 'visit_date']),
            models.Index(fields=['queue_number', 'visit_date']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.visit_number:
            today = timezone.now().date()
            count = PatientVisit.objects.filter(visit_date=today).count() + 1
            self.visit_number = f"VIS{today.strftime('%Y%m%d')}{count:04d}"
        
        if not self.queue_number:
            last_queue = PatientVisit.objects.filter(visit_date=self.visit_date).aggregate(
                models.Max('queue_number'))['queue_number__max']
            self.queue_number = (last_queue or 0) + 1
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.visit_number} - {self.patient.full_name} ({self.visit_type})"
    
    @property
    def wait_time_minutes(self):
        """Calculate waiting time in minutes"""
        if self.exit_time:
            delta = self.exit_time - self.arrival_time
        else:
            delta = timezone.now() - self.arrival_time
        return int(delta.total_seconds() / 60)


# =============================================================================
# TRIAGE & VITALS
# =============================================================================

class TriageAssessment(models.Model):
    """Triage and vital signs assessment"""
    EMERGENCY_LEVEL_CHOICES = [
        ('CRITICAL', 'Critical - Immediate'),
        ('EMERGENCY', 'Emergency - <15 minutes'),
        ('URGENT', 'Urgent - <60 minutes'),
        ('NORMAL', 'Normal - <4 hours'),
    ]
    
    visit = models.OneToOneField(PatientVisit, on_delete=models.CASCADE, related_name='triage')
    nurse = models.ForeignKey(User, on_delete=models.PROTECT, related_name='triage_assessments',
                              limit_choices_to={'role__name': 'NURSE'})
    
    # Vital Signs
    temperature = models.DecimalField(max_digits=4, decimal_places=1, help_text="°C",
                                      validators=[MinValueValidator(35.0), MaxValueValidator(45.0)])
    pulse = models.PositiveIntegerField(help_text="BPM (Beats Per Minute)",
                                        validators=[MinValueValidator(40), MaxValueValidator(200)])
    systolic_bp = models.PositiveIntegerField(help_text="mmHg",
                                               validators=[MinValueValidator(70), MaxValueValidator(250)])
    diastolic_bp = models.PositiveIntegerField(help_text="mmHg",
                                                validators=[MinValueValidator(40), MaxValueValidator(150)])
    respiratory_rate = models.PositiveIntegerField(help_text="Breaths per minute",
                                                    validators=[MinValueValidator(10), MaxValueValidator(60)])
    oxygen_saturation = models.PositiveIntegerField(help_text="SpO2 %",
                                                     validators=[MinValueValidator(70), MaxValueValidator(100)])
    
    weight = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, help_text="kg")
    height = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True, help_text="cm")
    
    # Assessment
    chief_complaint = models.TextField(help_text="Presenting complaints")
    pain_scale = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(10)],
                                     help_text="0=No pain, 10=Worst pain", null=True, blank=True)
    emergency_level = models.CharField(max_length=20, choices=EMERGENCY_LEVEL_CHOICES)
    
    triage_notes = models.TextField(help_text="Nursing assessment notes")
    
    assessment_time = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-assessment_time']
        indexes = [
            models.Index(fields=['visit', 'assessment_time']),
        ]
    
    def __str__(self):
        return f"Triage - {self.visit.patient.full_name} - {self.emergency_level}"
    
    @property
    def bmi(self):
        """Calculate BMI if height and weight are available"""
        if self.height and self.weight:
            height_m = float(self.height) / 100
            return round(float(self.weight) / (height_m ** 2), 2)
        return None


# =============================================================================
# CLINICAL WORKFLOW
# =============================================================================

class Consultation(models.Model):
    """Doctor/Clinical Officer consultation"""
    visit = models.ForeignKey(PatientVisit, on_delete=models.CASCADE, related_name='consultations')
    doctor = models.ForeignKey(User, on_delete=models.PROTECT, related_name='consultations',
                               limit_choices_to={'role__name__in': ['DOCTOR', 'CLINICAL_OFFICER']})
    
    consultation_start = models.DateTimeField(default=timezone.now)
    consultation_end = models.DateTimeField(null=True, blank=True)
    
    # Clinical Assessment
    chief_complaint = models.TextField()
    history_of_illness = models.TextField(help_text="History of presenting illness")
    past_medical_history = models.TextField(blank=True)
    physical_examination = models.TextField(help_text="Physical examination findings")
    
    # Diagnosis (ICD-10 codes)
    provisional_diagnosis = models.TextField(blank=True)
    final_diagnosis = models.TextField(help_text="ICD-10 coded diagnosis")
    differential_diagnosis = models.TextField(blank=True)
    
    # Treatment Plan
    treatment_plan = models.TextField(help_text="Management and treatment plan")
    follow_up_instructions = models.TextField(blank=True)
    follow_up_date = models.DateField(null=True, blank=True)
    
    # Outcome
    admission_required = models.BooleanField(default=False)
    referral_required = models.BooleanField(default=False)
    referral_facility = models.CharField(max_length=200, blank=True)
    
    consultation_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-consultation_start']
        indexes = [
            models.Index(fields=['visit', 'consultation_start']),
            models.Index(fields=['doctor', 'consultation_start']),
        ]
    
    def __str__(self):
        return f"Consultation - {self.visit.patient.full_name} by Dr. {self.doctor.last_name}"
    
    def save(self, *args, **kwargs):
        # Auto-set consultation fee if not set
        if not self.consultation_fee:
            settings = HospitalSettings.load()
            self.consultation_fee = settings.default_consultation_fee
            
            # Add emergency surcharge
            if self.visit.visit_type == 'EMERGENCY':
                self.consultation_fee += settings.emergency_surcharge
        
        super().save(*args, **kwargs)
        
        # Create/update invoice
        self._update_invoice()
    
    def _update_invoice(self):
        """Create or update invoice with consultation fee"""
        invoice, created = Invoice.objects.get_or_create(
            visit=self.visit,
            defaults={'patient': self.visit.patient}
        )
        
        # Add consultation charge
        InvoiceItem.objects.get_or_create(
            invoice=invoice,
            item_type='CONSULTATION',
            description=f'Consultation - Dr. {self.doctor.last_name}',
            defaults={'quantity': 1, 'unit_price': self.consultation_fee}
        )


class ClinicalNote(models.Model):
    """Detailed clinical notes and observations"""
    NOTE_TYPE_CHOICES = [
        ('CONSULTATION', 'Consultation Note'),
        ('PROGRESS', 'Progress Note'),
        ('PROCEDURE', 'Procedure Note'),
        ('DISCHARGE', 'Discharge Summary'),
    ]
    
    visit = models.ForeignKey(PatientVisit, on_delete=models.CASCADE, related_name='clinical_notes')
    note_type = models.CharField(max_length=20, choices=NOTE_TYPE_CHOICES)
    clinician = models.ForeignKey(User, on_delete=models.PROTECT, related_name='clinical_notes')
    
    subject = models.CharField(max_length=200)
    content = models.TextField()
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['visit', 'created_at']),
        ]
    
    def __str__(self):
        return f"{self.note_type} - {self.visit.patient.full_name} - {self.created_at.date()}"


# =============================================================================
# LABORATORY MANAGEMENT
# =============================================================================

class LabTest(models.Model):
    """Laboratory test catalog"""
    CATEGORY_CHOICES = [
        ('HEMATOLOGY', 'Hematology'),
        ('BIOCHEMISTRY', 'Biochemistry'),
        ('MICROBIOLOGY', 'Microbiology'),
        ('SEROLOGY', 'Serology'),
        ('HISTOPATHOLOGY', 'Histopathology'),
        ('PARASITOLOGY', 'Parasitology'),
        ('IMMUNOLOGY', 'Immunology'),
    ]
    
    name = models.CharField(max_length=200, unique=True)
    test_code = models.CharField(max_length=20, unique=True)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField(blank=True)
    
    price = models.DecimalField(max_digits=10, decimal_places=2)
    turnaround_time_hours = models.PositiveIntegerField(help_text="Expected TAT in hours")
    
    sample_type = models.CharField(max_length=100, help_text="Blood, Urine, Stool, etc.")
    sample_volume = models.CharField(max_length=50, blank=True)
    special_instructions = models.TextField(blank=True)
    
    requires_fasting = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['category', 'name']
        indexes = [
            models.Index(fields=['test_code']),
            models.Index(fields=['category', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.test_code} - {self.name}"


class LabOrder(models.Model):
    """Laboratory test orders"""
    ORDER_STATUS = [
        ('ORDERED', 'Ordered'),
        ('RECEIVED', 'Sample Received'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    order_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.ForeignKey(PatientVisit, on_delete=models.CASCADE, related_name='lab_orders')
    test = models.ForeignKey(LabTest, on_delete=models.PROTECT, related_name='orders')
    
    ordered_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='lab_orders_requested')
    ordered_at = models.DateTimeField(auto_now_add=True)
    
    clinical_notes = models.TextField(help_text="Clinical indication for test")
    sample_collected_at = models.DateTimeField(null=True, blank=True)
    sample_collected_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, 
                                            related_name='samples_collected')
    
    status = models.CharField(max_length=20, choices=ORDER_STATUS, default='ORDERED')
    priority = models.BooleanField(default=False, help_text="Urgent/STAT")
    
    class Meta:
        ordering = ['-ordered_at']
        indexes = [
            models.Index(fields=['visit', 'status']),
            models.Index(fields=['order_number']),
            models.Index(fields=['status', 'ordered_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.order_number:
            today = timezone.now().date()
            count = LabOrder.objects.filter(ordered_at__date=today).count() + 1
            self.order_number = f"LAB{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
        
        # Add to invoice
        self._update_invoice()
    
    def _update_invoice(self):
        invoice, created = Invoice.objects.get_or_create(
            visit=self.visit,
            defaults={'patient': self.visit.patient}
        )
        InvoiceItem.objects.get_or_create(
            invoice=invoice,
            item_type='LABORATORY',
            description=f'Lab Test - {self.test.name}',
            defaults={'quantity': 1, 'unit_price': self.test.price}
        )
    
    def __str__(self):
        return f"{self.order_number} - {self.test.name}"


class LabResult(models.Model):
    """Laboratory test results"""
    lab_order = models.OneToOneField(LabOrder, on_delete=models.CASCADE, related_name='result')
    technician = models.ForeignKey(User, on_delete=models.PROTECT, related_name='lab_results',
                                   limit_choices_to={'role__name': 'LAB_TECHNICIAN'})
    
    result_value = models.TextField(help_text="Test results - can be numeric or text")
    reference_range = models.CharField(max_length=200, blank=True)
    units = models.CharField(max_length=50, blank=True)
    
    interpretation = models.TextField(blank=True, help_text="Clinical interpretation")
    is_abnormal = models.BooleanField(default=False)
    
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='lab_results_verified')
    verified_at = models.DateTimeField(null=True, blank=True)
    
    result_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-result_date']
        indexes = [
            models.Index(fields=['lab_order', 'result_date']),
        ]
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        
        # Update order status
        self.lab_order.status = 'COMPLETED'
        self.lab_order.save()
        
        # Send notification to ordering doctor
        self._notify_doctor()
    
    def _notify_doctor(self):
        Notification.objects.create(
            recipient=self.lab_order.ordered_by,
            notification_type='LAB_RESULT',
            title='Lab Results Ready',
            message=f'Results ready for {self.lab_order.visit.patient.full_name} - {self.lab_order.test.name}',
            link_url=f'/lab/results/{self.id}/'
        )
    
    def __str__(self):
        return f"Result - {self.lab_order.test.name} for {self.lab_order.visit.patient.full_name}"


# =============================================================================
# RADIOLOGY MANAGEMENT
# =============================================================================

class RadiologyTest(models.Model):
    """Radiology tests catalog"""
    MODALITY_CHOICES = [
        ('XRAY', 'X-Ray'),
        ('ULTRASOUND', 'Ultrasound'),
        ('CT', 'CT Scan'),
        ('MRI', 'MRI'),
        ('MAMMOGRAPHY', 'Mammography'),
        ('FLUOROSCOPY', 'Fluoroscopy'),
    ]
    
    name = models.CharField(max_length=200, unique=True)
    test_code = models.CharField(max_length=20, unique=True)
    modality = models.CharField(max_length=20, choices=MODALITY_CHOICES)
    description = models.TextField(blank=True)
    
    price = models.DecimalField(max_digits=10, decimal_places=2)
    estimated_duration_minutes = models.PositiveIntegerField()
    
    requires_contrast = models.BooleanField(default=False)
    preparation_instructions = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['modality', 'name']
        indexes = [
            models.Index(fields=['test_code']),
            models.Index(fields=['modality', 'is_active']),
        ]
    
    def __str__(self):
        return f"{self.test_code} - {self.name}"


class RadiologyOrder(models.Model):
    """Radiology test orders"""
    ORDER_STATUS = [
        ('ORDERED', 'Ordered'),
        ('SCHEDULED', 'Scheduled'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('REPORTED', 'Report Ready'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    order_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.ForeignKey(PatientVisit, on_delete=models.CASCADE, related_name='radiology_orders')
    test = models.ForeignKey(RadiologyTest, on_delete=models.PROTECT, related_name='orders')
    
    ordered_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='radiology_orders_requested')
    ordered_at = models.DateTimeField(auto_now_add=True)
    
    clinical_notes = models.TextField(help_text="Clinical indication for imaging")
    scheduled_datetime = models.DateTimeField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=ORDER_STATUS, default='ORDERED')
    priority = models.BooleanField(default=False, help_text="Urgent")
    
    class Meta:
        ordering = ['-ordered_at']
        indexes = [
            models.Index(fields=['visit', 'status']),
            models.Index(fields=['order_number']),
            models.Index(fields=['status', 'ordered_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.order_number:
            today = timezone.now().date()
            count = RadiologyOrder.objects.filter(ordered_at__date=today).count() + 1
            self.order_number = f"RAD{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
        
        # Add to invoice
        self._update_invoice()
    
    def _update_invoice(self):
        invoice, created = Invoice.objects.get_or_create(
            visit=self.visit,
            defaults={'patient': self.visit.patient}
        )
        InvoiceItem.objects.get_or_create(
            invoice=invoice,
            item_type='RADIOLOGY',
            description=f'Radiology - {self.test.name}',
            defaults={'quantity': 1, 'unit_price': self.test.price}
        )
    
    def __str__(self):
        return f"{self.order_number} - {self.test.name}"


class RadiologyResult(models.Model):
    """Radiology results and reports"""
    radiology_order = models.OneToOneField(RadiologyOrder, on_delete=models.CASCADE, related_name='result')
    radiologist = models.ForeignKey(User, on_delete=models.PROTECT, related_name='radiology_results',
                                    limit_choices_to={'role__name': 'RADIOLOGIST'})
    
    findings = models.TextField(help_text="Radiological findings")
    impression = models.TextField(help_text="Radiologist impression/conclusion")
    recommendations = models.TextField(blank=True)
    
    image_file = models.FileField(upload_to='radiology_images/', null=True, blank=True)
    report_file = models.FileField(upload_to='radiology_reports/', null=True, blank=True)
    
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='radiology_results_verified')
    verified_at = models.DateTimeField(null=True, blank=True)
    
    result_date = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-result_date']
        indexes = [
            models.Index(fields=['radiology_order', 'result_date']),
        ]
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        
        # Update order status
        self.radiology_order.status = 'REPORTED'
        self.radiology_order.save()
        
        # Send notification to ordering doctor
        self._notify_doctor()
    
    def _notify_doctor(self):
        Notification.objects.create(
            recipient=self.radiology_order.ordered_by,
            notification_type='RADIOLOGY_RESULT',
            title='Radiology Results Ready',
            message=f'Results ready for {self.radiology_order.visit.patient.full_name} - {self.radiology_order.test.name}',
            link_url=f'/radiology/results/{self.id}/'
        )
    
    def __str__(self):
        return f"Result - {self.radiology_order.test.name} for {self.radiology_order.visit.patient.full_name}"


# =============================================================================
# PHARMACY & INVENTORY MANAGEMENT
# =============================================================================

class DrugCategory(models.Model):
    """Drug categories for organization"""
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    
    class Meta:
        ordering = ['name']
        verbose_name_plural = 'Drug Categories'
    
    def __str__(self):
        return self.name


class Drug(models.Model):
    """Drug/Medication catalog"""
    DRUG_FORM_CHOICES = [
        ('TABLET', 'Tablet'),
        ('CAPSULE', 'Capsule'),
        ('SYRUP', 'Syrup'),
        ('INJECTION', 'Injection'),
        ('OINTMENT', 'Ointment'),
        ('CREAM', 'Cream'),
        ('DROPS', 'Drops'),
        ('INHALER', 'Inhaler'),
        ('SUPPOSITORY', 'Suppository'),
    ]
    
    name = models.CharField(max_length=200)
    generic_name = models.CharField(max_length=200)
    brand_name = models.CharField(max_length=200, blank=True)
    drug_code = models.CharField(max_length=20, unique=True)
    
    category = models.ForeignKey(DrugCategory, on_delete=models.PROTECT, related_name='drugs')
    form = models.CharField(max_length=20, choices=DRUG_FORM_CHOICES)
    strength = models.CharField(max_length=50, help_text="e.g., 500mg, 5mg/ml")
    
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    reorder_level = models.PositiveIntegerField(help_text="Minimum stock level before reorder")
    
    description = models.TextField(blank=True)
    contraindications = models.TextField(blank=True)
    side_effects = models.TextField(blank=True)
    
    requires_prescription = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        indexes = [
            models.Index(fields=['drug_code']),
            models.Index(fields=['category', 'is_active']),
            models.Index(fields=['name']),
        ]
    
    def __str__(self):
        return f"{self.name} ({self.strength})"
    
    @property
    def current_stock(self):
        """Get current stock quantity"""
        stock = DrugStock.objects.filter(drug=self).aggregate(
            total=Sum('quantity'))['total']
        return stock or 0
    
    @property
    def needs_reorder(self):
        """Check if stock is below reorder level"""
        return self.current_stock <= self.reorder_level


class DrugStock(models.Model):
    """Drug inventory management"""
    drug = models.ForeignKey(Drug, on_delete=models.CASCADE, related_name='stock_records')
    batch_number = models.CharField(max_length=50)
    
    quantity = models.PositiveIntegerField()
    unit_cost = models.DecimalField(max_digits=10, decimal_places=2)
    
    manufacture_date = models.DateField()
    expiry_date = models.DateField()
    
    supplier_name = models.CharField(max_length=200)
    received_date = models.DateField(default=timezone.now)
    received_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='stock_received')
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['expiry_date']
        indexes = [
            models.Index(fields=['drug', 'expiry_date']),
            models.Index(fields=['batch_number']),
        ]
    
    def __str__(self):
        return f"{self.drug.name} - Batch: {self.batch_number} - Qty: {self.quantity}"
    
    @property
    def is_expired(self):
        return self.expiry_date < timezone.now().date()
    
    @property
    def days_to_expiry(self):
        delta = self.expiry_date - timezone.now().date()
        return delta.days


class Prescription(models.Model):
    """Prescription orders"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('DISPENSED', 'Dispensed'),
        ('PARTIALLY_DISPENSED', 'Partially Dispensed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    prescription_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.ForeignKey(PatientVisit, on_delete=models.CASCADE, related_name='prescriptions')
    prescribed_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='prescriptions_written',
                                      limit_choices_to={'role__can_prescribe': True})
    
    prescribed_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    
    special_instructions = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-prescribed_at']
        indexes = [
            models.Index(fields=['visit', 'status']),
            models.Index(fields=['prescription_number']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.prescription_number:
            today = timezone.now().date()
            count = Prescription.objects.filter(prescribed_at__date=today).count() + 1
            self.prescription_number = f"RX{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.prescription_number} - {self.visit.patient.full_name}"


class PrescriptionItem(models.Model):
    """Individual drug items in a prescription"""
    prescription = models.ForeignKey(Prescription, on_delete=models.CASCADE, related_name='items')
    drug = models.ForeignKey(Drug, on_delete=models.PROTECT, related_name='prescription_items')
    
    quantity = models.PositiveIntegerField()
    dosage = models.CharField(max_length=100, help_text="e.g., 1 tablet twice daily")
    duration = models.CharField(max_length=50, help_text="e.g., 7 days, 2 weeks")
    instructions = models.TextField(help_text="Special instructions for patient")
    
    dispensed_quantity = models.PositiveIntegerField(default=0)
    dispensed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                     related_name='medications_dispensed',
                                     limit_choices_to={'role__name': 'PHARMACIST'})
    dispensed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['id']
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        
        # Add to invoice when dispensed
        if self.dispensed_quantity > 0:
            self._update_invoice()
    
    def _update_invoice(self):
        invoice, created = Invoice.objects.get_or_create(
            visit=self.prescription.visit,
            defaults={'patient': self.prescription.visit.patient}
        )
        
        # Check for allergy conflicts
        patient = self.prescription.visit.patient
        if patient.allergies and self.drug.name.lower() in patient.allergies.lower():
            # Create alert
            Notification.objects.create(
                recipient=self.dispensed_by,
                notification_type='ALLERGY_ALERT',
                title='ALLERGY ALERT',
                message=f'Patient {patient.full_name} has documented allergy to {self.drug.name}',
                link_url=f'/patients/{patient.id}/'
            )
        
        # Add to invoice
        InvoiceItem.objects.create(
            invoice=invoice,
            item_type='PHARMACY',
            description=f'{self.drug.name} ({self.drug.strength})',
            quantity=self.dispensed_quantity,
            unit_price=self.drug.unit_price
        )
        
        # Reduce inventory
        self._reduce_inventory()
    
    def _reduce_inventory(self):
        """Reduce drug inventory using FIFO"""
        remaining = self.dispensed_quantity
        stock_records = DrugStock.objects.filter(
            drug=self.drug,
            quantity__gt=0,
            expiry_date__gt=timezone.now().date()
        ).order_by('expiry_date')
        
        for stock in stock_records:
            if remaining <= 0:
                break
            
            if stock.quantity >= remaining:
                stock.quantity -= remaining
                stock.save()
                remaining = 0
            else:
                remaining -= stock.quantity
                stock.quantity = 0
                stock.save()
    
    def __str__(self):
        return f"{self.drug.name} - {self.quantity} - {self.dosage}"


# =============================================================================
# INPATIENT MANAGEMENT
# =============================================================================

class Ward(models.Model):
    """Hospital wards"""
    WARD_TYPE_CHOICES = [
        ('MALE', 'Male Ward'),
        ('FEMALE', 'Female Ward'),
        ('PAEDIATRICS', 'Paediatrics'),
        ('MATERNITY', 'Maternity'),
        ('ICU', 'Intensive Care Unit'),
        ('HDU', 'High Dependency Unit'),
        ('ISOLATION', 'Isolation'),
    ]
    
    name = models.CharField(max_length=100, unique=True)
    ward_type = models.CharField(max_length=20, choices=WARD_TYPE_CHOICES)
    total_beds = models.PositiveIntegerField()
    location = models.CharField(max_length=200)
    floor = models.CharField(max_length=20, blank=True)
    
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.get_ward_type_display()})"
    
    @property
    def occupied_beds(self):
        return Bed.objects.filter(ward=self, is_occupied=True).count()
    
    @property
    def available_beds(self):
        return Bed.objects.filter(ward=self, is_occupied=False, is_available=True).count()
    
    @property
    def occupancy_rate(self):
        if self.total_beds == 0:
            return 0
        return round((self.occupied_beds / self.total_beds) * 100, 2)


class Bed(models.Model):
    """Individual beds in wards"""
    BED_STATUS_CHOICES = [
        ('AVAILABLE', 'Available'),
        ('OCCUPIED', 'Occupied'),
        ('MAINTENANCE', 'Under Maintenance'),
        ('RESERVED', 'Reserved'),
    ]
    
    ward = models.ForeignKey(Ward, on_delete=models.CASCADE, related_name='beds')
    bed_number = models.CharField(max_length=20)
    
    is_occupied = models.BooleanField(default=False)
    is_available = models.BooleanField(default=True)
    status = models.CharField(max_length=20, choices=BED_STATUS_CHOICES, default='AVAILABLE')
    
    daily_rate = models.DecimalField(max_digits=10, decimal_places=2, help_text="Daily bed charge")
    
    notes = models.TextField(blank=True)
    
    class Meta:
        ordering = ['ward', 'bed_number']
        unique_together = ['ward', 'bed_number']
        indexes = [
            models.Index(fields=['ward', 'is_occupied']),
        ]
    
    def __str__(self):
        return f"{self.ward.name} - Bed {self.bed_number}"


class Admission(models.Model):
    """Patient admissions"""
    ADMISSION_TYPE_CHOICES = [
        ('EMERGENCY', 'Emergency'),
        ('ELECTIVE', 'Elective'),
        ('MATERNITY', 'Maternity'),
        ('TRANSFER', 'Transfer'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('DISCHARGED', 'Discharged'),
        ('TRANSFERRED', 'Transferred'),
        ('ABSCONDED', 'Absconded'),
        ('DECEASED', 'Deceased'),
    ]
    
    admission_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.OneToOneField(PatientVisit, on_delete=models.CASCADE, related_name='admission')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='admissions')
    
    admission_type = models.CharField(max_length=20, choices=ADMISSION_TYPE_CHOICES)
    admission_datetime = models.DateTimeField(default=timezone.now)
    
    bed = models.ForeignKey(Bed, on_delete=models.PROTECT, related_name='admissions')
    admitting_doctor = models.ForeignKey(User, on_delete=models.PROTECT, related_name='admissions_made',
                                        limit_choices_to={'role__can_admit_patients': True})
    
    admission_diagnosis = models.TextField()
    admission_notes = models.TextField(blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    
    # Discharge Information
    discharge_datetime = models.DateTimeField(null=True, blank=True)
    discharge_diagnosis = models.TextField(blank=True)
    discharge_summary = models.TextField(blank=True)
    discharge_instructions = models.TextField(blank=True)
    discharged_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                      related_name='discharges_made')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-admission_datetime']
        indexes = [
            models.Index(fields=['admission_number']),
            models.Index(fields=['patient', 'status']),
            models.Index(fields=['status', 'admission_datetime']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.admission_number:
            today = timezone.now().date()
            count = Admission.objects.filter(admission_datetime__date=today).count() + 1
            self.admission_number = f"ADM{today.strftime('%Y%m%d')}{count:04d}"
        
        # Mark bed as occupied
        if self.status == 'ACTIVE':
            self.bed.is_occupied = True
            self.bed.status = 'OCCUPIED'
            self.bed.save()
        elif self.status in ['DISCHARGED', 'TRANSFERRED', 'ABSCONDED', 'DECEASED']:
            self.bed.is_occupied = False
            self.bed.status = 'AVAILABLE'
            self.bed.save()
        
        super().save(*args, **kwargs)
        
        # Update invoice with bed charges
        if self.status == 'DISCHARGED':
            self._calculate_bed_charges()
    
    def _calculate_bed_charges(self):
        """Calculate total bed charges for admission period"""
        if self.discharge_datetime:
            duration = self.discharge_datetime - self.admission_datetime
            days = max(1, duration.days)  # Minimum 1 day charge
            
            invoice, created = Invoice.objects.get_or_create(
                visit=self.visit,
                defaults={'patient': self.patient}
            )
            InvoiceItem.objects.create(
                invoice=invoice,
                item_type='BED',
                description=f'Bed Charges - {self.bed.ward.name} Bed {self.bed.bed_number} ({days} days)',
                quantity=days,
                unit_price=self.bed.daily_rate
            )
    
    def __str__(self):
        return f"{self.admission_number} - {self.patient.full_name}"
    
    @property
    def length_of_stay(self):
        """Calculate length of stay in days"""
        end_time = self.discharge_datetime or timezone.now()
        duration = end_time - self.admission_datetime
        return duration.days


class ProgressNote(models.Model):
    """Daily progress notes for inpatients"""
    admission = models.ForeignKey(Admission, on_delete=models.CASCADE, related_name='progress_notes')
    doctor = models.ForeignKey(User, on_delete=models.PROTECT, related_name='progress_notes')
    
    note_date = models.DateField(default=timezone.now)
    subjective = models.TextField(help_text="Patient's symptoms and complaints")
    objective = models.TextField(help_text="Clinical findings and vital signs")
    assessment = models.TextField(help_text="Clinical assessment and diagnosis")
    plan = models.TextField(help_text="Treatment plan for today")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-note_date']
        indexes = [
            models.Index(fields=['admission', 'note_date']),
        ]
    
    def __str__(self):
        return f"Progress Note - {self.admission.patient.full_name} - {self.note_date}"


class NursingNote(models.Model):
    """Nursing notes and observations for inpatients"""
    admission = models.ForeignKey(Admission, on_delete=models.CASCADE, related_name='nursing_notes')
    nurse = models.ForeignKey(User, on_delete=models.PROTECT, related_name='nursing_notes',
                              limit_choices_to={'role__name': 'NURSE'})
    
    note_datetime = models.DateTimeField(default=timezone.now)
    shift = models.CharField(max_length=20, choices=[
        ('MORNING', 'Morning'), ('AFTERNOON', 'Afternoon'), ('NIGHT', 'Night')
    ])
    
    vital_signs = models.TextField(help_text="Temperature, BP, Pulse, RR, SpO2")
    intake_output = models.TextField(blank=True, help_text="Fluid intake and output")
    observations = models.TextField(help_text="General observations")
    interventions = models.TextField(help_text="Nursing interventions performed")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-note_datetime']
        indexes = [
            models.Index(fields=['admission', 'note_datetime']),
        ]
    
    def __str__(self):
        return f"Nursing Note - {self.admission.patient.full_name} - {self.note_datetime}"


class MedicationAdministrationRecord(models.Model):
    """MAR - Track medication administration for inpatients"""
    STATUS_CHOICES = [
        ('SCHEDULED', 'Scheduled'),
        ('ADMINISTERED', 'Administered'),
        ('MISSED', 'Missed'),
        ('REFUSED', 'Refused'),
        ('HELD', 'Held'),
    ]
    
    admission = models.ForeignKey(Admission, on_delete=models.CASCADE, related_name='medication_records')
    prescription_item = models.ForeignKey(PrescriptionItem, on_delete=models.CASCADE, related_name='administration_records')
    
    scheduled_datetime = models.DateTimeField()
    administered_datetime = models.DateTimeField(null=True, blank=True)
    administered_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                       related_name='medications_administered',
                                       limit_choices_to={'role__name': 'NURSE'})
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SCHEDULED')
    dose_given = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True, help_text="Reason for missed/refused/held")
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['scheduled_datetime']
        indexes = [
            models.Index(fields=['admission', 'scheduled_datetime']),
            models.Index(fields=['status', 'scheduled_datetime']),
        ]
    
    def __str__(self):
        return f"MAR - {self.prescription_item.drug.name} - {self.scheduled_datetime}"


# =============================================================================
# THEATRE/SURGERY MANAGEMENT
# =============================================================================

class TheatreRoom(models.Model):
    """Operating theatre rooms"""
    name = models.CharField(max_length=100, unique=True)
    room_number = models.CharField(max_length=20)
    location = models.CharField(max_length=200)
    
    is_available = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['room_number']
    
    def __str__(self):
        return f"{self.name} - Room {self.room_number}"


class Surgery(models.Model):
    """Surgical procedures"""
    SURGERY_STATUS_CHOICES = [
        ('SCHEDULED', 'Scheduled'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('POSTPONED', 'Postponed'),
    ]
    
    SURGERY_TYPE_CHOICES = [
        ('ELECTIVE', 'Elective'),
        ('EMERGENCY', 'Emergency'),
        ('URGENT', 'Urgent'),
    ]
    
    surgery_number = models.CharField(max_length=20, unique=True, editable=False)
    admission = models.ForeignKey(Admission, on_delete=models.CASCADE, related_name='surgeries')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='surgeries')
    
    procedure_name = models.CharField(max_length=300)
    surgery_type = models.CharField(max_length=20, choices=SURGERY_TYPE_CHOICES)
    
    scheduled_datetime = models.DateTimeField()
    theatre_room = models.ForeignKey(TheatreRoom, on_delete=models.PROTECT, related_name='surgeries')
    
    surgeon = models.ForeignKey(User, on_delete=models.PROTECT, related_name='surgeries_performed',
                                limit_choices_to={'role__name': 'DOCTOR'})
    assistant_surgeon = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                         related_name='assisted_surgeries',
                                         limit_choices_to={'role__name': 'DOCTOR'})
    anaesthetist = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='anaesthesia_provided',
                                    limit_choices_to={'role__name': 'DOCTOR'})
    
    pre_op_diagnosis = models.TextField()
    post_op_diagnosis = models.TextField(blank=True)
    
    procedure_notes = models.TextField(blank=True)
    anaesthesia_notes = models.TextField(blank=True)
    
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=SURGERY_STATUS_CHOICES, default='SCHEDULED')
    
    surgery_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    anaesthesia_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    theatre_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-scheduled_datetime']
        verbose_name_plural = 'Surgeries'
            

        indexes = [
            models.Index(fields=['surgery_number']),
            models.Index(fields=['patient', 'scheduled_datetime']),
            models.Index(fields=['status', 'scheduled_datetime']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.surgery_number:
            today = timezone.now().date()
            count = Surgery.objects.filter(created_at__date=today).count() + 1
            self.surgery_number = f"SUR{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
        
        # Add surgery fees to invoice when completed
        if self.status == 'COMPLETED':
            self._update_invoice()
    
    def _update_invoice(self):
        invoice, created = Invoice.objects.get_or_create(
            visit=self.admission.visit,
            defaults={'patient': self.patient}
        )
        
        # Surgery fee
        InvoiceItem.objects.create(
            invoice=invoice,
            item_type='PROCEDURE',
            description=f'Surgery - {self.procedure_name}',
            quantity=1,
            unit_price=self.surgery_fee
        )
        
        # Anaesthesia fee
        if self.anaesthesia_fee > 0:
            InvoiceItem.objects.create(
                invoice=invoice,
                item_type='PROCEDURE',
                description='Anaesthesia Fee',
                quantity=1,
                unit_price=self.anaesthesia_fee
            )
        
        # Theatre fee
        if self.theatre_fee > 0:
            InvoiceItem.objects.create(
                invoice=invoice,
                item_type='PROCEDURE',
                description='Theatre Charges',
                quantity=1,
                unit_price=self.theatre_fee
            )
    
    def __str__(self):
        return f"{self.surgery_number} - {self.procedure_name}"
    
    @property
    def duration_minutes(self):
        """Calculate surgery duration in minutes"""
        if self.start_time and self.end_time:
            duration = self.end_time - self.start_time
            return int(duration.total_seconds() / 60)
        return None


# =============================================================================
# BILLING & PAYMENTS (Including M-Pesa Integration)
# =============================================================================

class Invoice(models.Model):
    """Patient invoices"""
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('PENDING', 'Pending Payment'),
        ('PARTIALLY_PAID', 'Partially Paid'),
        ('PAID', 'Paid'),
        ('CANCELLED', 'Cancelled'),
        ('NHIF_SUBMITTED', 'NHIF Claim Submitted'),
        ('NHIF_APPROVED', 'NHIF Approved'),
        ('NHIF_REJECTED', 'NHIF Rejected'),
    ]
    
    invoice_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.OneToOneField(PatientVisit, on_delete=models.CASCADE, related_name='invoice')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='invoices')
    
    invoice_date = models.DateTimeField(auto_now_add=True)
    due_date = models.DateField(null=True, blank=True)
    
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    discount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    tax = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    
    # NHIF Information
    nhif_coverage_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    patient_copay = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-invoice_date']
        indexes = [
            models.Index(fields=['invoice_number']),
            models.Index(fields=['patient', 'status']),
            models.Index(fields=['status', 'invoice_date']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.invoice_number:
            today = timezone.now().date()
            count = Invoice.objects.filter(invoice_date__date=today).count() + 1
            self.invoice_number = f"INV{today.strftime('%Y%m%d')}{count:04d}"
        
        # Only calculate totals if the invoice has been saved before (has pk)
        if self.pk:
            self.calculate_totals()
        
        super().save(*args, **kwargs)
    
    def calculate_totals(self):
        """Recalculate invoice totals"""
        # Check if invoice has been saved and has items relationship
        if not self.pk:
            # Can't calculate totals for unsaved invoice
            self.subtotal = Decimal('0.00')
            self.total_amount = Decimal('0.00')
            self.balance = Decimal('0.00')
            return
        
        items_total = self.items.aggregate(
            total=Sum(F('quantity') * F('unit_price')))['total'] or Decimal('0.00')
        
        self.subtotal = items_total
        self.total_amount = self.subtotal - self.discount + self.tax
        self.balance = self.total_amount - self.amount_paid - self.nhif_coverage_amount
        
        # Update status based on payment
        if self.balance <= 0 and self.total_amount > 0:
            self.status = 'PAID'
        elif self.amount_paid > 0 and self.balance > 0:
            self.status = 'PARTIALLY_PAID'
        elif self.amount_paid == 0 and self.total_amount > 0:
            self.status = 'PENDING'
    
    def __str__(self):
        return f"{self.invoice_number} - {self.patient.full_name} - KES {self.total_amount}"


class InvoiceItem(models.Model):
    """Line items in invoices"""
    ITEM_TYPE_CHOICES = [
        ('CONSULTATION', 'Consultation'),
        ('LABORATORY', 'Laboratory'),
        ('RADIOLOGY', 'Radiology'),
        ('PHARMACY', 'Pharmacy'),
        ('PROCEDURE', 'Procedure'),
        ('BED', 'Bed Charges'),
        ('CONSUMABLES', 'Consumables'),
        ('OTHER', 'Other'),
    ]
    
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='items')
    item_type = models.CharField(max_length=20, choices=ITEM_TYPE_CHOICES)
    
    description = models.CharField(max_length=300)
    quantity = models.DecimalField(max_digits=10, decimal_places=2, default=1)
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['id']
    
    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        # Recalculate invoice totals
        self.invoice.calculate_totals()
        self.invoice.save()
    
    @property
    def line_total(self):
        return self.quantity * self.unit_price
    
    def __str__(self):
        return f"{self.description} - KES {self.line_total}"


class Payment(models.Model):
    """Payment records"""
    PAYMENT_METHOD_CHOICES = [
        ('CASH', 'Cash'),
        ('MPESA', 'M-Pesa'),
        ('BANK_TRANSFER', 'Bank Transfer'),
        ('CARD', 'Card'),
        ('CHEQUE', 'Cheque'),
        ('INSURANCE', 'Insurance'),
        ('NHIF', 'NHIF'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('REVERSED', 'Reversed'),
    ]
    
    payment_number = models.CharField(max_length=20, unique=True, editable=False)
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='payments')
    
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHOD_CHOICES)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    payment_date = models.DateTimeField(default=timezone.now)
    received_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='payments_received',
                                   limit_choices_to={'role__name': 'CASHIER'})
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    
    # M-Pesa specific fields
    mpesa_receipt_number = models.CharField(max_length=50, blank=True, unique=True, null=True)
    mpesa_phone_number = models.CharField(max_length=15, blank=True)
    mpesa_transaction_id = models.CharField(max_length=50, blank=True)
    
    # Other payment details
    reference_number = models.CharField(max_length=100, blank=True, help_text="Cheque/Bank ref number")
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-payment_date']
        indexes = [
            models.Index(fields=['payment_number']),
            models.Index(fields=['invoice', 'status']),
            models.Index(fields=['mpesa_receipt_number']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.payment_number:
            today = timezone.now().date()
            count = Payment.objects.filter(payment_date__date=today).count() + 1
            self.payment_number = f"PAY{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
        
        # Update invoice when payment is completed
        if self.status == 'COMPLETED':
            self._update_invoice()
    
    def _update_invoice(self):
        """Update invoice with payment amount"""
        invoice = self.invoice
        completed_payments = invoice.payments.filter(status='COMPLETED').aggregate(
            total=Sum('amount'))['total'] or Decimal('0.00')
        
        invoice.amount_paid = completed_payments
        invoice.calculate_totals()
        invoice.save()
    
    def __str__(self):
        return f"{self.payment_number} - {self.payment_method} - KES {self.amount}"


class MpesaTransaction(models.Model):
    """M-Pesa STK Push transaction tracking"""
    TRANSACTION_STATUS = [
        ('INITIATED', 'Initiated'),
        ('PENDING', 'Pending'),
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
    ]
    
    checkout_request_id = models.CharField(max_length=100, unique=True)
    merchant_request_id = models.CharField(max_length=100)
    
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='mpesa_transactions')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='mpesa_transactions')
    
    phone_number = models.CharField(max_length=15)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    
    status = models.CharField(max_length=20, choices=TRANSACTION_STATUS, default='INITIATED')
    
    # M-Pesa response fields
    mpesa_receipt_number = models.CharField(max_length=50, blank=True)
    transaction_date = models.DateTimeField(null=True, blank=True)
    result_desc = models.TextField(blank=True)
    result_code = models.CharField(max_length=10, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['checkout_request_id']),
            models.Index(fields=['invoice', 'status']),
        ]
    
    def __str__(self):
        return f"M-Pesa {self.phone_number} - KES {self.amount} - {self.status}"


class Receipt(models.Model):
    """Payment receipts"""
    receipt_number = models.CharField(max_length=20, unique=True, editable=False)
    payment = models.OneToOneField(Payment, on_delete=models.CASCADE, related_name='receipt')
    
    issued_date = models.DateTimeField(auto_now_add=True)
    issued_by = models.ForeignKey(User, on_delete=models.PROTECT, related_name='receipts_issued')
    
    receipt_file = models.FileField(upload_to='receipts/', null=True, blank=True)
    
    class Meta:
        ordering = ['-issued_date']
    
    def save(self, *args, **kwargs):
        if not self.receipt_number:
            today = timezone.now().date()
            count = Receipt.objects.filter(issued_date__date=today).count() + 1
            self.receipt_number = f"RCP{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.receipt_number} - KES {self.payment.amount}"


# =============================================================================
# NHIF MANAGEMENT
# =============================================================================

class NHIFScheme(models.Model):
    """NHIF coverage schemes"""
    SCHEME_TYPE_CHOICES = [
        ('OUTPATIENT', 'Outpatient'),
        ('INPATIENT', 'Inpatient'),
        ('CIVIL_SERVANT', 'Civil Servant'),
        ('MATERNITY', 'Maternity'),
        ('SURGICAL', 'Surgical'),
    ]
    
    name = models.CharField(max_length=200, unique=True)
    scheme_type = models.CharField(max_length=20, choices=SCHEME_TYPE_CHOICES)
    code = models.CharField(max_length=20, unique=True)
    
    coverage_amount = models.DecimalField(max_digits=10, decimal_places=2)
    copay_percentage = models.DecimalField(max_digits=5, decimal_places=2, default=0,
                                          help_text="Patient copay percentage")
    
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        ordering = ['scheme_type', 'name']
        verbose_name = 'NHIF Scheme'
        verbose_name_plural = 'NHIF Schemes'
    
    def __str__(self):
        return f"{self.code} - {self.name}"


class NHIFClaim(models.Model):
    """NHIF claims"""
    CLAIM_TYPE_CHOICES = [
        ('OUTPATIENT', 'Outpatient'),
        ('INPATIENT', 'Inpatient'),
        ('CIVIL_SERVANT', 'Civil Servant'),
        ('MATERNITY', 'Maternity'),
    ]
    
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('SUBMITTED', 'Submitted'),
        ('UNDER_REVIEW', 'Under Review'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('PAID', 'Paid'),
    ]
    
    claim_number = models.CharField(max_length=20, unique=True, editable=False)
    visit = models.OneToOneField(PatientVisit, on_delete=models.CASCADE, related_name='nhif_claim')
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='nhif_claims')
    invoice = models.ForeignKey(Invoice, on_delete=models.CASCADE, related_name='nhif_claims')
    
    claim_type = models.CharField(max_length=20, choices=CLAIM_TYPE_CHOICES)
    scheme = models.ForeignKey(NHIFScheme, on_delete=models.PROTECT, related_name='claims')
    
    claimed_amount = models.DecimalField(max_digits=10, decimal_places=2)
    approved_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    
    # NHIF verification
    verified_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='nhif_claims_verified',
                                   limit_choices_to={'role__name': 'NHIF_OFFICER'})
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Submission details
    submitted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True,
                                    related_name='nhif_claims_submitted')
    submitted_at = models.DateTimeField(null=True, blank=True)
    
    # Response details
    rejection_reason = models.TextField(blank=True)
    nhif_response_date = models.DateField(null=True, blank=True)
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['claim_number']),
            models.Index(fields=['patient', 'status']),
            models.Index(fields=['status', 'created_at']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.claim_number:
            today = timezone.now().date()
            count = NHIFClaim.objects.filter(created_at__date=today).count() + 1
            self.claim_number = f"NHIF{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
        
        # Update invoice when claim is approved
        if self.status == 'APPROVED' and self.approved_amount > 0:
            self._update_invoice()
    
    def _update_invoice(self):
        """Update invoice with NHIF coverage"""
        self.invoice.nhif_coverage_amount = self.approved_amount
        self.invoice.patient_copay = self.invoice.total_amount - self.approved_amount
        self.invoice.status = 'NHIF_APPROVED'
        self.invoice.calculate_totals()
        self.invoice.save()
    
    def __str__(self):
        return f"{self.claim_number} - {self.patient.full_name} - KES {self.claimed_amount}"


# =============================================================================
# NOTIFICATIONS & MESSAGING
# =============================================================================

class Notification(models.Model):
    """System notifications for staff"""
    NOTIFICATION_TYPE_CHOICES = [
        ('LAB_RESULT', 'Lab Result Ready'),
        ('RADIOLOGY_RESULT', 'Radiology Result Ready'),
        ('APPOINTMENT', 'Appointment Reminder'),
        ('ALLERGY_ALERT', 'Allergy Alert'),
        ('CRITICAL_RESULT', 'Critical Result'),
        ('SYSTEM', 'System Notification'),
        ('GENERAL', 'General'),
    ]
    
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPE_CHOICES)
    
    title = models.CharField(max_length=200)
    message = models.TextField()
    link_url = models.CharField(max_length=300, blank=True)
    
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['recipient', 'is_read']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.title} - {self.recipient.username}"


class SMSLog(models.Model):
    """Log of SMS messages sent"""
    SMS_TYPE_CHOICES = [
        ('APPOINTMENT', 'Appointment Reminder'),
        ('LAB_RESULT', 'Lab Result Ready'),
        ('PRESCRIPTION', 'Prescription Ready'),
        ('PAYMENT', 'Payment Confirmation'),
        ('GENERAL', 'General'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('SENT', 'Sent'),
        ('FAILED', 'Failed'),
    ]
    
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='sms_logs')
    phone_number = models.CharField(max_length=15)
    
    sms_type = models.CharField(max_length=20, choices=SMS_TYPE_CHOICES)
    message = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    external_id = models.CharField(max_length=100, blank=True, help_text="SMS gateway message ID")
    
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['patient', 'created_at']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"SMS to {self.phone_number} - {self.sms_type}"


# =============================================================================
# HOSPITAL SETTINGS & CONFIGURATION
# =============================================================================

class HospitalSettings(models.Model):
    """System-wide hospital settings (Singleton)"""
    hospital_name = models.CharField(max_length=200, default="MediSphere Hospital")
    hospital_address = models.TextField()
    hospital_phone = models.CharField(max_length=15)
    hospital_email = models.EmailField()
    
    # Financial Settings
    default_consultation_fee = models.DecimalField(max_digits=10, decimal_places=2, default=500)
    emergency_surcharge = models.DecimalField(max_digits=10, decimal_places=2, default=1000)
    
    # M-Pesa Settings
    mpesa_shortcode = models.CharField(max_length=20, blank=True)
    mpesa_passkey = models.CharField(max_length=200, blank=True)
    mpesa_consumer_key = models.CharField(max_length=200, blank=True)
    mpesa_consumer_secret = models.CharField(max_length=200, blank=True)
    mpesa_environment = models.CharField(max_length=20, choices=[
        ('SANDBOX', 'Sandbox'), ('PRODUCTION', 'Production')
    ], default='SANDBOX')
    
    # SMS Settings
    sms_enabled = models.BooleanField(default=False)
    sms_api_key = models.CharField(max_length=200, blank=True)
    sms_sender_id = models.CharField(max_length=20, blank=True)
    
    # Tax Settings
    tax_rate = models.DecimalField(max_digits=5, decimal_places=2, default=0,
                                   help_text="Tax percentage (e.g., 16 for 16%)")
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Hospital Settings'
        verbose_name_plural = 'Hospital Settings'
    
    def save(self, *args, **kwargs):
        # Ensure only one instance exists (Singleton pattern)
        self.pk = 1
        super().save(*args, **kwargs)
    
    @classmethod
    def load(cls):
        """Get or create the single settings instance"""
        obj, created = cls.objects.get_or_create(pk=1)
        return obj
    
    def __str__(self):
        return self.hospital_name


# =============================================================================
# AUDIT LOG
# =============================================================================

class AuditLog(models.Model):
    """Audit trail for critical actions"""
    ACTION_TYPE_CHOICES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('VIEW', 'View'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPE_CHOICES)
    
    model_name = models.CharField(max_length=100)
    object_id = models.PositiveIntegerField(null=True, blank=True)
    object_repr = models.CharField(max_length=200, blank=True)
    
    changes = models.TextField(blank=True, help_text="JSON representation of changes")
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['model_name', 'object_id']),
            models.Index(fields=['action_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user} - {self.action_type} - {self.model_name} - {self.timestamp}"


# =============================================================================
# APPOINTMENT MANAGEMENT
# =============================================================================

class Appointment(models.Model):
    """Patient appointments"""
    STATUS_CHOICES = [
        ('SCHEDULED', 'Scheduled'),
        ('CONFIRMED', 'Confirmed'),
        ('ARRIVED', 'Arrived'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
        ('NO_SHOW', 'No Show'),
    ]
    
    appointment_number = models.CharField(max_length=20, unique=True, editable=False)
    patient = models.ForeignKey(Patient, on_delete=models.CASCADE, related_name='appointments')
    doctor = models.ForeignKey(User, on_delete=models.PROTECT, related_name='appointments',
                              limit_choices_to={'role__name__in': ['DOCTOR', 'CLINICAL_OFFICER']})
    
    appointment_datetime = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    
    appointment_type = models.CharField(max_length=50, help_text="Follow-up, New Visit, etc.")
    reason = models.TextField()
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SCHEDULED')
    
    # Reminder tracking
    sms_reminder_sent = models.BooleanField(default=False)
    sms_reminder_sent_at = models.DateTimeField(null=True, blank=True)
    
    notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['appointment_datetime']
        indexes = [
            models.Index(fields=['patient', 'appointment_datetime']),
            models.Index(fields=['doctor', 'appointment_datetime']),
            models.Index(fields=['status', 'appointment_datetime']),
        ]
    
    def save(self, *args, **kwargs):
        if not self.appointment_number:
            today = timezone.now().date()
            count = Appointment.objects.filter(created_at__date=today).count() + 1
            self.appointment_number = f"APT{today.strftime('%Y%m%d')}{count:04d}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.appointment_number} - {self.patient.full_name} - {self.appointment_datetime}"


