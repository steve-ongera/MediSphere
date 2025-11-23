"""
MediSphere Hospital Management System - Seed Data Command (FIXED)
Django management command to populate database with realistic Kenyan medical data
File: main_application/management/commands/seed_data.py

Usage: python manage.py seed_data [--clear] [--patients 500] [--visits 1000]
"""

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from faker import Faker
from decimal import Decimal
import random
from datetime import datetime, timedelta

from main_application.models import *


class Command(BaseCommand):
    help = 'Seeds the database with realistic Kenyan hospital data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before seeding',
        )
        parser.add_argument(
            '--patients',
            type=int,
            default=0,
            help='Number of patients to create (default: 0)',
        )
        parser.add_argument(
            '--visits',
            type=int,
            default=0,
            help='Number of visits to create (default: 0)',
        )
        parser.add_argument(
            '--base-only',
            action='store_true',
            help='Seed only base data (no patients/visits)',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting data seeding...'))
        
        # Initialize Faker with Kenyan locale where possible
        self.fake = Faker(['en_KE', 'en_US'])
        
        if options['clear']:
            self.clear_data()
        
        with transaction.atomic():
            # Seed base/reference data
            self.stdout.write(self.style.SUCCESS('\n=== Seeding Base Data ==='))
            self.seed_hospital_settings()
            self.seed_roles_and_departments()
            self.seed_users_and_staff()
            self.seed_drug_categories_and_drugs()
            self.seed_lab_tests()
            self.seed_radiology_tests()
            self.seed_wards_and_beds()
            self.seed_theatre_rooms()
            self.seed_nhif_schemes()
            
            # Seed patients and visits only if requested
            if not options['base_only']:
                patient_count = options['patients']
                visit_count = options['visits']
                
                if patient_count > 0 or visit_count > 0:
                    self.stdout.write(self.style.SUCCESS('\n=== Seeding Patient Data ==='))
                    
                    if patient_count > 0:
                        self.seed_patients(patient_count)
                    
                    if visit_count > 0:
                        self.seed_patient_visits(visit_count)
                    
                    if patient_count > 0:
                        self.seed_appointments()
            else:
                self.stdout.write(self.style.WARNING('\n⚠ Skipping patient and visit data (--base-only flag)'))
            
        self.stdout.write(self.style.SUCCESS('\n✓ Database seeding completed successfully!'))
        self.stdout.write(self.style.SUCCESS('  Default login: admin / admin123'))
        self.stdout.write(self.style.SUCCESS('  Staff logins: doctor1/password123, nurse1/password123, etc.'))

    def clear_data(self):
        """Clear existing data"""
        self.stdout.write(self.style.WARNING('Clearing existing data...'))
        
        # Clear in reverse dependency order
        models_to_clear = [
            MpesaTransaction, Receipt, Payment, NHIFClaim, InvoiceItem, Invoice,
            Surgery, MedicationAdministrationRecord, NursingNote,
            ProgressNote, Admission, Appointment, PrescriptionItem, Prescription,
            DrugStock, RadiologyResult, RadiologyOrder, LabResult, LabOrder,
            ClinicalNote, Consultation, TriageAssessment, PatientVisit, Patient,
            StaffProfile, TheatreRoom, Bed, Ward, NHIFScheme,
            Drug, DrugCategory, RadiologyTest, LabTest,
            Notification, SMSLog, AuditLog
        ]
        
        for model in models_to_clear:
            try:
                count = model.objects.all().delete()[0]
                if count > 0:
                    self.stdout.write(f'  Cleared {count} {model.__name__} records')
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'  Error clearing {model.__name__}: {str(e)}'))
        
        # Clear users (except superusers to be safe)
        User.objects.filter(is_superuser=False).delete()
        
        # Clear departments and roles
        Department.objects.all().delete()
        Role.objects.all().delete()

    # =========================================================================
    # KENYAN DATA SETS
    # =========================================================================
    
    KENYAN_COUNTIES = [
        'Nairobi', 'Mombasa', 'Kisumu', 'Nakuru', 'Eldoret', 'Thika', 'Malindi',
        'Kitale', 'Garissa', 'Nyeri', 'Machakos', 'Meru', 'Kakamega', 'Kisii',
        'Kericho', 'Bungoma', 'Migori', 'Kilifi', 'Homa Bay', 'Narok', 'Murang\'a',
        'Kiambu', 'Embu', 'Kajiado', 'Nyandarua', 'Laikipia', 'Baringo', 'Uasin Gishu'
    ]
    
    KENYAN_FIRST_NAMES_MALE = [
        'John', 'David', 'Peter', 'James', 'Joseph', 'Daniel', 'Samuel', 'Michael',
        'Brian', 'Kevin', 'Evans', 'George', 'Paul', 'Francis', 'Anthony', 'Collins',
        'Dennis', 'Kennedy', 'Victor', 'Moses', 'Emmanuel', 'Otieno', 'Kamau', 'Mwangi',
        'Kariuki', 'Njoroge', 'Omondi', 'Kiprotich', 'Kipchoge', 'Mutua'
    ]
    
    KENYAN_FIRST_NAMES_FEMALE = [
        'Mary', 'Jane', 'Grace', 'Lucy', 'Faith', 'Joyce', 'Catherine', 'Margaret',
        'Anne', 'Rose', 'Elizabeth', 'Sarah', 'Rachel', 'Rebecca', 'Ruth', 'Eunice',
        'Esther', 'Nancy', 'Linda', 'Agnes', 'Wanjiru', 'Akinyi', 'Wanjiku', 'Njeri',
        'Chebet', 'Cheptoo', 'Nyambura', 'Wangari', 'Makena', 'Kerubo'
    ]
    
    KENYAN_LAST_NAMES = [
        'Kamau', 'Mwangi', 'Njoroge', 'Wanjiru', 'Kariuki', 'Ochieng', 'Otieno', 'Omondi',
        'Akinyi', 'Kipchoge', 'Kiprotich', 'Chebet', 'Cheptoo', 'Mutua', 'Kioko', 'Mutiso',
        'Maina', 'Njenga', 'Kimani', 'Gitau', 'Njuguna', 'Waweru', 'Waithera', 'Gathoni',
        'Nyambura', 'Wangui', 'Karanja', 'Githiga', 'Muchoki', 'Mburu', 'Kibet', 'Rotich'
    ]
    
    KENYAN_PHONE_PREFIXES = ['0701', '0702', '0703', '0704', '0705', '0706', '0707', '0708', '0709',
                             '0710', '0711', '0712', '0713', '0714', '0715', '0720', '0721', '0722',
                             '0723', '0724', '0725', '0726', '0727', '0728', '0729', '0733', '0734',
                             '0735', '0736', '0737', '0738', '0739', '0740', '0741', '0742', '0743',
                             '0745', '0746', '0748', '0757', '0758', '0759', '0768', '0769', '0790',
                             '0791', '0792', '0793', '0794', '0795', '0796', '0797', '0798', '0799']
    
    COMMON_ALLERGIES = [
        'Penicillin', 'Sulfa drugs', 'Aspirin', 'Ibuprofen', 'Codeine',
        'Peanuts', 'Shellfish', 'Latex', 'None known'
    ]
    
    CHRONIC_CONDITIONS = [
        'Hypertension', 'Diabetes Mellitus Type 2', 'Asthma', 'HIV/AIDS on ARVs',
        'Epilepsy', 'Arthritis', 'Chronic Kidney Disease', 'Heart Disease', 'None'
    ]
    
    CHIEF_COMPLAINTS = [
        'Fever and chills', 'Headache', 'Abdominal pain', 'Chest pain',
        'Cough and difficulty breathing', 'Malaria symptoms', 'Diarrhea and vomiting',
        'Body weakness', 'Joint pains', 'Back pain', 'Stomach upset', 'Sore throat',
        'Skin rash', 'Dizziness', 'High blood sugar', 'High blood pressure',
        'Pregnancy complications', 'Child vaccination', 'Accident/Trauma', 'General checkup'
    ]
    
    DIAGNOSES = [
        'Malaria (P. falciparum)', 'Upper Respiratory Tract Infection',
        'Pneumonia', 'Gastroenteritis', 'Urinary Tract Infection',
        'Hypertension', 'Diabetes Mellitus', 'Typhoid Fever', 'Appendicitis',
        'Peptic Ulcer Disease', 'Acute Gastritis', 'Bronchitis', 'Asthma',
        'Tuberculosis', 'Meningitis', 'Cellulitis', 'Skin infection',
        'Food poisoning', 'Dehydration', 'Pregnancy - Normal', 'HIV/AIDS'
    ]

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def generate_kenyan_phone(self):
        """Generate a valid Kenyan phone number"""
        prefix = random.choice(self.KENYAN_PHONE_PREFIXES)
        suffix = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        return f"{prefix}{suffix}"

    def generate_kenyan_id(self):
        """Generate a Kenyan ID number (7-8 digits)"""
        return str(random.randint(10000000, 39999999))

    def random_date_between(self, start_days_ago, end_days_ago=0):
        """Generate random date between days ago"""
        today = timezone.now().date()
        start = today - timedelta(days=start_days_ago)
        end = today - timedelta(days=end_days_ago)
        return self.fake.date_between(start_date=start, end_date=end)

    def random_datetime_between(self, start_days_ago, end_days_ago=0):
        """Generate random datetime between days ago"""
        today = timezone.now()
        start = today - timedelta(days=start_days_ago)
        end = today - timedelta(days=end_days_ago)
        return self.fake.date_time_between(start_date=start, end_date=end, tzinfo=timezone.get_current_timezone())

    # =========================================================================
    # SEEDING METHODS
    # =========================================================================

    def seed_hospital_settings(self):
        """Create hospital settings"""
        self.stdout.write('Seeding hospital settings...')
        
        settings = HospitalSettings.load()
        settings.hospital_name = 'MediSphere Hospital - Nairobi'
        settings.hospital_address = '123 Uhuru Highway, Nairobi, Kenya'
        settings.hospital_phone = '0207123456'
        settings.hospital_email = 'info@medisphere.co.ke'
        settings.default_consultation_fee = Decimal('1000.00')
        settings.emergency_surcharge = Decimal('2000.00')
        settings.mpesa_shortcode = '174379'
        settings.mpesa_environment = 'SANDBOX'
        settings.sms_enabled = True
        settings.sms_sender_id = 'MEDISPHERE'
        settings.tax_rate = Decimal('0.00')
        settings.save()
        
        self.stdout.write(self.style.SUCCESS('  ✓ Hospital settings configured'))

    def seed_roles_and_departments(self):
        """Create roles and departments"""
        self.stdout.write('Seeding roles and departments...')
        
        # Create Roles
        roles_data = [
            ('MEDICAL_SUPERINTENDENT', True, True, True, False, True),
            ('DOCTOR', True, True, True, False, True),
            ('CLINICAL_OFFICER', True, True, False, False, False),
            ('NURSE', False, False, False, False, False),
            ('LAB_TECHNICIAN', False, False, False, False, False),
            ('RADIOLOGIST', False, False, False, False, True),
            ('PHARMACIST', False, False, True, True, False),
            ('RECEPTIONIST', False, False, False, False, False),
            ('CASHIER', False, False, True, False, True),
            ('NHIF_OFFICER', False, False, True, False, True),
            ('IT_ADMIN', False, False, True, True, True),
        ]
        
        for role_name, can_prescribe, can_admit, can_billing, can_inventory, can_reports in roles_data:
            Role.objects.get_or_create(
                name=role_name,
                defaults={
                    'can_prescribe': can_prescribe,
                    'can_admit_patients': can_admit,
                    'can_access_billing': can_billing,
                    'can_manage_inventory': can_inventory,
                    'can_view_reports': can_reports
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(roles_data)} roles'))
        
        # Create Departments
        dept_names = [
            'REGISTRATION', 'TRIAGE', 'OUTPATIENT', 'INPATIENT', 'LABORATORY',
            'RADIOLOGY', 'PHARMACY', 'BILLING', 'NHIF_DESK', 'THEATRE',
            'MATERNITY', 'PAEDIATRICS', 'ADMINISTRATION'
        ]
        
        for dept in dept_names:
            Department.objects.get_or_create(
                name=dept,
                defaults={
                    'location': f'{dept.replace("_", " ").title()} Wing',
                    'is_active': True
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(dept_names)} departments'))

    def seed_users_and_staff(self):
        """Create staff users"""
        self.stdout.write('Seeding users and staff...')
        
        # Create superuser if doesn't exist
        if not User.objects.filter(username='admin').exists():
            admin = User.objects.create_superuser(
                username='admin',
                email='admin@medisphere.co.ke',
                password='admin123',
                first_name='System',
                last_name='Administrator'
            )
            self.stdout.write(self.style.SUCCESS('  ✓ Created superuser (admin/admin123)'))
        
        # Create staff members
        roles = list(Role.objects.all())
        departments = list(Department.objects.all())
        
        staff_configs = [
            ('doctor', 'Doctor', 'DOCTOR', 'OUTPATIENT', 10),
            ('nurse', 'Nurse', 'NURSE', 'TRIAGE', 15),
            ('lab_tech', 'Lab Technician', 'LAB_TECHNICIAN', 'LABORATORY', 8),
            ('pharmacist', 'Pharmacist', 'PHARMACIST', 'PHARMACY', 6),
            ('receptionist', 'Receptionist', 'RECEPTIONIST', 'REGISTRATION', 5),
            ('cashier', 'Cashier', 'CASHIER', 'BILLING', 4),
            ('radiologist', 'Radiologist', 'RADIOLOGIST', 'RADIOLOGY', 3),
            ('nhif_officer', 'NHIF Officer', 'NHIF_OFFICER', 'NHIF_DESK', 2),
        ]
        
        user_count = 0
        for username_prefix, display_name, role_name, dept_name, count in staff_configs:
            role = Role.objects.get(name=role_name)
            department = Department.objects.get(name=dept_name)
            
            for i in range(1, count + 1):
                gender = random.choice(['MALE', 'FEMALE'])
                first_name = random.choice(
                    self.KENYAN_FIRST_NAMES_MALE if gender == 'MALE' else self.KENYAN_FIRST_NAMES_FEMALE
                )
                last_name = random.choice(self.KENYAN_LAST_NAMES)
                
                username = f'{username_prefix}{i}'
                
                if not User.objects.filter(username=username).exists():
                    user = User.objects.create_user(
                        username=username,
                        email=f'{username}@medisphere.co.ke',
                        password='password123',
                        first_name=first_name,
                        last_name=last_name,
                        role=role,
                        department=department,
                        phone_number=self.generate_kenyan_phone(),
                        is_staff=True,
                        is_active_staff=True
                    )
                    
                    # Create staff profile
                    StaffProfile.objects.create(
                        user=user,
                        staff_number=f'STF{timezone.now().year}{user.id:05d}',
                        id_number=self.generate_kenyan_id(),
                        date_of_birth=self.fake.date_of_birth(minimum_age=25, maximum_age=60),
                        gender=gender,
                        address=f'{random.randint(1, 999)} {self.fake.street_name()}, {random.choice(self.KENYAN_COUNTIES)}',
                        emergency_contact_name=f'{random.choice(self.KENYAN_FIRST_NAMES_MALE)} {random.choice(self.KENYAN_LAST_NAMES)}',
                        emergency_contact_phone=self.generate_kenyan_phone(),
                        specialization=self.fake.job() if role_name == 'DOCTOR' else '',
                        license_number=f'KEN{random.randint(10000, 99999)}' if role_name in ['DOCTOR', 'NURSE', 'PHARMACIST'] else '',
                        hire_date=self.random_date_between(1825, 30)
                    )
                    user_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {user_count} staff members'))

    def seed_drug_categories_and_drugs(self):
        """Create drug categories and medications"""
        self.stdout.write('Seeding drug categories and drugs...')
        
        # Get a pharmacist for stock records
        pharmacist = User.objects.filter(role__name='PHARMACIST').first()
        if not pharmacist:
            self.stdout.write(self.style.WARNING('  No pharmacist found, skipping drug stock creation'))
            return
        
        categories_data = {
            'Antimalarials': [
                ('Artemether + Lumefantrine', 'AL', 'TABLET', '20mg/120mg', 150),
                ('Quinine', 'Quinine', 'INJECTION', '300mg/ml', 200),
                ('Artesunate', 'Artesunate', 'INJECTION', '60mg', 250),
            ],
            'Antibiotics': [
                ('Amoxicillin', 'Amoxil', 'CAPSULE', '500mg', 50),
                ('Ciprofloxacin', 'Cipro', 'TABLET', '500mg', 80),
                ('Ceftriaxone', 'Ceftriaxone', 'INJECTION', '1g', 150),
                ('Metronidazole', 'Flagyl', 'TABLET', '400mg', 60),
                ('Azithromycin', 'Zithromax', 'TABLET', '500mg', 120),
            ],
            'Analgesics': [
                ('Paracetamol', 'Panadol', 'TABLET', '500mg', 20),
                ('Ibuprofen', 'Brufen', 'TABLET', '400mg', 30),
                ('Diclofenac', 'Voltaren', 'TABLET', '50mg', 40),
                ('Tramadol', 'Tramal', 'CAPSULE', '50mg', 100),
            ],
            'Antihypertensives': [
                ('Amlodipine', 'Norvasc', 'TABLET', '5mg', 70),
                ('Losartan', 'Cozaar', 'TABLET', '50mg', 90),
                ('Hydrochlorothiazide', 'HCTZ', 'TABLET', '25mg', 50),
                ('Atenolol', 'Tenormin', 'TABLET', '50mg', 60),
            ],
            'Antidiabetics': [
                ('Metformin', 'Glucophage', 'TABLET', '500mg', 80),
                ('Glibenclamide', 'Daonil', 'TABLET', '5mg', 70),
                ('Insulin (Human)', 'Actrapid', 'INJECTION', '100IU/ml', 200),
            ],
            'Antiretrovirals': [
                ('Tenofovir/Lamivudine/Dolutegravir', 'TLD', 'TABLET', '300/300/50mg', 0),
                ('Zidovudine/Lamivudine/Nevirapine', 'AZT/3TC/NVP', 'TABLET', '300/150/200mg', 0),
            ],
            'Respiratory': [
                ('Salbutamol', 'Ventolin', 'INHALER', '100mcg', 150),
                ('Prednisolone', 'Prednisolone', 'TABLET', '5mg', 80),
            ],
            'Gastrointestinal': [
                ('Omeprazole', 'Losec', 'CAPSULE', '20mg', 90),
                ('ORS (Oral Rehydration Salts)', 'ORS', 'TABLET', '20.5g', 10),
            ],
        }
        
        drug_count = 0
        for category_name, drugs in categories_data.items():
            category, _ = DrugCategory.objects.get_or_create(
                name=category_name,
                defaults={'description': f'{category_name} medications'}
            )
            
            for generic, brand, form, strength, price in drugs:
                # Generate unique drug code
                drug_code = f'DRG{str(random.randint(1000, 9999))}{str(drug_count).zfill(3)}'
                
                drug, created = Drug.objects.get_or_create(
                    drug_code=drug_code,
                    defaults={
                        'name': generic,
                        'generic_name': generic,
                        'brand_name': brand,
                        'category': category,
                        'form': form,
                        'strength': strength,
                        'unit_price': Decimal(str(price)),
                        'reorder_level': 50,
                        'requires_prescription': True,
                        'is_active': True
                    }
                )
                
                if created:
                    # Create initial stock
                    for _ in range(random.randint(1, 3)):
                        DrugStock.objects.create(
                            drug=drug,
                            batch_number=f'BATCH{random.randint(100000, 999999)}',
                            quantity=random.randint(100, 1000),
                            unit_cost=drug.unit_price * Decimal('0.7'),
                            manufacture_date=self.random_date_between(730, 180),
                            expiry_date=self.fake.date_between(start_date='+6m', end_date='+3y'),
                            supplier_name=random.choice(['Dawa Ltd', 'Pharmaceutical Suppliers Kenya', 'Medi Importers']),
                            received_date=self.random_date_between(365, 0),
                            received_by=pharmacist
                        )
                    drug_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {drug_count} drugs with stock'))

    def seed_lab_tests(self):
        """Create laboratory tests"""
        self.stdout.write('Seeding laboratory tests...')
        
        lab_tests_data = [
            ('FBC', 'Full Blood Count', 'HEMATOLOGY', 500, 2, 'Blood', False),
            ('BSS', 'Blood Sugar Random', 'BIOCHEMISTRY', 200, 1, 'Blood', False),
            ('BSF', 'Blood Sugar Fasting', 'BIOCHEMISTRY', 250, 1, 'Blood', True),
            ('HBA1C', 'HbA1c (Glycated Hemoglobin)', 'BIOCHEMISTRY', 1200, 24, 'Blood', False),
            ('RFT', 'Renal Function Tests', 'BIOCHEMISTRY', 800, 4, 'Blood', False),
            ('LFT', 'Liver Function Tests', 'BIOCHEMISTRY', 1000, 4, 'Blood', False),
            ('LIPID', 'Lipid Profile', 'BIOCHEMISTRY', 1500, 4, 'Blood', True),
            ('MALA', 'Malaria Test (BS for MPS)', 'PARASITOLOGY', 300, 1, 'Blood', False),
            ('URINALYSIS', 'Urinalysis', 'BIOCHEMISTRY', 200, 1, 'Urine', False),
            ('UCG', 'Pregnancy Test (UCG)', 'SEROLOGY', 300, 1, 'Urine', False),
            ('HIV', 'HIV Rapid Test', 'SEROLOGY', 500, 1, 'Blood', False),
            ('VDRL', 'VDRL/Syphilis Test', 'SEROLOGY', 600, 2, 'Blood', False),
            ('WIDAL', 'Widal Test (Typhoid)', 'SEROLOGY', 400, 2, 'Blood', False),
            ('STOOL', 'Stool Analysis', 'PARASITOLOGY', 300, 2, 'Stool', False),
            ('CULTURE', 'Blood Culture & Sensitivity', 'MICROBIOLOGY', 2000, 48, 'Blood', False),
        ]
        
        for code, name, category, price, tat, sample, fasting in lab_tests_data:
            LabTest.objects.get_or_create(
                test_code=code,
                defaults={
                    'name': name,
                    'category': category,
                    'price': Decimal(str(price)),
                    'turnaround_time_hours': tat,
                    'sample_type': sample,
                    'requires_fasting': fasting,
                    'is_active': True
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(lab_tests_data)} lab tests'))

    def seed_radiology_tests(self):
        """Create radiology tests"""
        self.stdout.write('Seeding radiology tests...')
        
        rad_tests_data = [
            ('XRAY_CHEST', 'Chest X-Ray', 'XRAY', 1000, 15, False),
            ('XRAY_ABD', 'Abdominal X-Ray', 'XRAY', 1200, 15, False),
            ('XRAY_LIMB', 'Limb X-Ray', 'XRAY', 800, 15, False),
            ('USS_ABD', 'Abdominal Ultrasound', 'ULTRASOUND', 2000, 30, False),
            ('USS_PREG', 'Obstetric Ultrasound', 'ULTRASOUND', 2500, 30, False),
            ('USS_PELV', 'Pelvic Ultrasound', 'ULTRASOUND', 2000, 30, False),
            ('CT_HEAD', 'CT Scan Head', 'CT', 8000, 45, False),
            ('CT_ABD', 'CT Scan Abdomen', 'CT', 12000, 45, True),
        ]
        
        for code, name, modality, price, duration, contrast in rad_tests_data:
            RadiologyTest.objects.get_or_create(
                test_code=code,
                defaults={
                    'name': name,
                    'modality': modality,
                    'price': Decimal(str(price)),
                    'estimated_duration_minutes': duration,
                    'requires_contrast': contrast,
                    'is_active': True
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(rad_tests_data)} radiology tests'))

    def seed_wards_and_beds(self):
        """Create wards and beds"""
        self.stdout.write('Seeding wards and beds...')
        
        wards_data = [
            ('Male Ward', 'MALE', 30, 1000),
            ('Female Ward', 'FEMALE', 30, 1000),
            ('Paediatrics Ward', 'PAEDIATRICS', 20, 800),
            ('Maternity Ward', 'MATERNITY', 15, 1500),
            ('ICU', 'ICU', 10, 5000),
            ('HDU', 'HDU', 8, 3000),
        ]
        
        bed_count = 0
        for ward_name, ward_type, total_beds, daily_rate in wards_data:
            ward, _ = Ward.objects.get_or_create(
                name=ward_name,
                defaults={
                    'ward_type': ward_type,
                    'total_beds': total_beds,
                    'location': f'{ward_name} - 2nd Floor',
                    'is_active': True
                }
            )
            
            # Create beds
            for i in range(1, total_beds + 1):
                Bed.objects.get_or_create(
                    ward=ward,
                    bed_number=f'{i:02d}',
                    defaults={
                        'daily_rate': Decimal(str(daily_rate)),
                        'is_occupied': False,
                        'is_available': True,
                        'status': 'AVAILABLE'
                    }
                )
                bed_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(wards_data)} wards with {bed_count} beds'))

    def seed_theatre_rooms(self):
        """Create theatre rooms"""
        self.stdout.write('Seeding theatre rooms...')
        
        for i in range(1, 4):
            TheatreRoom.objects.get_or_create(
                name=f'Operating Theatre {i}',
                defaults={
                    'room_number': f'OT-{i}',
                    'location': 'Surgical Wing - 3rd Floor',
                    'is_available': True,
                    'is_active': True
                }
            )
        
        self.stdout.write(self.style.SUCCESS('  ✓ Created 3 theatre rooms'))

    def seed_nhif_schemes(self):
        """Create NHIF schemes"""
        self.stdout.write('Seeding NHIF schemes...')
        
        schemes_data = [
            ('NHIF Outpatient', 'OUTPATIENT', 'NHIF-OUT', 1500, 10),
            ('NHIF Inpatient', 'INPATIENT', 'NHIF-INP', 15000, 10),
            ('NHIF Civil Servant', 'CIVIL_SERVANT', 'NHIF-CS', 20000, 0),
            ('NHIF Maternity', 'MATERNITY', 'NHIF-MAT', 10000, 10),
        ]
        
        for name, scheme_type, code, coverage, copay in schemes_data:
            NHIFScheme.objects.get_or_create(
                code=code,
                defaults={
                    'name': name,
                    'scheme_type': scheme_type,
                    'coverage_amount': Decimal(str(coverage)),
                    'copay_percentage': Decimal(str(copay)),
                    'is_active': True
                }
            )
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {len(schemes_data)} NHIF schemes'))

    def seed_patients(self, count=500):
        """Create patient records"""
        self.stdout.write(f'Seeding {count} patients...')
        
        patients_created = 0
        receptionists = list(User.objects.filter(role__name='RECEPTIONIST'))
        
        if not receptionists:
            self.stdout.write(self.style.ERROR('  No receptionists found. Please seed users first.'))
            return
        
        for i in range(count):
            gender = random.choice(['MALE', 'FEMALE'])
            first_name = random.choice(
                self.KENYAN_FIRST_NAMES_MALE if gender == 'MALE' else self.KENYAN_FIRST_NAMES_FEMALE
            )
            last_name = random.choice(self.KENYAN_LAST_NAMES)
            middle_name = random.choice(['', random.choice(self.KENYAN_FIRST_NAMES_MALE + self.KENYAN_FIRST_NAMES_FEMALE)])
            
            # Age distribution
            age_group = random.choices(
                ['infant', 'child', 'teen', 'adult', 'elderly'],
                weights=[5, 15, 10, 50, 20]
            )[0]
            
            if age_group == 'infant':
                dob = self.random_date_between(365, 0)
            elif age_group == 'child':
                dob = self.random_date_between(4380, 366)  # 1-12 years
            elif age_group == 'teen':
                dob = self.random_date_between(6570, 4381)  # 13-18 years
            elif age_group == 'adult':
                dob = self.random_date_between(23360, 6571)  # 18-64 years
            else:
                dob = self.random_date_between(36500, 23361)  # 65+ years
            
            # NHIF status distribution
            nhif_status = random.choices(
                ['NONE', 'ACTIVE', 'INACTIVE', 'CIVIL_SERVANT'],
                weights=[40, 35, 15, 10]
            )[0]
            
            nhif_number = ''
            if nhif_status != 'NONE':
                nhif_number = f'{random.randint(1000000, 9999999)}'
            
            # Chronic conditions based on age
            if age_group in ['adult', 'elderly']:
                chronic = random.choice(self.CHRONIC_CONDITIONS)
            else:
                chronic = 'None'
            
            county = random.choice(self.KENYAN_COUNTIES)
            
            patient = Patient.objects.create(
                first_name=first_name,
                middle_name=middle_name,
                last_name=last_name,
                date_of_birth=dob,
                gender=gender,
                id_number=self.generate_kenyan_id() if age_group != 'infant' else '',
                phone_number=self.generate_kenyan_phone(),
                alternate_phone=self.generate_kenyan_phone() if random.random() > 0.5 else '',
                email=f'{first_name.lower()}.{last_name.lower()}@email.com' if random.random() > 0.7 else '',
                county=county,
                sub_county=f'{county} {random.choice(["North", "South", "East", "West"])}',
                ward=self.fake.city(),
                village=self.fake.street_name(),
                postal_address=f'P.O. Box {random.randint(1, 99999)}-{random.randint(10000, 99999)}',
                next_of_kin_name=f'{random.choice(self.KENYAN_FIRST_NAMES_MALE)} {random.choice(self.KENYAN_LAST_NAMES)}',
                next_of_kin_relationship=random.choice(['Spouse', 'Parent', 'Sibling', 'Child', 'Friend']),
                next_of_kin_phone=self.generate_kenyan_phone(),
                blood_group=random.choice(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', '']),
                allergies=random.choice(self.COMMON_ALLERGIES),
                chronic_conditions=chronic,
                nhif_status=nhif_status,
                nhif_number=nhif_number,
                registered_by=random.choice(receptionists),
                registration_date=self.random_datetime_between(365, 0),
                is_active=True
            )
            patients_created += 1
            
            if (i + 1) % 100 == 0:
                self.stdout.write(f'  Created {i + 1} patients...')
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {patients_created} patients'))

    def seed_patient_visits(self, count=1000):
        """Create patient visits with full clinical workflow"""
        self.stdout.write(f'Seeding {count} patient visits...')
        
        patients = list(Patient.objects.all())
        if not patients:
            self.stdout.write(self.style.ERROR('  No patients found. Please seed patients first.'))
            return
        
        nurses = list(User.objects.filter(role__name='NURSE'))
        doctors = list(User.objects.filter(role__name__in=['DOCTOR', 'CLINICAL_OFFICER']))
        lab_techs = list(User.objects.filter(role__name='LAB_TECHNICIAN'))
        radiologists = list(User.objects.filter(role__name='RADIOLOGIST'))
        pharmacists = list(User.objects.filter(role__name='PHARMACIST'))
        cashiers = list(User.objects.filter(role__name='CASHIER'))
        
        if not doctors:
            self.stdout.write(self.style.ERROR('  No doctors found. Please seed users first.'))
            return
        
        visits_created = 0
        
        for i in range(count):
            try:
                patient = random.choice(patients)
                
                # Visit type distribution
                visit_type = random.choices(
                    ['OUTPATIENT', 'EMERGENCY', 'INPATIENT', 'REFERRAL'],
                    weights=[70, 20, 5, 5]
                )[0]
                
                # Create visit in the past year
                visit_date = self.random_date_between(365, 0)
                arrival_time = self.fake.date_time_between(
                    start_date=visit_date,
                    end_date=visit_date,
                    tzinfo=timezone.get_current_timezone()
                )
                
                priority = 3
                if visit_type == 'EMERGENCY':
                    priority = random.choice([1, 2])
                
                chief_complaint = random.choice(self.CHIEF_COMPLAINTS)
                
                # Generate unique visit number manually
                visit_number = self._generate_unique_visit_number(visit_date)
                
                visit = PatientVisit(
                    patient=patient,
                    visit_type=visit_type,
                    visit_date=visit_date,
                    arrival_time=arrival_time,
                    priority_level=priority,
                    chief_complaint=chief_complaint,
                    status='COMPLETED',
                    is_referral=(visit_type == 'REFERRAL'),
                    referring_facility='Kenyatta National Hospital' if visit_type == 'REFERRAL' else '',
                    exit_time=arrival_time + timedelta(hours=random.randint(2, 8))
                )
                # Set the visit_number before saving to bypass auto-generation
                visit.visit_number = visit_number
                visit.save()
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'  Error creating visit {i+1}: {str(e)}'))
                continue
            
            # Add Triage
            if nurses and random.random() > 0.1:  # 90% get triage
                try:
                    self._create_triage(visit, random.choice(nurses))
                except Exception as e:
                    pass
            
            # Add Consultation
            try:
                consultation = self._create_consultation(visit, random.choice(doctors))
                
                # Add Lab Orders (40% of visits)
                if lab_techs and random.random() > 0.6:
                    try:
                        self._create_lab_orders(visit, consultation, random.choice(doctors), lab_techs)
                    except Exception as e:
                        pass
                
                # Add Radiology Orders (20% of visits)
                if radiologists and random.random() > 0.8:
                    try:
                        self._create_radiology_orders(visit, consultation, random.choice(doctors), radiologists)
                    except Exception as e:
                        pass
                
                # Add Prescriptions (70% of visits)
                if pharmacists and random.random() > 0.3:
                    try:
                        self._create_prescription(visit, consultation, random.choice(doctors), pharmacists)
                    except Exception as e:
                        pass
            except Exception as e:
                self.stdout.write(self.style.WARNING(f'  Error creating consultation for visit {visit.visit_number}: {str(e)}'))
            
            # Create admission for some inpatient visits
            if visit_type == 'INPATIENT' and random.random() > 0.5:
                try:
                    self._create_admission(visit, doctors)
                except Exception as e:
                    pass
            
            # Create Payment (must be after all services to get proper invoice total)
            if cashiers:
                try:
                    self._create_payment(visit, patient, cashiers)
                except Exception as e:
                    pass
            
            visits_created += 1
            
            if (i + 1) % 100 == 0:
                self.stdout.write(f'  Created {i + 1} visits...')
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {visits_created} visits with full workflow'))

    def _generate_unique_visit_number(self, visit_date):
        """Generate a unique visit number for a given date"""
        # Count all visits for this date
        count = PatientVisit.objects.filter(visit_date=visit_date).count() + 1
        
        # Keep trying until we find a unique number
        max_attempts = 100
        for attempt in range(max_attempts):
            visit_number = f"VIS{visit_date.strftime('%Y%m%d')}{(count + attempt):04d}"
            if not PatientVisit.objects.filter(visit_number=visit_number).exists():
                return visit_number
        
        # Fallback to timestamp-based unique number
        return f"VIS{visit_date.strftime('%Y%m%d')}{timezone.now().microsecond:06d}"

    def _create_triage(self, visit, nurse):
        """Create triage assessment"""
        emergency_level = 'NORMAL'
        if visit.priority_level == 1:
            emergency_level = 'CRITICAL'
        elif visit.priority_level == 2:
            emergency_level = 'EMERGENCY'
        elif visit.priority_level == 3:
            emergency_level = 'URGENT'
        
        TriageAssessment.objects.create(
            visit=visit,
            nurse=nurse,
            temperature=Decimal(str(round(random.uniform(36.0, 39.5), 1))),
            pulse=random.randint(60, 120),
            systolic_bp=random.randint(90, 160),
            diastolic_bp=random.randint(60, 100),
            respiratory_rate=random.randint(12, 30),
            oxygen_saturation=random.randint(92, 100),
            weight=Decimal(str(round(random.uniform(40, 120), 2))) if visit.patient.age > 12 else Decimal(str(round(random.uniform(3, 40), 2))),
            height=Decimal(str(round(random.uniform(150, 190), 2))) if visit.patient.age > 12 else Decimal(str(round(random.uniform(50, 150), 2))),
            chief_complaint=visit.chief_complaint,
            pain_scale=random.randint(0, 10),
            emergency_level=emergency_level,
            triage_notes=f'Patient presenting with {visit.chief_complaint}. Vitals checked and stable.',
            assessment_time=visit.arrival_time + timedelta(minutes=random.randint(5, 30))
        )

    def _create_consultation(self, visit, doctor):
        """Create doctor consultation"""
        diagnosis = random.choice(self.DIAGNOSES)
        
        consultation_start = visit.arrival_time + timedelta(minutes=random.randint(30, 90))
        consultation_end = consultation_start + timedelta(minutes=random.randint(15, 60))
        
        # Get settings for consultation fee
        settings = HospitalSettings.load()
        consultation_fee = settings.default_consultation_fee
        if visit.visit_type == 'EMERGENCY':
            consultation_fee += settings.emergency_surcharge
        
        consultation = Consultation.objects.create(
            visit=visit,
            doctor=doctor,
            consultation_start=consultation_start,
            consultation_end=consultation_end,
            chief_complaint=visit.chief_complaint,
            history_of_illness=f'Patient reports {visit.chief_complaint} for the past {random.randint(1, 7)} days.',
            past_medical_history=visit.patient.chronic_conditions,
            physical_examination='General examination done. Patient alert and oriented. No acute distress noted.',
            provisional_diagnosis=diagnosis,
            final_diagnosis=diagnosis,
            treatment_plan=f'Treated for {diagnosis}. Advised rest and hydration.',
            follow_up_instructions='Return if symptoms worsen or persist beyond 7 days.',
            follow_up_date=visit.visit_date + timedelta(days=random.randint(7, 30)) if random.random() > 0.5 else None,
            admission_required=(visit.visit_type == 'INPATIENT'),
            referral_required=(visit.visit_type == 'REFERRAL'),
            consultation_fee=consultation_fee
        )
        
        return consultation

    def _create_lab_orders(self, visit, consultation, doctor, lab_techs):
        """Create lab orders and results"""
        lab_tests = list(LabTest.objects.all())
        if not lab_tests:
            return
        
        # Order 1-3 tests
        num_tests = random.randint(1, 3)
        selected_tests = random.sample(lab_tests, min(num_tests, len(lab_tests)))
        
        for test in selected_tests:
            order = LabOrder.objects.create(
                visit=visit,
                test=test,
                ordered_by=doctor,
                ordered_at=consultation.consultation_end,
                clinical_notes=f'Clinical indication: {consultation.final_diagnosis}',
                sample_collected_at=consultation.consultation_end + timedelta(minutes=random.randint(10, 30)),
                sample_collected_by=random.choice(lab_techs),
                status='COMPLETED',
                priority=(visit.priority_level <= 2)
            )
            
            # Create result (80% completed)
            if random.random() > 0.2:
                result_values = {
                    'FBC': f'WBC: {random.randint(4, 11)} x10^9/L, RBC: {round(random.uniform(4.0, 6.0), 1)} x10^12/L, Hb: {round(random.uniform(12, 16), 1)} g/dL',
                    'BSS': f'{random.randint(70, 140)} mg/dL',
                    'BSF': f'{random.randint(70, 126)} mg/dL',
                    'MALA': random.choice(['Negative', 'Positive - P. falciparum seen']),
                    'URINALYSIS': 'pH: 6.0, Protein: Negative, Glucose: Negative, Blood: Negative',
                    'HIV': random.choice(['Non-reactive', 'Reactive']),
                }
                
                result_value = result_values.get(test.test_code, 'Normal - within reference range')
                
                LabResult.objects.create(
                    lab_order=order,
                    technician=random.choice(lab_techs),
                    result_value=result_value,
                    reference_range='See laboratory reference ranges',
                    interpretation='Results reviewed and within expected parameters' if 'Normal' in result_value or 'Negative' in result_value else 'Abnormal result - clinical correlation required',
                    is_abnormal=('Positive' in result_value or 'Reactive' in result_value),
                    result_date=order.ordered_at + timedelta(hours=test.turnaround_time_hours)
                )

    def _create_radiology_orders(self, visit, consultation, doctor, radiologists):
        """Create radiology orders and results"""
        rad_tests = list(RadiologyTest.objects.all())
        if not rad_tests:
            return
        
        # Order 1-2 tests
        num_tests = random.randint(1, 2)
        selected_tests = random.sample(rad_tests, min(num_tests, len(rad_tests)))
        
        for test in selected_tests:
            order = RadiologyOrder.objects.create(
                visit=visit,
                test=test,
                ordered_by=doctor,
                ordered_at=consultation.consultation_end,
                clinical_notes=f'Clinical indication: {consultation.final_diagnosis}',
                status='REPORTED',
                priority=(visit.priority_level <= 2),
                scheduled_datetime=consultation.consultation_end + timedelta(hours=random.randint(1, 4))
            )
            
            # Create result (70% completed)
            if random.random() > 0.3:
                findings_templates = {
                    'XRAY_CHEST': 'Both lung fields are clear. Heart size is normal. No pleural effusion.',
                    'USS_ABD': 'Liver, spleen, kidneys appear normal in size and echogenicity. No free fluid.',
                    'CT_HEAD': 'No acute intracranial hemorrhage or mass effect. Brain parenchyma appears normal.',
                }
                
                findings = findings_templates.get(test.test_code, 'Examination completed. Findings documented.')
                
                RadiologyResult.objects.create(
                    radiology_order=order,
                    radiologist=random.choice(radiologists),
                    findings=findings,
                    impression='Normal study' if 'normal' in findings.lower() else 'See findings above',
                    recommendations='Clinical correlation advised' if random.random() > 0.7 else '',
                    result_date=order.ordered_at + timedelta(hours=random.randint(2, 24))
                )

    def _create_prescription(self, visit, consultation, doctor, pharmacists):
        """Create prescription with items"""
        prescription = Prescription.objects.create(
            visit=visit,
            prescribed_by=doctor,
            prescribed_at=consultation.consultation_end,
            status='DISPENSED'
        )
        
        drugs = list(Drug.objects.filter(is_active=True, stock_records__quantity__gt=0).distinct())
        if not drugs:
            return
        
        # Prescribe 1-4 drugs
        num_drugs = random.randint(1, min(4, len(drugs)))
        selected_drugs = random.sample(drugs, num_drugs)
        
        for drug in selected_drugs:
            quantity = random.choice([10, 14, 21, 28, 30])
            
            dosage_templates = {
                'TABLET': f'{random.choice([1, 2])} tablet(s) {random.choice(["once", "twice", "three times"])} daily',
                'CAPSULE': f'{random.choice([1, 2])} capsule(s) {random.choice(["once", "twice", "three times"])} daily',
                'SYRUP': f'{random.choice([5, 10])}ml {random.choice(["twice", "three times"])} daily',
                'INJECTION': 'As directed by clinician',
                'INHALER': f'{random.choice([1, 2])} puff(s) {random.choice(["twice", "three times"])} daily',
            }
            
            dosage = dosage_templates.get(drug.form, '1 unit as directed')
            duration = f'{random.choice([3, 5, 7, 10, 14])} days'
            
            PrescriptionItem.objects.create(
                prescription=prescription,
                drug=drug,
                quantity=quantity,
                dosage=dosage,
                duration=duration,
                instructions=f'Take {dosage} for {duration}. Complete the course.',
                dispensed_quantity=quantity,
                dispensed_by=random.choice(pharmacists),
                dispensed_at=consultation.consultation_end + timedelta(hours=random.randint(1, 3))
            )

    def _create_admission(self, visit, doctors):
        """Create hospital admission"""
        if not doctors:
            return
        
        available_beds = list(Bed.objects.filter(is_occupied=False, is_available=True))
        if not available_beds:
            return
        
        bed = random.choice(available_beds)
        admission_datetime = visit.arrival_time + timedelta(hours=random.randint(2, 6))
        
        # 70% discharged, 30% still admitted
        is_discharged = random.random() > 0.3
        
        admission = Admission.objects.create(
            visit=visit,
            patient=visit.patient,
            admission_type=random.choice(['EMERGENCY', 'ELECTIVE']),
            admission_datetime=admission_datetime,
            bed=bed,
            admitting_doctor=random.choice(doctors),
            admission_diagnosis=random.choice(self.DIAGNOSES),
            admission_notes='Patient admitted for observation and management.',
            status='DISCHARGED' if is_discharged else 'ACTIVE'
        )
        
        if is_discharged:
            discharge_datetime = admission_datetime + timedelta(days=random.randint(1, 7))
            admission.discharge_datetime = discharge_datetime
            admission.discharge_diagnosis = admission.admission_diagnosis
            admission.discharge_summary = 'Patient responded well to treatment. Condition improved.'
            admission.discharge_instructions = 'Continue medications as prescribed. Follow up in outpatient clinic.'
            admission.discharged_by = random.choice(doctors)
            admission.save()
        
        # Add progress notes (for multi-day admissions)
        if admission.discharge_datetime:
            days_admitted = (admission.discharge_datetime - admission.admission_datetime).days
            for day in range(min(days_admitted, 5)):
                ProgressNote.objects.create(
                    admission=admission,
                    doctor=random.choice(doctors),
                    note_date=admission.admission_datetime.date() + timedelta(days=day),
                    subjective=f'Patient reports feeling {random.choice(["better", "same", "slightly improved"])}.',
                    objective='Vitals stable. Patient alert and oriented.',
                    assessment='Condition improving with current management.',
                    plan='Continue current medications. Monitor progress.'
                )

    def _create_payment(self, visit, patient, cashiers):
        """Create payment for visit"""
        # Get or create invoice
        try:
            invoice = Invoice.objects.get(visit=visit)
        except Invoice.DoesNotExist:
            # If no invoice exists, services weren't added - skip
            return
        
        # Refresh and recalculate
        invoice.refresh_from_db()
        invoice.calculate_totals()
        invoice.save()
        
        # Skip if no charges
        if invoice.total_amount <= 0:
            return
        
        # 80% paid, 20% pending
        if random.random() > 0.2:
            payment_method = random.choices(
                ['CASH', 'MPESA', 'NHIF', 'BANK_TRANSFER'],
                weights=[40, 35, 20, 5]
            )[0]
            
            # NHIF coverage
            if payment_method == 'NHIF' and patient.nhif_status in ['ACTIVE', 'CIVIL_SERVANT']:
                schemes = list(NHIFScheme.objects.filter(is_active=True))
                if schemes:
                    scheme = random.choice(schemes)
                    
                    claimed_amount = invoice.total_amount
                    approved_amount = min(invoice.total_amount, scheme.coverage_amount)
                    
                    NHIFClaim.objects.create(
                        visit=visit,
                        patient=patient,
                        invoice=invoice,
                        claim_type=scheme.scheme_type,
                        scheme=scheme,
                        claimed_amount=claimed_amount,
                        approved_amount=approved_amount,
                        status='APPROVED'
                    )
                    
                    # Update invoice with NHIF coverage
                    invoice.refresh_from_db()
                    invoice.nhif_coverage_amount = approved_amount
                    invoice.calculate_totals()
                    invoice.save()
                    
                    payment_method = 'CASH'  # Patient pays copay
            
            # Calculate payment amount (total - NHIF coverage)
            invoice.refresh_from_db()
            payment_amount = invoice.total_amount - invoice.nhif_coverage_amount
            
            if payment_amount > 0:
                payment = Payment.objects.create(
                    invoice=invoice,
                    payment_method=payment_method,
                    amount=payment_amount,
                    payment_date=visit.exit_time or timezone.now(),
                    received_by=random.choice(cashiers),
                    status='COMPLETED'
                )
                
                if payment_method == 'MPESA':
                    payment.mpesa_receipt_number = f'PG{random.randint(10000000, 99999999)}'
                    payment.mpesa_phone_number = patient.phone_number
                    payment.save()
                
                # Create receipt
                Receipt.objects.create(
                    payment=payment,
                    issued_by=random.choice(cashiers)
                )

    def seed_appointments(self):
        """Create future appointments"""
        self.stdout.write('Seeding appointments...')
        
        patients = list(Patient.objects.all()[:100])  # Just 100 patients with appointments
        doctors = list(User.objects.filter(role__name__in=['DOCTOR', 'CLINICAL_OFFICER']))
        
        if not patients or not doctors:
            return
        
        appointments_created = 0
        
        # Create appointments for next 30 days
        for i in range(150):
            patient = random.choice(patients)
            doctor = random.choice(doctors)
            
            # Future date within 30 days
            days_ahead = random.randint(1, 30)
            appointment_date = timezone.now().date() + timedelta(days=days_ahead)
            hour = random.choice([9, 10, 11, 14, 15, 16])
            minute = random.choice([0, 30])
            
            appointment_datetime = timezone.make_aware(
                datetime.combine(appointment_date, datetime.min.time().replace(hour=hour, minute=minute))
            )
            
            Appointment.objects.create(
                patient=patient,
                doctor=doctor,
                appointment_datetime=appointment_datetime,
                duration_minutes=30,
                appointment_type=random.choice(['Follow-up', 'New Consultation', 'Review', 'Chronic Care']),
                reason=random.choice(self.CHIEF_COMPLAINTS),
                status=random.choices(
                    ['SCHEDULED', 'CONFIRMED', 'CANCELLED'],
                    weights=[70, 25, 5]
                )[0],
                sms_reminder_sent=(random.random() > 0.5)
            )
            appointments_created += 1
        
        self.stdout.write(self.style.SUCCESS(f'  ✓ Created {appointments_created} appointments'))