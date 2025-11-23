from django import forms
from django.core.exceptions import ValidationError
from .models import Patient
import re


class PatientRegistrationForm(forms.ModelForm):
    """
    Form for patient registration and updates
    """
    
    class Meta:
        model = Patient
        fields = [
            'first_name', 'middle_name', 'last_name', 'date_of_birth', 'gender',
            'id_number', 'phone_number', 'alternate_phone', 'email',
            'county', 'sub_county', 'ward', 'village', 'postal_address',
            'next_of_kin_name', 'next_of_kin_relationship', 'next_of_kin_phone',
            'next_of_kin_address', 'blood_group', 'allergies', 'chronic_conditions',
            'nhif_status', 'nhif_number', 'nhif_principal_name', 'notes'
        ]
        
        widgets = {
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter first name',
                'required': True
            }),
            'middle_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter middle name (optional)'
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter last name',
                'required': True
            }),
            'date_of_birth': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date',
                'required': True
            }),
            'gender': forms.Select(attrs={
                'class': 'form-select',
                'required': True
            }),
            'id_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter ID number (optional for children)'
            }),
            'phone_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': '0712345678 or +254712345678',
                'required': True
            }),
            'alternate_phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Alternative phone number (optional)'
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'placeholder': 'email@example.com (optional)'
            }),
            'county': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter county',
                'required': True
            }),
            'sub_county': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter sub-county'
            }),
            'ward': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter ward'
            }),
            'village': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter village'
            }),
            'postal_address': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'P.O. Box ...'
            }),
            'next_of_kin_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Next of kin full name',
                'required': True
            }),
            'next_of_kin_relationship': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'e.g., Spouse, Parent, Sibling',
                'required': True
            }),
            'next_of_kin_phone': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Next of kin phone number',
                'required': True
            }),
            'next_of_kin_address': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Next of kin address (optional)'
            }),
            'blood_group': forms.Select(attrs={
                'class': 'form-select'
            }),
            'allergies': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'List any known allergies (e.g., Penicillin, Peanuts)'
            }),
            'chronic_conditions': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'List chronic conditions (e.g., Diabetes, Hypertension)'
            }),
            'nhif_status': forms.Select(attrs={
                'class': 'form-select'
            }),
            'nhif_number': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'NHIF membership number'
            }),
            'nhif_principal_name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Principal member name (for dependents)'
            }),
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Additional notes or remarks'
            }),
        }
        
        labels = {
            'first_name': 'First Name *',
            'middle_name': 'Middle Name',
            'last_name': 'Last Name *',
            'date_of_birth': 'Date of Birth *',
            'gender': 'Gender *',
            'id_number': 'ID Number',
            'phone_number': 'Phone Number *',
            'alternate_phone': 'Alternative Phone',
            'email': 'Email Address',
            'county': 'County *',
            'sub_county': 'Sub-County',
            'ward': 'Ward',
            'village': 'Village',
            'postal_address': 'Postal Address',
            'next_of_kin_name': 'Next of Kin Name *',
            'next_of_kin_relationship': 'Relationship *',
            'next_of_kin_phone': 'Next of Kin Phone *',
            'next_of_kin_address': 'Next of Kin Address',
            'blood_group': 'Blood Group',
            'allergies': 'Allergies',
            'chronic_conditions': 'Chronic Conditions',
            'nhif_status': 'NHIF Status',
            'nhif_number': 'NHIF Number',
            'nhif_principal_name': 'NHIF Principal Member',
            'notes': 'Additional Notes',
        }
    
    def clean_phone_number(self):
        """Validate phone number format"""
        phone = self.cleaned_data.get('phone_number', '').strip()
        
        if not phone:
            raise ValidationError('Phone number is required.')
        
        # Remove spaces and special characters
        phone = re.sub(r'[^0-9+]', '', phone)
        
        # Kenyan phone number validation
        if phone.startswith('+254'):
            if len(phone) != 13:
                raise ValidationError('Invalid Kenyan phone number format. Should be +254XXXXXXXXX')
        elif phone.startswith('254'):
            if len(phone) != 12:
                raise ValidationError('Invalid Kenyan phone number format. Should be 254XXXXXXXXX')
        elif phone.startswith('0'):
            if len(phone) != 10:
                raise ValidationError('Invalid Kenyan phone number format. Should be 07XXXXXXXX or 01XXXXXXXX')
            # Convert to international format
            phone = f'254{phone[1:]}'
        elif phone.startswith('7') or phone.startswith('1'):
            if len(phone) != 9:
                raise ValidationError('Invalid phone number format.')
            phone = f'254{phone}'
        else:
            raise ValidationError('Invalid phone number format. Use format: 0712345678 or +254712345678')
        
        return phone
    
    def clean_alternate_phone(self):
        """Validate alternate phone number if provided"""
        phone = self.cleaned_data.get('alternate_phone', '').strip()
        
        if not phone:
            return ''
        
        # Same validation as primary phone
        phone = re.sub(r'[^0-9+]', '', phone)
        
        if phone.startswith('+254'):
            if len(phone) != 13:
                raise ValidationError('Invalid phone number format.')
        elif phone.startswith('254'):
            if len(phone) != 12:
                raise ValidationError('Invalid phone number format.')
        elif phone.startswith('0'):
            if len(phone) != 10:
                raise ValidationError('Invalid phone number format.')
            phone = f'254{phone[1:]}'
        elif phone.startswith('7') or phone.startswith('1'):
            if len(phone) != 9:
                raise ValidationError('Invalid phone number format.')
            phone = f'254{phone}'
        
        return phone
    
    def clean_next_of_kin_phone(self):
        """Validate next of kin phone number"""
        phone = self.cleaned_data.get('next_of_kin_phone', '').strip()
        
        if not phone:
            raise ValidationError('Next of kin phone number is required.')
        
        phone = re.sub(r'[^0-9+]', '', phone)
        
        if phone.startswith('+254'):
            if len(phone) != 13:
                raise ValidationError('Invalid phone number format.')
        elif phone.startswith('254'):
            if len(phone) != 12:
                raise ValidationError('Invalid phone number format.')
        elif phone.startswith('0'):
            if len(phone) != 10:
                raise ValidationError('Invalid phone number format.')
            phone = f'254{phone[1:]}'
        elif phone.startswith('7') or phone.startswith('1'):
            if len(phone) != 9:
                raise ValidationError('Invalid phone number format.')
            phone = f'254{phone}'
        
        return phone
    
    def clean_email(self):
        """Validate email if provided"""
        email = self.cleaned_data.get('email', '').strip().lower()
        
        if not email:
            return ''
        
        # Check if email already exists for another patient
        if self.instance.pk:
            # Updating existing patient
            if Patient.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
                raise ValidationError('This email is already registered to another patient.')
        else:
            # Creating new patient
            if Patient.objects.filter(email=email).exists():
                raise ValidationError('This email is already registered to another patient.')
        
        return email
    
    def clean_nhif_number(self):
        """Validate NHIF number if NHIF is active"""
        nhif_status = self.cleaned_data.get('nhif_status')
        nhif_number = self.cleaned_data.get('nhif_number', '').strip()
        
        if nhif_status in ['ACTIVE', 'CIVIL_SERVANT'] and not nhif_number:
            raise ValidationError('NHIF number is required when NHIF status is Active or Civil Servant.')
        
        return nhif_number
    
    def clean_date_of_birth(self):
        """Validate date of birth"""
        from django.utils import timezone
        from datetime import timedelta
        
        dob = self.cleaned_data.get('date_of_birth')
        
        if not dob:
            raise ValidationError('Date of birth is required.')
        
        today = timezone.now().date()
        
        # Check if date is in the future
        if dob > today:
            raise ValidationError('Date of birth cannot be in the future.')
        
        # Check if patient is too old (e.g., more than 120 years)
        max_age = today - timedelta(days=120*365)
        if dob < max_age:
            raise ValidationError('Please enter a valid date of birth.')
        
        return dob
    
    def clean(self):
        """Additional form-level validation"""
        cleaned_data = super().clean()
        
        # Check if patient with same details already exists (to prevent duplicates)
        first_name = cleaned_data.get('first_name', '').strip()
        last_name = cleaned_data.get('last_name', '').strip()
        date_of_birth = cleaned_data.get('date_of_birth')
        phone_number = cleaned_data.get('phone_number', '').strip()
        
        if first_name and last_name and date_of_birth and phone_number:
            # Check for potential duplicate
            duplicate_check = Patient.objects.filter(
                first_name__iexact=first_name,
                last_name__iexact=last_name,
                date_of_birth=date_of_birth,
                phone_number=phone_number,
                is_active=True
            )
            
            if self.instance.pk:
                duplicate_check = duplicate_check.exclude(pk=self.instance.pk)
            
            if duplicate_check.exists():
                raise ValidationError(
                    'A patient with the same name, date of birth, and phone number already exists. '
                    f'Patient Number: {duplicate_check.first().patient_number}'
                )
        
        return cleaned_data
    
    
from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import PatientVisit, TriageAssessment, Patient


class PatientVisitForm(forms.ModelForm):
    """Form for registering a new patient visit"""
    
    class Meta:
        model = PatientVisit
        fields = [
            'patient',
            'visit_type',
            'priority_level',
            'chief_complaint',
            'is_referral',
            'referring_facility',
            'referral_notes',
        ]
        widgets = {
            'patient': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'visit_type': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'priority_level': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'chief_complaint': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'required': True,
                'placeholder': 'Enter patient\'s main complaint...',
            }),
            'is_referral': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
            }),
            'referring_facility': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Name of referring hospital/clinic',
            }),
            'referral_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Reason for referral and notes',
            }),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show active patients
        self.fields['patient'].queryset = Patient.objects.filter(is_active=True).order_by('first_name', 'last_name')
        
        # Set priority level choices with descriptions
        self.fields['priority_level'].choices = [
            (1, '1 - Critical (Immediate)'),
            (2, '2 - Emergency (< 15 min)'),
            (3, '3 - Urgent (< 60 min)'),
            (4, '4 - Normal (< 4 hours)'),
            (5, '5 - Low Priority'),
        ]
    
    def clean(self):
        cleaned_data = super().clean()
        is_referral = cleaned_data.get('is_referral')
        referring_facility = cleaned_data.get('referring_facility')
        
        # If referral is checked, facility name is required
        if is_referral and not referring_facility:
            raise ValidationError({
                'referring_facility': 'Referring facility is required for referral cases.'
            })
        
        return cleaned_data


class TriageAssessmentForm(forms.ModelForm):
    """Form for triage assessment"""
    
    class Meta:
        model = TriageAssessment
        fields = [
            'temperature',
            'pulse',
            'systolic_bp',
            'diastolic_bp',
            'respiratory_rate',
            'oxygen_saturation',
            'weight',
            'height',
            'chief_complaint',
            'pain_scale',
            'emergency_level',
            'triage_notes',
        ]
        widgets = {
            'temperature': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.1',
                'min': '35.0',
                'max': '45.0',
                'required': True,
                'placeholder': '36.5',
            }),
            'pulse': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '40',
                'max': '200',
                'required': True,
                'placeholder': '72',
            }),
            'systolic_bp': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '70',
                'max': '250',
                'required': True,
                'placeholder': '120',
            }),
            'diastolic_bp': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '40',
                'max': '150',
                'required': True,
                'placeholder': '80',
            }),
            'respiratory_rate': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '10',
                'max': '60',
                'required': True,
                'placeholder': '16',
            }),
            'oxygen_saturation': forms.NumberInput(attrs={
                'class': 'form-control',
                'min': '70',
                'max': '100',
                'required': True,
                'placeholder': '98',
            }),
            'weight': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.1',
                'placeholder': '70.0',
            }),
            'height': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.1',
                'placeholder': '170',
            }),
            'chief_complaint': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'required': True,
            }),
            'pain_scale': forms.NumberInput(attrs={
                'class': 'form-range',
                'type': 'range',
                'min': '0',
                'max': '10',
                'value': '5',
            }),
            'emergency_level': forms.Select(attrs={
                'class': 'form-select',
                'required': True,
            }),
            'triage_notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'required': True,
                'placeholder': 'Detailed nursing assessment and observations...',
            }),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        
        # Validate blood pressure
        systolic = cleaned_data.get('systolic_bp')
        diastolic = cleaned_data.get('diastolic_bp')
        
        if systolic and diastolic:
            if systolic <= diastolic:
                raise ValidationError({
                    'systolic_bp': 'Systolic BP must be greater than diastolic BP.'
                })
        
        # Warn about critical vitals
        temp = cleaned_data.get('temperature')
        pulse = cleaned_data.get('pulse')
        spo2 = cleaned_data.get('oxygen_saturation')
        emergency_level = cleaned_data.get('emergency_level')
        
        # Auto-suggest critical if vitals are critical but level is not set
        is_critical_vitals = (
            (temp and (temp < 35.0 or temp > 40.0)) or
            (pulse and (pulse < 50 or pulse > 120)) or
            (spo2 and spo2 < 90)
        )
        
        if is_critical_vitals and emergency_level not in ['CRITICAL', 'EMERGENCY']:
            self.add_error(
                'emergency_level',
                'Warning: Vital signs indicate critical/emergency condition. Please review emergency level.'
            )
        
        return cleaned_data


class QuickTriageForm(forms.ModelForm):
    """Simplified triage form for quick assessment"""
    
    class Meta:
        model = TriageAssessment
        fields = [
            'temperature',
            'pulse',
            'systolic_bp',
            'diastolic_bp',
            'oxygen_saturation',
            'emergency_level',
            'triage_notes',
        ]
        widgets = {
            'temperature': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.1'}),
            'pulse': forms.NumberInput(attrs={'class': 'form-control'}),
            'systolic_bp': forms.NumberInput(attrs={'class': 'form-control'}),
            'diastolic_bp': forms.NumberInput(attrs={'class': 'form-control'}),
            'oxygen_saturation': forms.NumberInput(attrs={'class': 'form-control'}),
            'emergency_level': forms.Select(attrs={'class': 'form-select'}),
            'triage_notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }