import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from main_application.models import Patient, PatientVisit

class Command(BaseCommand):
    help = "Update existing Patient and PatientVisit dates with random dates from last year to today"

    def handle(self, *args, **kwargs):
        today = timezone.now().date()
        one_year_ago = today - timedelta(days=365)

        # Update Patient dates
        patients = Patient.objects.all()
        for patient in patients:
            # Random DOB: age 1-90
            age_days = random.randint(365, 90*365)
            patient.date_of_birth = today - timedelta(days=age_days)

            # Random registration date from last year to today
            reg_days_ago = random.randint(0, 365)
            random_registration_datetime = timezone.now() - timedelta(days=reg_days_ago,
                                                                     hours=random.randint(0,23),
                                                                     minutes=random.randint(0,59))
            patient.registration_date = random_registration_datetime
            patient.save(update_fields=['date_of_birth', 'registration_date'])
            self.stdout.write(self.style.SUCCESS(f"Updated Patient {patient.patient_number}"))

        # Update PatientVisit dates
        visits = PatientVisit.objects.all()
        for visit in visits:
            # Random visit_date
            visit_days_ago = random.randint(0, 365)
            visit.visit_date = today - timedelta(days=visit_days_ago)

            # Random arrival_time within that day
            visit.arrival_time = timezone.now() - timedelta(days=visit_days_ago,
                                                            hours=random.randint(0,23),
                                                            minutes=random.randint(0,59))
            visit.save(update_fields=['visit_date', 'arrival_time'])
            self.stdout.write(self.style.SUCCESS(f"Updated Visit {visit.visit_number}"))
