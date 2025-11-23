import random
from datetime import date, timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone

from main_application.models import (
    Patient, PatientVisit, TriageAssessment, User
)

# Kenyan Data Pools
KENYAN_FIRST_NAMES = [
    "Brian", "Kelvin", "Aisha", "Sharon", "Faith", "Moses", "Brenda", "Linet", "Otieno", "Mutiso", "Njoroge",
    "John", "Mary", "Stephen", "Cynthia", "Collins", "Eunice", "Derrick", "Naomi", "Dorcas", "Kevin",
    "Daniel", "Victor", "Joy", "Mercy", "Ann", "Joseph", "Samuel", "Eliud", "Caroline", "Edith",
    "Ruth", "Joshua", "Beatrice", "Evelyn", "Esther", "Gladys", "Philip", "Peter", "Florence", "Diana",
    "Judith", "Titus", "Alice", "George", "Lucy", "Nancy", "Agnes", "Hannah", "Paul", "Christine",
    "Boniface", "Vincent", "Sylvia", "Salome", "Lydia", "Abigail", "Maureen", "Valentine", "Purity", "Tracy",
    "Irene", "Fridah", "Janet", "Joel", "Timothy", "Benard", "Alex", "Allan", "Raymond", "Nicholas",
    "Rodgers", "Eric", "Albert", "Benson", "Sarah", "Catherine", "Sheila", "Angela", "Tabitha",
    "Miriam", "Loice", "Winnie", "Margaret", "Hilda", "Collins", "Lawrence", "Jason", "Jared",
    "Victorine", "Anita", "Judah", "Deborah", "Sospeter", "Humphrey", "Harrison", "Terry", "Brianne",
    "Sharleen", "Blessing", "Immaculate", "Martin", "Raphael", "Silas", "Kimani", "Kioni", "Gideon",
    "Abdi", "Abdirahman", "Ali", "Farhiya", "Halima", "Said", "Jamal", "Yasmin", "Fatuma", "Fartun",
    "Hussein", "Ismael", "Omar", "Amin", "Fahim", "Nasra", "Ayaan", "Rashid", "Abdullahi", "Saeed",
    "Laban", "Zablon", "Meshack", "Shadrack", "Job", "Nehemiah", "Jeremiah", "Cornelius",
    "Oscar", "Rodney", "Kelvin", "Fred", "Josphine", "Gloria", "Jane", "Jemimah", "Talia",
    "Brian", "Chris", "Mike", "Susan", "Joyce", "Queen", "Shiko", "Shiku", "Wairimu",
    "Njoki", "Ciku", "Muthoni", "Nyambura", "Wambui", "Kendi", "Makena", "Nkatha", "Mwende",
    "Syokau", "Ndinda", "Kaluki", "Koki", "Mumo", "Muli", "Mutheu", "Mwikali", "Kanini",
    "Chebet", "Cherono", "Chepkorir", "Jepchirchir", "Jepkoech", "Chepchumba", "Chepkoech", "Kiprotich",
    "Kiplagat", "Kipkoech", "Kipkorir", "Kipkemboi", "Kipchirchir", "Kipchumba", "Jepkemoi",
    "Achieng", "Atieno", "Akinyi", "Owino", "Ochieng", "Odhiambo", "Okello", "Were", "Owuor",
    "Baraka", "Juma", "Hassan", "Salim", "Ramadhan", "Bakari", "Mwanaisha", "Zawadi", "Sidi",
    "Hawa", "Mariamu", "Kasim", "Hamisi", "Bwana", "Chiper", "Teresia", "Lameck", "Yvonne",
    "Emily", "Keziah", "Doreen", "Florence", "Violet", "Juliet", "Lilian", "Norah",
    "Linus", "Norbert", "Crispin", "Ian", "Denis", "Mark", "Anthony", "Jasper",
    "Arnold", "Alfred", "Brayo", "Favian", "Gift", "Hope", "Justus", "Nyawira",
    "Kagwiria", "Mutuma", "Muriuki", "Kirimi", "Mugambi", "Nkatha", "Mwiti", "Mureithi",
]


KENYAN_LAST_NAMES = [
    "Mwangi", "Omondi", "Wanjiku", "Mutua", "Kamau", "Kiptoo", "Odhiambo", "Chebet", "Cheruiyot",
    "Oduor", "Onyango", "Were", "Wekesa", "Barasa", "Makori", "Nyabuto", "Otieno",
    "Juma", "Kassim", "Abdullahi", "Abdi", "Mohamed", "Ali", "Hassan", "Ismail", "Omar",
    "Mutisya", "Mueni", "Wambua", "Kyalo", "Mwendwa", "Kioko", "Musyoka",
    "Koech", "Kiprop", "Kiplagat", "Kiprotich", "Kibet", "Chepkwony", "Kipkemboi",
    "Cherono", "Chelangat", "Kipkorir", "Kipchumba", "Kipchirchir",
    "Wamuyu", "Njeri", "Wangeci", "Muthoni", "Kariuki", "Kagiri", "Murage",
    "Muriuki", "Gichuru", "Njuguna", "Waweru", "Karanja", "Wairimu",
    "Muthee", "Karimi", "Mugambi", "Muroki", "Kaberia", "Kinoti",
    "Mulei", "Ngang'a", "Nekesa", "Shikuku", "Mukasa", "Lusenaka",
    "Wakhungu", "Musimbi", "Wekulo", "Lutomia", "Wanyama", "Muyoka",
    "Kiplangat", "Kimutai", "Langat", "Rono", "Too", "Kemei", "Kigen",
    "Achieng", "Owino", "Ochieng", "Ouma", "Odongo", "Orengo",
    "Okoth", "Owuor", "Olando", "Ayieko", "Agolla", "Omollo", "Obiero",
    "Simiyu", "Situma", "Masinde", "Muliro", "Khaemba", "Makokha", "Wabwire",
    "Marete", "Thuranira", "Kiraithe", "Karimi", "Rimberia",
    "Mworia", "Kinyua", "Muthomi", "Njuki", "Riungu",
    "Ole Kantai", "Ole Kisar", "Ole Ntutu", "Sankale", "Naisula",
    "Mpapale", "Ekalale", "Lonyangapuo", "Napeyok", "Ewoi", "Ngasike",
    "Dida", "Jirmale", "Guyota", "Wario", "Guyo",
    "Bulemi", "Ngila", "Musimbi", "Munyao", "Ndambuki",
    "Mutuku", "Mumo", "Muthengi", "Mbatha", "Nzomo",
    "Khalwale", "Mudavadi", "Mabonga", "Wanjala", "Wafula",
    "Okongo", "Nyamweya", "Onsongo", "Nyakundi", "Ogeto",
    "Makena", "Kuria", "Muriithi", "Kang'ethe", "Ichungwah",
    "Mutai", "Chesire", "Sigei", "Cherop", "Choge",
    "Nguu", "Mutambo", "Mbogo", "Gathecha", "Muchiri",
    "Kabubo", "Kamotho", "Gathura", "Gachanja", "Kiarie",
]


KENYAN_COUNTIES = [
    "Nairobi", "Mombasa", "Kiambu", "Nakuru", "Kisumu", "Uasin Gishu",
    "Machakos", "Kakamega", "Meru", "Bungoma", "Kajiado"
]

RELATIONSHIPS = [
    "Father", "Mother", "Sibling", "Spouse", "Guardian", "Relative"
]

BLOOD_GROUPS = ['A+', 'A-', 'B+', 'B-', 'AB+', 'O+', 'O-', 'AB-']

NHIF_STATUSES = ['NONE', 'ACTIVE', 'INACTIVE', 'CIVIL_SERVANT']

VISIT_TYPES = ['OUTPATIENT', 'EMERGENCY', 'INPATIENT']

EMERGENCY_LEVELS = ['CRITICAL', 'EMERGENCY', 'URGENT', 'NORMAL']


class Command(BaseCommand):
    help = "Seeds Kenyan Patients, Visits, and Triage Data"

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=300,
            help='Number of patients to generate'
        )

    def handle(self, *args, **options):
        count = options['count']

        # Pick a user to assign as registered_by
        staff_users = User.objects.all()
        if not staff_users.exists():
            self.stdout.write(self.style.ERROR("❌ No staff users found! Create at least 1 user."))
            return

        nurse_users = User.objects.filter(role__name="NURSE")
        if not nurse_users.exists():
            self.stdout.write(self.style.ERROR("❌ No nurse found! Assign a user the NURSE role."))
            return

        self.stdout.write(self.style.WARNING("📌 Seeding Kenyan patient data..."))

        for i in range(count):

            first = random.choice(KENYAN_FIRST_NAMES)
            last = random.choice(KENYAN_LAST_NAMES)
            middle = random.choice(["", "W.", "O.", "K."])

            age_years = random.randint(1, 90)
            dob = date.today() - timedelta(days=age_years * 365)

            phone = f"07{random.randint(10,99)}{random.randint(100000, 999999)}"

            patient = Patient.objects.create(
                first_name=first,
                middle_name=middle,
                last_name=last,
                date_of_birth=dob,
                gender=random.choice(["MALE", "FEMALE"]),

                id_number=str(random.randint(10000000, 45000000)),
                phone_number=phone,

                county=random.choice(KENYAN_COUNTIES),
                sub_county="Central",
                ward="Ward " + str(random.randint(1, 10)),
                village="Village " + str(random.randint(1, 20)),

                next_of_kin_name=random.choice(KENYAN_FIRST_NAMES) + " " + random.choice(KENYAN_LAST_NAMES),
                next_of_kin_relationship=random.choice(RELATIONSHIPS),
                next_of_kin_phone=f"07{random.randint(10,99)}{random.randint(100000, 999999)}",

                blood_group=random.choice(BLOOD_GROUPS),
                allergies="None",
                chronic_conditions="None",

                nhif_status=random.choice(NHIF_STATUSES),
                nhif_number=str(random.randint(5000000, 8000000)) if random.random() > 0.4 else "",

                registered_by=random.choice(staff_users),
            )

            # Create Visit
            visit = PatientVisit.objects.create(
                patient=patient,
                visit_type=random.choice(VISIT_TYPES),
                chief_complaint=random.choice([
                    "Headache", "Chest Pain", "Malaria Symptoms",
                    "Injury", "Back Pain", "Cough and Fever"
                ]),
                priority_level=random.randint(1, 5)
            )

            # Create Triage Assessment
            TriageAssessment.objects.create(
                visit=visit,
                nurse=random.choice(nurse_users),

                temperature=round(random.uniform(36.0, 39.5), 1),
                pulse=random.randint(60, 120),
                systolic_bp=random.randint(100, 150),
                diastolic_bp=random.randint(60, 100),
                respiratory_rate=random.randint(12, 28),
                oxygen_saturation=random.randint(90, 100),

                weight=round(random.uniform(40, 95), 1),
                height=round(random.uniform(140, 190), 1),

                chief_complaint=visit.chief_complaint,
                pain_scale=random.randint(0, 10),
                emergency_level=random.choice(EMERGENCY_LEVELS),

                triage_notes="Patient stable. Monitoring advised."
            )

        self.stdout.write(self.style.SUCCESS(f"🎉 Successfully seeded {count} Kenyan patients!"))
