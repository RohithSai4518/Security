"""
Seeds demo user accounts and sample files for SecureShare.
"""

import os
import django
from django.core.files.base import ContentFile

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'secureshare.settings')
django.setup()

from django.contrib.auth.models import User
from portal.models import UploadedFile, FileShare, SecurityAuditLog

def seed():
    print("--- Seeding Demo Data for SecureShare ---")

    # 1. Create Admin User
    admin, created = User.objects.get_or_create(
        username='admin',
        defaults={
            'email': 'admin@secureshare.local',
            'is_staff': True,
            'is_superuser': True,
            'first_name': 'Security',
            'last_name': 'Admin'
        }
    )
    admin.set_password('AdminPassword@2026')
    admin.save()
    print("Created/Updated Superadmin: 'admin' (Password: AdminPassword@2026)")

    # 2. Create User Alice
    alice, created = User.objects.get_or_create(
        username='alice',
        defaults={
            'email': 'alice@secureshare.local',
            'first_name': 'Alice',
            'last_name': 'SecOps'
        }
    )
    alice.set_password('AlicePassword@2026')
    alice.save()
    print("Created/Updated User: 'alice' (Password: AlicePassword@2026)")

    # 3. Create User Bob
    bob, created = User.objects.get_or_create(
        username='bob',
        defaults={
            'email': 'bob@secureshare.local',
            'first_name': 'Bob',
            'last_name': 'Analyst'
        }
    )
    bob.set_password('BobPassword@2026')
    bob.save()
    print("Created/Updated User: 'bob' (Password: BobPassword@2026)")

    # 4. Upload Sample Secure Files for Alice
    file1_content = b"=== CONFIDENTIAL PROJECT BLUEPRINT ===\nClassification: Internal Restricted\nProject: Cyber Fortress 2026\nStatus: Active."
    file1, created = UploadedFile.objects.get_or_create(
        original_filename='Project_Cyber_Fortress_Blueprint.txt',
        owner=alice,
        defaults={
            'file_size': len(file1_content),
            'mime_type': 'text/plain',
            'description': 'Internal sensitive project blueprint and network topology design notes.'
        }
    )
    if created:
        file1.file.save('Project_Cyber_Fortress_Blueprint.txt', ContentFile(file1_content))
        file1.save()
        print("Created sample file 1: 'Project_Cyber_Fortress_Blueprint.txt' (Owner: alice)")

    file2_content = b"Q3 Financial Risk Assessment & Incident Mitigation Checklist\n1. Enforce MFA across all endpoints\n2. Review AWS S3 bucket ACLs\n3. Rotate API keys quarterly."
    file2, created = UploadedFile.objects.get_or_create(
        original_filename='Financial_Risk_Assessment_Q3.txt',
        owner=alice,
        defaults={
            'file_size': len(file2_content),
            'mime_type': 'text/plain',
            'description': 'Quarterly financial risk assessment and audit checklist.'
        }
    )
    if created:
        file2.file.save('Financial_Risk_Assessment_Q3.txt', ContentFile(file2_content))
        file2.save()
        print("Created sample file 2: 'Financial_Risk_Assessment_Q3.txt' (Owner: alice)")

    # 5. Share file2 with Bob (Download permission)
    share, created = FileShare.objects.get_or_create(
        file=file2,
        shared_with=bob,
        defaults={
            'shared_by': alice,
            'permission': 'DOWNLOAD'
        }
    )
    if created:
        print("Shared 'Financial_Risk_Assessment_Q3.txt' with bob [Permission: DOWNLOAD]")

    # 6. Seed Sample Audit Logs
    SecurityAuditLog.objects.get_or_create(
        action='REGISTER',
        user=alice,
        details='New user account registered: alice',
        ip_address='127.0.0.1'
    )
    SecurityAuditLog.objects.get_or_create(
        action='UPLOAD',
        user=alice,
        details="Uploaded 'Project_Cyber_Fortress_Blueprint.txt' (0.1 KB)",
        ip_address='127.0.0.1'
    )
    SecurityAuditLog.objects.get_or_create(
        action='SHARE',
        user=alice,
        details="Shared 'Financial_Risk_Assessment_Q3.txt' with user 'bob' [DOWNLOAD]",
        ip_address='127.0.0.1'
    )
    SecurityAuditLog.objects.get_or_create(
        action='ACCESS_DENIED',
        user=bob,
        details="Blocked unauthorized download attempt for file 'Project_Cyber_Fortress_Blueprint.txt' owned by alice",
        ip_address='127.0.0.1'
    )

    print("--- Seeding Completed Successfully! ---")

if __name__ == '__main__':
    seed()
