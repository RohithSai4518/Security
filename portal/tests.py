import os
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from .models import UploadedFile, FileShare, SecurityAuditLog

class SecureShareSecurityTests(TestCase):

    def setUp(self):
        self.client = Client()
        self.alice = User.objects.create_user(username='alice', password='AlicePassword@2026')
        self.bob = User.objects.create_user(username='bob', password='BobPassword@2026')
        self.admin = User.objects.create_superuser(username='admin', password='AdminPassword@2026')

        # Alice uploads a private file
        test_file = SimpleUploadedFile("confidential.txt", b"Secret payload 12345", content_type="text/plain")
        self.alice_file = UploadedFile.objects.create(
            owner=self.alice,
            original_filename="confidential.txt",
            file=test_file,
            file_size=20,
            mime_type="text/plain"
        )

    def test_unauthenticated_user_redirected(self):
        """Unauthenticated user cannot access dashboard or download files."""
        res = self.client.get(reverse('dashboard'))
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.url.startswith('/login'))

    def test_owner_can_download_file(self):
        """File owner can successfully download their own file."""
        self.client.login(username='alice', password='AlicePassword@2026')
        res = self.client.get(reverse('download_file', kwargs={'file_id': self.alice_file.id}))
        self.assertEqual(res.status_code, 200)

    def test_unauthorized_user_blocked_and_logged(self):
        """Anti-IDOR: Bob cannot download Alice's private file. 403 Forbidden is returned."""
        self.client.login(username='bob', password='BobPassword@2026')
        res = self.client.get(reverse('download_file', kwargs={'file_id': self.alice_file.id}))
        self.assertEqual(res.status_code, 403)
        
        # Verify access denied audit log was written
        denied_log = SecurityAuditLog.objects.filter(action='ACCESS_DENIED', user=self.bob).first()
        self.assertIsNotNone(denied_log)
        self.assertIn("confidential.txt", denied_log.details)

    def test_file_sharing_grants_access(self):
        """Once Alice shares file with Bob, Bob can download it."""
        FileShare.objects.create(
            file=self.alice_file,
            shared_by=self.alice,
            shared_with=self.bob,
            permission='DOWNLOAD'
        )

        self.client.login(username='bob', password='BobPassword@2026')
        res = self.client.get(reverse('download_file', kwargs={'file_id': self.alice_file.id}))
        self.assertEqual(res.status_code, 200)

    def test_dangerous_extension_rejected(self):
        """Dangerous extensions like .exe, .sh, .bat must be rejected."""
        self.client.login(username='alice', password='AlicePassword@2026')
        malicious_file = SimpleUploadedFile("malware.exe", b"MZ fake binary", content_type="application/octet-stream")
        res = self.client.post(reverse('upload_file'), {'file': malicious_file, 'description': 'bad file'})
        # Should not redirect, stay on page with form errors
        self.assertEqual(res.status_code, 200)
        self.assertFalse(UploadedFile.objects.filter(original_filename='malware.exe').exists())

    def test_admin_portal_access(self):
        """Regular users cannot access admin dashboard; Superadmin can."""
        self.client.login(username='alice', password='AlicePassword@2026')
        res = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(res.status_code, 302)  # Redirects unauthorized user

        self.client.login(username='admin', password='AdminPassword@2026')
        res = self.client.get(reverse('admin_dashboard'))
        self.assertEqual(res.status_code, 200)
