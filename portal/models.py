import uuid
import os
from django.db import models
from django.contrib.auth.models import User

def secure_file_upload_path(instance, filename):
    """Generates a UUID-based filename to prevent directory traversal and path exposure."""
    ext = filename.split('.')[-1].lower() if '.' in filename else 'bin'
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    return os.path.join('uploads', str(instance.owner.id), unique_filename)

class UploadedFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_files')
    original_filename = models.CharField(max_length=255)
    file = models.FileField(upload_to=secure_file_upload_path)
    file_size = models.BigIntegerField(default=0)  # Size in bytes
    mime_type = models.CharField(max_length=100, default="application/octet-stream")
    description = models.TextField(blank=True, default="")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_filename} (Owner: {self.owner.username})"

    @property
    def formatted_size(self):
        bytes_val = self.file_size
        if bytes_val < 1024:
            return f"{bytes_val} B"
        elif bytes_val < 1024 * 1024:
            return f"{bytes_val / 1024:.1f} KB"
        else:
            return f"{bytes_val / (1024 * 1024):.2f} MB"

    def delete(self, *args, **kwargs):
        # Clean up physical file from media storage when model is deleted
        if self.file and os.path.isfile(self.file.path):
            try:
                os.remove(self.file.path)
            except OSError:
                pass
        super().delete(*args, **kwargs)

class FileShare(models.Model):
    PERMISSION_CHOICES = [
        ('VIEW', 'View Metadata'),
        ('DOWNLOAD', 'Download File'),
    ]

    file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, related_name='shares')
    shared_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='shares_granted')
    shared_with = models.ForeignKey(User, on_delete=models.CASCADE, related_name='files_shared_with_me')
    permission = models.CharField(max_length=20, choices=PERMISSION_CHOICES, default='DOWNLOAD')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('file', 'shared_with')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.file.original_filename} shared with {self.shared_with.username} ({self.permission})"

class SecurityAuditLog(models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'User Login'),
        ('LOGOUT', 'User Logout'),
        ('REGISTER', 'User Registration'),
        ('UPLOAD', 'File Upload'),
        ('DOWNLOAD', 'File Download'),
        ('SHARE', 'File Shared'),
        ('REVOKE', 'Share Revoked'),
        ('DELETE', 'File Deleted'),
        ('ACCESS_DENIED', 'Unauthorized Access Attempt (IDOR Blocked)'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_CHOICES)
    ip_address = models.CharField(max_length=45, default="127.0.0.1")
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {self.action} by {username}"
