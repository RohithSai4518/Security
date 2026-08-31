from django.contrib import admin
from .models import UploadedFile, FileShare, SecurityAuditLog

@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'owner', 'file_size', 'mime_type', 'uploaded_at')
    list_filter = ('uploaded_at', 'mime_type')
    search_fields = ('original_filename', 'owner__username', 'description')

@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    list_display = ('file', 'shared_by', 'shared_with', 'permission', 'created_at')
    list_filter = ('permission', 'created_at')
    search_fields = ('file__original_filename', 'shared_with__username')

@admin.register(SecurityAuditLog)
class SecurityAuditLogAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'action', 'user', 'ip_address', 'details')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__username', 'ip_address', 'details')
    readonly_fields = ('timestamp', 'action', 'user', 'ip_address', 'details')
