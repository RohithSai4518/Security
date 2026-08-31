import os
import mimetypes
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse, Http404, HttpResponseForbidden, FileResponse
from django.db.models import Sum

from .models import UploadedFile, FileShare, SecurityAuditLog
from .forms import UserRegisterForm, FileUploadForm, FileShareForm

def get_client_ip(request):
    """Extracts client IP address safely from request metadata."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip

def log_security_event(user, action, request, details):
    """Creates an audit log entry for security tracking."""
    ip = get_client_ip(request)
    SecurityAuditLog.objects.create(
        user=user if user and user.is_authenticated else None,
        action=action,
        ip_address=ip,
        details=details
    )

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.save()
            log_security_event(user, 'REGISTER', request, f"New user account registered: {user.username}")
            login(request, user)
            messages.success(request, f"Welcome to SecureShare, {user.username}! Your account is ready.")
            return redirect('dashboard')
    else:
        form = UserRegisterForm()

    return render(request, 'portal/register.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            log_security_event(user, 'LOGIN', request, f"User logged in successfully: {user.username}")
            messages.success(request, f"Welcome back, {user.username}!")
            return redirect(request.GET.get('next') or 'dashboard')
        else:
            username_attempt = request.POST.get('username', 'Unknown')
            log_security_event(None, 'ACCESS_DENIED', request, f"Failed login attempt for username: '{username_attempt}'")
            messages.error(request, "Invalid username or password.")
    else:
        form = AuthenticationForm()

    return render(request, 'portal/login.html', {'form': form})

def logout_view(request):
    if request.user.is_authenticated:
        username = request.user.username
        log_security_event(request.user, 'LOGOUT', request, f"User logged out: {username}")
        logout(request)
        messages.info(request, "You have been securely logged out.")
    return redirect('login')

@login_required
def dashboard_view(request):
    my_files = UploadedFile.objects.filter(owner=request.user)
    shared_with_me = FileShare.objects.filter(shared_with=request.user).select_related('file', 'shared_by')
    
    total_bytes = my_files.aggregate(Sum('file_size'))['file_size__sum'] or 0
    if total_bytes < 1024 * 1024:
        total_storage_formatted = f"{total_bytes / 1024:.1f} KB"
    else:
        total_storage_formatted = f"{total_bytes / (1024 * 1024):.2f} MB"

    recent_logs = SecurityAuditLog.objects.filter(user=request.user)[:5]

    context = {
        'my_files': my_files,
        'shared_with_me': shared_with_me,
        'total_files_count': my_files.count(),
        'total_shared_count': shared_with_me.count(),
        'total_storage_formatted': total_storage_formatted,
        'recent_logs': recent_logs,
    }
    return render(request, 'portal/dashboard.html', context)

@login_required
def upload_file_view(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = form.save(commit=False)
            uploaded.owner = request.user
            file_obj = request.FILES['file']
            uploaded.original_filename = file_obj.name
            uploaded.file_size = file_obj.size
            mime_type, _ = mimetypes.guess_type(file_obj.name)
            uploaded.mime_type = mime_type or 'application/octet-stream'
            uploaded.save()

            log_security_event(
                request.user, 
                'UPLOAD', 
                request, 
                f"Uploaded '{uploaded.original_filename}' ({uploaded.formatted_size})"
            )
            messages.success(request, f"File '{uploaded.original_filename}' uploaded successfully and secured.")
            return redirect('dashboard')
    else:
        form = FileUploadForm()

    return render(request, 'portal/upload.html', {'form': form})

@login_required
def download_file_view(request, file_id):
    """
    Strict Access Control: Only file owner, authorized share recipient, or Admin can download.
    Unauthorized attempts are blocked and logged.
    """
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)

    # Permission check
    is_owner = (uploaded_file.owner == request.user)
    is_admin = request.user.is_staff or request.user.is_superuser
    share_grant = FileShare.objects.filter(file=uploaded_file, shared_with=request.user).first()
    has_share_permission = (share_grant is not None and share_grant.permission == 'DOWNLOAD')

    if not (is_owner or is_admin or has_share_permission):
        # Security Alert: IDOR or unauthorized access attempt
        log_security_event(
            request.user,
            'ACCESS_DENIED',
            request,
            f"Blocked unauthorized download attempt for file '{uploaded_file.original_filename}' (ID: {file_id}) owned by {uploaded_file.owner.username}"
        )
        return render(request, 'portal/access_denied.html', {
            'file_name': uploaded_file.original_filename
        }, status=403)

    if not os.path.exists(uploaded_file.file.path):
        raise Http404("File not found on server disk.")

    log_security_event(
        request.user,
        'DOWNLOAD',
        request,
        f"Downloaded '{uploaded_file.original_filename}' (Owner: {uploaded_file.owner.username})"
    )

    response = FileResponse(open(uploaded_file.file.path, 'rb'), as_attachment=True, filename=uploaded_file.original_filename)
    return response

@login_required
def share_file_view(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)

    # Only owner or admin can share file
    if uploaded_file.owner != request.user and not (request.user.is_staff or request.user.is_superuser):
        log_security_event(
            request.user,
            'ACCESS_DENIED',
            request,
            f"Attempted to configure sharing on file '{uploaded_file.original_filename}' without ownership."
        )
        messages.error(request, "You do not have permission to manage sharing for this file.")
        return redirect('dashboard')

    existing_shares = FileShare.objects.filter(file=uploaded_file).select_related('shared_with')

    if request.method == 'POST':
        form = FileShareForm(request.POST, owner=uploaded_file.owner)
        if form.is_valid():
            recipient_username = form.cleaned_data['recipient_username']
            permission = form.cleaned_data['permission']
            recipient = User.objects.get(username=recipient_username)

            share, created = FileShare.objects.update_or_create(
                file=uploaded_file,
                shared_with=recipient,
                defaults={'shared_by': request.user, 'permission': permission}
            )

            action_text = "Shared" if created else "Updated share permission for"
            log_security_event(
                request.user,
                'SHARE',
                request,
                f"{action_text} '{uploaded_file.original_filename}' with user '{recipient.username}' [{permission}]"
            )
            messages.success(request, f"File shared with '{recipient.username}' ({permission} access).")
            return redirect('share_file', file_id=file_id)
    else:
        form = FileShareForm(owner=uploaded_file.owner)

    return render(request, 'portal/share.html', {
        'file': uploaded_file,
        'form': form,
        'existing_shares': existing_shares
    })

@login_required
def revoke_share_view(request, share_id):
    share = get_object_or_404(FileShare, id=share_id)
    
    if share.file.owner != request.user and not (request.user.is_staff or request.user.is_superuser):
        return HttpResponseForbidden("Not authorized to revoke this share.")

    file_id = share.file.id
    recipient_name = share.shared_with.username
    file_name = share.file.original_filename

    log_security_event(
        request.user,
        'REVOKE',
        request,
        f"Revoked access to '{file_name}' for user '{recipient_name}'"
    )
    share.delete()
    messages.info(request, f"Revoked access for user '{recipient_name}'.")
    return redirect('share_file', file_id=file_id)

@login_required
def delete_file_view(request, file_id):
    uploaded_file = get_object_or_404(UploadedFile, id=file_id)

    if uploaded_file.owner != request.user and not (request.user.is_staff or request.user.is_superuser):
        log_security_event(
            request.user,
            'ACCESS_DENIED',
            request,
            f"Blocked unauthorized attempt to delete file '{uploaded_file.original_filename}'"
        )
        return HttpResponseForbidden("Not authorized to delete this file.")

    if request.method == 'POST':
        filename = uploaded_file.original_filename
        log_security_event(
            request.user,
            'DELETE',
            request,
            f"Deleted file '{filename}' (ID: {file_id})"
        )
        uploaded_file.delete()
        messages.success(request, f"File '{filename}' was securely deleted.")
        return redirect('dashboard')

    return render(request, 'portal/delete_confirm.html', {'file': uploaded_file})

@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_dashboard_view(request):
    """Admin-only security monitoring dashboard."""
    users = User.objects.all().order_by('-date_joined')
    all_files = UploadedFile.objects.all().select_related('owner')
    audit_logs = SecurityAuditLog.objects.all().select_related('user')[:50]

    total_storage = all_files.aggregate(Sum('file_size'))['file_size__sum'] or 0
    if total_storage < 1024 * 1024:
        total_storage_formatted = f"{total_storage / 1024:.1f} KB"
    else:
        total_storage_formatted = f"{total_storage / (1024 * 1024):.2f} MB"

    alerts_count = SecurityAuditLog.objects.filter(action='ACCESS_DENIED').count()

    context = {
        'users_count': users.count(),
        'files_count': all_files.count(),
        'total_storage_formatted': total_storage_formatted,
        'alerts_count': alerts_count,
        'users': users,
        'all_files': all_files,
        'audit_logs': audit_logs,
    }
    return render(request, 'portal/admin_dashboard.html', context)
