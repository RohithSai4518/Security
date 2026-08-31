from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import UploadedFile, FileShare

DANGEROUS_EXTENSIONS = {
    'exe', 'bat', 'cmd', 'sh', 'php', 'phtml', 'asp', 'aspx', 'jsp',
    'vbs', 'ps1', 'cgi', 'pl', 'py', 'jar', 'msi', 'scr'
}

MAX_FILE_SIZE_MB = 25

class UserRegisterForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter strong password'}),
        min_length=8,
        help_text="Minimum 8 characters."
    )
    confirm_password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Confirm password'}),
        min_length=8
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Choose username'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'name@example.com'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'First name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Last name'}),
        }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError("A user with that username already exists.")
        return username

    def clean(self):
        cleaned_data = super().clean()
        pwd = cleaned_data.get('password')
        cpwd = cleaned_data.get('confirm_password')

        if pwd and cpwd and pwd != cpwd:
            self.add_error('confirm_password', "Passwords do not match.")
        return cleaned_data

class FileUploadForm(forms.ModelForm):
    description = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Optional description / notes about this file'}),
        required=False
    )
    file = forms.FileField(
        widget=forms.FileInput(attrs={'class': 'form-control'})
    )

    class Meta:
        model = UploadedFile
        fields = ['file', 'description']

    def clean_file(self):
        uploaded = self.cleaned_data.get('file')
        if not uploaded:
            raise ValidationError("No file selected.")

        # File size check
        if uploaded.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            raise ValidationError(f"File size exceeds maximum allowed limit of {MAX_FILE_SIZE_MB}MB.")

        # Dangerous extension check
        ext = uploaded.name.split('.')[-1].lower() if '.' in uploaded.name else ''
        if ext in DANGEROUS_EXTENSIONS:
            raise ValidationError(f"File type '.{ext}' is restricted for security reasons.")

        return uploaded

class FileShareForm(forms.Form):
    recipient_username = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter recipient username'}),
        help_text="Must be a registered SecureShare user."
    )
    permission = forms.ChoiceField(
        choices=FileShare.PERMISSION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        initial='DOWNLOAD'
    )

    def __init__(self, *args, owner=None, **kwargs):
        self.owner = owner
        super().__init__(*args, **kwargs)

    def clean_recipient_username(self):
        username = self.cleaned_data.get('recipient_username', '').strip()
        if not User.objects.filter(username=username).exists():
            raise ValidationError(f"User '{username}' does not exist.")
        
        target_user = User.objects.get(username=username)
        if self.owner and target_user == self.owner:
            raise ValidationError("You cannot share a file with yourself.")

        return username
