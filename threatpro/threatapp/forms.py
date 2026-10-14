from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm

from .models import CustomUser, Enquiry, IncidentReport, ThreatDetection, ThreatLog


class CustomAuthenticationForm(AuthenticationForm):
    """Custom authentication form with proper Bootstrap classes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update(
                {
                    "class": "form-control",
                    "autocomplete": "off",
                }
            )
        self.fields["username"].widget.attrs.update(
            {
                "placeholder": "Enter username",
                "autofocus": True,
            }
        )
        self.fields["password"].widget.attrs.update(
            {
                "placeholder": "Enter password",
            }
        )


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ["username", "email", "phone", "password1", "password2"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs.update(
                {
                    "class": "form-control",
                    "autocomplete": "off",
                }
            )
        self.fields["username"].widget.attrs.update(
            {
                "placeholder": "Enter username",
                "autofocus": True,
            }
        )
        self.fields["email"].widget.attrs.update(
            {
                "placeholder": "Enter email address",
            }
        )
        self.fields["phone"].widget.attrs.update(
            {
                "placeholder": "Enter phone number (optional)",
            }
        )
        self.fields["password1"].widget.attrs.update(
            {
                "placeholder": "Enter password",
            }
        )
        self.fields["password2"].widget.attrs.update(
            {
                "placeholder": "Confirm password",
            }
        )


class LogUploadForm(forms.ModelForm):
    class Meta:
        model = ThreatLog
        fields = ["log_file"]
        widgets = {
            "log_file": forms.FileInput(
                attrs={
                    "class": "form-control",
                    "accept": ".log,.txt,.csv",
                }
            ),
        }


class IncidentReportForm(forms.ModelForm):
    class Meta:
        model = IncidentReport
        fields = ["title", "description", "status"]
        widgets = {
            "title": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Enter incident title",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 4,
                    "placeholder": "Describe the incident in detail",
                }
            ),
            "status": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }


class ThreatDetectionForm(forms.ModelForm):
    class Meta:
        model = ThreatDetection
        fields = ["log", "threat_type", "severity"]
        widgets = {
            "log": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
            "threat_type": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "e.g., SQL Injection, Brute Force, XSS",
                }
            ),
            "severity": forms.Select(
                attrs={
                    "class": "form-select",
                }
            ),
        }


class ReputationCheckForm(forms.Form):
    query = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter IP or Domain",
            }
        ),
    )


class EnquiryForm(forms.ModelForm):
    class Meta:
        model = Enquiry
        fields = "__all__"
        widgets = {
            "name": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Your Name",
                }
            ),
            "email": forms.EmailInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Email Address",
                }
            ),
            "phone": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "Phone Number (optional)",
                }
            ),
            "message": forms.Textarea(
                attrs={
                    "class": "form-control",
                    "rows": 4,
                    "placeholder": "Your message",
                }
            ),
        }
