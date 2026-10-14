from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render

from ..models import Enquiry, ThreatDetection

CustomUser = get_user_model()


def admin_required(view_func):
    """Decorator that requires the user to be a logged-in superuser."""
    decorated = login_required(user_passes_test(lambda u: u.is_superuser, login_url="login")(view_func))
    return decorated


@admin_required
def admin_dashboard(request):
    return render(request, "admin_pages/admin_dashboard.html")


@admin_required
def admin_view(request):
    total_threats = ThreatDetection.objects.count()
    high_severity = ThreatDetection.objects.filter(severity="High").count()
    medium_severity = ThreatDetection.objects.filter(severity="Medium").count()
    low_severity = ThreatDetection.objects.filter(severity="Low").count()
    threat_counts = ThreatDetection.objects.values("threat_type").annotate(count=Count("threat_type"))
    threat_labels = [item["threat_type"] for item in threat_counts]
    threat_values = [item["count"] for item in threat_counts]
    latest_threats = ThreatDetection.objects.order_by("-detected_at")[:10]
    return render(
        request,
        "admin_pages/admin_view.html",
        {
            "total_threats": total_threats,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
            "threat_labels": threat_labels,
            "threat_values": threat_values,
            "latest_threats": latest_threats,
        },
    )


@admin_required
def user_list_view(request):
    users = CustomUser.objects.all()
    return render(request, "admin_pages/user_list.html", {"users": users})


@admin_required
def delete_user(request, id):
    user = get_object_or_404(CustomUser, id=id)
    user.delete()
    messages.success(request, "User deleted successfully!")
    return redirect("user_list_view")


@admin_required
def enquiry_list(request):
    enquiries = Enquiry.objects.all().order_by("-id")
    return render(request, "admin_pages/enquiry_list.html", {"enquiries": enquiries})
