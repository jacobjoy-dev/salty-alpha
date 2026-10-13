import csv
import io

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from ..forms import ThreatDetectionForm
from ..models import ThreatDetection, ThreatLog


@login_required
def threat_list(request):
    threats = ThreatDetection.objects.all()
    return render(request, "threats/threat_list.html", {"threats": threats})


@login_required
def add_threat(request):
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("threat_list")
    else:
        form = ThreatDetectionForm()
    return render(request, "threats/add_threat.html", {"form": form})


@login_required
def update_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST, instance=threat)
        if form.is_valid():
            form.save()
            return redirect("threat_list")
    else:
        form = ThreatDetectionForm(instance=threat)
    return render(request, "threats/update_threat.html", {"form": form})


@login_required
def delete_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        threat.delete()
        return redirect("threat_list")
    return render(request, "threats/delete_threat.html", {"threat": threat})


@login_required
def log_details(request):
    logs = ThreatLog.objects.all().order_by("-uploaded_at")
    threat_detections = ThreatDetection.objects.select_related("log").all()
    log_data = []
    threat_data = []
    if logs.exists():
        latest_log = logs.first()
        try:
            with latest_log.log_file.open(mode="r") as file:
                file_content = file.read()
                if isinstance(file_content, bytes):
                    file_content = file_content.decode("utf-8")
                reader = csv.reader(io.StringIO(file_content))
                next(reader)  # skip header
                for row in reader:
                    if len(row) != 6:
                        continue
                    ip, timestamp, method, url, status, response_size = row
                    log_data.append(
                        {
                            "ip": ip,
                            "timestamp": timestamp,
                            "method": method,
                            "url": url,
                            "status": status,
                        }
                    )
        except Exception:
            pass
    if threat_detections.exists():
        for threat in threat_detections:
            threat_data.append(
                {"threat_type": threat.threat_type, "severity": threat.severity, "detected_at": threat.detected_at}
            )
    return render(request, "threats/detailed_log_analysis.html", {"log_data": log_data, "threat_data": threat_data})
