import csv
import io

import matplotlib
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render

matplotlib.use('Agg')

from ..forms import LogUploadForm
from ..models import IncidentReport, ThreatDetection, ThreatLog
from ..services.chart_generator import generate_severity_chart

# Re-export for backward compatibility
from ..services.log_analyzer import analyze_logs as svc_analyze_logs

analyze_logs = svc_analyze_logs


@login_required
def dashboard(request):
    logs = ThreatLog.objects.filter(user=request.user)
    incidents = IncidentReport.objects.filter(user=request.user)
    threats = ThreatDetection.objects.filter(log__user=request.user)

    threat_counts = threats.values('severity').annotate(count=Count('id'))
    labels = [entry['severity'] for entry in threat_counts]
    values = [entry['count'] for entry in threat_counts]

    threat_chart = generate_severity_chart(labels, values) if labels and values else None

    return render(request, 'threats/dashboard.html', {
        'logs': logs,
        'incidents': incidents,
        'threats': threats,
        'threat_chart': threat_chart
    })


@login_required
def upload_log_file(request):
    if request.method == 'POST':
        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            log_entry = form.save(commit=False)
            log_entry.user = request.user
            log_entry.save()
            svc_analyze_logs(log_entry)
            return redirect('log_analysis_report')
    else:
        form = LogUploadForm()
    return render(request, 'threats/upload_log.html', {'form': form})


@login_required
def log_analysis_report(request):
    logs = ThreatLog.objects.prefetch_related('threats')
    return render(request, 'threats/log_report.html', {'logs': logs})


@login_required
def threat_frequency_chart(request, log_id):
    log = get_object_or_404(ThreatLog, id=log_id)
    threat_counts = (
        log.threats.values('threat_type')
        .annotate(count=Count('threat_type'))
        .order_by('-count')
    )
    labels = [threat["threat_type"] for threat in threat_counts]
    counts = [threat["count"] for threat in threat_counts]
    return render(request, "threats/threat_chart.html", {
        "log_name": log.log_file.name.split('/')[-1],
        "labels": labels,
        "counts": counts
    })


@login_required
def detailed_log_analysis(request):
    logs = ThreatLog.objects.filter(user=request.user).order_by('-uploaded_at')
    log_data = []
    if logs.exists():
        latest_log = logs.first()
        try:
            with latest_log.log_file.open(mode='r') as file:
                file_content = file.read()
                if isinstance(file_content, bytes):
                    file_content = file_content.decode('utf-8')
                reader = csv.reader(io.StringIO(file_content))
                next(reader)  # skip header
                for row in reader:
                    if len(row) != 6:
                        continue
                    ip, timestamp, method, url, status, response_size = row
                    threat_level = "✅ Normal"
                    if status == "401":
                        threat_level = "⚠️ Possible Brute Force"
                    elif status == "403":
                        threat_level = "⚠️ Unauthorized Admin Access"
                    elif status == "404":
                        threat_level = "⚠️ Scanner/Bot Activity"
                    elif status == "200" and url == "/login":
                        threat_level = "✅ Successful Login"
                    log_data.append({
                        "ip": ip, "timestamp": timestamp, "method": method,
                        "url": url, "status": status, "threat_level": threat_level
                    })
        except Exception:
            pass
    return render(request, 'threats/detailed_log.html', {"log_data": log_data})
