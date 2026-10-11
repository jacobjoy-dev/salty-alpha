import re
import csv
import io
import base64
import ipaddress
import requests
from collections import defaultdict

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.db.models import Count
from django.conf import settings

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from .models import ThreatLog, ThreatDetection, IPReputation, IncidentReport, Enquiry
from .forms import RegisterForm, IncidentReportForm, EnquiryForm, LogUploadForm, ReputationCheckForm, ThreatDetectionForm


CustomUser = get_user_model()

THREAT_PATTERNS = {
    "SQL Injection": (r"(UNION\s+SELECT|SELECT\s+\*.*FROM|INSERT\s+INTO|DROP\s+TABLE)", "High"),
    "XSS Attack": (r"(<script>|javascript:|onerror=)", "High"),
    "Unauthorized Access": (r"(401|403)", "High"),
    "Brute Force Attempt": (r"(failed login|password incorrect)", "Medium"),
    "Directory Traversal": (r"(\.\./|\.\.\\|/etc/passwd|C:\\windows\\)", "Medium"),
    "Web Scraping": (r"(Scrapy|Python-urllib|wget|curl)", "Low"),
    "404 Probing": (r"(404)", "Low"),
    "Buffer Overflow": (r"([A-Za-z0-9]{1000,})", "High"),
    "Command Injection": (r"(\b(wget|curl|rm\s+-rf|chmod\s+\+x)\b)", "High"),
    "Malicious User Agent": (r"(sqlmap|nmap|nikto|metasploit)", "High"),
    "Port Scanning": (r"(SYN_SCAN|NMAP_SCAN)", "Medium"),
    "DDoS Attack": (r"(\b(?:\d{1,3}\.){3}\d{1,3}\b).*?(GET|POST).*?\1", "High"),
    "Malicious File Upload": (r"(upload.*?\.(exe|php|jsp|aspx|sh|bat))", "High"),
}


def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("login")
    else:
        form = RegisterForm()
    return render(request, "accounts/register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                if user.is_superuser:
                    return redirect("admin_dashboard")
                return redirect("check_reputation")
            else:
                messages.error(request, "Invalid username or password")
        else:
            messages.error(request, "Invalid username or password")
    form = AuthenticationForm()
    return render(request, "accounts/login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("index")


def index(request):
    if request.method == 'POST':
        form = EnquiryForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your message has been sent. Thank you!")
            return redirect('index')
        else:
            messages.error(request, "Error in form submission. Please check your inputs.")
    else:
        form = EnquiryForm()
    return render(request, 'index.html', {'form': form})


def enquiry_list(request):
    enquiries = Enquiry.objects.all().order_by('-id')
    return render(request, 'admin_pages/enquiry_list.html', {'enquiries': enquiries})


@login_required
def dashboard(request):
    logs = ThreatLog.objects.filter(user=request.user)
    incidents = IncidentReport.objects.filter(user=request.user)
    threats = ThreatDetection.objects.filter(log__user=request.user)

    threat_counts = threats.values('severity').annotate(count=Count('id'))
    labels = [entry['severity'] for entry in threat_counts]
    values = [entry['count'] for entry in threat_counts]

    if labels and values:
        fig, ax = plt.subplots()
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90, colors=['green', 'yellow', 'red'])
        ax.axis('equal')
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png")
        buffer.seek(0)
        image_data = base64.b64encode(buffer.getvalue()).decode()
        buffer.close()
    else:
        image_data = None

    return render(request, 'threats/dashboard.html', {
        'logs': logs,
        'incidents': incidents,
        'threats': threats,
        'threat_chart': image_data
    })


def upload_log_file(request):
    if request.method == 'POST':
        form = LogUploadForm(request.POST, request.FILES)
        if form.is_valid():
            log_entry = form.save(commit=False)
            log_entry.user = request.user
            log_entry.save()
            analyze_logs(log_entry)
            return redirect('log_analysis_report')
    else:
        form = LogUploadForm()
    return render(request, 'threats/upload_log.html', {'form': form})


def analyze_logs(log_entry):
    file_path = log_entry.log_file.path
    detected_threats = []
    ip_tracker = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            ip_match = re.search(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)", line)
            ip_address = ip_match.group(0) if ip_match else None

            for threat, (pattern, severity) in THREAT_PATTERNS.items():
                if re.search(pattern, line, re.IGNORECASE):
                    detected_threats.append(
                        ThreatDetection(log=log_entry, ip_address=ip_address, threat_type=threat, severity=severity)
                    )
                    if threat == "DDoS Attack" and ip_address:
                        ip_tracker[ip_address] += 1
                        if ip_tracker[ip_address] > 10:
                            detected_threats.append(
                                ThreatDetection(log=log_entry, ip_address=ip_address, threat_type="DDoS Flooding", severity="High")
                            )

    ThreatDetection.objects.bulk_create(detected_threats)
    log_entry.analyzed = True
    log_entry.save()


def log_analysis_report(request):
    logs = ThreatLog.objects.prefetch_related('threats')
    return render(request, 'threats/log_report.html', {'logs': logs})


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


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def check_ip_reputation(ip):
    if not is_public_ip(ip):
        return None, "Private or invalid IP. Only public IPs can be checked."

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": settings.ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        data = response.json()

        if response.status_code == 200 and "data" in data:
            reputation_score = data["data"].get("abuseConfidenceScore", 0)
            blacklisted = reputation_score > 50
            message = "This IP is blacklisted or not safe." if blacklisted else "This IP is safe."
            return {
                "id": ip,
                "reputation_score": reputation_score,
                "blacklisted": blacklisted,
                "message": message,
            }, None
        else:
            return None, f"Error: {data.get('errors', 'Unknown error')}"
    except Exception as e:
        return None, str(e)


def check_domain_reputation(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()

        if response.status_code == 200 and "data" in data:
            attributes = data["data"].get("attributes", {})
            reputation_score = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            blacklisted = reputation_score > 0
            message = "This domain is blacklisted or not safe." if blacklisted else "This domain is safe."
            return {
                "id": domain,
                "reputation_score": reputation_score,
                "blacklisted": blacklisted,
                "message": message,
            }, None
        else:
            return None, f"Error: {data.get('error', 'Unknown error')}"
    except Exception as e:
        return None, str(e)


def check_reputation(request):
    rep_form = ReputationCheckForm()
    log_form = LogUploadForm()
    if request.method == "POST":
        if 'query' in request.POST:
            rep_form = ReputationCheckForm(request.POST)
            if rep_form.is_valid():
                query = rep_form.cleaned_data["query"]
                try:
                    ipaddress.ip_address(query)
                    is_ip = True
                except ValueError:
                    is_ip = False

                if is_ip:
                    result, error = check_ip_reputation(query)
                    template_name = "threats/ip_result.html"
                else:
                    result, error = check_domain_reputation(query)
                    template_name = "threats/domain_result.html"

                if result:
                    IPReputation.objects.update_or_create(
                        ip_address=query if is_ip else None,
                        domain=query if not is_ip else None,
                        defaults={
                            "reputation_score": result.get("reputation_score", 0),
                            "blacklisted": result.get("blacklisted", False),
                        },
                    )
                return render(request, template_name, {
                    "query": query, "result": result, "error": error, "is_ip": is_ip
                })
        elif 'log_file' in request.FILES:
            log_form = LogUploadForm(request.POST, request.FILES)
            if log_form.is_valid():
                log_entry = log_form.save(commit=False)
                log_entry.user = request.user
                log_entry.save()
                analyze_logs(log_entry)
                return redirect('log_analysis_report')
    return render(request, "threats/reputation_check.html", {
        "rep_form": rep_form, "log_form": log_form, "result": None, "error": None
    })


@login_required
def delete_analysis(request, id):
    log = get_object_or_404(ThreatLog, id=id, user=request.user)
    log.delete()
    messages.success(request, "Log analysis deleted successfully!")
    return redirect('log_analysis_report')


def detailed_log_analysis(request):
    logs = ThreatLog.objects.filter(user=request.user).order_by('-uploaded_at')
    log_data = []
    if logs.exists():
        latest_log = logs.first()
        with latest_log.log_file.open(mode='r') as file:
            file_content = file.read()
            if isinstance(file_content, bytes):
                file_content = file_content.decode('utf-8')
            reader = csv.reader(io.StringIO(file_content))
            try:
                next(reader)
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


def threat_list(request):
    threats = ThreatDetection.objects.all()
    return render(request, 'threats/threat_list.html', {'threats': threats})


def add_threat(request):
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('threat_list')
    else:
        form = ThreatDetectionForm()
    return render(request, 'threats/add_threat.html', {'form': form})


def update_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        form = ThreatDetectionForm(request.POST, instance=threat)
        if form.is_valid():
            form.save()
            return redirect('threat_list')
    else:
        form = ThreatDetectionForm(instance=threat)
    return render(request, 'threats/update_threat.html', {'form': form})


def delete_threat(request, threat_id):
    threat = get_object_or_404(ThreatDetection, id=threat_id)
    if request.method == "POST":
        threat.delete()
        return redirect('threat_list')
    return render(request, 'threats/delete_threat.html', {'threat': threat})


def log_details(request):
    logs = ThreatLog.objects.all().order_by('-uploaded_at')
    threat_detections = ThreatDetection.objects.select_related('log').all()
    log_data = []
    threat_data = []
    if logs.exists():
        latest_log = logs.first()
        with latest_log.log_file.open(mode='r') as file:
            file_content = file.read()
            if isinstance(file_content, bytes):
                file_content = file_content.decode('utf-8')
            reader = csv.reader(io.StringIO(file_content))
            next(reader)
            for row in reader:
                ip, timestamp, method, url, status, response_size = row
                log_data.append({
                    "ip": ip, "timestamp": timestamp, "method": method,
                    "url": url, "status": status,
                })
    if threat_detections.exists():
        for threat in threat_detections:
            threat_data.append({
                "threat_type": threat.threat_type,
                "severity": threat.severity,
                "detected_at": threat.detected_at
            })
    return render(request, 'threats/detailed_log_analysis.html', {
        "log_data": log_data, "threat_data": threat_data
    })


@login_required
def report_incident(request):
    if request.method == 'POST':
        form = IncidentReportForm(request.POST)
        if form.is_valid():
            incident = form.save(commit=False)
            incident.user = request.user
            incident.save()
            return redirect('dashboard')
    else:
        form = IncidentReportForm()
    return render(request, 'incidents/report_incident.html', {'form': form})


def admin_dashboard(request):
    return render(request, 'admin_pages/admin_dashboard.html')


def admin_view(request):
    total_threats = ThreatDetection.objects.count()
    high_severity = ThreatDetection.objects.filter(severity="High").count()
    medium_severity = ThreatDetection.objects.filter(severity="Medium").count()
    low_severity = ThreatDetection.objects.filter(severity="Low").count()
    threat_counts = ThreatDetection.objects.values('threat_type').annotate(count=Count('threat_type'))
    threat_labels = [item['threat_type'] for item in threat_counts]
    threat_values = [item['count'] for item in threat_counts]
    latest_threats = ThreatDetection.objects.order_by('-detected_at')[:10]
    return render(request, 'admin_pages/admin_view.html', {
        "total_threats": total_threats,
        "high_severity": high_severity,
        "medium_severity": medium_severity,
        "low_severity": low_severity,
        "threat_labels": threat_labels,
        "threat_values": threat_values,
        "latest_threats": latest_threats,
    })


def test(request):
    return render(request, 'test.html')


def reg(request):
    return render(request, 'reg.html')


@login_required
def user_list_view(request):
    users = CustomUser.objects.all()
    return render(request, "admin_pages/user_list.html", {"users": users})


@login_required
def delete_user(request, id):
    user = get_object_or_404(CustomUser, id=id)
    user.delete()
    messages.success(request, "User deleted successfully!")
    return redirect('user_list_view')