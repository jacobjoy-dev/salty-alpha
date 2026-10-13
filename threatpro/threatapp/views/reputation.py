import ipaddress

from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from ..forms import LogUploadForm, ReputationCheckForm
from ..models import IPReputation
from ..services.log_analyzer import analyze_logs
from ..services.reputation_checker import (
    check_domain_reputation as svc_check_domain_reputation,
)
from ..services.reputation_checker import (
    check_ip_reputation as svc_check_ip_reputation,
)
from ..services.reputation_checker import (
    is_public_ip as svc_is_public_ip,
)

# Re-export for backward compatibility
is_public_ip = svc_is_public_ip
check_ip_reputation = svc_check_ip_reputation
check_domain_reputation = svc_check_domain_reputation


@login_required
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
