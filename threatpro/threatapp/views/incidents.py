from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from ..forms import IncidentReportForm


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
