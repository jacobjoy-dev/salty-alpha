from django.contrib import admin

from .models import CustomUser, Enquiry, IncidentReport, IPReputation, ThreatDetection, ThreatLog

admin.site.register(CustomUser)
admin.site.register(ThreatLog)
admin.site.register(ThreatDetection)
admin.site.register(IPReputation)
admin.site.register(IncidentReport)
admin.site.register(Enquiry)
