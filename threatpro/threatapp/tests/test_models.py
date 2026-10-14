import pytest

from threatapp.models import Enquiry, IncidentReport, IPReputation, ThreatDetection, ThreatLog


@pytest.mark.django_db
class TestThreatLog:
    def test_create_threat_log(self, user, sample_log_file):
        from django.core.files import File

        log = ThreatLog.objects.create(user=user)
        with open(sample_log_file, "rb") as f:
            log.log_file.save("test.log", File(f))
        assert log.user == user
        assert log.analyzed is False
        assert str(log).startswith("testuser")

    def test_threat_log_str(self, threat_log):
        assert "testuser" in str(threat_log)
        assert ".log" in str(threat_log)


@pytest.mark.django_db
class TestThreatDetection:
    def test_create_detection(self, threat_log):
        detection = ThreatDetection.objects.create(
            log=threat_log, ip_address="1.2.3.4", threat_type="SQL Injection", severity="High"
        )
        assert detection.threat_type == "SQL Injection"
        assert detection.severity == "High"
        assert detection.ip_address == "1.2.3.4"

    def test_detection_str(self, threat_log):
        detection = ThreatDetection.objects.create(log=threat_log, threat_type="XSS Attack", severity="Medium")
        assert "XSS Attack" in str(detection)
        assert "Medium" in str(detection)


@pytest.mark.django_db
class TestIncidentReport:
    def test_create_incident(self, user):
        inc = IncidentReport.objects.create(user=user, title="Test", description="Desc", status="Open")
        assert inc.user == user
        assert inc.status == "Open"

    def test_incident_str(self, user):
        inc = IncidentReport.objects.create(user=user, title="My Incident", description="Desc", status="Investigating")
        assert "My Incident" in str(inc)


@pytest.mark.django_db
class TestIPReputation:
    def test_create_ip_reputation(self):
        rep = IPReputation.objects.create(ip_address="8.8.8.8", reputation_score=75, blacklisted=True)
        assert rep.blacklisted is True

    def test_create_domain_reputation(self):
        rep = IPReputation.objects.create(domain="example.com", reputation_score=5, blacklisted=True)
        assert rep.blacklisted is True
        assert "example.com" in str(rep)


@pytest.mark.django_db
class TestEnquiry:
    def test_create_enquiry(self):
        eq = Enquiry.objects.create(name="John", email="j@j.com", message="Hi")
        assert eq.name == "John"

    def test_enquiry_str(self):
        eq = Enquiry.objects.create(name="Jane", email="jane@test.com")
        assert str(eq) == "Jane"
