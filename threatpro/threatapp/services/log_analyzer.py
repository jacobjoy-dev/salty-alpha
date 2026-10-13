import re
from collections import defaultdict

from threatapp.models import ThreatDetection

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
                        ThreatDetection(
                            log=log_entry,
                            ip_address=ip_address,
                            threat_type=threat,
                            severity=severity,
                        )
                    )
                    if threat == "DDoS Attack" and ip_address:
                        ip_tracker[ip_address] += 1
                        if ip_tracker[ip_address] > 10:
                            detected_threats.append(
                                ThreatDetection(
                                    log=log_entry,
                                    ip_address=ip_address,
                                    threat_type="DDoS Flooding",
                                    severity="High",
                                )
                            )

    ThreatDetection.objects.bulk_create(detected_threats)
    log_entry.analyzed = True
    log_entry.save()
