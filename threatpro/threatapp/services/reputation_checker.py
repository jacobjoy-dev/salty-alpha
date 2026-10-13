import ipaddress

import requests
from django.conf import settings


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
