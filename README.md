# Threat Hunting Toolkit

A web-based threat hunting platform built with **Django**. It lets security analysts upload server log files, automatically detects common attack patterns, checks IP addresses and domains against threat intelligence services, and presents the results in reports and charts.

Developed as a final-year project at **Yenepoya University**.

## Features

- **Log analysis:** upload a log file (for example Apache access logs) and have it scanned line by line for suspicious activity
- **Pattern-based threat detection** with severity levels (Low, Medium, High) for:
  - SQL injection and XSS attacks
  - Directory traversal and command injection
  - Brute force attempts and unauthorized access (401/403)
  - Malicious user agents (sqlmap, nmap, nikto, metasploit)
  - Port scanning, DDoS flooding and web scraping
  - Malicious file uploads and buffer overflow attempts
- **Reputation checker:** look up an IP address with AbuseIPDB or a domain with VirusTotal
- **Reports and charts:** threat frequency charts and detailed log analysis reports
- **Threat management:** add, update and delete detected threats
- **Incident reporting:** log incidents and track them as Open, Investigating or Resolved
- **Role-based access:** separate views for users and administrators, including user management and an enquiry list
- **User accounts:** registration, login and logout

## Tech Stack

- **Backend:** Python 3.12, Django 5.1
- **Database:** SQLite
- **Charts:** Matplotlib
- **Frontend:** HTML, CSS, JavaScript (Django templates)
- **Threat intelligence:** AbuseIPDB API, VirusTotal API

## Project Structure

```
salty-alpha/
├── DOCUMENTS/              # Project synopsis and final report
└── env/threatpro/          # Django project
    ├── manage.py
    ├── threatpro/          # Project settings and root URLs
    ├── threatapp/          # Models, views, forms, app URLs
    ├── templates/          # HTML templates
    ├── static/             # CSS, JS and images
    └── media/logs/         # Uploaded log files
```

## Getting Started

### Prerequisites

- Python 3.12 or later
- pip
- Free API keys from [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/)

### Installation

```bash
git clone https://github.com/jacobjoy-dev/salty-alpha.git
cd salty-alpha/env/threatpro

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install django matplotlib requests pillow numpy
```

### Configure API keys

Open `threatpro/settings.py` and set your own keys:

```python
ABUSEIPDB_API_KEY = "your-abuseipdb-key"
VIRUSTOTAL_API_KEY = "your-virustotal-key"
```

### Set up the database and run

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/` in your browser. The Django admin is available at `/admin/`.

## How to Use

1. Register an account and log in.
2. Go to **Upload Log** and upload a log file.
3. The file is analyzed automatically and you are taken to the log analysis report.
4. Open the threat chart and detailed log views to explore what was found.
5. Use the **Reputation Check** page to look up suspicious IPs or domains.
6. Administrators can manage threats, users, enquiries and incident reports from the admin pages.

## Documentation

The project synopsis and the full final report are in the [`DOCUMENTS`](./DOCUMENTS) folder.

## Team

- Jacob Joy
- Akshay Krishna PS
- Muhammed Irfan AK
- Abinav K
- Sayanth S

Guided by Mr. Vasudeva Shenoy, Ms. Ankitha Poojary and Ms. Prathiksha. Industry mentors: Mr. Sumith Shukla and Mr. Shashank.

## License

This project was developed for academic purposes.
