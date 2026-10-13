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
- **SOC Dark Theme:** Modern Security Operations Center UI with responsive sidebar, real-time status indicators, and severity-based color coding

## Tech Stack

- **Backend:** Python 3.12, Django 5.1
- **Database:** SQLite (production-ready for PostgreSQL)
- **Charts:** Matplotlib (server-rendered) + Chart.js (interactive)
- **Frontend:** HTML, CSS, JavaScript (Django templates with Bootstrap 5)
- **Threat intelligence:** AbuseIPDB API, VirusTotal API
- **Code Quality:** Ruff, Black, MyPy, Pre-commit hooks
- **Testing:** Pytest, pytest-django, factory-boy, responses

## Project Structure

```
salty-alpha/
├── .env.example              # Environment variable template
├── .env                      # Local environment (gitignored)
├── .gitignore
├── requirements.txt          # Python dependencies
├── requirements-dev.txt      # Development dependencies
├── .pre-commit-config.yaml   # Pre-commit hooks (Ruff + Black)
├── .github/workflows/ci.yml  # GitHub Actions CI
├── pyproject.toml            # Project metadata (Ruff, Black, MyPy, Pytest)
├── DOCUMENTS/                # Project synopsis and final report
└── threatpro/                # Django project
    ├── manage.py
    ├── db.sqlite3
    ├── static/               # Collected static files (css/, img/)
    ├── staticfiles/          # Production static files
    ├── media/logs/           # Uploaded log files
    ├── templates/
    │   ├── base.html         # SOC theme base template
    │   ├── 404.html          # Not Found page
    │   ├── 500.html          # Server Error page
    │   ├── index.html        # Landing page
    │   ├── accounts/         # Login / Register (SOC theme)
    │   ├── threats/          # Dashboard, logs, charts (SOC theme)
    │   ├── incidents/        # Report incident (SOC theme)
    │   └── admin_pages/      # Admin views (SOC theme)
    ├── threatpro/
    │   ├── settings.py       # Settings (loads from .env)
    │   ├── urls.py           # Root URLs
    │   └── wsgi.py
    └── threatapp/
        ├── models.py         # Database models
        ├── forms.py          # Django forms
        ├── urls.py           # App URLs
        ├── views/            # View modules
        │   ├── auth.py           # Authentication views
        │   ├── threats.py        # Threat detection views
        │   ├── reputation.py     # Reputation checker views
        │   ├── incidents.py      # Incident reporting views
        │   ├── admin_views.py    # Admin dashboard views
        │   ├── threat_crud.py    # Threat CRUD views
        │   ├── index.py          # Landing page view
        │   └── __init__.py
        ├── services/         # Business logic
        │   ├── log_analyzer.py       # Log analysis & 13 threat patterns
        │   ├── reputation_checker.py # AbuseIPDB + VirusTotal APIs
        │   ├── chart_generator.py    # Matplotlib charts
        │   └── __init__.py
        ├── tests/            # Pytest test suite (38 passing)
        │   ├── test_models.py
        │   ├── test_services/
        │   │   ├── test_log_analyzer.py
        │   │   └── test_reputation.py
        │   └── test_views/
        │       └── test_auth.py
        ├── admin.py
        ├── migrations/
        └── __init__.py
```

## Getting Started

### Prerequisites

- Python 3.12 or later
- pip
- Free API keys from [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/)

### Installation

```bash
git clone https://github.com/jacobjoy-dev/salty-alpha.git
cd salty-alpha

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configure Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
# Edit .env with your API keys
```

Required variables:
- `SECRET_KEY` - Django secret key (generate with `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`)
- `DEBUG` - Set to `True` for development
- `ALLOWED_HOSTS` - Comma-separated hosts (e.g., `localhost,127.0.0.1`)
- `ABUSEIPDB_API_KEY` - Your AbuseIPDB API key
- `VIRUSTOTAL_API_KEY` - Your VirusTotal API key

### Set up the database and run

```bash
cd threatpro
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

Open `http://127.0.0.1:8000/` in your browser. The Django admin is available at `/admin/`.

## Development

### Run tests

```bash
cd threatpro
pytest -v
```

### Code quality

```bash
# Format code
ruff format .
black .

# Lint
ruff check .
```

### Pre-commit hooks

```bash
pre-commit install
```

## How to Use

1. Register an account and log in.
2. Go to **Upload Log** and upload a log file.
3. The file is analyzed automatically and you are taken to the log analysis report.
4. Open the threat chart and detailed log views to explore what was found.
5. Use the **Reputation Check** page to look up suspicious IPs or domains.
6. Administrators can manage threats, users, enquiries and incident reports from the admin pages.

## Threat Detection Patterns

The log analyzer detects 13 threat patterns:

| Pattern | Severity | Description |
|---------|----------|-------------|
| SQL Injection | High | UNION SELECT, INSERT, DROP TABLE, etc. |
| XSS Attack | High | `<script>`, javascript:, onerror= |
| Unauthorized Access | High | HTTP 401, 403 |
| Brute Force Attempt | Medium | Failed login, password incorrect |
| Directory Traversal | Medium | `../`, `..\`, `/etc/passwd` |
| Web Scraping | Low | Scrapy, Python-urllib, wget, curl |
| 404 Probing | Low | HTTP 404 |
| Buffer Overflow | High | Strings > 1000 chars |
| Command Injection | High | wget, curl, rm -rf, chmod +x |
| Malicious User Agent | High | sqlmap, nmap, nikto, metasploit |
| Port Scanning | Medium | SYN_SCAN, NMAP_SCAN |
| DDoS Attack | High | Repeated requests from same IP |
| Malicious File Upload | High | .exe, .php, .jsp, .aspx, .sh, .bat uploads |

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