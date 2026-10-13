import pytest
from django.contrib.auth import get_user_model

from threatapp.models import ThreatLog

User = get_user_model()


@pytest.fixture
def user(db):
    return User.objects.create_user("testuser", "test@example.com", "testpass123")


@pytest.fixture
def superuser(db):
    return User.objects.create_superuser("admin", "admin@example.com", "adminpass123")


@pytest.fixture
def client(user):
    from django.test import Client

    c = Client()
    c.force_login(user)
    return c


@pytest.fixture
def admin_client(superuser):
    from django.test import Client

    c = Client()
    c.force_login(superuser)
    return c


@pytest.fixture
def sample_log_file(tmp_path):
    content = """ip,timestamp,method,url,status,response_size
192.168.1.1,2024-01-01 10:00:00,GET,/,200,1024
192.168.1.2,2024-01-01 10:01:00,POST,/login,401,512
10.0.0.1,2024-01-01 10:02:00,GET,/admin,403,256
"""
    f = tmp_path / "test.log"
    f.write_text(content)
    return f


@pytest.fixture
def threat_log(user, sample_log_file):
    from django.core.files import File

    log = ThreatLog.objects.create(user=user)
    with open(sample_log_file, "rb") as f:
        log.log_file.save("test.log", File(f))
    return log
