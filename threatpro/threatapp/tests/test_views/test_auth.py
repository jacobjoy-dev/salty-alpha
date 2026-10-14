import pytest
from django.urls import reverse


@pytest.mark.django_db
class TestAuthViews:
    @pytest.mark.skip(reason="Django/Python 3.14 template context bug")
    def test_register_get(self, client):
        response = client.get(reverse("register"))
        assert response.status_code == 200

    def test_register_post_valid(self, client):
        response = client.post(
            reverse("register"),
            {
                "username": "newuser",
                "email": "new@test.com",
                "password1": "complexpass123",
                "password2": "complexpass123",
            },
        )
        assert response.status_code == 302

    @pytest.mark.skip(reason="Django/Python 3.14 template context bug")
    def test_register_post_invalid_password_mismatch(self, client):
        response = client.post(
            reverse("register"),
            {"username": "newuser2", "email": "new2@test.com", "password1": "pass123", "password2": "differentpass"},
        )
        assert response.status_code == 200

    @pytest.mark.skip(reason="Django/Python 3.14 template context bug")
    def test_login_get(self, client):
        response = client.get(reverse("login"))
        assert response.status_code == 200

    def test_login_post_valid(self, user, client):
        response = client.post(reverse("login"), {"username": "testuser", "password": "testpass123"})
        assert response.status_code == 302

    @pytest.mark.skip(reason="Django/Python 3.14 template context bug")
    def test_login_post_invalid(self, client):
        response = client.post(reverse("login"), {"username": "testuser", "password": "wrongpass"})
        assert response.status_code == 200
        assert "Invalid username or password" in str(response.content)

    def test_logout(self, client):
        response = client.get(reverse("logout"))
        assert response.status_code == 302
