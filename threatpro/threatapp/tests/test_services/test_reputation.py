from unittest.mock import Mock, patch

from threatapp.services.reputation_checker import check_domain_reputation, check_ip_reputation, is_public_ip


class TestReputationChecker:
    def test_is_public_ip_valid(self):
        assert is_public_ip('8.8.8.8') is True
        assert is_public_ip('1.1.1.1') is True
        assert is_public_ip('192.168.1.1') is False
        assert is_public_ip('10.0.0.1') is False
        assert is_public_ip('172.16.0.1') is False
        assert is_public_ip('127.0.0.1') is False
        assert is_public_ip('invalid') is False

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_ip_reputation_success(self, mock_get, settings):
        settings.ABUSEIPDB_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'abuseConfidenceScore': 80}}
        mock_get.return_value = mock_resp

        result, error = check_ip_reputation('8.8.8.8')
        assert error is None
        assert result['reputation_score'] == 80
        assert result['blacklisted'] is True

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_ip_reputation_safe(self, mock_get, settings):
        settings.ABUSEIPDB_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'abuseConfidenceScore': 10}}
        mock_get.return_value = mock_resp

        result, error = check_ip_reputation('8.8.8.8')
        assert error is None
        assert result['reputation_score'] == 10
        assert result['blacklisted'] is False

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_ip_reputation_private_ip(self, mock_get):
        result, error = check_ip_reputation('192.168.1.1')
        assert result is None
        assert 'Private' in error
        mock_get.assert_not_called()

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_ip_reputation_api_error(self, mock_get, settings):
        settings.ABUSEIPDB_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 429
        mock_resp.json.return_value = {'errors': ['Rate limit exceeded']}
        mock_get.return_value = mock_resp

        result, error = check_ip_reputation('8.8.8.8')
        assert result is None
        assert 'Rate limit exceeded' in error

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_ip_reputation_exception(self, mock_get, settings):
        settings.ABUSEIPDB_API_KEY = 'test-key'
        mock_get.side_effect = Exception('Network error')

        result, error = check_ip_reputation('8.8.8.8')
        assert result is None
        assert 'Network error' in error

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_domain_reputation_success(self, mock_get, settings):
        settings.VIRUSTOTAL_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'attributes': {'last_analysis_stats': {'malicious': 5}}}}
        mock_get.return_value = mock_resp

        result, error = check_domain_reputation('example.com')
        assert error is None
        assert result['reputation_score'] == 5
        assert result['blacklisted'] is True

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_domain_reputation_safe(self, mock_get, settings):
        settings.VIRUSTOTAL_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'attributes': {'last_analysis_stats': {'malicious': 0}}}}
        mock_get.return_value = mock_resp

        result, error = check_domain_reputation('example.com')
        assert error is None
        assert result['reputation_score'] == 0
        assert result['blacklisted'] is False

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_domain_reputation_api_error(self, mock_get, settings):
        settings.VIRUSTOTAL_API_KEY = 'test-key'
        mock_resp = Mock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {'error': {'message': 'Not found'}}
        mock_get.return_value = mock_resp

        result, error = check_domain_reputation('example.com')
        assert result is None
        assert 'Not found' in error

    @patch('threatapp.services.reputation_checker.requests.get')
    def test_check_domain_reputation_exception(self, mock_get, settings):
        settings.VIRUSTOTAL_API_KEY = 'test-key'
        mock_get.side_effect = Exception('Network error')

        result, error = check_domain_reputation('example.com')
        assert result is None
        assert 'Network error' in error
