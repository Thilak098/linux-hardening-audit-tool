import unittest
from unittest.mock import patch
from checks.authentication import check_password_max_days

class TestAuthentication(unittest.TestCase):
    @patch('subprocess.run')
    def test_password_max_days_pass(self, mock_run):
        mock_run.return_value.stdout = "PASS_MAX_DAYS 90"
        result = check_password_max_days()
        self.assertEqual(result["status"], "PASS")

    @patch('subprocess.run')
    def test_password_max_days_fail(self, mock_run):
        mock_run.return_value.stdout = "PASS_MAX_DAYS 120"
        result = check_password_max_days()
        self.assertEqual(result["status"], "FAIL")

if __name__ == "__main__":
    unittest.main()
