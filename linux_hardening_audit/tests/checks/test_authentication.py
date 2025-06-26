import unittest
from checks.authentication import check_password_max_days
from unittest.mock import patch

class TestAuthChecks(unittest.TestCase):
    @patch('subprocess.run')
    def test_password_max_days(self, mock_run):
        # Setup mock
        mock_run.return_value.stdout = "PASS_MAX_DAYS 90"
        
        # Run test
        result = check_password_max_days()
        
        # Assertions
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["value"], 90)

if __name__ == "__main__":
    unittest.main()
