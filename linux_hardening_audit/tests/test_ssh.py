import unittest
from unittest.mock import patch
from checks.ssh import check_ssh_root_login  # Make sure this matches your actual function name

class TestSSH(unittest.TestCase):
    @patch('subprocess.run')
    def test_ssh_root_login(self, mock_run):
        # Test when root login is allowed (should FAIL)
        mock_run.return_value.stdout = "PermitRootLogin yes"
        result = check_ssh_root_login()
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["value"], "yes")
        
        # Test when root login is disabled (should PASS)
        mock_run.return_value.stdout = "PermitRootLogin no"
        result = check_ssh_root_login()
        self.assertEqual(result["status"], "PASS")

if __name__ == "__main__":
    unittest.main()
