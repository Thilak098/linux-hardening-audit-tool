import unittest
from outputs.html import generate_html_report

class TestHTMLReporter(unittest.TestCase):
    def test_html_generation(self):
        test_data = [{
            "check": "ssh_test",
            "status": "FAIL",
            "severity": "HIGH",
            "timestamp": "2023-08-21T00:00:00Z"
        }]
        html = generate_html_report(test_data)
        self.assertIn("<table>", html)
        self.assertIn("ssh_test", html)

if __name__ == "__main__":
    unittest.main()
