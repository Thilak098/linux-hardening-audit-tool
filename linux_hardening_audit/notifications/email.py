import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_audit_report(recipient: str, report_path: str):
    msg = MIMEMultipart()
    msg["Subject"] = "Security Audit Report"
    msg["From"] = "audit@yourdomain.com"
    msg["To"] = recipient
    
    with open(report_path) as f:
        msg.attach(MIMEText(f.read(), "html"))
    
    with smtplib.SMTP("your.smtp.server", 587) as server:
        server.starttls()
        server.login("user", "password")
        server.send_message(msg)
