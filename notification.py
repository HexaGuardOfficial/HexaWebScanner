import smtplib
from email.mime.text import MIMEText
from .db_manager import DatabaseManager

class NotificationService:
    def __init__(self):
        self.db_manager = DatabaseManager()
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "your-email@gmail.com"
        self.sender_password = "your-password"

    def send_notification(self, target_url, vulnerabilities):
        try:
            # Prepare email content
            msg = MIMEText(f"Vulnerabilities found for {target_url}: {vulnerabilities}")
            msg['Subject'] = f"Vulnerability Alert for {target_url}"
            msg['From'] = self.sender_email
            msg['To'] = "recipient@example.com"

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)

            print("Notification sent successfully.")
        except Exception as e:
            print(f"Error sending notification: {str(e)}") 