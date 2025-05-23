import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from colorama import init, Fore, Style
import ssl

# Initialize colorama for colored terminal output
init(autoreset=True)

class EmailAlert:
    def __init__(self):
        """Configuration for Gmail SMTP"""
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender = "ips.project4@gmail.com"
        self.password = 'yvsh mykh oyjc rpvn'
        self.recipient = "ips.project4@gmail.com"
        self.ssl_context = ssl.create_default_context()

    def send_alert(self, attack_type, ip, details):
        """
        Send real security alerts
        Args:
            attack_type: SQLi/XSS/BruteForce/etc.
            ip: Attacker IP address  
            details: Attack description
        """
        try:
            # Create email with UTF-8 encoding for emojis
            msg = MIMEText(f"""
            🚨🚨🚨 SECURITY ALERT 🚨🚨🚨
            ==========================
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Attack Type: {attack_type}
            Source IP: {ip}
            Details: {details[:100]}  
            ==========================
            IPS Protection System
            """, 'plain', 'utf-8')

            # Email headers
            msg['Subject'] = f"🚨 {attack_type.upper()} detected from {ip}"
            msg['From'] = self.sender
            msg['To'] = self.recipient

            # Secure SMTP connection
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=self.ssl_context)
                server.login(self.sender, self.password)
                server.send_message(msg)
            
            print(Fore.GREEN + Style.BRIGHT + 
                 f"[ALERT] Email sent for {attack_type} attack")
            return True

        except smtplib.SMTPAuthenticationError:
            print(Fore.RED + Style.BRIGHT + 
                 "[ERROR] Email failed: Invalid credentials")
            return False
        except Exception as e:
            print(Fore.RED + Style.BRIGHT + 
                 f"[ERROR] Email failed: {str(e)}")
            return False
