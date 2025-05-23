from scapy.all import IP, TCP, Raw
from netfilterqueue import NetfilterQueue
import re
from datetime import datetime
import csv
from email_config import EmailAlert
from colorama import init, Fore, Style
import os
import subprocess
from collections import defaultdict
from urllib.parse import unquote

init(autoreset=True)

INTERFACE = "lo"
#INTERFACE = "wlp0s20f3"
QUEUE_NUM = "1"

IPTABLES_RULES = [
    ["iptables", "-I", "INPUT", "-i", INTERFACE, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM],
    ["iptables", "-I", "OUTPUT", "-o", INTERFACE, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM],
]

IPTABLES_CLEAR = [
    ["iptables", "-D", "INPUT", "-i", INTERFACE, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM],
    ["iptables", "-D", "OUTPUT", "-o", INTERFACE, "-j", "NFQUEUE", "--queue-num", QUEUE_NUM],
]

def setup_iptables():
    for rule in IPTABLES_RULES:
        subprocess.run(rule, check=True)
    print(f"🛡️ Inserted NFQUEUE rules on interface {INTERFACE}")

def cleanup_iptables():
    for rule in IPTABLES_CLEAR:
        subprocess.run(rule, check=True)
    print(f"🛡️ Removed NFQUEUE rules from interface {INTERFACE}")

class IPS:
    def __init__(self):
        self.email = EmailAlert()
        os.makedirs('logs', exist_ok=True)
        self._init_log_file()
        self.blocked_ips = set()

        print(Fore.MAGENTA + r"""
    ___  ___   ___  
   |_ _ | _ \ / __|
    | | |   / \__ \ 
   |___ |_|   |___/
        """)
        print(Fore.CYAN + " " * 10 + "CYBERSECURITY PROTECTION SYSTEM")
        print(Style.RESET_ALL + "=" * 60)
        print(Fore.YELLOW + "Monitoring traffic using iptables and NetfilterQueue...\n")

    def start(self):
        print("[Signature-based IPS] Started monitoring traffic...")
        # Add logic for signature-based detection here

    def _init_log_file(self):
        with open('logs/ips_logs.csv', 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp','ip','attack','action','details'])

    def _log_attack(self, attack_type, ip, details):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        action = "🚨 BLOCKED"

        colors = {
            'SQLi': Fore.RED,
            'XSS': Fore.MAGENTA,
            'Directory Fuzzing': Fore.YELLOW,
            'DDoS': Fore.CYAN,
            'PortScan': Fore.BLUE,
            'CommandInjection': Fore.GREEN,
            'Fuzzing': Fore.WHITE
        }
        print(colors.get(attack_type, Fore.WHITE) + f"""
[{timestamp}] {attack_type.upper()} DETECTED
• Source: {ip}
• Details: {details[:100]}...
• Action: {action}
""")

        with open('logs/ips_logs.csv', 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, ip, attack_type, action, details[:200]])

        self.email.send_alert(attack_type, ip, details)

    def detect_and_block(self, packet):
        payload = packet.get_payload()
        try:
            ip_packet = IP(payload)
            src_ip = ip_packet.src

            if src_ip in self.blocked_ips:
                packet.drop()
                return

            if ip_packet.haslayer(TCP) and ip_packet[TCP].dport != 5001:
                packet.accept()
                return

            if ip_packet.haslayer(TCP) and ip_packet.haslayer(Raw):
                raw_data = str(ip_packet[Raw].load)

                with open('logs/logs.csv', 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        src_ip,
                        raw_data
                    ])

                directory_fuzzing_patterns = [
                    r"\.\.\/",
                    r"\.\.\\",
                    r"\/etc\/",
                    r"\/var\/",
                    r"\/root\/",
                    r"\/proc\/",
                    r"\/\w+\/\.\.\/",
                    r"\/\w+\/\w+\/\.\.\/",
                    r"\/\w+\/\w+\/\w+\/\.\.\/",
                    r"\w+\.php",
                    r"\w+\.env",
                    r"\w+\.log",
                    r"\w+\.conf",
                    r"\w+\.ini",
                    r"\w+\.bak",
                    r"\w+\.old",
                    r"\w+\.swp",
                ]

                if any(re.search(p, raw_data, re.IGNORECASE) for p in directory_fuzzing_patterns):
                    self._log_attack('Directory Fuzzing', src_ip, raw_data)
                    self.blocked_ips.add(src_ip)
                    packet.drop()
                    return

                sql_patterns = [
                    r"([';]+|(--)+)\s*(select|update|delete|insert|drop|alter|create|exec|union|truncate|replace|rename)\b",
                    r"\bunion\s+select\b",
                    r"\bexec\s*\(\b",
                    r"\bxp_cmdshell\b",
                    r"\bselect\s+.*\s+from\s+.*",
                    r"\binsert\s+into\s+.*",
                    r"\bdelete\s+from\s+.*",
                    r"\bdrop\s+table\s+.*",
                    r"\balter\s+table\s+.*",
                    r"\bcreate\s+table\s+.*",
                    r"--\s+.*",
                    r"\bor\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?\s*--",
                    r"\bwhere\s+.*\s*=\s*.*",
                    r"\bgroup\s+by\b",
                    r"\border\s+by\b",
                    r"\bhaving\s+.*\b",
                    r"\bselect\s+count\(\*\)\b",
                ]

                # Decode URL-encoded payloads to ensure proper detection
                raw_data = unquote(raw_data)

                # Ensure XSS detection works for common patterns
                xss_patterns = [
                    r"<script>alert\(1\)</script>",  # Specific XSS pattern
                    r"<script.*?>.*?</script>",
                    r"<.*?on[a-z]+\s*=\s*['\"].*?['\"].*?>",
                    r"javascript:\s*.*",
                    r"<iframe.*?>.*?</iframe>",
                    r"<img\s+.*?on[a-z]+\s*=\s*['\"].*?['\"].*?>",
                    r"<svg.*?on[a-z]+\s*=\s*['\"].*?['\"].*?>",
                    r"<.*?style\s*=\s*['\"].*?expression\(.*?\)['\"].*?>",
                    r"<.*?onload\s*=\s*['\"].*?['\"].*?>"
                ]

                if any(re.search(p, raw_data, re.IGNORECASE) for p in sql_patterns):
                    self._log_attack('SQLi', src_ip, raw_data)
                    self.blocked_ips.add(src_ip)
                    packet.drop()
                    return
                elif any(re.search(p, raw_data, re.IGNORECASE) for p in xss_patterns):
                    self._log_attack('XSS', src_ip, raw_data)
                    self.blocked_ips.add(src_ip)
                    packet.drop()
                    return
                else:
                    packet.accept()
            else:
                packet.accept()
        except Exception as e:
            print(Fore.YELLOW + f"[!] Packet processing error: {str(e)}")
            packet.accept()

def start_ips():
    print(Fore.GREEN + "[+] Starting IPS Engine with NetfilterQueue..." + Style.RESET_ALL)
    setup_iptables()
    nfqueue = NetfilterQueue()
    ips = IPS()
    nfqueue.bind(1, ips.detect_and_block)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopping IPS Engine..." + Style.RESET_ALL)
        nfqueue.unbind()
        cleanup_iptables()

if __name__ == '__main__':
    start_ips()
