import threading
import sys
import os

# Add the parent directory of 'sniff' to the Python path
sys.path.append('/home/neo/Desktop/IPS')
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from sniff.ml_detection import IPSCore
from sniff.Sig_IPS import IPS, setup_iptables, cleanup_iptables


def run_ml_detection(ips_core):
    # Start the ML-based IPS
    ips_core.start()

def run_signature_ips(signature_ips):
    # Start the signature-based IPS
    signature_ips.start()

if __name__ == '__main__':
    print("[+] Starting Hybrid IPS (ML + Signature-based)...")

    # Initialize ML-based IPS
    ml_ips = IPSCore()

    # Initialize Signature-based IPS
    setup_iptables()  # Ensure iptables rules are set up
    signature_ips = IPS()

    try:
        # Run both systems in separate threads
        t1 = threading.Thread(target=run_ml_detection, args=(ml_ips,), daemon=True)
        t2 = threading.Thread(target=run_signature_ips, args=(signature_ips,), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("\n[!] Stopping Hybrid IPS...")
    finally:
        cleanup_iptables()  # Clean up iptables rules