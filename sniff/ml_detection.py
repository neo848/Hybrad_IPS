# ips_main.py
import os
import time
import numpy as np
import csv
import subprocess
import threading
import requests
import re
from datetime import datetime
#! Importer les bibliothèques de capture de paquets
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict, deque
import tensorflow as tf
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from transformers import pipeline
from config import CONFIG, FEATURE_NAMES
from web_module import init_web_module, run_web_server
import ipaddress
from scapy.layers.http import HTTP, Raw


class IPSCore:
    def __init__(self):
        self.blocked_ips = set()
        self.scores = defaultdict(float)
        self.init_model()
        self.init_logs()
        self.init_detection_structures()
        self.last_packet_time = time.time()
        self.feature_lock = threading.Lock()
        self.fwd_packets = deque(maxlen=CONFIG['FEATURE_WINDOW_SIZE'])
        self.bwd_packets = deque(maxlen=CONFIG['FEATURE_WINDOW_SIZE'])
        self.whitelist_cache = set()  # Nouveau cache
        #! Mise à Jour Temps Réel
        init_web_module(self)
        threading.Thread(target=run_web_server, daemon=True).start()

    def init_model(self):
        """Charge le modèle ML et le scaler"""
        try:
            self.model = load_model(CONFIG['MODEL_PATH'])
            self.scaler = StandardScaler()
            self.scaler.mean_ = np.load(CONFIG['SCALER_MEAN_PATH'])
            self.scaler.scale_ = np.load(CONFIG['SCALER_SCALE_PATH'])
            self.training_errors = np.load(CONFIG['TRAINING_ERRORS_PATH'])
            print("[✅] Modèle, scaler et erreurs chargés")
        except Exception as e:
            print(f"[❌] Erreur de chargement: {str(e)}")
            exit(1)
#!sssssssssssssssssssssssssssssssssssssssssss
#!11111 journalisation
    def init_logs(self):
        """Initialise tous les fichiers de logs"""
        for log_file in [CONFIG['TRAFFIC_LOG'], CONFIG['BLOCKED_IPS_LOG'], CONFIG['WEB_LOG']]:
            dir_path = os.path.dirname(log_file)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                os.chmod(dir_path, 0o777)  # 777 en octal
            if not os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    writer = csv.writer(f)
                    headers = {
                        CONFIG['TRAFFIC_LOG']: ['Timestamp', 'Source_IP', 'Destination_Port', 'Protocol', 'Size', 'Flags', 'Action'],
                        CONFIG['BLOCKED_IPS_LOG']: ['Timestamp', 'IP', 'MAC', 'Type', 'Score'],
                        CONFIG['WEB_LOG']: ['Timestamp', 'IP', 'Username', 'Password']
                    }
                    writer.writerow(headers[log_file])

    def init_detection_structures(self):
        """Initialise les structures de détection"""
        self.port_scan_stats = defaultdict(lambda: {'ports': set(), 'start': 0})
        self.connection_stats = defaultdict(lambda: {'count': 0, 'start': 0})
        self.syn_stats = defaultdict(lambda: {'count': 0, 'start': 0})
        self.login_attempts = defaultdict(lambda: {
            'count': 0,
            'start': 0,
            'timestamps': [],
            'passwords': set()
        })

    def log_event(self, log_type, data):
        """Journalisation générique"""
        try:
            with open(CONFIG[log_type], 'a') as f:
                writer = csv.writer(f)
                writer.writerow(data)
        except Exception as e:
            print(f"[❌] Erreur de journalisation: {str(e)}")

    
    
    #! Ajout d'une règle iptables persistante

    #!   Journalisation avec MAC address via ARP

    #!  Exclusion des IPs whitelistées même si score élevé
    
    def block_ip(self, ip, reason, score=1.0):
        """Bloque une IP avec journalisation améliorée"""
        try:
            for subnet in CONFIG['WHITELIST_IPS']:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                    if CONFIG['DEBUG_MODE']:
                        print(f"[⚠️] Tentative de blocage d'une IP whitelist: {ip}")
                    return False

            if ip not in self.blocked_ips:
                mac = subprocess.getoutput(f"arp -n {ip} | awk 'NR==1 {{print $3}}'").strip()
                mac = mac if len(mac) == 17 else "N/A"

                if not self.iptables_rule_exists(ip):
                    os.system(f"sudo iptables -I INPUT 1 -s {ip} -j DROP")
                '''
                Fichiers séparés pour :

                        Traffic général

                        IPs bloquées

                        Activité web (logins)

                        Format CSV standardisé
                '''
                self.blocked_ips.add(ip)
                log_data = [
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    ip,
                    mac,
                    reason,
                    f"{score:.4f}"
                ]
                self.log_event('BLOCKED_IPS_LOG', log_data)
                print(f"[🚨] IP {ip} bloquée - Raison: {reason}")
                return True
            
            return False

        except Exception as e:
            print(f"[❌] Erreur critique lors du blocage: {str(e)}")
            return False

    def iptables_rule_exists(self, ip):
        """Vérifie si une règle iptables existe déjà"""
        try:
            output = subprocess.check_output(
                ["sudo", "iptables", "-n", "-L", "INPUT"],
                universal_newlines=True
            )
            return any(line.split()[3] == ip and line.split()[1] == "DROP" 
                     for line in output.split('\n') if "DROP" in line)
        except Exception as e:
            print(f"[❌] Erreur iptables: {str(e)}")
            return False

    def analyze_packet(self, packet):
        try:
            # !Verification des protocoles de base (IP/TCP)
            if IP not in packet or TCP not in packet:
                return

            ip = packet[IP].src
            #! Exclusion immédiate des IPs bloquées/whitelistées
            if ip in self.blocked_ips:
                return
            if ip in self.whitelist_cache:
                 return 
            if any(ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False) 
                for subnet in CONFIG['WHITELIST_IPS']):
                if CONFIG['DEBUG_MODE']:
                    print(f"[🔒] IP whitelistée ignorée: {ip}")
                return
            #!###################################

            #! Détection de scan de ports
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            with self.feature_lock:
                ps_stats = self.port_scan_stats[ip]
                if (current_time - ps_stats['start']) > CONFIG['PORT_SCAN_INTERVAL']:
                    ps_stats['ports'] = set()
                    ps_stats['start'] = current_time
                    ps_stats['scan_count'] = 0  # Compteur de scans

                ps_stats['ports'].add(dst_port)
                if len(ps_stats['ports']) >= CONFIG['PORT_SCAN_THRESHOLD']:
                    ps_stats['scan_count'] += 1
                    self.update_risk_score(ip, 1.0)  # Incrémenter de 1.0 à chaque scan
                    if CONFIG['DEBUG_MODE']:
                        print(f"[🔍] Scan de ports détecté ({ps_stats['scan_count']}) - Score: {self.scores[ip]}")
                    ps_stats['ports'].clear()
                    return

            #! Analyse HTTP
            if self.analyze_http(packet):
                return

######################!######################################
            #! Analyse par ML
            '''
                Reconstruction par autoencoder
                Seuil dynamique basé sur le 95ème percentile
                  des erreurs d'entraînement
            '''

            features = self.extract_features(packet)
            if features:
                with self.feature_lock:
                    # !a) Normalisation avec le scaler pré-entraîné
                    scaled = self.scaler.transform([features])
                    #! b) Reconstruction par l’auto-encodeur
                    reconstructed = self.model.predict(scaled, verbose=0)
                    #! c) Calcul de l’erreur quadratique moyenne (MSE)
                    mse = np.mean(np.square(scaled - reconstructed))
                    
                    if CONFIG['DEBUG_MODE']:
                        print(f"[🔍] {ip}:{dst_port} | MSE: {mse:.4f}")

                    if mse > CONFIG['DYNAMIC_THRESHOLD'] * np.percentile(self.training_errors, 95):
                        self.update_risk_score(ip, 0.6)

        except Exception as e:
            if CONFIG['DEBUG_MODE']:
                print(f" Erreur : {str(e)}")
            self.log_event('TRAFFIC_LOG', [
                datetime.now().isoformat(),
                ip if 'ip' in locals() else 'N/A',
                dst_port if 'dst_port' in locals() else 0,
                'TCP',
                len(packet),
                packet[TCP].flags if TCP in packet else '',
                'ERROR'
            ])

    def analyze_http(self, packet):
        """Analyse le trafic HTTP pour des attaques spécifiques"""

        if packet.haslayer(TCP) and packet[TCP].dport in CONFIG['HTTP_PORTS']:
            try:
                raw_layer = packet.getlayer(Raw)
                if not raw_layer:
                    return False
                
                http_layer = raw_layer.load.decode(errors='ignore')
                ip = packet[IP].src
                
                #! Vérification précoce des IP whitelist
                if any(ipaddress.ip_address(ip) in ipaddress.ip_network(subnet) 
                    for subnet in CONFIG['WHITELIST_IPS']):
                    if CONFIG['DEBUG_MODE']:
                        print(f"[🔒] Traffic local whitelisté: {ip}")
                    return False

                detection = False
                current_time = time.time()

                #! Détection SQLi avec vérification de charge utile

                # if False and http_layer:
                #     self.update_risk_score(ip, 0.7)
                #     detection = True
                #     if CONFIG['DEBUG_MODE']:
                #         print(f"[⚡] Détection SQLi sur {ip}")

                #! Analyse des requêtes HTTP
                if "HTTP" in http_layer:
                    http_request = http_layer.split('\r\n')[0]
                    path = http_request.split(' ')[1] if len(http_request.split(' ')) > 1 else '/'
                    method = http_request.split(' ')[0]

                    #! Tracking des chemins sensibles
                    if any(sensitive_path in path for sensitive_path in CONFIG['SENSITIVE_PATHS']):
                        self.login_attempts[ip]['sensitive_access'] = current_time
                        if CONFIG['DEBUG_MODE']:
                            print(f"[🛡️] Accès chemin sensible: {ip} -> {path}")

                    #! Détection bruteforce améliorée
                    if method == "POST" and "login" in path.lower():
                        self.login_attempts[ip]['count'] += 1
                        self.login_attempts[ip]['timestamps'].append(current_time)
                        #! DEBUG: Afficher les tentatives en temps réel
                        print(f"[📈] {ip} Tentatives: {self.login_attempts[ip]['count']}/{CONFIG['MAX_FAILED_LOGINS']} | Dernière: {datetime.fromtimestamp(current_time).strftime('%H:%M:%S')}")
                        #! Analyse du corps de la requête
                        if "username=" in http_layer and "password=" in http_layer:
                            creds = {
                                'username': re.search(r'username=([^&]*)', http_layer).group(1),
                                'password': re.search(r'password=([^&]*)', http_layer).group(1)
                            }
                            self.log_event('WEB_LOG', [
                                datetime.now().isoformat(),
                                ip,
                                creds['username'],
                                creds['password']
                            ])

                        #! Vérification combinée des patterns
                        if self.check_bruteforce(ip):
                            self.update_risk_score(ip, 2.0)  # +2.0 direct
                            print(f"[⚡] SCORE BRUTEFORCE: {self.scores[ip]}")
                if detection:
                    self.block_ip(ip, "Activité HTTP suspecte")
                    return True

            except Exception as e:
                if CONFIG['DEBUG_MODE']:
                    print(f"[⚠️] Erreur d'analyse HTTP: {str(e)}")
                self.log_event('TRAFFIC_LOG', [
                    datetime.now().isoformat(),
                    ip,
                    packet[TCP].dport,
                    'HTTP',
                    len(packet),
                    packet[TCP].flags,
                    'ERROR'
                ])
        return False

    def check_ip_reputation(self, ip):
        """Vérification locale avancée de la réputation"""
        stats = self.login_attempts.get(ip, {})
        reasons = []

        # 1. Tentatives de login échouées
        if stats.get('count', 0) > CONFIG['MAX_FAILED_LOGINS']:
            reasons.append(f"Tentatives login ({stats['count']})")

        # 2. Accès répétés aux chemins sensibles
        sensitive_access = stats.get('sensitive_access', 0)
        if time.time() - sensitive_access < CONFIG['SENSITIVE_ACCESS_WINDOW']:
            reasons.append("Accès chemin sensible")

        # 3. Taux de requêtes anormal
        request_rate = self.calculate_request_rate(ip)
        if request_rate > CONFIG['MAX_REQUEST_RATE']:
            reasons.append(f"Taux requêtes ({request_rate}/s)")

        # 4. User-Agent suspect
        if any(ua in stats.get('user_agent', '') for ua in CONFIG['USER_AGENT_BLACKLIST']):
            reasons.append("User-Agent blacklisté")

        return len(reasons) > 0

    def get_detection_reasons(self, ip):
        """Retourne les motifs de détection formatés"""
        return ", ".join([
            f"✗ {reason}" for reason in 
            self.check_ip_reputation(ip).get('reasons', [])
        ]) or "Aucun motif spécifique"
    def check_bruteforce(self, ip):
        """Vérifie les motifs de bruteforce sur une fenêtre glissante"""
        attempts = self.login_attempts[ip]
        now = time.time()
        
        # Garder seulement les tentatives des dernières X secondes
        window_start = now - CONFIG['BRUTEFORCE_WINDOW']
        attempts['timestamps'] = [t for t in attempts['timestamps'] if t > window_start]
        
        # Mettre à jour le compteur
        attempts['count'] = len(attempts['timestamps'])
        
        # Ne PAS bloquer ici, retourner simplement le statut
        return attempts['count'] >= CONFIG['MAX_FAILED_LOGINS']
  
    '''
        Combinaison de multiples contributeurs :

            +1.0 pour scan de ports

            +0.6 pour anomalie ML

            +2.0 direct pour bruteforce
    '''

    
    def update_risk_score(self, ip, delta):
        self.scores[ip] += delta
        
        #! Bloquer si score dépasse MAX_LOGIN_RATE
        if self.scores[ip] >= CONFIG['MAX_LOGIN_RATE']:
            self.block_ip(ip, "Machine Learning Anomaly (Port Scan)", self.scores[ip])
        
        #! Debug du score
        if CONFIG['DEBUG_MODE']:
            print(f"[⚖️] {ip} Score: {self.scores[ip]:.2f} (+{delta})")

#1################


    def extract_features(self, packet):
        """Extrait les caractéristiques réseau du paquet"""
        
        #! # Initialisation du dictionnaire à zéro pour toutes les features
        features = {k: 0.0 for k in FEATURE_NAMES}
        try:
            if IP in packet and TCP in packet:
                ip = packet[IP]
                tcp = packet[TCP]
                packet_time = packet.time
                #! # Calcul de la durée de la session
                flow_duration = max(packet_time - self.last_packet_time, 1e-5)
                features[' Flow Duration'] = flow_duration
                self.last_packet_time = packet_time

                features[' Total Fwd Packets'] = 1.0 / flow_duration if flow_duration > 0 else 0.0
                features['Total Length of Fwd Packets'] = len(ip)
                
                tcp_flags = tcp.flags
                features[' SYN Flag Count'] = 1.0 if 'S' in tcp_flags else 0.0
                features[' ACK Flag Count'] = 1.0 if 'A' in tcp_flags else 0.0
                #! 2. Nombre et taille des paquets forward/backward
                if ip.dst == CONFIG['MONITORED_IP']:
                    self.bwd_packets.append(len(packet))
                    features[' Total Backward Packets'] = 1.0
                    features[' Total Length of Bwd Packets'] = len(packet)
                else:
                    self.fwd_packets.append(len(packet))
                    features[' Total Fwd Packets'] = 1.0
                    features['Total Length of Fwd Packets'] = len(packet)
                #! 3. Caractéristiques des paquets forward
                if self.fwd_packets:
                    # 3. Statistiques sur la fenêtre glissante
                    window = list(self.fwd_packets)
                    features['Fwd Packet Length Max'] = max(window) if window else 0.0
                    features['Fwd Packet Length Min'] = min(window) if window else 0.0
                    features['Fwd Packet Length Std'] = np.std(window) if len(window) > 1 else 0.0

                features[' Flow IAT Mean'] = flow_duration
                features[' Active Mean'] = 1.0 if features[' SYN Flag Count'] > 0 and features[' ACK Flag Count'] == 0 else 0.0
                features[' Idle Mean'] = 1.0 if features[' ACK Flag Count'] > 0 and features[' SYN Flag Count'] == 0 else 0.0

                src_ip = ip.src
                scan_stats = self.port_scan_stats[src_ip]
                scan_likelihood = len(scan_stats['ports']) / CONFIG['PORT_SCAN_THRESHOLD']
                features[' Port Scan Likelihood'] = min(scan_likelihood, 1.0)

                port = tcp.dport
                features[' Destination Port'] = 0.0 if port in CONFIG['KNOWN_PORTS'] else 1.0
                features[' Packet Length Mean'] = len(packet) / CONFIG['MAX_PACKET_SIZE']
                
                #! 4. Récupération du vecteur sous forme de liste
                extracted = [features[k] for k in FEATURE_NAMES]
                if len(extracted) != 78:
                    raise ValueError(f"Mismatch features: {len(extracted)}/78")
                
                return extracted
        
        except Exception as e:
            if CONFIG['DEBUG_MODE']:
                print(f"[⚠️] Erreur extraction: {e}")
        return None
    

    def start(self):
        """Démarre le système de détection"""
        print("[🚀] Démarrage de l'IPS...")
        #!Dashboard web accessible sur CONFIG['WEB_SERVER_PORT']
        print(f"|-- Port web: {CONFIG['WEB_SERVER_PORT']}")
        print(f"|-- Seuil ML: {CONFIG['ML_THRESHOLD']}")
        print(f"|-- Détections actives: SQLi, Scans, Bruteforce, Anomalies ML")
        
        try:
            #! Capture Initiale  et delegation a analyze_packet()
            sniff(filter="ip and (tcp or udp)", prn=lambda p: self.analyze_packet(p), store=0)
        except KeyboardInterrupt:
            print("\n[🛑] Arrêt de l'IPS...")
        finally:
            print(f"[📊] IPs bloquées: {len(self.blocked_ips)}")


if __name__ == "__main__":
    ips = IPSCore()
    ips.start()