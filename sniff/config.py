# config.py
CONFIG = {
    # Configuration modèle
    'MODEL_PATH': "/home/neo/Desktop/IPS/CICIDS2017/autoencoder_model.keras",
    'SCALER_MEAN_PATH': "/home/neo/Desktop/IPS/CICIDS2017/scaler_mean.npy",
    'SCALER_SCALE_PATH': "/home/neo/Desktop/IPS/CICIDS2017/scaler_scale.npy",
    'TRAINING_ERRORS_PATH': "/home/neo/Desktop/IPS/CICIDS2017/training_errors.npy",
    
    #web page
    'SECRET_KEY': '@dmINE0O',  # Add this
    'ADMIN_CREDS': {'username': 'admin', 'password': 'admin'}, 
    
    'MAX_FAILED_LOGINS': 5, 
    'MAX_LOGIN_RATE': 2.0,  # Seuil pour bloquer après 2 scans

    'SENSITIVE_PATHS': ['/admin', '/wp-login.php', '/.env'],
    'SENSITIVE_ACCESS_WINDOW': 300, 
    'MAX_REQUEST_RATE': 5,  # Requêtes/seconde




    'PORT_SCAN_THRESHOLD': 5,  # 5 ports uniques en 2 secondes
    'PORT_SCAN_INTERVAL': 2,   # Fenêtre de 2 secondes
    'SYN_THRESHOLD': 10,  # 10 SYN en 5 secondes
    'SYN_INTERVAL': 5,
    'CONNECTION_THRESHOLD': 15,
    'CONNECTION_INTERVAL': 3,
    'LOGIN_TIME_WINDOW': 60,  # Fenêtre de temps pour la détection de brute force
    'LOGIN_ATTEMPTS_THRESHOLD': 5,  # Seuil de tentatives de connexion

    # Configuration de l'interfacFe réseau
    'MONITORED_IP' : "192.168.133.213", # Adresse IP de votre serveur IPS (celle qui apparaît dans les logs)
    #'192.168.133.0/24',  # Votre sous-réseau local actuel (adapté à votre LAN)
    #,'192.168.133.226/32'     # Localhost étendu
    #,'192.168.142.213 /32'  
    'WHITELIST_IPS' : [
    '127.0.0.0/8'
    ,'192.168.133.213/32'
    ,'192.168.142.213/32'
    # ,'13.107.246.77/8'
    # ,'35.155.53.104/8'
    # ,'104.18.26.90/8'
    ],
    # ! seuil dynamique 200
    
    'DYNAMIC_THRESHOLD': 0.8 , # Réduire l'impact des pics MSE
    'ML_THRESHOLD': 300 ,       # Augmenter le seuil absolu
    'LOGIN_PATHS': ['/login', '/auth'],
    'FEATURE_UPDATE_INTERVAL': 300,  # Mise à jour périodique des statistiques
    #'WHITELIST_IPS': ['127.0.0.1/24'],  # Format CIDR valide # Sous-réseau à exclure
    # Ports à considérer comme "normaux"
    'KNOWN_PORTS': [80, 443, 8080, 8000],
    'MAX_PACKET_SIZE': 1500.0  ,# Taille Ethernet standard
    'FEATURE_WINDOW_SIZE': 30,
    'BRUTEFORCE_WINDOW': 10,
    'PORT_SCAN_SCORE_INCREMENT': 1.5,  # Augmenter le score de détection de scan de port
    #! Seuils ML spécifiques
    'ML_ANOMALY_THRESHOLD': 300,  # Seuil MSE absolu
    'ML_DYNAMIC_FACTOR': 2.5,     # Multiplicateur du percentile 95
    'ML_SCORE_INCREMENT': 0.3,    # Score plus faible pour les anomalies ML
    #! sssssssssssssssssssssssssssss

    'BLOCK_THRESHOLD': 2.0,# Score maximum avant blocage
    'HTTP_PORTS': [80, 8080, 8000],
    'XSS_THRESHOLD': 1,  # Nombre de tentatives avant blocage
    'SQLI_THRESHOLD': 1,  # Une seule tentative suffit
    # Configuration web
    'WEB_SERVER_PORT': 8080,
    'LOGIN_PATH': '/login',
    'BRUTE_FORCE_THRESHOLD': 3,
    'BRUTE_FORCE_WINDOW': 60,
    'USER_AGENT_BLACKLIST': ['sqlmap', 'hydra', 'python-requests','nmap'],
    
    #! Fichiers de logs
    'TRAFFIC_LOG': "/home/neo/Desktop/IPS/traffic_logs.csv",
    'BLOCKED_IPS_LOG': "/home/neo/Desktop/IPS/blocked_ips.csv",
    'WEB_LOG': "/home/neo/Desktop/IPS/web_logs.csv",
    
    # Debug
    'DEBUG_MODE': True
}

# === LISTE DES CARACTÉRISTIQUES (DOIT ÊTRE EN HAUT) ===
FEATURE_NAMES = [
    'Destination Port', 'Flow Duration', ' Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets', ' Fwd Packet Length Max',
    ' Fwd Packet Length Min', ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min', ' Bwd Packet Length Mean',
    ' Bwd Packet Length Std', 'Flow Bytes/s', ' Flow Packets/s', ' Flow IAT Mean',
    ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min', 'Fwd IAT Total', ' Fwd IAT Mean',
    ' Fwd IAT Std', ' Fwd IAT Max','Fwd Header Length', ' Fwd IAT Min', 'Bwd IAT Total', ' Bwd IAT Mean',
    ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min', 'Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd URG Flags', ' Bwd URG Flags', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s', ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance', 'FIN Flag Count',
    ' SYN Flag Count', ' RST Flag Count', ' PSH Flag Count', ' ACK Flag Count',
    ' URG Flag Count', ' CWE Flag Count', ' ECE Flag Count', ' Down/Up Ratio',
    ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
    ' Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk',
    ' Fwd Avg Bulk Rate', ' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk',
    'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward', ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min',
    'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min'
]
