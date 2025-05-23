# Système de Détection d'Intrusion (IPS)

Ce projet implémente un système hybride de détection d'intrusion (IPS) combinant des techniques basées sur l'apprentissage automatique et des signatures pour détecter et bloquer les activités malveillantes sur un réseau.

## Fonctionnalités

- **Détection basée sur les signatures** : Analyse des paquets réseau pour détecter des modèles connus d'attaques (SQLi, XSS, bruteforce, etc.).
- **Détection basée sur l'IA** : Utilisation d'un autoencodeur pour identifier les anomalies réseau.
- **Blocage automatique** : Ajout de règles `iptables` pour bloquer les IP malveillantes.
- **Journalisation** : Enregistrement des événements dans des fichiers de logs détaillés.
- **Interface Web** : Tableau de bord pour visualiser les alertes et les statistiques.

## Prérequis

- Python 3.8 ou supérieur
- Droits administrateur (root) pour configurer `iptables`
- Clés API pour AbuseIPDB et VirusTotal (optionnel)

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/neo848/Hybrad_IPS.git
   cd Hybrad_IPS
   ```

2. Installez les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

3. Configurez le fichier `sniff/config.py` :
   - Définissez les chemins des modèles et des fichiers de logs.
   - Ajoutez vos clés API si nécessaire.

## Utilisation

1. Démarrez le système IPS :
   ```bash
   sudo python sniff/main.py
   ```

2. Surveillez les logs :
   ```bash
   tail -f logs/traffic_logs.csv
   ```

3. Accédez au tableau de bord Web (si activé) :
   ```
   http://localhost:8080
   ```

## Structure des Dossiers

```
.
├── sniff/
│   ├── config.py
│   ├── ml_detection.py
│   ├── Sig_IPS.py
│   ├── main.py
│   └── template/
├── CICIDS2017/
│   ├── autoencoder_model.keras
│   ├── scaler_mean.npy
│   ├── scaler_scale.npy
│   └── training_errors.npy
├── logs/
│   ├── traffic_logs.csv
│   ├── blocked_ips.csv
│   └── web_logs.csv
└── requirements.txt
```

## Notes

- Assurez-vous que votre interface réseau est correctement configurée dans `sniff/config.py`.
- Le système nécessite des privilèges root pour capturer les paquets réseau et modifier les règles `iptables`.

## Avertissement

Ce projet est destiné à des fins éducatives et expérimentales. Utilisez-le avec précaution dans un environnement contrôlé.