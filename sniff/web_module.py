# web_module.py
from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
import csv,os
import time
import numpy as np  # Added missing import
from datetime import datetime
from config import CONFIG

app = Flask(__name__, template_folder='/home/neo/Desktop/IPS/sniff/template')
app.secret_key = CONFIG['SECRET_KEY']
ips = None

def init_web_module(ips_core):
    global ips
    ips = ips_core

# Main entry point redirects to appropriate login
@app.route('/')
def home():
    return redirect(url_for('admin_login'))

# ========== ADMIN AUTHENTICATION ==========
@app.route('/admin/login', methods=['GET', 'POST'])  # Changed endpoint
def admin_login():
    if request.method == 'POST':
        if (request.form.get('username') == CONFIG['ADMIN_CREDS']['username'] and 
            request.form.get('password') == CONFIG['ADMIN_CREDS']['password']):
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    return redirect(url_for('admin_login'))

# ========== CLIENT LOGIN DETECTION ========== 
@app.route(CONFIG['LOGIN_PATH'], methods=['POST'])  # Keep client login separate
def client_login():
    try:
        ip = request.remote_addr
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # Logging
        with open(CONFIG['WEB_LOG'], 'a') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ip,
                username,
                password
            ])

        # Bruteforce detection
        now = time.time()
        stats = ips.login_attempts[ip]
        
        if now - stats['start'] > CONFIG['BRUTE_FORCE_WINDOW']:
            stats.update(count=0, start=now)
        
        stats['count'] += 1
        if stats['count'] >= CONFIG['BRUTE_FORCE_THRESHOLD']:
            ips.block_ip(ip, "Brute force détecté")

        return "Authentification échouée", 401
    except Exception as e:
        print(f"[!] Erreur de traitement: {str(e)}")
        return "Erreur interne", 500

# ========== SECURED DASHBOARD ==========
@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    try:
        avg_mse = np.mean(ips.training_errors) if ips.training_errors.size > 0 else 0.0
        stats = {
            'blocked': len(ips.blocked_ips),
            'avg_mse': avg_mse
        }
        return render_template('dashboard.html', stats=stats)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/favicon.ico')
def favicon():
    return '', 204
@app.route('/logs')
def list_logs():
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    log_files = {
        'Traffic Logs': CONFIG['TRAFFIC_LOG'],
        'Blocked IPs': CONFIG['BLOCKED_IPS_LOG'],
        'Web Logs': CONFIG['WEB_LOG']
    }
    return render_template('logs.html', logs=log_files)


@app.route('/logs/download/<log_type>')  # <-- Ajoutez le paramètre log_type
def download_log(log_type):  # <-- Acceptez le paramètre
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    log_paths = {
        'traffic': CONFIG['TRAFFIC_LOG'],
        'blocked': CONFIG['BLOCKED_IPS_LOG'],
        'web': CONFIG['WEB_LOG']
    }
    
    if log_type not in log_paths or not os.path.exists(log_paths[log_type]):
        return "File not found", 404
        
    return send_from_directory(
        os.path.dirname(log_paths[log_type]),
        os.path.basename(log_paths[log_type]),
        as_attachment=True,
        mimetype='text/csv'
    )



@app.route('/logs/view/<log_type>')
def view_log(log_type):
    if not session.get('logged_in'):
        return redirect(url_for('admin_login'))
    
    log_paths = {
        'traffic': CONFIG['TRAFFIC_LOG'],
        'blocked': CONFIG['BLOCKED_IPS_LOG'],
        'web': CONFIG['WEB_LOG']
    }
    
    if log_type not in log_paths:
        return "Invalid log type", 404

    try:
        # Vérifie si le fichier existe
        if not os.path.exists(log_paths[log_type]):
            return f"Log file {log_type} not found", 404

        with open(log_paths[log_type], 'r') as f:
            reader = csv.reader(f)
            data = list(reader)

            # Vérifie que le fichier n'est pas vide
            if not data:
                return render_template('log_view.html',
                                    log_type=log_type.capitalize(),
                                    headers=[],
                                    rows=[])

            headers = data[0]
            rows = data[1:] if len(data) > 1 else []

        return render_template('log_view.html',
                            log_type=log_type.capitalize(),
                            headers=headers,
                            rows=rows)

    except csv.Error as e:
        return f"CSV Error: {str(e)}", 500
    except Exception as e:
        return f"Unexpected error: {str(e)}", 500

def run_web_server():
    print(f"[🌐] Serveur web démarré sur http://localhost:{CONFIG['WEB_SERVER_PORT']}")
    app.run(
        host='0.0.0.0',
        port=CONFIG['WEB_SERVER_PORT'],
        use_reloader=False,
        debug=CONFIG['DEBUG_MODE']
    )