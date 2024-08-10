from flask import Flask, render_template, request, redirect, url_for, send_file
import mysql.connector
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
from flask_weasyprint import HTML, render_pdf
import threading
import time
import re
import socket

app = Flask(__name__)

# Configuración de la conexión a la base de datos
db_config = {
    'user': 'IPN',
    'password': 'tesisIPN@1234',
    'host': 'localhost',
    'database': 'logServer'
}

# Palabras clave y frases específicas
malicious_keywords = ["failed login", "unauthorized access", "DDoS attack", "port scan"]

# Detectar palabras clave en los mensajes
def detect_keyword_events():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    query = """
        SELECT FromHost as ip, COUNT(*) as count
        FROM SystemEvents
        WHERE {}
        GROUP BY FromHost
    """.format(' OR '.join([f"Message LIKE %s" for _ in malicious_keywords]))
    params = [f'%{keyword}%' for keyword in malicious_keywords]
    cursor.execute(query, params)
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return pd.DataFrame(results)

# Detectar alta frecuencia de eventos
def detect_high_frequency_events(threshold=100, period='1 HOUR'):
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    query = """
        SELECT FromHost as ip, COUNT(*) as count
        FROM SystemEvents
        WHERE ReceivedAt >= NOW() - INTERVAL {}
        GROUP BY FromHost
        HAVING COUNT(*) > %s
    """.format(period)
    cursor.execute(query, (threshold,))
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return pd.DataFrame(results)

# Función para analizar y bloquear IPs maliciosas
def analyze_and_block_suspicious_ips():
    server_ip = "192.168.1.102"
    suspicious_ips = pd.concat([
        detect_keyword_events(),
        detect_high_frequency_events()
    ])
    
    for ip_address in suspicious_ips['ip'].unique():
        if ip_address != server_ip:
            block_device(ip_address)
        else:
            print(f"Omitiendo el bloqueo de la IP del servidor: {ip_address}")

# Llamar a esta función periódicamente
def periodic_ip_check(interval=3600):
    while True:
        analyze_and_block_suspicious_ips()
        time.sleep(interval)

# Iniciar el chequeo periódico en un hilo separado
thread = threading.Thread(target=periodic_ip_check)
thread.start()

# Conectar a la base de datos y obtener los eventos del sistema con o sin filtro de búsqueda
def get_system_events(search_term=None, page=1, per_page=100):
    offset = (page - 1) * per_page
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    if search_term:
        query = "SELECT * FROM SystemEvents WHERE Message LIKE %s ORDER BY ReceivedAt DESC LIMIT %s OFFSET %s"
        cursor.execute(query, ('%' + search_term + '%', per_page, offset))
    else:
        query = "SELECT * FROM SystemEvents ORDER BY ReceivedAt DESC LIMIT %s OFFSET %s"
        cursor.execute(query, (per_page, offset))
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results

# Función para bloquear una dirección IP
def block_device(ip_address):
    print(f"Bloqueando IP: {ip_address}")
    try:
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True, check=True)
        
        # Guardar la IP bloqueada en la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        insert_query = "INSERT INTO BlockedDevices (ip_address, blocked_at) VALUES (%s, NOW())"
        cursor.execute(insert_query, (ip_address,))
        connection.commit()
        cursor.close()
        connection.close()
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando iptables: {e}")

    # Agregar una regla para registrar los paquetes bloqueados
    try:
        command = f"sudo iptables -I INPUT 1 -s {ip_address} -j LOG --log-prefix 'IP BLOCKED: '"
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al agregar la regla de registro en iptables: {e}")

# Función para desbloquear una dirección IP
def unblock_device(ip_address):
    try:
        command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True, check=True)
        
        # Eliminar la IP bloqueada de la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        delete_query = "DELETE FROM BlockedDevices WHERE ip_address = %s"
        cursor.execute(delete_query, (ip_address,))
        connection.commit()
        cursor.close()
        connection.close()
    except subprocess.CalledProcessError as e:
        print(f"Error al desbloquear la IP: {e}")

# Función para obtener todos los dispositivos bloqueados
def get_blocked_devices():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    query = "SELECT * FROM BlockedDevices"
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results

# Obtener estadísticas de eventos por hora
def get_events_per_hour():
    connection = mysql.connector.connect(**db_config)
    query = """
        SELECT HOUR(ReceivedAt) as hour, COUNT(*) as count
        FROM SystemEvents
        GROUP BY HOUR(ReceivedAt)
        ORDER BY hour;
    """
    df = pd.read_sql(query, connection)
    connection.close()
    return df

# Obtener top IPs sospechosas
def get_top_suspicious_ips():
    connection = mysql.connector.connect(**db_config)
    query = """
        SELECT FromHost as ip, COUNT(*) as count
        FROM SystemEvents
        GROUP BY FromHost
        ORDER BY count DESC
        LIMIT 10;
    """
    df = pd.read_sql(query, connection)
    connection.close()
    return df

# Ruta para el dashboard
@app.route('/dashboard')
def dashboard():
    events_per_hour = get_events_per_hour()
    top_ips = get_top_suspicious_ips()
    return render_template('dashboard.html', events_per_hour=events_per_hour, top_ips=top_ips)

# Generar gráficos para el dashboard
def create_bar_plot(df, x, y, title, xlabel, ylabel):
    plt.figure(figsize=(10, 6))
    sns.barplot(data=df, x=x, y=y)
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    return buf

# Ruta principal para mostrar eventos del sistema
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search')
    events = get_system_events(search_term, page)
    return render_template('index.html', events=events, page=page, search_term=search_term)

# Ruta para mostrar dispositivos bloqueados
@app.route('/blocked_devices')
def blocked_devices():
    devices = get_blocked_devices()
    return render_template('blockedDevices.html', devices=devices)

# Ruta para desbloquear un dispositivo
@app.route('/unblock_device', methods=['POST'])
def unblock():
    ip_address = request.form.get('ip_address')
    unblock_device(ip_address)
    return redirect(url_for('blocked_devices'))

# Ruta para generar y descargar reportes en PDF
@app.route('/report_pdf')
def report_pdf():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search')
    events = get_system_events(search_term, page)
    html = render_template('report_template.html', events=events)
    return render_pdf(HTML(string=html))

# Añadir host al archivo /etc/hosts
def add_host(ip_address, hostname):
    try:
        subprocess.run(['sudo', '/home/foxhound/Code/adminLogs/add_to_hosts.py', ip_address, hostname], check=True)
        return "Añadido con éxito."
    except subprocess.CalledProcessError as e:
        return f"Error al añadir: {e}"

# Ruta para mostrar el formulario de añadir host
@app.route('/add_host', methods=['GET', 'POST'])
def add_host_route():
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        hostname = request.form['hostname']
        result = add_host(ip_address, hostname)
        return render_template('add_host_result.html', result=result)
    return render_template('add_host.html')

if __name__ == '__main__':
    app.run(debug=True)
