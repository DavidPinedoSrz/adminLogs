from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
import subprocess
import threading
import time
import socket

app = Flask(__name__)

# Configuración de la conexión a la base de datos
db_config = {
    'user': 'IPN',
    'password': 'tesisIPN@1234',
    'host': 'localhost',
    'database': 'logServer'
}

# Detectar palabras clave en los mensajes
def detect_keyword_events():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    
    malicious_keywords = ["nmap"]
    
    query = """
        SELECT FromHost as host, COUNT(*) as count
        FROM (
            SELECT FromHost, Message
            FROM SystemEvents
            ORDER BY ReceivedAt DESC
            LIMIT 2
        ) as recent_events
        WHERE {}
        GROUP BY FromHost
    """.format(' OR '.join([f"Message LIKE %s" for _ in malicious_keywords]))
    params = [f'%{keyword}%' for keyword in malicious_keywords]
    print(f"Consulta SQL: {query}")
    print(f"Parámetros: {params}")
    cursor.execute(query, params)
    
    results = cursor.fetchall()
    print(f"Resultados de la consulta: {results}")
    cursor.close()
    connection.close()
    
    # Convertir nombres de host a direcciones IP
    ip_addresses = []
    for result in results:
        host = result['host']
        try:
            ip = socket.gethostbyname(host)
            ip_addresses.append(ip)
        except socket.error:
            print(f"Error al resolver el nombre de host: {host}")
    
    return ip_addresses

# Función para analizar y bloquear IPs maliciosas
def analyze_and_block_suspicious_ips():
    server_ip = "192.168.1.102"
    suspicious_ips = detect_keyword_events()
    
    for ip_address in suspicious_ips:
        if ip_address != server_ip:
            block_device(ip_address)
        else:
            print(f"Omitiendo el bloqueo de la IP del servidor: {ip_address}")

# Llamar a esta función periódicamente
def periodic_ip_check(interval=2):  # Cambiado a 2 segundos para pruebas
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
    print(f"Intentando bloquear IP: {ip_address}")
    try:
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True, check=True)
        
        # Guardar la IP bloqueada en la base de datos
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        insert_query = "INSERT INTO BlockedDevices (ip_address, blocked_at) VALUES (%s, NOW())"
        print(f"Añadida a tabla de bloqueos IP: {ip_address}")
        cursor.execute(insert_query, (ip_address,))
        connection.commit()
        cursor.close()
        connection.close()
        print(f"Bloqueada IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando iptables: {e}")

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
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results

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
    cursor = connection.cursor(dictionary=True)
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results

# Ruta para el dashboard
@app.route('/dashboard')
def dashboard():
    events_per_hour = get_events_per_hour()
    top_ips = get_top_suspicious_ips()
    return render_template('dashboard.html', events_per_hour=events_per_hour, top_ips=top_ips)

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
