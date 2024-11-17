from flask import Flask, render_template, request, redirect, url_for, jsonify, Response
import mysql.connector
import subprocess
import threading
import time
import socket
from flask_weasyprint import HTML, render_pdf

app = Flask(__name__)

# Configuración de la conexión a la base de datos
db_config = {
    'user': 'IPN',
    'password': 'tesisIPN@1234',
    'host': 'localhost',
    'database': 'logServer'
}

# Detectar alta frecuencia de eventos
def detect_high_frequency_events(threshold=100, period='1 MINUTE'):  # Más de 100 eventos en el último minuto
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    query = """
        SELECT FromHost as host, COUNT(*) as count
        FROM SystemEvents
        WHERE ReceivedAt >= NOW() - INTERVAL {}
        GROUP BY FromHost
        HAVING COUNT(*) > %s
    """.format(period)
    cursor.execute(query, (threshold,))
    results = cursor.fetchall()
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
    suspicious_ips = detect_high_frequency_events()

    # Devolver las IPs sospechosas detectadas por alta frecuencia de eventos
    return suspicious_ips

# Llamar a esta función periódicamente
def periodic_ip_check(interval=30):  # Cada 30 segundos
    while True:
        suspicious_ips = analyze_and_block_suspicious_ips()
        if suspicious_ips:
            # Si hay IPs sospechosas, mostrar notificación emergente
            for ip in suspicious_ips:
                # Devolver las IPs sospechosas al frontend para que el usuario decida si bloquearlas
                yield f"data: {ip}\n\n"
        time.sleep(interval)

# Iniciar el chequeo periódico en un hilo separado
thread = threading.Thread(target=periodic_ip_check, daemon=True)
thread.start()

# Ruta para obtener los eventos como JSON para actualizar la tabla sin recargar la página
@app.route('/get_events')
def get_events():
    page = request.args.get('page', 1, type=int)
    events = get_system_events(page=page)
    return jsonify({'events': events})

# Conectar a la base de datos y obtener los eventos del sistema con o sin filtro de búsqueda
# Función para obtener los eventos del sistema
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
    try:
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True, check=True)
        
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()
        insert_query = "INSERT INTO BlockedDevices (ip_address, blocked_at) VALUES (%s, NOW())"
        cursor.execute(insert_query, (ip_address,))
        connection.commit()
        cursor.close()
        connection.close()
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando iptables: {e}")

# Función para desbloquear una dirección IP
def unblock_device(ip_address):
    try:
        command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        subprocess.run(command, shell=True, check=True)
        
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

# Ruta para el dashboard
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Ruta principal para mostrar eventos del sistema
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    search_term = request.args.get('search')
    events = get_system_events(search_term, page)
    return render_template('index.html', events=events, page=page, search_term=search_term)

# Ruta para manejar el desbloqueo de dispositivos
@app.route('/unblock_device', methods=['POST'])
def unblock():
    ip_address = request.form.get('ip_address')
    unblock_device(ip_address)
    return redirect(url_for('blocked_devices'))

# Ruta para manejar el bloqueo de dispositivos
@app.route('/block_device', methods=['POST'])
def block():
    ip_address = request.form.get('ip_address')
    block_device(ip_address)
    return redirect(url_for('blocked_devices'))

# Ruta para mostrar dispositivos bloqueados
@app.route('/blocked_devices')
def blocked_devices():
    devices = get_blocked_devices()
    return render_template('blockedDevices.html', devices=devices)

# Generar reporte en formato PDF
@app.route('/report_pdf')
def report_pdf():
    events = get_system_events()
    html = render_template('report.html', events=events)
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

# Ruta para enviar las IPs sospechosas en tiempo real
@app.route('/periodic_ip_check')
def periodic_ip_check_route():
    def generate():
        while True:
            suspicious_ips = analyze_and_block_suspicious_ips()  # Obtén las IPs sospechosas
            if suspicious_ips:
                for ip in suspicious_ips:
                    yield f"data: {ip}\n\n"  # Envía cada IP sospechosa
            time.sleep(30)  # Espera 30 segundos antes de la próxima verificación
    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
