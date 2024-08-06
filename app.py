from flask import Flask, render_template, request, redirect, url_for, send_file
import mysql.connector
import subprocess
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
from flask_weasyprint import HTML, render_pdf
from flask import make_response

app = Flask(__name__)

# Configuración de la conexión a la base de datos
db_config = {
    'user': 'IPN',
    'password': 'tesisIPN@1234',
    'host': 'localhost',
    'database': 'logServer'
}

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

# Obtener IPs bloqueadas
def get_blocked_ips():
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor(dictionary=True)
    query = "SELECT * FROM BlockedIPs"
    cursor.execute(query)
    results = cursor.fetchall()
    cursor.close()
    connection.close()
    return results

# Desbloquear una IP
def unblock_ip(ip_address):
    command = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
    subprocess.run(command, shell=True, check=True)
    # Eliminar la IP bloqueada de la base de datos
    connection = mysql.connector.connect(**db_config)
    cursor = connection.cursor()
    delete_query = "DELETE FROM BlockedIPs WHERE ip_address = %s"
    cursor.execute(delete_query, (ip_address,))
    connection.commit()
    cursor.close()
    connection.close()

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

# Ruta para gráficos
@app.route('/plot/<plot_type>')
def plot(plot_type):
    if plot_type == 'events_per_hour':
        df = get_events_per_hour()
        buf = create_bar_plot(df, 'hour', 'count', 'Number of Events per Hour', 'Hour', 'Number of Events')
    elif plot_type == 'top_ips':
        df = get_top_suspicious_ips()
        buf = create_bar_plot(df, 'ip', 'count', 'Top Suspicious IPs', 'IP Address', 'Number of Events')
    return send_file(buf, mimetype='image/png')


# Generar reporte en formato PDF
@app.route('/report/pdf')
def report_pdf():
    events = get_system_events()
    html = render_template('report.html', events=events)
    return render_pdf(HTML(string=html))

@app.route('/blocked_ips')
def blocked_ips():
    blocked_ips = get_blocked_ips()
    return render_template('blockedIp.html', blocked_ips=blocked_ips)


# Ruta principal
@app.route('/')
def index():
    search_term = request.args.get('search')
    page = request.args.get('page', default=1, type=int)
    events = get_system_events(search_term, page)
    blocked_ips = get_blocked_ips()
    return render_template('index.html', events=events, blocked_ips=blocked_ips, page=page, search_term=search_term)


# Ruta para desbloquear una IP
@app.route('/unblock/<ip_address>')
def unblock(ip_address):
    unblock_ip(ip_address)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
