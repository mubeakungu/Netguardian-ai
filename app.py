#!/usr/bin/env python3
"""
Flask Web Application for NetGuardian AI
Fixed to work with existing and evolving database schema
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import sqlite3
import os
from datetime import datetime, timedelta
import json
import subprocess
import threading
import time

app = Flask(__name__)
app.secret_key = 'netguardian-ai-secret-key-change-in-production' # Change this!

# Configuration
DATABASE_PATH = 'network_devices.db'
DEFAULT_SUBNET = '192.168.1.0/24'

def get_db_connection():
    """Get a database connection with row factory for dictionary-like access."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"❌ Database connection error: {e}")
        return None

def init_or_update_db():
    """Initializes or updates the database schema to match the application's needs."""
    conn = get_db_connection()
    if not conn:
        return False

    try:
        # Create devices table with the intended schema if it doesn't exist
        conn.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                mac TEXT NOT NULL,
                vendor TEXT DEFAULT 'Unknown',
                os TEXT DEFAULT 'Unknown',
                hostname TEXT DEFAULT 'Unknown',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                status TEXT DEFAULT 'online'
            )
        ''')
        print("✅ Ensured 'devices' table exists.")

        # Check for and add missing columns, handling SQLite's limitations
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()}
        
        # Add missing columns with ALTER TABLE if they have a constant default
        expected_cols = {
            'is_active': 'BOOLEAN DEFAULT 1',
            'status': 'TEXT DEFAULT "online"'
        }
        
        for col, definition in expected_cols.items():
            if col not in existing_cols:
                conn.execute(f'ALTER TABLE devices ADD COLUMN {col} {definition}')
                print(f"➕ Added column '{col}' to 'devices' table.")

        # Handle 'first_seen' separately because of the non-constant default
        if 'first_seen' not in existing_cols:
            conn.execute('ALTER TABLE devices ADD COLUMN first_seen TIMESTAMP')
            print("➕ Added 'first_seen' column to 'devices' table.")
            conn.execute('UPDATE devices SET first_seen = last_seen WHERE first_seen IS NULL')
            print("🔄 Updated existing rows with a value for 'first_seen'.")

        # Create other tables as before
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                devices_found INTEGER,
                duration REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # --- FIX: Robustly create or update the alerts table schema to be consistent ---
        # First, check the existing columns in the alerts table
        alerts_cols_info = conn.execute("PRAGMA table_info(alerts)").fetchall()
        alerts_cols = {col[1] for col in alerts_cols_info}
        
        # Determine if the schema is broken (lacks device_id or has a NOT NULL on device_ip)
        is_schema_broken = 'device_id' not in alerts_cols or any(col[1] == 'device_ip' and col[3] == 1 for col in alerts_cols_info)

        if is_schema_broken:
            print("🚨 Alert schema is inconsistent. Recreating table.")
            
            # 1. Rename the old table
            conn.execute("ALTER TABLE alerts RENAME TO alerts_old")
            
            # 2. Create the new, correct alerts table
            conn.execute('''
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    device_ip TEXT,
                    alert_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    severity TEXT DEFAULT 'info',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_read BOOLEAN DEFAULT 0,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')
            
            # 3. Copy data from the old table to the new one, handling schema changes gracefully
            conn.execute('''
                INSERT INTO alerts (id, alert_type, message, severity, timestamp, is_read)
                SELECT id, alert_type, message, severity, timestamp, is_read FROM alerts_old
            ''')
            
            # 4. Drop the old table
            conn.execute("DROP TABLE alerts_old")
            print("✅ Alerts table schema fixed and data migrated.")
        else:
            print("✅ Alerts table schema is consistent.")

        conn.commit()
        print("✅ Database schema finalized.")
        return True
    
    except sqlite3.Error as e:
        print(f"❌ Database initialization error: {e}")
        return False
    finally:
        conn.close()

def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_devices():
    """Fetch all devices from the database."""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        devices = conn.execute('SELECT * FROM devices ORDER BY is_active DESC, ip').fetchall()
        
        device_list = []
        for device in devices:
            device_list.append({
                'id': device['id'],
                'ip': device['ip'],
                'mac': device['mac'],
                'vendor': device['vendor'],
                'os': device['os'],
                'hostname': device['hostname'],
                'last_seen': device['last_seen'],
                'first_seen': device['first_seen'],
                'is_active': bool(device['is_active']),
                'status': device['status']
            })
        
        return device_list
    except sqlite3.Error as e:
        print(f"❌ Error fetching devices: {e}")
        return []
    finally:
        conn.close()

def get_network_stats():
    """Get comprehensive network statistics."""
    conn = get_db_connection()
    if not conn:
        return {}
    
    try:
        stats = {}
        
        stats['total_devices'] = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        stats['active_devices'] = conn.execute('SELECT COUNT(*) FROM devices WHERE is_active = 1').fetchone()[0]
        stats['offline_devices'] = conn.execute('SELECT COUNT(*) FROM devices WHERE is_active = 0').fetchone()[0]
        
        vendor_data = conn.execute('''
            SELECT COALESCE(vendor, 'Unknown') as vendor, COUNT(*) as count
            FROM devices
            GROUP BY vendor
            ORDER BY count DESC
        ''').fetchall()
        stats['vendor_distribution'] = [{'vendor': row['vendor'], 'count': row['count']} for row in vendor_data]

        os_data = conn.execute('''
            SELECT COALESCE(os, 'Unknown') as os, COUNT(*) as count
            FROM devices
            GROUP BY os
            ORDER BY count DESC
        ''').fetchall()
        stats['os_distribution'] = [{'os': row['os'], 'count': row['count']} for row in os_data]
        
        # Provide placeholder data for performance metrics until they can be measured
        stats['avg_latency'] = 100 # Mock value
        stats['avg_throughput'] = 50 # Mock value
        stats['avg_jitter'] = 5 # Mock value
        stats['avg_bandwidth'] = 25 # Mock value
        
        return stats
    except sqlite3.Error as e:
        print(f"❌ Error getting network stats: {e}")
        return {}
    finally:
        conn.close()

def get_alerts():
    """Get recent alerts with device info."""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        alerts = conn.execute('''
            SELECT a.id, a.alert_type, a.message, a.severity, a.is_read, a.timestamp,
                   d.ip as ip_address, d.hostname
            FROM alerts a
            LEFT JOIN devices d ON a.device_id = d.id
            ORDER BY a.timestamp DESC
            LIMIT 20
        ''').fetchall()
        
        alert_list = []
        for alert in alerts:
            alert_list.append({
                'id': alert['id'],
                'ip_address': alert['ip_address'],
                'hostname': alert['hostname'],
                'alert_type': alert['alert_type'],
                'message': alert['message'],
                'severity': alert['severity'],
                'timestamp': alert['timestamp'],
                'is_read': bool(alert['is_read'])
            })
        
        return alert_list
    except sqlite3.Error as e:
        print(f"❌ Error getting alerts: {e}")
        return []
    finally:
        conn.close()

def run_network_scan(subnet):
    """Run network scan using main.py and log the result to the DB."""
    try:
        conn = get_db_connection()
        scan_id = conn.execute('SELECT COALESCE(MAX(scan_id), 0) + 1 FROM scan_logs').fetchone()[0]
        
        print(f"🔍 Starting network scan on {subnet} (ID: {scan_id})")
        
        result = subprocess.run(
            ['python3', 'main.py', subnet, str(scan_id)],
            capture_output=True,
            text=True,
            timeout=300 # 5 minute timeout
        )
        
        if result.returncode == 0:
            print(f"✅ Network scan completed successfully.")
            # Log success as a regular alert that the dashboard can read
            conn.execute('INSERT INTO alerts (alert_type, message, severity, device_id, device_ip) VALUES (?, ?, ?, ?, ?)',
                         ('Scan Complete', f'Network scan on {subnet} finished successfully.', 'info', None, None))
            conn.commit()
            return True, "Scan completed."
        else:
            print(f"❌ Network scan failed: {result.stderr}")
            # Log failure as an alert
            conn.execute('INSERT INTO alerts (alert_type, message, severity, device_id, device_ip) VALUES (?, ?, ?, ?, ?)',
                         ('Scan Failure', f'Network scan on {subnet} failed. Error: {result.stderr}', 'error', None, None))
            conn.commit()
            return False, result.stderr
    except subprocess.TimeoutExpired:
        print("⏰ Network scan timed out.")
        conn.execute('INSERT INTO alerts (alert_type, message, severity, device_id, device_ip) VALUES (?, ?, ?, ?, ?)',
                     ('Scan Timeout', f'Network scan on {subnet} timed out after 5 minutes.', 'warning', None, None))
        conn.commit()
        return False, "Scan timed out after 5 minutes."
    except Exception as e:
        print(f"❌ Error running network scan: {e}")
        conn.execute('INSERT INTO alerts (alert_type, message, severity, device_id, device_ip) VALUES (?, ?, ?, ?, ?)',
                     ('System Error', f'An internal error occurred during scan: {e}', 'error', None, None))
        conn.commit()
        return False, str(e)
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'netguardian':
            session['logged_in'] = True
            session['username'] = username
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials! Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    """Main dashboard."""
    devices = get_devices()
    stats = get_network_stats()
    alerts = get_alerts()
    
    current_time = datetime.now().strftime('%H:%M:%S')
    
    return render_template('dashboard.html', 
                          devices=devices, 
                          stats=stats,
                          alerts=alerts,
                          username=session.get('username', 'User'),
                          current_time=current_time)

@app.route('/scan', methods=['POST'])
@login_required
def trigger_scan():
    """Trigger a network scan via the web form."""
    subnet = request.form.get('subnet', DEFAULT_SUBNET)
    
    def scan_thread_target():
        run_network_scan(subnet)
        
    thread = threading.Thread(target=scan_thread_target)
    thread.daemon = True
    thread.start()
    
    flash(f'🔍 Network scan started on {subnet}. This may take a few minutes...', 'info')
    return redirect(url_for('dashboard'))

# API Routes
@app.route('/api/devices')
@login_required
def api_devices():
    """API: Get all devices."""
    return jsonify(get_devices())

@app.route('/api/stats')
@login_required
def api_stats():
    """API: Get network statistics."""
    return jsonify(get_network_stats())

@app.route('/api/alerts')
@login_required
def api_alerts():
    """API: Get alerts."""
    return jsonify(get_alerts())

@app.route('/api/refresh')
@login_required
def api_refresh():
    """API: Refresh all data."""
    return jsonify({
        'devices': get_devices(),
        'stats': get_network_stats(),
        'alerts': get_alerts(),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/scan', methods=['POST'])
@login_required
def api_scan():
    """API: Trigger network scan."""
    data = request.get_json()
    subnet = data.get('subnet', DEFAULT_SUBNET) if data else DEFAULT_SUBNET
    
    success, output = run_network_scan(subnet)
    
    return jsonify({
        'success': success,
        'message': output,
        'subnet': subnet,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected' if get_db_connection() else 'disconnected'
    })

def main():
    """Main function to run the Flask application."""
    print("🚀 Initializing NetGuardian AI Web Application...")
    
    if not init_or_update_db():
        print("❌ Failed to initialize database. Exiting.")
        return
    
    devices = get_devices()
    if len(devices) == 0:
        print("ℹ️ No devices found in database.")
        print("💡 Tip: Run 'python main.py 192.168.1.0/24 1' to perform your first network scan.")
    else:
        print(f"✅ Found {len(devices)} devices in database")
    
    print("\n" + "="*60)
    print("🌐 NetGuardian AI Dashboard Starting...")
    print("📊 Web Interface: http://localhost:5000")
    print("🔑 Login: admin / netguardian")
    print("📖 Features:")
    print("    • 🔐 Secure login system")
    print("    • 📊 Real-time network dashboard")
    print("    • 🔍 Web-based network scanning")
    print("    • 📱 Mobile-responsive design")
    print("    • 🚨 Security alerts monitoring")
    print("    • 📈 Interactive charts and statistics")
    print("="*60)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        print("\n👋 NetGuardian AI Dashboard stopped.")
    except Exception as e:
        print(f"❌ Error starting Flask app: {e}")

if __name__ == "__main__":
    main()
