# database.py

from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# ------------------------
# Database Configuration
# ------------------------

DATABASE_FILE = "netguardian.db"
engine = create_engine(f'sqlite:///{DATABASE_FILE}', echo=False)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ------------------------
# Models
# ------------------------

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    alerts = relationship("Alert", back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    mac_address = Column(String, unique=True, nullable=True)
    hostname = Column(String, nullable=True)
    vendor = Column(String, nullable=True)
    os_info = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    status = Column(String, default="online")

    alerts = relationship("Alert", back_populates="device")
    scans = relationship("ScanHistory", back_populates="device")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    alert_type = Column(String, index=True)
    message = Column(String)
    severity = Column(String, default="info")  # info, warning, error
    is_read = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")


class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, unique=True, nullable=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    target_subnet = Column(String)
    devices_found = Column(Integer, default=0)
    duration = Column(String, nullable=True)
    status = Column(String, default="in_progress")  # in_progress, completed, failed
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)

    device = relationship("Device", back_populates="scans")


# ------------------------
# Utility Functions
# ------------------------

def init_db():
    """Create database tables if they don't exist."""
    Base.metadata.create_all(bind=engine)
    print("Database and tables created or already exist.")


def get_db_session():
    """Get a new database session."""
    return SessionLocal()


def update_or_create_device(device_data):
    """
    Updates an existing device or creates a new one.
    device_data should be a dictionary with keys: ip, mac, hostname, vendor, os
    """
    db = get_db_session()
    try:
        # Step 1: Check if device exists by MAC address
        device = db.query(Device).filter_by(mac_address=device_data.get('mac')).first()

        if device:
            # Step 2: Detect IP change
            if device.ip_address != device_data.get('ip'):
                create_alert(
                    device_id=device.id,
                    alert_type="ip_change",
                    message=f"Device {device.mac_address} changed IP from {device.ip_address} to {device_data.get('ip')}",
                    severity="warning"
                )
                print(f"IP change detected for {device.mac_address}")

            # Step 3: Update existing device
            device.ip_address = device_data.get('ip')
            device.hostname = device_data.get('hostname')
            device.vendor = device_data.get('vendor')
            device.os_info = device_data.get('os')
            device.last_seen = datetime.utcnow()
            device.is_active = True
            device.status = "online"
            db.commit()
            print(f"Updated device: {device.ip_address} ({device.mac_address})")
        else:
            # Step 4: Create new device
            new_device = Device(
                ip_address=device_data.get('ip'),
                mac_address=device_data.get('mac'),
                hostname=device_data.get('hostname'),
                vendor=device_data.get('vendor'),
                os_info=device_data.get('os'),
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                is_active=True,
                status="online"
            )
            db.add(new_device)
            db.commit()
            print(f"Created new device: {new_device.ip_address} ({new_device.mac_address})")

            # Create alert for new device
            create_alert(
                device_id=new_device.id,
                alert_type="device_new",
                message=f"New device discovered: {new_device.ip_address}",
                severity="info"
            )

    except Exception as e:
        db.rollback()
        print(f"Error updating/creating device: {e}")
    finally:
        db.close()


def log_scan_complete(scan_id, devices_found, duration):
    """Log scan completion to database."""
    db = get_db_session()
    try:
        # Check if scan record already exists
        scan_record = db.query(ScanHistory).filter_by(scan_id=scan_id).first()
        
        if scan_record:
            # Update existing record
            scan_record.completed_at = datetime.utcnow()
            scan_record.devices_found = devices_found
            scan_record.duration = duration
            scan_record.status = "completed"
        else:
            # Create new scan record
            new_scan = ScanHistory(
                scan_id=scan_id,
                start_time=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                devices_found=devices_found,
                duration=duration,
                status="completed"
            )
            db.add(new_scan)
        
        db.commit()
        print(f"Scan {scan_id} logged to database")
    except Exception as e:
        db.rollback()
        print(f"Error logging scan completion: {e}")
    finally:
        db.close()


def create_alert(user_id=None, device_id=None, alert_type=None, message=None, severity="info"):
    """Create a new alert in the database."""
    db = get_db_session()
    try:
        new_alert = Alert(
            user_id=user_id,
            device_id=device_id,
            alert_type=alert_type,
            message=message,
            severity=severity
        )
        db.add(new_alert)
        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error creating alert: {e}")
    finally:
        db.close()


def create_default_user():
    """Create default admin user if none exists."""
    from werkzeug.security import generate_password_hash
    db = get_db_session()
    try:
        if not db.query(User).filter_by(username="admin").first():
            default_user = User(
                username="admin",
                email="admin@netguardian.ai",
                hashed_password=generate_password_hash("admin123"),
                is_admin=True
            )
            db.add(default_user)
            db.commit()
            print("Default admin user created")
    except Exception as e:
        db.rollback()
        print(f"Error creating default user: {e}")
    finally:
        db.close()


# ------------------------
# Initialize DB if missing
# ------------------------

if not os.path.exists(DATABASE_FILE):
    init_db()
    create_default_user()

# --- 1. Device Discovery (ARP Scan) ---
def get_devices(subnet):
    """
    Performs an ARP scan to discover devices on the local network.
    Returns a list of dictionaries, each representing a discovered device.
    """
    print(f"Starting ARP scan on {subnet}...")
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    try:
        answered, _ = srp(packet, timeout=3, verbose=False)
    except Exception as e:
        print(f"ARP scan failed: {e}")
        return []
    
    devices = []
    mac_lookup = MacLookup()
    
    print("Running a simple port scan for OS detection...")
    ip_list = [received.psrc for _, received in answered]
    nmap_results = {}
    
    if ip_list:
        try:
            nm = nmap.PortScanner()
            ip_range = ",".join(ip_list)
            # Scan for common ports to guess OS
            nm.scan(hosts=ip_range, ports='22,23,80,443,135,445,3389', arguments='-T4 --host-timeout 10s')
            nmap_results = nm.all_hosts()
        except Exception as e:
            print(f"Nmap scan failed: {e}")
            nmap_results = {}
    
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        
        vendor = "Unknown"
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown"
        
        os_info = detect_os_simple(ip, nmap_results)
        
        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "os": os_info,
            "hostname": get_hostname(ip)
        })
    
    return devices

def detect_os_simple(ip, nmap_results):
    """Simple OS detection based on open ports."""
    if ip not in nmap_results:
        return "Unknown"
    
    try:
        if 'tcp' in nmap_results[ip]:
            open_ports = [port for port, info in nmap_results[ip]['tcp'].items() if info['state'] == 'open']
            
            if 135 in open_ports or 445 in open_ports or 3389 in open_ports:
                return "Windows"
            if 22 in open_ports:
                return "Linux/Unix"
            if 23 in open_ports:
                return "Network Device"
    except KeyError:
        return "Unknown"
    
    return "Unknown"

def get_hostname(ip):
    """Attempts to get the hostname of a device."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.error:
        return "Unknown"

def mark_offline_devices_safe(active_ips):
    """Mark devices as offline if they weren't found in this scan (optional monitoring function)."""
    try:
        # Try to import from traffic_monitor module
        from traffic_monitor import mark_offline_devices
        print("🔍 Checking for offline devices...")
        mark_offline_devices(active_ips)
    except ImportError:
        print("ℹ️ traffic_monitor module not available - skipping offline device detection")
    except Exception as e:
        print(f"⚠️ Error marking offline devices: {e}")

def detect_conflicts_safe():
    """Detect IP/MAC conflicts if traffic_monitor module is available."""
    try:
        # Try to import from traffic_monitor module  
        from traffic_monitor import detect_conflicts
        print("🔍 Checking for conflicts...")
        detect_conflicts()
    except ImportError:
        print("ℹ️ traffic_monitor module not available - skipping conflict detection")
    except Exception as e:
        print(f"⚠️ Error detecting conflicts: {e}")

def monitoring_update_safe(device):
    """Update device using traffic_monitor module if available."""
    try:
        # Try to import from traffic_monitor module
        from traffic_monitor import update_or_create_device as monitoring_update
        monitoring_update(
            ip=device["ip"],
            mac=device["mac"], 
            os=device.get("os"),
            hostname=device.get("hostname")
        )
    except ImportError:
        # traffic_monitor module not available, just continue
        pass
    except Exception as e:
        print(f"⚠️ Traffic monitor update failed for {device['ip']}: {e}")

# --- Main Execution Block ---
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python main.py <subnet> <scan_id>")
        print("Example: python main.py 192.168.1.0/24 1")
        sys.exit(1)
        
    target_subnet = sys.argv[1]
    scan_id = int(sys.argv[2])
    
    print("=== Network Discovery Tool ===")
    
    try:
        init_db()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Database initialization failed: {e}")
        sys.exit(1)
    
    start_time = time.time()
    print(f"\nStarting network scan on {target_subnet}...")
    
    devices_found_count = 0
    try:
        discovered_devices = get_devices(target_subnet)
        
        if not discovered_devices:
            print("No devices found on the network. Check your subnet and connectivity.")
        else:
            print(f"\nDiscovered {len(discovered_devices)} devices.")
            print("Processing and storing device information...")
            
            active_ips = []
            
            for i, device in enumerate(discovered_devices, 1):
                print(f"Storing device {i}/{len(discovered_devices)}: {device['ip']}")
                
                # Use database module for basic storage
                update_or_create_device(device)
                
                # Try to use traffic_monitor module for advanced features if available
                monitoring_update_safe(device)
                
                active_ips.append(device['ip'])
                devices_found_count += 1
            
            # Optional monitoring functions (only if traffic_monitor module is available)
            mark_offline_devices_safe(active_ips)
            detect_conflicts_safe()
    
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Scan failed with error: {e}")
    finally:
        end_time = time.time()
        duration = f"{end_time - start_time:.2f} seconds"
        
        # Only try to log scan completion if function is available
        if HAS_SCAN_LOGGING:
            try:
                log_scan_complete(scan_id, devices_found_count, duration)
                print("Scan results logged to database.")
            except Exception as e:
                print(f"Warning: Failed to log scan completion: {e}")
        else:
            print("Scan logging not available - results stored but not logged.")
            
        print(f"\nScan completed in {duration}.")
        print("Database update complete.")
        print(f"Total devices processed: {devices_found_count}")
        
        if devices_found_count > 0:
            print("\n✅ Scan successful! You can now view the results in your dashboard.")
        else:
            print("\n⚠️ No devices found. Check your network configuration and try again.")
