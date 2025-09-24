from scapy.all import ARP, Ether, srp
import nmap
from mac_vendor_lookup import MacLookup
import socket
from database import update_or_create_device, init_db, log_scan_complete
import time
import sys

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
        
        try:
            log_scan_complete(scan_id, devices_found_count, duration)
        except Exception as e:
            print(f"⚠️ Failed to log scan completion: {e}")
            
        print(f"\nScan completed in {duration}.")
        print("Database update complete.")
        print(f"Total devices processed: {devices_found_count}")
        
        if devices_found_count > 0:
            print("\n✅ Scan successful! You can now view the results in your dashboard.")
        else:
            print("\n⚠️ No devices found. Check your network configuration and try again.")
