#!/usr/bin/env python3
"""
Standalone Network Security Monitor
Combines device discovery, traffic analysis, and intrusion detection
Fully integrated with your NetGuardian AI database schema.
"""

from scapy.all import ARP, Ether, srp, sniff, TCP, IP
import nmap
from mac_vendor_lookup import MacLookup
import socket
import time
import sys
import threading
import signal
from collections import defaultdict
from datetime import datetime

# Try to import database functions
try:
    from database import (
        update_or_create_device as db_update,
        init_db,
        log_scan_complete,
        create_alert,
        get_db_session,
        Device,
        mark_offline_devices,
        detect_conflicts
    )
    HAS_DATABASE = True
    print("✅ Database module loaded")
except ImportError as e:
    print(f"⚠️ Database module not available: {e}")
    print("ℹ️ Running in standalone mode without database logging")
    HAS_DATABASE = False

# Global variables
connection_attempts = defaultdict(list)
arp_table = {}

class StandaloneNetworkMonitor:
    def __init__(self, subnet="192.168.1.0/24", scan_interval=300):
        self.subnet = subnet
        self.scan_interval = scan_interval
        self.scan_id = 1
        self.running = False
        self.scan_thread = None
        self.packet_thread = None
        self.devices = {}  # In-memory storage
        self.has_database = HAS_DATABASE

        print("=== NetGuardian AI - Standalone Network Security Monitor ===")
        print(f"Target subnet: {subnet}")
        print(f"Active scan interval: {scan_interval} seconds")

        if self.has_database:
            try:
                init_db()
                print("✅ Database initialized successfully.")
            except Exception as e:
                print(f"❌ Database initialization failed: {e}")
                self.has_database = False

    def create_alert_safe(self, ip, alert_type, message, severity):
        """
        Create alert safely.
        Links to device_id if IP exists in DB.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert_msg = f"[{timestamp}] {severity.upper()}: {message}"
        print(f"🚨 {alert_msg}")

        device_id = None
        hostname = "Unknown"

        if self.has_database and ip:
            try:
                db_session = get_db_session()
                device = db_session.query(Device).filter(
                    (Device.ip == ip) | (Device.ip_address == ip)
                ).first()
                if device:
                    device_id = device.id
                    hostname = device.hostname or "Unknown"
            except Exception as e:
                print(f"⚠️ Could not find device_id for IP {ip}: {e}")

        if self.has_database:
            try:
                create_alert(device_id, alert_type, message, severity)
            except Exception as e:
                print(f"⚠️ Failed to log alert to database: {e}")

        if not self.has_database or device_id is None:
            print(f"🚨 [Standalone] Alert for IP: {ip}, Hostname: {hostname}, Type: {alert_type}, Severity: {severity}, Message: {message}")

    def detect_port_scan(self, pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == 2:  # SYN
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                dst_port = pkt[TCP].dport
                now = datetime.now()

                connection_attempts[src_ip].append((dst_ip, dst_port, now))

                recent_attempts = [t for t in connection_attempts[src_ip] 
                                   if (now - t[2]).total_seconds() < 5]

                if len(recent_attempts) > 10:
                    self.create_alert_safe(
                        src_ip,
                        "port_scan",
                        f"Possible port scan from {src_ip} targeting {dst_ip}",
                        "warning"
                    )

                connection_attempts[src_ip] = recent_attempts

    def detect_arp_spoof(self, pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc

            if ip in arp_table and arp_table[ip] != mac:
                self.create_alert_safe(
                    ip,
                    "arp_spoofing",
                    f"ARP spoofing detected: {ip} is claimed by {mac} (previously {arp_table[ip]})",
                    "error"
                )
            else:
                arp_table[ip] = mac

    def packet_handler(self, pkt):
        try:
            self.detect_port_scan(pkt)
            self.detect_arp_spoof(pkt)
        except Exception:
            pass

    def update_device_safe(self, ip, mac, os=None, hostname=None, vendor=None):
        device_info = {
            'ip': ip,
            'mac': mac,
            'os': os or 'Unknown',
            'hostname': hostname or 'Unknown',
            'vendor': vendor or 'Unknown',
            'last_seen': datetime.now(),
            'is_new': False
        }

        if self.has_database:
            try:
                db_session = get_db_session()
                device = db_session.query(Device).filter(
                    (Device.ip == ip) | (Device.ip_address == ip)
                ).first()
                if device:
                    device.mac = mac
                    device.os = os or device.os
                    device.hostname = hostname or device.hostname
                    device.vendor = vendor or device.vendor
                    device.last_seen = datetime.now()
                    db_session.commit()
                else:
                    db_update({
                        'ip': ip,
                        'mac': mac,
                        'os': os,
                        'hostname': hostname,
                        'vendor': vendor
                    })
            except Exception as e:
                print(f"⚠️ Database update failed for {ip}: {e}")
        else:
            if ip not in self.devices:
                device_info['is_new'] = True
                print(f"🆕 New device detected: {ip} ({mac}) - {hostname}")
            self.devices[ip] = device_info

    def get_devices(self, subnet):
        print(f"🔍 Starting ARP scan on {subnet}...")
        arp_request = ARP(pdst=subnet)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        try:
            answered, _ = srp(packet, timeout=3, verbose=False)
        except Exception as e:
            print(f"❌ ARP scan failed: {e}")
            return []

        devices = []
        try:
            mac_lookup = MacLookup()
        except Exception:
            mac_lookup = None
            print("⚠️ MAC vendor lookup not available")

        ip_list = [recv.psrc for _, recv in answered]
        nmap_results = {}

        if ip_list:
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=",".join(ip_list), ports='22,23,80,443,135,445,3389', arguments='-T4 --host-timeout 10s')
                for ip in ip_list:
                    if ip in nm.all_hosts():
                        nmap_results[ip] = nm[ip]
            except Exception as e:
                print(f"⚠️ Nmap scan failed: {e}")
                nmap_results = {}

        for _, recv in answered:
            ip = recv.psrc
            mac = recv.hwsrc
            vendor = "Unknown"
            if mac_lookup:
                try:
                    vendor = mac_lookup.lookup(mac)
                except Exception:
                    vendor = "Unknown"
            os_info = self.detect_os_simple(ip, nmap_results)
            hostname = self.get_hostname(ip)
            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "os": os_info,
                "hostname": hostname
            })

        return devices

    def detect_os_simple(self, ip, nmap_results):
        if ip not in nmap_results:
            return "Unknown"
        try:
            if 'tcp' in nmap_results[ip]:
                open_ports = [port for port, info in nmap_results[ip]['tcp'].items() if info['state'] == 'open']
                if any(port in open_ports for port in [135,445,3389]): return "Windows"
                if 22 in open_ports: return "Linux/Unix"
                if 23 in open_ports: return "Network Device"
        except (KeyError, AttributeError):
            return "Unknown"
        return "Unknown"

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.error:
            return "Unknown"

    def mark_offline_devices_safe(self, active_ips):
        if self.has_database:
            try:
                mark_offline_devices(active_ips)
                return
            except ImportError:
                pass
        current_time = datetime.now()
        for ip, device in self.devices.items():
            if ip not in active_ips:
                time_diff = (current_time - device['last_seen']).total_seconds()
                if time_diff > 300:
                    print(f"📴 Device {ip} ({device['hostname']}) went offline")

    def detect_conflicts_safe(self):
        if self.has_database:
            try:
                detect_conflicts()
                return
            except ImportError:
                pass
        ip_macs = {}
        mac_ips = {}
        for ip, device in self.devices.items():
            mac = device['mac']
            if mac in mac_ips and mac_ips[mac] != ip:
                print(f"⚠️ MAC conflict: {mac} used by {ip} and {mac_ips[mac]}")
            mac_ips[mac] = ip
            if ip in ip_macs and ip_macs[ip] != mac:
                print(f"⚠️ IP conflict: {ip} used by {mac} and {ip_macs[ip]}")
            ip_macs[ip] = mac

    def active_scan_loop(self):
        while self.running:
            try:
                print(f"\n🔄 Running active scan #{self.scan_id} on {self.subnet}...")
                start_time = time.time()
                devices = self.get_devices(self.subnet)
                active_ips = [d['ip'] for d in devices]

                for device in devices:
                    self.update_device_safe(
                        ip=device["ip"],
                        mac=device["mac"],
                        os=device.get("os"),
                        hostname=device.get("hostname"),
                        vendor=device.get("vendor")
                    )

                self.mark_offline_devices_safe(active_ips)
                self.detect_conflicts_safe()

                duration = f"{time.time() - start_time:.2f} seconds"
                if self.has_database:
                    try:
                        log_scan_complete(self.scan_id, len(devices), duration)
                    except Exception as e:
                        print(f"⚠️ Failed to log scan completion: {e}")

                print(f"✅ Active scan #{self.scan_id} completed in {duration}. Next scan in {self.scan_interval}s.")
                self.scan_id += 1

                for _ in range(self.scan_interval):
                    if not self.running: break
                    time.sleep(1)
            except Exception as e:
                print(f"❌ Active scan failed: {e}")
                if self.running:
                    time.sleep(30)

    def passive_monitor_loop(self):
        print("🚨 Starting real-time packet monitoring...")
        try:
            sniff(prn=self.packet_handler, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"❌ Packet monitoring failed: {e}")
            print("ℹ️ Run as root/admin for packet capture")

    def start_monitoring(self):
        self.running = True
        print("\n🚀 Starting monitoring...")
        self.scan_thread = threading.Thread(target=self.active_scan_loop, daemon=True)
        self.scan_thread.start()
        self.packet_thread = threading.Thread(target=self.passive_monitor_loop, daemon=True)
        self.packet_thread.start()
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping monitoring...")
            self.stop_monitoring()

    def stop_monitoring(self):
        self.running = False
        print("✅ Network security monitoring stopped.")

def main():
    subnet = "192.168.1.0/24"
    scan_interval = 300
    if len(sys.argv) >= 2: subnet = sys.argv[1]
    if len(sys.argv) >= 3:
        try: scan_interval = int(sys.argv[2])
        except ValueError: print("⚠️ Invalid scan interval. Using default (300s).")

    monitor = StandaloneNetworkMonitor(subnet, scan_interval)
    signal.signal(signal.SIGINT, lambda s,f: (monitor.stop_monitoring(), sys.exit(0)))
    monitor.start_monitoring()

if __name__ == "__main__":
    main()


