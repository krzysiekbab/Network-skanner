from flask import Flask, jsonify, request
import scapy.all as scapy
import threading
import re
import socket
import struct
import subprocess
import platform
from mac_vendor_lookup import MacLookup
from flasgger import Swagger

app = Flask(__name__)

# Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/api-docs"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Network Scanner REST API",
        "description": "REST API for network monitoring and device discovery with hostname, vendor, and port scanning capabilities.",
        "version": "1.0.0",
        "contact": {
            "name": "Network Scanner API"
        }
    },
    "schemes": ["http"],
    "tags": [
        {
            "name": "Network Discovery",
            "description": "Endpoints for network detection and device scanning"
        },
        {
            "name": "Device Management",
            "description": "Endpoints for managing and monitoring discovered devices"
        }
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

# Global variable to store scan results in RAM
discovered_devices = []
devices_lock = threading.Lock()

def validate_cidr(network):
    """
    Validates CIDR format correctness (e.g., 192.168.1.0/24).
    """
    cidr_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    if not re.match(cidr_pattern, network):
        return False
    
    # Check octet and mask ranges
    try:
        ip_part, mask_part = network.split('/')
        octets = [int(x) for x in ip_part.split('.')]
        mask = int(mask_part)
        
        if not all(0 <= octet <= 255 for octet in octets):
            return False
        if not 0 <= mask <= 32:
            return False
        return True
    except (ValueError, AttributeError):
        return False

def ping_host(host, timeout=1):
    """
    Pings a host and returns the latency in seconds, or None if unreachable.
    Uses system ping command (no root privileges required).
    """
    try:
        # Determine ping command based on OS
        system = platform.system().lower()
        
        if system == 'windows':
            # Windows: -n count, -w timeout_in_ms
            command = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), host]
        elif system == 'darwin':
            # macOS: -c count, -W timeout_in_ms, -t timeout_in_seconds
            command = ['ping', '-c', '1', '-W', str(int(timeout * 1000)), host]
        else:
            # Linux: -c count, -W timeout_in_seconds
            command = ['ping', '-c', '1', '-W', str(int(timeout)), host]
        
        # Execute ping
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout + 1
        )
        
        # Check if ping was successful
        if result.returncode == 0:
            # Parse output to extract time
            output = result.stdout.decode('utf-8')
            
            # Try to extract time from output (works for macOS/Linux)
            if 'time=' in output:
                time_str = output.split('time=')[1].split()[0]
                time_ms = float(time_str)
                return time_ms / 1000.0  # Convert to seconds
            else:
                # If we can't parse time, just return a small value to indicate success
                return 0.001
        else:
            return None
    except Exception as e:
        print(f"Ping error for {host}: {e}")
        return None

def get_hostname(ip):
    """
    Performs reverse DNS lookup to get hostname from IP address.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None

def get_vendor(mac):
    """
    Looks up the vendor/manufacturer from MAC address using OUI database.
    """
    try:
        mac_lookup = MacLookup()
        vendor = mac_lookup.lookup(mac)
        return vendor
    except Exception:
        return None

def scan_common_ports(ip, ports=None, timeout=0.3):
    """
    Scans common ports on a given IP address.
    Returns list of open ports with service names.
    """
    if ports is None:
        # Common ports to scan
        ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
    
    port_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = port_services.get(port, "Unknown")
                open_ports.append({
                    "port": port,
                    "service": service
                })
            sock.close()
        except Exception:
            pass
    
    return open_ports

def detect_local_network():
    """
    Detects local network based on network interface.
    Returns network address in CIDR format (e.g., 192.168.0.0/24).
    """
    try:
        # Create socket to find local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Get network mask for interface (assuming /24 as default)
        # In a more advanced version, you can use netifaces or psutil
        ip_parts = local_ip.split('.')
        network_address = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
        
        return {
            "local_ip": local_ip,
            "network": network_address,
            "netmask": "255.255.255.0",
            "cidr": 24
        }
    except Exception as e:
        return None

def perform_arp_scan(ip_range):
    """
    Function performing ARP scan using Scapy.
    Returns a list of dictionaries with IP and MAC.
    """
    try:
        # Create ARP Request packet
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send and receive (verbose=0 disables console logs)
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in answered_list:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "status": "ONLINE"
            })
        return devices
    except Exception as e:
        print(f"Scapy error: {e}")
        return []

def get_network_info():
    """
    Gathers detailed network information including interface details,
    gateway, DNS servers, and network speed.
    """
    try:
        network_info = {}
        
        # Get local IP and basic network info
        local_network = detect_local_network()
        if local_network:
            network_info.update(local_network)
        
        # Get default gateway
        try:
            if platform.system().lower() == 'darwin' or platform.system().lower() == 'linux':
                result = subprocess.run(['route', '-n', 'get', 'default'], 
                                      capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'gateway:' in line.lower():
                        network_info['gateway'] = line.split(':')[1].strip()
                    elif 'interface:' in line.lower():
                        network_info['interface'] = line.split(':')[1].strip()
            elif platform.system().lower() == 'windows':
                result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                      capture_output=True, text=True, timeout=2)
                # Parse Windows route output for gateway
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and '0.0.0.0' in line.split()[0]:
                        parts = line.split()
                        if len(parts) >= 3:
                            network_info['gateway'] = parts[2]
        except Exception as e:
            print(f"Gateway detection error: {e}")
        
        # Get DNS servers
        try:
            dns_servers = []
            if platform.system().lower() == 'darwin':
                result = subprocess.run(['scutil', '--dns'], 
                                      capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line.lower():
                        dns = line.split(':')[1].strip() if ':' in line else line.split()[-1]
                        if dns and dns not in dns_servers:
                            dns_servers.append(dns)
            elif platform.system().lower() == 'linux':
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns = line.split()[1]
                            dns_servers.append(dns)
            elif platform.system().lower() == 'windows':
                result = subprocess.run(['ipconfig', '/all'], 
                                      capture_output=True, text=True, timeout=2)
                for line in result.stdout.split('\n'):
                    if 'DNS Servers' in line:
                        dns = line.split(':')[1].strip()
                        dns_servers.append(dns)
            
            network_info['dns_servers'] = dns_servers[:3] if dns_servers else []
        except Exception as e:
            print(f"DNS detection error: {e}")
            network_info['dns_servers'] = []
        
        # Test internet speed (ping to gateway and external)
        try:
            gateway_ip = network_info.get('gateway', '8.8.8.8')
            gateway_latency = ping_host(gateway_ip, timeout=2)
            network_info['gateway_latency_ms'] = round(gateway_latency * 1000, 2) if gateway_latency else None
            
            # Ping external (Google DNS)
            external_latency = ping_host('8.8.8.8', timeout=2)
            network_info['internet_latency_ms'] = round(external_latency * 1000, 2) if external_latency else None
            network_info['internet_status'] = 'Connected' if external_latency else 'Disconnected'
        except Exception as e:
            print(f"Speed test error: {e}")
        
        # Get hostname
        try:
            network_info['hostname'] = socket.gethostname()
        except Exception:
            pass
        
        # Get MAC address of primary interface
        try:
            if 'interface' in network_info:
                if platform.system().lower() == 'darwin' or platform.system().lower() == 'linux':
                    result = subprocess.run(['ifconfig', network_info['interface']], 
                                          capture_output=True, text=True, timeout=2)
                    for line in result.stdout.split('\n'):
                        if 'ether' in line.lower() or 'hwaddr' in line.lower():
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if ':' in part and len(part) == 17:
                                    network_info['interface_mac'] = part
                                    break
        except Exception as e:
            print(f"MAC detection error: {e}")
        
        return network_info
    except Exception as e:
        print(f"Network info error: {e}")
        return None

@app.route('/')
def index():
    """
    Welcome message
    ---
    tags:
      - Network Discovery
    responses:
      200:
        description: Welcome message
        examples:
          application/json:
            message: "Welcome to Network Monitoring API (Flask Version)"
    """
    return jsonify({"message": "Welcome to Network Monitoring API (Flask Version)"})

@app.route('/detect-network', methods=['GET'])
def detect_network():
    """
    Auto-detect local network
    ---
    tags:
      - Network Discovery
    responses:
      200:
        description: Network info (local_ip, network, netmask, cidr)
        examples:
          application/json:
            message: "Network detected successfully"
            local_ip: "192.168.0.100"
            network: "192.168.0.0/24"
            netmask: "255.255.255.0"
            cidr: 24
            info: "Use this range in /scan?network=192.168.0.0/24"
      500:
        description: Detection failed
    """
    try:
        network_info = detect_local_network()
        
        if network_info is None:
            return jsonify({
                "error": "Failed to detect local network"
            }), 500
        
        return jsonify({
            "message": "Network detected successfully",
            "local_ip": network_info["local_ip"],
            "network": network_info["network"],
            "netmask": network_info["netmask"],
            "cidr": network_info["cidr"],
            "info": "Use this range in /scan?network=" + network_info["network"]
        })
    except Exception as e:
        return jsonify({
            "error": "An error occurred while detecting network",
            "details": str(e)
        }), 500

@app.route('/network-info', methods=['GET'])
def network_info():
    """
    Detailed network information (gateway, DNS, speed, interface)
    ---
    tags:
      - Network Discovery
    responses:
      200:
        description: Comprehensive network information
        examples:
          application/json:
            local_ip: "192.168.0.100"
            network: "192.168.0.0/24"
            netmask: "255.255.255.0"
            cidr: 24
            gateway: "192.168.0.1"
            interface: "en0"
            interface_mac: "a4:83:e7:5f:2e:c1"
            hostname: "Mac.local"
            dns_servers: ["192.168.0.1", "8.8.8.8"]
            gateway_latency_ms: 2.34
            internet_latency_ms: 15.67
            internet_status: "Connected"
      500:
        description: Failed to get network info
    """
    try:
        info = get_network_info()
        
        if info is None:
            return jsonify({
                "error": "Failed to retrieve network information"
            }), 500
        
        return jsonify(info)
    except Exception as e:
        return jsonify({
            "error": "An error occurred while retrieving network info",
            "details": str(e)
        }), 500

@app.route('/scan', methods=['POST'])
def scan_network():
    """
    Basic ARP scan (IP, MAC, Status) - Auto-detects network
    ---
    tags:
      - Network Discovery
    responses:
      200:
        description: Devices found with IP, MAC, status
        examples:
          application/json:
            message: "Scan completed"
            count: 3
            network_scanned: "192.168.0.0/24"
            devices:
              - ip: "192.168.0.1"
                mac: "00:11:22:33:44:55"
                status: "ONLINE"
              - ip: "192.168.0.10"
                mac: "aa:bb:cc:dd:ee:ff"
                status: "ONLINE"
      500:
        description: Network detection failed
    """
    global discovered_devices
    
    try:
        # Auto-detect network
        network_info = detect_local_network()
        if not network_info:
            return jsonify({
                "error": "Failed to detect local network"
            }), 500
        
        network = network_info['network']
        
        print(f"Scanning network: {network}...")
        results = perform_arp_scan(network)
        
        # Update global list in a thread-safe manner
        with devices_lock:
            discovered_devices = results
        
        return jsonify({
            "message": "Scan completed",
            "count": len(results),
            "network_scanned": network,
            "devices": results
        })
    except Exception as e:
        return jsonify({
            "error": "An error occurred during scanning",
            "details": str(e)
        }), 500

@app.route('/detailed-scan', methods=['POST'])
def detailed_scan():
    """
    Full scan + Hostname + Vendor + Ports (slower) - Auto-detects network
    ---
    tags:
      - Network Discovery
    responses:
      200:
        description: Devices with hostname, vendor, open ports
        examples:
          application/json:
            message: "Detailed scan completed"
            count: 2
            network_scanned: "192.168.0.0/24"
            devices:
              - ip: "192.168.0.1"
                mac: "18:34:af:a4:c3:68"
                status: "ONLINE"
                hostname: "router.lan"
                vendor: "Cisco Systems"
                open_ports:
                  - port: 80
                    service: "HTTP"
                  - port: 443
                    service: "HTTPS"
                ports_count: 2
              - ip: "192.168.0.10"
                mac: "b8:27:eb:12:34:56"
                status: "ONLINE"
                hostname: "raspberrypi.local"
                vendor: "Raspberry Pi Foundation"
                open_ports:
                  - port: 22
                    service: "SSH"
                ports_count: 1
      500:
        description: Network detection failed
    """
    global discovered_devices
    
    try:
        # Auto-detect network
        network_info = detect_local_network()
        if not network_info:
            return jsonify({
                "error": "Failed to detect local network"
            }), 500
        
        network = network_info['network']
        
        print(f"Performing detailed scan on network: {network}...")
        
        # First, perform ARP scan
        basic_results = perform_arp_scan(network)
        
        # Enhance results with additional information
        detailed_results = []
        for device in basic_results:
            ip = device['ip']
            mac = device['mac']
            
            # Get hostname
            print(f"  Resolving hostname for {ip}...")
            hostname = get_hostname(ip)
            
            # Get vendor
            print(f"  Looking up vendor for {mac}...")
            vendor = get_vendor(mac)
            
            # Scan ports
            print(f"  Scanning ports on {ip}...")
            open_ports = scan_common_ports(ip)
            
            detailed_results.append({
                "ip": ip,
                "mac": mac,
                "status": device['status'],
                "hostname": hostname,
                "vendor": vendor,
                "open_ports": open_ports,
                "ports_count": len(open_ports)
            })
        
        # Update global list
        with devices_lock:
            discovered_devices = detailed_results
        
        return jsonify({
            "message": "Detailed scan completed",
            "count": len(detailed_results),
            "network_scanned": network,
            "devices": detailed_results
        })
    except Exception as e:
        return jsonify({
            "error": "An error occurred during detailed scanning",
            "details": str(e)
        }), 500

@app.route('/devices', methods=['GET'])
def get_devices():
    """
    List discovered devices
    ---
    tags:
      - Device Management
    responses:
      200:
        description: Array of discovered devices
        examples:
          application/json:
            - ip: "192.168.0.1"
              mac: "00:11:22:33:44:55"
              status: "ONLINE"
              hostname: "router.lan"
              vendor: "Cisco Systems"
            - ip: "192.168.0.10"
              mac: "aa:bb:cc:dd:ee:ff"
              status: "ONLINE"
              hostname: null
              vendor: "Apple Inc."
      404:
        description: No devices (scan first)
    """
    try:
        with devices_lock:
            if not discovered_devices:
                return jsonify({
                    "message": "No devices found. Perform a scan first (/scan)"
                }), 404
            return jsonify(discovered_devices)
    except Exception as e:
        return jsonify({
            "error": "An error occurred while retrieving devices",
            "details": str(e)
        }), 500

@app.route('/monitor', methods=['POST'])
def monitor_devices():
    """
    Check status & latency of known devices
    ---
    tags:
      - Device Management
    responses:
      200:
        description: Devices with updated status and latency
        examples:
          application/json:
            - ip: "192.168.0.1"
              mac: "00:11:22:33:44:55"
              status: "ONLINE"
              latency_ms: 2.45
              hostname: "router.lan"
              vendor: "Cisco Systems"
            - ip: "192.168.0.10"
              mac: "aa:bb:cc:dd:ee:ff"
              status: "OFFLINE"
              latency_ms: null
              hostname: null
              vendor: "Apple Inc."
      400:
        description: No devices (scan first)
    """
    global discovered_devices
    
    try:
        with devices_lock:
            if not discovered_devices:
                return jsonify({
                    "message": "Perform a scan first (/scan), the list is empty."
                }), 400
            
            # Create a copy to work with
            devices_to_check = discovered_devices.copy()
        
        updated_devices = []
        for device in devices_to_check:
            # Ping (timeout 1s - some devices block ICMP)
            lat = ping_host(device['ip'], timeout=1)
            
            if lat is None:
                device['status'] = "OFFLINE"
                device['latency_ms'] = None
            else:
                device['status'] = "ONLINE"
                device['latency_ms'] = round(lat * 1000, 2)
            
            updated_devices.append(device)
        
        # Update global list in a thread-safe manner
        with devices_lock:
            discovered_devices = updated_devices
        
        return jsonify(updated_devices)
    except Exception as e:
        return jsonify({
            "error": "An error occurred during monitoring",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    # Run the application on all interfaces (0.0.0.0)
    app.run(debug=True, host='0.0.0.0', port=4000)