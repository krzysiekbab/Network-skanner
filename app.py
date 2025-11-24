from flask import Flask, jsonify, request
import scapy.all as scapy
import threading
import re
import socket
import struct
import subprocess
import platform
from mac_vendor_lookup import MacLookup

app = Flask(__name__)

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
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-W' if platform.system().lower() != 'windows' else '-w'
        
        # Build command: ping -c 1 -W 1 <host>
        command = ['ping', param, '1', timeout_param, str(int(timeout * 1000)), host]
        
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
                "status": "ONLINE" # If it responded to ARP, it means it's online
            })
        return devices
    except Exception as e:
        print(f"Scapy error: {e}")
        return []

@app.route('/')
def index():
    return jsonify({"message": "Welcome to Network Monitoring API (Flask Version)"})

@app.route('/detect-network', methods=['GET'])
def detect_network():
    """
    Endpoint automatically detecting local network.
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

@app.route('/scan', methods=['POST'])
def scan_network():
    """
    Endpoint forcing network scan.
    You can provide a parameter in URL, e.g.: /scan?network=192.168.0.0/24
    """
    global discovered_devices
    
    try:
        # Get network from query parameters, default 192.168.1.0/24
        network = request.args.get('network', '192.168.1.0/24')
        
        # CIDR format validation
        if not validate_cidr(network):
            return jsonify({
                "error": "Invalid network format. Use CIDR format (e.g., 192.168.1.0/24)"
            }), 400
        
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
    Performs detailed network scan including hostname, vendor, and open ports.
    This is slower than regular scan but provides more information.
    """
    global discovered_devices
    
    try:
        # Get network from query parameters
        network = request.args.get('network', '192.168.1.0/24')
        
        # CIDR format validation
        if not validate_cidr(network):
            return jsonify({
                "error": "Invalid network format. Use CIDR format (e.g., 192.168.1.0/24)"
            }), 400
        
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
    """Returns the stored list of devices."""
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
    Iterates through the known list of devices and pings them
    to update their status and response time.
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
            # Ping (timeout 0.5s for speed)
            lat = ping_host(device['ip'], timeout=0.5)
            
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