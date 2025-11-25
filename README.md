# Network Scanner - REST API

REST API for network monitoring and device discovery with hostname, vendor, and port scanning capabilities.

## Quick Start

```bash
# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run
python app.py
```

Server runs at: `http://127.0.0.1:4000`

**Swagger Documentation:** `http://127.0.0.1:4000/api-docs`

---

## API Endpoints

Access interactive API documentation at: **http://127.0.0.1:4000/api-docs**

| Endpoint | Method | Purpose | Speed |
|----------|--------|---------|-------|
| `/` | GET | Welcome message | Instant |
| `/detect-network` | GET | Auto-detect local network | Instant |
| `/scan` | POST | Basic ARP scan (IP, MAC, Status) | Fast (~2-3s) |
| `/detailed-scan` | POST | Full scan + Hostname + Vendor + Ports | Slow (~30-60s) |
| `/devices` | GET | List discovered devices | Instant |
| `/monitor` | POST | Check status & latency of known devices | Fast (~5-10s) |

---

## Usage Examples

### Detect Network
```bash
curl http://127.0.0.1:4000/detect-network
```

### Basic Scan
```bash
curl -X POST "http://127.0.0.1:4000/scan"
curl -X POST "http://127.0.0.1:4000/scan?network=192.168.0.0/24"
```

### Detailed Scan (Hostname, Vendor, Ports)
```bash
curl -X POST "http://127.0.0.1:4000/detailed-scan"
curl -X POST "http://127.0.0.1:4000/detailed-scan?network=192.168.0.0/24"
```

### Monitor Devices
```bash
curl -X POST http://127.0.0.1:4000/monitor
```

### List Devices
```bash
curl http://127.0.0.1:4000/devices
```

---

## Response Examples

### Basic Scan Response
```json
{
  "message": "Scan completed",
  "count": 3,
  "network_scanned": "192.168.0.0/24",
  "devices": [
    {
      "ip": "192.168.0.1",
      "mac": "00:11:22:33:44:55",
      "status": "ONLINE"
    }
  ]
}
```

### Detailed Scan Response
```json
{
  "message": "Detailed scan completed",
  "count": 2,
  "devices": [
    {
      "ip": "192.168.0.1",
      "mac": "18:34:af:a4:c3:68",
      "status": "ONLINE",
      "hostname": "router.lan",
      "vendor": "Cisco Systems",
      "open_ports": [
        {"port": 80, "service": "HTTP"},
        {"port": 443, "service": "HTTPS"}
      ],
      "ports_count": 2
    }
  ]
}
```

---

## Workflows

**Quick Discovery:**
```bash
curl http://127.0.0.1:4000/detect-network
curl -X POST "http://127.0.0.1:4000/scan?network=192.168.0.0/24"
curl http://127.0.0.1:4000/devices
```

**Continuous Monitoring:**
```bash
while true; do
  curl -s -X POST http://127.0.0.1:4000/monitor | jq
  sleep 10
done
```

---

## Features

✅ Fast ARP network scanning  
✅ Device identification (hostname, vendor)  
✅ Port scanning (security audit)  
✅ Network auto-detection  
✅ Status monitoring with latency  
✅ Thread-safe operations  
✅ No root required (for most features)  
✅ **Interactive Swagger/OpenAPI documentation**

---

