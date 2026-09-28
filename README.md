# Q-SHIELD Command Center

**Secure field-to-command status system — prototype dashboard**

A single-page tactical dashboard that receives, stores, and visualises real-time status packets from field units. Built with Flask (Python) and vanilla JavaScript. Runs fully offline on any laptop.

---

## Quick Start

```bash
# 1. Install dependencies (only Flask)
pip install -r requirements.txt

# 2. Run the server
python app.py
```

Open **http://localhost:5000** in any browser.

### Demo Mode

Click the **DEMO** toggle in the top bar — the server will generate a simulated packet every 2 seconds (Ladakh LAC Border Sector coordinates, random walk, occasional DISTRESS and INJURED_SUSPECTED events). No Raspberry Pi needed.

---

## How the Pi Posts Packets

On the field unit, the `sender.py` script (or equivalent) sends a `POST` request to this server:

```python
import requests, json, time, hashlib, hmac

SERVER = "http://<COMMAND_IP>:5000"
SESSION_KEY = "qshield-demo-session-key"

packet = {
    "unit_id": "UNIT_01",
    "seq": 42,
    "ts": "2025-01-15T10:30:00Z",
    "location": {
        "fix": True,
        "lat": 33.7548,
        "lon": 78.6834,
        "sats": 10,
        "src": "GPS"        # GPS | MANUAL | SIM
    },
    "motion": {
        "state": "MOVING",   # STILL | MOVING | IMPACT
        "accel_g": 1.12,
        "peak_g": 1.45
    },
    "vitals": {
        "finger": True,
        "bpm": 82
    },
    "status": "ACTIVE",      # ACTIVE | DISTRESS | INJURED_SUSPECTED
    "priority": "ROUTINE",   # ROUTINE | HIGH | CRITICAL
    "security": {
        "mode": "HMAC-SHA256",
        "note": "ML-KEM planned — using pre-shared demo key"
    },
    "digest": ""
}

# Calculate HMAC-SHA256 signature
canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"))
packet["sig"] = hmac.new(SESSION_KEY.encode(), canonical.encode(), hashlib.sha256).hexdigest()

resp = requests.post(f"{SERVER}/api/packet", json=packet)
print(resp.json())
```

The server stamps `server_rx` time and computes a SHA-256 digest (placeholder for PQC signature verification).

---

## API Endpoints

| Method | Path               | Description                                   |
|--------|--------------------|-----------------------------------------------|
| POST   | `/api/packet`      | Submit a status packet (JSON body)            |
| GET    | `/api/packets`     | Return all stored packets (up to 200)         |
| GET    | `/api/latest`      | Return the most recent packet                 |
| GET    | `/api/events`      | Return event log entries                      |
| POST   | `/api/demo/start`  | Start demo packet generator (every 2 s)       |
| POST   | `/api/demo/stop`   | Stop demo packet generator                    |
| GET    | `/api/demo/status` | Check if demo mode is running                 |

---

## Packet Schema

```json
{
    "unit_id": "UNIT_01",
    "seq": 1,
    "ts": "ISO-8601 timestamp",
    "location": {
        "fix": true,
        "lat": 33.7548,
        "lon": 78.6834,
        "sats": 10,
        "src": "GPS"
    },
    "motion": {
        "state": "STILL | MOVING | IMPACT",
        "accel_g": 1.0,
        "peak_g": 1.2
    },
    "vitals": {
        "finger": true,
        "bpm": 78
    },
    "status": "ACTIVE | DISTRESS | INJURED_SUSPECTED",
    "priority": "ROUTINE | HIGH | CRITICAL",
    "security": {
        "mode": "PLAINTEXT",
        "note": "..."
    },
    "digest": "sha256-hex-16-chars"
}
```

---

## Project Structure

```
├── app.py                  # Flask backend (all endpoints + demo generator)
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── index.html          # Single-page dashboard
└── static/
    ├── style.css           # Dark tactical theme
    └── app.js              # Frontend logic (polling, charts, animations)
```

---

## Placeholder Hooks (code only, not visible in UI)

- `app.py` line with `# PQC verify here` — future post-quantum signature verification
- `app.py` line with `# ML anomaly score here` — future ML-based anomaly detection
- Security panel in UI shows **upcoming features** clearly labelled

---

## Offline Operation

- **Map**: Leaflet loads OpenStreetMap tiles. If offline, the map automatically falls back to a coordinate grid showing lat/lon as text.
- **Fonts**: Google Fonts are loaded for typography; if offline, system monospace and sans-serif fonts are used as fallback.
- **No other external dependencies** — everything else is self-contained.

---

## License

Internal prototype — not for public distribution.
