# Q-SHIELD — Project Documentation

**Team:** Wire_we_here · **Event:** Async 2026 · **Track:** Cybersecurity & Defense

## Overview
Q-SHIELD is a portable Raspberry Pi field gateway that collects an operative's location, movement and vitals, packages them as timestamped status packets, and sends them to a command dashboard. The goal is that command only acts on status data that is authentic, current, and still delivered when the channel is under attack, including "harvest now, decrypt later" quantum threats.

## What is used
**Hardware:** Raspberry Pi 4, NEO-6M GPS module, IMU (accelerometer/gyro), MAX-series pulse sensor, breadboard wiring, cardboard enclosure (3D-printed case planned).
**Software:** Python 3 (`smbus2`, `pyserial`), Flask command dashboard (Leaflet map, live packet feed), Wokwi for hardware simulation.
**Planned security stack:** liboqs (ML-KEM, ML-DSA), AES-256-GCM, scikit-learn Isolation Forest, LoRa backup link, SQLite logging.

## How it is made
1. **Sensing:** `qshield_gateway.py` reads GPS (serial), IMU and pulse sensor (I2C). The IMU is sampled for about a second to classify motion as STILL, MOVING or IMPACT.
2. **Status packet:** readings are fused into one JSON packet with unit ID, sequence number, UTC timestamp, location, motion, vitals, a rule-based status (ACTIVE / DISTRESS / INJURED_SUSPECTED), a priority level and a digest.
3. **Transport:** the script logs packets to `packets.jsonl` and can POST them to the dashboard's `/api/packet` endpoint.
4. **Command center:** the web dashboard shows the latest verified status, map position, motion, heart rate, a packet feed and event log. It has a demo mode that generates packets when no Pi is connected.
5. **Attack demo:** `attacker.py` replays, tampers with, or floods packets against the local demo server.

## Current status
- Working: sensor reading on the Pi, status packet generation, live dashboard, Wokwi simulation, demo video.
- Rule-based status classification (placeholder for ML).

## Still left
- Post-quantum layer: ML-KEM/ML-DSA handshake and AES-256-GCM per packet (currently unsecured or demo-key signing only).
- Replay and tamper rejection with plain-language reasons on the dashboard.
- Isolation Forest channel monitor trained on baseline vs simulated attack traffic.
- Simulated jamming and automatic LoRa failover (physical LoRa pair is optional).
- Edge injury classifier trained on public fall datasets (SisFall/MobiFall).
- 3D-printed rugged enclosure.

## How to run
```
pip install smbus2 pyserial
python3 qshield_gateway.py --fallback-loc <lat>,<lon> --post http://<DASHBOARD_IP>:5000/api/packet
python3 attacker.py replay   # or tamper / flood
```
Use `--sim` to run without hardware. GPS rarely gets a fix indoors, so use `--fallback-loc`.

## Known limitations
Jamming and LoRa are simulated for the demo; real RF jamming needs SDR hardware and is not legal to run on air. PQC and ML components are prototype-scope.

## Links
Wokwi: https://wokwi.com/projects/475881167495110657
Dashboard: https://async-2cuj.onrender.com/
Demo video: https://drive.google.com/file/d/1YaRn1F-XxA3o67vE3By7Ewt47fsZuu2M/view?usp=sharing
