#!/usr/bin/env python3
"""
Q-SHIELD demo attacker - run on the laptop, targets YOUR OWN demo server only.
  python3 attacker.py replay   # re-send an old, validly-signed packet
  python3 attacker.py tamper   # change status/location, keep the old signature
  python3 attacker.py flood    # burst of junk packets
  add --url http://<LAPTOP_IP>:5000 if not running on the laptop
"""
import json, random, sys, time, urllib.request

URL = "http://localhost:5000"
if "--url" in sys.argv:
    URL = sys.argv[sys.argv.index("--url") + 1]


def get(path):
    d = json.loads(urllib.request.urlopen(URL + path, timeout=3).read())
    return d.get("packets", []) if isinstance(d, dict) else d


def post(pkt):
    r = urllib.request.Request(URL + "/api/packet", json.dumps(pkt).encode(),
                               {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(r, timeout=3)
    except Exception as e:
        print("   server said:", e)   # a 4xx here means the packet was rejected - good


mode = next((a for a in sys.argv[1:] if a in ("replay", "tamper", "flood")), "replay")
sniffed = get("/api/packets")          # "attacker is listening on the channel"
if len(sniffed) < 3:
    sys.exit("not enough sniffed packets yet - let the Pi run for a few seconds first")

if mode == "replay":
    old = sniffed[-6] if len(sniffed) >= 6 else sniffed[0]
    print(f"[ATTACK] replaying captured packet seq #{old['seq']} x3")
    for _ in range(3):
        post(old); time.sleep(0.4)

elif mode == "tamper":
    p = json.loads(json.dumps(sniffed[-1]))
    p["seq"] += 1                       # fresh seq, so ONLY the signature check can catch it
    p["status"] = "OFFLINE"
    if p.get("location"):
        p["location"]["lat"] = round(p["location"]["lat"] + 0.05, 6)
    print(f"[ATTACK] tampered packet seq #{p['seq']}: status->OFFLINE, position shifted, old signature kept")
    post(p)

else:
    print("[ATTACK] flooding 60 junk packets")
    base = sniffed[-1]
    for i in range(60):
        p = json.loads(json.dumps(base))
        p["seq"] = random.randint(1, 99999)
        p["sig"] = "%064x" % random.getrandbits(256)
        post(p); time.sleep(0.05)
