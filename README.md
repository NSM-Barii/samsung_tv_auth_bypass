
# Samsung Tizen Smart TV — Authentication Bypass via Unauthenticated UPnP Services

> Samsung Tizen TVs gate remote control behind a WebSocket pairing popup on port 8001, but expose full device control (volume, mute, media playback, content injection) through unauthenticated UPnP services on port 9197 — bypassing the authentication mechanism entirely. Combined with Wake-on-LAN using a MAC address leaked via SSDP, the full attack chain works from a powered-off state with zero user interaction.

---

## Summary

Samsung Tizen smart TVs implement a pairing-based authentication gate on port 8001 for WebSocket remote control. However, the same TV exposes UPnP DLNA services (RenderingControl, AVTransport) on port 9197 that provide equivalent or greater control with **zero authentication**. Additional services on ports 7678, 8001 (REST), and 9080 leak device identifiers, serial numbers, and the connected router's BSSID (a geolocation vector) — all without authentication.

### Findings

1. **Authentication bypass via UPnP (Port 9197)** — RenderingControl and AVTransport accept SOAP commands with no auth, no pairing, no token. An attacker on the LAN can set volume (0-100), mute/unmute, push arbitrary media URLs to the TV, and control playback (play/pause/stop/seek). Samsung's WebSocket pairing gate on port 8001 is completely bypassed.

2. **Unauthenticated device wake (WOL)** — The TV's MAC address is leaked via SSDP M-SEARCH responses (`WAKEUP: MAC=<addr>`). An attacker can Wake-on-LAN the TV from a powered-off state, wait for port 9197 to become available, and execute Finding 1. The TV never prompts the user.

3. **Information disclosure (Ports 7678, 8001, 9080, 9197)** — Four separate services expose device identifiers without authentication:
   - Two distinct serial numbers (one via DIAL, one via DMR)
   - WiFi MAC address + screen mirroring P2P MAC
   - **Router BSSID** — maps to physical location via WiFi geolocation databases
   - Samsung device ID, two UUIDs, model number, internal model code
   - Netflix NRDP firmware version and build hash
   - OS version, country, language, resolution, developer mode state

---

## Why This Is Not "By Design"

Samsung explicitly treats unauthenticated device control as a security risk. The evidence:

1. **Samsung built an authentication gate.** Port 8001 WebSocket remote control requires a pairing handshake — the TV displays a popup asking "Allow this device to connect?" and the user must physically accept on the TV. An unpaired client receives `ms.channel.unauthorized` and is blocked from sending commands. Samsung intentionally built this.

2. **The capabilities overlap.** Both the WebSocket (port 8001) and UPnP (port 9197) control the same TV — volume, mute, media playback. Samsung gated one path and left the other wide open. If unauthenticated control were acceptable, the WebSocket pairing gate would not exist.

3. **UPnP provides *more* control than WebSocket.** The unauthenticated path isn't a reduced-privilege fallback — it's strictly more powerful. UPnP can push arbitrary media URLs to the screen (`SetAVTransportURI`), read what's currently playing (`GetMediaInfo`), and set exact volume levels (0-100). The "secured" WebSocket path cannot push media URLs at all.

4. **The pairing popup is a user consent mechanism.** It exists so the user can decide which devices control their TV. Port 9197 bypasses this consent entirely — the user is never informed, never prompted, and has no way to block it short of network-level firewall rules.

5. **Samsung's own security model contradicts the exposure.** The REST API on port 8001 returns `"FrameTVSupport": "true"` and `"TokenAuthSupport": "true"` — Samsung's firmware explicitly references token-based authentication as a supported feature. The UPnP services ignore this entirely.

A vendor cannot argue "it's by design" when they built an authentication mechanism for the same functionality on a different port. The existence of the pairing gate on 8001 is Samsung's own acknowledgment that unauthenticated control is a security concern. Port 9197 is a gap in that security model, not a feature.

---

## Impact

### Authentication Bypass
- Samsung implements WebSocket pairing on port 8001 — the TV displays a popup asking "Allow this device?"
- Port 9197 provides **equivalent control** with no pairing, no popup, no token
- Any device on the LAN can control the TV silently
- The user has no indication that control is occurring

### Content Injection
- `SetAVTransportURI` pushes any media URL (video, audio, image) to the TV
- Combined with `Play`, arbitrary content appears on screen with no user consent
- Attack scenario: push malicious/offensive content to a TV in a public or shared space

### Surveillance
- `GetMediaInfo` returns the URI of whatever is currently playing
- `GetPositionInfo` returns the exact playback position and duration
- An attacker can passively monitor what someone is watching

### Full Chain from Power-Off
1. SSDP M-SEARCH → TV leaks MAC address in `WAKEUP` header
2. Wake-on-LAN → TV powers on
3. `SetVolume(100)` + `SetAVTransportURI` + `Play` → blast arbitrary content
4. Zero popups, zero pairing, zero user interaction at any step

### Geolocation
- REST API on port 8001 exposes `ssid` field containing the **router's BSSID**
- BSSID can be cross-referenced with WiFi geolocation databases (Google, Apple, WiGLE) to determine the TV's physical address
- This extends the impact beyond the device itself to the household's location

---

## Affected

| Field | Value |
|---|---|
| **Vendor** | Samsung Electronics |
| **Model** | UN65AU8000FXZA (Samsung AU8000 65") |
| **Platform** | Tizen Y2021 |
| **Firmware** | Samsung-Linux/4.1, Kernel 4.1.10 |
| **REST API** | v2.0.25 |
| **Likely affected** | Other Tizen-based Samsung smart TVs exposing UPnP DMR on port 9197 |

---

## Proof of Concept

```bash
pip install requests rich
python3 poc.py --ip <SAMSUNG_IP> --scan
```

### Quick verification (curl only)

**Read volume (no auth):**
```bash
curl -s -X POST \
  -H 'Content-Type: text/xml; charset="utf-8"' \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:RenderingControl:1#GetVolume"' \
  -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel></u:GetVolume></s:Body></s:Envelope>' \
  http://<SAMSUNG_IP>:9197/upnp/control/RenderingControl1
```

**Set volume to 0 (no auth):**
```bash
curl -s -X POST \
  -H 'Content-Type: text/xml; charset="utf-8"' \
  -H 'SOAPAction: "urn:schemas-upnp-org:service:RenderingControl:1#SetVolume"' \
  -d '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>0</DesiredVolume></u:SetVolume></s:Body></s:Envelope>' \
  http://<SAMSUNG_IP>:9197/upnp/control/RenderingControl1
```

**Discover Samsung TVs on the LAN:**
```bash
python3 poc.py --discover
```

---

## Exposed Services

| Port | Service | Auth | What it leaks/controls |
|---|---|---|---|
| **9197** | UPnP RenderingControl | **None** | Volume, mute — full audio control |
| **9197** | UPnP AVTransport | **None** | Media push, play/pause/stop/seek — content injection |
| **9197** | UPnP DMR Descriptor | **None** | Serial, UUID, P2P MAC, model, ProductCap |
| **7678** | DIAL/UPnP Descriptor | **None** | Serial, Samsung device ID, model, UUID |
| **8001** | REST API `/api/v2/` | **None** | MAC, BSSID, model, UUID, OS, resolution, country, capabilities |
| **8001** | WebSocket Remote | **Pairing** | Remote control keys (the only gated service) |
| **9080** | Netflix NRDP | **None** | NRDP firmware version and build hash |

---

## Comparison: Samsung vs Roku Authentication

| Capability | Roku | Samsung |
|---|---|---|
| Remote control auth | None (by design) | WebSocket pairing on 8001 — **bypassed via 9197** |
| Volume control | Keypress only | Exact value (0-100), no auth |
| Push media to screen | No | Yes (`SetAVTransportURI`), no auth |
| Read what's playing | Active app name only | Full URI + position + duration |
| Geolocation via BSSID | No | Yes — router BSSID in REST API |
| Wake from power-off | No | Yes — WOL + leaked MAC |

---

## Remediation

Samsung should:
1. Require authentication on UPnP RenderingControl and AVTransport (port 9197) — at minimum the same pairing gate used for WebSocket on 8001
2. Remove the router BSSID (`ssid` field) from the unauthenticated REST API response
3. Restrict SSDP responses to not include the device MAC in `WAKEUP` headers
4. Require authentication for the DIAL device descriptor on port 7678

### User Mitigation
- Isolate the TV on a separate VLAN or guest network
- Block port 9197 inbound on the TV via router firewall rules
- Disable UPnP on the router if not needed

---

## Timeline

| Date | Action |
|---|---|
| 2026-11-17 | Discovery and initial verification |
| TBD | Vendor notification (Samsung PSIRT) |
| TBD | CVE submission |

---

## Author

**NSM Barii**

