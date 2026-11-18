
# Samsung Tizen Smart TV — Inconsistent Authentication Across Services

> Samsung Tizen TVs gate remote control behind a WebSocket pairing popup on port 8001, but leave surveillance, device fingerprinting, geolocation, and app disruption completely unauthenticated across multiple other ports. Device authentication exists as a setting but is **OFF by default** and incomplete when enabled — it blocks writes but not reads, info disclosure, or app kill.

---

## Summary

Samsung Tizen smart TVs have an inconsistent authentication model. Port 8001 requires a WebSocket pairing handshake, but ports 9197, 7678, 8080, 8001 (REST), and 8002 expose UPnP state reads, device info, and DIAL app control **without any authentication**. Even when the user manually enables device authentication, reads (surveillance), info disclosure (including router BSSID geolocation), and app kill still bypass it. The setting only blocks UPnP writes and DIAL app launch.

### Findings

1. **Unauthenticated UPnP surveillance (Port 9197)** — RenderingControl and AVTransport accept SOAP read commands with no auth, no pairing, no token. An attacker on the LAN can read the current volume and mute state, query what media is playing (`GetMediaInfo`), and get the exact playback position and duration (`GetPositionInfo`). In the **default configuration** (device auth OFF), writes also work — SetVolume, SetMute, media push via `SetAVTransportURI`. When device auth is manually enabled, reads still bypass it but writes are blocked.

2. **Unauthenticated device wake (WOL)** — The TV's MAC address is leaked via SSDP M-SEARCH responses (`WAKEUP: MAC=<addr>`). An attacker can Wake-on-LAN the TV from a powered-off state, wait for port 9197 to become available, and execute Finding 1. The TV never prompts the user.

3. **Information disclosure (Ports 7678, 8001, 8002, 9080, 9197)** — Multiple services expose device identifiers without authentication, **even with device auth ON**:
   - Two distinct serial numbers (one via DIAL, one via DMR)
   - WiFi MAC address + screen mirroring P2P MAC
   - **Router BSSID** — maps to physical location via WiFi geolocation databases
   - Samsung device ID, two UUIDs, model number, internal model code
   - Netflix NRDP firmware version and build hash
   - OS version, country, language, resolution, developer mode state

4. **Unauthenticated app kill via DIAL DELETE** — DIAL DELETE stops running apps (returns 200) with no auth, **even with device auth ON**. An attacker can force-close DIAL-registered apps (Netflix, YouTube, Amazon confirmed) while the user is watching. Samsung gates app launch (POST returns 401) but leaves app kill wide open.

5. **DIAL auth bypass on port 8080 (default config only)** — Samsung runs a second DIAL server on port 8080 that bypasses the 401 auth gate on port 8001. In the **default configuration** (device auth OFF), app launch (POST) returns 201 on 8080. The server sets `Access-Control-Allow-Origin: *` and HTML form submissions omit the Origin header, enabling browser-based CSRF for app launch and app kill. When device auth is enabled, the launch bypass is blocked, but app enumeration (GET) and app kill (DELETE) still work from 8080.

---

## Why This Is Not "By Design"

Samsung explicitly treats unauthenticated device control as a security risk. The evidence:

1. **Samsung built an authentication gate.** Port 8001 WebSocket remote control requires a pairing handshake — the TV displays a popup asking "Allow this device to connect?" and the user must physically accept on the TV. An unpaired client receives `ms.channel.unauthorized` and is blocked from sending commands. Samsung intentionally built this.

2. **The capabilities overlap.** Both the WebSocket (port 8001) and UPnP (port 9197) control the same TV — volume, mute, media playback. Samsung gated one path and left the other wide open. If unauthenticated control were acceptable, the WebSocket pairing gate would not exist.

3. **UPnP exposes capabilities the WebSocket path does not.** UPnP can read what's currently playing (`GetMediaInfo`), get exact playback position, and in default config push arbitrary media URLs (`SetAVTransportURI`). The "secured" WebSocket path cannot do these things at all.

4. **The pairing popup is a user consent mechanism.** It exists so the user can decide which devices control their TV. Port 9197 bypasses this consent entirely — the user is never informed, never prompted, and has no way to block it short of network-level firewall rules.

5. **Samsung's own security model contradicts the exposure.** The REST API on port 8001 returns `"FrameTVSupport": "true"` and `"TokenAuthSupport": "true"` — Samsung's firmware explicitly references token-based authentication as a supported feature. The UPnP services ignore this entirely.

A vendor cannot argue "it's by design" when they built an authentication gate on one port and left overlapping functionality unprotected on another. The pairing gate on 8001 is Samsung's own acknowledgment that unauthenticated access is a security concern. The unprotected services on 9197 and 8080 are gaps in that model.

---

## Impact

### What works regardless of device auth setting (always unauthenticated)

| Capability | Port | Detail |
|---|---|---|
| **Surveillance** | 9197 | `GetMediaInfo` returns what's playing, `GetPositionInfo` returns exact position/duration |
| **Device fingerprinting** | 7678, 8001, 8002, 9080, 9197 | Serials, MACs, UUIDs, model, OS version, capabilities |
| **Geolocation** | 8001 | Router BSSID in REST API → physical location via WiFi geolocation DBs |
| **App kill** | 8001, 8080 | DIAL DELETE force-closes DIAL-registered apps (Netflix, YouTube, Amazon confirmed) |
| **Wake-on-LAN** | SSDP | MAC leaked in `WAKEUP` header → power on TV remotely |
| **Event subscription** | 9197 | Subscribe to state change events, TV pushes updates |

### What works only in default config (device auth OFF — the default)

| Capability | Port | Detail |
|---|---|---|
| **Volume/mute control** | 9197 | `SetVolume` (0-100), `SetMute` — bypasses WebSocket pairing on 8001 |
| **Media push** | 9197 | `SetAVTransportURI` + `Play` — push arbitrary content to screen |
| **App launch** | 8080 | DIAL POST on second server bypasses 401 on 8001, CSRF via HTML form |

### Device Authentication is OFF by Default
- Samsung offers a "Device Authentication" toggle — **it ships OFF**
- Out of the box, any LAN device gets read+write access with zero prompts
- Even when manually enabled, it only blocks writes and app launch — surveillance, info disclosure, and app kill are not covered
- Most users will never know this setting exists

### Geolocation
- REST API on port 8001 exposes `ssid` field containing the **router's BSSID**
- BSSID maps to physical location via WiFi geolocation databases (Google, Apple, WiGLE)
- Works without authentication regardless of device auth setting

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

**Set volume to 0 (default config only — blocked when device auth is ON):**
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
| **9197** | UPnP RenderingControl | **None** | Read volume/mute state (always); set volume/mute (default config only) |
| **9197** | UPnP AVTransport | **None** | Read what's playing + position (always); media push (default config only) |
| **9197** | UPnP DMR Descriptor | **None** | Serial, UUID, P2P MAC, model, ProductCap |
| **7678** | DIAL/UPnP Descriptor | **None** | Serial, Samsung device ID, model, UUID |
| **8001** | REST API `/api/v2/` | **None** | MAC, BSSID, model, UUID, OS, resolution, country, capabilities |
| **8001** | WebSocket Remote | **Pairing** | Remote control keys (the only gated service) |
| **9080** | Netflix NRDP | **None** | NRDP firmware version and build hash |
| **8080** | DIAL (second server) | **None** | DIAL-registered app launch (bypasses 8001 gate), app kill, app enumeration, CORS `*` |
| **8002** | SmartView SDK (SSL) | **None** | Same device info as 8001 over HTTPS, self-signed cert |
| **8187** | AllShare (hidden) | **N/A** | Undocumented UPnP server, not advertised via SSDP, rejects all known actions |

---


## Remediation

Samsung should:
1. Require authentication on UPnP RenderingControl and AVTransport (port 9197) — at minimum the same pairing gate used for WebSocket on 8001
2. Remove the router BSSID (`ssid` field) from the unauthenticated REST API response
3. Restrict SSDP responses to not include the device MAC in `WAKEUP` headers
4. Require authentication for the DIAL device descriptor on port 7678
5. Gate DIAL DELETE (app kill) behind the same auth as DIAL POST (app launch)
6. Remove or gate the second DIAL server on port 8080 — it bypasses the auth on 8001 entirely
7. Remove `Access-Control-Allow-Origin: *` from port 8080 responses
8. Enable device authentication **by default**, not as an opt-in setting
9. Ensure device authentication covers UPnP reads, REST API info disclosure, and event subscriptions — not just writes

### User Mitigation
- **Enable Device Authentication** in TV settings (Settings > General > External Device Manager > Device Connection Manager) — this is OFF by default
- Isolate the TV on a separate VLAN or guest network
- Block ports 9197, 8080, 8187 inbound on the TV via router firewall rules
- Disable UPnP on the router if not needed

---

## Timeline

| Date | Action |
|---|---|
| 2026-11-17 | Discovery and initial verification |
| 2026-11-18 | Findings 4-5 confirmed (DIAL app kill, 8080 auth bypass + CSRF) |
| 2026-11-18 | Device authentication bypass confirmed (default OFF, incomplete when ON) |
| TBD | Vendor notification (Samsung PSIRT) |
| TBD | CVE submission |

---

## Authors

- **NSM Barii**
- **JakeSwiz (Swiz Security)**

