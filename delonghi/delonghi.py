import http.server
import requests
import socketserver
import json
import hmac
import hashlib
import base64
import time
from urllib.parse import urlparse, parse_qs
from Crypto.Cipher import AES
from socketserver import ThreadingMixIn
import threading
from concurrent.futures import ThreadPoolExecutor
import os

# ------------------------------
# Konstante Pfade im Add-on
# ------------------------------
APP_DIR = "/app"
KEYS_PATH = "/data/keys.json"
TOKEN_PATH = "/data/token.txt"
TOKEN_PATH = os.path.join(APP_DIR, "token.txt")
KEYS_PATH = os.path.join(APP_DIR, "keys.json")

# ------------------------------
# Server-Einstellungen
# ------------------------------
PORT = 10280
SRV_IP = "0.0.0.0"

# ------------------------------
# Globale Variablen
# ------------------------------
seq = 0
appiv = ""
rnd_1 = ""
rnd_2 = "a5rLvXXkl7CAH6db"
time_1 = ""
time_2 = "446005717073803"
lankey = ""
appCryptoKey = ""
appSignKey = ""
appIvSeed = ""
devCryptoKey = ""
devIvSeed = ""
data = "{\"seq_no\":"+str(seq)+",\"data\":{}}"
laststatus = '<meta http-equiv="refresh" content="5">'

DSN = ""
DEV_IP = ""

# ------------------------------
# Hilfsfunktionen (HMAC / AES)
# ------------------------------
def hmacForKeyAndData(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * b'\x00'
unpad = lambda s: s[:s.find(b'\x00')]

def AESencrypt(message, key, iv):
    message = message.encode()
    raw = pad(message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(raw)
    return base64.b64encode(enc).decode('utf-8')

def AESdecrypt(enc, key, iv):
    enc = base64.b64decode(enc)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    dec = cipher.decrypt(enc)
    return unpad(dec)

# ------------------------------
# Token / Keys laden
# ------------------------------
def load_keys():
    global rnd_1, time_1
    with open(KEYS_PATH, 'r') as f:
        keys_json = json.load(f)
    rnd_1 = keys_json.get("rnd_1", "")
    time_1 = str(keys_json.get("time_1", ""))

def get_refresh_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, "r") as f:
            return f.read().strip()
    return ""

def save_refresh_token(token):
    with open(TOKEN_PATH, "w") as f:
        f.write(token)

# ------------------------------
# Webserver Handler
# ------------------------------
class myHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global laststatus
        file = self.path.split('?')[0]
        if file == "/status":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(laststatus.encode('utf-8'))
        elif file == "/turn_on":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Hier kommt der Code zum Anschalten der Maschine
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    class PoolHTTPServer(ThreadingMixIn, http.server.HTTPServer):
        pool = ThreadPoolExecutor(max_workers=10)
    server = PoolHTTPServer((SRV_IP, PORT), myHandler)
    print(f"DeLonghi Controller Webserver läuft auf {SRV_IP}:{PORT}")
    server.serve_forever()

# ------------------------------
# Hauptprogramm
# ------------------------------
if __name__ == "__main__":
    print("Starte DeLonghi Controller Script...")
    load_keys()
    # Token laden (noch nicht automatisch erneuert in dieser Version)
    refresh_token = get_refresh_token()
    run_server()
