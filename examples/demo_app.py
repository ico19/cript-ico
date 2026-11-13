"""
Programma DEMO che integra Cript-ico.
Mostra come "aggiungere il codice di Cript-ico" a un programma qualsiasi.
"""
import sys, time
sys.path.insert(0, "../sdk/python")   # in produzione: pip install del pacchetto SDK
from criptico import CriptIco, LicenseError

SERVER = "http://127.0.0.1:8000"
KEY = sys.argv[1] if len(sys.argv) > 1 else "CRIPTICO-XXXX"

cripto = CriptIco(server=SERVER, key=KEY, product="demo")

# --- 1) Blocco all'avvio se licenza non valida ---
try:
    lic = cripto.require_valid_license()
    print(f"[Cript-ico] Licenza OK. Scade il {lic['expires_at']} (scope: {lic['scope']})")
except LicenseError as e:
    print(f"[Cript-ico] ACCESSO NEGATO -> {e}")
    sys.exit(1)

# --- 2) Reagisci ai comandi remoti + blocco remoto ---
def on_command(cmd):
    print(f"[Cript-ico] Comando ricevuto da remoto: {cmd!r}")

def on_revoked():
    print("[Cript-ico] La licenza e' stata BLOCCATA da remoto. Chiusura.")
    sys.exit(1)

cripto.start_heartbeat(interval=5, on_command=on_command,
                       status_fn=lambda: "in esecuzione", on_revoked=on_revoked)

# --- 3) Cifratura dati prodotti dal programma ---
segreto = b"Dati riservati del cliente"
blob = cripto.encrypt_bytes(segreto, password=KEY)   # cifra con la licenza come password
print(f"[Cript-ico] Dati cifrati ({len(blob)} byte, illeggibili senza chiave)")
print(f"[Cript-ico] Decifrati: {cripto.decrypt_bytes(blob, password=KEY)!r}")

print("Il programma e' in esecuzione. (Ctrl+C per uscire)")
try:
    while True:
        time.sleep(2)
except KeyboardInterrupt:
    cripto.stop_heartbeat()
