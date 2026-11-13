"""
Cript-ico — Server centrale (MVP)
=================================
Gestisce:
  * Prodotti e chiavi di licenza CON SCADENZA
  * Validazione firmata (Ed25519) -> l'SDK puo' fidarsi della risposta
  * Attivazione / blocco remoto delle chiavi
  * Heartbeat: il programma integrato riporta il suo stato e riceve COMANDI
  * Registro dispositivi (chi ha attivato quella chiave)

Avvio:
    python gen_server_keys.py          # una volta sola
    uvicorn main:app --host 0.0.0.0 --port 8000

Sicurezza (MVP): l'area /admin e' protetta da un token statico (ADMIN_TOKEN).
In produzione va messa dietro VPN/Intranet + HTTPS (come da tua preferenza).
"""
import os, secrets, sqlite3, json, base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import contextmanager

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

BASE = Path(__file__).resolve().parent.parent
DB_PATH = BASE / "server" / "criptico.db"
PRIV_KEY_PATH = BASE / "keys" / "server_private.pem"
ADMIN_TOKEN = os.environ.get("CRIPTICO_ADMIN_TOKEN", "admin-cambia-questo-token")

app = FastAPI(title="Cript-ico Server", version="0.1.0")

# ---------- Chiave di firma ----------
def load_signing_key() -> Ed25519PrivateKey:
    pem = PRIV_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)

SIGNING_KEY = load_signing_key()

def sign(payload: dict) -> str:
    """Firma un dict (JSON canonico) e restituisce la firma base64."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(SIGNING_KEY.sign(raw)).decode()

# ---------- Database ----------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            product TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'client',   -- 'client' (licenza venduta) o 'personal' (tuo accesso)
            label TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            max_devices INTEGER NOT NULL DEFAULT 1,
            status TEXT NOT NULL DEFAULT 'active',   -- active | blocked | revoked
            pending_command TEXT                     -- comando da consegnare al prossimo heartbeat
        );
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_status TEXT,
            UNIQUE(key, device_id)
        );
        """)

init_db()

def now():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat()

# ---------- Auth admin ----------
def require_admin(x_admin_token: str = Header(None)):
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(401, "Token admin mancante o errato")
    return True

# ---------- Modelli ----------
class CreateKey(BaseModel):
    product: str
    scope: str = "client"          # 'client' o 'personal'
    label: str | None = None
    valid_days: int = 30           # scadenza in giorni
    max_devices: int = 1

class ValidateReq(BaseModel):
    key: str
    device_id: str
    product: str | None = None

class HeartbeatReq(BaseModel):
    key: str
    device_id: str
    status: str | None = None      # info libere dal programma (es. "elaborazione 42%")

class CommandReq(BaseModel):
    command: str                   # es. "block", "pause", "run:report", "message:ciao"

# ==================================================================
#  AREA ADMIN  (tu / il pannello di controllo)
# ==================================================================
@app.post("/admin/keys", dependencies=[Depends(require_admin)])
def create_key(body: CreateKey):
    key = "CRIPTICO-" + "-".join(
        secrets.token_hex(2).upper() for _ in range(4)
    )  # es. CRIPTICO-4F2A-9C10-...
    created = now()
    expires = created + timedelta(days=body.valid_days)
    with db() as conn:
        conn.execute(
            "INSERT INTO keys (key, product, scope, label, created_at, expires_at, max_devices) "
            "VALUES (?,?,?,?,?,?,?)",
            (key, body.product, body.scope, body.label, iso(created), iso(expires), body.max_devices),
        )
    return {"key": key, "product": body.product, "scope": body.scope,
            "expires_at": iso(expires), "max_devices": body.max_devices}

@app.get("/admin/keys", dependencies=[Depends(require_admin)])
def list_keys():
    with db() as conn:
        keys = [dict(r) for r in conn.execute("SELECT * FROM keys ORDER BY created_at DESC")]
        devs = [dict(r) for r in conn.execute("SELECT * FROM devices")]
    by_key = {}
    for d in devs:
        by_key.setdefault(d["key"], []).append(d)
    for k in keys:
        k["devices"] = by_key.get(k["key"], [])
    return {"keys": keys}

@app.post("/admin/keys/{key}/block", dependencies=[Depends(require_admin)])
def block_key(key: str):
    with db() as conn:
        cur = conn.execute("UPDATE keys SET status='blocked' WHERE key=?", (key,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Chiave non trovata")
    return {"key": key, "status": "blocked"}

@app.post("/admin/keys/{key}/unblock", dependencies=[Depends(require_admin)])
def unblock_key(key: str):
    with db() as conn:
        cur = conn.execute("UPDATE keys SET status='active' WHERE key=?", (key,))
        if cur.rowcount == 0:
            raise HTTPException(404, "Chiave non trovata")
    return {"key": key, "status": "active"}

@app.post("/admin/keys/{key}/command", dependencies=[Depends(require_admin)])
def queue_command(key: str, body: CommandReq):
    """Accoda un comando: verra' consegnato al programma al prossimo heartbeat."""
    with db() as conn:
        cur = conn.execute("UPDATE keys SET pending_command=? WHERE key=?", (body.command, key))
        if cur.rowcount == 0:
            raise HTTPException(404, "Chiave non trovata")
    return {"key": key, "queued_command": body.command}

# ==================================================================
#  AREA SDK  (il programma integrato chiama questi endpoint)
# ==================================================================
@app.post("/validate")
def validate(body: ValidateReq):
    """Verifica la licenza. Risposta FIRMATA: l'SDK controlla la firma."""
    with db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key=?", (body.key,)).fetchone()
        if not row:
            return _signed({"valid": False, "reason": "chiave_inesistente"})
        row = dict(row)

        # scadenza
        expires = datetime.fromisoformat(row["expires_at"])
        if now() > expires:
            return _signed({"valid": False, "reason": "scaduta", "expires_at": row["expires_at"]})
        if row["status"] != "active":
            return _signed({"valid": False, "reason": row["status"], "key": body.key})
        if body.product and body.product != row["product"]:
            return _signed({"valid": False, "reason": "prodotto_errato"})

        # registro dispositivi + limite attivazioni
        dev = conn.execute("SELECT * FROM devices WHERE key=? AND device_id=?",
                           (body.key, body.device_id)).fetchone()
        if not dev:
            count = conn.execute("SELECT COUNT(*) c FROM devices WHERE key=?", (body.key,)).fetchone()["c"]
            if count >= row["max_devices"]:
                return _signed({"valid": False, "reason": "limite_dispositivi",
                                "max_devices": row["max_devices"]})
            conn.execute("INSERT INTO devices (key, device_id, first_seen, last_seen) VALUES (?,?,?,?)",
                         (body.key, body.device_id, iso(now()), iso(now())))
        else:
            conn.execute("UPDATE devices SET last_seen=? WHERE key=? AND device_id=?",
                         (iso(now()), body.key, body.device_id))

    return _signed({
        "valid": True,
        "key": body.key,
        "product": row["product"],
        "scope": row["scope"],
        "expires_at": row["expires_at"],
        # nonce anti-replay: cambia ad ogni risposta
        "nonce": secrets.token_hex(8),
        "server_time": iso(now()),
    })

@app.post("/heartbeat")
def heartbeat(body: HeartbeatReq):
    """Il programma riporta lo stato e riceve un eventuale comando in coda."""
    with db() as conn:
        row = conn.execute("SELECT * FROM keys WHERE key=?", (body.key,)).fetchone()
        if not row:
            raise HTTPException(404, "Chiave non trovata")
        row = dict(row)
        conn.execute(
            "UPDATE devices SET last_seen=?, last_status=? WHERE key=? AND device_id=?",
            (iso(now()), body.status, body.key, body.device_id),
        )
        command = row["pending_command"]
        conn.execute("UPDATE keys SET pending_command=NULL WHERE key=?", (body.key,))  # consegnato una volta
    # includo lo stato della chiave: cosi' il programma sa se e' stato bloccato da remoto
    return _signed({
        "key": body.key,
        "key_status": row["status"],
        "expired": now() > datetime.fromisoformat(row["expires_at"]),
        "command": command,
        "server_time": iso(now()),
    })

def _signed(payload: dict):
    return {"data": payload, "signature": sign(payload)}

@app.get("/health")
def health():
    return {"ok": True, "service": "cript-ico", "time": iso(now())}
