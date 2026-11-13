"""
Cript-ico SDK (Python)
======================
Questo e' "il codice da aggiungere al tuo programma".
Fa 3 cose:
  1) VERIFICA la licenza all'avvio (chiave con scadenza) e blocca se non valida
  2) HEARTBEAT: riporta lo stato al server e riceve comandi da remoto
  3) CIFRATURA DEI DATI: helper per salvare file/dati illeggibili senza chiave

Uso minimo:
    from criptico import CriptIco
    cripto = CriptIco(server="https://tuoserver", key="CRIPTICO-....")
    cripto.require_valid_license()   # blocca qui se licenza scaduta/bloccata
    ...il tuo programma continua...

La firma delle risposte del server viene verificata con la chiave pubblica
incorporata (SERVER_PUBLIC_KEY_PEM): impedisce che un finto server o una
risposta manomessa possano sbloccare il programma.
"""
import os, sys, json, base64, hashlib, uuid, platform, time, threading
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature

# >>> INCOLLA QUI il contenuto di keys/server_public.pem <<<
SERVER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAyLO+6ngxPAXtVJiFwtNKNhYiyPEPfs/f9UJccKuPF8=
-----END PUBLIC KEY-----"""


class LicenseError(Exception):
    """Sollevata quando la licenza non e' valida (scaduta, bloccata, assente)."""


class CriptIco:
    def __init__(self, server: str, key: str, product: str | None = None,
                 public_key_pem: bytes | None = None, timeout: float = 8.0):
        self.server = server.rstrip("/")
        self.key = key
        self.product = product
        self.timeout = timeout
        pem = public_key_pem or SERVER_PUBLIC_KEY_PEM
        self._pub = serialization.load_pem_public_key(pem)
        self.device_id = self._device_id()
        self._last_license = None
        self._hb_thread = None
        self._hb_stop = threading.Event()

    # ---------- Identita' dispositivo (stabile per macchina) ----------
    def _device_id(self) -> str:
        raw = f"{platform.node()}-{uuid.getnode()}-{platform.system()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    # ---------- Verifica firma ----------
    def _verify(self, resp: dict) -> dict:
        data, sig = resp.get("data"), resp.get("signature")
        if data is None or sig is None:
            raise LicenseError("Risposta del server non firmata")
        raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        try:
            self._pub.verify(base64.b64decode(sig), raw)
        except InvalidSignature:
            raise LicenseError("Firma del server non valida (possibile manomissione)")
        return data

    # ---------- 1) Validazione licenza ----------
    def validate(self) -> dict:
        try:
            r = httpx.post(f"{self.server}/validate", timeout=self.timeout, json={
                "key": self.key, "device_id": self.device_id, "product": self.product,
            })
            r.raise_for_status()
        except Exception as e:
            raise LicenseError(f"Impossibile contattare il server licenze: {e}")
        data = self._verify(r.json())
        self._last_license = data
        return data

    def require_valid_license(self):
        """Blocca l'esecuzione se la licenza non e' valida."""
        data = self.validate()
        if not data.get("valid"):
            raise LicenseError(f"Licenza non valida: {data.get('reason', 'sconosciuto')}")
        return data

    # ---------- 2) Heartbeat + comandi ----------
    def heartbeat(self, status: str | None = None) -> dict:
        r = httpx.post(f"{self.server}/heartbeat", timeout=self.timeout, json={
            "key": self.key, "device_id": self.device_id, "status": status,
        })
        r.raise_for_status()
        return self._verify(r.json())

    def start_heartbeat(self, interval: int = 30, on_command=None, status_fn=None,
                        on_revoked=None):
        """
        Avvia un heartbeat periodico in background.
          - on_command(cmd): chiamata quando arriva un comando da remoto
          - status_fn() -> str: fornisce lo stato corrente da inviare
          - on_revoked(): chiamata se la chiave viene bloccata/scade da remoto
        """
        def loop():
            while not self._hb_stop.wait(interval):
                try:
                    st = status_fn() if status_fn else None
                    data = self.heartbeat(st)
                    if data.get("key_status") != "active" or data.get("expired"):
                        if on_revoked:
                            on_revoked()
                    cmd = data.get("command")
                    if cmd and on_command:
                        on_command(cmd)
                except Exception:
                    pass  # rete assente: non bloccare il programma, ritento al giro dopo
        self._hb_thread = threading.Thread(target=loop, daemon=True)
        self._hb_thread.start()

    def stop_heartbeat(self):
        self._hb_stop.set()

    # ---------- 3) Cifratura dati (AES-256-GCM) ----------
    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(password.encode())

    def encrypt_bytes(self, data: bytes, password: str) -> bytes:
        """Cifra dati con una password. Output = salt(16)+nonce(12)+ciphertext."""
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive(password, salt)
        ct = AESGCM(key).encrypt(nonce, data, None)
        return salt + nonce + ct

    def decrypt_bytes(self, blob: bytes, password: str) -> bytes:
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        key = self._derive(password, salt)
        return AESGCM(key).decrypt(nonce, ct, None)

    def encrypt_file(self, path, password: str, out=None):
        path = Path(path); out = Path(out) if out else path.with_suffix(path.suffix + ".enc")
        out.write_bytes(self.encrypt_bytes(path.read_bytes(), password))
        return out

    def decrypt_file(self, path, password: str, out):
        Path(out).write_bytes(self.decrypt_bytes(Path(path).read_bytes(), password))
        return out
