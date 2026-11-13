"""
Genera la coppia di chiavi Ed25519 del server Cript-ico.
- La chiave PRIVATA resta sul server (firma le risposte di licenza).
- La chiave PUBBLICA viene inserita nell'SDK (verifica le firme).
Esegui una volta sola:  python gen_server_keys.py
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEYS_DIR = Path(__file__).resolve().parent.parent / "keys"
KEYS_DIR.mkdir(exist_ok=True)

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
pub_pem = pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

(KEYS_DIR / "server_private.pem").write_bytes(priv_pem)
(KEYS_DIR / "server_public.pem").write_bytes(pub_pem)
print("Chiavi generate in:", KEYS_DIR)
print("  - server_private.pem  -> TIENILA SEGRETA, resta sul server")
print("  - server_public.pem   -> va copiata dentro l'SDK")
