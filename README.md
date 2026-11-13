# 🔐 Cript-ico

**Universal licensing, protection and remote-control layer that can be embedded into any application.**

Cript-ico lets a developer drop a small SDK into an existing program and immediately gain expiring license keys, signed validation, data encryption and remote management — without rewriting the application.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=flat-square&logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=flat-square&logo=sqlite&logoColor=white)
![Ed25519](https://img.shields.io/badge/Signatures-Ed25519-555?style=flat-square)
![AES-256-GCM](https://img.shields.io/badge/Encryption-AES--256--GCM-555?style=flat-square)

---

## ✨ Features

| Area | Capability |
|---|---|
| 🔑 **Licensing** | License keys with expiry date — `client` scope (sold licenses) or `personal` scope (own access) |
| ✍️ **Signed validation** | Every server response is signed with **Ed25519** and verified by the SDK: a fake server or a tampered response cannot unlock the program |
| 🛑 **Remote control** | Remote block/unblock of any key, live status reporting, remote commands delivered on the next heartbeat |
| 💓 **Heartbeat** | Background check-in thread; the host app is notified if its license is revoked or expired |
| 💻 **Device limits** | Per-key device registry with a maximum number of activations |
| 🔒 **Data encryption** | **AES-256-GCM** with **scrypt** key derivation for files and data produced by the protected program |
| 🖥️ **Admin panel** | Streamlit web panel to create keys, inspect devices, block/unblock and queue commands |

## 🏗️ Architecture

```
┌──────────────────────┐        HTTPS · signed responses        ┌──────────────────────────┐
│  Protected program   │ ─────────────────────────────────────▶ │   Cript-ico server       │
│  + Cript-ico SDK     │ ◀───────────────────────────────────── │   FastAPI + SQLite       │
│                      │   heartbeat · commands · lock/unlock   │   keys · devices         │
└──────────────────────┘                                        └────────────▲─────────────┘
                                                                             │ /admin API
                                                                ┌────────────┴─────────────┐
                                                                │  Admin panel (Streamlit) │
                                                                └──────────────────────────┘
```

```
cript-ico/
├── server/              Central server (FastAPI)
│   ├── main.py
│   └── gen_server_keys.py   Generates the Ed25519 signing key pair
├── sdk/python/          The code you add to your programs
│   └── criptico.py
├── admin/               Streamlit admin panel
│   └── panel.py
└── examples/
    └── demo_app.py      Sample program integrating the SDK
```

## 🚀 Quick start

```bash
# 1) Generate your own signing keys (stored in keys/, never committed)
cd server
python gen_server_keys.py
#    then paste keys/server_public.pem into sdk/python/criptico.py (SERVER_PUBLIC_KEY_PEM)

# 2) Install and start the server
pip install -r requirements.txt
export CRIPTICO_ADMIN_TOKEN=your-secret-token        # Windows: set CRIPTICO_ADMIN_TOKEN=...
uvicorn main:app --host 0.0.0.0 --port 8000

# 3) Create a license key
curl -X POST http://127.0.0.1:8000/admin/keys \
  -H "x-admin-token: your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"product":"demo","valid_days":30,"max_devices":1}'

# 4) Run the demo app with the key you received
cd ../examples
python demo_app.py CRIPTICO-XXXX-XXXX-XXXX-XXXX

# 5) (optional) Start the admin panel
cd ../admin
pip install -r requirements.txt
streamlit run panel.py
```

### Integrating the SDK

```python
from criptico import CriptIco, LicenseError

cripto = CriptIco(server="https://your-server", key="CRIPTICO-....", product="demo")
cripto.require_valid_license()                      # stops here if expired / blocked
cripto.start_heartbeat(interval=30,
                       on_command=lambda cmd: print("remote command:", cmd),
                       on_revoked=lambda: exit(1))
blob = cripto.encrypt_bytes(b"secret data", password="...")
```

## ⚠️ Security notes

- `keys/server_private.pem` must stay **secret** and only on the server — it is excluded from this repository.
- In production, run the server behind **HTTPS** and, ideally, a **VPN/intranet**.
- The MVP `/admin` area uses a static token: replace it with real authentication before production use.
- Anti-copy protection raises the cost of piracy considerably, but no client-side system can make copying 100% impossible.

## 🗺️ Roadmap

- [x] **Phase 1 – MVP core**: FastAPI server, expiring keys, Ed25519-signed validation, remote lock, heartbeat + commands, device limits, Python SDK, AES-256-GCM encryption
- [x] **Phase 2 (in progress)**: Streamlit admin panel
- [ ] SDKs for additional languages
- [ ] Code obfuscation / anti-tamper hardening
- [ ] Advanced remote control, audit log, high availability

## 📄 License

© Federico Murgese — All rights reserved.
