# 🔐 Cript-ico

**Universal licensing, protection and remote-control layer that can be embedded into any application.**

Cript-ico lets a developer drop a small SDK into an existing program and immediately gain expiring license keys, signed validation, data encryption and remote management — without rewriting the application.

---

## ✨ Features

| Area | Capability |
|---|---|
| 🔑 **Licensing** | Generation of access keys with expiry date, for selling licenses to customers or for personal access |
| ✍️ **Signed validation** | License checks signed with **Ed25519**, so responses cannot be forged by the client |
| 🛑 **Remote control** | Remote lock/unlock of any installation, live status, remote commands |
| 💓 **Heartbeat** | Periodic check-in of every installation with the central server |
| 💻 **Device limits** | Maximum number of devices per license |
| 🔒 **Data encryption** | **AES-256** encryption of the data handled by the protected program |

## 🏗️ Architecture

```
┌──────────────────────┐        HTTPS / signed responses        ┌──────────────────────────┐
│  Protected program   │ ─────────────────────────────────────▶ │   Cript-ico server       │
│  + Cript-ico SDK     │ ◀───────────────────────────────────── │   (FastAPI)              │
│                      │   heartbeat · commands · lock/unlock   │   keys · devices · audit │
└──────────────────────┘                                        └──────────────────────────┘
```

- **Server** — Python / FastAPI: key issuance and expiry, Ed25519 signing, device registry, heartbeat and command queue.
- **SDK** — one lightweight client library per language (Python first) that the host program calls at startup and periodically.

## 🛠️ Tech stack

![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![Ed25519](https://img.shields.io/badge/Signatures-Ed25519-555?style=flat-square)
![AES-256](https://img.shields.io/badge/Encryption-AES--256-555?style=flat-square)

## 🗺️ Roadmap

- [x] **Phase 1 – MVP core**: FastAPI server, expiring keys, Ed25519-signed validation, remote lock, heartbeat + commands, device limits, Python SDK, AES-256 data encryption
- [ ] Admin dashboard for license and device management
- [ ] SDKs for additional languages
- [ ] Code-protection hardening against unauthorized copies

## 📄 License

© Federico Murgese — All rights reserved.
