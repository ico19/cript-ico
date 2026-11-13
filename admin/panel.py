"""
Cript-ico — Pannello Admin (Fase 2, MVP)
=========================================
Interfaccia web minimale per gestire il server Cript-ico:
  * crea chiavi di licenza
  * elenca chiavi + dispositivi attivati
  * blocca / sblocca chiavi
  * accoda comandi remoti (consegnati al prossimo heartbeat)

Avvio:
    pip install -r requirements.txt
    streamlit run panel.py

Il pannello parla col server SOLO tramite le stesse API /admin/* usate da
curl nel README: non ha permessi extra, e' un client come un altro.
"""
import os
from datetime import datetime, timezone

import httpx
import streamlit as st

st.set_page_config(page_title="Cript-ico Admin", page_icon="🔑", layout="wide")

# ---------- Connessione ----------
if "server" not in st.session_state:
    st.session_state.server = os.environ.get("CRIPTICO_SERVER", "http://127.0.0.1:8000")
if "token" not in st.session_state:
    st.session_state.token = os.environ.get("CRIPTICO_ADMIN_TOKEN", "")

with st.sidebar:
    st.header("Connessione")
    st.session_state.server = st.text_input("Server", st.session_state.server)
    st.session_state.token = st.text_input("Admin token", st.session_state.token, type="password")
    st.caption("Le stesse credenziali dell'header `x-admin-token` usato via curl.")
    if st.button("🔄 Aggiorna", width='stretch'):
        st.rerun()


def api(method: str, path: str, **kwargs):
    """Chiama un endpoint /admin/* e restituisce (ok, dati_o_errore)."""
    url = st.session_state.server.rstrip("/") + path
    headers = {"x-admin-token": st.session_state.token}
    try:
        r = httpx.request(method, url, headers=headers, timeout=8.0, **kwargs)
    except httpx.ConnectError:
        return False, f"Impossibile raggiungere il server ({url})"
    except Exception as e:
        return False, str(e)
    if r.status_code == 401:
        return False, "Token admin mancante o errato"
    if r.status_code >= 400:
        try:
            return False, r.json().get("detail", r.text)
        except Exception:
            return False, r.text
    return True, r.json()


def fmt_dt(iso_str: str) -> str:
    try:
        return datetime.fromisoformat(iso_str).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return iso_str


def is_expired(iso_str: str) -> bool:
    try:
        return datetime.now(timezone.utc) > datetime.fromisoformat(iso_str)
    except Exception:
        return False


st.title("🔑 Cript-ico — Pannello Admin")

if not st.session_state.token:
    st.warning("Inserisci l'admin token nella barra laterale per continuare.")
    st.stop()

# ---------- Crea nuova chiave ----------
with st.expander("➕ Crea nuova chiave", expanded=False):
    with st.form("create_key"):
        c1, c2, c3 = st.columns(3)
        product = c1.text_input("Prodotto", value="demo")
        scope = c2.selectbox("Scope", ["client", "personal"])
        label = c3.text_input("Etichetta (opzionale)")
        c4, c5 = st.columns(2)
        valid_days = c4.number_input("Validità (giorni)", min_value=1, value=30)
        max_devices = c5.number_input("Max dispositivi", min_value=1, value=1)
        submitted = st.form_submit_button("Crea chiave", type="primary")
        if submitted:
            ok, res = api("POST", "/admin/keys", json={
                "product": product, "scope": scope,
                "label": label or None,
                "valid_days": int(valid_days), "max_devices": int(max_devices),
            })
            if ok:
                st.success(f"Chiave creata: `{res['key']}` (scade {fmt_dt(res['expires_at'])})")
            else:
                st.error(res)

st.divider()

# ---------- Elenco chiavi ----------
ok, res = api("GET", "/admin/keys")
if not ok:
    st.error(res)
    st.stop()

keys = res["keys"]
st.subheader(f"Chiavi ({len(keys)})")

search = st.text_input("🔍 Filtra per chiave, prodotto o etichetta", "")
if search:
    s = search.lower()
    keys = [k for k in keys if s in k["key"].lower() or s in (k["product"] or "").lower()
            or s in (k["label"] or "").lower()]

if not keys:
    st.info("Nessuna chiave trovata.")

for k in keys:
    expired = is_expired(k["expires_at"])
    if k["status"] == "blocked":
        badge = "🔴 bloccata"
    elif expired:
        badge = "⚪ scaduta"
    else:
        badge = "🟢 attiva"

    header = f"{badge} · **{k['key']}** · {k['product']} ({k['scope']})"
    if k.get("label"):
        header += f" · _{k['label']}_"

    with st.expander(header):
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Scadenza", fmt_dt(k["expires_at"]))
        c2.metric("Dispositivi", f"{len(k['devices'])}/{k['max_devices']}")
        c3.metric("Stato", k["status"])
        c4.metric("Creata", fmt_dt(k["created_at"]))

        if k["devices"]:
            st.caption("Dispositivi registrati:")
            st.dataframe(
                [{"device_id": d["device_id"][:16] + "…",
                  "primo accesso": fmt_dt(d["first_seen"]),
                  "ultimo accesso": fmt_dt(d["last_seen"]),
                  "ultimo stato": d["last_status"]} for d in k["devices"]],
                hide_index=True, width='stretch',
            )

        b1, b2 = st.columns(2)
        if k["status"] == "active":
            if b1.button("🚫 Blocca", key=f"block_{k['key']}", width='stretch'):
                ok, r = api("POST", f"/admin/keys/{k['key']}/block")
                st.rerun() if ok else st.error(r)
        else:
            if b1.button("✅ Sblocca", key=f"unblock_{k['key']}", width='stretch'):
                ok, r = api("POST", f"/admin/keys/{k['key']}/unblock")
                st.rerun() if ok else st.error(r)

        with b2.popover("📡 Invia comando", width='stretch'):
            cmd = st.text_input("Comando", placeholder="es. pause, run:report, message:ciao",
                                 key=f"cmd_{k['key']}")
            if st.button("Accoda", key=f"send_{k['key']}"):
                if cmd:
                    ok, r = api("POST", f"/admin/keys/{k['key']}/command", json={"command": cmd})
                    if ok:
                        st.success("Comando accodato, verrà consegnato al prossimo heartbeat.")
                    else:
                        st.error(r)
                else:
                    st.warning("Scrivi un comando prima di inviarlo.")
