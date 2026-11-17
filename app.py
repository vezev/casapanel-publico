"""Parte pública de CasaPanel: lo que queda expuesto a internet a través del túnel.

El panel de la casa solo se ve desde la red local. Desde internet únicamente
existen el webhook de WhatsApp y las páginas que exige Meta.
"""

import hashlib
import hmac
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

# Rutas que se pueden pedir desde internet (por el túnel de Cloudflare).
RUTAS_PUBLICAS = {
    "/api/whatsapp",
    "/privacy",
    "/data-deletion",
    "/data-deletion-callback",
}


def viene_del_tunel() -> bool:
    # cloudflared corre en la misma Raspberry, así que la IP de origen es 127.0.0.1
    # y no sirve para distinguir. Se mira el host y los encabezados que agrega Cloudflare.
    host = (request.host or "").split(":", 1)[0].lower().rstrip(".")
    return (
        host.endswith(".trycloudflare.com")
        or bool(request.headers.get("CF-Ray"))
        or bool(request.headers.get("CF-Connecting-IP"))
    )


@app.before_request
def filtrar_rutas_publicas():
    # Desde internet, todo lo que no es público responde 404: ni se sabe que existe.
    if viene_del_tunel() and request.path not in RUTAS_PUBLICAS:
        return "Not Found", 404
    return None


def firma_valida(cuerpo: bytes, encabezado: str, secreto: str) -> bool:
    # Meta firma cada mensaje con HMAC-SHA256 usando el App Secret.
    # Sin el secreto no se puede fabricar una firma que coincida.
    if not secreto or not encabezado.startswith("sha256="):
        return False
    esperada = hmac.new(secreto.encode(), cuerpo, hashlib.sha256).hexdigest()
    return hmac.compare_digest(encabezado.removeprefix("sha256="), esperada)


@app.route("/api/whatsapp", methods=["GET", "POST"])
def webhook_whatsapp():
    if request.method == "GET":
        # Saludo inicial de Meta: hay que devolver el challenge si el token coincide.
        esperado = os.environ.get("WHATSAPP_VERIFY_TOKEN", "")
        if not esperado:
            # Un token vacío no puede valer como secreto.
            return "Webhook no configurado", 503
        token = request.args.get("hub.verify_token", "")
        if request.args.get("hub.mode") == "subscribe" and hmac.compare_digest(token, esperado):
            return request.args.get("hub.challenge", ""), 200
        return "Verificación fallida", 403

    # La firma se calcula sobre los bytes crudos, antes de interpretar el JSON.
    cuerpo = request.get_data()
    firma = request.headers.get("X-Hub-Signature-256", "")
    if not firma_valida(cuerpo, firma, os.environ.get("WHATSAPP_APP_SECRET", "")):
        return "Firma inválida", 403

    datos = request.get_json(force=True, silent=True) or {}
    mensajes = [
        m.get("text", {}).get("body", "")
        for entrada in datos.get("entry", [])
        for cambio in entrada.get("changes", [])
        for m in cambio.get("value", {}).get("messages", [])
        if m.get("type") == "text"
    ]
    # En CasaPanel acá el mensaje se clasifica y se guarda para el panel.
    return jsonify({"ok": True, "recibidos": len(mensajes)})


@app.route("/privacy")
def privacidad():
    return "Política de privacidad de CasaPanel."


@app.route("/data-deletion")
def borrado_de_datos():
    return "Instrucciones para pedir el borrado de datos."


@app.route("/data-deletion-callback", methods=["GET", "POST"])
def borrado_callback():
    return jsonify({"ok": True})


@app.route("/")
def panel():
    # En CasaPanel acá está el panel de la casa (privado, solo red local).
    return "Panel local"
