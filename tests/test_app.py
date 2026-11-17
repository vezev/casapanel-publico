import hashlib
import hmac
import json

import pytest

from app import app

SECRETO = "secreto-de-prueba"
TOKEN = "token-de-prueba"
DESDE_TUNEL = {"CF-Ray": "abc123"}


@pytest.fixture
def cliente(monkeypatch):
    monkeypatch.setenv("WHATSAPP_APP_SECRET", SECRETO)
    monkeypatch.setenv("WHATSAPP_VERIFY_TOKEN", TOKEN)
    return app.test_client()


def firmar(cuerpo: bytes, secreto: str = SECRETO) -> str:
    return "sha256=" + hmac.new(secreto.encode(), cuerpo, hashlib.sha256).hexdigest()


MENSAJE = json.dumps({
    "entry": [{"changes": [{"value": {"messages": [
        {"type": "text", "text": {"body": "Falta comprar pan"}}
    ]}}]}]
}).encode()


# --- Filtro del túnel ---

def test_panel_visible_desde_la_red_local(cliente):
    assert cliente.get("/").status_code == 200


def test_panel_oculto_desde_el_tunel(cliente):
    assert cliente.get("/", headers=DESDE_TUNEL).status_code == 404


def test_panel_oculto_por_host_de_cloudflare(cliente):
    respuesta = cliente.get("/", base_url="https://algo.trycloudflare.com")
    assert respuesta.status_code == 404


def test_paginas_legales_visibles_desde_el_tunel(cliente):
    assert cliente.get("/privacy", headers=DESDE_TUNEL).status_code == 200


# --- Saludo de Meta (GET) ---

def test_saludo_con_token_correcto(cliente):
    r = cliente.get("/api/whatsapp?hub.mode=subscribe&hub.verify_token=token-de-prueba&hub.challenge=123")
    assert r.status_code == 200 and r.data == b"123"


def test_saludo_con_token_incorrecto(cliente):
    r = cliente.get("/api/whatsapp?hub.mode=subscribe&hub.verify_token=otro&hub.challenge=123")
    assert r.status_code == 403


def test_saludo_sin_token_configurado_no_pasa(cliente, monkeypatch):
    monkeypatch.delenv("WHATSAPP_VERIFY_TOKEN")
    r = cliente.get("/api/whatsapp?hub.mode=subscribe&hub.challenge=123")
    assert r.status_code == 503


# --- Mensajes (POST) ---

def test_mensaje_con_firma_valida(cliente):
    r = cliente.post("/api/whatsapp", data=MENSAJE, headers={**DESDE_TUNEL, "X-Hub-Signature-256": firmar(MENSAJE)})
    assert r.status_code == 200 and r.get_json()["recibidos"] == 1


def test_mensaje_sin_firma_rechazado(cliente):
    r = cliente.post("/api/whatsapp", data=MENSAJE, headers=DESDE_TUNEL)
    assert r.status_code == 403


def test_mensaje_firmado_con_otro_secreto_rechazado(cliente):
    r = cliente.post("/api/whatsapp", data=MENSAJE, headers={"X-Hub-Signature-256": firmar(MENSAJE, "secreto-falso")})
    assert r.status_code == 403


def test_mensaje_modificado_despues_de_firmar_rechazado(cliente):
    firma = firmar(MENSAJE)
    alterado = MENSAJE.replace(b"pan", b"vino")
    r = cliente.post("/api/whatsapp", data=alterado, headers={"X-Hub-Signature-256": firma})
    assert r.status_code == 403
