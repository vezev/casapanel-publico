# casapanel-publico

CasaPanel es un panel para la casa que corre en una Raspberry Pi con Flask: recibe mensajes por
WhatsApp (API de Meta) y los muestra en una pantalla como tareas pendientes. El proyecto completo es
privado; esta es la parte que queda expuesta a internet y cómo está protegida.

## Cómo llega internet a la Raspberry

No hay puertos abiertos en el router. La Raspberry corre `cloudflared`, que abre una conexión
**saliente** hacia Cloudflare, y los pedidos de Meta entran por ahí. Así tampoco se expone la IP de
la casa, y funciona aunque el proveedor use CGNAT.

## Qué está protegido

- **Filtro del túnel:** el túnel expone toda la app, así que antes de cada pedido se revisa si vino
  por Cloudflare (host `*.trycloudflare.com` o encabezados `CF-Ray` / `CF-Connecting-IP`). Desde
  internet solo existen el webhook y las páginas legales que pide Meta; el resto responde 404.
  La IP de origen no sirve para esto: como `cloudflared` corre en la misma Raspberry, todo lo que
  viene del túnel llega desde `127.0.0.1`.
- **Saludo de Meta (GET):** se devuelve el `challenge` solo si el token coincide. Si el token no
  está configurado, no pasa nadie.
- **Firma de los mensajes (POST):** Meta firma cada mensaje con HMAC-SHA256 usando el App Secret.
  Se recalcula la firma sobre el cuerpo crudo y se compara con `hmac.compare_digest`. Un mensaje
  sin firma, con firma de otro secreto o modificado después de firmar se rechaza con 403.

Estos dos últimos puntos los agregué después de auditar la versión original, que no verificaba
la firma y aceptaba un token vacío.

## Probar

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Los tests cubren el filtro, el saludo y los casos de firma válida e inválida.
