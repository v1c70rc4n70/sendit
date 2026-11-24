#!/usr/bin/env python3
"""sendit — pasa un archivo, texto o comandos a otra maquina.

Sin daemon: cada invocacion hace una entrega y termina.
Nunca ejecuta nada en el receptor, solo entrega el contenido.
"""
import argparse
import concurrent.futures
import functools
import hashlib
import http.server
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

MAX_QR_BYTES = 2000
COMMANDS_FILENAME = "comandos.sh"


class TransferError(Exception):
    """Error esperable (dependencia ausente, limite excedido, timeout)."""


def detect_kind(arg: str) -> str:
    """'file' si arg es una ruta a un archivo existente, si no 'text'."""
    return "file" if Path(arg).is_file() else "text"


def require_tool(name: str, hint: str) -> str:
    """Devuelve la ruta del binario `name` o lanza TransferError con `hint`."""
    path = shutil.which(name)
    if not path:
        raise TransferError(f"falta '{name}'. Instala con: {hint}")
    return path


def parse_route_src_ip(route_output: str) -> str:
    parts = route_output.split()
    if "src" not in parts or parts.index("src") + 1 >= len(parts):
        raise TransferError(f"no se pudo extraer la IP de: {route_output!r}")
    return parts[parts.index("src") + 1]


def _first_global_ipv4(addr_output: str) -> str:
    for line in addr_output.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet":
                return parts[i + 1].split("/")[0]
    raise TransferError(f"no se encontro una IP global en: {addr_output!r}")


def detect_lan_ip() -> str:
    try:
        out = subprocess.run(
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True, text=True, check=True, timeout=3,
        ).stdout
        return parse_route_src_ip(out)
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, check=True, timeout=3,
        ).stdout
        return _first_global_ipv4(out)
    except Exception as e:
        raise TransferError(f"no se pudo detectar la IP LAN: {e}")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_pasted_commands(stream=None) -> str:
    """Lee comandos pegados en la consola hasta EOF (Ctrl+D)."""
    stream = stream or sys.stdin
    print("Pega los comandos, uno por linea. Cuando termines, pulsa Ctrl+D:",
          file=sys.stderr)
    commands = stream.read()
    if not commands.strip():
        raise TransferError("no se pegaron comandos")
    return commands.rstrip("\n")


def make_payload_dir(arg: str, kind: str, filename: str = None) -> tuple:
    tmp = Path(tempfile.mkdtemp(prefix="sendit-"))
    if kind == "file":
        src = Path(arg)
        dest = tmp / src.name
        shutil.copy2(src, dest)
    else:
        dest = tmp / (filename or "mensaje.txt")
        dest.write_text(arg + "\n")
    return tmp, dest


class _OneShotServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.timed_out = False
        self.served = False
        super().__init__(*args, **kwargs)

    def handle_timeout(self):
        self.timed_out = True


def run_lan(arg: str, kind: str, timeout: int = 300, bind_ip: str = None,
            _url_sink: dict = None, filename: str = None, _ready_callback=None) -> None:
    """Sirve el archivo/texto una vez por HTTP y termina.

    `bind_ip` y `_url_sink` existen para permitir pruebas locales sin
    tocar la deteccion real de IP ni el flujo de impresion.
    """
    tmp, payload = make_payload_dir(arg, kind, filename=filename)
    try:
        ip = bind_ip or detect_lan_ip()
        token = secrets.token_urlsafe(16)
        expected_path = f"/{token}/{payload.name}"

        class _Handler(http.server.SimpleHTTPRequestHandler):
            timeout = 10

            def send_head(self):
                if self.path != expected_path:
                    self.send_error(404)
                    return None
                self.path = f"/{payload.name}"
                result = super().send_head()
                if result is not None:
                    self.server.served = True
                return result

        handler_cls = functools.partial(_Handler, directory=str(tmp))
        httpd = _OneShotServer((ip, 0), handler_cls)
        port = httpd.server_address[1]
        url = f"http://{ip}:{port}{expected_path}"
        digest = sha256_of(payload)
        print(f"URL: {url}")
        print(f"sha256: {digest}")
        if _url_sink is not None:
            _url_sink["url"] = url
        if _ready_callback is not None:
            _ready_callback(url)
        if _url_sink is None:
            try:
                print_qr(url)
            except TransferError as e:
                print(f"(no se pudo mostrar el QR: {e})")
        deadline = time.monotonic() + timeout
        while not httpd.served and not httpd.timed_out:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                httpd.timed_out = True
                break
            httpd.timeout = remaining
            httpd.handle_request()
        httpd.server_close()
        if httpd.timed_out:
            raise TransferError("nadie descargo el archivo/texto antes del timeout")
        print("entregado.")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)





@functools.lru_cache(maxsize=1)
def _mac_vendor_table() -> dict:
    """OUI (6 hex) -> fabricante, desde la base de datos offline de nmap."""
    table = {}
    try:
        with open("/usr/share/nmap/nmap-mac-prefixes", encoding="utf-8", errors="ignore") as f:
            for line in f:
                oui, _, vendor = line.strip().partition(" ")
                if oui and vendor:
                    table[oui.upper()] = vendor
    except OSError:
        pass
    return table


def _resolve_name(ip: str) -> str | None:
    """Intenta DNS inverso, luego mDNS (avahi) y NetBIOS (nmblookup)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass
    try:
        out = subprocess.run(["avahi-resolve-address", ip], capture_output=True,
                             text=True, timeout=1.5).stdout
        if out.strip():
            return out.split()[-1]
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        out = subprocess.run(["nmblookup", "-A", ip], capture_output=True,
                             text=True, timeout=1.5).stdout
        for line in out.splitlines():
            if "<00>" in line and "GROUP" not in line:
                return line.split()[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _vendor_from_mac(mac: str) -> str | None:
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    return _mac_vendor_table().get(oui)


def discover_lan_devices() -> list[dict]:
    """Devuelve vecinos conocidos por el sistema, sin escanear Internet."""
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True,
                             check=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise TransferError(f"no se pudo buscar la red local: {e}")
    neighbors = []
    for line in out.splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("127."):
            continue
        state = parts[-1] if parts else ""
        if state == "FAILED":
            continue
        ip = parts[0]
        mac = ""
        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
        neighbors.append((ip, mac, state))

    # shortcut: gethostbyaddr puede bloquearse bastante si el resolver del
    # sistema no falla rapido (en vez de NXDOMAIN instantaneo). Se resuelve
    # en paralelo con un limite de 3s total; lo que no responda a tiempo
    # cae al fabricante por MAC o a la IP. Si esto no basta, cambiar a un
    # resolver con timeout propio (p.ej. dnspython) en vez de socket/libc.
    resolved_names = {}
    if neighbors:
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(neighbors))
        futures = {pool.submit(_resolve_name, ip): ip for ip, _, _ in neighbors}
        done, _pending = concurrent.futures.wait(futures, timeout=3)
        for fut in done:
            resolved_names[futures[fut]] = fut.result()
        pool.shutdown(wait=False, cancel_futures=True)

    devices = []
    for ip, mac, state in neighbors:
        resolved = resolved_names.get(ip)
        vendor = _vendor_from_mac(mac) if mac else None
        if resolved and vendor:
            name = f"{resolved} ({vendor})"
        elif resolved:
            name = resolved
        elif vendor:
            name = vendor
        else:
            name = f"equipo-{ip.replace('.', '-')}"
        devices.append({"ip": ip, "name": name, "mac": mac, "state": state})
    return devices



def discover_wifi_networks() -> list[str]:
    """Lista redes Wi-Fi visibles usando NetworkManager, sin conectarse."""
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "IN-USE,BSSID,SSID,SECURITY,SIGNAL", "dev", "wifi",
             "list", "--rescan", "no"],
            capture_output=True, text=True, check=True, timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise TransferError(f"no se pudieron buscar redes Wi-Fi: {e}")
    networks = []
    for line in out.splitlines():
        # nmcli -t escapa los ":" dentro de cada campo (p.ej. el BSSID) como "\:"
        # para no confundirlos con el separador de campos.
        parts = [p.replace("\x00", ":") for p in line.replace("\\:", "\x00").split(":")]
        if len(parts) < 5:
            continue
        in_use, bssid = parts[0], parts[1]
        ssid, security, signal = ":".join(parts[2:-2]), parts[-2], parts[-1]
        if not ssid:
            continue
        vendor = _vendor_from_mac(bssid)
        label = f"{ssid}  ({signal}%{', conectada' if in_use == '*' else ''}"
        label += f", router: {vendor})" if vendor else ")"
        networks.append(label)
    return list(dict.fromkeys(networks))


def discover_bluetooth_devices() -> list[str]:
    """Lista dispositivos Bluetooth conocidos/visibles."""
    try:
        out = subprocess.run(["bluetoothctl", "devices"], capture_output=True,
                             text=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as e:
        raise TransferError(f"no se pudieron buscar dispositivos Bluetooth: {e}")
    devices = []
    for line in out.splitlines():
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[0] == "Device":
            mac, name = parts[1], parts[2]
            vendor = _vendor_from_mac(mac)
            label = f"{name}  ({mac}"
            label += f", {vendor})" if vendor and vendor not in name else ")"
            devices.append(label)
    return devices


def run_gui() -> None:
    """Abre la pantalla de Sendit para pegar comandos y transferirlos."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except ImportError as e:
        raise TransferError(f"Tkinter no esta disponible: {e}")
    import threading

    root = tk.Tk()
    root.title("Sendit - comandos offline")
    root.geometry("800x700")
    root.minsize(620, 520)

    tk.Label(root, text="Comandos para enviar", font=("Sans", 14, "bold")).pack(
        anchor="w", padx=18, pady=(16, 4))
    tk.Label(root, text="Pega o escribe aquí los comandos. Se guardarán como comandos.sh; no se ejecutan automáticamente.",
             wraplength=650, justify="left").pack(anchor="w", padx=18, pady=(0, 8))
    text = tk.Text(root, wrap="none", undo=True, height=14, font=("Monospace", 11))
    text.pack(fill="both", expand=False, padx=18, pady=4)
    text.focus_set()

    network_frame = tk.Frame(root)
    network_frame.pack(fill="x", padx=18, pady=(2, 4))
    lan_col = tk.Frame(network_frame)
    lan_col.pack(side="left", fill="both", expand=True, padx=(0, 6))
    wifi_col = tk.Frame(network_frame)
    wifi_col.pack(side="left", fill="both", expand=True, padx=6)
    bt_col = tk.Frame(network_frame)
    bt_col.pack(side="left", fill="both", expand=True, padx=(6, 0))
    tk.Label(lan_col, text="Equipos LAN").pack(anchor="w")
    device_list = tk.Listbox(lan_col, height=4, selectmode="multiple")
    device_list.pack(fill="x")
    tk.Button(lan_col, text="BUSCAR LAN", command=lambda: search_lan(), padx=6).pack(pady=3)
    tk.Label(wifi_col, text="Red Wi-Fi").pack(anchor="w")
    wifi_list = tk.Listbox(wifi_col, height=4)
    wifi_list.pack(fill="x")
    tk.Button(wifi_col, text="BUSCAR Wi-Fi", command=lambda: search_wifi(), padx=6).pack(pady=3)
    tk.Label(bt_col, text="Bluetooth").pack(anchor="w")
    bt_list = tk.Listbox(bt_col, height=4)
    bt_list.pack(fill="x")
    tk.Button(bt_col, text="BUSCAR Bluetooth", command=lambda: search_bt(), padx=6).pack(pady=3)
    qr_frame = tk.Frame(root)
    qr_frame.pack(pady=4)
    status = tk.StringVar(value="Listo. El teléfono y este ordenador deben estar en la misma Wi-Fi o hotspot.")
    tk.Label(root, textvariable=status, anchor="w", justify="left", wraplength=650).pack(
        fill="x", padx=18, pady=8)
    qr_image = {"value": None}

    def show_qr(url):
        try:
            import os
            fd, qr_path = tempfile.mkstemp(prefix="sendit-qr-", suffix=".png")
            os.close(fd)
            try:
                tool = require_tool("qrencode", "sudo apt install qrencode")
                subprocess.run([tool, "-o", qr_path, url], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                image = tk.PhotoImage(file=qr_path)
                qr_image["value"] = image
                for child in qr_frame.winfo_children():
                    child.destroy()
                tk.Label(qr_frame, text="Escanea este QR con el teléfono").pack()
                tk.Label(qr_frame, image=image).pack()
                finish(f"Escanea el QR o abre: {url}")
            finally:
                os.unlink(qr_path)
        except (OSError, TransferError, subprocess.CalledProcessError) as e:
            finish(f"URL del teléfono: {url} (QR no disponible: {e})")

    def finish(message):
        root.after(0, lambda: status.set(message))

    def search_lan():
        try:
            devices = discover_lan_devices()
            device_list.delete(0, "end")
            for device in devices:
                label = f"{device['name']} | {device['ip']}"
                if device["mac"]:
                    label += f" | {device['mac']}"
                device_list.insert("end", label)
            if not devices:
                device_list.insert("end", "No hay vecinos detectados todavía")
                status.set("No se detectaron equipos. Comprueba la misma Wi-Fi.")
            else:
                status.set(f"{len(devices)} equipo(s) LAN detectado(s).")
        except TransferError as e:
            status.set(f"Error buscando la LAN: {e}")

    def search_wifi():
        try:
            wifi_list.delete(0, "end")
            networks = discover_wifi_networks()
            for network in networks:
                wifi_list.insert("end", network)
            if not networks:
                wifi_list.insert("end", "No hay redes Wi-Fi visibles")
            status.set("Redes Wi-Fi visibles. La conexión se cambia desde los ajustes del sistema.")
        except TransferError as e:
            status.set(f"Error buscando Wi-Fi: {e}")

    def search_bt():
        try:
            bt_list.delete(0, "end")
            devices = discover_bluetooth_devices()
            for device in devices:
                bt_list.insert("end", device)
            if not devices:
                bt_list.insert("end", "No hay dispositivos Bluetooth emparejados")
            status.set("Dispositivos Bluetooth listados. El envío Bluetooth usa el diálogo del sistema.")
        except TransferError as e:
            status.set(f"Error buscando Bluetooth: {e}")

    def send_phone():
        commands = text.get("1.0", "end-1c").strip()
        if not commands:
            messagebox.showwarning("Sendit", "Escribe o pega algún comando primero.")
            return
        status.set("Creando enlace local… abre la URL desde el teléfono.")
        threading.Thread(target=lambda: transfer(commands), daemon=True).start()

    def transfer(commands):
        try:
            link = {}
            run_lan(commands, "text", filename=COMMANDS_FILENAME, _url_sink=link,
                    _ready_callback=lambda url: root.after(0, lambda: show_qr(url)))
            finish(f"Listo para el teléfono. Escanea el QR o abre: {link.get('url', '')}")
        except TransferError as e:
            finish(f"Error: {e}")

    def receive_phone():
        folder = filedialog.askdirectory(title="Guardar comandos recibidos en")
        if not folder:
            return
        status.set("Creando página local… abre la URL desde el teléfono.")
        threading.Thread(target=lambda: receive(folder), daemon=True).start()

    def receive(folder):
        try:
            link = {}
            run_receive(output_dir=folder, _url_sink=link)
            finish(f"Comandos recibidos y guardados en {folder}/comandos.sh")
        except TransferError as e:
            finish(f"Error: {e}")

    buttons = tk.Frame(root)
    buttons.pack(fill="x", padx=18, pady=(0, 16))
    tk.Button(buttons, text="ENVIAR (QR / enlace)", command=send_phone,
              bg="#1769aa", fg="white", padx=16, pady=8).pack(side="left")
    tk.Button(buttons, text="RECIBIR DESDE EL TELÉFONO", command=receive_phone,
              padx=12, pady=8).pack(side="left", padx=8)
    tk.Button(buttons, text="Limpiar", command=lambda: text.delete("1.0", "end")).pack(side="right")
    root.mainloop()


def run_receive(timeout: int = 300, bind_ip: str = None,
                output_dir: str = ".", _url_sink: dict = None, port: int = 8765) -> None:
    """Recibe comandos desde el navegador de un telefono por la LAN."""
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    received = {}
    token_path = "/" + secrets.token_urlsafe(16)

    class _ReceiveHandler(http.server.BaseHTTPRequestHandler):
        def _send_page(self, message=""):
            body = f"""<!doctype html>
<html lang="es"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sendit - enviar comandos</title>
<h2>Sendit</h2><p>{message}</p>
<form method="post">
<textarea name="commands" rows="14" cols="42" autofocus
 placeholder="Pega aqui los comandos"></textarea><br>
<button type="submit">Enviar al ordenador</button>
</form></html>""".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == token_path:
                self._send_page()
            else:
                self.send_error(404)

        timeout = 10

        def do_POST(self):
            if self.path != token_path:
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if not 0 <= length <= 1024 * 1024:
                self.send_error(413, "mensaje demasiado grande o invalido")
                return
            form = urllib.parse.parse_qs(
                self.rfile.read(length).decode("utf-8", errors="replace")
            )
            commands = form.get("commands", [""])[0].strip()
            if not commands:
                self._send_page("Escribe algun comando antes de enviar.")
                return
            path = destination / COMMANDS_FILENAME
            path.write_text(commands + "\n")
            received["path"] = path
            self._send_page(f"Recibido. Guardado como {path.name}.")
            self.server.served = True

        def log_message(self, format, *args):
            pass

    ip = bind_ip or detect_lan_ip()
    try:
        httpd = _OneShotServer((ip, port), _ReceiveHandler)
    except OSError as e:
        raise TransferError(f"no se pudo abrir el receptor en el puerto {port}: {e}")
    try:
        port = httpd.server_address[1]
        url = f"http://{ip}:{port}{token_path}"
        print(f"Abre esta direccion en el telefono: {url}")
        if _url_sink is not None:
            _url_sink["url"] = url
        deadline = time.monotonic() + timeout
        while not httpd.served and not httpd.timed_out:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                httpd.timed_out = True
                break
            httpd.timeout = remaining
            httpd.handle_request()
        if httpd.timed_out:
            raise TransferError("no se recibieron comandos antes del timeout")
        print(f"recibido: {received['path']}")
    finally:
        httpd.server_close()


def print_qr(data: str) -> None:
    require_tool("qrencode", "sudo apt install qrencode")
    subprocess.run(["qrencode", "-t", "ANSIUTF8", "--", data], check=True)


def run_qr(arg: str, kind: str) -> None:
    if kind == "file":
        raise TransferError("--qr solo funciona con texto, no con archivos")
    data = arg.encode("utf-8")
    if len(data) > MAX_QR_BYTES:
        raise TransferError(
            f"texto de {len(data)} bytes excede el limite de {MAX_QR_BYTES} "
            "para --qr; usa el modo LAN o --bt"
        )
    print_qr(arg)


def run_bt(arg: str, kind: str, filename: str = None) -> None:
    tool = require_tool("bluetooth-sendto", "sudo apt install gnome-bluetooth")
    tmp, payload = make_payload_dir(arg, kind, filename=filename)
    try:
        subprocess.run([tool, str(payload)], check=True)
        print("entregado (confirma en el dialogo del dispositivo receptor).")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sendit",
        description="Pasa un archivo, texto o comandos a otra maquina por LAN, Bluetooth o QR.",
    )
    parser.add_argument("payload", nargs="?", help="ruta de archivo o texto libre a enviar")
    parser.add_argument("--comandos", "--commands", action="store_true",
                        help="pedir comandos pegados en la consola y enviarlos como comandos.sh")
    parser.add_argument("--recibir", action="store_true",
                        help="abrir una pagina para recibir comandos desde un telefono")
    parser.add_argument("--pantalla", "--gui", action="store_true",
                        help="abrir la pantalla grafica para escribir y transferir comandos")
    parser.add_argument("--salida", default=".",
                        help="directorio donde guardar lo recibido (default: .)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--bt", action="store_true", help="enviar por Bluetooth")
    group.add_argument("--qr", action="store_true",
                        help="mostrar como QR puro (solo texto)")
    parser.add_argument("--timeout", type=int, default=300,
                         help="segundos de espera en modo LAN (default 300)")
    args = parser.parse_args(argv)

    try:
        if args.pantalla and (args.payload or args.comandos or args.recibir or args.bt or args.qr):
            parser.error("--pantalla no se puede combinar con otras opciones de envio")
        if args.pantalla:
            run_gui()
            return 0
        if args.recibir and (args.payload or args.comandos or args.bt or args.qr):
            parser.error("--recibir no se puede combinar con payload, --comandos, --bt o --qr")
        if args.recibir:
            run_receive(args.timeout, output_dir=args.salida)
            return 0
        if args.comandos and args.payload:
            parser.error("--comandos no se puede combinar con payload")
        if args.comandos:
            payload = read_pasted_commands()
            kind = "text"
            filename = COMMANDS_FILENAME
        elif args.payload is None:
            parser.error("indica un archivo/texto o usa --comandos")
        else:
            payload = args.payload
            kind = detect_kind(payload)
            filename = None
        if args.qr:
            run_qr(payload, kind)
        elif args.bt:
            run_bt(payload, kind, filename=filename)
        else:
            run_lan(payload, kind, args.timeout, filename=filename)
    except TransferError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
