#!/usr/bin/env python3
"""Self-check minimo para sendit.py (sin red ni hardware real)."""
import shutil
import time

import sendit


def test_detect_kind_file(tmp_path):
    f = tmp_path / "script.sh"
    f.write_text("echo hola\n")
    assert sendit.detect_kind(str(f)) == "file"


def test_detect_kind_text():
    assert sendit.detect_kind("echo hola") == "text"
    assert sendit.detect_kind("/ruta/que/no/existe.sh") == "text"


def test_require_tool_missing(monkeypatch):
    monkeypatch.setattr(sendit.shutil, "which", lambda name: None)
    try:
        sendit.require_tool("qrencode", "sudo apt install qrencode")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError as e:
        assert "qrencode" in str(e)
        assert "sudo apt install qrencode" in str(e)


def test_require_tool_present(monkeypatch):
    monkeypatch.setattr(sendit.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert sendit.require_tool("qrencode", "hint") == "/usr/bin/qrencode"


def test_parse_route_src_ip():
    sample = "1.1.1.1 via 192.168.1.1 dev eno1 src 192.168.1.50 uid 1000\n"
    assert sendit.parse_route_src_ip(sample) == "192.168.1.50"


def test_parse_route_src_ip_missing():
    try:
        sendit.parse_route_src_ip("sin la palabra clave\n")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError:
        pass


def test_parse_route_src_ip_trailing_src():
    try:
        sendit.parse_route_src_ip("1.1.1.1 via 192.168.1.1 dev eno1 src")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError:
        pass


def test_first_global_ipv4():
    sample = "2: eno1    inet 192.168.1.50/24 brd 192.168.1.255 scope global eno1"
    assert sendit._first_global_ipv4(sample) == "192.168.1.50"


def test_first_global_ipv4_missing():
    try:
        sendit._first_global_ipv4("2: eno1    inet6 fe80::1/64 scope link")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError:
        pass


def test_sha256_of(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"hola")
    import hashlib
    assert sendit.sha256_of(f) == hashlib.sha256(b"hola").hexdigest()


def test_make_payload_dir_file(tmp_path):
    src = tmp_path / "script.sh"
    src.write_text("echo hola\n")
    tmp, payload = sendit.make_payload_dir(str(src), "file")
    assert payload.name == "script.sh"
    assert payload.read_text() == "echo hola\n"
    import shutil as _sh
    _sh.rmtree(tmp)


def test_make_payload_dir_text(tmp_path):
    tmp, payload = sendit.make_payload_dir("echo hola", "text")
    assert payload.name == "mensaje.txt"
    assert payload.read_text() == "echo hola\n"
    import shutil as _sh
    _sh.rmtree(tmp)


def test_run_lan_round_trip(tmp_path):
    """Sirve un archivo real en 127.0.0.1 y lo descarga con urllib."""
    import threading
    import urllib.request

    src = tmp_path / "script.sh"
    src.write_text("echo hola\n")

    result = {}

    def _server_thread():
        try:
            sendit.run_lan(str(src), "file", timeout=5, bind_ip="127.0.0.1",
                            _url_sink=result)
        except sendit.TransferError as e:
            result["error"] = str(e)

    t = threading.Thread(target=_server_thread, daemon=True)
    t.start()
    deadline = time.monotonic() + 3
    while "url" not in result and time.monotonic() < deadline:
        time.sleep(0.02)
    assert "url" in result, "run_lan no publico la URL a tiempo"

    body = urllib.request.urlopen(result["url"], timeout=3).read()
    assert body == b"echo hola\n"
    t.join(timeout=5)
    assert "error" not in result


def test_run_lan_ignores_wrong_path_then_serves(tmp_path):
    """Una peticion a una ruta incorrecta no debe terminar el servidor."""
    import threading
    import urllib.error
    import urllib.request

    src = tmp_path / "script.sh"
    src.write_text("echo hola\n")

    result = {}

    def _server_thread():
        try:
            sendit.run_lan(str(src), "file", timeout=3, bind_ip="127.0.0.1",
                            _url_sink=result)
        except sendit.TransferError as e:
            result["error"] = str(e)

    t = threading.Thread(target=_server_thread, daemon=True)
    t.start()
    deadline = time.monotonic() + 3
    while "url" not in result and time.monotonic() < deadline:
        time.sleep(0.02)
    assert "url" in result, "run_lan no publico la URL a tiempo"

    base = result["url"].rsplit("/", 1)[0]
    try:
        urllib.request.urlopen(f"{base}/no-existe.txt", timeout=3)
        assert False, "deberia haber devuelto 404"
    except urllib.error.HTTPError as e:
        assert e.code == 404

    # el servidor sigue vivo tras el 404: la descarga correcta aun funciona
    body = urllib.request.urlopen(result["url"], timeout=3).read()
    assert body == b"echo hola\n"
    t.join(timeout=5)
    assert "error" not in result


def test_run_lan_continues_without_qrencode(monkeypatch, tmp_path):
    """Si falta qrencode, la transferencia LAN debe seguir sin abortar.

    No pasa _url_sink a proposito: eso fuerza el camino real que llama a
    print_qr(url), que es la rama sin cobertura que este test cierra.
    """
    import io
    import re
    import threading
    import urllib.request

    monkeypatch.setattr(sendit.shutil, "which", lambda name: None)

    src = tmp_path / "script.sh"
    src.write_text("echo hola\n")

    result = {}
    captured = io.StringIO()

    def _server_thread():
        import contextlib
        try:
            with contextlib.redirect_stdout(captured):
                sendit.run_lan(str(src), "file", timeout=3, bind_ip="127.0.0.1")
        except sendit.TransferError as e:
            result["error"] = str(e)
        finally:
            result["done"] = True

    t = threading.Thread(target=_server_thread, daemon=True)
    t.start()

    deadline = time.monotonic() + 3
    url = None
    while url is None and time.monotonic() < deadline:
        m = re.search(r"URL: (\S+)", captured.getvalue())
        if m:
            url = m.group(1)
        else:
            time.sleep(0.02)
    assert url, "run_lan no publico la URL a tiempo"

    body = urllib.request.urlopen(url, timeout=3).read()
    assert body == b"echo hola\n"

    t.join(timeout=5)
    assert "error" not in result, result.get("error")
    assert "no se pudo mostrar el QR" in captured.getvalue()


def test_run_bt_missing_tool(monkeypatch):
    monkeypatch.setattr(sendit.shutil, "which", lambda name: None)
    try:
        sendit.run_bt("echo hola", "text")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError as e:
        assert "bluetooth-sendto" in str(e)




def test_run_qr_rejects_file(tmp_path):
    f = tmp_path / "script.sh"
    f.write_text("echo hola\n")
    try:
        sendit.run_qr(str(f), "file")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError as e:
        assert "texto" in str(e)


def test_run_qr_rejects_oversize(monkeypatch):
    monkeypatch.setattr(sendit.shutil, "which", lambda name: f"/usr/bin/{name}")
    big = "x" * (sendit.MAX_QR_BYTES + 1)
    try:
        sendit.run_qr(big, "text")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError as e:
        assert "limite" in str(e) or "excede" in str(e)


def test_run_qr_missing_tool(monkeypatch):
    monkeypatch.setattr(sendit.shutil, "which", lambda name: None)
    try:
        sendit.run_qr("echo hola", "text")
        assert False, "deberia haber lanzado TransferError"
    except sendit.TransferError as e:
        assert "qrencode" in str(e)


def test_main_qr_and_file_conflict(tmp_path):
    f = tmp_path / "script.sh"
    f.write_text("echo hola\n")
    rc = sendit.main(["--qr", str(f)])
    assert rc == 1


if __name__ == "__main__":
    import inspect
    from pathlib import Path
    from types import SimpleNamespace

    class _Monkeypatch:
        def __init__(self):
            self._undo = []

        def setattr(self, obj, name, value):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, value)

        def undo(self):
            for obj, name, old in self._undo:
                setattr(obj, name, old)

    for _name, _fn in list(globals().items()):
        if not _name.startswith("test_"):
            continue
        params = inspect.signature(_fn).parameters
        kwargs = {}
        mp = _Monkeypatch()
        if "tmp_path" in params:
            import tempfile
            kwargs["tmp_path"] = Path(tempfile.mkdtemp(prefix="sendit-test-"))
        if "monkeypatch" in params:
            kwargs["monkeypatch"] = mp
        _fn(**kwargs)
        mp.undo()
        if "tmp_path" in kwargs:
            shutil.rmtree(kwargs["tmp_path"], ignore_errors=True)
        print(f"ok  {_name}")
    print("all tests passed")
