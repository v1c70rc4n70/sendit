# sendit

Pasa un archivo, texto o comandos a otra maquina por LAN, Bluetooth o QR.
Sin daemon: cada invocacion hace una entrega y termina. Nunca ejecuta nada
en el receptor, solo entrega el contenido.

## Instalar

```bash
./install_sendit.sh
```

Copia `sendit.py` a `~/.local/bin/sendit` y crea un lanzador de escritorio.
Solo necesita Python 3 (biblioteca estandar); `tkinter` es opcional, solo
para el modo grafico `--pantalla`. El instalador avisa de que herramientas
de sistema opcionales faltan (`nmcli`, `bluetoothctl`, `qrencode`,
`avahi-resolve-address`, `nmblookup`, `nmap`) y que mejoran, sin ser
imprescindibles.

## Uso

```
sendit <archivo-o-texto> [--bt | --qr] [--timeout SEGUNDOS]
sendit --comandos          # pega comandos en la consola y los envia
sendit --recibir           # abre una pagina para recibir comandos de un telefono
sendit --pantalla          # interfaz grafica
```

- Si el argumento es una ruta de archivo existente -> modo archivo.
- Si no, se trata como texto libre (comando/snippet) -> modo texto.
- Sin flag -> LAN (por defecto): levanta un servidor HTTP temporal en la
  IP local y lo cierra solo al primer GET o al agotar `--timeout`
  (300s por defecto).
- `--bt` -> Bluetooth (`bluetooth-sendto`, selector nativo del SO).
- `--qr` -> QR puro en terminal, solo texto, sin red ni Bluetooth.
- `--recibir` -> levanta un receptor LAN protegido con un token aleatorio
  en la URL; cualquier peticion a otra ruta devuelve 404.

La deteccion de equipos LAN/Wi-Fi/Bluetooth muestra nombre y fabricante
(por MAC, con una base de datos offline) en vez de solo direcciones IP.

## Tests

```bash
python3 -m pytest test_sendit.py
```
