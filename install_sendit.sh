#!/usr/bin/env bash
# Instala sendit para el usuario actual: copia a ~/.local/bin y crea el
# lanzador de escritorio. No necesita pip ni root (sendit.py solo usa la
# libreria estandar de Python; tkinter es la unica dependencia de sistema,
# y solo para el modo --pantalla).
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sendit.py"
BIN_DIR="$HOME/.local/bin"
APPS_DIR="$HOME/.local/share/applications"

mkdir -p "$BIN_DIR" "$APPS_DIR"
cp "$SRC" "$BIN_DIR/sendit"
chmod +x "$BIN_DIR/sendit"

cat > "$APPS_DIR/sendit.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=sendit
Comment=Enviar un archivo o texto a otra maquina (LAN/Bluetooth/QR)
Exec=$BIN_DIR/sendit --pantalla
Icon=utilities-terminal
Terminal=false
Categories=Utility;
EOF

echo "sendit instalado en $BIN_DIR/sendit"
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "aviso: $BIN_DIR no esta en tu PATH. Anade esto a tu ~/.bashrc o ~/.zshrc:" ;
       echo "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac

echo
echo "comprobando dependencias opcionales:"
check() { command -v "$1" >/dev/null 2>&1 && echo "  ok   $1" || echo "  falta $1  ($2)"; }
python3 -c "import tkinter" >/dev/null 2>&1 && echo "  ok   tkinter (modo --pantalla)" || echo "  falta tkinter  (apt install python3-tk)  -- solo afecta a --pantalla"
check nmcli      "apt install network-manager"
check bluetoothctl "apt install bluez"
check qrencode   "apt install qrencode"
check bluetooth-sendto "apt install gnome-bluetooth"
check avahi-resolve-address "apt install avahi-utils -- opcional, mejora nombres LAN"
check nmblookup  "apt install samba-common-bin -- opcional, mejora nombres LAN"
[ -f /usr/share/nmap/nmap-mac-prefixes ] && echo "  ok   base de fabricantes MAC" || echo "  falta base de fabricantes MAC  (apt install nmap -- opcional)"
