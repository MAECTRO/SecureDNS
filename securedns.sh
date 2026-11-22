#!/usr/bin/env bash
# SecureDNS — лаунчер для Linux.
# GUI:  ./securedns.sh          (автоопределение Xauthority, sudo)
# CLI:  ./securedns.sh --cli    (терминальный режим — работает везде, даже на Wayland)
cd "$(dirname "$0")" || exit 1

# 1. Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "✘ Не найден python3."
    echo "  Debian/Ubuntu: sudo apt install python3"
    echo "  Fedora:        sudo dnf install python3"
    echo "  Arch:          sudo pacman -S python"
    exit 1
fi

# 2. tkinter (нужен только для GUI)
CLI_MODE=0
for arg in "$@"; do [ "$arg" = "--cli" ] && CLI_MODE=1; done
if [ "$CLI_MODE" -eq 0 ] && ! python3 -c "import tkinter" >/dev/null 2>&1; then
    echo "✘ Не найден модуль tkinter (нужен для окна программы)."
    echo "  Debian/Ubuntu: sudo apt install python3-tk"
    echo "  Fedora:        sudo dnf install python3-tkinter"
    echo "  Arch:          sudo pacman -S tk"
    echo
    echo "Либо запустите терминальный режим без иксов:  $0 --cli"
    exit 1
fi

# 3. Запуск с правами root (нужны для смены DNS и порта 53)
if [ "$(id -u)" -ne 0 ]; then
    if [ "$CLI_MODE" -eq 1 ]; then
        exec sudo python3 main.py "$@"
    fi
    # GUI: рутовому окну нужен доступ к дисплею текущего пользователя.
    # Ищем Xauthority: сессия → домашний каталог → файлы композиторов (GNOME/KDE/Wayland)
    XA="${XAUTHORITY:-$HOME/.Xauthority}"
    if [ ! -r "$XA" ]; then
        for f in /run/user/"$(id -u)"/.mutter-Xwaylandauth.* \
                 /run/user/"$(id -u)"/xauth_* \
                 /run/user/"$(id -u)"/Xauthority; do
            if [ -r "$f" ]; then XA="$f"; break; fi
        done
    fi
    if command -v xhost >/dev/null 2>&1; then
        XAUTHORITY="$XA" xhost +SI:localuser:root >/dev/null 2>&1
    fi
    exec sudo env DISPLAY="${DISPLAY:-:0}" XAUTHORITY="$XA" \
                  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
                  python3 main.py "$@"
fi

exec python3 main.py "$@"
