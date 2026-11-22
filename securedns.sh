#!/usr/bin/env bash
# SecureDNS — лаунчер для Linux.
# Проверяет зависимости и запускает программу с нужными правами.
cd "$(dirname "$0")" || exit 1

# 1. Python
if ! command -v python3 >/dev/null 2>&1; then
    echo "✘ Не найден python3."
    echo "  Debian/Ubuntu: sudo apt install python3"
    echo "  Fedora:        sudo dnf install python3"
    exit 1
fi

# 2. tkinter (GUI)
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
    echo "✘ Не найден модуль tkinter (нужен для окна программы)."
    echo "  Debian/Ubuntu: sudo apt install python3-tk"
    echo "  Fedora:        sudo dnf install python3-tkinter"
    echo "  Arch:          sudo pacman -S tk"
    exit 1
fi

# 3. Запуск с правами root (нужны для смены DNS и порта 53)
if [ "$(id -u)" -ne 0 ]; then
    # На Wayland/X11 рутовому GUI нужен доступ к дисплею текущего пользователя
    if command -v xhost >/dev/null 2>&1; then
        xhost +SI:localuser:root >/dev/null 2>&1
    fi
    exec sudo -E python3 main.py "$@"
fi

exec python3 main.py "$@"
