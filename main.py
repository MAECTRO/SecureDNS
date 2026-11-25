# -*- coding: utf-8 -*-
"""
SecureDNS — бесплатное приложение для шифрованного DNS на Windows 10/11 и Linux.

Как работает:
  - Поднимает локальный DNS-прокси на 127.0.0.1:53.
  - Запросы от системы пересылает на ВАШИ серверы по шифрованному каналу:
    DoT (DNS-over-TLS, порт 853) или DoH (DNS-over-HTTPS, порт 443).
  - Системе назначает DNS = 127.0.0.1:
      Windows — через Set-DnsClientServerAddress;
      Linux — через systemd-resolved (resolvectl), NetworkManager (nmcli)
              или прямую правку /etc/resolv.conf.
  - Провайдер сети видит только зашифрованный TLS-трафик, запросы не читает.

Работает с ЛЮБЫМИ серверами — просто впишите их IP.
Лицензия: MIT. Распространяется бесплатно, "как есть".
"""

import base64
import collections
import concurrent.futures
import ctypes
import datetime
import http.client
import io
import ipaddress
import json
import os
import platform
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import traceback

try:
    import winreg
except ImportError:
    winreg = None

APP_NAME = "SecureDNS"
APP_VERSION = "1.3.6"
DEFAULT_DOH_PLACEHOLDER = "https://example.com/dns-query"
IS_WINDOWS = sys.platform.startswith("win")
SPAWN_KW = {"creationflags": 0x08000000} if IS_WINDOWS else {}
LOCAL_DNS = "127.0.0.1"
LOCAL_DNS_V6 = "::1"
BLOCKED_V6_QUIC_QTYPES = {28, 64, 65}  # AAAA, SVCB, HTTPS
QUIC_FW_RULE = "SecureDNS_Block_QUIC"
AUTOSTART_TASK = "SecureDNS_Autostart"
DEFAULT_SPLIT_DOMAINS = (
    # Google Gemini / AI Studio
    "gemini.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "alkalimakersuite-pa.clients6.google.com",
    "generativelanguage.googleapis.com",
    "proactivebackend-pa.googleapis.com",
    "robinfrontend-pa.googleapis.com",
    "geller-pa.googleapis.com",
    "assistant-s3-pa.googleapis.com",
    "waa-pa.clients6.google.com",
    "notebooklm.google.com",
    "labs.google",
    "jules.google.com",
    "deepmind.google",
    # OpenAI / ChatGPT / Sora
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "sora.com",
    # Anthropic / Claude
    "claude.ai",
    "anthropic.com",
    "claudeusercontent.com",
    # xAI / Perplexity / Cursor / Copilot
    "grok.com",
    "x.ai",
    "perplexity.ai",
    "cursor.com",
    "cursor.sh",
    "copilot.microsoft.com",
    "githubcopilot.com",
)
FALLBACK_DIRECT_DNS = ("77.88.8.8", "77.88.8.1")
if IS_WINDOWS:
    BACKUP_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "SecureDNS")
else:
    BACKUP_DIR = "/etc/securedns"
BACKUP_FILE = os.path.join(BACKUP_DIR, "backup.json")
CONFIG_FILE = os.path.join(BACKUP_DIR, "config.json")
LOG_FILE = os.path.join(BACKUP_DIR, "securedns.log")
LOG_MAX_BYTES = 512 * 1024
_LOG_LOCK = threading.Lock()
_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 64: "SVCB", 65: "HTTPS",
}

# ---------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------

def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", None) if is_frozen() else None
    if not base:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def admin_hint() -> str:
    if IS_WINDOWS:
        return "запустите её «от имени администратора»"
    return "запустите её через sudo:  sudo -E python3 main.py"


def run_ps(command: str, timeout: int = 30):
    full = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + command
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", full],
            capture_output=True, timeout=timeout, **SPAWN_KW,
        )
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, "", str(e)


def run_cmd(args, timeout: int = 30):
    """Запуск внешней команды (Linux)."""
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout, **SPAWN_KW)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, "", str(e)


def write_log_file(msg: str, level: str = "INFO"):
    """Потокобезопасная запись событий в securedns.log с простой ротацией."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = str(msg).splitlines() or [""]
    with _LOG_LOCK:
        try:
            log_dir = os.path.dirname(LOG_FILE)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) >= LOG_MAX_BYTES:
                os.replace(LOG_FILE, LOG_FILE + ".1")
            with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
                for line in lines:
                    f.write(f"{ts} [{level}] {line}\n")
        except OSError:
            pass


def read_log_tail(max_lines: int = 300) -> str:
    """Возвращает последние max_lines строк из securedns.log (с учётом архива .1)."""
    cur_lines = []
    old_lines = []
    with _LOG_LOCK:
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    cur_lines = f.read().splitlines()
        except OSError:
            cur_lines = []
        if (max_lines <= 0 or len(cur_lines) < max_lines) and os.path.exists(LOG_FILE + ".1"):
            try:
                with open(LOG_FILE + ".1", "r", encoding="utf-8", errors="replace") as f:
                    old_lines = f.read().splitlines()
            except OSError:
                old_lines = []
    if max_lines > 0:
        if len(cur_lines) >= max_lines:
            combined = cur_lines[-max_lines:]
        else:
            need = max_lines - len(cur_lines)
            combined = old_lines[-need:] + cur_lines
    else:
        combined = old_lines + cur_lines
    if not combined:
        return "(файл журнала пуст или отсутствует)"
    return "\n".join(combined)


def log_session_header(mode: str = "GUI"):
    """Записывает строку старта сессии в securedns.log."""
    write_log_file(
        f"=== Запуск {APP_NAME} {APP_VERSION} ({mode}) | OS={platform.platform()} "
        f"| Python={sys.version.split()[0]} | frozen={is_frozen()} | admin={is_admin()} ===",
        level="SESSION",
    )


# ---------------------------------------------------------------------------
# Сетевой бэкенд: Windows (PowerShell) / Linux (resolvectl, nmcli, resolv.conf)
# ---------------------------------------------------------------------------

def _linux_dns_tool():
    for tool in ("resolvectl", "systemd-resolve"):
        if shutil.which(tool):
            return tool
    if shutil.which("nmcli"):
        return "nmcli"
    return "resolvconf"


def _nmcli_connection(device: str):
    """Имя активного соединения NetworkManager для устройства."""
    rc, out, _ = run_cmd(["nmcli", "-t", "-f", "NAME,DEVICE", "con", "show", "--active"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.rsplit(":", 1)
            if len(parts) == 2 and parts[1] == device:
                return parts[0]
    return None


def get_adapters():
    """Список активных адаптеров: [{index, name, desc}]."""
    if IS_WINDOWS:
        rc, out, _ = run_ps(
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
            "Select-Object ifIndex, Name, InterfaceDescription | ConvertTo-Json -Compress"
        )
        if rc != 0 or not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            data = [data]
        return [{"index": int(a["ifIndex"]), "name": a["Name"],
                 "desc": a["InterfaceDescription"]} for a in data]
    # Linux: ip -j link show
    rc, out, _ = run_cmd(["ip", "-j", "link", "show"])
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    result = []
    for a in data:
        if a.get("ifname") == "lo" or a.get("operstate") != "UP":
            continue
        result.append({"index": int(a.get("ifindex", 0)),
                       "name": a["ifname"],
                       "desc": a.get("link_type", "link")})
    return result


def _clean_sni_host(raw: str) -> str | None:
    """Извлекает чистое доменное имя из SNI (отрезает https://, /путь, :порт)."""
    s = str(raw or "").strip()
    if not s:
        return None
    if "://" in s or "/" in s:
        from urllib.parse import urlparse
        u = urlparse(s if "://" in s else "https://" + s)
        host = (u.hostname or "").strip().strip(".")
        return host or None
    host = s.split(":", 1)[0].strip().strip(".")
    return host or None


def _clean_doh_url(raw: str) -> str:
    """Очищает URL DoH и отбрасывает пример https://example.com/dns-query."""
    s = str(raw or "").strip()
    if not s or s.rstrip("/").lower() == DEFAULT_DOH_PLACEHOLDER.rstrip("/"):
        return ""
    return s


def _extract_https_url(raw: str) -> str | None:
    """Находит первую https:// ссылку внутри произвольного текста или поля ввода."""
    for tok in re.split(r"[\s,;]+", str(raw or "").strip()):
        if tok.lower().startswith("https://"):
            return tok
    return None


def _with_url_port(url: str, port: int) -> str:
    """Меняет порт в URL, корректно обрабатывая стандартный 443."""
    from urllib.parse import urlparse, urlunparse
    u = urlparse(url)
    host = u.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if int(port) == 443 else f"{host}:{int(port)}"
    if u.username:
        auth = f"{u.username}:{u.password}@" if u.password is not None else f"{u.username}@"
        netloc = auth + netloc
    return urlunparse((u.scheme, netloc, u.path or "/dns-query", u.params, u.query, u.fragment))


def parse_ip_targets(raw: str, default_port: int = 853) -> list[tuple[str, int]]:
    """Разбирает список IP[:порт] (разделители: запятая, ;, пробел, перенос; убирает tls://)."""
    out = []
    seen = set()
    for tok in re.split(r"[\s,;]+", str(raw or "").strip()):
        if not tok:
            continue
        s = tok
        if s.lower().startswith(("tls://", "dot://")):
            s = s.split("://", 1)[1].rstrip("/")
        if ":" in s:
            ip_part, port_part = s.rsplit(":", 1)
            if not port_part.isdigit():
                raise ValueError(f"некорректный порт в «{tok}»")
            port = int(port_part)
            if not (1 <= port <= 65535):
                raise ValueError(f"порт вне диапазона 1..65535 в «{tok}»")
        else:
            ip_part, port = s, int(default_port)
        if not _valid_ip(ip_part):
            raise ValueError(f"некорректный IP «{tok}»")
        key = (ip_part, port)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def format_ip_targets(targets: list[tuple[str, int]], default_port: int = 853) -> str:
    return ", ".join(ip if p == default_port else f"{ip}:{p}" for ip, p in targets)


def _is_win_default_v6_dns(addr: str) -> bool:
    s = str(addr or "").strip().lower()
    return (not s) or s.startswith("fec0:0:0:ffff::")


def get_dns_servers(adapter):
    """Текущие IPv4 DNS адаптера. adapter — index (Windows) или имя (Linux)."""
    if IS_WINDOWS:
        rc, out, _ = run_ps(
            f"(Get-DnsClientServerAddress -InterfaceIndex {adapter} -AddressFamily IPv4"
            f" -ErrorAction SilentlyContinue).ServerAddresses | ConvertTo-Json -Compress"
        )
        if not out.strip():
            return []
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return []
        if isinstance(data, str):
            data = [data]
        return list(data)
    # Linux
    tool = _linux_dns_tool()
    if tool in ("resolvectl", "systemd-resolve"):
        rc, out, _ = run_cmd([tool, "dns", adapter])
        if rc == 0 and ":" in out:
            servers = out.split(":", 1)[1].split()
            if servers:
                return servers
    elif tool == "nmcli":
        rc, out, _ = run_cmd(["nmcli", "-t", "-f", "IP4.DNS", "dev", "show", adapter])
        servers = [l.split(":", 1)[1].strip() for l in out.splitlines() if ":" in l]
        if servers:
            return servers
    # fallback: /etc/resolv.conf
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
            return [l.split()[1] for l in f
                    if l.strip().startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        return []


def get_dns_servers_v6(adapter):
    """Текущие несистемные IPv6 DNS адаптера (без fec0:0:0:ffff::*)."""
    if not IS_WINDOWS:
        return []
    rc, out, _ = run_ps(
        f"(Get-DnsClientServerAddress -InterfaceIndex {adapter} -AddressFamily IPv6"
        f" -ErrorAction SilentlyContinue).ServerAddresses | ConvertTo-Json -Compress"
    )
    if rc != 0 or not out.strip():
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, str):
        data = [data]
    return [str(s).strip() for s in data if not _is_win_default_v6_dns(s)]


def set_dns_servers(adapter, servers):
    """Назначить DNS адаптеру. Возвращает (ok, ошибка)."""
    if IS_WINDOWS:
        servers_list = [str(s).strip() for s in servers if str(s).strip()]
        rc, _, err = run_ps(
            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({})".format(
                adapter, ",".join('"%s"' % s for s in servers_list))
        )
        if rc != 0 and any(":" in s for s in servers_list):
            v4_only = [s for s in servers_list if ":" not in s]
            if v4_only:
                rc4, _, err4 = run_ps(
                    "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({})".format(
                        adapter, ",".join('"%s"' % s for s in v4_only))
                )
                if rc4 == 0:
                    return True, ""
                return False, (err4 or err).strip()
        return rc == 0, err.strip()
    tool = _linux_dns_tool()
    if tool in ("resolvectl", "systemd-resolve"):
        rc, _, err = run_cmd([tool, "dns", adapter] + list(servers))
        if rc == 0:
            # направляем ВСЕ запросы через этот линк
            run_cmd([tool, "domain", adapter, "~."])
        return rc == 0, err.strip()
    if tool == "nmcli":
        conn = _nmcli_connection(adapter)
        if not conn:
            return False, f"нет активного соединения NM для {adapter}"
        rc, _, err = run_cmd(["nmcli", "con", "mod", conn,
                              "ipv4.dns", " ".join(servers),
                              "ipv4.ignore-auto-dns", "yes"])
        if rc == 0:
            run_cmd(["nmcli", "con", "up", conn])
        return rc == 0, err.strip()
    # resolvconf: правим /etc/resolv.conf напрямую
    try:
        bak = "/etc/resolv.conf.securedns.bak"
        should_backup = not os.path.exists(bak)
        if not should_backup:
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as cur_f:
                    if "# SecureDNS" not in cur_f.read():
                        should_backup = True
            except OSError:
                pass
        if should_backup and os.path.exists("/etc/resolv.conf"):
            shutil.copy2("/etc/resolv.conf", bak)
        with open("/etc/resolv.conf", "w", encoding="utf-8") as f:
            f.write("# SecureDNS\n" + "".join(f"nameserver {s}\n" for s in servers))
        return True, ""
    except OSError as e:
        return False, str(e)


def reset_dns_servers(adapter):
    """Вернуть DNS в автоматический режим (DHCP)."""
    if IS_WINDOWS:
        rc, _, err = run_ps(
            f"Set-DnsClientServerAddress -InterfaceIndex {adapter} -ResetServerAddresses")
        return rc == 0, err.strip()
    tool = _linux_dns_tool()
    if tool in ("resolvectl", "systemd-resolve"):
        rc, _, err = run_cmd([tool, "revert", adapter])
        return rc == 0, err.strip()
    if tool == "nmcli":
        conn = _nmcli_connection(adapter)
        if not conn:
            return False, f"нет активного соединения NM для {adapter}"
        rc, _, err = run_cmd(["nmcli", "con", "mod", conn,
                              "ipv4.dns", "", "ipv4.ignore-auto-dns", "no"])
        if rc == 0:
            run_cmd(["nmcli", "con", "up", conn])
        return rc == 0, err.strip()
    try:
        shutil.copy2("/etc/resolv.conf.securedns.bak", "/etc/resolv.conf")
        return True, ""
    except OSError as e:
        return False, str(e)


def flush_dns_cache():
    """Очистить системный кэш DNS (best-effort)."""
    if IS_WINDOWS:
        run_ps("Clear-DnsClientCache")
        return
    tool = _linux_dns_tool()
    if tool in ("resolvectl", "systemd-resolve"):
        run_cmd([tool, "flush-caches"])


def adapter_key(a):
    """Идентификатор адаптера для DNS-операций: ifindex (Windows) или имя (Linux)."""
    return a["index"] if IS_WINDOWS else a["name"]


# ---------------------------------------------------------------------------
# Системные фичи Windows: QUIC Firewall, политики DoH браузеров, автозапуск, трей
# ---------------------------------------------------------------------------

def has_quic_firewall_rule() -> bool:
    """Проверяет, активно ли правило Windows Firewall, блокирующее UDP:443 (QUIC)."""
    if not IS_WINDOWS:
        return False
    rc, _, _ = run_cmd(["netsh", "advfirewall", "firewall", "show", "rule", f"name={QUIC_FW_RULE}"], timeout=8)
    return rc == 0


def set_quic_firewall_block(enabled: bool) -> tuple[bool, str]:
    """Включает или полностью удаляет временное правило блокировки исходящего UDP:443 (QUIC)."""
    if not IS_WINDOWS:
        return False, "поддерживается только на Windows"
    run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={QUIC_FW_RULE}"], timeout=8)
    if not enabled:
        return True, "правило QUIC Firewall снято"
    rc, out, err = run_cmd([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={QUIC_FW_RULE}", "dir=out", "action=block",
        "protocol=UDP", "remoteport=443", "enable=yes",
    ], timeout=10)
    if rc == 0:
        return True, "UDP:443 (QUIC) заблокирован в брандмауэре"
    return False, (err or out or f"rc={rc}").strip()


_BROWSER_DOH_POLICY_KEYS = (
    ("Chrome", r"SOFTWARE\Policies\Google\Chrome"),
    ("Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
    ("Yandex", r"SOFTWARE\Policies\YandexBrowser"),
)


def check_browser_doh_status() -> dict:
    """Проверяет политики реестра и Local State браузеров на свой встроенный DoH."""
    policies = {}
    local_modes = {}
    if not IS_WINDOWS or winreg is None:
        return {
            "policies": policies, "local_modes": local_modes,
            "policy_off": False, "needs_attention": False,
            "summary": "Linux — проверяйте DoH в настройках браузера",
        }

    for name, subkey in _BROWSER_DOH_POLICY_KEYS:
        val = None
        try:
            with winreg.OpenKeyEx(
                winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
            ) as k:
                val, _ = winreg.QueryValueEx(k, "DnsOverHttpsMode")
        except OSError:
            pass
        policies[name] = val

    local_app = os.environ.get("LOCALAPPDATA", "")
    local_state_paths = {
        "Chrome": os.path.join(local_app, "Google", "Chrome", "User Data", "Local State"),
        "Edge": os.path.join(local_app, "Microsoft", "Edge", "User Data", "Local State"),
        "Yandex": os.path.join(local_app, "Yandex", "YandexBrowser", "User Data", "Local State"),
    }
    for name, path in local_state_paths.items():
        try:
            if path and os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                mode = (data.get("dns_over_https") or {}).get("mode")
                if mode:
                    local_modes[name] = str(mode)
        except Exception:  # noqa: BLE001
            pass

    chrome_edge_off = all(
        str(policies.get(b) or "").lower() == "off" for b in ("Chrome", "Edge")
    )
    active_browser_doh = [
        f"{k}={v}" for k, v in local_modes.items()
        if str(v).lower() in ("automatic", "secure") and str(policies.get(k) or "").lower() != "off"
    ]
    if chrome_edge_off and not active_browser_doh:
        summary = "отключён политикой Chrome/Edge (трафик идёт через SecureDNS ✔)"
        needs_att = False
    elif active_browser_doh:
        summary = f"может обходить через свой DoH ({', '.join(active_browser_doh)})"
        needs_att = True
    else:
        summary = "политика не задана (если в браузере «Безопасный DNS» включён — пойдёт мимо)"
        needs_att = True
    return {
        "policies": policies,
        "local_modes": local_modes,
        "policy_off": chrome_edge_off,
        "needs_attention": needs_att,
        "summary": summary,
    }


def set_browser_doh_policy(disable_browser_doh: bool) -> tuple[bool, str]:
    """Ставит или снимает политику HKLM DnsOverHttpsMode='off' для Chrome/Edge/Yandex."""
    if not IS_WINDOWS or winreg is None:
        return False, "поддерживается только на Windows"
    if not is_admin():
        return False, "нужны права администратора"
    try:
        for _, subkey in _BROWSER_DOH_POLICY_KEYS:
            if disable_browser_doh:
                with winreg.CreateKeyEx(
                    winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY
                ) as k:
                    winreg.SetValueEx(k, "DnsOverHttpsMode", 0, winreg.REG_SZ, "off")
            else:
                try:
                    with winreg.OpenKeyEx(
                        winreg.HKEY_LOCAL_MACHINE, subkey, 0,
                        winreg.KEY_READ | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
                    ) as k:
                        cur, _ = winreg.QueryValueEx(k, "DnsOverHttpsMode")
                        if str(cur).lower() == "off":
                            winreg.DeleteValue(k, "DnsOverHttpsMode")
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
        if disable_browser_doh:
            return True, "встроенный DoH в Chrome/Edge/Yandex отключён политикой (перезапустите браузер)"
        return True, "политика запрета DoH в Chrome/Edge/Yandex удалена"
    except OSError as e:
        return False, str(e)


def get_autostart() -> bool:
    """Проверяет задачу Планировщика Windows SecureDNS_Autostart."""
    if not IS_WINDOWS:
        return False
    rc, _, _ = run_cmd(["schtasks", "/Query", "/TN", AUTOSTART_TASK], timeout=8)
    return rc == 0


def set_autostart(enabled: bool) -> tuple[bool, str]:
    """Создаёт или удаляет задачу автозапуска с повышенными правами без окна UAC."""
    if not IS_WINDOWS:
        return False, "поддерживается только на Windows"
    if not is_admin():
        return False, "нужны права администратора"
    if not enabled:
        rc, out, err = run_cmd(["schtasks", "/Delete", "/TN", AUTOSTART_TASK, "/F"], timeout=10)
        if rc == 0 or "не существует" in (out + err).lower() or "does not exist" in (out + err).lower():
            return True, "автозапуск отключён"
        return False, (err or out or f"rc={rc}").strip()

    if is_frozen():
        target = f'"{os.path.abspath(sys.executable)}" --autostart'
    else:
        target = f'"{os.path.abspath(sys.executable)}" "{os.path.abspath(__file__)}" --autostart'
    rc, out, err = run_cmd([
        "schtasks", "/Create", "/TN", AUTOSTART_TASK,
        "/TR", target, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F",
    ], timeout=12)
    if rc == 0:
        return True, "автозапуск через Планировщик Windows включён"
    return False, (err or out or f"rc={rc}").strip()


class Win32Tray:
    """Нативная иконка в системном трее Windows на чистом ctypes без сторонних пакетов."""

    def __init__(self, tooltip: str, icon_path: str | None,
                 on_show, on_status, on_quit):
        self.tooltip = str(tooltip or APP_NAME)[:127]
        self.icon_path = icon_path
        self.on_show = on_show
        self.on_status = on_status
        self.on_quit = on_quit
        self.available = False
        self._thread = None
        self._hwnd = None
        self._stop_req = threading.Event()
        self._ready = threading.Event()
        self._user32 = None
        self._shell32 = None
        self._nid = None
        self._hicon = None
        self._cls_name = f"SecureDNSTrayWnd_{os.getpid()}_{id(self)}"

    def start(self) -> bool:
        if not IS_WINDOWS:
            return False
        if self._thread is not None and self._thread.is_alive():
            return self.available
        self._ready.clear()
        self._stop_req.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Win32Tray")
        self._thread.start()
        self._ready.wait(timeout=2.5)
        return self.available

    def stop(self):
        self._stop_req.set()
        if self._user32 and self._hwnd:
            try:
                self._user32.PostMessageW(self._hwnd, 0x0010, 0, 0)  # WM_CLOSE
            except Exception:  # noqa: BLE001
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
        self.available = False

    def _loop(self):
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user32 = user32
        self._shell32 = shell32

        LRESULT = getattr(wintypes, "LRESULT", ctypes.c_ssize_t)
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT), ("style", wintypes.UINT), ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON), ("hCursor", wintypes.HICON), ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR), ("hIconSm", wintypes.HICON),
            ]

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8),
            ]

        class NOTIFYICONDATAW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("hWnd", wintypes.HWND), ("uID", wintypes.UINT),
                ("uFlags", wintypes.UINT), ("uCallbackMessage", wintypes.UINT), ("hIcon", wintypes.HICON),
                ("szTip", wintypes.WCHAR * 128), ("dwState", wintypes.DWORD), ("dwStateMask", wintypes.DWORD),
                ("szInfo", wintypes.WCHAR * 256), ("uTimeoutOrVersion", wintypes.UINT),
                ("szInfoTitle", wintypes.WCHAR * 64), ("dwInfoFlags", wintypes.DWORD),
                ("guidItem", GUID), ("hBalloonIcon", wintypes.HICON),
            ]

        class POINT(ctypes.Structure):
            _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]

        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = LRESULT
        user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        user32.RegisterClassExW.restype = wintypes.ATOM
        user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        user32.UnregisterClassW.restype = wintypes.BOOL
        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.LoadImageW.restype = wintypes.HANDLE
        user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
        user32.LoadIconW.restype = wintypes.HICON
        user32.DestroyIcon.argtypes = [wintypes.HICON]
        user32.CreatePopupMenu.restype = wintypes.HMENU
        user32.AppendMenuW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.WPARAM, wintypes.LPCWSTR]
        user32.TrackPopupMenu.argtypes = [wintypes.HMENU, wintypes.UINT, ctypes.c_int, ctypes.c_int, ctypes.c_int, wintypes.HWND, wintypes.LPVOID]
        user32.TrackPopupMenu.restype = wintypes.BOOL
        user32.DestroyMenu.argtypes = [wintypes.HMENU]
        user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.RegisterWindowMessageW.argtypes = [wintypes.LPCWSTR]
        user32.RegisterWindowMessageW.restype = wintypes.UINT
        shell32.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        shell32.Shell_NotifyIconW.restype = wintypes.BOOL
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE

        WM_TRAY = 0x8001
        wm_taskbar = user32.RegisterWindowMessageW("TaskbarCreated")
        hinst = kernel32.GetModuleHandleW(None)
        nid_ref = [None]
        hicon_own = None

        if self.icon_path and os.path.exists(self.icon_path):
            hicon_own = user32.LoadImageW(None, self.icon_path, 1, 16, 16, 0x10)
        hicon = hicon_own or user32.LoadIconW(None, ctypes.cast(32512, wintypes.LPCWSTR))
        self._hicon = hicon_own

        def show_menu(hwnd):
            pt = POINT()
            user32.GetCursorPos(ctypes.byref(pt))
            user32.SetForegroundWindow(hwnd)
            menu = user32.CreatePopupMenu()
            try:
                user32.AppendMenuW(menu, 0x0000, 1, "Открыть SecureDNS")
                user32.AppendMenuW(menu, 0x0000, 2, "Обновить статус")
                user32.AppendMenuW(menu, 0x0800, 0, None)
                user32.AppendMenuW(menu, 0x0000, 3, "Отключить DNS и выйти")
                cmd = user32.TrackPopupMenu(menu, 0x0100 | 0x0002, pt.x, pt.y, 0, hwnd, None)
                user32.PostMessageW(hwnd, 0, 0, 0)
            finally:
                user32.DestroyMenu(menu)
            if cmd == 1:
                self.on_show()
            elif cmd == 2:
                self.on_status()
            elif cmd == 3:
                self.on_quit()

        def wndproc(hwnd, msg, wp, lp):
            if msg == WM_TRAY:
                ev = lp & 0xFFFF
                if ev in (0x0202, 0x0203):  # WM_LBUTTONUP / WM_LBUTTONDBLCLK
                    self.on_show()
                elif ev == 0x0205:  # WM_RBUTTONUP
                    show_menu(hwnd)
                return 0
            if wm_taskbar and msg == wm_taskbar and nid_ref[0] is not None:
                shell32.Shell_NotifyIconW(0, ctypes.byref(nid_ref[0]))
                return 0
            if msg == 0x0010:  # WM_CLOSE
                if nid_ref[0] is not None:
                    shell32.Shell_NotifyIconW(2, ctypes.byref(nid_ref[0]))
                user32.DestroyWindow(hwnd)
                return 0
            if msg == 0x0002:  # WM_DESTROY
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wp, lp)

        proc_cb = WNDPROC(wndproc)  # держим ссылку на callback, пока жив цикл сообщений
        wc = WNDCLASSEXW(cbSize=ctypes.sizeof(WNDCLASSEXW), lpfnWndProc=proc_cb, hInstance=hinst, lpszClassName=self._cls_name)
        hwnd = None
        try:
            atom = user32.RegisterClassExW(ctypes.byref(wc))
            if not atom:
                return
            hwnd = user32.CreateWindowExW(0, self._cls_name, APP_NAME, 0, 0, 0, 0, 0, None, None, hinst, None)
            self._hwnd = hwnd
            if not hwnd:
                return
            nid = NOTIFYICONDATAW(
                cbSize=ctypes.sizeof(NOTIFYICONDATAW),
                hWnd=hwnd,
                uID=1,
                uFlags=0x07,  # NIF_MESSAGE | NIF_ICON | NIF_TIP
                uCallbackMessage=WM_TRAY,
                hIcon=hicon,
                szTip=self.tooltip,
            )
            nid_ref[0] = nid
            self._nid = nid
            self.available = bool(shell32.Shell_NotifyIconW(0, ctypes.byref(nid)))
            self._ready.set()
            if not self.available or self._stop_req.is_set():
                return
            msg_st = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg_st), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg_st))
                user32.DispatchMessageW(ctypes.byref(msg_st))
        finally:
            self._ready.set()
            if nid_ref[0] is not None:
                try:
                    shell32.Shell_NotifyIconW(2, ctypes.byref(nid_ref[0]))
                except Exception:  # noqa: BLE001
                    pass
            self._hwnd = None
            if hwnd:
                try:
                    user32.DestroyWindow(hwnd)
                except Exception:  # noqa: BLE001
                    pass
            try:
                user32.UnregisterClassW(self._cls_name, hinst)
            except Exception:  # noqa: BLE001
                pass
            if hicon_own:
                try:
                    user32.DestroyIcon(hicon_own)
                except Exception:  # noqa: BLE001
                    pass
            self._hicon = None


# ---------------------------------------------------------------------------
# Автообновление (GitHub)
# ---------------------------------------------------------------------------

UPDATE_VERSION_URL = "https://raw.githubusercontent.com/MAECTRO/SecureDNS/main/version.txt"
UPDATE_EXE_URL = "https://github.com/MAECTRO/SecureDNS/releases/latest/download/SecureDNS.exe"
UPDATE_SRC_URL = "https://raw.githubusercontent.com/MAECTRO/SecureDNS/main/main.py"
UPDATE_RELEASE_API_URL = "https://api.github.com/repos/MAECTRO/SecureDNS/releases/latest"


def _fetch(url: str, timeout: float = 8.0, extra_headers: dict | None = None) -> bytes:
    import urllib.request
    headers = {"User-Agent": f"SecureDNS/{APP_VERSION}"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _parse_ver(s: str):
    cleaned = str(s or "").strip().lstrip("vV")
    m = re.match(r"(\d+(?:\.\d+)*)", cleaned)
    if not m:
        return (0,)
    return tuple(int(x) for x in m.group(1).split("."))


def _fetch_latest_release():
    raw = _fetch(
        UPDATE_RELEASE_API_URL,
        timeout=8.0,
        extra_headers={
            "Accept": "application/vnd.github+json",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        },
    )
    return json.loads(raw.decode("utf-8", "replace"))


def check_for_update_info():
    """Возвращает dict {'version', 'url', 'size'} если есть более новая версия на GitHub, иначе None."""
    if is_frozen() and not IS_WINDOWS:
        return None

    remote_ver = None
    download_url = None
    expected_size = None
    no_cache = {"Cache-Control": "no-cache", "Pragma": "no-cache"}

    if is_frozen() and IS_WINDOWS:
        try:
            rel = _fetch_latest_release()
            tag = str(rel.get("tag_name") or "").strip()
            assets = rel.get("assets") or []
            exe_asset = next(
                (a for a in assets if str(a.get("name") or "").lower() == "securedns.exe"),
                None,
            )
            if tag and exe_asset and exe_asset.get("browser_download_url"):
                remote_ver = tag.lstrip("vV")
                download_url = str(exe_asset["browser_download_url"])
                raw_size = exe_asset.get("size")
                expected_size = int(raw_size) if raw_size is not None else None
            elif tag:
                # Релиз ещё без прикреплённого exe — не предлагаем обновление
                return None
        except Exception:  # noqa: BLE001 — API недоступен: fallback на version.txt
            try:
                remote_ver = _fetch(UPDATE_VERSION_URL, extra_headers=no_cache).decode("utf-8", "replace").strip()
                download_url = UPDATE_EXE_URL
            except Exception:  # noqa: BLE001
                return None
    else:
        try:
            remote_ver = _fetch(UPDATE_VERSION_URL, extra_headers=no_cache).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            try:
                rel = _fetch_latest_release()
                remote_ver = str(rel.get("tag_name") or "").strip().lstrip("vV")
            except Exception:  # noqa: BLE001
                return None
        download_url = UPDATE_SRC_URL

    if remote_ver and _parse_ver(remote_ver) > _parse_ver(APP_VERSION):
        return {
            "version": remote_ver,
            "url": download_url,
            "size": expected_size,
        }
    return None


def check_for_update():
    """Возвращает строку новой версии, если на GitHub есть новее, иначе None."""
    info = check_for_update_info()
    return info["version"] if info else None


def _ps_single_quote(value: str) -> str:
    return str(value).replace("'", "''")


def do_update(log, download_url=None, expected_size=None, on_before_restart=None):
    """Скачивает и применяет обновление.
    Возвращает 'restart' (перезапустится сам), 'manual' (нужен ручной перезапуск),
    либо None при ошибке."""
    try:
        if is_frozen() and not IS_WINDOWS:
            log("  ✘ Автообновление готового бинарника для Linux не поддерживается; обновите вручную.")
            return None

        if is_frozen() and IS_WINDOWS:
            exe = os.path.abspath(sys.executable)
            new_exe = exe + ".new"
            log("  Скачиваю новую версию…")
            data = _fetch(download_url or UPDATE_EXE_URL, timeout=60.0)
            if len(data) < 1_000_000 or not data.startswith(b"MZ"):
                log("  ✘ Скачанное не похоже на exe. Обновление отменено.")
                return None
            if expected_size is not None and len(data) != int(expected_size):
                log(f"  ✘ Размер файла не совпал ({len(data)} != {expected_size}). Обновление отменено.")
                return None
            try:
                with open(new_exe, "wb") as f:
                    f.write(data)
            except OSError:
                try:
                    if os.path.exists(new_exe):
                        os.remove(new_exe)
                except OSError:
                    pass
                raise

            if on_before_restart is not None:
                on_before_restart()

            ps1_path = os.path.join(tempfile.gettempdir(), f"securedns_update_{os.getpid()}.ps1")
            ps1_script = (
                "$ErrorActionPreference = 'SilentlyContinue'\n"
                f"$TargetPid = {os.getpid()}\n"
                f"$NewExe = '{_ps_single_quote(new_exe)}'\n"
                f"$Exe = '{_ps_single_quote(exe)}'\n"
                f"$WorkDir = '{_ps_single_quote(os.path.dirname(exe))}'\n"
                "try {\n"
                "    for ($i = 0; $i -lt 100; $i++) {\n"
                "        if (-not (Get-Process -Id $TargetPid -ErrorAction SilentlyContinue)) { break }\n"
                "        Start-Sleep -Milliseconds 300\n"
                "    }\n"
                "    $moved = $false\n"
                "    for ($j = 0; $j -lt 15; $j++) {\n"
                "        try {\n"
                "            Move-Item -LiteralPath $NewExe -Destination $Exe -Force -ErrorAction Stop\n"
                "            $moved = $true\n"
                "            break\n"
                "        } catch {\n"
                "            Start-Sleep -Milliseconds 500\n"
                "        }\n"
                "    }\n"
                "    if ($moved) {\n"
                "        Get-ChildItem Env: | Where-Object { $_.Name -like '_PYI_*' -or $_.Name -like '_MEIPASS*' } | Remove-Item -Force -ErrorAction SilentlyContinue\n"
                "        Start-Process -FilePath $Exe -WorkingDirectory $WorkDir\n"
                "    }\n"
                "} finally {\n"
                "    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue\n"
                "}\n"
            )
            with open(ps1_path, "w", encoding="utf-8-sig", newline="\r\n") as f:
                f.write(ps1_script)
            clean_env = {
                k: v for k, v in os.environ.items()
                if not k.upper().startswith(("_PYI_", "_MEIPASS"))
            }
            subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-WindowStyle",
                    "Hidden",
                    "-File",
                    ps1_path,
                ],
                creationflags=0x08000000 | 0x00000200,
                close_fds=True,
                env=clean_env,
            )
            log("  ✔ Обновление скачано, перезапускаюсь…")
            return "restart"

        # Запуск из исходников: подменяем main.py атомарно через временный файл
        log("  Скачиваю новую версию исходников…")
        data = _fetch(UPDATE_SRC_URL, timeout=30.0, extra_headers={"Cache-Control": "no-cache"})
        text = data.decode("utf-8").replace("\r\n", "\n")
        if "APP_VERSION" not in text or "LocalDNSProxy" not in text:
            log("  ✘ Скачанное не похоже на main.py. Обновление отменено.")
            return None
        compile(text, "main.py", "exec")  # проверка синтаксиса до подмены
        target = os.path.abspath(__file__)
        tmp_target = target + ".new"
        try:
            with open(tmp_target, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            shutil.copy2(target, target + ".bak")
            os.replace(tmp_target, target)
        finally:
            if os.path.exists(tmp_target):
                try:
                    os.remove(tmp_target)
                except OSError:
                    pass
        ver_file = os.path.join(os.path.dirname(target), "version.txt")
        if os.path.exists(ver_file):
            m_ver = re.search(r'^APP_VERSION\s*=\s*["\']([^"\']+)["\']', text, re.M)
            if m_ver:
                try:
                    with open(ver_file, "w", encoding="utf-8", newline="\n") as vf:
                        vf.write(m_ver.group(1).strip() + "\n")
                except OSError:
                    pass
        log("  ✔ main.py обновлён (старый сохранён как main.py.bak). "
            "Перезапустите программу.")
        return "manual"
    except Exception as e:  # noqa: BLE001
        log(f"  ✘ Ошибка обновления: {e}")
        return None


def restore_adapter_dns(key):
    """Вернуть DNS адаптера: из бэкапа (IPv4 + IPv6), либо в DHCP. Возвращает (ok, описание)."""
    v4, v6 = load_backup_full(key)
    v4_valid = [s for s in v4 if s != LOCAL_DNS]
    v6_valid = [s for s in v6 if s != LOCAL_DNS_V6 and not _is_win_default_v6_dns(s)]
    if IS_WINDOWS:
        ok_reset, err_reset = reset_dns_servers(key)
        combined = v4_valid + v6_valid
        if combined:
            ok_set, err_set = set_dns_servers(key, combined)
            if ok_set:
                return True, f"восстановлены DNS: {', '.join(combined)}"
            ok2, err2 = reset_dns_servers(key)
            return ok2, (
                "бэкап не применился, DNS возвращён в авто (DHCP)"
                if ok2 else f"{err_set}; и DHCP не сработал: {err2}"
            )
        return ok_reset, ("DNS возвращён в авто (DHCP)" if ok_reset else f"ошибка: {err_reset}")
    if v4_valid:
        ok, err = set_dns_servers(key, v4_valid)
        if ok:
            return True, f"восстановлены DNS: {', '.join(v4_valid)}"
        # бэкап не применился — уходим в DHCP как безопасный вариант
        ok2, err2 = reset_dns_servers(key)
        return ok2, ("бэкап не применился, DNS возвращён в авто (DHCP)"
                     if ok2 else f"{err}; и DHCP не сработал: {err2}")
    ok, err = reset_dns_servers(key)
    return ok, ("DNS возвращён в авто (DHCP)" if ok else f"ошибка: {err}")


def startup_rollback(log, should_abort=None):
    """Аварийный откат: если адаптер смотрит на 127.0.0.1 или ::1, а прокси не запущен —
    значит программу закрыли/убили с активной защитой. Возвращаем настройки."""
    if should_abort and should_abort():
        return
    if IS_WINDOWS and has_quic_firewall_rule():
        if not (should_abort and should_abort()) and is_admin():
            ok_fw, msg_fw = set_quic_firewall_block(False)
            log(f"⚠ Обнаружено правило QUIC Firewall от прошлой сессии: {msg_fw}")
    for a in get_adapters():
        if should_abort and should_abort():
            return
        k = adapter_key(a)
        stuck_v4 = get_dns_servers(k) == [LOCAL_DNS]
        stuck_v6 = get_dns_servers_v6(k) == [LOCAL_DNS_V6]
        if stuck_v4 or stuck_v6:
            if should_abort and should_abort():
                return
            if not is_admin():
                log(f"⚠ Адаптер «{a['name']}» смотрит на 127.0.0.1/::1, но прокси не "
                    f"запущен. Для отката нужны права — перезапустите: {admin_hint()}")
                continue
            ok, msg = restore_adapter_dns(k)
            flush_dns_cache()
            log(f"⚠ Обнаружен «зависший» DNS на «{a['name']}» (программа "
                f"была закрыта с активной защитой). Автооткат: {msg}")


# Порт «замка» единственного экземпляра (не имеет отношения к DNS)
SINGLE_INSTANCE_ADDR = (LOCAL_DNS, 53177)
_INSTANCE_GUARD = None


def acquire_single_instance():
    """Не даём запустить вторую копию: держим TCP-сокет на служебном порту.
    Возвращает сокет-замок (держать открытым) или None, если копия уже есть."""
    global _INSTANCE_GUARD
    if _INSTANCE_GUARD is not None:
        return _INSTANCE_GUARD
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(SINGLE_INSTANCE_ADDR)
        s.listen(1)
        _INSTANCE_GUARD = s
        return s
    except OSError:
        s.close()
        return None


def release_single_instance():
    global _INSTANCE_GUARD
    s = _INSTANCE_GUARD
    _INSTANCE_GUARD = None
    if s is not None:
        try:
            s.close()
        except OSError:
            pass


def save_backup(if_index: int, servers, servers_v6=None):
    v4_clean = [str(s).strip() for s in (servers or []) if str(s).strip()]
    v6_clean = None
    if servers_v6 is not None:
        v6_clean = [str(s).strip() for s in servers_v6 if not _is_win_default_v6_dns(s)]

    save_v4 = v4_clean != [LOCAL_DNS]
    save_v6 = (v6_clean is not None) and (v6_clean != [LOCAL_DNS_V6])
    if not save_v4 and not save_v6:
        return
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        data = {}
        if os.path.exists(BACKUP_FILE):
            try:
                with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
            except (OSError, json.JSONDecodeError):
                pass
        entry = data.get(str(if_index))
        if not isinstance(entry, dict):
            entry = {}
        if save_v4:
            entry["servers"] = v4_clean
        if save_v6:
            entry["servers_v6"] = v6_clean
        data[str(if_index)] = entry
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def load_backup_full(if_index: int) -> tuple[list, list]:
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            entry = json.load(f).get(str(if_index), {})
        if not isinstance(entry, dict):
            return [], []
        v4 = [str(s).strip() for s in entry.get("servers", []) if str(s).strip()]
        v6 = [str(s).strip() for s in entry.get("servers_v6", []) if not _is_win_default_v6_dns(s)]
        return v4, v6
    except (OSError, json.JSONDecodeError):
        return [], []


def load_backup(if_index: int):
    v4, _ = load_backup_full(if_index)
    return v4


# ---------------------------------------------------------------------------
# Шифрованный апстрим: DoT и DoH
# ---------------------------------------------------------------------------

def make_ssl_context(verify: bool, server_hostname: str | None):
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class _SplitTLSRawIO(io.RawIOBase):
    """Адаптер потока для http.client.HTTPResponse.makefile('rb') поверх SplitTLSSocket."""

    def __init__(self, wrapper):
        self._w = wrapper

    def readable(self):
        return True

    def readinto(self, b):
        data = self._w.recv(len(b))
        n = len(data)
        b[:n] = data
        return n


class SplitTLSSocket:
    """Обёртка над SSLObject+MemoryBIO, дробящая первый пакет TLS ClientHello (по умолчанию 3 байта + остаток)."""

    def __init__(self, sock: socket.socket, ssl_obj: ssl.SSLObject,
                 in_bio: ssl.MemoryBIO, out_bio: ssl.MemoryBIO,
                 split_bytes: int = 3, split_delay: float = 0.015):
        self._sock = sock
        self._ssl = ssl_obj
        self._in = in_bio
        self._out = out_bio
        self._split_bytes = split_bytes
        self._split_delay = split_delay
        self._first_flight = True

    def _flush_out(self):
        data = self._out.read()
        if not data:
            return
        if self._first_flight and self._split_bytes > 0 and len(data) > self._split_bytes:
            self._first_flight = False
            try:
                self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            self._sock.sendall(data[:self._split_bytes])
            if self._split_delay > 0:
                time.sleep(self._split_delay)
            self._sock.sendall(data[self._split_bytes:])
        else:
            self._first_flight = False
            self._sock.sendall(data)

    def _feed_in(self):
        chunk = self._sock.recv(16384)
        if not chunk:
            raise ConnectionError("соединение закрыто во время TLS-рукопожатия")
        self._in.write(chunk)

    def do_handshake(self):
        while True:
            try:
                self._ssl.do_handshake()
                self._flush_out()
                return
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()
            except ssl.SSLWantWriteError:
                self._flush_out()

    def send(self, data):
        while True:
            try:
                n = self._ssl.write(data)
                self._flush_out()
                return n
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()
            except ssl.SSLWantWriteError:
                self._flush_out()

    def sendall(self, data):
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            try:
                n = self._ssl.write(view[sent:])
                self._flush_out()
                sent += n
            except ssl.SSLWantReadError:
                self._flush_out()
                self._feed_in()
            except ssl.SSLWantWriteError:
                self._flush_out()

    def recv(self, bufsize: int = 4096) -> bytes:
        while True:
            try:
                self._flush_out()
                return self._ssl.read(bufsize)
            except ssl.SSLWantReadError:
                chunk = self._sock.recv(max(4096, bufsize))
                if not chunk:
                    return b""
                self._in.write(chunk)
            except ssl.SSLWantWriteError:
                self._flush_out()
            except ssl.SSLZeroReturnError:
                return b""

    def makefile(self, mode: str = "r", buffering=None):
        raw = _SplitTLSRawIO(self)
        if buffering == 0:
            return raw
        return io.BufferedReader(raw, buffer_size=buffering or 8192)

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def fileno(self):
        return self._sock.fileno()

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


def _connect_tls_once(ip: str, port: int, ctx: ssl.SSLContext, server_hostname: str | None,
                      connect_timeout: float, io_timeout: float, use_split: bool = False):
    raw = socket.create_connection((ip, port), timeout=connect_timeout)
    try:
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        raw.settimeout(connect_timeout)
        if use_split:
            in_bio = ssl.MemoryBIO()
            out_bio = ssl.MemoryBIO()
            ssl_obj = ctx.wrap_bio(in_bio, out_bio, server_hostname=server_hostname)
            sock = SplitTLSSocket(raw, ssl_obj, in_bio, out_bio, split_bytes=3, split_delay=0.015)
            sock.do_handshake()
        else:
            sock = ctx.wrap_socket(raw, server_hostname=server_hostname)
        sock.settimeout(io_timeout)
        return sock
    except Exception:
        try:
            raw.close()
        except OSError:
            pass
        raise


def _connect_tls_smart(ip: str, port: int, ctx: ssl.SSLContext, server_hostname: str | None,
                       connect_timeout: float, io_timeout: float, split_hello: bool = False):
    """Открывает TLS-сокет с быстрым ретраем при потерях и фоллбэком между резкой и цельным ClientHello."""
    if port == 443:
        attempts = [True, True, False] if split_hello else [False, False, True]
    else:
        attempts = [True, False] if split_hello else [False, False]

    last_err = None
    for use_split in attempts:
        try:
            return _connect_tls_once(
                ip, port, ctx, server_hostname,
                connect_timeout=connect_timeout, io_timeout=io_timeout, use_split=use_split,
            )
        except ssl.SSLCertVerificationError:
            raise
        except ConnectionRefusedError:
            raise
        except Exception as e:  # noqa: BLE001
            last_err = e
    raise last_err


class DoTUpstream:
    """DNS-over-TLS (RFC 7858): пул TLS-соединений на порт 853, кадрирование 2 байта длины."""

    def __init__(self, ip: str, port: int = 853, verify: bool = False,
                 hostname: str | None = None, timeout: float = 6.0,
                 split_hello: bool = False, connect_timeout: float = 4.0):
        self.ip, self.port, self.timeout = ip, port, timeout
        self.connect_timeout = min(float(connect_timeout), float(timeout))
        self.hostname = hostname
        self.verify = verify
        self.split_hello = bool(split_hello)
        self._ctx = make_ssl_context(verify, hostname)
        self._pool = queue.LifoQueue(maxsize=4)
        self._closed = False

    def _connect(self):
        sni = self.hostname or (self.ip if self.verify else None)
        return _connect_tls_smart(
            self.ip, self.port, self._ctx, sni,
            connect_timeout=self.connect_timeout, io_timeout=self.timeout,
            split_hello=self.split_hello,
        )

    @staticmethod
    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("соединение закрыто")
            buf += chunk
        return buf

    def _roundtrip(self, s, packet: bytes) -> bytes:
        s.settimeout(self.timeout)
        s.sendall(struct.pack("!H", len(packet)) + packet)
        ln = struct.unpack("!H", self._recv_exact(s, 2))[0]
        if ln < 2:
            raise IOError("некорректная длина DNS-ответа")
        resp = self._recv_exact(s, ln)
        if len(packet) >= 2 and resp[:2] != packet[:2]:
            raise IOError("несовпадение Transaction ID")
        return resp

    def _put_sock(self, s):
        if self._closed:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            self._pool.put_nowait(s)
        except queue.Full:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass

    def query(self, packet: bytes) -> bytes:
        # 1. Пробуем переиспользовать сокеты из пула (до 2 попыток на случай протухшего)
        for _ in range(2):
            try:
                s = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                resp = self._roundtrip(s, packet)
                self._put_sock(s)
                return resp
            except Exception:  # noqa: BLE001
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass

        # 2. Открываем свежее TLS-соединение (с быстрым ретраем в _connect_tls_smart)
        s = None
        try:
            s = self._connect()
            resp = self._roundtrip(s, packet)
            self._put_sock(s)
            return resp
        except Exception as e:  # noqa: BLE001
            if s is not None:
                try:
                    s.close()
                except Exception:  # noqa: BLE001
                    pass
            raise IOError(f"DoT {self.ip}: {e}")

    def close(self):
        self._closed = True
        while True:
            try:
                s = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass


class DoHUpstream:
    """DNS-over-HTTPS (RFC 8484): пул Keep-Alive соединений POST application/dns-message.

    Решает «проблему курицы и яйца»: коннектимся напрямую на bootstrap IP
    (или зарезолвленный до переключения DNS), переиспользуем открытый TLS-сокет
    по HTTP/1.1 Keep-Alive и быстро ретраим рукопожатие при потерях пакетов на :443.
    """

    def __init__(self, url: str, verify: bool = True,
                 bootstrap_ip: str | None = None, timeout: float = 6.0,
                 bootstrap_ips: list[str] | None = None,
                 split_hello: bool = False, connect_timeout: float = 4.0,
                 defer_resolve: bool = False, bootstrap_dns_ips: list[str] | None = None):
        from urllib.parse import urlparse
        u = urlparse(url)
        if not u.hostname:
            raise ValueError("некорректный DoH URL")
        self.url = url
        self.host = u.hostname
        self.port = u.port or 443
        self.path = u.path or "/dns-query"
        if u.query:
            self.path += "?" + u.query
        self.verify = bool(verify)
        self.timeout = timeout
        self.connect_timeout = min(float(connect_timeout), float(timeout))
        self.split_hello = bool(split_hello)
        self._ctx = make_ssl_context(verify, self.host)
        ips = [ip for ip in (bootstrap_ips or []) if ip]
        if not ips and bootstrap_ip:
            ips = [bootstrap_ip]
        self._explicit_ips = bool(ips)
        self._ips = list(dict.fromkeys(ips))
        self._bootstrap_dns_ips = [ip for ip in (bootstrap_dns_ips or []) if _valid_ip(ip)]
        self._pool = queue.LifoQueue(maxsize=4)
        self._closed = False
        if not self._ips and not defer_resolve:
            self._resolve()

    def _resolve(self):
        """Резолвим IPv4 хоста (включая прямой UDP-резолв в обход 127.0.0.1)."""
        ips = resolve_bootstrap_ips(self.host, self._bootstrap_dns_ips)
        if ips:
            self._ips = ips

    def _pop_conn(self, ip: str):
        requeue = []
        found = None
        while True:
            try:
                item_ip, conn = self._pool.get_nowait()
            except queue.Empty:
                break
            if found is None and item_ip == ip:
                found = conn
                break
            requeue.append((item_ip, conn))
        for item in requeue:
            try:
                self._pool.put_nowait(item)
            except queue.Full:
                try:
                    item[1].close()
                except Exception:  # noqa: BLE001
                    pass
        return found

    def _push_conn(self, ip: str, conn):
        if self._closed:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            return
        try:
            self._pool.put_nowait((ip, conn))
        except queue.Full:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

    def _send_over_conn(self, conn: http.client.HTTPSConnection, packet: bytes) -> tuple[bytes, bool, int]:
        host_hdr = self.host if self.port == 443 else f"{self.host}:{self.port}"
        if conn.sock is not None:
            conn.sock.settimeout(self.timeout)
        conn.request("POST", self.path, body=packet, headers={
            "Host": host_hdr,
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "Connection": "keep-alive",
        })
        resp = conn.getresponse()
        body = resp.read()
        keep = (not resp.will_close) and (not self._closed)
        return body, keep, resp.status

    def query(self, packet: bytes) -> bytes:
        if not self._ips and not self._explicit_ips:
            self._resolve()
        last = None
        targets = self._ips if self._explicit_ips else (self._ips or [self.host])
        for ip in targets:
            try:
                return self._query_via(ip, packet)
            except Exception as e:  # noqa: BLE001
                last = e
        if not self._explicit_ips:
            self._resolve()  # вдруг адрес сменился
        raise IOError(f"DoH {self.host}: {last}")

    def _query_via(self, ip: str, packet: bytes) -> bytes:
        # 1. Пробуем живой Keep-Alive коннект из пула
        for _ in range(2):
            conn = self._pop_conn(ip)
            if conn is None:
                break
            try:
                body, keep, status = self._send_over_conn(conn, packet)
            except Exception:  # noqa: BLE001
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
                continue
            if status != 200:
                try:
                    conn.close()
                except Exception:  # noqa: BLE001
                    pass
                raise IOError(f"DoH {self.host}: HTTP {status}")
            if keep:
                self._push_conn(ip, conn)
            else:
                conn.close()
            return body

        # 2. Открываем новое TLS-соединение (с быстрым ретраем и фоллбэком резки для :443)
        sock = _connect_tls_smart(
            ip, self.port, self._ctx, self.host,
            connect_timeout=self.connect_timeout, io_timeout=self.timeout,
            split_hello=self.split_hello,
        )
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        conn.sock = sock
        try:
            body, keep, status = self._send_over_conn(conn, packet)
            if status != 200:
                conn.close()
                raise IOError(f"DoH {self.host}: HTTP {status}")
            if keep:
                self._push_conn(ip, conn)
            else:
                conn.close()
            return body
        except Exception:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            raise

    def close(self):
        self._closed = True
        while True:
            try:
                _, conn = self._pool.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def parse_split_domains(raw) -> tuple[str, ...]:
    """Разбирает строку/список доменов (поддержка #, *, URL, запятых, переносов строк)."""
    if isinstance(raw, (list, tuple, set)):
        raw_text = "\n".join(str(x) for x in raw)
    else:
        raw_text = str(raw or "")
    out = []
    seen = set()
    for line in raw_text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for tok in re.split(r"[\s,;]+", line):
            tok = tok.strip()
            if not tok:
                continue
            if "://" in tok or "/" in tok:
                host = _clean_sni_host(tok) or ""
            else:
                host = tok.split(":", 1)[0]
            while host.startswith("*."):
                host = host[2:]
            host = host.strip(".*").lower()
            if not host or "." not in host or ".." in host:
                continue
            if not all(ch.isalnum() or ch in "-._" for ch in host):
                continue
            if host not in seen:
                seen.add(host)
                out.append(host)
    return tuple(out)


def match_split_domain(qname: str, domains_set) -> bool:
    """True, если qname совпадает с доменом из списка или является его поддоменом."""
    if not qname or not domains_set or qname.startswith("<"):
        return False
    q = qname.strip().rstrip(".").lower()
    if not q:
        return False
    while True:
        if q in domains_set:
            return True
        dot = q.find(".")
        if dot == -1:
            return False
        q = q[dot + 1:]


class PlainUDPUpstream:
    """Обычный UDP/TCP:53 апстрим для прямого трафика мимо SmartDNS (без цикла на 127.0.0.1)."""

    def __init__(self, ip: str, port: int = 53, timeout: float = 2.5):
        if not _valid_ip(ip):
            raise ValueError(f"некорректный прямой DNS IP: {ip}")
        self.ip = ip
        self.port = int(port)
        self.timeout = float(timeout)

    def query(self, packet: bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(packet, (self.ip, self.port))
            resp, _ = s.recvfrom(4096)
        if len(resp) < 2 or (len(packet) >= 2 and resp[:2] != packet[:2]):
            raise IOError("некорректный UDP-ответ DNS")
        if len(resp) >= 3 and (resp[2] & 0x02):  # TC=1 -> дочитываем по TCP
            with socket.create_connection((self.ip, self.port), timeout=self.timeout) as ts:
                ts.settimeout(self.timeout)
                ts.sendall(struct.pack("!H", len(packet)) + packet)
                ln = struct.unpack("!H", DoTUpstream._recv_exact(ts, 2))[0]
                if ln < 2:
                    raise IOError("некорректная длина TCP-ответа DNS")
                resp = DoTUpstream._recv_exact(ts, ln)
        return resp

    def close(self):
        pass


def resolve_direct_dns(if_index, pre_old_v4=None, manual_raw: str = "") -> tuple[list[str], str]:
    """Определяет рабочий прямой IPv4 DNS для не-ИИ доменов при раздельном DNS."""
    manual_ips = [s.strip() for s in str(manual_raw or "").split(",") if s.strip()]
    valid_manual = [ip for ip in manual_ips if _valid_ip(ip)]
    if valid_manual:
        return list(dict.fromkeys(valid_manual)), "указан вручную"

    valid_old = [ip for ip in (pre_old_v4 or []) if _valid_ip(ip)]
    if valid_old:
        return list(dict.fromkeys(valid_old)), "из адаптера"

    bak_v4 = [ip for ip in load_backup(if_index) if _valid_ip(ip)]
    if bak_v4:
        return list(dict.fromkeys(bak_v4)), "из бэкапа"

    if IS_WINDOWS and if_index is not None:
        rc, out, _ = run_ps(
            f"(Get-NetIPConfiguration -InterfaceIndex {if_index} -ErrorAction SilentlyContinue)"
            f".IPv4DefaultGateway.NextHop | ConvertTo-Json -Compress",
            timeout=5,
        )
        if rc == 0 and out.strip():
            try:
                gw_data = json.loads(out)
                if isinstance(gw_data, str):
                    gw_data = [gw_data]
                valid_gw = [str(ip).strip() for ip in gw_data if _valid_ip(str(ip).strip())]
                if valid_gw:
                    return list(dict.fromkeys(valid_gw)), "шлюз роутера"
            except (json.JSONDecodeError, TypeError):
                pass

    return list(FALLBACK_DIRECT_DNS), "резерв (77.88.8.8)"


def resolve_bootstrap_ips(host: str, direct_dns_ips: list[str] | None = None) -> list[str]:
    """Находит IPv4-адреса для домена DoH напрямую (через UDP:53 в обход 127.0.0.1 или через ОС)."""
    h = str(host or "").strip().strip(".")
    if not h:
        return []
    try:
        ip_obj = ipaddress.IPv4Address(h)
        return [str(ip_obj)] if not ip_obj.is_unspecified and not ip_obj.is_loopback else []
    except ValueError:
        pass

    # 1. Прямой UDP A-запрос к провайдерским/публичным серверам (не зависит от того, задан ли 127.0.0.1)
    q = build_dns_query(h, qtype=1)
    candidates = []
    for ip in list(direct_dns_ips or []) + ["77.88.8.8", "1.1.1.1", "8.8.8.8"]:
        if _valid_ip(ip) and ip not in candidates:
            candidates.append(ip)
    for dns_ip in candidates:
        try:
            resp = PlainUDPUpstream(dns_ip, timeout=2.0).query(q)
            ans = [ip for ip in parse_answers(resp) if _valid_ip(ip)]
            if ans:
                return list(dict.fromkeys(ans))
        except Exception:  # noqa: BLE001
            pass

    # 2. Фоллбэк на системный резолвер (поддерживает hosts и корпоративные имена)
    try:
        infos = socket.getaddrinfo(h, 443, socket.AF_INET)
        sys_ips = sorted({i[4][0] for i in infos if _valid_ip(i[4][0])})
        if sys_ips:
            return sys_ips
    except OSError:
        pass
    return []


def expand_doh_upstreams(url: str, verify: bool, split_hello: bool,
                         ips: list[str] | None = None,
                         direct_dns_ips: list[str] | None = None) -> tuple[list, list[str]]:
    """Превращает DoH URL (+ пустые или явные IP) в список независимых DoHUpstream на каждый IP."""
    from urllib.parse import urlparse
    u = urlparse(url)
    target_ips = [ip for ip in (ips or []) if _valid_ip(ip)]
    if not target_ips and u.hostname:
        target_ips = resolve_bootstrap_ips(u.hostname, direct_dns_ips=direct_dns_ips)
    if target_ips:
        return [
            DoHUpstream(
                url, verify=verify, bootstrap_ips=[ip],
                split_hello=split_hello, bootstrap_dns_ips=direct_dns_ips,
            )
            for ip in target_ips
        ], target_ips
    return [
        DoHUpstream(
            url, verify=verify, bootstrap_ips=[],
            split_hello=split_hello, defer_resolve=True, bootstrap_dns_ips=direct_dns_ips,
        )
    ], []


def _strict_doh_probe(ip: str, host: str, port: int, path: str, verify: bool, use_split: bool) -> str:
    """Строгий однопопыточный DoH-тест конкретного порта и режима TLS без фоллбэков."""
    ctx = make_ssl_context(verify, host)
    t0 = time.monotonic()
    sock = _connect_tls_once(ip, port, ctx, host, connect_timeout=4.0, io_timeout=5.0, use_split=use_split)
    conn = http.client.HTTPSConnection(host, port, timeout=5.0)
    conn.sock = sock
    host_hdr = host if port == 443 else f"{host}:{port}"
    try:
        conn.request("POST", path, body=build_dns_query("example.com"), headers={
            "Host": host_hdr,
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read()
        if resp.status != 200:
            raise IOError(f"HTTP {resp.status}")
        ips = parse_answers(body)
        ms = int((time.monotonic() - t0) * 1000)
        return f"✔ {ms} мс ({', '.join(ips) or 'OK'})"
    finally:
        conn.close()


def probe_transports(ips: list[str], doh_url: str = "", sni: str | None = None,
                     verify: bool = False, direct_dns_ips: list[str] | None = None) -> list[tuple[str, bool, str]]:
    """Параллельная диагностика DoT :853, DoH :443 (цельный / резка 3B) и DoH :8443."""
    from urllib.parse import urlparse
    tasks = []
    q = build_dns_query("example.com")

    def run_dot(ip: str):
        t0 = time.monotonic()
        up = DoTUpstream(ip, 853, verify=verify, hostname=sni, timeout=5.0, connect_timeout=4.0)
        try:
            resp = up.query(q)
            ms = int((time.monotonic() - t0) * 1000)
            return True, f"✔ {ms} мс ({', '.join(parse_answers(resp)) or 'OK'})"
        finally:
            up.close()

    def run_tls_ping(ip: str, port: int, use_split: bool = False):
        t0 = time.monotonic()
        ctx = make_ssl_context(verify and bool(sni), sni)
        s = _connect_tls_once(ip, port, ctx, sni, connect_timeout=4.0, io_timeout=4.0, use_split=use_split)
        try:
            ms = int((time.monotonic() - t0) * 1000)
            return True, f"✔ TLS рукопожатие {ms} мс"
        finally:
            s.close()

    for ip in ips[:2]:
        tasks.append((f"DoT :853 ({ip})", lambda ip=ip: run_dot(ip)))

    if doh_url and doh_url.startswith("https://"):
        u = urlparse(doh_url)
        host = u.hostname or ""
        path = (u.path or "/dns-query") + (f"?{u.query}" if u.query else "")
        doh_ips = [ip for ip in ips if _valid_ip(ip)] or resolve_bootstrap_ips(host, direct_dns_ips)
        probe_ip = doh_ips[0] if doh_ips else host
        if probe_ip and host:
            tasks.append((f"DoH :443 цельный ({probe_ip})",
                          lambda p=probe_ip, h=host, pa=path: (True, _strict_doh_probe(p, h, 443, pa, verify, False))))
            tasks.append((f"DoH :443 резка 3B ({probe_ip})",
                          lambda p=probe_ip, h=host, pa=path: (True, _strict_doh_probe(p, h, 443, pa, verify, True))))
            tasks.append((f"DoH :8443 цельный ({probe_ip})",
                          lambda p=probe_ip, h=host, pa=path: (True, _strict_doh_probe(p, h, 8443, pa, verify, False))))
    else:
        for ip in ips[:1]:
            tasks.append((f"TLS :443 цельный ({ip})", lambda ip=ip: run_tls_ping(ip, 443, False)))
            tasks.append((f"TLS :443 резка 3B ({ip})", lambda ip=ip: run_tls_ping(ip, 443, True)))
            tasks.append((f"TLS :8443 ({ip})", lambda ip=ip: run_tls_ping(ip, 8443, False)))

    if not tasks:
        return []

    results = [None] * len(tasks)
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(tasks))) as pool:
        futs = {pool.submit(fn): idx for idx, (_, fn) in enumerate(tasks)}
        for fut, idx in futs.items():
            label = tasks[idx][0]
            try:
                ok, msg = fut.result()
                results[idx] = (label, ok, msg)
            except Exception as e:  # noqa: BLE001
                results[idx] = (label, False, f"✘ {e}")
    return results


def resolve_auto_upstreams(ip_targets: list[tuple[str, int]], doh_url: str = "",
                           direct_dns_ips: list[str] | None = None,
                           verify_dot: bool = True) -> tuple[list, str, list[tuple[str, bool, str]]]:
    """Автоматически подбирает первый рабочий транспорт (:853 -> DoH :443 -> :443 3B -> :8443)."""
    from urllib.parse import urlparse
    clean_url = _clean_doh_url(doh_url)
    targets = list(ip_targets or [])
    if not targets and not clean_url:
        raise ValueError("Укажите IP-адреса сервера и/или ссылку DoH https://...")

    q = build_dns_query("example.com")
    report_rows: list[tuple[str, bool, str]] = []

    if not clean_url:
        working_msg = None
        last_err = None
        for ip, port in targets:
            up = DoTUpstream(ip, port, verify=False, timeout=5.0, connect_timeout=4.0)
            t0 = time.monotonic()
            try:
                resp = up.query(q)
                ms = int((time.monotonic() - t0) * 1000)
                ans = ", ".join(parse_answers(resp)) or "OK"
                report_rows.append((f"DoT :{port} ({ip})", True, f"✔ {ms} мс ({ans})"))
                if working_msg is None:
                    working_msg = f"Авто → DoT ({format_ip_targets(targets)})"
                    break
            except Exception as e:  # noqa: BLE001
                last_err = e
                report_rows.append((f"DoT :{port} ({ip})", False, f"✘ {e}"))
            finally:
                up.close()
        if working_msg is not None:
            return [DoTUpstream(ip, port, verify=False) for ip, port in targets], working_msg, report_rows
        tls_rows = probe_transports([targets[0][0]], doh_url="", sni=None, verify=False, direct_dns_ips=direct_dns_ips)
        for row in tls_rows:
            if not row[0].startswith("DoT "):
                report_rows.append(row)
        open_hints = [lbl for lbl, ok, _ in report_rows if ok]
        if open_hints:
            raise IOError(
                f"Порт :853 не отвечает ({last_err}), но доступны: {', '.join(open_hints)}. "
                f"Добавьте ссылку DoH (https://.../dns-query) для автоперехода."
            )
        raise IOError(f"Ни один транспорт не отвечает (последняя ошибка: {last_err})")

    if not clean_url.lower().startswith("https://"):
        raise ValueError("DoH-ссылка должна начинаться с https://")
    u = urlparse(clean_url)
    host = u.hostname or ""
    path = (u.path or "/dns-query") + (f"?{u.query}" if u.query else "")
    if not host:
        raise ValueError("Некорректный DoH URL")

    explicit_ips = bool(targets)
    if targets:
        probe_list = targets[:2]
        final_ips = [ip for ip, _ in targets]
    else:
        resolved = resolve_bootstrap_ips(host, direct_dns_ips=direct_dns_ips)
        if not resolved:
            raise IOError(f"Не удалось определить IP для {host}. Проверьте ссылку и интернет.")
        probe_list = [(resolved[0], 853)]
        final_ips = resolved

    def _run_doh(p_ip: str, tgt_url: str, use_split: bool):
        pu = urlparse(tgt_url)
        p_port = pu.port or 443
        detail = _strict_doh_probe(p_ip, host, p_port, path, True, use_split)
        return True, detail

    def _run_dot(p_ip: str, p_port: int):
        t0 = time.monotonic()
        up = DoTUpstream(p_ip, p_port, verify=bool(verify_dot), hostname=host, timeout=5.0, connect_timeout=4.0)
        try:
            resp = up.query(q)
            ms = int((time.monotonic() - t0) * 1000)
            ans = ", ".join(parse_answers(resp)) or "OK"
            return True, f"✔ {ms} мс ({ans})"
        finally:
            up.close()

    for probe_ip, dot_port in probe_list:
        cands = []
        if explicit_ips:
            cands.append((1, f"DoT :{dot_port} ({probe_ip})", "dot", dot_port, False, lambda ip=probe_ip, dp=dot_port: _run_dot(ip, dp)))
        if u.port and u.port != 443:
            cands.append((2, f"DoH :{u.port} ({probe_ip})", clean_url, u.port, False, lambda ip=probe_ip, url_=clean_url: _run_doh(ip, url_, False)))
        else:
            cands.append((2, f"DoH :443 цельный ({probe_ip})", clean_url, 443, False, lambda ip=probe_ip, url_=clean_url: _run_doh(ip, url_, False)))
            cands.append((3, f"DoH :443 резка 3B ({probe_ip})", clean_url, 443, True, lambda ip=probe_ip, url_=clean_url: _run_doh(ip, url_, True)))
            url_8443 = _with_url_port(clean_url, 8443)
            cands.append((4, f"DoH :8443 ({probe_ip})", url_8443, 8443, False, lambda ip=probe_ip, url_=url_8443: _run_doh(ip, url_, False)))

        cand_results = [None] * len(cands)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cands)) as pool:
            futs = {pool.submit(fn): idx for idx, (*_, fn) in enumerate(cands)}
            for fut, idx in futs.items():
                lbl = cands[idx][1]
                try:
                    ok, msg = fut.result()
                    cand_results[idx] = (True, msg)
                    report_rows.append((lbl, True, msg))
                except Exception as e:  # noqa: BLE001
                    cand_results[idx] = (False, str(e))
                    report_rows.append((lbl, False, f"✘ {e}"))

        for idx, (prio, lbl, kind_or_url, port_num, use_split, _) in enumerate(cands):
            ok, _msg = cand_results[idx]
            if not ok:
                continue
            if kind_or_url == "dot":
                ups = [DoTUpstream(ip, p, verify=bool(verify_dot), hostname=host) for ip, p in targets]
                desc = f"Авто → DoT:{dot_port} ({format_ip_targets(targets)})"
                return ups, desc, report_rows
            ups = [
                DoHUpstream(
                    kind_or_url, verify=True, bootstrap_ips=[ip],
                    split_hello=use_split, bootstrap_dns_ips=direct_dns_ips,
                )
                for ip in final_ips
            ]
            split_sfx = " + резка 3B" if use_split else ""
            desc = f"Авто → DoH :{port_num}{split_sfx} ({', '.join(final_ips)})"
            return ups, desc, report_rows

    last_fail = next((msg for _, ok, msg in reversed(report_rows) if not ok), "timed out")
    raise IOError(f"Ни один транспорт не ответил ({last_fail})")


# ---------------------------------------------------------------------------
# Локальный TTL-кэш DNS (Serve-Stale при сбое сети)
# ---------------------------------------------------------------------------

def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Читает DNS-имя с поддержкой сжатия 0xC0 и защитой от циклов. Возвращает (имя, next_offset)."""
    n = len(packet)
    labels = []
    jumped = False
    next_offset = offset
    jumps = 0
    pos = offset
    while pos < n and jumps < 32:
        b = packet[pos]
        if b == 0:
            if not jumped:
                next_offset = pos + 1
            return ".".join(labels), next_offset
        if (b & 0xC0) == 0xC0:
            if pos + 2 > n:
                raise ValueError("обрезанный DNS-указатель")
            ptr = ((b & 0x3F) << 8) | packet[pos + 1]
            if not jumped:
                next_offset = pos + 2
            jumped = True
            pos = ptr
            jumps += 1
            continue
        if (b & 0xC0) != 0:
            raise ValueError("некорректная метка DNS")
        pos += 1
        if pos + b > n:
            raise ValueError("обрезанная метка DNS")
        labels.append(packet[pos:pos + b].decode("ascii", "replace"))
        pos += b
    raise ValueError("цикл или выход за пределы DNS-пакета")


def parse_cnames(packet: bytes) -> list[str]:
    """Извлекает целевые домены CNAME (type 5) из секции ответов DNS-пакета."""
    cnames = []
    try:
        if len(packet) < 12:
            return cnames
        qdcount, ancount = struct.unpack("!HH", packet[4:8])
        i = 12
        for _ in range(qdcount):
            i = _skip_name(packet, i) + 4
        for _ in range(ancount):
            i = _skip_name(packet, i)
            if i + 10 > len(packet):
                break
            rr_type, _cls, _ttl, rdlen = struct.unpack("!HHIH", packet[i:i + 10])
            i += 10
            if i + rdlen > len(packet):
                break
            if rr_type == 5:
                target, _ = _read_name(packet, i)
                t = target.strip().rstrip(".").lower()
                if t and "." in t:
                    cnames.append(t)
            i += rdlen
    except Exception:  # noqa: BLE001
        pass
    return cnames


class DNSCache:
    """Потокобезопасный in-memory TTL-кэш DNS-ответов с поддержкой Serve-Stale."""

    MIN_TTL = 30
    MAX_TTL = 3600
    STALE_GRACE = 300

    def __init__(self, max_entries: int = 2048):
        self._max_entries = max_entries
        self._lock = threading.Lock()
        self._entries = collections.OrderedDict()

    @staticmethod
    def _parse_query_key(packet: bytes, route_tag: str):
        if len(packet) < 12:
            return None
        flags = struct.unpack("!H", packet[2:4])[0]
        if (flags & 0x8000) != 0 or (flags & 0x0100) == 0:  # только запросы (QR=0) с RD=1
            return None
        qdcount = struct.unpack("!H", packet[4:6])[0]
        if qdcount != 1:
            return None
        try:
            q_end = _skip_name(packet, 12) + 4
        except Exception:  # noqa: BLE001
            return None
        if q_end > len(packet):
            return None
        qname, qtype = LocalDNSProxy._parse_question(packet)
        if qname.startswith("<") or qtype is None:
            return None
        qclass = struct.unpack("!H", packet[q_end - 2:q_end])[0]
        return (qname.strip().rstrip(".").lower(), qtype, qclass, route_tag), packet[12:q_end]

    @staticmethod
    def _extract_cache_ttl(resp: bytes) -> int | None:
        if len(resp) < 12:
            return None
        flags = struct.unpack("!H", resp[2:4])[0]
        rcode = flags & 0x000F
        if (flags & 0x8000) == 0 or (flags & 0x0200) != 0:  # игнорируем TC=1 и не-ответы
            return None
        if rcode not in (0, 3):  # только NOERROR / NXDOMAIN
            return None
        qdcount, ancount, nscount, _arcount = struct.unpack("!HHHH", resp[4:12])
        if qdcount != 1:
            return None
        try:
            i = _skip_name(resp, 12) + 4
            if i > len(resp):
                return None
            ttls = []
            for _ in range(ancount):
                i = _skip_name(resp, i)
                if i + 10 > len(resp):
                    break
                rr_type, _cls, ttl, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
                i += 10
                if i + rdlen > len(resp):
                    break
                if rr_type != 41:
                    ttls.append(ttl)
                i += rdlen
            if ttls:
                raw_ttl = min(ttls)
                return max(DNSCache.MIN_TTL, min(raw_ttl, DNSCache.MAX_TTL))
            if ancount == 0:
                return 30 if nscount > 0 or rcode == 3 else 30
        except Exception:  # noqa: BLE001
            pass
        return DNSCache.MIN_TTL

    @staticmethod
    def _build_reply(cached_resp: bytes, cached_q_len: int, req_packet: bytes, req_q: bytes, ttl_val: int) -> bytes:
        if len(cached_resp) < 12 + cached_q_len or len(req_q) != cached_q_len:
            return req_packet[:2] + cached_resp[2:]
        out = bytearray(req_packet[:2] + cached_resp[2:12] + req_q + cached_resp[12 + cached_q_len:])
        try:
            _qd, ancount, nscount, arcount = struct.unpack("!HHHH", out[4:12])
            i = 12 + cached_q_len
            for _ in range(ancount + nscount + arcount):
                i = _skip_name(out, i)
                if i + 10 > len(out):
                    break
                rr_type, _cls, _ttl, rdlen = struct.unpack("!HHIH", out[i:i + 10])
                if rr_type != 41:
                    struct.pack_into("!I", out, i + 4, max(1, int(ttl_val)))
                i += 10 + rdlen
        except Exception:  # noqa: BLE001
            pass
        return bytes(out)

    def get(self, req_packet: bytes, route_tag: str) -> tuple[bytes | None, bytes | None]:
        """Возвращает (fresh_reply, stale_reply)."""
        parsed = self._parse_query_key(req_packet, route_tag)
        if parsed is None:
            return None, None
        key, req_q = parsed
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None, None
            expires_at, stale_until, cached_resp, q_len = entry
            if now < expires_at:
                self._entries.move_to_end(key)
                rem_ttl = max(1, int(expires_at - now))
                return self._build_reply(cached_resp, q_len, req_packet, req_q, rem_ttl), None
            if now < stale_until:
                return None, self._build_reply(cached_resp, q_len, req_packet, req_q, 10)
            self._entries.pop(key, None)
            return None, None

    def put(self, req_packet: bytes, resp: bytes, route_tag: str):
        ttl = self._extract_cache_ttl(resp)
        if ttl is None:
            return
        parsed = self._parse_query_key(req_packet, route_tag)
        if parsed is None:
            return
        key, req_q = parsed
        try:
            resp_q_end = _skip_name(resp, 12) + 4
        except Exception:  # noqa: BLE001
            return
        if resp_q_end - 12 != len(req_q):
            return
        now = time.monotonic()
        with self._lock:
            self._entries[key] = (now + ttl, now + ttl + self.STALE_GRACE, resp, len(req_q))
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def clear(self):
        with self._lock:
            self._entries.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._entries)


# ---------------------------------------------------------------------------
# Локальный DNS-прокси (UDP + TCP на 127.0.0.1:53 и ::1:53)
# ---------------------------------------------------------------------------

class LocalDNSProxy:
    def __init__(self, upstreams, on_log=None, bind_port: int = 53,
                 cooldown_sec: float = 30.0, block_v6_quic: bool = False,
                 bind_ipv6: bool = True,
                 split_domains=None, direct_upstreams=None,
                 enable_cache: bool = True):
        self.upstreams = list(upstreams)    # список DoTUpstream/DoHUpstream
        self.direct_upstreams = list(direct_upstreams or [])
        self.split_domains = parse_split_domains(split_domains)
        self._split_set = set(self.split_domains)
        self._dynamic_split = collections.deque(maxlen=512)
        self._dynamic_lock = threading.Lock()
        self.split_enabled = bool(self._split_set and self.direct_upstreams)
        self.on_log = on_log or (lambda m: None)
        self.bind_port = bind_port
        self._cooldown_sec = cooldown_sec
        self.block_v6_quic = bool(block_v6_quic)
        self._bind_ipv6 = bool(bind_ipv6)
        self.ipv6_bound = False
        self._dns_cache = DNSCache() if enable_cache else None
        self._cooldown_until = [0.0] * len(self.upstreams)
        self._direct_cooldown_until = [0.0] * len(self.direct_upstreams)
        self._cooldown_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._stats = {
            "total": 0, "ok": 0, "direct_ok": 0,
            "cache_hit": 0, "stale_hit": 0, "blocked_v6_quic": 0, "err": 0,
        }
        self._recent = collections.deque(maxlen=40)
        self._stop = threading.Event()
        self._threads = []
        self._pool = None
        self._udp = None
        self._tcp = None
        self._udp6 = None
        self._tcp6 = None

    def start(self):
        self._stop.clear()
        self._threads = []
        self.ipv6_bound = False
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = None
        try:
            if IS_WINDOWS and hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    udp.ioctl(socket.SIO_UDP_CONNRESET, False)
                except OSError:
                    pass
            udp.bind((LOCAL_DNS, self.bind_port))
            udp.settimeout(1.0)

            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((LOCAL_DNS, self.bind_port))
            tcp.listen(32)
            tcp.settimeout(1.0)
        except OSError:
            for s in (udp, tcp):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._udp = None
            self._tcp = None
            raise

        self._udp = udp
        self._tcp = tcp

        if self._bind_ipv6 and socket.has_ipv6:
            udp6 = None
            tcp6 = None
            try:
                udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                if hasattr(socket, "IPV6_V6ONLY"):
                    udp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                if IS_WINDOWS and hasattr(socket, "SIO_UDP_CONNRESET"):
                    try:
                        udp6.ioctl(socket.SIO_UDP_CONNRESET, False)
                    except OSError:
                        pass
                udp6.bind((LOCAL_DNS_V6, self.bind_port))
                udp6.settimeout(1.0)

                tcp6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                if hasattr(socket, "IPV6_V6ONLY"):
                    tcp6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                tcp6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp6.bind((LOCAL_DNS_V6, self.bind_port))
                tcp6.listen(32)
                tcp6.settimeout(1.0)

                self._udp6 = udp6
                self._tcp6 = tcp6
                self.ipv6_bound = True
            except OSError:
                for s in (udp6, tcp6):
                    if s is not None:
                        try:
                            s.close()
                        except OSError:
                            pass
                self._udp6 = None
                self._tcp6 = None
                self.ipv6_bound = False

        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=32, thread_name_prefix="DNSWorker"
        )
        loops = [(self._udp_loop, self._udp), (self._tcp_loop, self._tcp)]
        if self.ipv6_bound:
            loops.extend([(self._udp_loop, self._udp6), (self._tcp_loop, self._tcp6)])
        for target, sock in loops:
            t = threading.Thread(target=target, args=(sock,), daemon=True)
            t.start()
            self._threads.append(t)

    @staticmethod
    def _parse_question(packet: bytes) -> tuple[str, int | None]:
        try:
            if len(packet) < 12:
                return "<unknown>", None
            qdcount = struct.unpack("!H", packet[4:6])[0]
            if qdcount < 1:
                return "<unknown>", None
            pos = 12
            labels = []
            steps = 0
            n = len(packet)
            while pos < n and steps < 128:
                length = packet[pos]
                if length == 0:
                    pos += 1
                    break
                if (length & 0xC0) == 0xC0:
                    if pos + 2 > n:
                        return "<unknown>", None
                    pos += 2
                    break
                if (length & 0xC0) != 0:
                    return "<unknown>", None
                pos += 1
                if pos + length > n:
                    return "<unknown>", None
                labels.append(packet[pos:pos + length].decode("ascii", "replace"))
                pos += length
                steps += 1
            else:
                return "<unknown>", None
            if pos + 4 > n:
                return ".".join(labels) or "<root>", None
            qtype = struct.unpack("!H", packet[pos:pos + 2])[0]
            return ".".join(labels) or "<root>", qtype
        except Exception:  # noqa: BLE001
            return "<unknown>", None

    @staticmethod
    def _parse_first_qtype(packet: bytes) -> int | None:
        _, qtype = LocalDNSProxy._parse_question(packet)
        return qtype

    def _record_query(self, qname: str, qtype: int | None, outcome: str, stat_key: str):
        qtype_str = _QTYPE_NAMES.get(qtype, str(qtype) if qtype is not None else "?")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        with self._stats_lock:
            self._stats["total"] += 1
            self._stats[stat_key] = self._stats.get(stat_key, 0) + 1
            self._recent.append((ts, qtype_str, qname, outcome))

    def get_stats(self) -> dict:
        with self._stats_lock:
            stats = dict(self._stats)
            recent = list(self._recent)
        with self._dynamic_lock:
            dyn_count = len(self._dynamic_split)
        return {
            "bind_port": self.bind_port,
            "ipv6_bound": self.ipv6_bound,
            "block_v6_quic": self.block_v6_quic,
            "split_enabled": self.split_enabled,
            "split_domains_count": len(self.split_domains),
            "dynamic_cnames": dyn_count,
            "cache_entries": self._dns_cache.size() if self._dns_cache else 0,
            "direct_targets": [getattr(d, "ip", str(d)) for d in self.direct_upstreams],
            "stats": stats,
            "recent": recent,
        }

    def _is_smart_domain(self, qname: str) -> bool:
        if match_split_domain(qname, self._split_set):
            return True
        with self._dynamic_lock:
            dyn = set(self._dynamic_split)
        return match_split_domain(qname, dyn)

    def _learn_cnames(self, resp: bytes):
        if not self.split_enabled:
            return
        targets = parse_cnames(resp)
        if not targets:
            return
        with self._dynamic_lock:
            for t in targets:
                if t not in self._split_set and t not in self._dynamic_split:
                    self._dynamic_split.append(t)

    @staticmethod
    def _build_nodata(packet: bytes) -> bytes | None:
        if len(packet) < 12:
            return None
        tid = packet[:2]
        flags = struct.unpack("!H", packet[2:4])[0]
        resp_flags = 0x8000 | (flags & 0x0100)  # QR=1, keep RD, RCODE=0 (NOERROR)
        qdcount = struct.unpack("!H", packet[4:6])[0]
        pos = 12
        try:
            for _ in range(qdcount):
                pos = _skip_name(packet, pos) + 4
        except Exception:  # noqa: BLE001
            return None
        if pos > len(packet):
            return None
        question = packet[12:pos] if qdcount > 0 else b""
        header = tid + struct.pack("!HHHHH", resp_flags, qdcount if question else 0, 0, 0, 0)
        return header + question

    def _query_upstream_pool(self, packet: bytes, upstreams: list, cooldowns: list) -> bytes:
        with self._cooldown_lock:
            now = time.monotonic()
            ready = [i for i, until in enumerate(cooldowns) if until <= now]
            cooling = sorted(
                (i for i, until in enumerate(cooldowns) if until > now),
                key=lambda i: cooldowns[i],
            )
            order = ready + cooling

        last = None
        for idx in order:
            up = upstreams[idx]
            try:
                resp = up.query(packet)
                with self._cooldown_lock:
                    cooldowns[idx] = 0.0
                return resp
            except Exception as e:  # noqa: BLE001
                with self._cooldown_lock:
                    cooldowns[idx] = time.monotonic() + self._cooldown_sec
                last = e
                if not self._stop.is_set():
                    self.on_log(f"   ✘ {e}")
        raise IOError(f"все апстримы недоступны ({last})")

    def _forward(self, packet: bytes) -> bytes:
        qname, qtype = self._parse_question(packet)
        use_direct = self.split_enabled and not self._is_smart_domain(qname)

        if not use_direct and self.block_v6_quic and qtype in BLOCKED_V6_QUIC_QTYPES:
            nodata = self._build_nodata(packet)
            if nodata is not None:
                self._record_query(qname, qtype, "NODATA (blocked IPv6/QUIC)", "blocked_v6_quic")
                return nodata

        route_tag = "direct" if use_direct else ("smart" if self.split_enabled else "full")
        stale_reply = None
        if self._dns_cache is not None:
            fresh_reply, stale_reply = self._dns_cache.get(packet, route_tag)
            if fresh_reply is not None:
                ans = parse_answers(fresh_reply)
                summary = ", ".join(ans[:4]) if ans else f"OK ({len(fresh_reply)} B)"
                self._record_query(qname, qtype, f"[кэш] {summary}", "cache_hit")
                return fresh_reply

        try:
            if use_direct:
                resp = self._query_upstream_pool(packet, self.direct_upstreams, self._direct_cooldown_until)
                if self._dns_cache is not None:
                    self._dns_cache.put(packet, resp, route_tag)
                ans = parse_answers(resp)
                summary = ", ".join(ans[:4]) if ans else f"OK ({len(resp)} B)"
                self._record_query(qname, qtype, f"[прямой] {summary}", "direct_ok")
                return resp

            resp = self._query_upstream_pool(packet, self.upstreams, self._cooldown_until)
            self._learn_cnames(resp)
            if self._dns_cache is not None:
                self._dns_cache.put(packet, resp, route_tag)
            ans = parse_answers(resp)
            summary = ", ".join(ans[:4]) if ans else f"OK ({len(resp)} B)"
            prefix = "[SmartDNS] " if self.split_enabled else ""
            self._record_query(qname, qtype, f"{prefix}{summary}", "ok")
            return resp
        except Exception as e:
            if stale_reply is not None:
                ans = parse_answers(stale_reply)
                summary = ", ".join(ans[:4]) if ans else f"OK ({len(stale_reply)} B)"
                self._record_query(qname, qtype, f"[stale-кэш] {summary}", "stale_hit")
                return stale_reply
            self._record_query(qname, qtype, f"ERR: {e}", "err")
            raise

    @staticmethod
    def _build_servfail(packet: bytes) -> bytes | None:
        if len(packet) < 12:
            return None
        tid = packet[:2]
        flags = struct.unpack("!H", packet[2:4])[0]
        resp_flags = 0x8000 | (flags & 0x0100) | 0x0002  # QR=1, keep RD, RCODE=2 (SERVFAIL)
        qdcount = struct.unpack("!H", packet[4:6])[0]
        pos = 12
        try:
            for _ in range(qdcount):
                pos = _skip_name(packet, pos) + 4
        except Exception:  # noqa: BLE001
            qdcount = 0
            pos = 12
        question = packet[12:pos] if qdcount > 0 and pos <= len(packet) else b""
        header = tid + struct.pack("!HHHHH", resp_flags, qdcount if question else 0, 0, 0, 0)
        return header + question

    def _udp_loop(self, sock):
        while not self._stop.is_set():
            if sock is None:
                break
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set() or sock.fileno() == -1:
                    break
                continue
            pool = self._pool
            if pool is not None:
                try:
                    pool.submit(self._handle_udp, sock, data, addr)
                except RuntimeError:
                    break

    def _handle_udp(self, sock, data, addr):
        if self._stop.is_set():
            return
        try:
            resp = self._forward(data)
        except Exception as e:  # noqa: BLE001
            if not self._stop.is_set():
                self.on_log(f"   ✘ UDP-запрос не обслужен: {e}")
            resp = self._build_servfail(data)
            if not resp:
                return
        if sock is not None and not self._stop.is_set() and sock.fileno() != -1:
            try:
                sock.sendto(resp, addr)
            except OSError:
                pass

    def _tcp_loop(self, sock):
        while not self._stop.is_set():
            if sock is None:
                break
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set() or sock.fileno() == -1:
                    break
                continue
            pool = self._pool
            if pool is not None:
                try:
                    pool.submit(self._handle_tcp, conn)
                except RuntimeError:
                    conn.close()
                    break
            else:
                conn.close()

    def _handle_tcp(self, conn):
        with conn:
            data = None
            try:
                conn.settimeout(8)
                hdr = conn.recv(2)
                if not hdr:
                    return
                while len(hdr) < 2:
                    chunk = conn.recv(2 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                ln = struct.unpack("!H", hdr)[0]
                data = DoTUpstream._recv_exact(conn, ln)
                resp = self._forward(data)
                conn.sendall(struct.pack("!H", len(resp)) + resp)
            except Exception as e:  # noqa: BLE001
                if not self._stop.is_set():
                    self.on_log(f"   ✘ TCP-запрос не обслужен: {e}")
                if data and not self._stop.is_set():
                    sf = self._build_servfail(data)
                    if sf:
                        try:
                            conn.sendall(struct.pack("!H", len(sf)) + sf)
                        except OSError:
                            pass

    def stop(self):
        self._stop.set()
        for s in (self._udp, self._tcp, self._udp6, self._tcp6):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        self._udp = None
        self._tcp = None
        self._udp6 = None
        self._tcp6 = None
        self.ipv6_bound = False
        pool = self._pool
        self._pool = None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        for up in self.upstreams:
            up.close()
        for up in self.direct_upstreams:
            up.close()
        if self._dns_cache is not None:
            self._dns_cache.clear()
        with self._dynamic_lock:
            self._dynamic_split.clear()

    def clear_cache(self):
        if self._dns_cache is not None:
            self._dns_cache.clear()


# ---------------------------------------------------------------------------
# Тестовый DNS-запрос (собираем пакет вручную, без внешних библиотек)
# ---------------------------------------------------------------------------

def build_dns_query(name: str, qtype: int = 1) -> bytes:
    tid = os.urandom(2)
    flags = b"\x01\x00"  # RD=1
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    clean = name.strip().rstrip(".")
    parts = [part for part in clean.split(".") if part]
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in parts) + b"\x00"
    return tid + flags + counts + qname + struct.pack("!HH", qtype, 1)


def _skip_name(packet: bytes, i: int) -> int:
    """Пропустить DNS-имя: метки до нулевого байта либо сжатый указатель (0xC0)."""
    n = len(packet)
    steps = 0
    while i < n and steps < 128:
        b = packet[i]
        if b == 0:
            return i + 1
        if (b & 0xC0) == 0xC0:
            if i + 2 > n:
                raise ValueError("обрезанный DNS-указатель")
            return i + 2
        if (b & 0xC0) != 0:
            raise ValueError("некорректная метка DNS")
        i += 1 + b
        steps += 1
    raise ValueError("некорректное DNS-имя")


def parse_answers(packet: bytes):
    answers = []
    try:
        if len(packet) < 12:
            return answers
        qdcount, ancount = struct.unpack("!HH", packet[4:8])
        i = 12
        for _ in range(qdcount):
            i = _skip_name(packet, i) + 4  # имя вопроса + qtype + qclass
        for _ in range(ancount):
            i = _skip_name(packet, i)
            if i + 10 > len(packet):
                break
            _type, _cls, _ttl, rdlen = struct.unpack("!HHIH", packet[i:i + 10])
            i += 10
            if i + rdlen > len(packet):
                break
            rdata = packet[i:i + rdlen]
            if _type == 1 and rdlen == 4:
                answers.append(".".join(str(b) for b in rdata))
            i += rdlen
    except Exception:  # noqa: BLE001
        pass
    return answers


CONFIG_LINK_PREFIX = "securedns://v1/"


def export_config_link(cfg: dict) -> str:
    """Кодирует настройки SecureDNS в компактную строку securedns://v1/... для обмена в чате."""
    proto = str(cfg.get("proto") or "auto").strip()
    if proto not in ("auto", "dot", "doh", "doh_url"):
        proto = "auto"
    raw_doms = list(parse_split_domains(cfg.get("split_domains", [])))
    doms_val = "default" if raw_doms == list(DEFAULT_SPLIT_DOMAINS) else raw_doms
    payload = {
        "v": 1,
        "proto": proto,
        "ips": str(cfg.get("ips") or "").strip(),
        "doh": _clean_doh_url(str(cfg.get("doh_url") or "")),
        "sni": _clean_sni_host(str(cfg.get("sni") or "")) or "",
        "verify": bool(cfg.get("verify", False)),
        "v6q": bool(cfg.get("block_v6_quic", True)),
        "split3": bool(cfg.get("split_hello", False)),
        "fwquic": bool(cfg.get("block_fw_quic", False)),
        "sdns": bool(cfg.get("split_dns", False)),
        "doms": doms_val,
        "dir": str(cfg.get("direct_dns") or "").strip(),
    }
    raw_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    token = base64.urlsafe_b64encode(raw_bytes).decode("ascii").rstrip("=")
    return CONFIG_LINK_PREFIX + token


def import_config_link(raw: str) -> dict:
    """Декодирует и проверяет строку securedns://v1/... или JSON-конфиг."""
    s = str(raw or "").strip()
    if not s:
        raise ValueError("пустая строка настроек")
    if s.startswith("{"):
        data = json.loads(s)
    elif s.lower().startswith("securedns://"):
        token = s[len("securedns://"):].strip()
        if token.lower().startswith("v1/"):
            token = token[3:]
        token = token.strip("/")
        pad = (-len(token)) % 4
        if pad:
            token += "=" * pad
        raw_bytes = base64.urlsafe_b64decode(token.encode("ascii"))
        data = json.loads(raw_bytes.decode("utf-8"))
    else:
        raise ValueError("ожидается строка вида securedns://v1/...")

    if not isinstance(data, dict):
        raise ValueError("некорректный формат конфига")
    proto = str(data.get("proto") or "dot").strip()
    if proto not in ("auto", "dot", "doh", "doh_url"):
        raise ValueError(f"неизвестный протокол: {proto}")

    ips_raw = str(data.get("ips") or "").strip()
    targets = parse_ip_targets(ips_raw) if ips_raw else []
    ips_fmt = format_ip_targets(targets)

    doh_url = _clean_doh_url(str(data.get("doh") or data.get("doh_url") or ""))
    if proto in ("doh", "doh_url") and not doh_url.startswith("https://"):
        raise ValueError("для DoH нужна ссылка https://...")

    dir_raw = str(data.get("dir") or data.get("direct_dns") or "").strip()
    dir_list = [ip for ip, _ in parse_ip_targets(dir_raw)] if dir_raw else []

    doms_raw = data.get("doms") if "doms" in data else data.get("split_domains", "default")
    if doms_raw == "default" or doms_raw is None:
        split_domains = list(DEFAULT_SPLIT_DOMAINS)
    else:
        split_domains = list(parse_split_domains(doms_raw))

    return {
        "proto": proto,
        "ips": ips_fmt,
        "doh_url": doh_url,
        "sni": _clean_sni_host(str(data.get("sni") or "")) or "",
        "verify": bool(data.get("verify", proto == "doh_url")),
        "block_v6_quic": bool(data.get("v6q", data.get("block_v6_quic", True))),
        "split_hello": bool(data.get("split3", data.get("split_hello", False))),
        "block_fw_quic": bool(data.get("fwquic", data.get("block_fw_quic", False))),
        "split_dns": bool(data.get("sdns", data.get("split_dns", False))),
        "split_domains": split_domains,
        "direct_dns": ", ".join(dir_list),
    }


BEGINNER_GUIDE_SECTIONS = (
    (
        "Шаг 1. Подготовка и выбор адаптера",
        (
            "1. Запустите от администратора (вверху справа должно гореть «права ✓»; на Linux — ./securedns.sh).",
            "2. В списке «Сетевой адаптер» выберите сеть, через которую сейчас есть интернет (Wi-Fi или Ethernet).",
        ),
    ),
    (
        "Шаг 2. Как ввести настройки (выберите свой вариант)",
        (
            "• Вариант А — вам скинули строку securedns://v1/... (или скопировали URL / IP):\n"
            "  Скопируйте в буфер и нажмите «Вставить конфиг» в правом верхнем углу — поля заполнятся сами.\n"
            "  В любом поле работают Ctrl+C / Ctrl+V / Ctrl+A даже на русской раскладке и меню правой кнопкой.",
            "• Вариант Б — самый простой режим «Авто» (включён по умолчанию):\n"
            "  Просто вставьте то, что вам дали: только IP (и даже IP:порт), только ссылку https://..., либо оба поля.\n"
            "  При нажатии «Включить» программа сама проверит :853, :443, :443 резку 3B и :8443 и выберет рабочий.",
            "• Вариант В — ручной выбор строгого режима:\n"
            "  - «DoT :853» — только IP (или IP:порт). Поле SNI появится, если включить «Проверять TLS-сертификат».\n"
            "  - «DoH по URL (как в Chrome)» — только ссылка https://.../dns-query без ввода IP.\n"
            "  - «DoH по своим IP» — ссылка https://... + явные IP (при потерях на :443 можно дописать :8443).",
        ),
    ),
    (
        "Шаг 3. Какие галочки нужны",
        (
            "• «Блокировать IPv6 и QUIC (AAAA/SVCB)» — держите включённой, чтобы браузер не шёл в обход.",
            "• «Раздельный DNS» — включайте, если нужны только нейросети (список «Домены…»), а обычные сайты,\n"
            "  банки и игры должны идти напрямую от вашего провайдера.",
            "• «Сворачивать в трей при закрытии» и «Автозапуск с Windows» — по желанию для фоновой работы.",
            "• Кнопка «Откл. DoH Chrome/Edge» вверху — нажмите, если статус «Браузеры (DoH)» показывает, что\n"
            "  в Chrome / Edge / Яндексе включён свой встроенный защищённый DNS.",
        ),
    ),
    (
        "Шаг 4. Проверка, счётчики и что делать при сбое",
        (
            "1. Нажмите «Включить шифрованный DNS», затем «Проверить» — покажет IP ответа и время в мс.\n"
            "   Под статусом в реальном времени считаются запросы, попадания в кэш, блокировки v6/QUIC и ошибки.",
            "2. Кнопка «Сбросить кэш» над журналом очищает локальный и системный DNS-кэш в один клик.",
            "3. Если в ручном «DoT :853» порт закрыт — программа сама проверит :443 / резку 3B / :8443 и предложит\n"
            "   переключиться в один клик. Либо просто используйте режим «Авто» или кнопку «Тест портов».",
            "4. Пока защита включена, программу закрывать не надо (пусть висит в трее). Для возврата — «Отключить».",
        ),
    ),
)


def format_beginner_guide() -> str:
    """Форматирует пошаговую инструкцию для встроенной справки GUI, CLI и буфера обмена."""
    return "\n\n".join(title + "\n" + "\n".join(items) for title, items in BEGINNER_GUIDE_SECTIONS)


def default_log_export_dir() -> str:
    """Папка по умолчанию для сохранения диагностического .txt отчёта."""
    desktop = os.path.join(os.path.expanduser("~"), "Desktop")
    return desktop if os.path.isdir(desktop) else os.path.expanduser("~")


def _read_text_safe(path: str) -> str:
    try:
        if not os.path.exists(path):
            return "(файл отсутствует)"
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            txt = f.read().strip()
        return txt if txt else "(файл пуст)"
    except OSError as e:
        return f"(не удалось прочитать: {e})"


def collect_diagnostics(app_state: dict | None = None, ui_log_text: str = "") -> str:
    """Собирает полный текстовый отчёт для разбора проблем без скриншотов."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"================ {APP_NAME} {APP_VERSION} DIAGNOSTIC REPORT ================",
        f"Generated: {now}",
        f"OS: {platform.platform()} ({platform.machine()})",
        f"Python: {sys.version.split()[0]} | Executable: {sys.executable}",
        f"Frozen: {is_frozen()} | Admin: {is_admin()}",
        f"BackupDir: {BACKUP_DIR}",
        f"ConfigFile: {CONFIG_FILE}",
        f"BackupFile: {BACKUP_FILE}",
        f"LogFile: {LOG_FILE}",
        "",
        "--- APP STATE ---",
    ]
    if app_state:
        sni_raw = app_state.get("sni", "")
        sni_clean = _clean_sni_host(sni_raw) if sni_raw else None
        proxy_stats = app_state.get("proxy_stats")
        proxy_running = bool(app_state.get("proxy_running") or proxy_stats is not None)
        lines.extend([
            f"SelectedAdapter: {app_state.get('adapter') or 'не выбран'}",
            f"IPs: {app_state.get('ips', '')!r}",
            f"Proto: {app_state.get('proto', '')!r}",
            f"SNI (raw): {sni_raw!r} -> clean: {sni_clean!r}",
            f"DoH URL: {app_state.get('doh_url', '')!r}",
            f"Verify TLS: {app_state.get('verify')}",
            f"Block IPv6/QUIC: {app_state.get('block_v6_quic')}",
            f"Split TLS ClientHello: {app_state.get('split_hello')}",
            f"Block QUIC Firewall: {app_state.get('block_fw_quic')} (rule_active={has_quic_firewall_rule()})",
            f"Split DNS: {app_state.get('split_dns')} ({app_state.get('split_domains_count', 0)} domains)",
            f"Direct DNS Override: {app_state.get('direct_dns', '')!r}",
            f"Autostart: {app_state.get('autostart')} | MinimizeToTray: {app_state.get('minimize_to_tray')}",
            f"Proxy Running: {proxy_running}",
        ])
    else:
        lines.append("(нет активного снимка UI)")

    if IS_WINDOWS:
        try:
            bdoh = check_browser_doh_status()
            lines.extend([
                "",
                "--- BROWSER BUILT-IN DoH ---",
                f"Summary: {bdoh.get('summary')}",
                f"Policies: {bdoh.get('policies')} | LocalStateModes: {bdoh.get('local_modes')}",
            ])
        except Exception as e:  # noqa: BLE001
            lines.extend(["", "--- BROWSER BUILT-IN DoH ---", f"Error: {e}"])

    lines.extend([
        "",
        f"--- SAVED CONFIG ({CONFIG_FILE}) ---",
        _read_text_safe(CONFIG_FILE),
        "",
        f"--- SAVED BACKUP ({BACKUP_FILE}) ---",
        _read_text_safe(BACKUP_FILE),
        "",
        "--- PROXY TELEMETRY ---",
    ])
    proxy_stats = (app_state or {}).get("proxy_stats")
    if proxy_stats:
        st = proxy_stats.get("stats") or {}
        split_line = ""
        if proxy_stats.get("split_enabled"):
            split_line = (
                f" | SplitDNS: {proxy_stats.get('split_domains_count', 0)} domains "
                f"(+{proxy_stats.get('dynamic_cnames', 0)} CNAMEs) "
                f"-> Direct: {proxy_stats.get('direct_targets')}"
            )
        lines.extend([
            f"BindPort: {proxy_stats.get('bind_port')} | IPv6Bound: {proxy_stats.get('ipv6_bound')} "
            f"| BlockV6QUIC: {proxy_stats.get('block_v6_quic')} | CacheEntries: {proxy_stats.get('cache_entries', 0)}{split_line}",
            f"Counters: total={st.get('total', 0)}, ok={st.get('ok', 0)}, "
            f"direct_ok={st.get('direct_ok', 0)}, cache_hit={st.get('cache_hit', 0)}, "
            f"stale_hit={st.get('stale_hit', 0)}, blocked_v6_quic={st.get('blocked_v6_quic', 0)}, "
            f"err={st.get('err', 0)}",
            "RecentQueries (up to 40):",
        ])
        recent = proxy_stats.get("recent") or []
        if recent:
            for ts, qt, qn, out in recent:
                lines.append(f"  {ts}  {qt:<6} {qn} -> {out}")
        else:
            lines.append("  (запросов пока не было)")
    else:
        lines.append("(прокси сейчас остановлен)")

    lines.extend(["", "--- NETWORK ADAPTERS & DNS ---"])
    try:
        adapters = get_adapters()
    except Exception as e:  # noqa: BLE001
        adapters = []
        lines.append(f"get_adapters error: {e}")
    if not adapters:
        lines.append("(активных адаптеров не найдено)")
    for a in adapters:
        try:
            k = adapter_key(a)
            v4 = get_dns_servers(k)
            v6 = get_dns_servers_v6(k)
            lines.append(
                f"[{a.get('index')}] {a.get('name')} ({a.get('desc')}) | "
                f"IPv4={v4 or ['DHCP']} | IPv6={v6 or ['DHCP/default']}"
            )
        except Exception as e:  # noqa: BLE001
            lines.append(f"[{a.get('index')}] {a.get('name')}: error reading DNS: {e}")

    if IS_WINDOWS:
        ps_checks = [
            (
                "WINDOWS Get-DnsClientServerAddress",
                "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } "
                "| Format-Table InterfaceIndex, InterfaceAlias, AddressFamily, ServerAddresses -AutoSize "
                "| Out-String -Width 200",
            ),
            (
                "WINDOWS Port 53 UDP Listeners",
                "Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue "
                "| Select-Object LocalAddress, LocalPort, OwningProcess, "
                "@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} "
                "| Format-Table -AutoSize | Out-String -Width 160",
            ),
            (
                "WINDOWS Get-DnsClientDohServerAddress",
                "Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue "
                "| Format-Table -AutoSize | Out-String -Width 160",
            ),
        ]
        for title, cmd in ps_checks:
            lines.extend(["", f"--- {title} ---"])
            try:
                rc, out, err = run_ps(cmd, timeout=8)
                body = out.strip() or err.strip() or f"(пусто, rc={rc})"
                lines.append(body)
            except Exception as e:  # noqa: BLE001
                lines.append(f"(ошибка выполнения: {e})")
    else:
        lines.extend(["", "--- LINUX resolvectl status (first 80 lines) ---"])
        try:
            rc, out, err = run_cmd(["resolvectl", "status"], timeout=8)
            if rc == 0 and out.strip():
                lines.extend(out.splitlines()[:80])
            else:
                lines.append(err.strip() or f"(resolvectl rc={rc})")
        except Exception as e:  # noqa: BLE001
            lines.append(f"(ошибка resolvectl: {e})")
        lines.extend(["", "--- LINUX /etc/resolv.conf ---", _read_text_safe("/etc/resolv.conf")])

    if ui_log_text and ui_log_text.strip():
        lines.extend(["", "--- CURRENT GUI LOG ---", ui_log_text.strip()])

    lines.extend(["", f"--- PERSISTENT LOG TAIL ({LOG_FILE}, last 300 lines) ---", read_log_tail(300)])
    lines.append("")
    return "\n".join(lines)


def save_diagnostics_report(path: str, app_state: dict | None = None, ui_log_text: str = "") -> str:
    """Формирует и сохраняет диагностический .txt отчёт в указанный файл."""
    report = collect_diagnostics(app_state=app_state, ui_log_text=ui_log_text)
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(report)
    return path


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

BG, PANEL, FG, MUTED = "#1b1e24", "#242832", "#e6e8ec", "#9aa3b2"
ACCENT, GREEN, RED = "#3d8bfd", "#2ecc71", "#e74c3c"


def _clipboard_win_get() -> str | None:
    if not IS_WINDOWS:
        return None
    import ctypes
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
    user32.IsClipboardFormatAvailable.restype = ctypes.c_int
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int

    for _ in range(3):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.01)
    else:
        return None
    try:
        if not user32.IsClipboardFormatAvailable(13):
            return ""
        handle = user32.GetClipboardData(13)
        if not handle:
            return ""
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return ""
        try:
            return ctypes.wstring_at(ptr) or ""
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _clipboard_win_set(text: str) -> bool:
    if not IS_WINDOWS:
        return False
    import ctypes
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    user32.EmptyClipboard.argtypes = []
    user32.EmptyClipboard.restype = ctypes.c_int
    user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
    user32.SetClipboardData.restype = ctypes.c_void_p
    kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int
    kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
    kernel32.GlobalFree.restype = ctypes.c_void_p

    raw = (str(text) + "\x00").encode("utf-16-le")
    hmem = kernel32.GlobalAlloc(0x0002, len(raw))
    if not hmem:
        return False
    ptr = kernel32.GlobalLock(hmem)
    if not ptr:
        kernel32.GlobalFree(hmem)
        return False
    try:
        ctypes.memmove(ptr, raw, len(raw))
    finally:
        kernel32.GlobalUnlock(hmem)

    for _ in range(3):
        if user32.OpenClipboard(None):
            break
        time.sleep(0.01)
    else:
        kernel32.GlobalFree(hmem)
        return False
    try:
        user32.EmptyClipboard()
        if not user32.SetClipboardData(13, hmem):
            kernel32.GlobalFree(hmem)
            return False
        hmem = None
        return True
    finally:
        user32.CloseClipboard()


def _clipboard_get(widget) -> str:
    if IS_WINDOWS:
        win_txt = _clipboard_win_get()
        if win_txt is not None:
            return win_txt
    try:
        return str(widget.clipboard_get() or "")
    except tk.TclError:
        return ""


def _clipboard_set(widget, text: str):
    if IS_WINDOWS and _clipboard_win_set(text):
        return
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update()


def _widget_editable(w) -> bool:
    try:
        if hasattr(w, "instate"):
            return not (w.instate(["disabled"]) or w.instate(["readonly"]))
        return str(w.cget("state")) not in ("disabled", "readonly")
    except tk.TclError:
        return False


def _widget_get_selection(w) -> str | None:
    try:
        if isinstance(w, tk.Text):
            ranges = w.tag_ranges("sel")
            return w.get(ranges[0], ranges[1]) if ranges else None
        return w.selection_get() if w.selection_present() else None
    except tk.TclError:
        return None


def _widget_select_all(w):
    if isinstance(w, tk.Text):
        w.tag_add("sel", "1.0", "end-1c")
        w.mark_set("insert", "end-1c")
    else:
        w.selection_range(0, "end")
        w.icursor("end")


def _widget_copy(w):
    sel = _widget_get_selection(w)
    if sel is not None:
        _clipboard_set(w, sel)


def _widget_cut(w):
    if not _widget_editable(w):
        return
    sel = _widget_get_selection(w)
    if sel is None:
        return
    _clipboard_set(w, sel)
    try:
        w.delete("sel.first", "sel.last")
    except tk.TclError:
        pass


def _widget_paste(w):
    if not _widget_editable(w):
        return
    txt = _clipboard_get(w)
    if not txt:
        return
    if isinstance(w, tk.Text):
        if w.tag_ranges("sel"):
            try:
                w.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
        w.insert("insert", txt)
    else:
        if _widget_get_selection(w) is not None:
            try:
                w.delete("sel.first", "sel.last")
            except tk.TclError:
                pass
        lines = [ln.strip() for ln in txt.replace("\r\n", "\n").replace("\r", "\n").splitlines() if ln.strip()]
        if len(lines) > 1:
            sep = ", " if all(re.match(r"^[0-9.:a-zA-Z/-]+$", x) and "://" not in x for x in lines) else " "
            clean = sep.join(lines)
        elif lines:
            clean = lines[0]
        else:
            clean = ""
        w.insert("insert", clean)


_VK_TO_CLIP_ACT = {65: "a", 67: "c", 86: "v", 88: "x"}
_KEYSYM_TO_CLIP_ACT = {
    "a": "a", "cyrillic_ef": "a",
    "c": "c", "cyrillic_es": "c",
    "v": "v", "cyrillic_em": "v",
    "x": "x", "cyrillic_che": "x",
}


def _install_clipboard_support(root: tk.Tk):
    """Включает Ctrl+C/V/X/A на русской/любой раскладке и контекстное меню ПКМ для всех полей."""
    menu = tk.Menu(
        root, tearoff=0, bg=PANEL, fg=FG,
        activebackground=ACCENT, activeforeground="white", relief="flat",
    )

    def run_act(w, act: str):
        if act == "a":
            _widget_select_all(w)
        elif act == "c":
            _widget_copy(w)
        elif act == "x":
            _widget_cut(w)
        elif act == "v":
            _widget_paste(w)
        return "break"

    def on_ctrl_key(event):
        if (event.state & 0x20000) or (event.state & 0x8):
            return
        act = (_VK_TO_CLIP_ACT.get(event.keycode) if IS_WINDOWS else None) or _KEYSYM_TO_CLIP_ACT.get(
            str(event.keysym or "").lower()
        )
        if not act:
            return
        return run_act(event.widget, act)

    root._clip_handler = on_ctrl_key

    def show_ctx_menu(event):
        w = event.widget
        try:
            w.focus_set()
        except tk.TclError:
            pass
        editable = _widget_editable(w)
        has_sel = _widget_get_selection(w) is not None
        menu.delete(0, "end")
        if editable:
            menu.add_command(label="Вырезать", state="normal" if has_sel else "disabled", command=lambda w=w: _widget_cut(w))
            menu.add_command(label="Копировать", state="normal" if has_sel else "disabled", command=lambda w=w: _widget_copy(w))
            menu.add_command(label="Вставить", command=lambda w=w: _widget_paste(w))
            menu.add_separator()
            menu.add_command(label="Выделить всё", command=lambda w=w: _widget_select_all(w))
        else:
            menu.add_command(label="Копировать", state="normal" if has_sel else "disabled", command=lambda w=w: _widget_copy(w))
            menu.add_command(label="Выделить всё", command=lambda w=w: _widget_select_all(w))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    for cls in ("TEntry", "Entry", "Text"):
        root.bind_class(cls, "<<SelectAll>>", lambda e: run_act(e.widget, "a"))
        root.bind_class(cls, "<<Copy>>", lambda e: run_act(e.widget, "c"))
        root.bind_class(cls, "<<Cut>>", lambda e: run_act(e.widget, "x"))
        root.bind_class(cls, "<<Paste>>", lambda e: run_act(e.widget, "v"))
        for ch in ("a", "c", "v", "x"):
            root.bind_class(cls, f"<Control-{ch}>", lambda e, act=ch: run_act(e.widget, act))
            root.bind_class(cls, f"<Control-{ch.upper()}>", lambda e, act=ch: run_act(e.widget, act))
        root.bind_class(cls, "<Control-KeyPress>", on_ctrl_key, add="+")
        root.bind_class(cls, "<Control-Insert>", lambda e: run_act(e.widget, "c"))
        root.bind_class(cls, "<Shift-Insert>", lambda e: run_act(e.widget, "v"))
        root.bind_class(cls, "<Button-3>", show_ctx_menu, add="+")
        if cls == "Text":
            root.bind_class(cls, "<Button-1>", lambda e: e.widget.focus_set(), add="+")


class App(tk.Tk):
    def __init__(self, autostart: bool = False, enable_tray: bool = True):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} — шифрованный DNS (DoT/DoH)")
        self.geometry("740x765")
        self.minsize(690, 715)
        self.configure(bg=BG)
        self._ico_path = resource_path("icon.ico") if IS_WINDOWS else None
        if IS_WINDOWS and self._ico_path and os.path.exists(self._ico_path):
            try:
                self.iconbitmap(self._ico_path)
            except Exception:  # noqa: BLE001
                pass
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.adapters = []
        self.proxy = None
        self.active_adapter = None
        self._busy = False
        self._autostart = bool(autostart)
        self._autostart_done = False
        self._update_info = None
        self._browser_doh_info = {}
        self._tray = None
        self._help_win = None
        self._last_stats_tick = 0.0
        self.btn_update = None
        self.btn_help = None
        self.btn_save_log = None
        self.btn_flush_cache = None
        self.btn_clear_log = None
        self.btn_split_edit = None
        self.btn_probe = None
        self.btn_copy_cfg = None
        self.btn_paste_cfg = None
        self.btn_browser_doh = None
        self.chk_autostart = None
        self.chk_verify = None
        self.chk_split_hello = None
        self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
        self.direct_dns_raw = ""
        self.q = queue.Queue()
        log_session_header("GUI-autostart" if autostart else "GUI")
        self._build_ui()
        _install_clipboard_support(self)
        self._load_config()
        if enable_tray and IS_WINDOWS:
            self._tray = Win32Tray(
                tooltip=f"{APP_NAME} {APP_VERSION}",
                icon_path=self._ico_path,
                on_show=lambda: self.q.put(("tray_show", None)),
                on_status=lambda: self.q.put(("refresh_req", None)),
                on_quit=lambda: self.q.put(("tray_quit", None)),
            )
            self._tray.start()
        self._poll_queue()
        self.after(50, self._startup_init)
        self.after(2000, self._check_update_bg)

    def destroy(self):
        tray = getattr(self, "_tray", None)
        self._tray = None
        if tray is not None:
            try:
                tray.stop()
            except Exception:  # noqa: BLE001
                pass
        super().destroy()

    # ---------- UI ----------
    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Segoe UI", 9))
        style.configure("Panel.TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 10))
        style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED,
                        font=("Segoe UI", 9))
        style.configure("Title.TLabel", background=BG, foreground=FG,
                        font=("Segoe UI Semibold", 15))
        style.configure(
            "TCombobox",
            fieldbackground=PANEL,
            background=PANEL,
            foreground=FG,
            selectbackground=PANEL,
            selectforeground=FG,
            arrowcolor=FG,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", PANEL), ("disabled", BG), ("active", PANEL)],
            foreground=[("readonly", FG), ("disabled", MUTED)],
            background=[("readonly", PANEL), ("active", "#333947")],
            selectbackground=[("readonly", PANEL)],
            selectforeground=[("readonly", FG)],
        )
        style.configure("TRadiobutton", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.map("TRadiobutton", background=[("active", BG)])
        style.configure("TCheckbutton", background=BG, foreground=FG, font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("Accent.TButton", background=ACCENT, foreground="white",
                        font=("Segoe UI Semibold", 10), padding=(12, 6), borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#2f6fd6")])
        style.configure("TButton", background=PANEL, foreground=FG,
                        font=("Segoe UI", 10), padding=(10, 5), borderwidth=0)
        style.map("TButton", background=[("active", "#333947")])
        style.configure("Small.TButton", background=PANEL, foreground=FG,
                        font=("Segoe UI", 9), padding=(8, 3), borderwidth=0)
        style.map("Small.TButton", background=[("active", "#333947")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                        insertcolor=FG, selectbackground=ACCENT,
                        selectforeground="white", borderwidth=1)
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "white")

        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(12, 4))
        self.header = header
        ttk.Label(header, text=f"🛡  SecureDNS {APP_VERSION}", style="Title.TLabel").pack(side="left")
        self.lbl_admin = ttk.Label(header,
                                   text="права ✓" if is_admin() else "нет прав",
                                   style="Muted.TLabel",
                                   foreground=GREEN if is_admin() else RED)
        self.lbl_admin.pack(side="right")
        self.btn_paste_cfg = ttk.Button(
            header, text="Вставить конфиг", style="Small.TButton", command=self.on_paste_config
        )
        self.btn_paste_cfg.pack(side="right", padx=(0, 8))
        self.btn_copy_cfg = ttk.Button(
            header, text="Копировать конфиг", style="Small.TButton", command=self.on_copy_config
        )
        self.btn_copy_cfg.pack(side="right", padx=(0, 6))
        self.btn_help = ttk.Button(
            header, text="? Инструкция", style="Small.TButton", command=self.on_show_help
        )
        self.btn_help.pack(side="right", padx=(0, 6))

        if not is_admin():
            tk.Label(self, text="Нет прав администратора: закройте программу и "
                                + admin_hint() + ", иначе сменить DNS не выйдет.",
                     bg="#4a2c2c", fg="#ffb4b4", font=("Segoe UI", 9), anchor="w",
                     padx=10, pady=5, wraplength=680, justify="left"
                     ).pack(fill="x", padx=16, pady=(0, 6))

        # Статус
        st = ttk.Frame(self, style="Panel.TFrame", padding=10)
        st.pack(fill="x", padx=16, pady=4)
        ttk.Label(st, text="Текущее состояние", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 11)).pack(anchor="w")
        self.lbl_adapter = ttk.Label(st, text="Адаптер: —", style="PanelMuted.TLabel")
        self.lbl_adapter.pack(anchor="w", pady=(4, 0))
        self.lbl_dns = ttk.Label(st, text="DNS адаптера: —", style="PanelMuted.TLabel")
        self.lbl_dns.pack(anchor="w")
        self.lbl_proxy = ttk.Label(st, text="Прокси: остановлен", style="PanelMuted.TLabel")
        self.lbl_proxy.pack(anchor="w")
        self.lbl_stats = ttk.Label(st, text="Счётчики: ожидание запуска", style="PanelMuted.TLabel")
        self.lbl_stats.pack(anchor="w")

        brow_row = ttk.Frame(st, style="Panel.TFrame")
        brow_row.pack(fill="x", pady=(2, 0))
        self.lbl_browser_doh = ttk.Label(
            brow_row, text="Браузеры (DoH): проверка…", style="PanelMuted.TLabel"
        )
        self.lbl_browser_doh.pack(side="left")
        if IS_WINDOWS:
            self.btn_browser_doh = ttk.Button(
                brow_row, text="Откл. DoH Chrome/Edge", style="Small.TButton",
                command=self.on_toggle_browser_doh,
            )
            self.btn_browser_doh.pack(side="right")

        # Адаптер
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16, pady=(8, 0))
        ttk.Label(row, text="Сетевой адаптер:").pack(anchor="w")
        self.cmb_adapter = ttk.Combobox(row, state="readonly")
        self.cmb_adapter.pack(fill="x", pady=(3, 0))
        self.cmb_adapter.bind("<<ComboboxSelected>>", lambda e: self.refresh_status())

        # Протокол и параметры подключения (компактная сетка 2x2)
        proto_frm = ttk.Frame(self)
        proto_frm.pack(fill="x", padx=16, pady=(6, 0))
        ttk.Label(proto_frm, text="Способ подключения:").pack(anchor="w")
        proto_grid = ttk.Frame(proto_frm)
        proto_grid.pack(fill="x", pady=(2, 0))
        proto_grid.columnconfigure(0, weight=1)
        proto_grid.columnconfigure(1, weight=1)
        self.var_proto = tk.StringVar(value="auto")
        ttk.Radiobutton(
            proto_grid,
            text="Авто (сам найдёт :853 / :443 / :8443)",
            variable=self.var_proto, value="auto", command=self._on_proto_user_click,
        ).grid(row=0, column=0, sticky="w", pady=1)
        ttk.Radiobutton(
            proto_grid,
            text="DoT :853 (по IP)",
            variable=self.var_proto, value="dot", command=self._on_proto_user_click,
        ).grid(row=0, column=1, sticky="w", pady=1)
        ttk.Radiobutton(
            proto_grid,
            text="DoH по URL (как в Chrome)",
            variable=self.var_proto, value="doh_url", command=self._on_proto_user_click,
        ).grid(row=1, column=0, sticky="w", pady=1)
        ttk.Radiobutton(
            proto_grid,
            text="DoH по своим IP (:443 / :8443)",
            variable=self.var_proto, value="doh", command=self._on_proto_user_click,
        ).grid(row=1, column=1, sticky="w", pady=1)

        self.frm_conn = ttk.Frame(self)
        self.frm_conn.pack(fill="x", padx=16, pady=(6, 0))

        self.frm_ips = ttk.Frame(self.frm_conn)
        self.lbl_ips = ttk.Label(self.frm_ips, text="IP-адреса серверов (если есть):")
        self.lbl_ips.pack(anchor="w")
        self.ent_ips = ttk.Entry(self.frm_ips)
        self.ent_ips.pack(fill="x", pady=(2, 0))
        self.lbl_ips_hint = ttk.Label(
            self.frm_ips,
            text="Порядок важен. Поддерживается ip:порт.",
            style="Muted.TLabel",
        )
        self.lbl_ips_hint.pack(anchor="w")

        self.frm_doh = ttk.Frame(self.frm_conn)
        self.lbl_doh = ttk.Label(self.frm_doh, text="URL DoH-сервера (https://...):")
        self.lbl_doh.pack(anchor="w")
        self.ent_doh = ttk.Entry(self.frm_doh)
        self.ent_doh.pack(fill="x", pady=(2, 0))
        self.lbl_doh_hint = ttk.Label(
            self.frm_doh,
            text="Например: https://dns.example.com/dns-query",
            style="Muted.TLabel",
        )
        self.lbl_doh_hint.pack(anchor="w")

        self.frm_sni = ttk.Frame(self.frm_conn)
        ttk.Label(
            self.frm_sni,
            text="Домен сертификата SNI (для строгой проверки по IP):",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.ent_sni = ttk.Entry(self.frm_sni)
        self.ent_sni.pack(fill="x", pady=(2, 0))

        # Опции конкретного режима (показываются динамически)
        self.mode_opts_frm = ttk.Frame(self)
        self.mode_opts_frm.pack(fill="x", padx=16, pady=(4, 0))
        self.var_verify = tk.BooleanVar(value=False)
        self.chk_verify = ttk.Checkbutton(
            self.mode_opts_frm, text="Проверять TLS-сертификат",
            variable=self.var_verify, command=self._on_proto,
        )
        self.var_split_hello = tk.BooleanVar(value=False)
        self.chk_split_hello = ttk.Checkbutton(
            self.mode_opts_frm, text="Резать ClientHello по 3 байта (:443)",
            variable=self.var_split_hello,
        )

        # Общие опции (2 колонки)
        opts_frm = ttk.Frame(self)
        opts_frm.pack(fill="x", padx=16, pady=(4, 0))
        opts_frm.columnconfigure(0, weight=1)
        opts_frm.columnconfigure(1, weight=1)

        self.var_block_v6_quic = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opts_frm, text="Блокировать IPv6 и QUIC (AAAA/SVCB)", variable=self.var_block_v6_quic
        ).grid(row=0, column=0, sticky="w", pady=1)

        self.var_fw_quic = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            opts_frm, text="Блок UDP:443 QUIC в Firewall", variable=self.var_fw_quic
        ).grid(row=0, column=1, sticky="w", pady=1)

        self.var_tray = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opts_frm, text="Сворачивать в трей при закрытии", variable=self.var_tray
        ).grid(row=1, column=0, sticky="w", pady=1)

        self.var_autostart = tk.BooleanVar(value=False)
        self.chk_autostart = ttk.Checkbutton(
            opts_frm, text="Автозапуск с Windows",
            variable=self.var_autostart, command=self.on_toggle_autostart,
        )
        self.chk_autostart.grid(row=1, column=1, sticky="w", pady=1)
        if not IS_WINDOWS:
            self.chk_autostart.configure(state="disabled")

        split_row = ttk.Frame(opts_frm)
        split_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(3, 0))
        self.var_split_dns = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            split_row,
            text="Раздельный DNS (только ИИ-домены через сервер, остальное — провайдер)",
            variable=self.var_split_dns,
        ).pack(side="left")
        self.btn_split_edit = ttk.Button(
            split_row,
            text=f"Домены… ({len(self.split_domains)})",
            style="Small.TButton",
            command=self.on_edit_split_domains,
        )
        self.btn_split_edit.pack(side="right")

        # Кнопки
        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=16, pady=10)
        self.btn_on = ttk.Button(btns, text="Включить шифрованный DNS",
                                 style="Accent.TButton", command=self.on_enable)
        self.btn_on.pack(side="left")
        self.btn_off = ttk.Button(btns, text="Отключить", command=self.on_disable)
        self.btn_off.pack(side="left", padx=(8, 0))
        self.btn_test = ttk.Button(btns, text="Проверить", command=self.on_test)
        self.btn_test.pack(side="left", padx=(8, 0))
        self.btn_probe = ttk.Button(btns, text="Тест портов", command=self.on_probe_ports)
        self.btn_probe.pack(side="left", padx=(8, 0))
        self.btn_refresh = ttk.Button(btns, text="Статус", command=self.refresh_status)
        self.btn_refresh.pack(side="right")

        # Лог
        log_bar = ttk.Frame(self)
        log_bar.pack(fill="x", padx=16, pady=(0, 3))
        ttk.Label(log_bar, text="Журнал событий:", style="Muted.TLabel").pack(side="left")
        self.btn_save_log = ttk.Button(
            log_bar, text="Сохранить лог (.txt)", style="Small.TButton", command=self.on_save_log
        )
        self.btn_save_log.pack(side="right")
        self.btn_flush_cache = ttk.Button(
            log_bar, text="Сбросить кэш", style="Small.TButton", command=self.on_flush_cache
        )
        self.btn_flush_cache.pack(side="right", padx=(0, 6))
        self.btn_clear_log = ttk.Button(
            log_bar, text="Очистить", style="Small.TButton", command=self.on_clear_log
        )
        self.btn_clear_log.pack(side="right", padx=(0, 6))

        self.txt_log = tk.Text(self, bg="#12141a", fg="#b8c0cc", insertbackground=FG,
                               font=("Consolas", 9), wrap="word", relief="flat",
                               height=7, state="disabled")
        self.txt_log.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        self.log(f"{APP_NAME} {APP_VERSION}. Выбран «Авто» — впишите IP и/или URL и нажмите «Включить» "
                 f"(памятка: «? Инструкция» вверху).")

    # ---------- утилиты UI ----------
    def log(self, msg: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg.rstrip() + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")
        write_log_file(msg)

    def _thread_log(self, msg):
        self.q.put(("log", msg))

    def _set_busy(self, busy: bool):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in (
            self.btn_on, self.btn_off, self.btn_test, self.btn_probe,
            self.btn_refresh, self.btn_save_log, self.btn_flush_cache, self.btn_split_edit,
            self.btn_copy_cfg, self.btn_paste_cfg, self.btn_browser_doh, self.btn_update,
        ):
            if btn is not None:
                try:
                    btn.configure(state=state)
                except tk.TclError:
                    pass

    def _run_async(self, fn):
        if self._busy:
            return
        self._set_busy(True)
        def wrapper():
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                write_log_file(traceback.format_exc(), level="ERROR")
                self.q.put(("log", f"Неожиданная ошибка: {e}"))
            finally:
                self.q.put(("done", None))
        threading.Thread(target=wrapper, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log(payload)
                elif kind == "status":
                    self._apply_status(*payload)
                elif kind == "adapters_status":
                    self._apply_adapters_and_status(*payload)
                elif kind == "env_status":
                    self._apply_env_status(payload)
                elif kind == "refresh_req":
                    self.refresh_status()
                elif kind == "proxy":
                    self._apply_proxy_state(payload)
                elif kind == "update":
                    self._show_update_button(payload)
                elif kind == "log_saved":
                    self._on_log_saved(payload)
                elif kind == "offer_switch_doh":
                    self._on_offer_switch_doh(payload)
                elif kind == "tray_show":
                    self.deiconify()
                    self.lift()
                    try:
                        self.focus_force()
                    except tk.TclError:
                        pass
                elif kind == "tray_quit":
                    self._force_quit_from_tray()
                elif kind == "autostart_enable":
                    self._maybe_autostart_enable()
                elif kind == "autostart_retry":
                    self._maybe_autostart_enable(retry=payload)
                elif kind == "quit":
                    if self.proxy:
                        self.proxy.stop()
                        self.proxy = None
                    release_single_instance()
                    self.destroy()
                    return
                elif kind == "done":
                    self._set_busy(False)
        except queue.Empty:
            pass
        if self.proxy is not None:
            now = time.monotonic()
            if now - self._last_stats_tick >= 1.2:
                self._last_stats_tick = now
                self._update_live_stats()
        self.after(80, self._poll_queue)

    def _on_proto_user_click(self):
        if self.var_proto.get() == "doh_url":
            self.var_verify.set(True)
        self._on_proto()

    def _on_proto(self):
        proto = self.var_proto.get()
        for child in (self.frm_ips, self.frm_doh, self.frm_sni):
            child.pack_forget()
        for cb in (self.chk_verify, self.chk_split_hello):
            cb.pack_forget()

        if proto == "auto":
            self.frm_ips.pack(fill="x")
            self.frm_doh.pack(fill="x", pady=(5, 0))
            self.lbl_ips.config(text="IP-адреса серверов (если есть — для :853 или DoH по IP):")
            self.lbl_ips_hint.config(
                text="Через запятую, можно ip:порт. Оставьте пустым, если есть только ссылка DoH ниже."
            )
            self.lbl_doh.config(text="Ссылка DoH https://... (если есть — для :443 / :8443):")
            self.lbl_doh_hint.config(
                text="Оставьте пустым, если есть только IP для DoT :853. Программа сама выберет рабочий порт."
            )
            self.mode_opts_frm.pack_forget()
            return

        if not self.mode_opts_frm.winfo_manager():
            self.mode_opts_frm.pack(fill="x", padx=16, pady=(4, 0), after=self.frm_conn)

        if proto == "doh_url":
            self.frm_doh.pack(fill="x")
            self.lbl_doh.config(text="URL DoH-сервера (https://...):")
            self.lbl_doh_hint.config(
                text="Чистый DoH (как в Chrome): IP резолвятся напрямую в обход 127.0.0.1. Можно :8443."
            )
            self.chk_verify.pack(side="left")
            self.chk_split_hello.pack(side="left", padx=(16, 0))
        elif proto == "doh":
            self.frm_ips.pack(fill="x")
            self.frm_doh.pack(fill="x", pady=(5, 0))
            self.lbl_ips.config(text="IP DoH-сервера (прямой коннект без DNS-резолва):")
            self.lbl_ips_hint.config(
                text="Каждый IP балансируется отдельно (Keep-Alive). Пусто — резолвим IP из URL сами."
            )
            self.lbl_doh.config(text="URL DoH-сервера (https://...):")
            self.lbl_doh_hint.config(
                text="При потерях :443 у провайдера допишите порт: https://домен:8443/dns-query"
            )
            self.chk_verify.pack(side="left")
            self.chk_split_hello.pack(side="left", padx=(16, 0))
        else:
            self.frm_ips.pack(fill="x")
            self.lbl_ips.config(text="DNS-серверы DoT (IP или IP:порт через запятую):")
            self.lbl_ips_hint.config(
                text="Порт по умолчанию :853. При недоступности первого запросы уходят на следующий."
            )
            self.chk_verify.pack(side="left")
            if self.var_verify.get():
                self.frm_sni.pack(fill="x", pady=(5, 0))

    def _apply_env_status(self, payload: dict):
        self.var_autostart.set(bool(payload.get("autostart", False)))
        bdoh = payload.get("browser_doh") or {}
        self._browser_doh_info = bdoh
        summary = bdoh.get("summary") or "неизвестно"
        color = MUTED if not bdoh.get("needs_attention") else "#f1c40f"
        if bdoh.get("policy_off") and not bdoh.get("needs_attention"):
            color = GREEN
        self.lbl_browser_doh.config(text=f"Браузеры (DoH): {summary}", foreground=color)
        if self.btn_browser_doh is not None:
            self.btn_browser_doh.configure(
                text="Вернуть DoH браузерам" if bdoh.get("policy_off") else "Откл. DoH Chrome/Edge"
            )

    def _maybe_autostart_enable(self, retry: int = 0):
        if self._autostart_done:
            return
        if not os.path.exists(CONFIG_FILE) or not is_admin() or self._busy:
            self._autostart_done = True
            return
        if not self.adapters and retry < 3:
            self.after(2500, lambda: self._retry_autostart_adapters(retry + 1))
            return
        self._autostart_done = True
        if not self._selected_adapter():
            self.log("⚠ Автозапуск: активный сетевой адаптер не найден, включите защиту вручную.")
            return
        if self.var_tray.get() and self._tray is not None and self._tray.available:
            self.withdraw()
        self.on_enable()

    def _retry_autostart_adapters(self, retry: int):
        def work():
            adapters = get_adapters()
            sel = adapters[0] if adapters else None
            dns = get_dns_servers(adapter_key(sel)) if sel else []
            dns_v6 = get_dns_servers_v6(adapter_key(sel)) if sel else []
            self.q.put(("adapters_status", (adapters, sel, dns, dns_v6)))
            self.q.put(("autostart_retry", retry))
        threading.Thread(target=work, daemon=True).start()

    def _force_quit_from_tray(self):
        if self.proxy and self.active_adapter:
            if not self._busy and is_admin():
                self.on_disable(quit_after=True)
                return
            if self.proxy:
                self.proxy.stop()
                self.proxy = None
        if IS_WINDOWS and has_quic_firewall_rule() and is_admin():
            set_quic_firewall_block(False)
        release_single_instance()
        self.destroy()

    def on_toggle_autostart(self):
        desired = bool(self.var_autostart.get())
        if not IS_WINDOWS:
            self.var_autostart.set(False)
            return
        if not is_admin():
            self.var_autostart.set(not desired)
            messagebox.showerror(APP_NAME, "Для настройки автозапуска нужны права администратора.")
            return
        ok, msg = set_autostart(desired)
        if not ok:
            self.var_autostart.set(not desired)
            messagebox.showerror(APP_NAME, f"Не удалось изменить автозапуск:\n{msg}")
            self.log(f"✘ Автозапуск: {msg}")
        else:
            self.log(f"✔ {msg}")

    def on_toggle_browser_doh(self):
        if not IS_WINDOWS or self._busy:
            return
        if not is_admin():
            messagebox.showerror(APP_NAME, "Для смены политики реестра Chrome/Edge нужны права администратора.")
            return
        cur_off = bool(self._browser_doh_info.get("policy_off"))
        target_off = not cur_off
        if target_off:
            if not messagebox.askyesno(
                APP_NAME,
                "Отключить встроенный DoH в Chrome / Edge / Yandex Browser через групповую политику?\n\n"
                "Это гарантирует, что браузер пойдёт через SecureDNS (и раздельный DNS).\n"
                "Отменить можно в любой момент кнопкой «Вернуть DoH браузерам».",
            ):
                return
        ok, msg = set_browser_doh_policy(target_off)
        if ok:
            self.log(f"✔ {msg}")
        else:
            self.log(f"✘ Политика браузеров: {msg}")
            messagebox.showerror(APP_NAME, msg)
        self._apply_env_status({
            "autostart": self.var_autostart.get(),
            "browser_doh": check_browser_doh_status(),
        })

    def _current_cfg_dict(self) -> dict:
        return {
            "ips": self.ent_ips.get().strip(),
            "proto": self.var_proto.get(),
            "verify": bool(self.var_verify.get()),
            "block_v6_quic": bool(self.var_block_v6_quic.get()),
            "split_hello": bool(self.var_split_hello.get()),
            "block_fw_quic": bool(self.var_fw_quic.get()),
            "minimize_to_tray": bool(self.var_tray.get()),
            "split_dns": bool(self.var_split_dns.get()),
            "split_domains": "\n".join(self.split_domains),
            "direct_dns": self.direct_dns_raw,
            "sni": self.ent_sni.get().strip(),
            "doh_url": _clean_doh_url(self.ent_doh.get()),
        }

    def _apply_imported_config(self, cfg: dict):
        self.ent_ips.delete(0, "end")
        if cfg.get("ips"):
            self.ent_ips.insert(0, cfg["ips"])
        self.var_proto.set(cfg.get("proto", "auto"))
        self.var_verify.set(bool(cfg.get("verify", False)))
        self.var_block_v6_quic.set(bool(cfg.get("block_v6_quic", True)))
        self.var_split_hello.set(bool(cfg.get("split_hello", False)))
        self.var_fw_quic.set(bool(cfg.get("block_fw_quic", False)))
        self.var_split_dns.set(bool(cfg.get("split_dns", False)))
        self.split_domains = list(cfg.get("split_domains") or DEFAULT_SPLIT_DOMAINS)
        self.direct_dns_raw = str(cfg.get("direct_dns") or "")
        self.ent_sni.delete(0, "end")
        if cfg.get("sni"):
            self.ent_sni.insert(0, cfg["sni"])
        self.ent_doh.delete(0, "end")
        clean_doh = _clean_doh_url(str(cfg.get("doh_url") or ""))
        if clean_doh:
            self.ent_doh.insert(0, clean_doh)
        self._update_split_btn_text()
        self._on_proto()
        self._save_config()

    def on_copy_config(self):
        cfg = self._current_cfg_dict()
        cfg["split_domains"] = list(self.split_domains)
        link = export_config_link(cfg)
        _clipboard_set(self, link)
        self.log(f"✔ Конфиг скопирован в буфер ({len(link)} симв.): можно скидывать в чат.")

    def on_paste_config(self):
        if self._busy:
            return
        clip = _clipboard_get(self).strip()

        if clip.lower().startswith("securedns://") or (clip.startswith("{") and "proto" in clip):
            try:
                cfg = import_config_link(clip)
                self._apply_imported_config(cfg)
                self.log(f"✔ Настройки загружены из буфера (режим {cfg['proto']}, "
                         f"раздельный DNS: {'вкл' if cfg['split_dns'] else 'выкл'}).")
                if self.proxy is not None:
                    self.log("ℹ Для применения новых настроек нажмите «Включить» для перезапуска.")
                return
            except Exception as e:  # noqa: BLE001
                messagebox.showerror(APP_NAME, f"Ошибка разбора конфига из буфера:\n{e}")
                return

        if clip.lower().startswith("https://") and len(clip.split()) == 1:
            self.ent_doh.delete(0, "end")
            self.ent_doh.insert(0, clip)
            cur_ips = self.ent_ips.get().strip()
            if self.var_proto.get() == "dot":
                self.var_proto.set("doh" if cur_ips else "doh_url")
            self.var_verify.set(True)
            self._on_proto()
            self._save_config()
            self.log(f"✔ DoH-ссылка подставлена из буфера: {clip}")
            return

        if clip and not any(c.isalpha() for c in clip.replace("tls://", "").replace("dot://", "")):
            try:
                parsed_ips = parse_ip_targets(clip)
                if parsed_ips:
                    fmt = format_ip_targets(parsed_ips)
                    self.ent_ips.delete(0, "end")
                    self.ent_ips.insert(0, fmt)
                    if self.var_proto.get() == "doh_url":
                        self.var_proto.set("auto")
                    self._on_proto()
                    self._save_config()
                    self.log(f"✔ IP-адреса подставлены из буфера: {fmt}")
                    return
            except ValueError:
                pass

        win = tk.Toplevel(self)
        win.title("Вставить настройки (securedns://...)")
        win.geometry("500x210")
        win.minsize(420, 180)
        win.configure(bg=BG)
        win.transient(self)
        win.grab_set()
        if IS_WINDOWS and self._ico_path and os.path.exists(self._ico_path):
            try:
                win.iconbitmap(self._ico_path)
            except Exception:  # noqa: BLE001
                pass
        ttk.Label(win, text="Вставьте строку настроек вида securedns://v1/...:").pack(
            anchor="w", padx=14, pady=(12, 4)
        )
        txt = tk.Text(win, bg="#12141a", fg=FG, insertbackground=FG, font=("Consolas", 9),
                      wrap="word", relief="flat", height=5)
        txt.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        if clip:
            txt.insert("1.0", clip)

        def apply_paste():
            raw = txt.get("1.0", "end").strip()
            try:
                cfg = import_config_link(raw)
                self._apply_imported_config(cfg)
                self.log(f"✔ Настройки применены (режим {cfg['proto']}).")
                if self.proxy is not None:
                    self.log("ℹ Для применения нажмите «Отключить» → «Включить».")
                win.destroy()
            except Exception as e:  # noqa: BLE001
                messagebox.showerror(APP_NAME, f"Не удалось применить конфиг:\n{e}", parent=win)

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(bar, text="Применить", style="Accent.TButton", command=apply_paste).pack(side="left")
        ttk.Button(bar, text="Отмена", command=win.destroy).pack(side="right")

    def on_show_help(self):
        if self._help_win is not None:
            try:
                if self._help_win.winfo_exists():
                    self._help_win.deiconify()
                    self._help_win.lift()
                    self._help_win.focus_force()
                    return
            except tk.TclError:
                pass
            self._help_win = None

        win = tk.Toplevel(self)
        self._help_win = win
        win.title(f"{APP_NAME} {APP_VERSION} — инструкция для новичков")
        win.geometry("670x580")
        win.minsize(540, 420)
        win.configure(bg=BG)
        win.transient(self)
        if IS_WINDOWS and self._ico_path and os.path.exists(self._ico_path):
            try:
                win.iconbitmap(self._ico_path)
            except Exception:  # noqa: BLE001
                pass

        ttk.Label(
            win,
            text="Как настроить SecureDNS за 1 минуту",
            font=("Segoe UI Semibold", 11),
        ).pack(anchor="w", padx=14, pady=(12, 4))

        body = ttk.Frame(win)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        scroll = ttk.Scrollbar(body, orient="vertical")
        scroll.pack(side="right", fill="y")
        txt = tk.Text(
            body, bg="#12141a", fg=FG, font=("Segoe UI", 9),
            wrap="word", relief="flat", padx=10, pady=8, yscrollcommand=scroll.set,
        )
        txt.pack(side="left", fill="both", expand=True)
        scroll.configure(command=txt.yview)
        txt.tag_configure("heading", font=("Segoe UI Semibold", 10), foreground=ACCENT)

        for idx, (title, items) in enumerate(BEGINNER_GUIDE_SECTIONS):
            if idx:
                txt.insert("end", "\n\n")
            txt.insert("end", title + "\n", "heading")
            txt.insert("end", "\n".join(items))
        txt.configure(state="disabled")

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=14, pady=(0, 12))

        def copy_guide():
            _clipboard_set(self, format_beginner_guide())
            self.log("✔ Инструкция скопирована в буфер обмена.")

        ttk.Button(bar, text="Скопировать инструкцию", command=copy_guide).pack(side="left")
        ttk.Button(bar, text="Закрыть", style="Accent.TButton", command=win.destroy).pack(side="right")
        win.bind("<Escape>", lambda _e: win.destroy())

    # ---------- автообновление ----------
    def _check_update_bg(self):
        def work():
            info = check_for_update_info()
            if info:
                self.q.put(("update", info))
        threading.Thread(target=work, daemon=True).start()

    def _show_update_button(self, info):
        if getattr(self, "_update_shown", False):
            return
        self._update_shown = True
        if isinstance(info, str):
            info = {"version": info, "url": None, "size": None}
        self._update_info = info
        version = info["version"]
        self.btn_update = ttk.Button(
            self.header,
            text=f"⬆ Обновить до {version}",
            command=lambda: self.on_update(version),
        )
        if self._busy:
            self.btn_update.configure(state="disabled")
        self.btn_update.pack(side="right", padx=(0, 10))
        self.log(f"⬆ Доступна новая версия {version} (у вас {APP_VERSION}) — "
                 f"кнопка обновления в шапке.")

    def on_update(self, version: str):
        info = self._update_info or {"version": str(version), "url": None, "size": None}
        ver = info["version"]
        if not messagebox.askyesno(
                APP_NAME,
                f"Доступна версия {ver} (у вас {APP_VERSION}).\n\n"
                f"Скачать и обновить сейчас?\n"
                f"Если защита включена, после перезапуска её надо будет включить заново."):
            return

        def work():
            self.q.put(("log", f"▶ Обновление до {ver}…"))
            def before_restart():
                if self.proxy:
                    self.proxy.stop()
                    self.proxy = None
                    self.q.put(("proxy", None))
                if self.active_adapter:
                    key = adapter_key(self.active_adapter)
                    if get_dns_servers(key) == [LOCAL_DNS] or get_dns_servers_v6(key) == [LOCAL_DNS_V6]:
                        restore_adapter_dns(key)
                        flush_dns_cache()
                    self.active_adapter = None
                release_single_instance()

            res = do_update(
                self._thread_log,
                download_url=info.get("url"),
                expected_size=info.get("size"),
                on_before_restart=before_restart,
            )
            if res == "restart":
                self.q.put(("quit", None))
            elif res == "manual":
                self.q.put(("log", "Закройте программу и запустите её снова."))
        self._run_async(work)

    def _selected_adapter(self):
        i = self.cmb_adapter.current()
        return self.adapters[i] if 0 <= i < len(self.adapters) else None

    def _parse_ips(self):
        try:
            return [ip for ip, _ in parse_ip_targets(self.ent_ips.get())]
        except ValueError:
            return None

    def _parse_targets(self):
        try:
            return parse_ip_targets(self.ent_ips.get())
        except ValueError:
            return None

    def _maybe_offer_doh_redirect(self, raw_text: str, from_field: str) -> bool:
        url = _extract_https_url(raw_text)
        if not url:
            return False
        if not messagebox.askyesno(
            APP_NAME,
            f"Похоже, вы вставили DoH-ссылку в поле {from_field}:\n{url}\n\n"
            f"Перенести её в поле URL DoH и переключить режим на подходящий?",
        ):
            return False
        if from_field == "IP":
            leftover = [tok for tok in re.split(r"[\s,;]+", self.ent_ips.get().strip()) if tok and tok != url]
            self.ent_ips.delete(0, "end")
            if leftover:
                self.ent_ips.insert(0, ", ".join(leftover))
        else:
            self.ent_sni.delete(0, "end")
        self.ent_doh.delete(0, "end")
        self.ent_doh.insert(0, url)
        has_ips = bool(self.ent_ips.get().strip())
        if self.var_proto.get() == "dot":
            self.var_proto.set("doh" if has_ips else "doh_url")
            self.var_verify.set(True)
        self._on_proto()
        self._save_config()
        return True

    def _build_upstreams(self):
        proto = self.var_proto.get()
        verify = bool(self.var_verify.get())
        split_hello = bool(self.var_split_hello.get())
        split_tag = " + TLS-резка 3B" if split_hello else ""

        if proto == "auto":
            if self._maybe_offer_doh_redirect(self.ent_ips.get(), "IP"):
                proto = self.var_proto.get()
            else:
                targets = self._parse_targets()
                if targets is None:
                    messagebox.showerror(
                        APP_NAME,
                        "Некорректный формат IP-адресов.\n"
                        "Пример: 77.90.47.223 или 77.90.47.223:853 через запятую.",
                    )
                    return None
                clean_url = _clean_doh_url(self.ent_doh.get())
                raw_url = self.ent_doh.get().strip()
                if raw_url and not clean_url:
                    clean_url = ""
                if clean_url and not clean_url.lower().startswith("https://"):
                    messagebox.showerror(APP_NAME, "DoH-ссылка должна начинаться с https://")
                    return None
                if not targets and not clean_url:
                    messagebox.showerror(
                        APP_NAME,
                        "Для режима «Авто» впишите IP-адрес сервера и/или ссылку DoH https://...",
                    )
                    return None
                parts = []
                if targets:
                    parts.append(format_ip_targets(targets))
                if clean_url:
                    parts.append(clean_url)
                desc = f"Авто ({' + '.join(parts)})"
                if clean_url:
                    b_ips = [targets[0][0]] if targets else []
                    ups = [DoHUpstream(clean_url, verify=True, bootstrap_ips=b_ips, defer_resolve=not bool(b_ips))]
                else:
                    ups = [DoTUpstream(ip, port, verify=False) for ip, port in targets]
                return ups, desc

        if proto == "dot":
            if self._maybe_offer_doh_redirect(self.ent_ips.get(), "IP"):
                return self._build_upstreams()
            if verify and self._maybe_offer_doh_redirect(self.ent_sni.get(), "SNI"):
                return self._build_upstreams()
            targets = self._parse_targets()
            if targets is None:
                messagebox.showerror(
                    APP_NAME,
                    "Впишите корректные IPv4-адреса (или IP:порт) через запятую,\n"
                    "например: 9.9.9.9, 149.112.112.112:853",
                )
                return None
            if not targets:
                messagebox.showerror(APP_NAME, "Для DoT впишите хотя бы один IP сервера.")
                return None
            sni = _clean_sni_host(self.ent_sni.get())
            if verify and not sni:
                if messagebox.askyesno(
                        APP_NAME,
                        "Включена проверка TLS-сертификата, но домен SNI не задан.\n"
                        "Сертификат обычно выпущен на домен, поэтому по голому IP проверка не пройдёт.\n\n"
                        "Отключить проверку сертификата и продолжить?"):
                    verify = False
                    self.var_verify.set(False)
                    self._on_proto()
                elif not messagebox.askyesno(APP_NAME, "Всё равно запустить со строгой проверкой без домена?"):
                    return None
            return [DoTUpstream(ip, port, verify=verify, hostname=sni) for ip, port in targets], \
                   f"DoT → {format_ip_targets(targets)}" + (f" (SNI {sni})" if sni else "")

        url = _clean_doh_url(self.ent_doh.get())
        if not url.lower().startswith("https://"):
            messagebox.showerror(APP_NAME, "Впишите реальную ссылку DoH-сервера, начинающуюся с https://")
            return None
        if proto == "doh_url":
            desc = f"DoH (URL) → {url}" + split_tag
            return [DoHUpstream(url, verify=verify, bootstrap_ips=[], split_hello=split_hello, defer_resolve=True)], desc

        targets = self._parse_targets()
        if targets is None:
            messagebox.showerror(APP_NAME, "Впишите корректные IPv4-адреса (не 127.0.0.1 и не 0.0.0.0),\n"
                                           "или выберите режим «DoH по URL (как в Chrome)».")
            return None
        ips = [ip for ip, _ in targets]
        desc = f"DoH → {url}" + (f" (через {', '.join(ips)})" if ips else " (резолв из URL)") + split_tag
        if ips:
            return [DoHUpstream(url, verify=verify, bootstrap_ips=[ip], split_hello=split_hello) for ip in ips], desc
        return [DoHUpstream(url, verify=verify, bootstrap_ips=[], split_hello=split_hello, defer_resolve=True)], desc

    # ---------- конфиг ----------
    def _update_split_btn_text(self):
        if self.btn_split_edit is not None:
            self.btn_split_edit.configure(text=f"Домены… ({len(self.split_domains)})")

    def on_edit_split_domains(self):
        if self._busy:
            return
        win = tk.Toplevel(self)
        win.title("Раздельный DNS — список доменов")
        win.geometry("560x500")
        win.minsize(480, 420)
        win.configure(bg=BG)
        win.transient(self)
        win.grab_set()
        if IS_WINDOWS:
            try:
                ico = resource_path("icon.ico")
                if os.path.exists(ico):
                    win.iconbitmap(ico)
            except Exception:  # noqa: BLE001
                pass

        ttk.Label(
            win,
            text="Домены, которые пойдут через шифрованный DNS / SmartDNS:",
            font=("Segoe UI Semibold", 10),
        ).pack(anchor="w", padx=14, pady=(12, 2))
        ttk.Label(
            win,
            text="По одному в строке (или через запятую). Поддомены включаются сами "
                 "(например, openai.com заберёт api.openai.com).",
            style="Muted.TLabel",
            wraplength=520,
            justify="left",
        ).pack(anchor="w", padx=14, pady=(0, 6))

        txt = tk.Text(
            win, bg="#12141a", fg=FG, insertbackground=FG,
            font=("Consolas", 10), wrap="word", relief="flat", height=14,
        )
        txt.pack(fill="both", expand=True, padx=14, pady=(0, 10))
        txt.insert("1.0", "\n".join(self.split_domains))

        ttk.Label(
            win,
            text="Прямой DNS провайдера (для всех остальных сайтов, необязательно):",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=14)
        ent_dir = ttk.Entry(win)
        ent_dir.pack(fill="x", padx=14, pady=(2, 2))
        ent_dir.insert(0, self.direct_dns_raw)
        ttk.Label(
            win,
            text="Если оставить пустым — возьмём автоматически с адаптера перед включением.",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=14, pady=(0, 10))

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=14, pady=(0, 12))

        def on_save():
            raw_dir = ent_dir.get().strip()
            if raw_dir:
                bad = [ip.strip() for ip in raw_dir.split(",") if ip.strip() and not _valid_ip(ip.strip())]
                if bad:
                    messagebox.showerror(
                        APP_NAME,
                        f"Некорректный прямой DNS: {', '.join(bad)}\nУкажите IPv4 (не 127.0.0.1) или оставьте пустым.",
                        parent=win,
                    )
                    return
            parsed = list(parse_split_domains(txt.get("1.0", "end")))
            self.split_domains = parsed
            self.direct_dns_raw = raw_dir
            self._update_split_btn_text()
            self._save_config()
            if self.proxy is not None:
                self.log("ℹ Список раздельного DNS обновлён — нажмите «Отключить» и «Включить», чтобы применить.")
            win.destroy()

        def on_reset():
            txt.delete("1.0", "end")
            txt.insert("1.0", "\n".join(DEFAULT_SPLIT_DOMAINS))

        ttk.Button(bar, text="Сохранить", style="Accent.TButton", command=on_save).pack(side="left")
        ttk.Button(bar, text="Сбросить пресет ИИ", command=on_reset).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="Отмена", command=win.destroy).pack(side="right")

    def _load_config(self):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            self.ent_ips.delete(0, "end")
            ips = cfg.get("ips", "")
            if ips:
                self.ent_ips.insert(0, ips)
            self.var_proto.set(cfg.get("proto", "auto"))
            self.var_verify.set(bool(cfg.get("verify", False)))
            self.var_block_v6_quic.set(bool(cfg.get("block_v6_quic", True)))
            self.var_split_hello.set(bool(cfg.get("split_hello", False)))
            self.var_fw_quic.set(bool(cfg.get("block_fw_quic", False)))
            self.var_tray.set(bool(cfg.get("minimize_to_tray", True)))
            self.var_split_dns.set(bool(cfg.get("split_dns", False)))
            if "split_domains" in cfg:
                self.split_domains = list(parse_split_domains(cfg.get("split_domains", "")))
            else:
                self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
            self.direct_dns_raw = str(cfg.get("direct_dns", "")).strip()
            if cfg.get("sni"):
                self.ent_sni.delete(0, "end")
                self.ent_sni.insert(0, cfg["sni"])
            clean_doh = _clean_doh_url(str(cfg.get("doh_url") or ""))
            self.ent_doh.delete(0, "end")
            if clean_doh:
                self.ent_doh.insert(0, clean_doh)
        except (OSError, json.JSONDecodeError):
            self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
            self.direct_dns_raw = ""
        self._update_split_btn_text()
        self._on_proto()

    def _save_config(self):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self._current_cfg_dict(), f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- статус ----------
    def _apply_adapters_and_status(self, adapters, sel, dns, dns_v6=None):
        self.adapters = adapters
        names = [f"{a['name']}  —  {a['desc']}" for a in adapters]
        self.cmb_adapter["values"] = names
        if sel is not None and sel in adapters:
            self.cmb_adapter.current(adapters.index(sel))
        elif names:
            self.cmb_adapter.current(0)
        else:
            self.cmb_adapter.set("")
        self._apply_status(sel, dns, dns_v6)

    def refresh_status(self):
        prev = self._selected_adapter()
        prev_key = adapter_key(prev) if prev else None
        def work():
            adapters = get_adapters()
            sel = next((a for a in adapters if adapter_key(a) == prev_key), None)
            if sel is None and adapters:
                sel = adapters[0]
            dns = get_dns_servers(adapter_key(sel)) if sel else []
            dns_v6 = get_dns_servers_v6(adapter_key(sel)) if sel else []
            self.q.put(("adapters_status", (adapters, sel, dns, dns_v6)))
            self.q.put(("proxy", None))
        threading.Thread(target=work, daemon=True).start()

    def _apply_status(self, adapter, dns, dns_v6=None):
        if adapter:
            self.lbl_adapter.config(
                text=f"Адаптер: {adapter['name']} — {adapter['desc']}")
        else:
            self.lbl_adapter.config(text="Адаптер: не выбран")
        if dns == [LOCAL_DNS]:
            v6_mark = " + ::1" if dns_v6 == [LOCAL_DNS_V6] else ""
            self.lbl_dns.config(text=f"DNS адаптера: 127.0.0.1{v6_mark} (через SecureDNS ✔)",
                                foreground=GREEN)
        else:
            all_dns = list(dns or []) + [s for s in (dns_v6 or []) if s not in (dns or [])]
            self.lbl_dns.config(
                text="DNS адаптера: " + (", ".join(all_dns) if all_dns else "автоматически (DHCP)"),
                foreground=MUTED)

    def _update_live_stats(self):
        if not self.proxy:
            self.lbl_stats.config(text="Счётчики: ожидание запуска", foreground=MUTED)
            return
        st = self.proxy.get_stats()
        s = st.get("stats") or {}
        self.lbl_stats.config(
            text=(
                f"Запросов: {s.get('total', 0)} | Кэш: {s.get('cache_hit', 0)} "
                f"({st.get('cache_entries', 0)} зап.) | Блок v6/QUIC: {s.get('blocked_v6_quic', 0)} | "
                f"Ошибок: {s.get('err', 0)}"
            ),
            foreground=MUTED,
        )

    def _apply_proxy_state(self, _):
        if self.proxy:
            v6_txt = " + ::1:53" if self.proxy.ipv6_bound else ""
            blk_txt = " [блок IPv6/QUIC]" if self.proxy.block_v6_quic else ""
            split_txt = f" [разд. DNS: {len(self.proxy.split_domains)}]" if self.proxy.split_enabled else ""
            self.lbl_proxy.config(text=f"Прокси: работает на 127.0.0.1:53{v6_txt}{blk_txt}{split_txt} ✔",
                                  foreground=GREEN)
        else:
            self.lbl_proxy.config(text="Прокси: остановлен", foreground=MUTED)
        self._update_live_stats()

    def on_flush_cache(self):
        if self.proxy:
            self.proxy.clear_cache()
        flush_dns_cache()
        self._update_live_stats()
        self.log("✔ Кэш DNS (прокси + система) очищен.")

    def on_clear_log(self):
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _on_offer_switch_doh(self, payload: dict):
        title = payload.get("label") or "DoH"
        url = payload.get("url") or ""
        split = bool(payload.get("split", False))
        has_ips = bool(self.ent_ips.get().strip())
        if not messagebox.askyesno(
            APP_NAME,
            f"Порт 853 не отвечает, но ваш сервер ответил по {title}.\n\n"
            f"Переключиться на рабочий режим и запустить шифрованный DNS прямо сейчас?",
        ):
            return
        if url:
            self.ent_doh.delete(0, "end")
            self.ent_doh.insert(0, url)
        self.var_proto.set("doh" if has_ips else "doh_url")
        self.var_verify.set(True)
        self.var_split_hello.set(split)
        self._on_proto()
        self._save_config()
        self.on_enable()

    # ---------- действия ----------
    def on_enable(self):
        if not is_admin():
            messagebox.showerror(APP_NAME, "Нужны права администратора.\n"
                                           "Перезапустите программу: " + admin_hint())
            return
        a = self._selected_adapter()
        if not a:
            messagebox.showerror(APP_NAME, "Выберите сетевой адаптер.")
            return
        split_dns = bool(self.var_split_dns.get())
        split_domains = list(self.split_domains)
        direct_dns_raw = self.direct_dns_raw
        if split_dns and not split_domains:
            messagebox.showerror(
                APP_NAME,
                "Включён «Раздельный DNS», но список доменов пуст.\n"
                "Нажмите «Домены…» и добавьте домены (или «Сбросить пресет ИИ»).",
            )
            return
        if direct_dns_raw:
            bad_dir = [ip.strip() for ip in direct_dns_raw.split(",") if ip.strip() and not _valid_ip(ip.strip())]
            if bad_dir:
                messagebox.showerror(
                    APP_NAME,
                    f"Некорректный прямой DNS в настройках раздельного DNS: {', '.join(bad_dir)}",
                )
                return
        built = self._build_upstreams()
        if not built:
            return
        upstreams, desc = built
        proto = self.var_proto.get()
        targets = self._parse_targets() or []
        doh_url = _clean_doh_url(self.ent_doh.get())
        sni = _clean_sni_host(self.ent_sni.get()) if proto == "dot" else None
        verify = bool(self.var_verify.get())
        split_hello = bool(self.var_split_hello.get())
        block_v6_quic = self.var_block_v6_quic.get()
        fw_quic = bool(self.var_fw_quic.get())
        self._save_config()
        prev_active = self.active_adapter

        def work():
            nonlocal upstreams
            self.q.put(("log", f"▶ Включаю шифрованный DNS ({desc}) на «{a['name']}»…"))
            k = adapter_key(a)
            pre_v4 = get_dns_servers(k)
            direct_cand = [ip for ip in (pre_v4 + load_backup(k)) if _valid_ip(ip)]

            if proto == "auto":
                for up in upstreams:
                    up.close()
                try:
                    upstreams, win_desc, probe_rows = resolve_auto_upstreams(
                        targets, doh_url=doh_url, direct_dns_ips=direct_cand, verify_dot=True
                    )
                except Exception as e:  # noqa: BLE001
                    self.q.put(("log", f"   ✘ Автоподбор не нашёл рабочий канал: {e}"))
                    self.q.put(("log", "   Настройки НЕ применены."))
                    return
                for lbl, _ok, detail in probe_rows:
                    self.q.put(("log", f"   {lbl}: {detail}"))
                self.q.put(("log", f"   ✔ Выбран рабочий канал: {win_desc}"))
            else:
                # 0a. Если выбран DoH без явных IP — резолвим IP в фоне напрямую
                if proto in ("doh_url", "doh") and any(not getattr(up, "_ips", None) for up in upstreams):
                    for up in upstreams:
                        up.close()
                    upstreams, resolved_ips = expand_doh_upstreams(
                        doh_url, verify, split_hello, ips=[], direct_dns_ips=direct_cand
                    )
                    if not resolved_ips:
                        for up in upstreams:
                            up.close()
                        self.q.put(("log", "   ✘ Не удалось определить IP для DoH-домена. Проверьте ссылку и интернет."))
                        return
                    self.q.put(("log", f"   ✔ Домен DoH → {', '.join(resolved_ips)}"))

                # 0b. Проверяем, что хотя бы один апстрим реально отвечает
                test = build_dns_query("example.com")
                ok_up = False
                last_err = None
                for idx, up in enumerate(upstreams, 1):
                    try:
                        resp = up.query(test)
                        ips = parse_answers(resp)
                        self.q.put(("log", f"   ✔ Апстрим #{idx} отвечает: example.com → "
                                           f"{', '.join(ips) or 'ответ получен'}"))
                        ok_up = True
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        self.q.put(("log", f"   ⚠ Апстрим #{idx} не ответил: {e}"))
                if not ok_up:
                    for up in upstreams:
                        up.close()
                    self.q.put(("log", f"   ✘ Ни один апстрим НЕ отвечает: {last_err}"))
                    if proto == "dot":
                        self.q.put(("log", "   Проверяю альтернативные порты (:443 / резка 3B / :8443)…"))
                        alt_rows = probe_transports(
                            [ip for ip, _ in targets[:2]],
                            doh_url=doh_url,
                            sni=sni or (_clean_sni_host(doh_url) if doh_url else None),
                            verify=verify or bool(doh_url),
                            direct_dns_ips=direct_cand,
                        )
                        offer = None
                        for lbl, ok, detail in alt_rows:
                            if not lbl.startswith("DoT "):
                                self.q.put(("log", f"   {lbl}: {detail}"))
                                if ok and doh_url and offer is None and lbl.startswith("DoH "):
                                    sw_url = _with_url_port(doh_url, 8443) if ":8443" in lbl else doh_url
                                    offer = {"label": lbl, "url": sw_url, "split": "резка 3B" in lbl}
                        if offer is not None:
                            self.q.put(("offer_switch_doh", offer))
                    self.q.put(("log", "   Настройки НЕ применены."))
                    return

            # 1. Если защита была включена на другом адаптере — откатим его DNS
            if prev_active and adapter_key(prev_active) != adapter_key(a):
                prev_k = adapter_key(prev_active)
                if get_dns_servers(prev_k) == [LOCAL_DNS] or get_dns_servers_v6(prev_k) == [LOCAL_DNS_V6]:
                    _, prev_msg = restore_adapter_dns(prev_k)
                    self.q.put(("log", f"   Предыдущий адаптер «{prev_active['name']}»: {prev_msg}"))

            # 2. Бэкап текущих DNS (IPv4 и IPv6)
            old = get_dns_servers(k)
            old_v6 = get_dns_servers_v6(k)
            if old == [LOCAL_DNS] or old_v6 == [LOCAL_DNS_V6]:
                save_backup(k, old, old_v6)
                self.q.put(("log", "   На адаптере уже адрес SecureDNS — прежний бэкап сохранён."))
            else:
                save_backup(k, old, old_v6)
                old_all = list(old or []) + list(old_v6 or [])
                self.q.put(("log", f"   Резервная копия DNS: {old_all or 'авто (DHCP)'}"))

            direct_upstreams = []
            if split_dns:
                direct_ips, direct_src = resolve_direct_dns(k, pre_old_v4=old, manual_raw=direct_dns_raw)
                direct_upstreams = [PlainUDPUpstream(ip) for ip in direct_ips]
                self.q.put(("log", f"   Раздельный DNS: {len(split_domains)} дом. → шифр, "
                                   f"остальное → {', '.join(direct_ips)} ({direct_src})"))

            # 3. Стоп старого прокси, старт нового
            if self.proxy:
                self.proxy.stop()
                self.proxy = None
            proxy = LocalDNSProxy(
                upstreams,
                on_log=self._thread_log,
                block_v6_quic=block_v6_quic,
                split_domains=(split_domains if split_dns else None),
                direct_upstreams=direct_upstreams,
            )
            try:
                proxy.start()
            except OSError as e:
                proxy.stop()
                self.q.put(("log", f"   ✘ Не удалось занять 127.0.0.1:53 — {e}"))
                self.q.put(("proxy", None))
                return
            self.proxy = proxy
            self.active_adapter = a
            self.q.put(("proxy", None))
            v6_msg = " + ::1:53" if proxy.ipv6_bound else ""
            blk_msg = ", блок IPv6/QUIC: ВКЛ" if block_v6_quic else ""
            split_msg = f", раздельный DNS: {len(split_domains)} дом." if proxy.split_enabled else ""
            self.q.put(("log", f"   ✔ Локальный прокси слушает 127.0.0.1:53{v6_msg}{blk_msg}{split_msg}"))

            # 4. Назначаем системный DNS
            target_dns = [LOCAL_DNS, LOCAL_DNS_V6] if (IS_WINDOWS and block_v6_quic and proxy.ipv6_bound) else [LOCAL_DNS]
            ok, err = set_dns_servers(k, target_dns)
            if not ok:
                self.q.put(("log", f"   ✘ Ошибка смены DNS адаптера: {err}"))
                proxy.stop()
                self.proxy = None
                self.active_adapter = None
                self.q.put(("proxy", None))
                return
            if IS_WINDOWS and fw_quic:
                ok_fw, msg_fw = set_quic_firewall_block(True)
                self.q.put(("log", f"   {'✔' if ok_fw else '⚠'} {msg_fw}"))
            flush_dns_cache()
            cur_v4 = get_dns_servers(k)
            cur_v6 = get_dns_servers_v6(k)
            assigned = " + ".join(cur_v4 + ([LOCAL_DNS_V6] if cur_v6 == [LOCAL_DNS_V6] else [])) or LOCAL_DNS
            self.q.put(("log", f"   DNS адаптера → {assigned}, кэш очищен."))
            if proxy.split_enabled:
                self.q.put(("log", "✔ Готово! Раздельный DNS работает: список ИИ → шифр, остальное → провайдер."))
            else:
                self.q.put(("log", "✔ Готово! Весь DNS-трафик шифруется. Нажмите «Проверить»."))
            self.q.put(("status", (a, cur_v4, cur_v6)))
        self._run_async(work)

    def _restore_adapter_dns(self, if_index: int):
        return restore_adapter_dns(if_index)

    def _startup_init(self):
        def work():
            startup_rollback(
                self._thread_log,
                should_abort=lambda: self.proxy is not None or self._busy,
            )
            adapters = get_adapters()
            sel = adapters[0] if adapters else None
            dns = get_dns_servers(adapter_key(sel)) if sel else []
            dns_v6 = get_dns_servers_v6(adapter_key(sel)) if sel else []
            self.q.put(("adapters_status", (adapters, sel, dns, dns_v6)))
            self.q.put(("proxy", None))
            env_st = {
                "autostart": get_autostart() if IS_WINDOWS else False,
                "browser_doh": check_browser_doh_status(),
            }
            self.q.put(("env_status", env_st))
            if self._autostart:
                self.q.put(("autostart_enable", None))
        threading.Thread(target=work, daemon=True).start()

    def on_disable(self, quit_after: bool = False):
        if not is_admin():
            messagebox.showerror(APP_NAME, "Нужны права администратора.")
            return
        a = self.active_adapter or self._selected_adapter()

        def work():
            self.q.put(("log", "▶ Отключаю шифрованный DNS…"))
            if self.proxy:
                self.proxy.stop()
                self.proxy = None
                self.q.put(("proxy", None))
                self.q.put(("log", "   Локальный прокси остановлен."))
            self.active_adapter = None
            if IS_WINDOWS and has_quic_firewall_rule():
                ok_fw, msg_fw = set_quic_firewall_block(False)
                self.q.put(("log", f"   {'✔' if ok_fw else '⚠'} {msg_fw}"))
            if a:
                k = adapter_key(a)
                ok, msg = self._restore_adapter_dns(k)
                self.q.put(("log", f"   {msg}"))
                flush_dns_cache()
                # Проверяем, что откат реально применился
                current = get_dns_servers(k)
                current_v6 = get_dns_servers_v6(k)
                if current == [LOCAL_DNS] or current_v6 == [LOCAL_DNS_V6]:
                    # Последняя линия обороны — принудительный DHCP
                    ok2, _ = reset_dns_servers(k)
                    flush_dns_cache()
                    current = get_dns_servers(k)
                    current_v6 = get_dns_servers_v6(k)
                    self.q.put(("log", "   ⚠ Локальный DNS ещё оставался — принудительно "
                                       f"переведён в DHCP: {'успешно' if ok2 else 'не удалось'}"))
                if current == [LOCAL_DNS] or current_v6 == [LOCAL_DNS_V6]:
                    self.q.put(("log", "   ✘ Не удалось убрать 127.0.0.1/::1! Откройте "
                                       "свойства адаптера и выберите "
                                       "«Получить адрес DNS-сервера автоматически»."))
                else:
                    restored = current + current_v6
                    self.q.put(("log", f"   ✔ Откат подтверждён, текущие DNS: "
                                       f"{', '.join(restored) or 'авто (DHCP)'}"))
                self.q.put(("status", (a, current, current_v6)))
            self.q.put(("log", "✔ Отключено, обычный интернет работает как раньше."))
            if quit_after:
                self.q.put(("quit", None))
        self._run_async(work)

    def on_probe_ports(self):
        proto = self.var_proto.get()
        targets = [] if proto == "doh_url" else (self._parse_targets() or [])
        ips = [ip for ip, _ in targets]
        doh_url = _clean_doh_url(self.ent_doh.get()) if proto in ("auto", "doh", "doh_url") else ""
        sni = _clean_sni_host(self.ent_sni.get()) if proto == "dot" else None
        verify = (True if doh_url else False) if proto == "auto" else bool(self.var_verify.get())
        sel = self._selected_adapter()

        if not ips and not (doh_url and doh_url.startswith("https://")):
            messagebox.showerror(APP_NAME, "Впишите IP сервера и/или URL DoH для теста портов.")
            return

        def work():
            self.q.put(("log", "▶ Диагностика транспортов (:853 / :443 / резка 3B / :8443)…"))
            cand_dns = []
            if sel:
                k = adapter_key(sel)
                cand_dns = [x for x in (get_dns_servers(k) + load_backup(k)) if _valid_ip(x)]
            rows = probe_transports(ips, doh_url=doh_url, sni=sni, verify=verify, direct_dns_ips=cand_dns)
            if not rows:
                self.q.put(("log", "   ⚠ Нет доступных адресов для проверки."))
                return
            for label, _ok, detail in rows:
                self.q.put(("log", f"   {label}: {detail}"))
            self.q.put(("log", "✔ Тест портов завершён."))
        self._run_async(work)

    def on_test(self):
        if self.proxy:
            def work():
                self.q.put(("log", "▶ Проверка…"))
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(8)
                        if self.proxy.split_enabled and self.proxy.split_domains:
                            ai_host = self.proxy.split_domains[0]
                            t0 = time.monotonic()
                            s.sendto(build_dns_query(ai_host), (LOCAL_DNS, 53))
                            r_ai, _ = s.recvfrom(4096)
                            ms_ai = int((time.monotonic() - t0) * 1000)
                            self.q.put(("log", f"   127.0.0.1:53 → {ai_host} = "
                                               f"{', '.join(parse_answers(r_ai)) or 'ответ без A-записей'} ({ms_ai} мс) [SmartDNS ✔]"))
                            dir_host = ("example.org"
                                        if self.proxy._is_smart_domain("example.com")
                                        else "example.com")
                            t1 = time.monotonic()
                            s.sendto(build_dns_query(dir_host), (LOCAL_DNS, 53))
                            r_dir, _ = s.recvfrom(4096)
                            ms_dir = int((time.monotonic() - t1) * 1000)
                            self.q.put(("log", f"   127.0.0.1:53 → {dir_host} = "
                                               f"{', '.join(parse_answers(r_dir)) or 'ответ без A-записей'} ({ms_dir} мс) [Провайдер ✔]"))
                            self.q.put(("log", "✔ Раздельный DNS работает: список ИИ идёт через шифрованный "
                                               "сервер, остальное — через провайдера."))
                        else:
                            t0 = time.monotonic()
                            s.sendto(build_dns_query("example.com"), (LOCAL_DNS, 53))
                            resp, _ = s.recvfrom(4096)
                            ms = int((time.monotonic() - t0) * 1000)
                            ips = parse_answers(resp)
                            self.q.put(("log", f"   127.0.0.1:53 → example.com = "
                                               f"{', '.join(ips) or 'ответ без A-записей'} ({ms} мс)"))
                            self.q.put(("log", "✔ Шифрованный канал работает: запрос ушёл "
                                               "по TLS на ваш сервер и вернулся с ответом."))
                except Exception as e:  # noqa: BLE001
                    self.q.put(("log", f"   ✘ Прокси не ответил: {e}"))
            self._run_async(work)
            return

        built = self._build_upstreams()
        if not built:
            return
        upstreams, desc = built
        proto = self.var_proto.get()
        targets = self._parse_targets() or []
        doh_url = _clean_doh_url(self.ent_doh.get())
        verify = bool(self.var_verify.get())
        split_hello = bool(self.var_split_hello.get())
        sel = self._selected_adapter()

        def work_upstream():
            nonlocal upstreams
            self.q.put(("log", "▶ Проверка…"))
            cand_dns = []
            if sel:
                k = adapter_key(sel)
                cand_dns = [x for x in (get_dns_servers(k) + load_backup(k)) if _valid_ip(x)]
            if proto == "auto":
                for up in upstreams:
                    up.close()
                try:
                    test_ups, win_desc, probe_rows = resolve_auto_upstreams(
                        targets, doh_url=doh_url, direct_dns_ips=cand_dns, verify_dot=True
                    )
                    for up in test_ups:
                        up.close()
                    for lbl, _ok, detail in probe_rows:
                        self.q.put(("log", f"   {lbl}: {detail}"))
                    self.q.put(("log", f"✔ Рабочий транспорт найден ({win_desc}) — можно нажимать «Включить»."))
                except Exception as e:  # noqa: BLE001
                    self.q.put(("log", f"✘ Автопроверка не прошла: {e}"))
                return
            if proto in ("doh_url", "doh") and any(not getattr(up, "_ips", None) for up in upstreams):
                for up in upstreams:
                    up.close()
                upstreams, resolved_ips = expand_doh_upstreams(
                    doh_url, verify, split_hello, ips=[], direct_dns_ips=cand_dns
                )
                if resolved_ips:
                    self.q.put(("log", f"   ✔ Домен DoH → {', '.join(resolved_ips)}"))
            self.q.put(("log", f"   Прокси не запущен. Проверяю апстрим ({desc})…"))
            ok_any = False
            last_err = None
            q = build_dns_query("example.com")
            try:
                for idx, up in enumerate(upstreams, 1):
                    try:
                        t0 = time.monotonic()
                        resp = up.query(q)
                        ms = int((time.monotonic() - t0) * 1000)
                        ips = parse_answers(resp)
                        self.q.put(("log", f"   ✔ Апстрим #{idx} отвечает: example.com → "
                                           f"{', '.join(ips) or 'ответ получен'} ({ms} мс)"))
                        ok_any = True
                        break
                    except Exception as e:  # noqa: BLE001
                        last_err = e
                        self.q.put(("log", f"   ⚠ Апстрим #{idx} не ответил: {e}"))
                if ok_any:
                    self.q.put(("log", "   Сервер рабочий — можно нажимать «Включить»."))
                else:
                    self.q.put(("log", f"   ✘ Ни один апстрим не отвечает: {last_err}"))
            finally:
                for up in upstreams:
                    up.close()
        self._run_async(work_upstream)

    def _on_log_saved(self, path: str):
        if messagebox.askyesno(
            APP_NAME,
            f"Диагностический лог сохранён:\n{path}\n\n"
            f"Отправьте этот .txt файл разработчику.\n"
            f"Открыть папку с файлом?",
        ):
            try:
                if IS_WINDOWS:
                    subprocess.Popen(["explorer", "/select," + os.path.normpath(path)])
                else:
                    subprocess.Popen(["xdg-open", os.path.dirname(os.path.abspath(path))])
            except OSError:
                pass

    def on_save_log(self):
        if self._busy:
            return
        fname = f"SecureDNS_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        path = filedialog.asksaveasfilename(
            title="Сохранить журнал диагностики",
            initialdir=default_log_export_dir(),
            initialfile=fname,
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt"), ("Все файлы", "*.*")],
        )
        if not path:
            return
        sel = self._selected_adapter()
        state = {
            "adapter": f"{sel['name']} — {sel['desc']}" if sel else None,
            "ips": self.ent_ips.get().strip(),
            "proto": self.var_proto.get(),
            "sni": self.ent_sni.get().strip(),
            "doh_url": self.ent_doh.get().strip(),
            "verify": bool(self.var_verify.get()),
            "block_v6_quic": bool(self.var_block_v6_quic.get()),
            "split_hello": bool(self.var_split_hello.get()),
            "block_fw_quic": bool(self.var_fw_quic.get()),
            "split_dns": bool(self.var_split_dns.get()),
            "split_domains_count": len(self.split_domains),
            "direct_dns": self.direct_dns_raw,
            "autostart": bool(self.var_autostart.get()),
            "minimize_to_tray": bool(self.var_tray.get()),
            "proxy_running": self.proxy is not None,
            "proxy_stats": self.proxy.get_stats() if self.proxy else None,
        }
        ui_text = self.txt_log.get("1.0", "end-1c")

        def work():
            try:
                saved = save_diagnostics_report(path, app_state=state, ui_log_text=ui_text)
                self.q.put(("log", f"✔ Журнал диагностики сохранён: {saved}"))
                self.q.put(("log_saved", saved))
            except Exception as e:  # noqa: BLE001
                write_log_file(traceback.format_exc(), level="ERROR")
                self.q.put(("log", f"✘ Не удалось сохранить лог: {e}"))

        self._run_async(work)

    def on_close(self):
        if self.proxy and self.active_adapter:
            if self.var_tray.get() and self._tray is not None and self._tray.available:
                self.withdraw()
                self.log("ℹ Свёрнуто в трей — защита работает в фоне (клик по иконке вернёт окно).")
                return
            if messagebox.askyesno(
                    APP_NAME,
                    "Сейчас DNS адаптера направлен на программу (127.0.0.1).\n"
                    "Если просто закрыть — интернет перестанет резолвиться.\n\n"
                    "Отключить шифрованный DNS и вернуть настройки?"):
                if not self._busy:
                    self.on_disable(quit_after=True)
                return
        if self.proxy:
            self.proxy.stop()
            self.proxy = None
        if IS_WINDOWS and has_quic_firewall_rule() and is_admin():
            set_quic_firewall_block(False)
        release_single_instance()
        self.destroy()


# ---------------------------------------------------------------------------
# CLI-режим (для Linux без GUI / Wayland / серверов):  python3 main.py --cli
# ---------------------------------------------------------------------------

def _cli_input(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        val = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val or default


def _valid_ip(ip: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip)
        return not addr.is_unspecified and not addr.is_loopback
    except ValueError:
        return False


def _cli_build_upstreams():
    """Спрашивает параметры у пользователя, возвращает (upstreams, описание).
    Опечатки переспрашиваем, пустой ввод — отмена."""
    while True:
        proto = _cli_input(
            "Режим: auto (подберёт сам), dot (:853), doh_url (DoH по ссылке), doh (URL + IP)",
            "auto",
        ).lower()
        if proto in ("auto", "dot", "doh", "doh_url"):
            break
        print("✘ Впишите «auto», «dot», «doh_url» или «doh».")

    if proto == "auto":
        while True:
            raw_ips = _cli_input("IP-адреса сервера (через запятую, можно пусто если есть ссылка)", "")
            try:
                targets = parse_ip_targets(raw_ips) if raw_ips else []
                break
            except ValueError as e:
                print(f"✘ {e}")
        while True:
            raw_url = _cli_input("DoH URL https://... (или пусто, если только IP для :853)", "")
            if not raw_url or raw_url.lower().startswith("https://"):
                break
            print("✘ URL должен начинаться с https://")
        if not targets and not raw_url:
            return None
        try:
            ups, win_desc, rows = resolve_auto_upstreams(targets, doh_url=raw_url, verify_dot=True)
            for lbl, _ok, detail in rows:
                print(f"  {lbl}: {detail}")
            return ups, win_desc
        except Exception as e:  # noqa: BLE001
            print(f"✘ {e}")
            return None

    targets = []
    if proto in ("dot", "doh"):
        while True:
            raw = _cli_input("Ваши DNS-серверы (IP или IP:порт через запятую; для doh можно пусто)")
            if not raw:
                if proto == "dot":
                    return None
                targets = []
                break
            try:
                targets = parse_ip_targets(raw)
                if targets:
                    break
            except ValueError as e:
                print(f"✘ {e}. Пример: 9.9.9.9, 149.112.112.112:853")

    ips = [ip for ip, _ in targets]
    default_verify = "y" if proto == "doh_url" else "n"
    verify = _cli_input("Проверять TLS-сертификат сервера? (y/n)", default_verify).lower() == "y"
    if proto == "dot":
        sni = None
        if verify:
            raw_sni = _cli_input("Домен сертификата для проверки (пусто — проверять по IP)")
            sni = _clean_sni_host(raw_sni)
        return [DoTUpstream(ip, port, verify=verify, hostname=sni) for ip, port in targets], \
               f"DoT → {format_ip_targets(targets)}" + (f" (SNI {sni})" if sni else "")
    split_hello = _cli_input("Резать TLS ClientHello по 3 байта (:443)? (y/n)", "n").lower() == "y"
    split_tag = " + TLS-резка 3B" if split_hello else ""
    while True:
        url = _cli_input("DoH-шаблон (https://... или https://домен:8443/dns-query, пусто — отмена)")
        if not url:
            return None
        if url.startswith("https://"):
            break
        print("✘ Шаблон должен начинаться с https://")
    desc = f"DoH → {url}" + (f" (через {', '.join(ips)})" if ips else " (резолв из URL)") + split_tag
    try:
        upstreams, _ = expand_doh_upstreams(url, verify, split_hello, ips=ips)
        return upstreams, desc
    except ValueError as e:
        print(f"✘ {e}")
        return None


def cli_main():
    print(f"{APP_NAME} {APP_VERSION} — шифрованный DNS (режим командной строки)")
    print("Для графического режима запустите без параметра --cli\n")
    if not is_admin():
        print("✘ Нужны права root. Запустите: sudo python3 main.py --cli")
        return 1
    if acquire_single_instance() is None:
        print("✘ SecureDNS уже запущен в другом окне.")
        return 1
    try:
        log_session_header("CLI")

        def cli_log(msg: str):
            print(msg)
            write_log_file(msg)

        startup_rollback(cli_log)
        # Проверка обновлений
        info = check_for_update_info()
        if info:
            new_ver = info["version"]
            print(f"⬆ Доступна новая версия {new_ver} (у вас {APP_VERSION}).")
            if _cli_input("Обновить сейчас? (y/n)", "n").lower() == "y":
                res = do_update(
                    cli_log,
                    download_url=info.get("url"),
                    expected_size=info.get("size"),
                    on_before_restart=release_single_instance,
                )
                if res:
                    return 0
        proxy = None
        active = None

        def show_status():
            ads = get_adapters()
            if not ads:
                print("Активных адаптеров не найдено.")
            for a in ads:
                dns = get_dns_servers(adapter_key(a))
                mark = " ← через SecureDNS" if dns == [LOCAL_DNS] else ""
                print(f"  {a['name']} ({a['desc']}): {', '.join(dns) or 'авто (DHCP)'}{mark}")
            print(f"  Прокси: {'работает на 127.0.0.1:53' if proxy else 'остановлен'}")
            if proxy:
                st = proxy.get_stats()
                s = st.get("stats") or {}
                print(
                    f"  Счётчики: запросов={s.get('total', 0)}, кэш={s.get('cache_hit', 0)} "
                    f"({st.get('cache_entries', 0)} зап.), блок v6/QUIC={s.get('blocked_v6_quic', 0)}, ошибок={s.get('err', 0)}"
                )

        def enable():
            nonlocal proxy, active
            ads = get_adapters()
            if not ads:
                print("✘ Нет активных адаптеров.")
                return
            print("Адаптеры:")
            for i, a in enumerate(ads, 1):
                print(f"  {i}) {a['name']} — {a['desc']}")
            while True:
                choice = _cli_input("Номер адаптера", "1")
                if choice.isdigit() and 1 <= int(choice) <= len(ads):
                    break
                print("✘ Нет такого номера — впишите цифру из списка.")
            a = ads[int(choice) - 1]
            built = _cli_build_upstreams()
            if not built:
                return
            upstreams, desc = built
            block_v6_quic = _cli_input("Блокировать IPv6 и QUIC для SmartDNS/ИИ? (y/n)", "y").lower() != "n"
            split_dns = _cli_input(
                "Раздельный DNS (только ИИ-домены через сервер, остальное — провайдер)? (y/n)",
                "n",
            ).lower() == "y"
            split_domains = []
            if split_dns:
                raw_doms = _cli_input("Домены через запятую (Enter — пресет Gemini/ChatGPT/Claude/и др.)", "")
                split_domains = list(parse_split_domains(raw_doms)) if raw_doms else list(DEFAULT_SPLIT_DOMAINS)
            print(f"▶ Проверяю апстрим ({desc})…")
            q = build_dns_query("example.com")
            ok_up = False
            last_err = None
            for idx, up in enumerate(upstreams, 1):
                try:
                    resp = up.query(q)
                    print(f"  ✔ Апстрим #{idx} отвечает: example.com → "
                          f"{', '.join(parse_answers(resp)) or 'ответ получен'}")
                    ok_up = True
                    break
                except Exception as e:  # noqa: BLE001
                    last_err = e
                    print(f"  ⚠ Апстрим #{idx} не ответил: {e}")
            if not ok_up:
                for up in upstreams:
                    up.close()
                print(f"  ✘ Ни один апстрим НЕ отвечает: {last_err}")
                print("  Настройки НЕ применены. Проверьте IP, протокол и сертификат.")
                return
            if active and adapter_key(active) != adapter_key(a):
                prev_k = adapter_key(active)
                if get_dns_servers(prev_k) == [LOCAL_DNS] or get_dns_servers_v6(prev_k) == [LOCAL_DNS_V6]:
                    _, prev_msg = restore_adapter_dns(prev_k)
                    print(f"  Предыдущий адаптер «{active['name']}»: {prev_msg}")
            key = adapter_key(a)
            old = get_dns_servers(key)
            old_v6 = get_dns_servers_v6(key)
            if old == [LOCAL_DNS] or old_v6 == [LOCAL_DNS_V6]:
                save_backup(key, old, old_v6)
                print("  На адаптере уже адрес SecureDNS — прежний бэкап сохранён.")
            else:
                save_backup(key, old, old_v6)
                old_all = list(old or []) + list(old_v6 or [])
                print(f"  Резервная копия DNS: {old_all or 'авто (DHCP)'}")
            direct_upstreams = []
            if split_dns:
                direct_ips, direct_src = resolve_direct_dns(key, pre_old_v4=old)
                direct_upstreams = [PlainUDPUpstream(ip) for ip in direct_ips]
                print(f"  Раздельный DNS: {len(split_domains)} дом. → шифр, "
                      f"остальное → {', '.join(direct_ips)} ({direct_src})")
            if proxy:
                proxy.stop()
                proxy = None
            proxy = LocalDNSProxy(
                upstreams,
                block_v6_quic=block_v6_quic,
                split_domains=(split_domains if split_dns else None),
                direct_upstreams=direct_upstreams,
            )
            try:
                proxy.start()
            except OSError as e:
                proxy.stop()
                print(f"  ✘ Не удалось занять 127.0.0.1:53 — {e}")
                proxy = None
                return
            active = a
            target_dns = [LOCAL_DNS, LOCAL_DNS_V6] if (IS_WINDOWS and block_v6_quic and proxy.ipv6_bound) else [LOCAL_DNS]
            ok, err = set_dns_servers(key, target_dns)
            if not ok:
                print(f"  ✘ Ошибка смены DNS: {err}")
                proxy.stop()
                proxy = None
                active = None
                return
            flush_dns_cache()
            print(f"✔ Шифрованный DNS включён на «{a['name']}»."
                  + (" Режим: раздельный DNS." if proxy.split_enabled else " Весь DNS идёт через TLS."))

        def disable():
            nonlocal proxy, active
            if proxy:
                proxy.stop()
                proxy = None
                print("  Прокси остановлен.")
            a = active or (get_adapters() or [None])[0]
            active = None
            if a:
                k = adapter_key(a)
                ok, msg = restore_adapter_dns(k)
                flush_dns_cache()
                print(f"  {msg}")
                cur = get_dns_servers(k)
                cur_v6 = get_dns_servers_v6(k)
                if cur == [LOCAL_DNS] or cur_v6 == [LOCAL_DNS_V6]:
                    ok2, _ = reset_dns_servers(k)
                    flush_dns_cache()
                    cur = get_dns_servers(k)
                    cur_v6 = get_dns_servers_v6(k)
                    print("  ⚠ Локальный DNS ещё оставался — принудительно переведён в DHCP: "
                          + ("успешно" if ok2 else "не удалось"))
                print("  ✔ Откат подтверждён." if (cur != [LOCAL_DNS] and cur_v6 != [LOCAL_DNS_V6])
                      else "  ✘ DNS всё ещё 127.0.0.1/::1 — проверьте вручную!")
            print("✔ Отключено.")

        def test():
            if proxy:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(8)
                        if proxy.split_enabled and proxy.split_domains:
                            ai_host = proxy.split_domains[0]
                            s.sendto(build_dns_query(ai_host), (LOCAL_DNS, 53))
                            r_ai, _ = s.recvfrom(4096)
                            print(f"  ✔ 127.0.0.1:53 → {ai_host} = "
                                  f"{', '.join(parse_answers(r_ai)) or 'ответ без A-записей'} [SmartDNS]")
                            dir_host = ("example.org"
                                        if match_split_domain("example.com", proxy._split_set)
                                        else "example.com")
                            s.sendto(build_dns_query(dir_host), (LOCAL_DNS, 53))
                            r_dir, _ = s.recvfrom(4096)
                            print(f"  ✔ 127.0.0.1:53 → {dir_host} = "
                                  f"{', '.join(parse_answers(r_dir)) or 'ответ без A-записей'} [Провайдер]")
                        else:
                            s.sendto(build_dns_query("example.com"), (LOCAL_DNS, 53))
                            resp, _ = s.recvfrom(4096)
                            print(f"  ✔ 127.0.0.1:53 → example.com = "
                                  f"{', '.join(parse_answers(resp)) or 'ответ без A-записей'}")
                except Exception as e:  # noqa: BLE001
                    print(f"  ✘ Прокси не ответил: {e}")
            else:
                print("  Прокси не запущен. Сначала включите (пункт 2).")

        def save_log():
            default_path = os.path.join(
                default_log_export_dir(),
                f"SecureDNS_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            )
            path = _cli_input("Путь к файлу лога", default_path)
            if not path:
                return
            state = {
                "adapter": f"{active['name']} — {active['desc']}" if active else None,
                "proxy_running": proxy is not None,
                "proxy_stats": proxy.get_stats() if proxy else None,
            }
            try:
                saved = save_diagnostics_report(path, app_state=state)
                cli_log(f"✔ Журнал диагностики сохранён: {saved}")
            except Exception as e:  # noqa: BLE001
                cli_log(f"✘ Не удалось сохранить лог: {e}")

        def probe_ports():
            raw_ips = _cli_input("IP для теста :853 (или пусто для DoH по URL)", "")
            ips = [x.strip() for x in raw_ips.split(",") if _valid_ip(x.strip())]
            doh_url = _cli_input("DoH URL (https://..., или пусто)", "")
            sni = _clean_sni_host(_cli_input("SNI домен (необязательно)", ""))
            rows = probe_transports(ips, doh_url=doh_url, sni=sni, verify=False)
            for label, _ok, detail in rows:
                print(f"  {label}: {detail}")

        try:
            while True:
                print("\n  1) Статус   2) Включить   3) Отключить   4) Проверить   5) Тест портов   6) Сохранить лог (.txt)   7) Инструкция   8) Выход")
                cmd = _cli_input("Выбор")
                if cmd == "1":
                    show_status()
                elif cmd == "2":
                    enable()
                elif cmd == "3":
                    disable()
                elif cmd == "4":
                    test()
                elif cmd == "5":
                    probe_ports()
                elif cmd == "6":
                    save_log()
                elif cmd in ("7", "?", "h", "H"):
                    print("\n" + format_beginner_guide() + "\n")
                elif cmd in ("8", "q", "й"):
                    break
                elif cmd == "":
                    continue
        except KeyboardInterrupt:
            print()
        if proxy:
            ans = _cli_input("Прокси ещё работает. Отключить и вернуть DNS? (y/n)", "y")
            if ans.lower() == "y":
                disable()
            else:
                print("⚠ DNS остался на 127.0.0.1. При следующем запуске программа "
                      "сама вернёт настройки (автооткат).")
        return 0
    finally:
        release_single_instance()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        sys.exit(cli_main())
    _guard = acquire_single_instance()
    if _guard is None:
        _r = tk.Tk()
        _r.withdraw()
        messagebox.showwarning(
            APP_NAME,
            "SecureDNS уже запущен.\n\n"
            "Вторая копия не нужна: DNS-порт 53 один, и две программы "
            "начали бы за него драться. Найдите окно уже запущенной "
            "копии и работайте в ней.")
        _r.destroy()
        sys.exit(0)
    try:
        App(autostart=("--autostart" in sys.argv)).mainloop()
    except tk.TclError as e:
        print(f"✘ Не удалось открыть окно: {e}", file=sys.stderr)
        print("Похоже, рутовому GUI не достучаться до дисплея (частая история "
              "на Wayland).\nЗапустите терминальный режим:  sudo python3 main.py --cli",
              file=sys.stderr)
        sys.exit(1)
    finally:
        release_single_instance()
