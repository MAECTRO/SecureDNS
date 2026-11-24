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

APP_NAME = "SecureDNS"
APP_VERSION = "1.3.4"
IS_WINDOWS = sys.platform.startswith("win")
SPAWN_KW = {"creationflags": 0x08000000} if IS_WINDOWS else {}
LOCAL_DNS = "127.0.0.1"
LOCAL_DNS_V6 = "::1"
BLOCKED_V6_QUIC_QTYPES = {28, 64, 65}  # AAAA, SVCB, HTTPS
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
    """Открывает TLS-сокет с быстрым ретраем при потерях и фоллбэком на резку ClientHello для :443."""
    if port == 443:
        attempts = [True, True, False] if split_hello else [False, False, True]
    else:
        attempts = [True, True] if split_hello else [False, False]

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
                 split_hello: bool = False, connect_timeout: float = 2.0):
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
                 split_hello: bool = False, connect_timeout: float = 2.0):
        from urllib.parse import urlparse
        u = urlparse(url)
        if not u.hostname:
            raise ValueError("некорректный DoH URL")
        self.host = u.hostname
        self.port = u.port or 443
        self.path = u.path or "/dns-query"
        if u.query:
            self.path += "?" + u.query
        self.timeout = timeout
        self.connect_timeout = min(float(connect_timeout), float(timeout))
        self.split_hello = bool(split_hello)
        self._ctx = make_ssl_context(verify, self.host)
        ips = [ip for ip in (bootstrap_ips or []) if ip]
        if not ips and bootstrap_ip:
            ips = [bootstrap_ip]
        self._explicit_ips = bool(ips)
        self._ips = list(dict.fromkeys(ips))
        self._pool = queue.LifoQueue(maxsize=4)
        self._closed = False
        if not self._ips:
            self._resolve()

    def _resolve(self):
        """Резолвим имя хоста, пока системный DNS ещё работает."""
        try:
            infos = socket.getaddrinfo(self.host, self.port, socket.AF_INET)
            ips = sorted({i[4][0] for i in infos})
            if ips:
                self._ips = ips
        except OSError:
            pass  # оставляем прежние адреса

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


# ---------------------------------------------------------------------------
# Локальный DNS-прокси (UDP + TCP на 127.0.0.1:53 и ::1:53)
# ---------------------------------------------------------------------------

class LocalDNSProxy:
    def __init__(self, upstreams, on_log=None, bind_port: int = 53,
                 cooldown_sec: float = 30.0, block_v6_quic: bool = False,
                 bind_ipv6: bool = True,
                 split_domains=None, direct_upstreams=None):
        self.upstreams = list(upstreams)    # список DoTUpstream/DoHUpstream
        self.direct_upstreams = list(direct_upstreams or [])
        self.split_domains = parse_split_domains(split_domains)
        self._split_set = set(self.split_domains)
        self.split_enabled = bool(self._split_set and self.direct_upstreams)
        self.on_log = on_log or (lambda m: None)
        self.bind_port = bind_port
        self._cooldown_sec = cooldown_sec
        self.block_v6_quic = bool(block_v6_quic)
        self._bind_ipv6 = bool(bind_ipv6)
        self.ipv6_bound = False
        self._cooldown_until = [0.0] * len(self.upstreams)
        self._direct_cooldown_until = [0.0] * len(self.direct_upstreams)
        self._cooldown_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._stats = {"total": 0, "ok": 0, "direct_ok": 0, "blocked_v6_quic": 0, "err": 0}
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
            return {
                "bind_port": self.bind_port,
                "ipv6_bound": self.ipv6_bound,
                "block_v6_quic": self.block_v6_quic,
                "split_enabled": self.split_enabled,
                "split_domains_count": len(self.split_domains),
                "direct_targets": [getattr(d, "ip", str(d)) for d in self.direct_upstreams],
                "stats": dict(self._stats),
                "recent": list(self._recent),
            }

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
        use_direct = self.split_enabled and not match_split_domain(qname, self._split_set)

        if not use_direct and self.block_v6_quic and qtype in BLOCKED_V6_QUIC_QTYPES:
            nodata = self._build_nodata(packet)
            if nodata is not None:
                self._record_query(qname, qtype, "NODATA (blocked IPv6/QUIC)", "blocked_v6_quic")
                return nodata

        try:
            if use_direct:
                resp = self._query_upstream_pool(packet, self.direct_upstreams, self._direct_cooldown_until)
                ans = parse_answers(resp)
                summary = ", ".join(ans[:4]) if ans else f"OK ({len(resp)} B)"
                self._record_query(qname, qtype, f"[прямой] {summary}", "direct_ok")
                return resp

            resp = self._query_upstream_pool(packet, self.upstreams, self._cooldown_until)
            ans = parse_answers(resp)
            summary = ", ".join(ans[:4]) if ans else f"OK ({len(resp)} B)"
            prefix = "[SmartDNS] " if self.split_enabled else ""
            self._record_query(qname, qtype, f"{prefix}{summary}", "ok")
            return resp
        except Exception as e:
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
            f"Split DNS: {app_state.get('split_dns')} ({app_state.get('split_domains_count', 0)} domains)",
            f"Direct DNS Override: {app_state.get('direct_dns', '')!r}",
            f"Proxy Running: {proxy_running}",
        ])
    else:
        lines.append("(нет активного снимка UI)")

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
                f"-> Direct: {proxy_stats.get('direct_targets')}"
            )
        lines.extend([
            f"BindPort: {proxy_stats.get('bind_port')} | IPv6Bound: {proxy_stats.get('ipv6_bound')} "
            f"| BlockV6QUIC: {proxy_stats.get('block_v6_quic')}{split_line}",
            f"Counters: total={st.get('total', 0)}, ok={st.get('ok', 0)}, "
            f"direct_ok={st.get('direct_ok', 0)}, blocked_v6_quic={st.get('blocked_v6_quic', 0)}, "
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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} — шифрованный DNS (DoT/DoH)")
        self.geometry("700x770")
        self.minsize(660, 700)
        self.configure(bg=BG)
        if IS_WINDOWS:
            try:
                ico = resource_path("icon.ico")
                if os.path.exists(ico):
                    self.iconbitmap(ico)
            except Exception:  # noqa: BLE001
                pass
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.adapters = []
        self.proxy = None
        self.active_adapter = None
        self._busy = False
        self._update_info = None
        self.btn_update = None
        self.btn_save_log = None
        self.btn_split_edit = None
        self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
        self.direct_dns_raw = ""
        self.q = queue.Queue()
        log_session_header("GUI")
        self._build_ui()
        self._load_config()
        self._poll_queue()
        self.after(50, self._startup_init)
        self.after(2000, self._check_update_bg)

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
                        font=("Segoe UI Semibold", 10), padding=(14, 7), borderwidth=0)
        style.map("Accent.TButton", background=[("active", "#2f6fd6")])
        style.configure("TButton", background=PANEL, foreground=FG,
                        font=("Segoe UI", 10), padding=(12, 6), borderwidth=0)
        style.map("TButton", background=[("active", "#333947")])
        style.configure("Small.TButton", background=PANEL, foreground=FG,
                        font=("Segoe UI", 9), padding=(10, 4), borderwidth=0)
        style.map("Small.TButton", background=[("active", "#333947")])
        style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                        insertcolor=FG, selectbackground=ACCENT,
                        selectforeground="white", borderwidth=1)
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", "white")

        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 6))
        self.header = header
        ttk.Label(header, text="🛡  SecureDNS", style="Title.TLabel").pack(side="left")
        self.lbl_admin = ttk.Label(header,
                                   text="права ✓" if is_admin() else "нет прав",
                                   style="Muted.TLabel",
                                   foreground=GREEN if is_admin() else RED)
        self.lbl_admin.pack(side="right")

        if not is_admin():
            tk.Label(self, text="Нет прав администратора: закройте программу и "
                                + admin_hint() + ", иначе сменить DNS не выйдет.",
                     bg="#4a2c2c", fg="#ffb4b4", font=("Segoe UI", 9), anchor="w",
                     padx=10, pady=6, wraplength=650, justify="left"
                     ).pack(fill="x", padx=16, pady=(0, 8))

        # Статус
        st = ttk.Frame(self, style="Panel.TFrame", padding=12)
        st.pack(fill="x", padx=16, pady=6)
        ttk.Label(st, text="Текущее состояние", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 11)).pack(anchor="w")
        self.lbl_adapter = ttk.Label(st, text="Адаптер: —", style="PanelMuted.TLabel")
        self.lbl_adapter.pack(anchor="w", pady=(6, 0))
        self.lbl_dns = ttk.Label(st, text="DNS адаптера: —", style="PanelMuted.TLabel")
        self.lbl_dns.pack(anchor="w")
        self.lbl_proxy = ttk.Label(st, text="Прокси: остановлен", style="PanelMuted.TLabel")
        self.lbl_proxy.pack(anchor="w")

        # Адаптер
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16, pady=(10, 0))
        ttk.Label(row, text="Сетевой адаптер:").pack(anchor="w")
        self.cmb_adapter = ttk.Combobox(row, state="readonly")
        self.cmb_adapter.pack(fill="x", pady=(4, 0))
        self.cmb_adapter.bind("<<ComboboxSelected>>", lambda e: self.refresh_status())

        # Серверы
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16, pady=(10, 0))
        self.lbl_ips = ttk.Label(row, text="Ваши DNS-серверы (IP через запятую — любые):")
        self.lbl_ips.pack(anchor="w")
        self.ent_ips = ttk.Entry(row)
        self.ent_ips.pack(fill="x", pady=(4, 0))
        self.lbl_ips_hint = ttk.Label(row, text="Порядок важен: при недоступности первого "
                                                "запросы уходят на следующий.",
                                      style="Muted.TLabel")
        self.lbl_ips_hint.pack(anchor="w")

        # Протокол
        row = ttk.Frame(self)
        row.pack(fill="x", padx=16, pady=(10, 0))
        ttk.Label(row, text="Протокол шифрования:").pack(anchor="w")
        self.var_proto = tk.StringVar(value="dot")
        ttk.Radiobutton(row, text="DoT — DNS-over-TLS, порт 853 (рекомендуется для РФ — без потерь :443)",
                        variable=self.var_proto, value="dot",
                        command=self._on_proto).pack(anchor="w", pady=(4, 0))
        ttk.Radiobutton(row, text="DoH — DNS-over-HTTPS, порт 443 или :8443 в URL (при сбое :443 в РФ укажите :8443)",
                        variable=self.var_proto, value="doh",
                        command=self._on_proto).pack(anchor="w")
        self.ent_doh = ttk.Entry(row)
        self.ent_doh.insert(0, "https://example.com/dns-query")

        # Домен сертификата (SNI) для DoT
        self.frm_sni = ttk.Frame(row)
        ttk.Label(self.frm_sni, text="Домен сертификата (для проверки TLS по IP, "
                                     "необязательно):", style="Muted.TLabel").pack(anchor="w")
        self.ent_sni = ttk.Entry(self.frm_sni)
        self.ent_sni.pack(fill="x", pady=(2, 0))
        self.frm_sni.pack(fill="x", pady=(4, 0))

        # TLS-сертификат
        self.var_verify = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Проверять TLS-сертификат сервера "
                                  "(выключите для своих серверов по IP)",
                        variable=self.var_verify).pack(anchor="w", pady=(6, 0))

        # Блокировка IPv6 и QUIC (утечки мимо SmartDNS)
        self.var_block_v6_quic = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text="Блокировать IPv6 и QUIC (рекомендуется для SmartDNS / ИИ)",
                        variable=self.var_block_v6_quic).pack(anchor="w", pady=(2, 0))

        # Фрагментация ClientHello на 3 байта при ТСПУ-блокировках :443
        self.var_split_hello = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Резать TLS ClientHello по 3 байта (обход ТСПУ для :443; иначе сработает как фоллбэк)",
                        variable=self.var_split_hello).pack(anchor="w", pady=(2, 0))

        # Раздельный DNS (только ИИ/выбранные домены через SmartDNS, остальное — провайдер)
        split_row = ttk.Frame(row)
        split_row.pack(fill="x", pady=(4, 0))
        self.var_split_dns = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            split_row,
            text="Раздельный DNS (только домены ИИ через сервер, остальное — провайдер)",
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
        btns.pack(fill="x", padx=16, pady=14)
        self.btn_on = ttk.Button(btns, text="Включить шифрованный DNS",
                                 style="Accent.TButton", command=self.on_enable)
        self.btn_on.pack(side="left")
        self.btn_off = ttk.Button(btns, text="Отключить", command=self.on_disable)
        self.btn_off.pack(side="left", padx=(10, 0))
        self.btn_test = ttk.Button(btns, text="Проверить", command=self.on_test)
        self.btn_test.pack(side="left", padx=(10, 0))
        self.btn_refresh = ttk.Button(btns, text="Статус", command=self.refresh_status)
        self.btn_refresh.pack(side="right")

        # Лог
        log_bar = ttk.Frame(self)
        log_bar.pack(fill="x", padx=16, pady=(0, 4))
        ttk.Label(log_bar, text="Журнал событий:", style="Muted.TLabel").pack(side="left")
        self.btn_save_log = ttk.Button(
            log_bar, text="Сохранить лог (.txt)", style="Small.TButton", command=self.on_save_log
        )
        self.btn_save_log.pack(side="right")

        self.txt_log = tk.Text(self, bg="#12141a", fg="#b8c0cc", insertbackground=FG,
                               font=("Consolas", 9), wrap="word", relief="flat",
                               height=8, state="disabled")
        self.txt_log.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        self.log(f"{APP_NAME} {APP_VERSION}. Впишите свои DNS-серверы, выберите протокол "
                 f"и нажмите «Включить». Весь DNS-поток пойдёт через 127.0.0.1 → TLS.")

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
        for btn in (self.btn_on, self.btn_off, self.btn_test,
                    self.btn_refresh, self.btn_save_log, self.btn_split_edit, self.btn_update):
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
                elif kind == "refresh_req":
                    self.refresh_status()
                elif kind == "proxy":
                    self._apply_proxy_state(payload)
                elif kind == "update":
                    self._show_update_button(payload)
                elif kind == "log_saved":
                    self._on_log_saved(payload)
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
        self.after(80, self._poll_queue)

    def _on_proto(self):
        if self.var_proto.get() == "doh":
            self.ent_doh.pack(fill="x", pady=(4, 0))
            self.frm_sni.pack_forget()
            self.lbl_ips.config(text="IP DoH-сервера (рекомендуется — прямое подключение "
                                     "без DNS-резолва):")
            self.lbl_ips_hint.config(
                text="Каждый IP балансируется отдельно (Keep-Alive). В РФ при потерях :443 "
                     "допишите порт: https://домен:8443/dns-query")
        else:
            self.ent_doh.pack_forget()
            self.frm_sni.pack(fill="x", pady=(4, 0))
            self.lbl_ips.config(text="Ваши DNS-серверы (IP через запятую — любые):")
            self.lbl_ips_hint.config(text="Порядок важен: при недоступности первого "
                                          "запросы уходят на следующий.")

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
        ips = [s.strip() for s in self.ent_ips.get().split(",") if s.strip()]
        for ip in ips:
            if not _valid_ip(ip):
                return None
        return ips

    def _build_upstreams(self):
        ips = self._parse_ips()
        if ips is None:
            messagebox.showerror(APP_NAME, "Впишите корректные IPv4-адреса (не 127.0.0.1 и не 0.0.0.0),\n"
                                           "например: 9.9.9.9, 149.112.112.112")
            return None
        verify = self.var_verify.get()
        split_hello = self.var_split_hello.get()
        split_tag = " + TLS-резка 3B" if split_hello else ""
        if self.var_proto.get() == "dot":
            if not ips:
                messagebox.showerror(APP_NAME, "Для DoT впишите хотя бы один IP сервера.")
                return None
            sni = _clean_sni_host(self.ent_sni.get())
            if verify and not sni:
                if not messagebox.askyesno(
                        APP_NAME,
                        "Включена проверка сертификата, но «Домен сертификата» не задан.\n"
                        "Сертификат сервера обычно выпущен на домен, а не на IP —\n"
                        "проверка, скорее всего, не пройдёт (IP address mismatch).\n\n"
                        "Продолжить без домена?"):
                    return None
            return [DoTUpstream(ip, 853, verify=verify, hostname=sni, split_hello=split_hello) for ip in ips], \
                   f"DoT:853 → {', '.join(ips)}" + (f" (SNI {sni})" if sni else "") + split_tag
        url = self.ent_doh.get().strip()
        if not url.startswith("https://"):
            messagebox.showerror(APP_NAME, "DoH-шаблон должен начинаться с https://")
            return None
        desc = f"DoH → {url}" + (f" (через {', '.join(ips)})" if ips else "") + split_tag
        if ips:
            return [DoHUpstream(url, verify=verify, bootstrap_ips=[ip], split_hello=split_hello) for ip in ips], desc
        return [DoHUpstream(url, verify=verify, bootstrap_ips=[], split_hello=split_hello)], desc

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
            self.var_proto.set(cfg.get("proto", "dot"))
            self.var_verify.set(bool(cfg.get("verify", False)))
            self.var_block_v6_quic.set(bool(cfg.get("block_v6_quic", True)))
            self.var_split_hello.set(bool(cfg.get("split_hello", False)))
            self.var_split_dns.set(bool(cfg.get("split_dns", False)))
            if "split_domains" in cfg:
                self.split_domains = list(parse_split_domains(cfg.get("split_domains", "")))
            else:
                self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
            self.direct_dns_raw = str(cfg.get("direct_dns", "")).strip()
            if cfg.get("sni"):
                self.ent_sni.delete(0, "end")
                self.ent_sni.insert(0, cfg["sni"])
            if cfg.get("doh_url"):
                self.ent_doh.delete(0, "end")
                self.ent_doh.insert(0, cfg["doh_url"])
        except (OSError, json.JSONDecodeError):
            self.split_domains = list(DEFAULT_SPLIT_DOMAINS)
            self.direct_dns_raw = ""
        self._update_split_btn_text()
        self._on_proto()

    def _save_config(self):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": self.ent_ips.get().strip(),
                    "proto": self.var_proto.get(),
                    "verify": self.var_verify.get(),
                    "block_v6_quic": self.var_block_v6_quic.get(),
                    "split_hello": self.var_split_hello.get(),
                    "split_dns": self.var_split_dns.get(),
                    "split_domains": "\n".join(self.split_domains),
                    "direct_dns": self.direct_dns_raw,
                    "sni": self.ent_sni.get().strip(),
                    "doh_url": self.ent_doh.get().strip(),
                }, f, ensure_ascii=False, indent=2)
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

    def _apply_proxy_state(self, _):
        if self.proxy:
            v6_txt = " + ::1:53" if self.proxy.ipv6_bound else ""
            blk_txt = " [блок IPv6/QUIC]" if self.proxy.block_v6_quic else ""
            split_txt = f" [разд. DNS: {len(self.proxy.split_domains)}]" if self.proxy.split_enabled else ""
            self.lbl_proxy.config(text=f"Прокси: работает на 127.0.0.1:53{v6_txt}{blk_txt}{split_txt} ✔",
                                  foreground=GREEN)
        else:
            self.lbl_proxy.config(text="Прокси: остановлен", foreground=MUTED)

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
        block_v6_quic = self.var_block_v6_quic.get()
        self._save_config()
        prev_active = self.active_adapter

        def work():
            self.q.put(("log", f"▶ Включаю шифрованный DNS ({desc}) на «{a['name']}»…"))
            # 0. Проверяем, что хотя бы один апстрим реально отвечает
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
                self.q.put(("log", "   Проверьте IP, протокол и галочку проверки "
                                   "сертификата. Настройки НЕ применены."))
                return

            # 1. Если защита была включена на другом адаптере — откатим его DNS
            if prev_active and adapter_key(prev_active) != adapter_key(a):
                prev_k = adapter_key(prev_active)
                if get_dns_servers(prev_k) == [LOCAL_DNS] or get_dns_servers_v6(prev_k) == [LOCAL_DNS_V6]:
                    _, prev_msg = restore_adapter_dns(prev_k)
                    self.q.put(("log", f"   Предыдущий адаптер «{prev_active['name']}»: {prev_msg}"))

            # 2. Бэкап текущих DNS (IPv4 и IPv6)
            k = adapter_key(a)
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

    def on_test(self):
        if self.proxy:
            def work():
                self.q.put(("log", "▶ Проверка…"))
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(8)
                        if self.proxy.split_enabled and self.proxy.split_domains:
                            ai_host = self.proxy.split_domains[0]
                            s.sendto(build_dns_query(ai_host), (LOCAL_DNS, 53))
                            r_ai, _ = s.recvfrom(4096)
                            self.q.put(("log", f"   127.0.0.1:53 → {ai_host} = "
                                               f"{', '.join(parse_answers(r_ai)) or 'ответ без A-записей'} [SmartDNS ✔]"))
                            dir_host = ("example.org"
                                        if match_split_domain("example.com", self.proxy._split_set)
                                        else "example.com")
                            s.sendto(build_dns_query(dir_host), (LOCAL_DNS, 53))
                            r_dir, _ = s.recvfrom(4096)
                            self.q.put(("log", f"   127.0.0.1:53 → {dir_host} = "
                                               f"{', '.join(parse_answers(r_dir)) or 'ответ без A-записей'} [Провайдер ✔]"))
                            self.q.put(("log", "✔ Раздельный DNS работает: список ИИ идёт через шифрованный "
                                               "сервер, остальное — через провайдера."))
                        else:
                            s.sendto(build_dns_query("example.com"), (LOCAL_DNS, 53))
                            resp, _ = s.recvfrom(4096)
                            ips = parse_answers(resp)
                            self.q.put(("log", f"   127.0.0.1:53 → example.com = "
                                               f"{', '.join(ips) or 'ответ без A-записей'}"))
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

        def work_upstream():
            self.q.put(("log", "▶ Проверка…"))
            self.q.put(("log", f"   Прокси не запущен. Проверяю апстрим ({desc})…"))
            ok_any = False
            last_err = None
            q = build_dns_query("example.com")
            try:
                for idx, up in enumerate(upstreams, 1):
                    try:
                        resp = up.query(q)
                        ips = parse_answers(resp)
                        self.q.put(("log", f"   ✔ Апстрим #{idx} отвечает: example.com → "
                                           f"{', '.join(ips) or 'ответ получен'}"))
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
            "split_dns": bool(self.var_split_dns.get()),
            "split_domains_count": len(self.split_domains),
            "direct_dns": self.direct_dns_raw,
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
        raw = _cli_input("Ваши DNS-серверы (IP через запятую, пусто — отмена)")
        if not raw:
            return None
        ips = [s.strip() for s in raw.split(",") if s.strip()]
        bad = [ip for ip in ips if not _valid_ip(ip)]
        if ips and not bad:
            break
        print(f"✘ Некорректные адреса: {', '.join(bad) or raw}. "
              f"Пример: 9.9.9.9, 149.112.112.112")
    while True:
        proto = _cli_input("Протокол: dot (порт 853, рекомендуется для РФ) или doh (443/:8443)", "dot").lower()
        if proto in ("dot", "doh"):
            break
        print("✘ Впишите буквально «dot» или «doh». "
              "Домен сюда вписывать не надо — он спросится дальше.")
    verify = _cli_input("Проверять TLS-сертификат сервера? (y/n)", "n").lower() == "y"
    split_hello = _cli_input("Резать TLS ClientHello по 3 байта принудительно (обход ТСПУ для :443)? (y/n)", "n").lower() == "y"
    split_tag = " + TLS-резка 3B" if split_hello else ""
    if proto == "dot":
        sni = None
        if verify:
            raw_sni = _cli_input("Домен сертификата для проверки (сертификат обычно "
                                 "выпущен на домен, а не на IP; пусто — проверять по IP)")
            sni = _clean_sni_host(raw_sni)
        return [DoTUpstream(ip, 853, verify=verify, hostname=sni, split_hello=split_hello) for ip in ips], \
               f"DoT:853 → {', '.join(ips)}" + (f" (SNI {sni})" if sni else "") + split_tag
    while True:
        url = _cli_input("DoH-шаблон (https://... или https://домен:8443/dns-query, пусто — отмена)")
        if not url:
            return None
        if url.startswith("https://"):
            break
        print("✘ Шаблон должен начинаться с https://")
    desc = f"DoH → {url}" + (f" (через {', '.join(ips)})" if ips else "") + split_tag
    try:
        if ips:
            return [DoHUpstream(url, verify=verify, bootstrap_ips=[ip], split_hello=split_hello) for ip in ips], desc
        return [DoHUpstream(url, verify=verify, bootstrap_ips=[], split_hello=split_hello)], desc
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

        try:
            while True:
                print("\n  1) Статус   2) Включить   3) Отключить   4) Проверить   5) Сохранить лог (.txt)   6) Выход")
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
                    save_log()
                elif cmd in ("6", "q", "й"):
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
        App().mainloop()
    except tk.TclError as e:
        print(f"✘ Не удалось открыть окно: {e}", file=sys.stderr)
        print("Похоже, рутовому GUI не достучаться до дисплея (частая история "
              "на Wayland).\nЗапустите терминальный режим:  sudo python3 main.py --cli",
              file=sys.stderr)
        sys.exit(1)
    finally:
        release_single_instance()
