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

import ctypes
import http.client
import json
import os
import queue
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox

APP_NAME = "SecureDNS"
APP_VERSION = "1.1.0"
IS_WINDOWS = sys.platform.startswith("win")
SPAWN_KW = {"creationflags": 0x08000000} if IS_WINDOWS else {}
LOCAL_DNS = "127.0.0.1"
if IS_WINDOWS:
    BACKUP_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "SecureDNS")
else:
    BACKUP_DIR = "/etc/securedns"
BACKUP_FILE = os.path.join(BACKUP_DIR, "backup.json")
CONFIG_FILE = os.path.join(BACKUP_DIR, "config.json")

# ---------------------------------------------------------------------------
# Вспомогательное
# ---------------------------------------------------------------------------

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
    p = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", full],
        capture_output=True, timeout=timeout, **SPAWN_KW,
    )
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def run_cmd(args, timeout: int = 30):
    """Запуск внешней команды (Linux)."""
    p = subprocess.run(args, capture_output=True, timeout=timeout, **SPAWN_KW)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


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


def set_dns_servers(adapter, servers):
    """Назначить DNS адаптеру. Возвращает (ok, ошибка)."""
    if IS_WINDOWS:
        rc, _, err = run_ps(
            "Set-DnsClientServerAddress -InterfaceIndex {} -ServerAddresses ({})".format(
                adapter, ",".join('"%s"' % s for s in servers))
        )
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
        shutil.copy2("/etc/resolv.conf", "/etc/resolv.conf.securedns.bak")
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
        flush_dns_cache()
        return
    tool = _linux_dns_tool()
    if tool in ("resolvectl", "systemd-resolve"):
        run_cmd([tool, "flush-caches"])


def adapter_key(a):
    """Идентификатор адаптера для DNS-операций: ifindex (Windows) или имя (Linux)."""
    return a["index"] if IS_WINDOWS else a["name"]


def save_backup(if_index: int, servers):
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        data = {}
        if os.path.exists(BACKUP_FILE):
            with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        data[str(if_index)] = {"servers": servers}
        with open(BACKUP_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def load_backup(if_index: int):
    try:
        with open(BACKUP_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get(str(if_index), {}).get("servers", [])
    except (OSError, json.JSONDecodeError):
        return []


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


class DoTUpstream:
    """DNS-over-TLS (RFC 7858): TLS-соединение на порт 853, кадрирование 2 байта длины."""

    def __init__(self, ip: str, port: int = 853, verify: bool = False,
                 hostname: str | None = None, timeout: float = 6.0):
        self.ip, self.port, self.timeout = ip, port, timeout
        self.hostname = hostname
        self.verify = verify
        self._ctx = make_ssl_context(verify, hostname)
        self._sock = None
        self._lock = threading.Lock()

    def _connect(self):
        raw = socket.create_connection((self.ip, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        sni = self.hostname or (self.ip if self.verify else None)
        return self._ctx.wrap_socket(raw, server_hostname=sni)

    @staticmethod
    def _recv_exact(s, n):
        buf = b""
        while len(buf) < n:
            chunk = s.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("соединение закрыто")
            buf += chunk
        return buf

    def query(self, packet: bytes) -> bytes:
        with self._lock:
            last_err = None
            for _ in range(2):  # одна попытка переподключения
                try:
                    if self._sock is None:
                        self._sock = self._connect()
                    s = self._sock
                    s.sendall(struct.pack("!H", len(packet)) + packet)
                    ln = struct.unpack("!H", self._recv_exact(s, 2))[0]
                    return self._recv_exact(s, ln)
                except Exception as e:  # noqa: BLE001
                    last_err = e
                    try:
                        self._sock.close()
                    except Exception:  # noqa: BLE001
                        pass
                    self._sock = None
            raise IOError(f"DoT {self.ip}: {last_err}")

    def close(self):
        try:
            if self._sock:
                self._sock.close()
        except Exception:  # noqa: BLE001
            pass
        self._sock = None


class DoHUpstream:
    """DNS-over-HTTPS (RFC 8484): POST application/dns-message на указанный URL.

    Решает «проблему курицы и яйца»: после переключения системного DNS на
    локальный прокси резолвить имя DoH-сервера уже некому. Поэтому коннектимся
    на заранее известный IP (bootstrap_ip или зарезолвленный до переключения),
    а домен отправляем в TLS SNI и HTTP-заголовке Host — nginx поймёт маршрут.
    """

    def __init__(self, url: str, verify: bool = True,
                 bootstrap_ip: str | None = None, timeout: float = 6.0):
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
        self._ctx = make_ssl_context(verify, self.host)
        self._ips = [bootstrap_ip] if bootstrap_ip else []
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

    def query(self, packet: bytes) -> bytes:
        if not self._ips:
            self._resolve()
        last = None
        for ip in self._ips or [self.host]:
            try:
                return self._query_via(ip, packet)
            except Exception as e:  # noqa: BLE001
                last = e
        self._resolve()  # вдруг адрес сменился
        raise IOError(f"DoH {self.host}: {last}")

    def _query_via(self, ip: str, packet: bytes) -> bytes:
        raw = socket.create_connection((ip, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        sock = self._ctx.wrap_socket(raw, server_hostname=self.host)
        # HTTPConnection с готовым TLS-сокетом: Host-заголовок = домен
        conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        conn.sock = sock
        try:
            conn.request("POST", self.path, body=packet, headers={
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
            })
            resp = conn.getresponse()
            if resp.status != 200:
                raise IOError(f"DoH {self.host}: HTTP {resp.status}")
            return resp.read()
        finally:
            conn.close()

    def close(self):
        pass


# ---------------------------------------------------------------------------
# Локальный DNS-прокси (UDP + TCP на 127.0.0.1:53)
# ---------------------------------------------------------------------------

class LocalDNSProxy:
    def __init__(self, upstreams, on_log=None):
        self.upstreams = upstreams          # список DoTUpstream/DoHUpstream
        self.on_log = on_log or (lambda m: None)
        self._stop = threading.Event()
        self._threads = []
        self._udp = None
        self._tcp = None

    def start(self):
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((LOCAL_DNS, 53))
        self._udp.settimeout(1.0)

        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind((LOCAL_DNS, 53))
        self._tcp.listen(16)
        self._tcp.settimeout(1.0)

        for target in (self._udp_loop, self._tcp_loop):
            t = threading.Thread(target=target, daemon=True)
            t.start()
            self._threads.append(t)

    def _forward(self, packet: bytes) -> bytes:
        last = None
        for up in self.upstreams:
            try:
                return up.query(packet)
            except Exception as e:  # noqa: BLE001
                last = e
                self.on_log(f"   ✘ {e}")
        raise IOError(f"все апстримы недоступны ({last})")

    def _udp_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self._udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_udp, args=(data, addr),
                             daemon=True).start()

    def _handle_udp(self, data, addr):
        try:
            resp = self._forward(data)
            self._udp.sendto(resp, addr)
        except Exception as e:  # noqa: BLE001
            self.on_log(f"   ✘ UDP-запрос не обслужен: {e}")

    def _tcp_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_tcp, args=(conn,),
                             daemon=True).start()

    def _handle_tcp(self, conn):
        try:
            conn.settimeout(8)
            ln = struct.unpack("!H", DoTUpstream._recv_exact(conn, 2))[0]
            data = DoTUpstream._recv_exact(conn, ln)
            resp = self._forward(data)
            conn.sendall(struct.pack("!H", len(resp)) + resp)
        except Exception as e:  # noqa: BLE001
            self.on_log(f"   ✘ TCP-запрос не обслужен: {e}")
        finally:
            conn.close()

    def stop(self):
        self._stop.set()
        for s in (self._udp, self._tcp):
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        for up in self.upstreams:
            up.close()


# ---------------------------------------------------------------------------
# Тестовый DNS-запрос (собираем пакет вручную, без внешних библиотек)
# ---------------------------------------------------------------------------

def build_dns_query(name: str, qtype: int = 1) -> bytes:
    tid = os.urandom(2)
    flags = b"\x01\x00"  # RD=1
    counts = struct.pack("!HHH", 1, 0, 0) + struct.pack("!H", 0)
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return tid + flags + counts + qname + struct.pack("!HH", qtype, 1)


def _skip_name(packet: bytes, i: int) -> int:
    """Пропустить DNS-имя: метки до нулевого байта либо сжатый указатель (0xC0)."""
    while True:
        b = packet[i]
        if b == 0:
            return i + 1
        if b & 0xC0 == 0xC0:
            return i + 2
        i += 1 + b


def parse_answers(packet: bytes):
    answers = []
    try:
        ancount = struct.unpack("!H", packet[6:8])[0]
        i = _skip_name(packet, 12) + 4  # имя вопроса + qtype + qclass
        for _ in range(ancount):
            i = _skip_name(packet, i)
            _type, _cls, _ttl, rdlen = struct.unpack("!HHIH", packet[i:i + 10])
            i += 10
            rdata = packet[i:i + rdlen]
            if _type == 1 and rdlen == 4:
                answers.append(".".join(str(b) for b in rdata))
            i += rdlen
    except Exception:  # noqa: BLE001
        pass
    return answers


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

BG, PANEL, FG, MUTED = "#1b1e24", "#242832", "#e6e8ec", "#9aa3b2"
ACCENT, GREEN, RED = "#3d8bfd", "#2ecc71", "#e74c3c"


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} — шифрованный DNS (DoT/DoH)")
        self.geometry("700x700")
        self.minsize(660, 660)
        self.configure(bg=BG)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.adapters = []
        self.proxy = None
        self.active_adapter = None
        self.q = queue.Queue()
        self._build_ui()
        self._load_config()
        self._poll_queue()
        self.after(100, self.refresh_status)
        self.after(600, self._startup_rollback)

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
        style.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=FG)
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
        style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                        insertcolor=FG, borderwidth=1)
        self.option_add("*TCombobox*Listbox.background", PANEL)
        self.option_add("*TCombobox*Listbox.foreground", FG)

        header = ttk.Frame(self)
        header.pack(fill="x", padx=16, pady=(14, 6))
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
        ttk.Radiobutton(row, text="DoT — DNS-over-TLS, порт 853",
                        variable=self.var_proto, value="dot",
                        command=self._on_proto).pack(anchor="w", pady=(4, 0))
        ttk.Radiobutton(row, text="DoH — DNS-over-HTTPS, порт 443 (нужен URL шаблона)",
                        variable=self.var_proto, value="doh",
                        command=self._on_proto).pack(anchor="w")
        self.ent_doh = ttk.Entry(row)
        self.ent_doh.insert(0, "https://example.com/dns-query")

        # TLS-сертификат
        self.var_verify = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text="Проверять TLS-сертификат сервера "
                                  "(выключите для своих серверов по IP)",
                        variable=self.var_verify).pack(anchor="w", pady=(6, 0))

        # Кнопки
        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=16, pady=14)
        self.btn_on = ttk.Button(btns, text="Включить шифрованный DNS",
                                 style="Accent.TButton", command=self.on_enable)
        self.btn_on.pack(side="left")
        ttk.Button(btns, text="Отключить", command=self.on_disable).pack(side="left", padx=(10, 0))
        ttk.Button(btns, text="Проверить", command=self.on_test).pack(side="left", padx=(10, 0))
        ttk.Button(btns, text="Обновить", command=self.refresh_status).pack(side="right")

        # Лог
        self.txt_log = tk.Text(self, bg="#12141a", fg="#b8c0cc", insertbackground=FG,
                               font=("Consolas", 9), wrap="word", relief="flat",
                               state="disabled")
        self.txt_log.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        self.log(f"{APP_NAME} {APP_VERSION}. Впишите свои DNS-серверы, выберите протокол "
                 f"и нажмите «Включить». Весь DNS-поток пойдёт через 127.0.0.1 → TLS.")
        self._refresh_adapters()

    # ---------- утилиты UI ----------
    def log(self, msg: str):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", msg.rstrip() + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _thread_log(self, msg):
        self.q.put(("log", msg))

    def _run_async(self, fn):
        self.btn_on.configure(state="disabled")
        def wrapper():
            try:
                fn()
            except Exception as e:  # noqa: BLE001
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
                elif kind == "proxy":
                    self._apply_proxy_state(payload)
                elif kind == "done":
                    self.btn_on.configure(state="normal")
        except queue.Empty:
            pass
        self.after(80, self._poll_queue)

    def _on_proto(self):
        if self.var_proto.get() == "doh":
            self.ent_doh.pack(fill="x", pady=(4, 0))
            self.lbl_ips.config(text="IP DoH-сервера (рекомендуется — прямое подключение "
                                     "без DNS-резолва):")
            self.lbl_ips_hint.config(
                text="Домен из URL пойдёт в SNI/Host, коннект — напрямую на этот IP. "
                     "Если оставить пустым, домен резолвится заранее.")
        else:
            self.ent_doh.pack_forget()
            self.lbl_ips.config(text="Ваши DNS-серверы (IP через запятую — любые):")
            self.lbl_ips_hint.config(text="Порядок важен: при недоступности первого "
                                          "запросы уходят на следующий.")

    def _selected_adapter(self):
        i = self.cmb_adapter.current()
        return self.adapters[i] if 0 <= i < len(self.adapters) else None

    def _parse_ips(self):
        ips = [s.strip() for s in self.ent_ips.get().split(",") if s.strip()]
        for ip in ips:
            parts = ip.split(".")
            if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return None
        return ips

    def _build_upstreams(self):
        ips = self._parse_ips()
        if ips is None:
            messagebox.showerror(APP_NAME, "Впишите корректные IP-адреса через запятую,\n"
                                           "например: 9.9.9.9, 149.112.112.112")
            return None
        verify = self.var_verify.get()
        if self.var_proto.get() == "dot":
            if not ips:
                messagebox.showerror(APP_NAME, "Для DoT впишите хотя бы один IP сервера.")
                return None
            return [DoTUpstream(ip, 853, verify=verify) for ip in ips], \
                   f"DoT:853 → {', '.join(ips)}"
        url = self.ent_doh.get().strip()
        if not url.startswith("https://"):
            messagebox.showerror(APP_NAME, "DoH-шаблон должен начинаться с https://")
            return None
        bootstrap = ips[0] if ips else None
        desc = f"DoH → {url}" + (f" (через {bootstrap})" if bootstrap else "")
        return [DoHUpstream(url, verify=verify, bootstrap_ip=bootstrap)], desc

    # ---------- конфиг ----------
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
            if cfg.get("doh_url"):
                self.ent_doh.delete(0, "end")
                self.ent_doh.insert(0, cfg["doh_url"])
        except (OSError, json.JSONDecodeError):
            pass
        self._on_proto()

    def _save_config(self):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "ips": self.ent_ips.get().strip(),
                    "proto": self.var_proto.get(),
                    "verify": self.var_verify.get(),
                    "doh_url": self.ent_doh.get().strip(),
                }, f, ensure_ascii=False, indent=2)
        except OSError:
            pass

    # ---------- статус ----------
    def _refresh_adapters(self):
        self.adapters = get_adapters()
        names = [f"{a['name']}  —  {a['desc']}" for a in self.adapters]
        self.cmb_adapter["values"] = names
        if names and self.cmb_adapter.current() < 0:
            self.cmb_adapter.current(0)

    def refresh_status(self):
        def work():
            self._refresh_adapters()
            a = self._selected_adapter()
            dns = get_dns_servers(adapter_key(a)) if a else []
            self.q.put(("status", (a, dns)))
            self.q.put(("proxy", None))
        threading.Thread(target=work, daemon=True).start()

    def _apply_status(self, adapter, dns):
        if adapter:
            self.lbl_adapter.config(
                text=f"Адаптер: {adapter['name']} — {adapter['desc']}")
        else:
            self.lbl_adapter.config(text="Адаптер: не выбран")
        if dns == [LOCAL_DNS]:
            self.lbl_dns.config(text="DNS адаптера: 127.0.0.1 (через SecureDNS ✔)",
                                foreground=GREEN)
        else:
            self.lbl_dns.config(
                text="DNS адаптера: " + (", ".join(dns) if dns else "автоматически (DHCP)"),
                foreground=MUTED)

    def _apply_proxy_state(self, _):
        if self.proxy:
            self.lbl_proxy.config(text="Прокси: работает на 127.0.0.1:53 ✔",
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
        built = self._build_upstreams()
        if not built:
            return
        upstreams, desc = built
        self._save_config()

        def work():
            self.q.put(("log", f"▶ Включаю шифрованный DNS ({desc}) на «{a['name']}»…"))
            # 0. Сначала проверяем, что апстрим реально отвечает
            test = build_dns_query("example.com")
            try:
                resp = upstreams[0].query(test)
                ips = parse_answers(resp)
                self.q.put(("log", f"   ✔ Апстрим отвечает: example.com → "
                                   f"{', '.join(ips) or 'ответ получен'}"))
            except Exception as e:  # noqa: BLE001
                self.q.put(("log", f"   ✘ Апстрим НЕ отвечает: {e}"))
                self.q.put(("log", "   Проверьте IP, протокол и галочку проверки "
                                   "сертификата. Настройки НЕ применены."))
                return
            # 1. Бэкап текущих DNS
            old = get_dns_servers(adapter_key(a))
            save_backup(adapter_key(a), old)
            self.q.put(("log", f"   Резервная копия DNS: {old or 'авто (DHCP)'}"))
            # 2. Стоп старого прокси, старт нового
            if self.proxy:
                self.proxy.stop()
            self.proxy = LocalDNSProxy(upstreams, on_log=self._thread_log)
            try:
                self.proxy.start()
            except OSError as e:
                self.q.put(("log", f"   ✘ Не удалось занять 127.0.0.1:53 — {e}"))
                self.proxy = None
                return
            self.active_adapter = a
            self.q.put(("proxy", None))
            self.q.put(("log", "   ✔ Локальный прокси слушает 127.0.0.1:53"))
            # 3. Назначаем системный DNS
            ok, err = set_dns_servers(adapter_key(a), [LOCAL_DNS])
            if not ok:
                self.q.put(("log", f"   ✘ Ошибка смены DNS адаптера: {err}"))
                return
            flush_dns_cache()
            self.q.put(("log", "   DNS адаптера → 127.0.0.1, кэш очищен."))
            self.q.put(("log", "✔ Готово! Весь DNS-трафик шифруется. "
                               "Нажмите «Проверить»."))
            self.q.put(("status", (a, get_dns_servers(adapter_key(a)))))
        self._run_async(work)

    def _restore_adapter_dns(self, if_index: int):
        """Вернуть DNS адаптера: из бэкапа, либо в DHCP. Возвращает описание."""
        backup = load_backup(if_index)
        if backup and backup != [LOCAL_DNS]:
            ok, err = set_dns_servers(if_index, backup)
            if ok:
                return True, f"восстановлены DNS: {', '.join(backup)}"
            # бэкап не применился — уходим в DHCP как безопасный вариант
            ok2, err2 = reset_dns_servers(if_index)
            return ok2, ("бэкап не применился, DNS возвращён в авто (DHCP)"
                         if ok2 else f"{err}; и DHCP не сработал: {err2}")
        ok, err = reset_dns_servers(if_index)
        return ok, ("DNS возвращён в авто (DHCP)" if ok else f"ошибка: {err}")

    def _startup_rollback(self):
        """Аварийный откат: если адаптер смотрит на 127.0.0.1, а прокси не запущен —
        значит программу закрыли/убили с активной защитой. Возвращаем настройки."""
        def work():
            for a in get_adapters():
                dns = get_dns_servers(adapter_key(a))
                if dns == [LOCAL_DNS]:
                    if not is_admin():
                        self.q.put(("log", f"⚠ Адаптер «{a['name']}» смотрит на 127.0.0.1, "
                                           f"но прокси не запущен. Для отката нужны права — "
                                           f"перезапустите программу: {admin_hint()}"))
                        continue
                    ok, msg = self._restore_adapter_dns(adapter_key(a))
                    flush_dns_cache()
                    self.q.put(("log", f"⚠ Обнаружен «зависший» DNS 127.0.0.1 на "
                                       f"«{a['name']}» (программа была закрыта с активной "
                                       f"защитой). Автооткат: {msg}"))
                    self.q.put(("status", (a, get_dns_servers(adapter_key(a)))))
        threading.Thread(target=work, daemon=True).start()

    def on_disable(self):
        if not is_admin():
            messagebox.showerror(APP_NAME, "Нужны права администратора.")
            return

        def work():
            a = self.active_adapter or self._selected_adapter()
            self.q.put(("log", "▶ Отключаю шифрованный DNS…"))
            if self.proxy:
                self.proxy.stop()
                self.proxy = None
                self.q.put(("proxy", None))
                self.q.put(("log", "   Локальный прокси остановлен."))
            if a:
                ok, msg = self._restore_adapter_dns(adapter_key(a))
                self.q.put(("log", f"   {msg}"))
                flush_dns_cache()
                # Проверяем, что откат реально применился
                current = get_dns_servers(adapter_key(a))
                if current == [LOCAL_DNS]:
                    # Последняя линия обороны — принудительный DHCP
                    ok2, _ = reset_dns_servers(adapter_key(a))
                    flush_dns_cache()
                    current = get_dns_servers(adapter_key(a))
                    self.q.put(("log", "   ⚠ DNS всё ещё был 127.0.0.1 — принудительно "
                                       f"переведён в DHCP: {'успешно' if ok2 else 'не удалось'}"))
                if current == [LOCAL_DNS]:
                    self.q.put(("log", "   ✘ Не удалось убрать 127.0.0.1! Откройте "
                                       "свойства адаптера и выберите "
                                       "«Получить адрес DNS-сервера автоматически»."))
                else:
                    self.q.put(("log", f"   ✔ Откат подтверждён, текущие DNS: "
                                       f"{', '.join(current) or 'авто (DHCP)'}"))
                self.q.put(("status", (a, current)))
            self.q.put(("log", "✔ Отключено, обычный интернет работает как раньше."))
        self._run_async(work)

    def on_test(self):
        def work():
            self.q.put(("log", "▶ Проверка…"))
            if self.proxy:
                # Спрашиваем напрямую наш локальный прокси
                try:
                    q = build_dns_query("example.com")
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(8)
                    s.sendto(q, (LOCAL_DNS, 53))
                    resp, _ = s.recvfrom(4096)
                    s.close()
                    ips = parse_answers(resp)
                    self.q.put(("log", f"   127.0.0.1:53 → example.com = "
                                       f"{', '.join(ips) or 'ответ без A-записей'}"))
                    self.q.put(("log", "✔ Шифрованный канал работает: запрос ушёл "
                                       "по TLS на ваш сервер и вернулся с ответом."))
                except Exception as e:  # noqa: BLE001
                    self.q.put(("log", f"   ✘ Прокси не ответил: {e}"))
            else:
                # Прокси не запущен — просто проверим апстрим без смены настроек
                built = self._build_upstreams()
                if not built:
                    return
                upstreams, desc = built
                self.q.put(("log", f"   Прокси не запущен. Проверяю апстрим ({desc})…"))
                try:
                    resp = upstreams[0].query(build_dns_query("example.com"))
                    ips = parse_answers(resp)
                    self.q.put(("log", f"   ✔ Апстрим отвечает: example.com → "
                                       f"{', '.join(ips) or 'ответ получен'}"))
                    self.q.put(("log", "   Сервер рабочий — можно нажимать «Включить»."))
                except Exception as e:  # noqa: BLE001
                    self.q.put(("log", f"   ✘ Апстрим не отвечает: {e}"))
        self._run_async(work)

    def on_close(self):
        if self.proxy and self.active_adapter:
            if messagebox.askyesno(
                    APP_NAME,
                    "Сейчас DNS адаптера направлен на программу (127.0.0.1).\n"
                    "Если просто закрыть — интернет перестанет резолвиться.\n\n"
                    "Отключить шифрованный DNS и вернуть настройки?"):
                self.on_disable()
                self.after(6000, self.destroy)
                return
        if self.proxy:
            self.proxy.stop()
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
