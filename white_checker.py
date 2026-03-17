"""
white_checker.py  —  реальная проверка «белого списка» через xray.

Алгоритм для одного ключа:
  1. Парсим vpn_uri → xray outbound-объект (vless/vmess/trojan/ss).
  2. Генерируем временный JSON-конфиг xray с SOCKS5-прокси на свободном порту.
  3. Запускаем xray run как subprocess.
  4. Вместо фиксированного sleep — активно опрашиваем порт (socket.connect_ex)
     до реального поднятия SOCKS5 (или до XRAY_STARTUP_TIMEOUT).
  5. Делаем HTTPS-запросы к WHITE_TEST_DOMAINS через socks5h-прокси.
  6. Если >= WHITE_THRESHOLD доменов ответили любым HTTP-кодом — WHITE, иначе BLACK.
  7. В finally: гарантированно kill xray + удаляем временный конфиг.

Улучшения по сравнению с первой версией:
  - Активный опрос порта вместо time.sleep  → на быстрых серверах экономит 1-2 с.
  - Ограниченный параллелизм через ThreadPoolExecutor + Semaphore (WHITE_WORKERS):
    при 200 ключах и 5 воркерах время сокращается в ~5 раз.
  - Кеш белого статуса: результат сохраняется в history dict и повторно
    не проверяется в течение WHITE_CACHE_HOURS часов.
  - xray_available() — публичная функция для быстрой проверки наличия бинарника.
  - Поддержка транспортов: tcp, ws, grpc, h2, httpupgrade для всех протоколов.
  - Graceful shutdown: сначала terminate → wait(3) → kill.
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from base64 import b64decode
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Semaphore
from typing import Optional
from urllib.parse import unquote, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# Публичные константы / конфигурация
# =============================================================================

# Якорные домены РФ белого списка (банк, платёжная система, ритейл)
WHITE_TEST_DOMAINS = ["alfabank.ru", "mironline.ru", "vkusvill.ru"]

# Сколько доменов должны ответить, чтобы ключ считался WHITE
WHITE_THRESHOLD = 2

# Максимальный таймаут на один HTTP-запрос через прокси (с)
HTTP_TIMEOUT = 5

# Максимальное время ожидания старта xray (активный опрос порта)
XRAY_STARTUP_TIMEOUT = 5.0

# Интервал опроса порта при ожидании старта xray (с)
XRAY_POLL_INTERVAL = 0.15

# Общий таймаут на одну белую проверку (старт xray + HTTP-запросы)
WHITE_CHECK_TIMEOUT = 22.0

# Параллельных xray-процессов одновременно (не перегружаем CPU/сеть)
WHITE_WORKERS = 5

# Через сколько часов перечеченять белый статус уже проверенного ключа
WHITE_CACHE_HOURS = 24

# Путь к бинарнику: ENV > рядом со скриптом > PATH
XRAY_BIN = os.environ.get(
    "XRAY_BIN",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "xray"),
)

# =============================================================================
# Внутренний глобальный семафор (ограничивает параллелизм)
# =============================================================================
_sem = Semaphore(WHITE_WORKERS)


# =============================================================================
# Утилиты
# =============================================================================

def xray_available() -> bool:
    """Возвращает True, если бинарник xray найден и исполняем."""
    return _xray_binary() is not None


def _xray_binary() -> Optional[str]:
    """Ищет бинарник xray: ENV-переменная → рядом со скриптом → PATH."""
    if os.path.isfile(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK):
        return XRAY_BIN
    base = os.path.dirname(os.path.abspath(__file__))
    for name in ("xray", "xray-linux-64", "xray-linux-arm64", "xray.exe"):
        cand = os.path.join(base, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("xray")


def _free_port() -> int:
    """Находит свободный TCP-порт на 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float) -> bool:
    """
    Активно опрашивает 127.0.0.1:port каждые XRAY_POLL_INTERVAL секунд.
    Возвращает True, когда порт принимает соединения, или False по таймауту.
    Гораздо надёжнее и быстрее, чем фиксированный time.sleep.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(XRAY_POLL_INTERVAL)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(XRAY_POLL_INTERVAL)
    return False


# =============================================================================
# Парсинг URI → xray outbound
# =============================================================================

def _p(params: dict, key: str, default: str = "") -> str:
    """Получает первое значение из parse_qs-словаря."""
    return params.get(key, [default])[0]


def _stream_settings(params: dict, net: str, security: str, host: str) -> dict:
    """
    Универсальный строитель streamSettings для любого протокола.
    Поддерживает: tcp, ws, grpc, h2, httpupgrade.
    Поддерживает security: none, tls, reality.
    """
    sni      = _p(params, "sni", host)
    fp       = _p(params, "fp", "chrome")
    pbk      = _p(params, "pbk", "")
    sid      = _p(params, "sid", "")
    path     = unquote(_p(params, "path", "/"))
    h_header = unquote(_p(params, "host", host))
    alpn_raw = _p(params, "alpn", "")

    ss: dict = {"network": net}

    # Безопасность
    if security == "tls":
        tls_cfg: dict = {
            "allowInsecure": True,
            "serverName": sni,
            "fingerprint": fp or "chrome",
        }
        if alpn_raw:
            tls_cfg["alpn"] = [a.strip() for a in alpn_raw.split(",") if a.strip()]
        ss["security"] = "tls"
        ss["tlsSettings"] = tls_cfg
    elif security == "reality":
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid,
        }
    else:
        ss["security"] = "none"

    # Транспорт
    if net == "ws":
        ss["wsSettings"] = {"path": path, "headers": {"Host": h_header}}
    elif net == "grpc":
        ss["grpcSettings"] = {
            "serviceName": _p(params, "serviceName", ""),
            "multiMode": False,
        }
    elif net == "h2":
        ss["httpSettings"] = {
            "path": path,
            "host": [h_header] if h_header else [],
        }
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": h_header}

    return ss


def _parse_vless(uri: str) -> Optional[dict]:
    try:
        body = uri[len("vless://"):]
        user_id, rest = body.split("@", 1)
        # Хост может содержать IPv6 в квадратных скобках
        host_port_qs, *_ = rest.split("?", 1) + [""]
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host_port = rest.split("?")[0]
        # rsplit по ":" безопасен для IPv6 [::1]:port
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "none")
        net      = _p(params, "type", "tcp")
        flow     = _p(params, "flow", "")

        ss = _stream_settings(params, net, security, host)

        user: dict = {"id": user_id, "encryption": "none"}
        if flow:
            user["flow"] = flow

        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_trojan(uri: str) -> Optional[dict]:
    try:
        body = uri[len("trojan://"):]
        password, rest = body.split("@", 1)
        password = unquote(password)
        qs = rest.split("?", 1)[1] if "?" in rest else ""
        qs = qs.split("#")[0]
        host_port = rest.split("?")[0]
        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        params = parse_qs(qs)

        security = _p(params, "security", "tls")
        net      = _p(params, "type", "tcp")

        ss = _stream_settings(params, net, security, host)

        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_vmess(uri: str) -> Optional[dict]:
    try:
        enc = uri[len("vmess://"):]
        enc += "=" * (-len(enc) % 4)
        data = json.loads(b64decode(enc).decode("utf-8", errors="ignore"))

        host    = str(data.get("add", ""))
        port    = int(data.get("port", 443))
        uid     = str(data.get("id", ""))
        aid     = int(data.get("aid", 0))
        net     = str(data.get("net", "tcp"))
        tls     = str(data.get("tls", ""))
        sni     = str(data.get("sni", host))
        path    = str(data.get("path", "/"))
        h_host  = str(data.get("host", host))
        fp      = str(data.get("fp", "chrome"))
        alpn    = str(data.get("alpn", ""))

        ss: dict = {"network": net}
        if tls == "tls":
            tls_cfg: dict = {
                "allowInsecure": True,
                "serverName": sni,
                "fingerprint": fp or "chrome",
            }
            if alpn:
                tls_cfg["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
            ss["security"] = "tls"
            ss["tlsSettings"] = tls_cfg
        else:
            ss["security"] = "none"

        if net == "ws":
            ss["wsSettings"] = {"path": path, "headers": {"Host": h_host}}
        elif net == "grpc":
            ss["grpcSettings"] = {"serviceName": path, "multiMode": False}
        elif net == "h2":
            ss["httpSettings"] = {"path": path, "host": [h_host] if h_host else []}

        return {
            "protocol": "vmess",
            "settings": {"vnext": [{
                "address": host,
                "port": port,
                "users": [{"id": uid, "alterId": aid, "security": "auto"}],
            }]},
            "streamSettings": ss,
        }
    except Exception:
        return None


def _parse_ss(uri: str) -> Optional[dict]:
    """
    Поддерживает два формата ShadowSocks URI:
      ss://BASE64(method:pass)@host:port
      ss://BASE64(method:pass@host:port)
    Параметр ?plugin= игнорируется (xray v2fly не поддерживает плагины через эту схему).
    """
    try:
        body = uri[len("ss://"):]
        body = body.split("#")[0].split("?")[0]  # убираем имя и плагин

        if "@" in body:
            cred_part, host_port = body.rsplit("@", 1)
            # cred_part может быть base64 или plaintext
            try:
                pad = cred_part + "=" * (-len(cred_part) % 4)
                decoded_cred = b64decode(pad).decode("utf-8")
                if ":" in decoded_cred:
                    method, password = decoded_cred.split(":", 1)
                else:
                    method, password = cred_part, ""
            except Exception:
                if ":" in cred_part:
                    method, password = cred_part.split(":", 1)
                else:
                    return None
        else:
            # Весь URI — base64
            pad = body + "=" * (-len(body) % 4)
            decoded = b64decode(pad).decode("utf-8")
            if "@" not in decoded:
                return None
            cred_part, host_port = decoded.rsplit("@", 1)
            if ":" not in cred_part:
                return None
            method, password = cred_part.split(":", 1)

        host, port_s = host_port.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)

        return {
            "protocol": "shadowsocks",
            "settings": {"servers": [{
                "address": host,
                "port": port,
                "method": method,
                "password": password,
                "uot": False,
            }]},
            "streamSettings": {"network": "tcp", "security": "none"},
        }
    except Exception:
        return None


def _build_outbound(vpn_uri: str) -> Optional[dict]:
    uri = vpn_uri.split("#")[0].strip()
    if uri.startswith("vless://"):   return _parse_vless(uri)
    if uri.startswith("trojan://"):  return _parse_trojan(uri)
    if uri.startswith("vmess://"):   return _parse_vmess(uri)
    if uri.startswith("ss://"):      return _parse_ss(uri)
    return None


def _build_xray_config(outbound: dict, socks_port: int) -> dict:
    """Минимальный xray-конфиг: SOCKS5-прокси → один VPN-outbound."""
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
            "sniffing": {"enabled": False},
        }],
        "outbounds": [
            {**outbound, "tag": "proxy"},
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {}, "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                # Весь трафик через VPN
                {"type": "field", "outboundTag": "proxy", "port": "0-65535"},
            ],
        },
    }


# =============================================================================
# Основные функции
# =============================================================================

def is_white_key(vpn_uri: str, timeout: float = WHITE_CHECK_TIMEOUT) -> bool:
    """
    Проверяет, является ли vpn_uri «белым» ключом.

    Алгоритм:
      1. Парсим URI → xray outbound.
      2. Запускаем xray с SOCKS5-прокси на свободном порту.
      3. Активно ждём, пока порт начнёт принимать соединения.
      4. Делаем HTTPS-запросы к WHITE_TEST_DOMAINS через socks5h.
      5. WHITE, если >= WHITE_THRESHOLD доменов ответили (любой HTTP-код).

    Returns:
        True  — WHITE
        False — BLACK / ошибка / xray не найден
    """
    with _sem:  # ограничиваем параллелизм глобальным семафором
        return _check_one(vpn_uri, timeout)


def _check_one(vpn_uri: str, timeout: float) -> bool:
    xray_bin = _xray_binary()
    if not xray_bin:
        return False

    outbound = _build_outbound(vpn_uri)
    if outbound is None:
        return False

    socks_port = _free_port()
    config = _build_xray_config(outbound, socks_port)

    proc: Optional[subprocess.Popen] = None
    tmp_cfg: Optional[str] = None
    t_start = time.monotonic()

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(config, tf)
            tmp_cfg = tf.name

        proc = subprocess.Popen(
            [xray_bin, "run", "-config", tmp_cfg],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Активный опрос: ждём, пока SOCKS5 реально начнёт слушать порт
        if not _wait_for_port(socks_port, XRAY_STARTUP_TIMEOUT):
            return False  # xray не поднялся за отведённое время

        # xray мог упасть сразу после bind (краш)
        if proc.poll() is not None:
            return False

        elapsed = time.monotonic() - t_start
        remaining = max(1.0, timeout - elapsed)
        per_req = min(HTTP_TIMEOUT, max(2.0, remaining / len(WHITE_TEST_DOMAINS)))

        proxies = {
            "http":  f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,*/*",
        }

        success = 0
        for domain in WHITE_TEST_DOMAINS:
            # Прерываемся, если уже не хватает времени
            if time.monotonic() - t_start > timeout - 1:
                break
            try:
                resp = requests.get(
                    f"https://{domain}/",
                    proxies=proxies,
                    timeout=per_req,
                    allow_redirects=True,
                    verify=False,
                    headers=headers,
                )
                # Любой HTTP-ответ означает сетевую доступность сервера
                if resp.status_code < 600:
                    success += 1
            except requests.exceptions.ProxyError:
                # SOCKS5 прокси отклонил — xray упал или не смог подключиться
                pass
            except Exception:
                pass

        return success >= WHITE_THRESHOLD

    except Exception:
        return False

    finally:
        _kill_proc(proc)
        _rm_file(tmp_cfg)


def _kill_proc(proc: Optional[subprocess.Popen]) -> None:
    """Graceful shutdown: terminate → wait(3с) → kill."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
    except Exception:
        pass


def _rm_file(path: Optional[str]) -> None:
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except Exception:
            pass


# =============================================================================
# Пакетная проверка с прогрессом и кешем
# =============================================================================

def batch_white_check(
    keys: list,
    history: dict,
    *,
    workers: int = WHITE_WORKERS,
    cache_hours: float = WHITE_CACHE_HOURS,
    label: str = "",
) -> tuple[list, list]:
    """
    Пакетная WHITE/BLACK проверка списка ключей.

    Параметры:
      keys        — список финальных ключей (с хвостом #...), уже отсортированы по пингу
      history     — словарь кеша из history.json (читается и обновляется on-the-fly)
      workers     — параллельных xray-процессов (по умолчанию WHITE_WORKERS)
      cache_hours — сколько часов кешировать результат (по умолчанию WHITE_CACHE_HOURS)
      label       — метка для вывода прогресса ("RU" / "EURO")

    Возвращает:
      (white_keys, black_keys) — два списка финальных ключей
    """
    now = time.time()
    white_keys: list = []
    black_keys: list = []

    # Разбиваем на кешированные и требующие проверки
    cached_white, cached_black, to_test = [], [], []
    for k in keys:
        k_id = k.split("#")[0]
        h = history.get(k_id, {})
        w = h.get("white")
        w_time = h.get("white_time", 0)
        if w is not None and (now - w_time) < cache_hours * 3600:
            (cached_white if w else cached_black).append(k)
        else:
            to_test.append(k)

    if cached_white or cached_black:
        print(f"  [{label}] Из кеша белого статуса: WHITE={len(cached_white)} BLACK={len(cached_black)}")

    white_keys.extend(cached_white)
    black_keys.extend(cached_black)

    if not to_test:
        return white_keys, black_keys

    print(f"  [{label}] Белый чек: {len(to_test)} ключей | воркеры={workers} | таймаут={WHITE_CHECK_TIMEOUT}с")

    completed = 0
    total = len(to_test)

    # Ограничиваем параллелизм: workers воркеров одновременно
    # Семафор _sem уже ограничивает на уровне is_white_key,
    # но ThreadPoolExecutor тоже ставим = workers для экономии памяти
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_key = {
            executor.submit(is_white_key, k.split("#")[0]): k
            for k in to_test
        }
        for future in as_completed(future_to_key):
            k = future_to_key[future]
            k_id = k.split("#")[0]
            try:
                result = future.result()
            except Exception:
                result = False

            # Обновляем кеш
            if k_id in history:
                history[k_id]["white"] = result
                history[k_id]["white_time"] = time.time()

            if result:
                white_keys.append(k)
            else:
                black_keys.append(k)

            completed += 1
            if completed % 10 == 0 or completed == total:
                pct = completed * 100 // total
                print(
                    f"  [{label}] {completed}/{total} ({pct}%) "
                    f"WHITE={len(white_keys)} BLACK={len(black_keys)}"
                )

    return white_keys, black_keys
