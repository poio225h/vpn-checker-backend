#!/usr/bin/env python3

import os
import re
import socket
import ssl
import time
import json
import requests
import base64
import websocket
import shutil
import threading
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

# ================== НАСТРОЙКИ ==================

BASE_DIR = "checked"
FOLDER_ALL = os.path.join(BASE_DIR, "ALL")

# Чистим и создаём выходную папку
if os.path.exists(FOLDER_ALL):
    shutil.rmtree(FOLDER_ALL)
os.makedirs(FOLDER_ALL, exist_ok=True)

TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40

CACHE_HOURS = 6
CHUNK_LIMIT = 1000
MAX_KEYS_TO_CHECK = 30000

MAX_PING_MS = 3000
FAST_LIMIT = 30000        # по сути, лимит «ALL», можно поднять/опустить
MAX_HISTORY_AGE = 2 * 24 * 3600

# Кэш IP → страна
IP_CACHE_FILE = os.path.join(BASE_DIR, "ip_cache.json")
IP_CACHE_MAX_AGE_DAYS = 30

# ip-api лимит
GEO_API_RATE_LIMIT = 38
GEO_API_WINDOW = 60.0

# Единственный источник — весь пул без geo-фильтра
URLS_ALL = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/clean_nofilter/all_nofilter.txt",
]

MY_CHANNEL = "@vlesstrojan"

# ================== GEO-API + КЭШ ==================

_disk_ip_cache: dict = {}

def load_ip_cache():
    global _disk_ip_cache
    if os.path.exists(IP_CACHE_FILE):
        try:
            with open(IP_CACHE_FILE, "r", encoding="utf-8") as f:
                _disk_ip_cache = json.load(f)
        except Exception:
            _disk_ip_cache = {}
    cutoff = time.time() - IP_CACHE_MAX_AGE_DAYS * 86400
    _disk_ip_cache = {k: v for k, v in _disk_ip_cache.items() if v.get("time", 0) > cutoff}

def save_ip_cache():
    os.makedirs(BASE_DIR, exist_ok=True)
    try:
        with open(IP_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_disk_ip_cache, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

_ip_cache_lock = threading.Lock()
_host_to_ip: dict = {}
_host_ip_lock = threading.Lock()

def resolve_host(host: str) -> str | None:
    with _host_ip_lock:
        if host in _host_to_ip:
            return _host_to_ip[host]
    try:
        ip = socket.gethostbyname(host)
        with _host_ip_lock:
            _host_to_ip[host] = ip
        return ip
    except Exception:
        with _host_ip_lock:
            _host_to_ip[host] = None
        return None

_geo_rate_lock = threading.Lock()
_geo_request_times: list = []
_ip_api_disabled = False

_geo_stats = defaultdict(int)
_geo_stats_lock = threading.Lock()

def _inc_geo_stat(key: str):
    with _geo_stats_lock:
        _geo_stats[key] += 1

def _geo_api_wait_slot() -> bool:
    global _ip_api_disabled
    if _ip_api_disabled:
        return False
    with _geo_rate_lock:
        now = time.time()
        cutoff = now - GEO_API_WINDOW
        while _geo_request_times and _geo_request_times[0] < cutoff:
            _geo_request_times.pop(0)
        if len(_geo_request_times) >= GEO_API_RATE_LIMIT:
            sleep_time = GEO_API_WINDOW - (now - _geo_request_times[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)
            now = time.time()
            cutoff = now - GEO_API_WINDOW
            while _geo_request_times and _geo_request_times[0] < cutoff:
                _geo_request_times.pop(0)
        _geo_request_times.append(time.time())
    return True

def detect_exit_country_via_http(proxy_host: str) -> str:
    global _ip_api_disabled

    ip = resolve_host(proxy_host)
    if not ip:
        return "UNKNOWN"

    with _ip_cache_lock:
        cached = _disk_ip_cache.get(ip)
    if cached:
        _inc_geo_stat("cache")
        return cached["country"]

    if _ip_api_disabled:
        return "UNKNOWN"

    if not _geo_api_wait_slot():
        return "UNKNOWN"

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=countryCode",
            timeout=4
        )
        if r.status_code == 429:
            _ip_api_disabled = True
            print("⚠️  ip-api вернул 429 (rate limit) — geo-API отключён до конца запуска")
            return "UNKNOWN"
        if r.status_code == 200:
            code = r.json().get("countryCode", "UNKNOWN") or "UNKNOWN"
            with _ip_cache_lock:
                _disk_ip_cache[ip] = {"country": code, "time": time.time()}
            _inc_geo_stat("api")
            return code
    except Exception:
        pass

    return "UNKNOWN"

# ================== ЗАГРУЗКА КЛЮЧЕЙ ==================

def fetch_keys(urls):
    out = []
    print("Загрузка ALL...")
    for url in urls:
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            r = requests.get(url, timeout=10)
            if r.status_code != 200:
                continue
            content = r.text.strip()
            if "://" not in content:
                try:
                    lines = base64.b64decode(content + "==").decode("utf-8", errors="ignore").splitlines()
                except Exception:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()
            for l in lines:
                l = l.strip()
                if len(l) > 2000:
                    continue
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    out.append(l)
        except Exception:
            pass
    return out

# ================== ПРОВЕРКА ОДНОГО КЛЮЧА ==================

ERR_TIMEOUT = "timeout"
ERR_TLS = "tls"
ERR_DNS = "dns"
ERR_OTHER = "other"

_err_stats = defaultdict(int)
_err_stats_lock = threading.Lock()

def _inc_err(kind: str):
    with _err_stats_lock:
        _err_stats[kind] += 1

def check_single_key(key: str):
    try:
        if "@" not in key or ":" not in key:
            return None, None, None, key, ERR_OTHER

        part = key.split("@")[1].split("?")[0].split("#")[0]
        host_port = part.split(":")
        host = host_port[0]
        port = int(host_port[1])
    except Exception:
        return None, None, None, key, ERR_OTHER

    is_tls = (
        "security=tls" in key or
        "security=reality" in key or
        "trojan://" in key or
        "vmess://" in key
    )
    is_ws = "type=ws" in key or "net=ws" in key
    path = "/"
    match = re.search(r"path=([^&]+)", key)
    if match:
        path = unquote(match.group(1))

    start = time.time()

    try:
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

    except socket.timeout:
        _inc_err(ERR_TIMEOUT)
        return None, None, None, key, ERR_TIMEOUT
    except ssl.SSLError:
        _inc_err(ERR_TLS)
        return None, None, None, key, ERR_TLS
    except socket.gaierror:
        _inc_err(ERR_DNS)
        return None, None, None, key, ERR_DNS
    except OSError as e:
        msg = str(e).lower()
        if "timed out" in msg or "timeout" in msg:
            _inc_err(ERR_TIMEOUT)
            return None, None, None, key, ERR_TIMEOUT
        _inc_err(ERR_OTHER)
        return None, None, None, key, ERR_OTHER
    except Exception:
        _inc_err(ERR_OTHER)
        return None, None, None, key, ERR_OTHER

    latency = int((time.time() - start) * 1000)

    country_exit = detect_exit_country_via_http(host)

    return latency, country_exit, host, key, None

# ================== ФОРМАТ И СОХРАНЕНИЕ ==================

def make_final_key(k_id, latency, country):
    # Подписываем только ping и страну, без RU/EURO деления
    info_str = f"[{latency}ms {country or 'UNKNOWN'} {MY_CHANNEL}]"
    return f"{k_id}#{info_str}"

def extract_ping(key_str):
    try:
        label = key_str.split("#")[-1]
        match = re.search(r"(\d+)ms", label)
        if match:
            return int(match.group(1))
        return None
    except Exception:
        return None

def save_exact(keys, folder, filename):
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(keys) if keys else "")
    return path

def save_chunked_all(keys_list, folder, base_name="ALL_all", chunk_size=None):
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid_keys[i:i + chunk_size] for i in range(0, len(valid_keys), chunk_size)]
    file_names = []
    for idx, chunk in enumerate(chunks, start=1):
        filename = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, filename)
        file_names.append(filename)
        print(f"  {filename}: {len(chunk)} ключей")
    return file_names

# ================== JSON-КЭШ И SUBS ==================

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def generate_subscriptions_list(all_files):
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"

    subs_lines = []
    subs_lines.append("=== 🌍 ALL (ALL) ===")
    for filename in all_files:
        subs_lines.append(f"{BASE_RAW}/checked/ALL/{filename}")
    subs_lines.append("")

    subs_path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(subs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    http_count = sum(1 for l in subs_lines if l.startswith("http"))
    print(f"\n📋 subscriptions_list.txt создан ({http_count} ссылок):")
    for line in subs_lines:
        if line:
            print(f"  {line}")

    return subs_path

# ================== MAIN ==================

if __name__ == "__main__":
    print("=== CHECKER v2 (ALL from all_nofilter + GEO-CACHE) ===")
    print(f"Параметры: CACHE={CACHE_HOURS}h, MAX_PING={MAX_PING_MS}ms, FAST={FAST_LIMIT}, HISTORY={MAX_HISTORY_AGE // 3600}h")

    load_ip_cache()
    print(f"📂 Дисковый ip_cache загружен: {len(_disk_ip_cache)} записей")

    HISTORY_FILE = os.path.join(BASE_DIR, "history_all.json")
    history = load_json(HISTORY_FILE)

    tasks_raw = fetch_keys(URLS_ALL)
    unique_keys = list(dict.fromkeys(tasks_raw))  # preserve order, dedup
    if len(unique_keys) > MAX_KEYS_TO_CHECK:
        unique_keys = unique_keys[:MAX_KEYS_TO_CHECK]

    current_time = time.time()
    to_check = []
    result_all = []
    dead_all = []

    print(f"\n📊 Всего уникальных ключей: {len(unique_keys)}")

    for k in unique_keys:
        k_id = k.split("#")[0]
        cached = history.get(k_id)

        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached["alive"]:
            latency = cached["latency"]
            country = cached.get("country", "UNKNOWN")
            final = make_final_key(k_id, latency, country)
            result_all.append(final)
        else:
            to_check.append(k)

    print(f"✅ Из кэша: {len(result_all)}")
    print(f"🔍 На проверку: {len(to_check)}")

    if to_check:
        checked_ok = 0

        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_map = {executor.submit(check_single_key, key): key for key in to_check}

            for future in as_completed(future_map):
                original_key = future_map[future]
                try:
                    latency, country, host, _, err_type = future.result()
                except Exception:
                    dead_all.append(original_key)
                    continue

                if latency is None:
                    dead_all.append(original_key)
                    continue

                k_id = original_key.split("#")[0]
                history[k_id] = {
                    "alive": True,
                    "latency": latency,
                    "time": time.time(),
                    "country": country,
                    "host": host,
                }

                final = make_final_key(k_id, latency, country)
                result_all.append(final)
                checked_ok += 1

        print(f"✅ Проверено успешно: {checked_ok}")

    save_ip_cache()
    print(f"💾 ip_cache сохранён: {len(_disk_ip_cache)} записей")

    save_json(
        HISTORY_FILE,
        {k: v for k, v in history.items() if current_time - v["time"] < MAX_HISTORY_AGE}
    )

    result_clean = [k for k in result_all if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    result_clean.sort(key=extract_ping)

    print(f"\n📈 После фильтрации (≤ {MAX_PING_MS} ms) и сортировки:")
    print(f"  ALL: {len(result_clean)} ключей")

    result_fast = result_clean[:FAST_LIMIT]
    print(f"\n🚀 FAST слой (топ {FAST_LIMIT}): {len(result_fast)}")

    print(f"\n💾 Сохранение ALL (чанки по {CHUNK_LIMIT}) → {FOLDER_ALL}:")
    all_files = save_chunked_all(result_clean, FOLDER_ALL, base_name="ALL_all", chunk_size=CHUNK_LIMIT)

    generate_subscriptions_list(all_files)

    print("\n" + "=" * 55)
    print("📊 ФИНАЛЬНЫЙ ОТЧЁТ")
    print("=" * 55)

    print(f"\n✅ Результат:")
    print(f"  ALL: {len(result_clean)}, DEAD: {len(dead_all)}")

    print(f"\n🌍 Гео-статистика:")
    with _geo_stats_lock:
        stats = dict(_geo_stats)
    total_geo = sum(stats.values()) or 1
    for src in ("api", "cache", "fast", "unknown"):
        n = stats.get(src, 0)
        print(f"  {src:8s}: {n:5d}  ({n * 100 // total_geo}%)")
    if _ip_api_disabled:
        print("  ⚠️  ip-api был отключён из-за 429 в процессе работы")

    print(f"\n❌ Ошибки соединения:")
    with _err_stats_lock:
        estats = dict(_err_stats)
    total_err = sum(estats.values()) or 1
    for kind in (ERR_TIMEOUT, ERR_TLS, ERR_DNS, ERR_OTHER):
        n = estats.get(kind, 0)
        print(f"  {kind:8s}: {n:5d}  ({n * 100 // total_err}%)")

    print("\n✅ SUCCESS: ALL CHUNKS + subscriptions_list GENERATED")
