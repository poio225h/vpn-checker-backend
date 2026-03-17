#!/usr/bin/env python3
"""
CHECKER v5  —  FAST / ALL / WHITE / BLACK  (лайтовый WHITE, удобные страны)

Главные отличия:
  - Больше ключей гоняется через WHITE-чек (MAX_WHITE_TEST = 400).
  - Ожидания от white_checker.py смягчены (он должен реже кидать ключи в BLACK).
  - Хвост имени ноды содержит стабильный country-name для удобной фильтрации в клиентах.
"""

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
from urllib.parse import quote, unquote
from concurrent.futures import ThreadPoolExecutor

# =============================================================================
# Настройки
# =============================================================================

BASE_DIR    = "checked"
FOLDER_RU   = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

if os.path.exists(FOLDER_RU):
    shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO):
    shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU,   exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

TIMEOUT    = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS    = 40

CACHE_HOURS       = 6
CHUNK_LIMIT       = 1000
EURO_CHUNK_LIMIT  = 500
MAX_KEYS_TO_CHECK = 30000

MAX_PING_MS      = 3000
FAST_LIMIT       = 3000
MAX_HISTORY_AGE  = 2 * 24 * 3600

# Максимум ключей, которые прогоняем через белый HTTP-чек (лайтовый режим)
MAX_WHITE_TEST = 400

RU_FILES = [
    "ru_white_part1.txt", "ru_white_part2.txt",
    "ru_white_part3.txt", "ru_white_part4.txt",
]
EURO_FILES = [
    "my_euro_part1.txt", "my_euro_part2.txt",
    "my_euro_part3.txt",
]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL   = "@vlesstrojan"

URLS_RU = [
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_VLESS_RUS_mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/BLACK_SS%2BAll_RUS.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile-2.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-all.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-checked.txt",
    "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-SNI-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://etoneya.a9fm.site/1",
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr",
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt",
]

EURO_CODES = {
    "NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ",
    "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE",
    "LU", "EE", "LV", "LT",
}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"]

RU_MARKERS_STRICT = [
    ".ru", "moscow", "msk", "spb", "saint-peter", "russia",
    "россия", "москва", "питер", "ru-", "-ru.",
    "178.154.", "77.88.", "5.255.", "87.250.",
    "95.108.", "213.180.", "195.208.",
    "91.108.", "149.154.",
]

WHITELIST_DOMAINS = [
    "alfabank.ru", "vtb.ru", "psbank.ru", "mts-bank.ru",
    "sberbank.ru", "tinkoff.ru", "raiffeisen.ru", "gazprombank.ru",
    "rshb.ru", "open.ru", "sovcombank.ru", "mkb.ru",
    "rosbank.ru", "uralsib.ru", "akbars.ru", "bspb.ru",
    "mironline.ru", "sbp.nspk.ru", "nspk.ru", "moex.com",
    "mir.ru", "qiwi.com", "yoomoney.ru", "payonline.ru",
    "vkusvill.ru", "auchan.ru", "magnit.ru", "dixy.ru",
    "spar.ru", "metro-cc.ru", "azbukavkusa.ru",
    "5ka.ru", "x5.ru", "perekrestok.ru",
    "lenta.com", "okmarket.ru", "globus.ru", "bristol.ru",
    "samokat.ru", "eda.yandex.ru", "lavka.yandex.ru",
    "delivery-club.ru", "sbermarket.ru", "vprok.ru",
    "sbermegamarket.ru", "market.yandex.ru",
    "wildberries.ru", "ozon.ru", "lamoda.ru", "mvideo.ru",
    "eldorado.ru", "citilink.ru", "dns-shop.ru",
    "avito.ru", "youla.ru",
    "vkusnoitochka.ru", "burgerking.ru", "kfc.ru",
    "dodopizza.ru", "papajohns.ru",
    "petrovich.ru", "leroymerlin.ru", "obi.ru",
    "detmir.ru",
    "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru",
    "rostelecom.ru", "dom.ru",
    "gosuslugi.ru", "mos.ru", "nalog.ru", "pfr.gov.ru",
    "cbr.ru", "minfin.ru", "egov.ru",
    "zdravcity.ru", "apteka.ru", "eapteka.ru",
]

# =============================================================================
# Флаги + названия стран
# =============================================================================

COUNTRY_NAMES = {
    "RU": "Russia",
    "NL": "Netherlands",
    "DE": "Germany",
    "FI": "Finland",
    "GB": "United Kingdom",
    "FR": "France",
    "SE": "Sweden",
    "PL": "Poland",
    "CZ": "Czechia",
    "AT": "Austria",
    "CH": "Switzerland",
    "IT": "Italy",
    "ES": "Spain",
    "NO": "Norway",
    "DK": "Denmark",
    "BE": "Belgium",
    "IE": "Ireland",
    "LU": "Luxembourg",
    "EE": "Estonia",
    "LV": "Latvia",
    "LT": "Lithuania",
    "US": "United States",
    "UA": "Ukraine",
    "BY": "Belarus",
    "KZ": "Kazakhstan",
    "TR": "Turkey",
    "JP": "Japan",
    "SG": "Singapore",
    "HK": "Hong Kong",
    "CA": "Canada",
    "AU": "Australia",
    "NZ": "New Zealand",
}

def country_to_flag(country: str) -> str:
    flags = {
        "RU": "🇷🇺", "NL": "🇳🇱", "DE": "🇩🇪", "FI": "🇫🇮",
        "GB": "🇬🇧", "FR": "🇫🇷", "SE": "🇸🇪", "PL": "🇵🇱",
        "CZ": "🇨🇿", "AT": "🇦🇹", "CH": "🇨🇭", "IT": "🇮🇹",
        "ES": "🇪🇸", "NO": "🇳🇴", "DK": "🇩🇰", "BE": "🇧🇪",
        "IE": "🇮🇪", "LU": "🇱🇺", "EE": "🇪🇪", "LV": "🇱🇻",
        "LT": "🇱🇹", "US": "🇺🇸", "UA": "🇺🇦", "BY": "🇧🇾",
        "KZ": "🇰🇿", "TR": "🇹🇷", "JP": "🇯🇵", "SG": "🇸🇬",
        "HK": "🇭🇰", "CA": "🇨🇦", "AU": "🇦🇺", "NZ": "🇳🇿",
    }
    return flags.get(country.upper(), "🏳️")

def country_to_name(country: str) -> str:
    return COUNTRY_NAMES.get(country.upper(), "Unknown")

# =============================================================================
# Фильтры
# =============================================================================

def is_russian_exit(key_str: str, host: str, country: str) -> bool:
    if country == "RU":
        return True
    host_lower = host.lower()
    key_upper  = key_str.upper()
    if host_lower.endswith(".ru"):
        return True
    for marker in RU_MARKERS_STRICT:
        if marker.lower() in host_lower:
            return True
        if marker.upper() in key_upper:
            return True
    return False

def is_garbage_text(key_str: str) -> bool:
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper:
            return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str:
        return True
    return False

# =============================================================================
# JSON-кеш
# =============================================================================

def load_json(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_json(path: str, data: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

# =============================================================================
# Определение страны по хосту / имени ключа
# =============================================================================

def get_country_fast(host: str, key_name: str) -> str:
    try:
        h = host.lower()
        n = key_name.upper()
        if h.endswith(".ru"):                         return "RU"
        if h.endswith(".de"):                         return "DE"
        if h.endswith(".nl"):                         return "NL"
        if h.endswith(".uk") or h.endswith(".co.uk"): return "GB"
        if h.endswith(".fr"):                         return "FR"
        if h.endswith(".fi"):                         return "FI"
        if h.endswith(".se"):                         return "SE"
        if h.endswith(".no"):                         return "NO"
        if h.endswith(".dk"):                         return "DK"
        if h.endswith(".pl"):                         return "PL"
        if h.endswith(".cz"):                         return "CZ"
        if h.endswith(".at"):                         return "AT"
        if h.endswith(".ch"):                         return "CH"
        if h.endswith(".it"):                         return "IT"
        if h.endswith(".es"):                         return "ES"
        if h.endswith(".be"):                         return "BE"
        if h.endswith(".ie"):                         return "IE"
        if h.endswith(".lu"):                         return "LU"
        if h.endswith(".ee"):                         return "EE"
        if h.endswith(".lv"):                         return "LV"
        if h.endswith(".lt"):                         return "LT"
        for code in EURO_CODES:
            if code in n:
                return code
    except Exception:
        pass
    return "UNKNOWN"

# =============================================================================
# Загрузка ключей
# =============================================================================

def fetch_keys(urls: list, tag: str) -> list:
    out = []
    print(f"📥 Загрузка {tag}...")
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
            added = 0
            for line in lines:
                line = line.strip()
                if len(line) > 2000:
                    continue
                if line.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY" and is_garbage_text(line):
                        continue
                    out.append((line, tag))
                    added += 1
            print(f"  {url.split('/')[-1][:60]}: +{added}")
        except Exception as e:
            print(f"  ⚠️  Ошибка загрузки {url[:60]}: {e}")
    return out

# =============================================================================
# TCP/TLS/WS проверка одного ключа
# =============================================================================

def check_single_key(data: tuple):
    key, tag = data
    try:
        if "@" not in key or ":" not in key:
            return None, None, None, None

        part = key.split("@")[1].split("?")[0].split("#")[0]
        host_port = part.rsplit(":", 1)
        if len(host_port) != 2:
            return None, None, None, None
        host, port = host_port[0].strip("[]"), int(host_port[1])

        country = get_country_fast(host, key)

        if tag == "MY" and country == "RU":
            return None, None, None, None

        is_tls = (
            "security=tls" in key
            or "security=reality" in key
            or key.startswith("trojan://")
            or key.startswith("vmess://")
        )
        is_ws = "type=ws" in key or "net=ws" in key

        path = "/"
        m = re.search(r"path=([^&]+)", key)
        if m:
            path = unquote(m.group(1))

        start = time.time()

        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                sockopt=((socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT),),
            )
            ws.close()
        elif is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT):
                pass

        latency = int((time.time() - start) * 1000)
        return latency, tag, country, host

    except Exception:
        return None, None, None, None

# =============================================================================
# Финальный ключ: k_id + хвост с пингом, флагом, страной, названием, каналом
# =============================================================================

def make_final_key(k_id: str, latency: int, country: str) -> str:
    flag      = country_to_flag(country)
    cname     = country_to_name(country)
    # Вид хвоста: [12ms 🇩🇪 DE Germany @vlesstrojan]
    info_str  = f"[{latency}ms {flag} {country} {cname} {MY_CHANNEL}]"
    return f"{k_id}#{quote(info_str, safe='')}"

def extract_ping(key_str: str):
    try:
        label = unquote(key_str).split("#")[-1]
        m = re.search(r"(\d+)ms", label)
        return int(m.group(1)) if m else None
    except Exception:
        return None

# =============================================================================
# Сохранение файлов
# =============================================================================

def save_exact(keys: list, folder: str, filename: str) -> str:
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(k for k in keys if k and k.strip()))
    return path

def save_fixed_chunks_ru(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + CHUNK_LIMIT] for i in range(0, min(len(valid), CHUNK_LIMIT * 4), CHUNK_LIMIT)]
    while len(chunks) < 4:
        chunks.append([])
    for i, fname in enumerate(RU_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return RU_FILES

def save_fixed_chunks_euro(keys_list: list, folder: str) -> list:
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + EURO_CHUNK_LIMIT]
              for i in range(0, min(len(valid), EURO_CHUNK_LIMIT * 3), EURO_CHUNK_LIMIT)]
    while len(chunks) < 3:
        chunks.append([])
    for i, fname in enumerate(EURO_FILES):
        chunk = chunks[i] if i < len(chunks) else []
        save_exact(chunk, folder, fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return EURO_FILES

def save_chunked(keys_list: list, folder: str, base_name: str, chunk_size: int = None) -> list:
    if chunk_size is None:
        chunk_size = CHUNK_LIMIT
    valid = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid[i:i + chunk_size] for i in range(0, len(valid), chunk_size)]
    names = []
    for idx, chunk in enumerate(chunks, start=1):
        fname = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, fname)
        names.append(fname)
        print(f"  {fname}: {len(chunk)} ключей")
    return names

# =============================================================================
# Генерация subscriptions_list.txt
# =============================================================================

def generate_subscriptions_list() -> str:
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH   = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"

    lines = []

    lines += ["=== 🇷🇺 RUSSIA (FAST) ==="]
    lines += [f"{BASE_RAW}/checked/RU_Best/{f}" for f in RU_FILES]
    lines += [""]

    lines += ["=== 🇪🇺 EUROPE (FAST) ==="]
    lines += [f"{BASE_RAW}/checked/My_Euro/{f}" for f in EURO_FILES]
    lines += [""]

    lines += ["=== 🇷🇺 RUSSIA (ALL) ==="]
    ru_all = sorted(
        f for f in os.listdir(FOLDER_RU)
        if f.startswith("ru_white_all_part") and f.endswith(".txt")
    )
    lines += [f"{BASE_RAW}/checked/RU_Best/{f}" for f in ru_all[:2]]
    lines += [""]

    lines += ["=== 🇪🇺 EUROPE (ALL) ==="]
    eu_all = sorted(
        f for f in os.listdir(FOLDER_EURO)
        if f.startswith("my_euro_all_part") and f.endswith(".txt")
    )
    lines += [f"{BASE_RAW}/checked/My_Euro/{f}" for f in eu_all[:2]]
    lines += [""]

    lines += ["=== ✅ WHITE RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/checked/RU_Best/ru_white_all_WHITE.txt", ""]

    lines += ["=== ✅ WHITE EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/checked/My_Euro/my_euro_all_WHITE.txt", ""]

    lines += ["=== ⚠️ BLACK RUSSIA (ALL) ==="]
    lines += [f"{BASE_RAW}/checked/RU_Best/ru_white_all_BLACK.txt", ""]

    lines += ["=== ⚠️ BLACK EUROPE (ALL) ==="]
    lines += [f"{BASE_RAW}/checked/My_Euro/my_euro_all_BLACK.txt"]

    path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    http_count = sum(1 for l in lines if l.startswith("http"))
    print(f"\n📋 subscriptions_list.txt: {http_count} ссылок")
    for l in lines:
        if l:
            print(f"  {l}")
    return path

# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print("=" * 55)
    print("  CHECKER v5  —  FAST / ALL / WHITE / BLACK")
    print("=" * 55)
    print(
        f"Параметры: CACHE={CACHE_HOURS}h  MAX_PING={MAX_PING_MS}ms  "
        f"FAST={FAST_LIMIT}  HISTORY={MAX_HISTORY_AGE // 3600}h  "
        f"WHITE_TEST={MAX_WHITE_TEST}"
    )

    # Импорт white_checker
    try:
        from white_checker import batch_white_check, xray_available
        if xray_available():
            WHITE_CHECK_AVAILABLE = True
            print("✅ white_checker.py + xray найдены — WHITE/BLACK чек активен")
        else:
            WHITE_CHECK_AVAILABLE = False
            print("⚠️  xray не найден — WHITE/BLACK чек пропущен (все ключи → WHITE)")
    except ImportError:
        WHITE_CHECK_AVAILABLE = False
        print("⚠️  white_checker.py не найден — WHITE/BLACK чек пропущен (все ключи → WHITE)")

    # 1. Загрузка ключей
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")

    unique_tasks: dict = {}
    for k, tag in tasks:
        k_id = k.split("#")[0]
        if k_id not in unique_tasks:
            unique_tasks[k_id] = (k, tag)
    all_items = list(unique_tasks.values())

    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]

    print(f"\n📊 Уникальных ключей: {len(all_items)}")

    # 2. Кеш
    history = load_json(HISTORY_FILE)
    current_time = time.time()
    to_check: list = []
    res_ru:   list = []
    res_euro: list = []

    for k, tag in all_items:
        k_id   = k.split("#")[0]
        cached = history.get(k_id)

        if cached and (current_time - cached["time"] < CACHE_HOURS * 3600) and cached["alive"]:
            latency  = cached["latency"]
            country  = cached.get("country", "UNKNOWN")
            host     = cached.get("host", "")
            final    = make_final_key(k_id, latency, country)

            if tag == "RU":
                res_ru.append(final)
            elif tag == "MY" and not is_russian_exit(k, host, country):
                res_euro.append(final)
        else:
            to_check.append((k, tag))

    print(f"✅ Из кеша: RU={len(res_ru)}  EURO={len(res_euro)}")
    print(f"🔍 На проверку: {len(to_check)}")

    # 3. Параллельная TCP/TLS/WS-проверка
    if to_check:
        checked_count = 0
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {
                executor.submit(check_single_key, item): item
                for item in to_check
            }
            for future in future_to_item:
                key, tag = future_to_item[future]
                res = future.result()
                if not res or res[0] is None:
                    continue

                latency, _, country, host = res
                k_id = key.split("#")[0]

                history[k_id] = {
                    "alive":   True,
                    "latency": latency,
                    "time":    time.time(),
                    "country": country,
                    "host":    host,
                    "white":      history.get(k_id, {}).get("white"),
                    "white_time": history.get(k_id, {}).get("white_time", 0),
                }

                final = make_final_key(k_id, latency, country)

                if tag == "RU":
                    res_ru.append(final)
                elif tag == "MY" and not is_russian_exit(key, host, country):
                    res_euro.append(final)

                checked_count += 1

        print(f"✅ Успешно проверено: {checked_count}")

    # 4. Очистка истории
    save_json(HISTORY_FILE, {
        k: v for k, v in history.items()
        if current_time - v["time"] < MAX_HISTORY_AGE
    })
    history = load_json(HISTORY_FILE)

    # 5. Фильтрация по пингу + сортировка
    res_ru_clean   = [k for k in res_ru   if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]
    res_euro_clean = [k for k in res_euro if extract_ping(k) is not None and extract_ping(k) <= MAX_PING_MS]

    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)

    print(f"\n📈 После фильтрации (≤{MAX_PING_MS}ms):")
    print(f"  RU:   {len(res_ru_clean)}")
    print(f"  EURO: {len(res_euro_clean)}")

    # 6. FAST / ALL
    res_ru_fast   = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]
    res_ru_all    = res_ru_clean
    res_euro_all  = res_euro_clean

    print(f"\n🚀 FAST (топ {FAST_LIMIT}):")
    print(f"  RU FAST:   {len(res_ru_fast)}")
    print(f"  EURO FAST: {len(res_euro_fast)}")

    # 7. Сохранение FAST
    print(f"\n💾 RU FAST → {FOLDER_RU}:")
    save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)

    print(f"\n💾 EURO FAST → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT}):")
    save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)

    # 7b. WHITE / BLACK split (лайтовый)
    print(f"\n🔬 WHITE / BLACK сплит (лимит {MAX_WHITE_TEST} ключей на направление):")

    if WHITE_CHECK_AVAILABLE:
        ru_to_test   = res_ru_all[:MAX_WHITE_TEST]
        ru_untested  = res_ru_all[MAX_WHITE_TEST:]

        ru_white, ru_black = batch_white_check(
            ru_to_test, history, label="RU"
        )
        ru_black.extend(ru_untested)
        if ru_untested:
            print(f"  [RU] Непроверенных → BLACK: {len(ru_untested)}")
        print(f"  [RU] Итог: WHITE={len(ru_white)}  BLACK={len(ru_black)}")

        euro_to_test  = res_euro_all[:MAX_WHITE_TEST]
        euro_untested = res_euro_all[MAX_WHITE_TEST:]

        euro_white, euro_black = batch_white_check(
            euro_to_test, history, label="EURO"
        )
        euro_black.extend(euro_untested)
        if euro_untested:
            print(f"  [EURO] Непроверенных → BLACK: {len(euro_untested)}")
        print(f"  [EURO] Итог: WHITE={len(euro_white)}  BLACK={len(euro_black)}")

        save_json(HISTORY_FILE, {
            k: v for k, v in history.items()
            if current_time - v["time"] < MAX_HISTORY_AGE
        })

    else:
        ru_white,   ru_black   = list(res_ru_all),   []
        euro_white, euro_black = list(res_euro_all), []
        print("  ⚠️  xray недоступен — все ключи → WHITE, BLACK пустой")

    # 8. Сохранение ALL
    print(f"\n💾 RU ALL → {FOLDER_RU}:")
    save_chunked(res_ru_all, FOLDER_RU, "ru_white_all")

    print(f"\n💾 EURO ALL → {FOLDER_EURO} (по {EURO_CHUNK_LIMIT}):")
    save_chunked(res_euro_all, FOLDER_EURO, "my_euro_all", chunk_size=EURO_CHUNK_LIMIT)

    # 8b. Сохранение WHITE / BLACK
    print(f"\n💾 WHITE/BLACK → {FOLDER_RU}:")
    save_exact(ru_white, FOLDER_RU, "ru_white_all_WHITE.txt")
    save_exact(ru_black, FOLDER_RU, "ru_white_all_BLACK.txt")
    print(f"  ru_white_all_WHITE.txt: {len(ru_white)}")
    print(f"  ru_white_all_BLACK.txt: {len(ru_black)}")

    print(f"\n💾 WHITE/BLACK → {FOLDER_EURO}:")
    save_exact(euro_white, FOLDER_EURO, "my_euro_all_WHITE.txt")
    save_exact(euro_black, FOLDER_EURO, "my_euro_all_BLACK.txt")
    print(f"  my_euro_all_WHITE.txt: {len(euro_white)}")
    print(f"  my_euro_all_BLACK.txt: {len(euro_black)}")

    # 9. subscriptions_list.txt
    generate_subscriptions_list()

    # Итог
    print("\n" + "=" * 55)
    print("  ✅  SUCCESS")
    print("=" * 55)
    print(f"  RU  FAST  : {len(res_ru_fast)}")
    print(f"  RU  ALL   : {len(res_ru_all)}")
    print(f"  RU  WHITE : {len(ru_white)}")
    print(f"  RU  BLACK : {len(ru_black)}")
    print(f"  EU  FAST  : {len(res_euro_fast)}")
    print(f"  EU  ALL   : {len(res_euro_all)}")
    print(f"  EU  WHITE : {len(euro_white)}")
    print(f"  EU  BLACK : {len(euro_black)}")
    print("=" * 55)































































































































































































































































