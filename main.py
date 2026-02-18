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

# ------------------ Настройки ------------------
BASE_DIR = "checked"
FOLDER_RU = os.path.join(BASE_DIR, "RU_Best")
FOLDER_EURO = os.path.join(BASE_DIR, "My_Euro")

# Чистим папки перед стартом
if os.path.exists(FOLDER_RU): shutil.rmtree(FOLDER_RU)
if os.path.exists(FOLDER_EURO): shutil.rmtree(FOLDER_EURO)
os.makedirs(FOLDER_RU, exist_ok=True)
os.makedirs(FOLDER_EURO, exist_ok=True)

# Основные параметры
TIMEOUT = 5
socket.setdefaulttimeout(TIMEOUT)
THREADS = 40

CACHE_HOURS = 6              # было 12
CHUNK_LIMIT = 1000
MAX_KEYS_TO_CHECK = 30000    # было 15000

MAX_PING_MS = 3000           # мягкий потолок пинга
FAST_LIMIT = 3000            # сколько ключей идёт в fast‑слой
MAX_HISTORY_AGE = 2 * 24 * 3600  # 2 дня

# Фиксированные имена файлов для префильтра
RU_FILES = ["ru_white_part1.txt", "ru_white_part2.txt", "ru_white_part3.txt", "ru_white_part4.txt"]
EURO_FILES = ["my_euro_part1.txt", "my_euro_part2.txt", "my_euro_part3.txt"]

HISTORY_FILE = os.path.join(BASE_DIR, "history.json")
MY_CHANNEL = "@vlesstrojan"

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
    "https://s3c3.001.gpucloud.ru/vahe4xkwi/cjdr"
]

URLS_MY = [
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/githubmirror/new/all_new.txt"
]

EURO_CODES = {"NL", "DE", "FI", "GB", "FR", "SE", "PL", "CZ", "AT", "CH", "IT", "ES", "NO", "DK", "BE", "IE", "LU", "EE", "LV", "LT"}
BAD_MARKERS = ["CN", "IR", "KR", "BR", "IN", "RELAY", "POOL", "🇨🇳", "🇮🇷", "🇰🇷"]

# ------------------ Функции ------------------

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except: pass
    return {}

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except: pass

def get_country_fast(host, key_name):
    try:
        host = host.lower()
        name = key_name.upper()
        if host.endswith(".ru"): return "RU"
        if host.endswith(".de"): return "DE"
        if host.endswith(".nl"): return "NL"
        if host.endswith(".uk") or host.endswith(".co.uk"): return "GB"
        if host.endswith(".fr"): return "FR"
        for code in EURO_CODES:
            if code in name: return code
    except: pass
    return "UNKNOWN"

def is_garbage_text(key_str):
    upper = key_str.upper()
    for m in BAD_MARKERS:
        if m in upper: return True
    if ".ir" in key_str or ".cn" in key_str or "127.0.0.1" in key_str: return True
    return False

def fetch_keys(urls, tag):
    out = []
    print(f"Загрузка {tag}...")
    for url in urls:
        try:
            if "github.com" in url and "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            
            r = requests.get(url, timeout=10)
            if r.status_code != 200: continue
            content = r.text.strip()
            
            if "://" not in content:
                try:
                    lines = base64.b64decode(content + "==").decode('utf-8', errors='ignore').splitlines()
                except:
                    lines = content.splitlines()
            else:
                lines = content.splitlines()
            
            for l in lines:
                l = l.strip()
                if len(l) > 2000: continue
                if l.startswith(("vless://", "vmess://", "trojan://", "ss://")):
                    if tag == "MY" and is_garbage_text(l):
                        continue
                    out.append((l, tag))
        except: pass
    return out

def check_single_key(data):
    key, tag = data
    try:
        if "@" in key and ":" in key:
            part = key.split("@")[1].split("?")[0].split("#")[0]
            host, port = part.split(":")[0], int(part.split(":")[1])
        else:
            return None, None, None

        country = get_country_fast(host, key)
        
        if tag == "MY" and country == "RU":
            return None, None, None

        is_tls = 'security=tls' in key or 'security=reality' in key or 'trojan://' in key or 'vmess://' in key
        is_ws = 'type=ws' in key or 'net=ws' in key
        path = "/"
        match = re.search(r'path=([^&]+)', key)
        if match: path = unquote(match.group(1))

        start = time.time()
        
        if is_ws:
            protocol = "wss" if is_tls else "ws"
            ws_url = f"{protocol}://{host}:{port}{path}"
            ws = websocket.create_connection(
                ws_url,
                timeout=TIMEOUT,
                sslopt={"cert_reqs": ssl.CERT_NONE},
                sockopt=((socket.SOL_SOCKET, socket.SO_RCVTIMEO, TIMEOUT),)
            )
            ws.close()
        elif is_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=host): pass
        else:
            with socket.create_connection((host, port), timeout=TIMEOUT): pass
            
        latency = int((time.time() - start) * 1000)
        return latency, tag, country
    except:
        return None, None, None

def make_final_key(k_id, latency, country):
    """Создает ключ с правильно закодированной меткой для Hiddify"""
    info_str = f"[{latency}ms {country} {MY_CHANNEL}]"
    label_encoded = quote(info_str, safe='')
    return f"{k_id}#{label_encoded}"

def extract_ping(key_str):
    """Извлекает пинг из метки ключа"""
    try:
        decoded = unquote(key_str)
        label = decoded.split("#")[-1]
        match = re.search(r'(\d+)ms', label)
        if match:
            return int(match.group(1))
        return None
    except:
        return None

def save_exact(keys, folder, filename):
    """Сохраняет ключи в конкретный файл"""
    path = os.path.join(folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(keys) if keys else "")
    return path

def save_fixed_chunks_ru(keys_list, folder):
    """
    Сохраняет RU ключи в фиксированные 4 файла:
    - part1: первые 1000
    - part2: следующие 1000
    - part3: следующие 1000
    - part4: следующие 1000
    """
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    
    # Разбиваем на чанки по CHUNK_LIMIT
    chunks = [valid_keys[i:i + CHUNK_LIMIT] for i in range(0, min(len(valid_keys), CHUNK_LIMIT * 4), CHUNK_LIMIT)]
    
    # Дополняем пустыми списками если чанков меньше 4
    while len(chunks) < 4:
        chunks.append([])
    
    # Сохраняем в фиксированные файлы
    for i, filename in enumerate(RU_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
    
    return RU_FILES

def save_fixed_chunks_euro(keys_list, folder):
    """
    Сохраняет EURO ключи в фиксированные 3 файла:
    - part1: первые 1000
    - part2: следующие 1000
    - part3: следующие 1000
    """
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    
    # Разбиваем на чанки по CHUNK_LIMIT
    chunks = [valid_keys[i:i + CHUNK_LIMIT] for i in range(0, min(len(valid_keys), CHUNK_LIMIT * 3), CHUNK_LIMIT)]
    
    # Дополняем пустыми списками если чанков меньше 3
    while len(chunks) < 3:
        chunks.append([])
    
    # Сохраняем в фиксированные файлы
    for i, filename in enumerate(EURO_FILES):
        save_exact(chunks[i] if i < len(chunks) else [], folder, filename)
        count = len(chunks[i]) if i < len(chunks) else 0
        print(f"  {filename}: {count} ключей")
    
    return EURO_FILES

def save_chunked(keys_list, folder, base_name):
    """Режет список на чанки по CHUNK_LIMIT и сохраняет base_name_partN.txt."""
    valid_keys = [k.strip() for k in keys_list if k and k.strip()]
    chunks = [valid_keys[i:i + CHUNK_LIMIT] for i in range(0, len(valid_keys), CHUNK_LIMIT)]

    file_names = []
    for idx, chunk in enumerate(chunks, start=1):
        filename = f"{base_name}_part{idx}.txt"
        save_exact(chunk, folder, filename)
        file_names.append(filename)
        print(f"  {filename}: {len(chunk)} ключей")
    return file_names

def generate_subscriptions_list():
    """Генерирует subscriptions_list.txt с аккуратным набором ссылок."""
    GITHUB_USER_REPO = "kort0881/vpn-checker-backend"
    BRANCH = "main"
    BASE_RAW = f"https://raw.githubusercontent.com/{GITHUB_USER_REPO}/{BRANCH}"

    subs_lines = []

    # 🇷🇺 FAST — старые статичные файлы (их читает и префильтр, и постер)
    subs_lines.append("=== 🇷🇺 RUSSIA (FAST) ===")
    for filename in RU_FILES:
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{filename}")

    subs_lines.append("")

    # 🇷🇺 ALL — но ограничим количество ссылок, чтобы не было 20 кнопок
    subs_lines.append("=== 🇷🇺 RUSSIA (ALL) ===")
    ru_all_candidates = sorted(
        f for f in os.listdir(FOLDER_RU)
        if f.startswith("ru_white_all_part") and f.endswith(".txt")
    )
    # Показываем только первые 2 файла ALL
    for fname in ru_all_candidates[:2]:
        subs_lines.append(f"{BASE_RAW}/checked/RU_Best/{fname}")

    subs_lines.append("")

    # 🇪🇺 FAST — старые статичные файлы
    subs_lines.append("=== 🇪🇺 EUROPE (FAST) ===")
    for filename in EURO_FILES:
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{filename}")

    subs_lines.append("")

    # 🇪🇺 ALL — тоже ограничим до 2 ссылок
    subs_lines.append("=== 🇪🇺 EUROPE (ALL) ===")
    euro_all_candidates = sorted(
        f for f in os.listdir(FOLDER_EURO)
        if f.startswith("my_euro_all_part") and f.endswith(".txt")
    )
    for fname in euro_all_candidates[:2]:
        subs_lines.append(f"{BASE_RAW}/checked/My_Euro/{fname}")

    subs_path = os.path.join(BASE_DIR, "subscriptions_list.txt")
    with open(subs_path, "w", encoding="utf-8") as f:
        f.write("\n".join(subs_lines))

    print(f"\n📋 subscriptions_list.txt создан ({len([l for l in subs_lines if l.startswith('http')])} ссылок):")
    for line in subs_lines:
        if line:
            print(f"  {line}")

    return subs_path

# ------------------ MAIN ------------------

if __name__ == "__main__":
    print("=== CHECKER v5 (FAST/ALL LAYERS) ===")
    print(f"Параметры: CACHE={CACHE_HOURS}h, MAX_PING={MAX_PING_MS}ms, FAST={FAST_LIMIT}, HISTORY={MAX_HISTORY_AGE//3600}h")
    
    # 1. Загрузка истории и ключей
    history = load_json(HISTORY_FILE)
    tasks = fetch_keys(URLS_RU, "RU") + fetch_keys(URLS_MY, "MY")
    
    # Дедупликация
    unique_tasks = {k: tag for k, tag in tasks}
    all_items = list(unique_tasks.items())
    
    if len(all_items) > MAX_KEYS_TO_CHECK:
        all_items = all_items[:MAX_KEYS_TO_CHECK]
    
    current_time = time.time()
    to_check = []
    res_ru = []
    res_euro = []
    
    print(f"\n📊 Всего уникальных ключей: {len(all_items)}")

    # 2. Обработка кэша (новый CACHE_HOURS)
    for k, tag in all_items:
        k_id = k.split("#")[0]
        cached = history.get(k_id)
        
        if cached and (current_time - cached['time'] < CACHE_HOURS * 3600) and cached['alive']:
            latency = cached['latency']
            country = cached.get('country', 'UNKNOWN')
            final = make_final_key(k_id, latency, country)
            
            if tag == "RU":
                res_ru.append(final)
            elif tag == "MY" and country != "RU":
                res_euro.append(final)
        else:
            to_check.append((k, tag))

    print(f"✅ Из кэша: RU={len(res_ru)}, EURO={len(res_euro)}")
    print(f"🔍 На проверку: {len(to_check)}")

    # 3. Проверка новых ключей
    if to_check:
        checked_count = 0
        with ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_item = {executor.submit(check_single_key, item): item for item in to_check}
            
            for future in future_to_item:
                key, tag = future_to_item[future]
                res = future.result()
                
                if not res or res[0] is None:
                    continue
                
                latency, _, country = res
                k_id = key.split("#")[0]
                
                # ✅ ИСПРАВЛЕНИЕ: используем реальное время проверки, а не current_time
                history[k_id] = {
                    'alive': True,
                    'latency': latency,
                    'time': time.time(),  # вместо current_time
                    'country': country
                }
                
                final = make_final_key(k_id, latency, country)
                
                if tag == "RU":
                    res_ru.append(final)
                elif tag == "MY" and country != "RU":
                    res_euro.append(final)
                
                checked_count += 1
        
        print(f"✅ Проверено успешно: {checked_count}")

    # 4. Чистка истории (новый MAX_HISTORY_AGE)
    save_json(HISTORY_FILE, {
        k: v for k, v in history.items()
        if current_time - v['time'] < MAX_HISTORY_AGE
    })

    # 5. Фильтрация по пингу + сортировка
    res_ru_clean = []
    for k in res_ru:
        p = extract_ping(k)
        if p is not None and p <= MAX_PING_MS:
            res_ru_clean.append(k)

    res_euro_clean = []
    for k in res_euro:
        p = extract_ping(k)
        if p is not None and p <= MAX_PING_MS:
            res_euro_clean.append(k)

    res_ru_clean.sort(key=extract_ping)
    res_euro_clean.sort(key=extract_ping)

    print(f"\n📈 После фильтрации (≤ {MAX_PING_MS} ms) и сортировки:")
    print(f"  RU: {len(res_ru_clean)} ключей")
    print(f"  EURO: {len(res_euro_clean)} ключей")

    # 6. Формируем fast/all слои
    res_ru_fast = res_ru_clean[:FAST_LIMIT]
    res_euro_fast = res_euro_clean[:FAST_LIMIT]

    res_ru_all = res_ru_clean
    res_euro_all = res_euro_clean

    print(f"\n🚀 FAST слои (топ {FAST_LIMIT}):")
    print(f"  RU FAST: {len(res_ru_fast)}")
    print(f"  EURO FAST: {len(res_euro_fast)}")

    # 7. Сохранение фиксированных файлов (FAST для префильтра)
    print(f"\n💾 Сохранение RU FAST в фиксированные файлы {FOLDER_RU}:")
    save_fixed_chunks_ru(res_ru_fast, FOLDER_RU)

    print(f"\n💾 Сохранение EURO FAST в фиксированные файлы {FOLDER_EURO}:")
    save_fixed_chunks_euro(res_euro_fast, FOLDER_EURO)

    # 8. Сохранение ALL слоёв (динамические чанки)
    print(f"\n💾 Сохранение RU ALL чанками в {FOLDER_RU}:")
    ru_all_files = save_chunked(res_ru_all, FOLDER_RU, "ru_white_all")

    print(f"\n💾 Сохранение EURO ALL чанками в {FOLDER_EURO}:")
    euro_all_files = save_chunked(res_euro_all, FOLDER_EURO, "my_euro_all")

    # 9. Генерация subscriptions_list.txt (аккуратный набор ссылок)
    generate_subscriptions_list()

    print("\n✅ SUCCESS: FAST/ALL LAYERS GENERATED")
    print(f"  Префильтр использует: {len(RU_FILES)} RU + {len(EURO_FILES)} EURO (FAST)")
    print(f"  Постер покажет: ~9-11 кнопок (FAST + ограниченные ALL)")
































































































































