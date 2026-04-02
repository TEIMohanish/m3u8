# main.py — Tata Play DRM Proxy (Official API + YGX Backup + pywidevine)
from flask import Flask, request, Response, jsonify
import requests
import re
import base64
import struct
import json
import logging
import time
import os
from datetime import datetime
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from Crypto.Cipher import AES
from Crypto.Util import Counter
from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import pytz
import uuid as uuid_lib

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Optional upstream proxy support (useful for VPN/proxy-routed VPS setups).
UPSTREAM_PROXY = os.getenv("UPSTREAM_PROXY", "").strip()
UPSTREAM_TIMEOUT = int(os.getenv("UPSTREAM_TIMEOUT", "20"))
PROXY_BYPASS_HOSTS = {
    h.strip().lower() for h in os.getenv("PROXY_BYPASS_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()
}
GEO_SPOOF_COUNTRY = os.getenv("GEO_SPOOF_COUNTRY", "").strip().upper()
GEO_SPOOF_IP = os.getenv("GEO_SPOOF_IP", "").strip()


def _build_proxies():
    if not UPSTREAM_PROXY:
        return None
    return {"http": UPSTREAM_PROXY, "https": UPSTREAM_PROXY}


PROXIES = _build_proxies()
if PROXIES:
    logger.info(f"🌐 Upstream proxy enabled: {UPSTREAM_PROXY}")
else:
    logger.info("🌐 Upstream proxy disabled")
if GEO_SPOOF_COUNTRY or GEO_SPOOF_IP:
    logger.info(f"🧭 Geo spoof enabled: country={GEO_SPOOF_COUNTRY or '-'} ip={GEO_SPOOF_IP or '-'}")
else:
    logger.info("🧭 Geo spoof disabled")


def should_bypass_proxy(url):
    try:
        host = (urlparse(url).hostname or "").lower()
        return host in PROXY_BYPASS_HOSTS
    except Exception:
        return False


def get_geo_spoof_headers(url):
    if not (GEO_SPOOF_COUNTRY or GEO_SPOOF_IP):
        return {}
    if should_bypass_proxy(url):
        return {}

    headers = {}
    if GEO_SPOOF_COUNTRY:
        headers["CF-IPCountry"] = GEO_SPOOF_COUNTRY
        headers["X-Forwarded-Country"] = GEO_SPOOF_COUNTRY
    if GEO_SPOOF_IP:
        headers["X-Forwarded-For"] = GEO_SPOOF_IP
        headers["X-Real-IP"] = GEO_SPOOF_IP
        headers["X-Client-IP"] = GEO_SPOOF_IP
        headers["True-Client-IP"] = GEO_SPOOF_IP
    return headers


def http_get(url, **kwargs):
    if PROXIES and not should_bypass_proxy(url):
        kwargs.setdefault("proxies", PROXIES)
    spoof_headers = get_geo_spoof_headers(url)
    if spoof_headers:
        headers = dict(kwargs.get("headers") or {})
        for k, v in spoof_headers.items():
            headers.setdefault(k, v)
        kwargs["headers"] = headers
    kwargs.setdefault("timeout", UPSTREAM_TIMEOUT)
    return requests.get(url, **kwargs)


def http_post(url, **kwargs):
    if PROXIES and not should_bypass_proxy(url):
        kwargs.setdefault("proxies", PROXIES)
    spoof_headers = get_geo_spoof_headers(url)
    if spoof_headers:
        headers = dict(kwargs.get("headers") or {})
        for k, v in spoof_headers.items():
            headers.setdefault(k, v)
        kwargs["headers"] = headers
    kwargs.setdefault("timeout", UPSTREAM_TIMEOUT)
    return requests.post(url, **kwargs)

# ================================================================
# AUTH CONFIG
# ================================================================
# Fallback credentials (used if login.json doesn't exist)
FALLBACK_PLATFORM_TOKEN = "o1xEF2co66vUy7IGeRM71nSQmsftGui7"
FALLBACK_SUBSCRIBER_ID = "1483439566"
FALLBACK_SUBSCRIBER_NAME = "Ramasubramanian A"
FALLBACK_DEVICE_ID = "eafbb0e76a4680231360fb61c87ad271"
FALLBACK_PROFILE_ID = "ee44773d-7189-4098-98f4-ab5d9d6adf7f"

# Dynamic credentials (loaded from login.json)
PLATFORM_TOKEN = FALLBACK_PLATFORM_TOKEN
SUBSCRIBER_ID = FALLBACK_SUBSCRIBER_ID
SUBSCRIBER_NAME = FALLBACK_SUBSCRIBER_NAME
DEVICE_ID = FALLBACK_DEVICE_ID
PROFILE_ID = FALLBACK_PROFILE_ID

DEVICE_DETAILS = {
    "pl": "web", "os": "WINDOWS", "lo": "en-us", "app": "1.58.1",
    "dn": "PC", "bv": 146, "bn": "CHROME", "device_id": DEVICE_ID,
    "device_type": "WEB", "device_platform": "PC", "device_category": "open",
    "manufacturer": "WINDOWS_CHROME_146", "model": "PC", "sname": SUBSCRIBER_NAME
}


def build_api_headers():
    """Build API headers with current credentials"""
    return {
        "accept": "*/*",
        "authorization": f"Bearer {PLATFORM_TOKEN}",
        "content-type": "application/json",
        "origin": "https://watch.tataplay.com",
        "referer": "https://watch.tataplay.com/",
        "platform": "web",
        "locale": "ENG",
        "kp": "false",
        "subscriberid": SUBSCRIBER_ID,
        "profileid": PROFILE_ID,
        "device_details": json.dumps(DEVICE_DETAILS),
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        "x-device-id": DEVICE_ID,
        "x-device-platform": "PC",
        "x-device-type": "WEB",
        "x-subscriber-id": SUBSCRIBER_ID,
        "x-subscriber-name": SUBSCRIBER_NAME,
    }


def get_api_headers():
    """Get current API headers"""
    return build_api_headers()


def load_credentials():
    """Load credentials from login.json if available, else use fallback"""
    global PLATFORM_TOKEN, SUBSCRIBER_ID, SUBSCRIBER_NAME, DEVICE_ID, PROFILE_ID, DEVICE_DETAILS
    
    login_file = os.path.join(os.path.dirname(__file__), "login.json")
    if os.path.exists(login_file):
        try:
            with open(login_file, 'r') as f:
                login_data = json.load(f)
            
            # Extract credentials from login response
            account_details = login_data.get('data', {}).get('accountDetails', [{}])[0]
            PLATFORM_TOKEN = login_data.get('data', {}).get('userAuthenticateToken', FALLBACK_PLATFORM_TOKEN)
            SUBSCRIBER_ID = account_details.get('subscriberId', FALLBACK_SUBSCRIBER_ID)
            PROFILE_ID = login_data.get('data', {}).get('profileId', FALLBACK_PROFILE_ID)
            SUBSCRIBER_NAME = account_details.get('subscriberName', FALLBACK_SUBSCRIBER_NAME)
            DEVICE_ID = login_data.get('deviceId', FALLBACK_DEVICE_ID)
            
            DEVICE_DETAILS["device_id"] = DEVICE_ID
            DEVICE_DETAILS["sname"] = SUBSCRIBER_NAME
            
            logger.info(f"✅ Loaded credentials from login.json: {SUBSCRIBER_NAME}")
        except Exception as e:
            logger.warning(f"Failed to load login.json: {e}, using fallback")
    else:
        logger.info("ℹ️ No login.json found, using fallback credentials")


API_HEADERS = build_api_headers()

CDN_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Origin": "https://watch.tataplay.com",
    "Referer": "https://watch.tataplay.com/",
}

CHANNEL_URL = "https://ts-api.videoready.tv/content-detail/pub/api/v1/channels"
PLAYER_URL = "https://tm.tapi.videoready.tv/digital-feed-services/api/partner/cdn/player/details/LIVE/{}"
JWT_URL = "https://tm.tapi.videoready.tv/auth-service/v3/sampling/token-service/token"
YGX_URL = "https://api.ygxworld.workers.dev/fetcher.json"
SAMPLING_EXPIRY = "ucPtCl63EsD1qBrlIhY9nw==#v2"

# ================================================================
# CACHES
# ================================================================
CHANNEL_CACHE = None
YGX_CACHE = None
YGX_CACHE_TIME = 0
KEY_CACHE = {}
JWT_CACHE = {}
STREAM_CACHE = {}
STREAM_CACHE_TTL = 200

# ================================================================
# WIDEVINE CDM
# ================================================================
try:
    WV_CDM = Cdm.from_device(Device.load("device.wvd"))
    logger.info("✅ Widevine CDM loaded")
except Exception as e:
    WV_CDM = None
    logger.error(f"❌ CDM load failed: {e}")


# ================================================================
# HELPERS
# ================================================================

def normalize_name(name):
    if not name:
        return ""
    return re.sub(r'[^a-z0-9]', '', name.lower().replace("hd", "").replace("tv", ""))


def decrypt_aes_ecb(encrypted_str):
    if not encrypted_str:
        return None
    try:
        clean = encrypted_str
        if clean.endswith("#v2"):
            clean = clean[:-3]
        clean = clean.replace("\n", "").replace(" ", "").strip()
        if not clean:
            return None
        raw = base64.b64decode(clean)
        cipher = AES.new(b"aesEncryptionKey", AES.MODE_ECB)
        dec = cipher.decrypt(raw)
        pad = dec[-1]
        if 1 <= pad <= 16 and all(b == pad for b in dec[-pad:]):
            dec = dec[:-pad]
        text = dec.decode("utf-8", errors="ignore").strip()
        text = text.replace("hdnea-", "hdnea=").replace("hmac-", "hmac=")
        return text
    except Exception as e:
        logger.error(f"Decrypt failed: {e}")
        return None


def to_timestamp(date_str):
    """Convert date string OR unix timestamp to unix timestamp"""
    if not date_str:
        return None
    
    # Check if already a unix timestamp (numeric)
    try:
        ts = int(date_str)
        # Sanity check: valid timestamp range (year 2000 to 2100)
        if 946684800 <= ts <= 4102444800:
            logger.info(f"📅 Using unix timestamp directly: {ts}")
            return ts
    except (ValueError, TypeError):
        pass
    
    # Try parsing as date string
    try:
        date_str = str(date_str).replace("+", " ").strip()
        dt = datetime.strptime(date_str, "%d/%m/%Y %H:%M:%S")
        ts = int(pytz.timezone("Asia/Kolkata").localize(dt).timestamp())
        logger.info(f"📅 Parsed date '{date_str}' -> {ts}")
        return ts
    except Exception as e:
        logger.warning(f"Date parse failed for '{date_str}': {e}")
        return None


def append_or_replace_query_params(url, params):
    """Append query params if absent; replace existing values when provided."""
    try:
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        for k, v in params.items():
            if v is None:
                continue
            q[k] = [str(v)]
        new_query = urlencode(q, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
    except Exception:
        return url


def extract_expiry_from_stream_url(url):
    """Extract token expiry epoch from query (`exp`) or Akamai `hdntl` field."""
    try:
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)

        # Direct exp in query
        direct_exp = q.get("exp", [None])[0]
        if direct_exp and str(direct_exp).isdigit():
            return int(direct_exp)

        # hdntl usually has `~` separated k=v pairs
        hdntl_raw = q.get("hdntl", [None])[0]
        if hdntl_raw:
            hdntl_qs = parse_qs(hdntl_raw.replace("~", "&"), keep_blank_values=True)
            hdntl_exp = hdntl_qs.get("exp", [None])[0]
            if hdntl_exp and str(hdntl_exp).isdigit():
                return int(hdntl_exp)
    except Exception:
        pass
    return None


def is_future_expiry(exp_ts, safety_seconds=20):
    if not exp_ts:
        return False
    return int(time.time()) + safety_seconds < int(exp_ts)


def rewrite_catchup_host(netloc):
    """Prefer host patterns known to work across Tata catchup CDNs."""
    if not netloc:
        return netloc
    updated = netloc.replace("bpwta", "bpwcatchupta")
    updated = updated.replace("bpaita", "bpaicatchupta")
    return updated


def decode_jwt_exp(jwt_token):
    try:
        parts = jwt_token.split(".")
        if len(parts) >= 2:
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
    except Exception:
        pass
    return 0


def extract_hdntl(response):
    """Extract hdntl token from response headers/cookies (for segment auth)"""
    # Check response cookies
    hdntl = response.cookies.get("hdntl")
    if hdntl:
        logger.info(f"✅ hdntl from cookie: {hdntl[:60]}...")
        return f"hdntl={hdntl}"

    # Check Set-Cookie headers
    set_cookies = response.headers.get("Set-Cookie", "")
    match = re.search(r'hdntl=([^;\s,]+)', set_cookies)
    if match:
        logger.info(f"✅ hdntl from Set-Cookie")
        return f"hdntl={match.group(1)}"

    # Check all response headers
    for key, value in response.headers.items():
        match = re.search(r'hdntl=([^;\s,]+)', value)
        if match:
            logger.info(f"✅ hdntl from header {key}")
            return f"hdntl={match.group(1)}"

    logger.warning("⚠️ No hdntl found in response")
    return None


def log_upstream_http_failure(tag, url, response):
    """Log upstream HTTP failures with enough context for CDN debugging."""
    if response is None:
        logger.warning(f"{tag}: no response object for {url}")
        return

    # Keep logs compact and avoid dumping very large bodies.
    body_preview = response.text[:500].replace("\n", "\\n").replace("\r", "\\r")
    header_preview = {
        "server": response.headers.get("Server"),
        "content-type": response.headers.get("Content-Type"),
        "x-cache": response.headers.get("X-Cache"),
        "x-cache-remote": response.headers.get("X-Cache-Remote"),
        "x-akamai-request-id": response.headers.get("X-Akamai-Request-ID"),
        "via": response.headers.get("Via"),
        "set-cookie": response.headers.get("Set-Cookie"),
    }
    logger.warning(
        f"{tag}: status={response.status_code} url={url} "
        f"headers={json.dumps(header_preview, ensure_ascii=True)} body={body_preview}"
    )


def extract_pssh_from_segment(segment_data):
    """Extract PSSH/KID from init segment binary data"""
    hex_content = segment_data.hex()
    pssh_marker = "70737368"  # "pssh" in hex
    pos = hex_content.find(pssh_marker)

    if pos == -1:
        return None, None

    # Read box size (4 bytes before "pssh")
    header_size_hex = hex_content[pos - 8:pos - 0]
    if len(header_size_hex) < 8:
        return None, None

    header_size = int(header_size_hex, 16)
    pssh_hex = hex_content[pos - 8:pos - 8 + header_size * 2]

    # Extract KID (at offset 34 bytes = 68 hex chars into pssh box)
    kid_hex = pssh_hex[68:68 + 32] if len(pssh_hex) >= 100 else None

    if kid_hex:
        # Build clean Widevine PSSH
        new_pssh_hex = "000000327073736800000000edef8ba979d64acea3c827dcd51d21ed000000121210" + kid_hex
        pssh_b64 = base64.b64encode(bytes.fromhex(new_pssh_hex)).decode()
        kid_uuid = f"{kid_hex[:8]}-{kid_hex[8:12]}-{kid_hex[12:16]}-{kid_hex[16:20]}-{kid_hex[20:]}"
        return pssh_b64, kid_uuid

    return None, None


def normalize_kid(kid_str):
    """Normalize KID to lowercase hex without dashes"""
    if not kid_str:
        return None
    return kid_str.replace("-", "").lower()


def store_key(kid_hex, key_hex):
    """Store key with all possible KID formats"""
    kid_norm = normalize_kid(kid_hex)
    if not kid_norm or not key_hex:
        return
    
    # Store in multiple formats
    KEY_CACHE[kid_norm] = key_hex
    KEY_CACHE[kid_norm.upper()] = key_hex
    
    # UUID format
    kid_uuid = f"{kid_norm[:8]}-{kid_norm[8:12]}-{kid_norm[12:16]}-{kid_norm[16:20]}-{kid_norm[20:]}"
    KEY_CACHE[kid_uuid] = key_hex
    KEY_CACHE[kid_uuid.upper()] = key_hex
    
    logger.info(f"🔑 Stored key: KID={kid_norm} KEY={key_hex}")


def lookup_key(kid_str):
    """Lookup key by KID in any format"""
    if not kid_str or kid_str == "NONE":
        return None
    
    kid_norm = normalize_kid(kid_str)
    
    # Try all formats
    for fmt in [kid_str, kid_str.upper(), kid_str.lower(), 
                kid_norm, kid_norm.upper() if kid_norm else None]:
        if fmt and fmt in KEY_CACHE:
            return KEY_CACHE[fmt]
    
    # Try UUID format
    if kid_norm and len(kid_norm) == 32:
        kid_uuid = f"{kid_norm[:8]}-{kid_norm[8:12]}-{kid_norm[12:16]}-{kid_norm[16:20]}-{kid_norm[20:]}"
        for fmt in [kid_uuid, kid_uuid.upper()]:
            if fmt in KEY_CACHE:
                return KEY_CACHE[fmt]
    
    return None


# ================================================================
# YGX BACKUP
# ================================================================

def get_ygx_channels():
    global YGX_CACHE, YGX_CACHE_TIME
    if YGX_CACHE and (time.time() - YGX_CACHE_TIME < 1800):
        return YGX_CACHE
    try:
        logger.info("📡 Fetching YGX...")
        r = http_get(YGX_URL, timeout=20)
        if r.ok:
            channels = r.json().get("data", {}).get("channels", [])
            YGX_CACHE = {str(ch["id"]): ch for ch in channels}
            YGX_CACHE_TIME = time.time()
            logger.info(f"✅ YGX: {len(YGX_CACHE)} channels")
    except Exception as e:
        logger.error(f"YGX: {e}")
    return YGX_CACHE or {}


def find_ygx_channel(identifier):
    ygx = get_ygx_channels()
    if not ygx:
        return None
    sid = str(identifier)
    if sid in ygx:
        return ygx[sid]
    norm = normalize_name(str(identifier))
    if norm:
        for ch in ygx.values():
            if norm in normalize_name(ch.get("name", "")):
                return ch
    return None


# ================================================================
# TATA PLAY API
# ================================================================

def get_channels():
    global CHANNEL_CACHE
    if CHANNEL_CACHE is not None:
        return CHANNEL_CACHE
    try:
        r = http_get(f"{CHANNEL_URL}?limit=1000", headers=get_api_headers(), timeout=15)
        CHANNEL_CACHE = r.json().get("data", {}).get("list", []) if r.ok else []
    except Exception as e:
        logger.error(f"Channels: {e}")
        CHANNEL_CACHE = []
    return CHANNEL_CACHE


def find_channel(identifier):
    channels = get_channels()
    try:
        cid = int(identifier)
        for ch in channels:
            if ch.get("id") == cid:
                return ch
    except (ValueError, TypeError):
        pass
    norm = normalize_name(str(identifier))
    if norm:
        for ch in channels:
            if norm in normalize_name(ch.get("title", "")):
                return ch
    return None


def get_player_data(channel_id):
    url = PLAYER_URL.format(channel_id)
    for attempt in range(2):
        try:
            r = http_get(url, headers=get_api_headers(), timeout=15)
            if r.ok:
                return r.json().get("data", {})
        except Exception as e:
            logger.warning(f"Player {attempt + 1}: {e}")
        time.sleep(1)
    return {}


def get_channel_epids(channel):
    """Get epids — use ONLY 1 epid like PHP reference does"""
    entitlements = channel.get("entitlements", [])
    special_id = "1000001274"

    # Priority: special ID if in entitlements
    if special_id in entitlements:
        return [{"epid": "Subscription", "bid": special_id}]

    # Otherwise first entitlement
    if entitlements:
        return [{"epid": "Subscription", "bid": entitlements[0]}]

    # Fallback to offerId first epid
    offer = channel.get("offerId", {})
    epids = offer.get("epids", [])
    if epids:
        return [epids[0]]

    return [{"epid": "Subscription", "bid": "1000001067"}]


def get_jwt_token(channel_id, force_refresh=False):
    """Get JWT via v3/sampling — cached until expiry"""
    if force_refresh:
        JWT_CACHE.pop(channel_id, None)

    cached = JWT_CACHE.get(channel_id)
    if (not force_refresh) and cached and time.time() < cached["exp"] - 30:
        return cached["token"]

    ch = None
    for c in get_channels():
        if c.get("id") == channel_id:
            ch = c
            break
    if not ch:
        return None

    epids = get_channel_epids(ch)

    payload = {
        "action": "stream",
        "epids": epids,
        "samplingExpiry": SAMPLING_EXPIRY,
    }

    logger.info(f"🔑 JWT for ch {channel_id} epids={epids}")

    try:
        r = http_post(JWT_URL, headers=get_api_headers(), json=payload, timeout=15)
        if r.ok:
            resp = r.json()
            if resp.get("code") == 0 and resp.get("data", {}).get("token"):
                token = resp["data"]["token"]
                if token.startswith("Bearer "):
                    token = token[7:].strip()
                JWT_CACHE[channel_id] = {"token": token, "exp": decode_jwt_exp(token)}
                logger.info(f"✅ JWT obtained")
                return token
            logger.warning(f"JWT resp: {json.dumps(resp)[:200]}")
        else:
            logger.warning(f"JWT {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"JWT: {e}")
    return None


def get_stream_official(channel_identifier, begin=None, end=None):
    """Official API — HMAC in decrypted URL, JWT via ls_session"""
    ch = find_channel(channel_identifier)
    if not ch:
        raise Exception(f"Channel not found: {channel_identifier}")

    cid = ch["id"]
    title = ch.get("title", "Unknown")

    cache_key = f"off_{cid}_{begin}_{end}"
    cached = STREAM_CACHE.get(cache_key)
    if cached:
        cached_data = cached.get("data", {})
        cached_mpd = cached_data.get("mpd_url", "")
        exp_ts = extract_expiry_from_stream_url(cached_mpd)
        if is_future_expiry(exp_ts) or (time.time() - cached.get("ts", 0) < STREAM_CACHE_TTL):
            logger.info(f"📦 Cached: {title}")
            return cached_data

    logger.info(f"📺 {title} (ID: {cid})")

    data = get_player_data(cid)
    if not data:
        raise Exception(f"Player empty for {cid}")

    mpd_enc = data.get("dashWidewinePlayUrl") or data.get("dashWidevinePlayUrl") or data.get("dashPlayreadyPlayUrl") or ""
    lic_enc = data.get("dashWidewineLicenseUrl") or data.get("dashWidevineLicenseUrl") or ""

    mpd_url = decrypt_aes_ecb(mpd_enc) if mpd_enc else None
    base_license_url = decrypt_aes_ecb(lic_enc) if lic_enc else None

    if not mpd_url or not base_license_url:
        raise Exception(f"Decrypt failed for {title}")

    logger.info(f"📄 MPD: {mpd_url[:120]}...")

    # Get JWT and append to license URL
    jwt = get_jwt_token(cid)
    if jwt:
        license_url = append_or_replace_query_params(base_license_url, {"ls_session": jwt})
    else:
        license_url = base_license_url
        logger.warning("⚠️ No JWT")

    lic_headers = {
        "content-type": "application/octet-stream",
        "origin": "https://watch.tataplay.com",
        "referer": "https://watch.tataplay.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    # Fetch MPD to get hdntl token for segments
    logger.info("🔑 Fetching MPD to extract hdntl...")
    mpd_response = http_get(mpd_url, headers=CDN_HEADERS, timeout=15, allow_redirects=True)
    hdntl = None
    if mpd_response.ok:
        hdntl = extract_hdntl(mpd_response)
    else:
        log_upstream_http_failure("Official MPD prefetch failed", mpd_url, mpd_response)

    # If no hdntl from headers, try extracting from hdnea in URL
    if not hdntl and "hdnea=" in mpd_url:
        match = re.search(r'hdnea=([^&]+)', mpd_url)
        if match:
            hdntl = f"hdnea={match.group(1)}"
            logger.info("ℹ️ Using hdnea as segment token")

    # Catchup - convert timestamps
    if begin and end:
        st = to_timestamp(begin)
        et = to_timestamp(end)
        if st and et:
            parsed = urlparse(mpd_url)
            nl = rewrite_catchup_host(parsed.netloc)
            mpd_url = urlunparse(parsed._replace(netloc=nl))
            mpd_url = append_or_replace_query_params(mpd_url, {"begin": st, "end": et})
            logger.info(f"📅 Catchup: {st} -> {et}")

    result = {
        "mpd_url": mpd_url,
        "license_url": license_url,
        "license_headers": lic_headers,
        "manifest_headers": CDN_HEADERS.copy(),
        "title": title,
        "source": "official",
        "is_drm": True,
        "channel_id": cid,
        "hdntl": hdntl,
    }

    STREAM_CACHE[cache_key] = {"data": result, "ts": time.time()}
    return result


def get_stream_ygx(channel_identifier, official_data=None, begin=None, end=None):
    """YGX backup — use official HMAC URL + JWT"""
    ch = find_ygx_channel(channel_identifier)
    if not ch:
        return None

    mpd_url = ch.get("manifest_url", "")
    base_license_url = ch.get("license_url", "")
    name = ch.get("name", "Unknown")

    if not mpd_url or not base_license_url:
        return None

    # Use official MPD URL (has HMAC)
    if official_data and "hdnea=" in official_data.get("mpd_url", ""):
        mpd_url = official_data["mpd_url"]

    # Use JWT from official
    jwt_token = None
    if official_data and "ls_session=" in official_data.get("license_url", ""):
        m = re.search(r'ls_session=([^&]+)', official_data["license_url"])
        if m:
            jwt_token = m.group(1)

    license_url = append_or_replace_query_params(base_license_url, {"ls_session": jwt_token}) if jwt_token else base_license_url

    lic_headers = {
        "content-type": "application/octet-stream",
        "origin": "https://watch.tataplay.com",
        "referer": "https://watch.tataplay.com/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    }

    hdntl = official_data.get("hdntl") if official_data else None

    if begin and end and ch.get("is_catchup_available"):
        st = to_timestamp(begin)
        et = to_timestamp(end)
        if st and et:
            parsed = urlparse(mpd_url)
            nl = rewrite_catchup_host(parsed.netloc)
            mpd_url = urlunparse(parsed._replace(netloc=nl))
            mpd_url = append_or_replace_query_params(mpd_url, {"begin": st, "end": et})

    return {
        "mpd_url": mpd_url,
        "license_url": license_url,
        "license_headers": lic_headers,
        "manifest_headers": ch.get("manifest_headers", CDN_HEADERS.copy()),
        "title": name,
        "source": "ygx_backup",
        "is_drm": ch.get("is_drm_protected", True),
        "hdntl": hdntl,
    }


def get_stream_info(channel_identifier, begin=None, end=None):
    """Official first, then YGX fallback"""
    official_data = None

    try:
        result = get_stream_official(channel_identifier, begin, end)
        official_data = result
        test = http_get(result["mpd_url"], headers=CDN_HEADERS, timeout=10, stream=True)
        if test.status_code >= 400:
            log_upstream_http_failure("Official MPD validation failed", result["mpd_url"], test)
        test.close()
        if test.status_code < 400:
            logger.info(f"✅ Official OK for {result['title']}")
            return result
    except Exception as e:
        logger.warning(f"⚠️ Official: {e}")

    result = get_stream_ygx(channel_identifier, official_data, begin, end)
    if result:
        return result

    raise Exception(f"All sources failed for: {channel_identifier}")


# ================================================================
# WIDEVINE
# ================================================================

def extract_all_pssh_from_mpd(mpd_text):
    """Extract ALL PSSH values from MPD (video + audio may have different ones)"""
    pssh_list = []
    for pat in [r'<cenc:pssh[^>]*>(.*?)</cenc:pssh>', r'<pssh[^>]*>(.*?)</pssh>']:
        for m in re.findall(pat, mpd_text, re.DOTALL):
            b64 = m.strip()
            try:
                decoded = base64.b64decode(b64)
                # Check if it's Widevine PSSH
                if b'\xed\xef\x8b\xa9' in decoded:
                    if b64 not in pssh_list:
                        pssh_list.append(b64)
            except Exception:
                continue
    return pssh_list


def extract_all_kids_from_mpd(mpd_text):
    """Extract all KIDs from MPD ContentProtection elements"""
    kids = []
    # Pattern for cenc:default_KID
    for m in re.findall(r'cenc:default_KID="([0-9a-fA-F-]+)"', mpd_text):
        kid_norm = normalize_kid(m)
        if kid_norm and kid_norm not in kids:
            kids.append(kid_norm)
    return kids


def extract_pssh_from_mpd(mpd_text):
    """Extract first Widevine PSSH from MPD (backward compat)"""
    pssh_list = extract_all_pssh_from_mpd(mpd_text)
    return pssh_list[0] if pssh_list else None


def fetch_pssh_from_init_segment(mpd_text, base_url, hdntl=None):
    """Extract PSSH from init segment when not in MPD (catchup streams)"""
    try:
        # Find an audio init segment URL from SegmentTemplate
        for match in re.finditer(r'<SegmentTemplate[^>]*initialization="([^"]+)"', mpd_text):
            init_template = match.group(1)

            # Find a RepresentationID
            rep_match = re.search(r'<Representation[^>]*id="([^"]+)"', mpd_text)
            if rep_match:
                init_url = init_template.replace("$RepresentationID$", rep_match.group(1))
                full_url = base_url + init_url
                if hdntl:
                    full_url += f"?{hdntl}"

                logger.info(f"🔍 Fetching init segment for PSSH: {full_url[:100]}...")
                r = http_get(full_url, headers=CDN_HEADERS, timeout=10)
                if r.ok:
                    pssh_b64, kid_uuid = extract_pssh_from_segment(r.content)
                    if pssh_b64:
                        logger.info(f"✅ PSSH from init segment: KID={kid_uuid}")
                        return pssh_b64, kid_uuid

    except Exception as e:
        logger.warning(f"Init segment PSSH extraction: {e}")
    return None, None


def fetch_widevine_keys(pssh_b64, license_url, license_headers, channel_id=None):
    """Fetch keys for a single PSSH"""
    if not WV_CDM or not pssh_b64:
        return {}
    session_id = None
    try:
        session_id = WV_CDM.open()
        challenge = WV_CDM.get_license_challenge(session_id, PSSH(pssh_b64))
        logger.info(f"📡 License → {license_url[:100]}...")
        r = http_post(license_url, data=challenge, headers=license_headers, timeout=15)

        if r.status_code == 403 and channel_id is not None:
            logger.warning("⚠️ License 403. Refreshing JWT and retrying once...")
            fresh_jwt = get_jwt_token(channel_id, force_refresh=True)
            if fresh_jwt:
                retry_url = append_or_replace_query_params(license_url, {"ls_session": fresh_jwt})
                logger.info(f"🔁 Retry license → {retry_url[:100]}...")
                r = http_post(retry_url, data=challenge, headers=license_headers, timeout=15)

        if r.status_code == 200:
            lic_bytes = r.content
            try:
                j = r.json()
                for f in ("license", "response", "License", "Response"):
                    if f in j:
                        lic_bytes = base64.b64decode(j[f])
                        break
            except Exception:
                pass
            WV_CDM.parse_license(session_id, lic_bytes)
            keys = {}
            for key in WV_CDM.get_keys(session_id):
                if "CONTENT" in str(key.type):
                    kid_hex = key.kid.hex
                    key_hex = key.key.hex()
                    keys[kid_hex] = key_hex
                    store_key(kid_hex, key_hex)
            WV_CDM.close(session_id)
            return keys
        else:
            logger.error(f"License {r.status_code}: {r.text[:200]}")
            WV_CDM.close(session_id)
            return {}
    except Exception as e:
        logger.error(f"Widevine: {e}")
        if session_id:
            try:
                WV_CDM.close(session_id)
            except Exception:
                pass
        return {}


def fetch_all_widevine_keys(pssh_list, license_url, license_headers, channel_id=None):
    """Fetch keys for all PSSH values (handles separate video/audio keys)"""
    all_keys = {}
    for pssh_b64 in pssh_list:
        keys = fetch_widevine_keys(pssh_b64, license_url, license_headers, channel_id=channel_id)
        all_keys.update(keys)
    return all_keys

# ================================================================
# CENC PARSER
# ================================================================

class CENCParser:
    def __init__(self, data, key_hex):
        self.data = bytearray(data)
        self.view = memoryview(self.data)
        self.key = bytes.fromhex(key_hex) if key_hex else None

    def u32(self, o):
        return struct.unpack(">I", self.view[o:o + 4])[0]

    def u16(self, o):
        return struct.unpack(">H", self.view[o:o + 2])[0]

    def decrypt(self):
        if not self.key:
            return self.data
            
        off, limit = 0, len(self.data)
        samples, crypto = [], []
        moof_found, mdat_off, mdat_sz = False, None, 0
        
        while off < limit - 8:
            sz = self.u32(off)
            if sz == 0 or sz > limit - off:
                break
            bt = self.data[off+4:off+8]
            if bt == b'moof':
                moof_found = True
                self._moof(off, sz, samples, crypto)
            elif bt == b'mdat':
                mdat_off, mdat_sz = off, sz
            off += sz
            
        if moof_found and mdat_off is not None and crypto:
            self._dec(mdat_off + 8, mdat_sz - 8, samples, crypto)
        return self.data

    def _moof(self, off, sz, s, c):
        p, end = off+8, off+sz
        while p < end-8:
            ss = self.u32(p)
            if ss == 0 or ss > end - p:
                break
            if self.data[p+4:p+8] == b'traf':
                self._traf(p, ss, s, c)
            p += ss

    def _traf(self, off, sz, s, c):
        p, end = off+8, off+sz
        while p < end-8:
            ss = self.u32(p)
            if ss == 0 or ss > end - p:
                break
            t = self.data[p+4:p+8]
            if t == b'trun':
                s.extend(self._trun(p))
            elif t == b'senc':
                c.extend(self._senc(p))
            p += ss

    def _trun(self, off):
        fl = struct.unpack(">I", self.view[off+8:off+12])[0] & 0xFFFFFF
        cnt = self.u32(off+12)
        c = off+16
        if fl & 0x01:
            c += 4
        if fl & 0x04:
            c += 4
        sizes = []
        for _ in range(cnt):
            if fl & 0x100:
                c += 4
            s = self.u32(c) if (fl & 0x200) else 0
            if fl & 0x200:
                c += 4
            if fl & 0x400:
                c += 4
            if fl & 0x800:
                c += 4
            sizes.append(s)
        return sizes

    def _senc(self, off):
        fl = struct.unpack(">I", self.view[off+8:off+12])[0] & 0xFFFFFF
        cnt = self.u32(off+12)
        us = fl & 0x02
        c = off+16
        entries = []
        for _ in range(cnt):
            if c + 8 > len(self.data):
                break
            iv = self.view[c:c+8].tobytes()
            c += 8
            subs = []
            if us:
                if c + 2 > len(self.data):
                    break
                sc = self.u16(c)
                c += 2
                for _ in range(sc):
                    if c + 6 > len(self.data):
                        break
                    cl, ci = self.u16(c), self.u32(c+2)
                    c += 6
                    subs.append((cl, ci))
            entries.append((iv, subs))
        return entries

    def _dec(self, start, total, samples, crypto):
        cur = start
        for i in range(min(len(samples), len(crypto))):
            sz = samples[i]
            iv, subs = crypto[i]
            if cur + sz > len(self.data):
                break
            ctr = Counter.new(64, prefix=iv, initial_value=0)
            ci = AES.new(self.key, AES.MODE_CTR, counter=ctr)
            if not subs:
                self.data[cur:cur+sz] = ci.decrypt(self.data[cur:cur+sz])
            else:
                lc = cur
                for cl, en in subs:
                    lc += cl
                    if en > 0 and lc + en <= len(self.data):
                        self.data[lc:lc+en] = ci.decrypt(self.data[lc:lc+en])
                        lc += en
            cur += sz


# ================================================================
# CORS
# ================================================================

@app.after_request
def add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' https:; "
        "img-src 'self' data: https:; "
        "media-src 'self' https:; "
        "connect-src 'self' https:;"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    return resp


# ================================================================
# ROUTES
# ================================================================

@app.route("/health")
def health():
    return {"status": "ok", "cdm": WV_CDM is not None,
            "keys": len(KEY_CACHE), "jwts": len(JWT_CACHE),
            "channels": len(CHANNEL_CACHE) if CHANNEL_CACHE else 0,
            "ygx": len(YGX_CACHE) if YGX_CACHE else 0}


@app.route("/channels")
def list_channels():
    channels = get_channels()
    return {"total": len(channels),
            "channels": [{"id": ch["id"], "title": ch.get("title", "")} for ch in channels]}


@app.route("/keys")
def list_keys():
    """Debug endpoint to see all cached keys"""
    unique_keys = {}
    for kid, key in KEY_CACHE.items():
        kid_norm = normalize_kid(kid)
        if kid_norm:
            unique_keys[kid_norm] = key
    return {"total": len(unique_keys), "keys": unique_keys}


# ================================================================
# LOGIN/LOGOUT ENDPOINTS
# ================================================================

def generate_numeric_uuid():
    """Generate a numeric device ID"""
    import random
    return str(random.randint(100, 999)) + str(int(time.time())) + str(random.randint(10, 99))


def get_or_create_guest_device():
    """Get or create guest device credentials"""
    cred_file = os.path.join(os.path.dirname(__file__), "guest-device.json")
    
    if os.path.exists(cred_file):
        try:
            with open(cred_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load guest credentials: {e}")
    
    # Create new device
    device_id = generate_numeric_uuid()
    logger.info(f"🆕 Registering new guest device: {device_id}")
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'authorization': 'bearer undefined',
        'content-length': '0',
        'referer': 'https://www.tataplaybinge.com/',
        'deviceid': device_id,
        'origin': 'https://www.tataplaybinge.com',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    }
    
    try:
        r = http_post('https://tb.tapi.videoready.tv/binge-mobile-services/pub/api/v1/user/guest/register', 
                     headers=headers, timeout=15)
        if r.ok:
            guest_data = r.json().get('data', {})
            anonymous_id = guest_data.get('anonymousId', '')
            
            if anonymous_id:
                cred = {'deviceId': device_id, 'anonymousId': anonymous_id}
                os.makedirs(os.path.dirname(cred_file), exist_ok=True)
                with open(cred_file, 'w') as f:
                    json.dump(cred, f, indent=2)
                logger.info(f"✅ Guest device registered: {anonymous_id[:20]}...")
                return cred
    except Exception as e:
        logger.error(f"Guest registration failed: {e}")
    
    return None


LOGIN_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <meta name="theme-color" content="#0f111a" />
    <title>Tata Play Login</title>
    <style>
        :root {
            --bg: #0f111a;
            --panel: rgba(17, 20, 31, 0.86);
            --panel-border: rgba(255, 255, 255, 0.08);
            --text: #f4f7fb;
            --muted: #a8b0c1;
            --accent: #ff2d55;
            --accent-2: #7c4dff;
            --success: #29cc6a;
            --danger: #ff5d5d;
            --field: #1a1f2e;
            --field-border: rgba(255,255,255,0.08);
            --shadow: 0 30px 80px rgba(0, 0, 0, 0.45);
        }

        * { box-sizing: border-box; }
        html, body { height: 100%; }
        body {
            margin: 0;
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background:
                radial-gradient(circle at top left, rgba(124, 77, 255, 0.25), transparent 35%),
                radial-gradient(circle at top right, rgba(255, 45, 85, 0.2), transparent 30%),
                linear-gradient(180deg, #0b0d14 0%, #111522 100%);
            overflow-x: hidden;
        }

        .bg-grid {
            position: fixed;
            inset: 0;
            pointer-events: none;
            opacity: 0.22;
            background-image:
                linear-gradient(rgba(255,255,255,0.04) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255,255,255,0.04) 1px, transparent 1px);
            background-size: 48px 48px;
            mask-image: radial-gradient(circle at center, black 30%, transparent 100%);
        }

        .shell {
            min-height: 100vh;
            display: grid;
            place-items: center;
            padding: 24px;
        }

        .card {
            width: min(100%, 980px);
            display: grid;
            grid-template-columns: 1.05fr 0.95fr;
            background: var(--panel);
            backdrop-filter: blur(18px);
            border: 1px solid var(--panel-border);
            border-radius: 28px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .hero {
            position: relative;
            padding: 44px;
            background:
                linear-gradient(135deg, rgba(255,45,85,0.16), rgba(124,77,255,0.12)),
                radial-gradient(circle at top right, rgba(255,255,255,0.14), transparent 34%);
            border-right: 1px solid rgba(255,255,255,0.06);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 620px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 28px;
        }

        .brand-mark {
            width: 46px;
            height: 46px;
            border-radius: 14px;
            background: linear-gradient(135deg, var(--accent), var(--accent-2));
            display: grid;
            place-items: center;
            font-weight: 800;
            box-shadow: 0 12px 30px rgba(255,45,85,0.3);
        }

        .brand h1 {
            font-size: 1.05rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            margin: 0;
        }

        .brand p {
            margin: 3px 0 0;
            color: var(--muted);
            font-size: 0.92rem;
        }

        .headline {
            margin-top: auto;
            max-width: 520px;
        }

        .headline h2 {
            font-size: clamp(2rem, 4vw, 4rem);
            line-height: 0.98;
            margin: 0;
            letter-spacing: -0.04em;
        }

        .headline p {
            margin: 18px 0 0;
            color: rgba(244, 247, 251, 0.82);
            font-size: 1rem;
            line-height: 1.7;
            max-width: 42ch;
        }

        .feature-row {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-top: 28px;
        }

        .chip {
            padding: 10px 14px;
            border-radius: 999px;
            background: rgba(255,255,255,0.07);
            border: 1px solid rgba(255,255,255,0.08);
            font-size: 0.9rem;
            color: rgba(244,247,251,0.92);
        }

        .panel {
            padding: 38px;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .status-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            margin-bottom: 24px;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            background: rgba(41, 204, 106, 0.12);
            color: #c9ffe0;
            border: 1px solid rgba(41, 204, 106, 0.18);
            font-size: 0.88rem;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            box-shadow: 0 0 0 6px rgba(41, 204, 106, 0.14);
        }

        .step-count {
            color: var(--muted);
            font-size: 0.92rem;
        }

        .title {
            font-size: 1.8rem;
            margin: 0 0 8px;
            letter-spacing: -0.03em;
        }

        .subtitle {
            color: var(--muted);
            margin: 0 0 28px;
            line-height: 1.6;
        }

        .field {
            margin-bottom: 14px;
        }

        .field label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.92rem;
            color: #dfe5f4;
        }

        input {
            width: 100%;
            padding: 15px 16px;
            border-radius: 16px;
            border: 1px solid var(--field-border);
            background: var(--field);
            color: var(--text);
            font-size: 1rem;
            outline: none;
            transition: border-color 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
        }

        input::placeholder { color: #7d879d; }
        input:focus {
            border-color: rgba(255, 45, 85, 0.55);
            box-shadow: 0 0 0 4px rgba(255, 45, 85, 0.12);
        }

        input:disabled {
            opacity: 0.65;
            cursor: not-allowed;
        }

        .row {
            display: flex;
            gap: 12px;
        }

        button {
            width: 100%;
            border: none;
            border-radius: 16px;
            padding: 14px 16px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            transition: transform 0.15s ease, filter 0.2s ease, opacity 0.2s ease;
        }

        button:hover { transform: translateY(-1px); }
        button:active { transform: translateY(0); }
        button:disabled {
            cursor: not-allowed;
            opacity: 0.7;
            transform: none;
        }

        .primary {
            background: linear-gradient(135deg, var(--accent), #ff6b4a);
            color: white;
            box-shadow: 0 14px 34px rgba(255, 45, 85, 0.24);
        }

        .secondary {
            background: rgba(255,255,255,0.08);
            color: var(--text);
            border: 1px solid rgba(255,255,255,0.1);
        }

        .ghost {
            background: transparent;
            color: #d8deec;
            border: 1px solid rgba(255,255,255,0.12);
        }

        .hidden { display: none !important; }

        .helper {
            color: var(--muted);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-top: 14px;
        }

        .spinner {
            margin-top: 18px;
            display: none;
            color: #dfe5f4;
            font-size: 0.95rem;
        }

        .account-card {
            margin-top: 24px;
            padding: 18px;
            border-radius: 18px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.08);
        }

        .account-card .label {
            color: var(--muted);
            font-size: 0.88rem;
            margin-bottom: 4px;
        }

        .account-card .value {
            font-size: 1.05rem;
            font-weight: 700;
        }

        .toast {
            position: fixed;
            left: 50%;
            bottom: 24px;
            transform: translateX(-50%);
            background: rgba(15, 17, 26, 0.95);
            color: #fff;
            padding: 12px 18px;
            border-radius: 999px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 20px 40px rgba(0,0,0,0.35);
            opacity: 0;
            pointer-events: none;
            transition: opacity 0.2s ease, transform 0.2s ease;
            z-index: 999;
            max-width: min(92vw, 560px);
            text-align: center;
        }

        .toast.show {
            opacity: 1;
            pointer-events: auto;
            transform: translateX(-50%) translateY(-4px);
        }

        @media (max-width: 900px) {
            .card { grid-template-columns: 1fr; }
            .hero {
                min-height: auto;
                padding: 28px;
                border-right: none;
                border-bottom: 1px solid rgba(255,255,255,0.06);
            }
            .panel { padding: 28px; }
        }

        @media (max-width: 560px) {
            .shell { padding: 14px; }
            .hero, .panel { padding: 22px; }
            .row { flex-direction: column; }
            .title { font-size: 1.5rem; }
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>

    <div class="shell">
        <main class="card" id="app" style="display:none;">
            <section class="hero">
                <div>
                    <div class="brand">
                        <div class="brand-mark">TP</div>
                        <div>
                            <h1>Tata Play Access</h1>
                            <p>Secure OTP sign-in</p>
                        </div>
                    </div>

                    <div class="headline">
                        <h2>Fast sign-in.
                            <br />
                            Clean control.
                        </h2>
                        <p>
                            Enter your mobile number, verify the OTP, and manage access from a single polished dashboard.
                            No playlist controls are shown here.
                        </p>
                    </div>
                </div>

                <div>
                    <div class="feature-row">
                        <span class="chip">OTP login</span>
                        <span class="chip">Auto verify</span>
                        <span class="chip">Logout anytime</span>
                    </div>
                </div>
            </section>

            <section class="panel">
                <div class="status-bar">
                    <div class="status-pill"><span class="status-dot"></span><span id="statusText">Ready</span></div>
                    <div class="step-count" id="stepCount">Step 1 of 2</div>
                </div>

                <h2 class="title" id="pageTitle">Login with OTP</h2>
                <p class="subtitle" id="subtitle">Use your registered mobile number to receive a one-time password.</p>

                <div id="loginUI">
                    <div class="field">
                        <label for="mobile">Mobile number</label>
                        <input type="tel" id="mobile" placeholder="Enter 10-digit mobile number" maxlength="10" inputmode="numeric" autocomplete="tel" />
                    </div>

                    <div class="row">
                        <button id="sendOtpBtn" class="primary">Send OTP</button>
                        <button id="clearBtn" class="secondary" type="button">Clear</button>
                    </div>

                    <div id="otpSection" class="hidden" style="margin-top: 18px;">
                        <div class="field">
                            <label for="otp">OTP</label>
                            <input type="text" id="otp" placeholder="Enter OTP" maxlength="6" inputmode="numeric" autocomplete="one-time-code" />
                        </div>
                        <div class="row">
                            <button id="verifyOtpBtn" class="primary">Verify OTP</button>
                            <button id="resendBtn" class="ghost" type="button" disabled>Resend</button>
                        </div>
                        <div class="helper">OTP may auto-submit when the code reaches 4 digits.</div>
                    </div>
                </div>

                <div class="spinner" id="spinner">Processing…</div>

                <div id="postLoginActions" class="hidden">
                    <div class="account-card">
                        <div class="label">Signed in as</div>
                        <div class="value" id="signedInUser">User</div>
                        <div class="helper" id="signedInInfo">Your session is active.</div>
                    </div>
                    <div class="row" style="margin-top: 18px;">
                        <button id="logoutBtn" class="ghost">Logout</button>
                    </div>
                </div>
            </section>
        </main>
    </div>

    <div id="toast" class="toast"></div>

    <script>
        const mobileInput = document.getElementById('mobile');
        const otpInput = document.getElementById('otp');
        const otpSection = document.getElementById('otpSection');
        const postLoginActions = document.getElementById('postLoginActions');
        const spinner = document.getElementById('spinner');
        const sendBtn = document.getElementById('sendOtpBtn');
        const verifyBtn = document.getElementById('verifyOtpBtn');
        const resendBtn = document.getElementById('resendBtn');
        const clearBtn = document.getElementById('clearBtn');
        const loginUI = document.getElementById('loginUI');
        const pageTitle = document.getElementById('pageTitle');
        const subtitle = document.getElementById('subtitle');
        const toast = document.getElementById('toast');
        const app = document.getElementById('app');
        const statusText = document.getElementById('statusText');
        const stepCount = document.getElementById('stepCount');
        const signedInUser = document.getElementById('signedInUser');
        const signedInInfo = document.getElementById('signedInInfo');

        let otpTimerInterval = null;
        let resendCooldown = 0;

        const showSpinner = (text = 'Processing…') => {
            spinner.innerText = text;
            spinner.style.display = 'block';
        };

        const hideSpinner = () => {
            spinner.style.display = 'none';
        };

        function showToast(message, kind = 'info') {
            toast.innerText = message;
            toast.style.borderColor = kind === 'error' ? 'rgba(255,93,93,0.35)' : 'rgba(255,255,255,0.1)';
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3200);
        }

        function setStatus(message, stepText) {
            statusText.innerText = message;
            if (stepText) {
                stepCount.innerText = stepText;
            }
        }

        function resetOtpTimer() {
            if (otpTimerInterval) {
                clearInterval(otpTimerInterval);
                otpTimerInterval = null;
            }
            resendCooldown = 0;
            resendBtn.disabled = true;
            resendBtn.innerText = 'Resend';
        }

        function startResendTimer(seconds = 60) {
            resetOtpTimer();
            resendCooldown = seconds;
            resendBtn.disabled = true;
            resendBtn.innerText = `Resend in ${resendCooldown}s`;
            otpTimerInterval = setInterval(() => {
                resendCooldown -= 1;
                if (resendCooldown > 0) {
                    resendBtn.innerText = `Resend in ${resendCooldown}s`;
                } else {
                    resetOtpTimer();
                    resendBtn.disabled = false;
                }
            }, 1000);
        }

        function clearForm() {
            mobileInput.value = '';
            otpInput.value = '';
            mobileInput.disabled = false;
            otpInput.disabled = false;
            otpSection.classList.add('hidden');
            postLoginActions.classList.add('hidden');
            loginUI.classList.remove('hidden');
            pageTitle.innerText = 'Login with OTP';
            subtitle.innerText = 'Use your registered mobile number to receive a one-time password.';
            setStatus('Ready', 'Step 1 of 2');
            resetOtpTimer();
            sendBtn.disabled = false;
            verifyBtn.disabled = false;
        }

        async function fetchLoginState() {
            try {
                const res = await fetch('/check-login');
                const data = await res.json();
                if (data.logged_in) {
                    loginUI.classList.add('hidden');
                    postLoginActions.classList.remove('hidden');
                    pageTitle.innerText = 'Login complete';
                    subtitle.innerText = 'Your account is already authenticated on this server.';
                    signedInUser.innerText = data.user || 'User';
                    signedInInfo.innerText = 'Logout to switch accounts or reset credentials.';
                    setStatus('Signed in', 'Session active');
                }
            } catch (e) {
                showToast('Unable to check login state', 'error');
            }
        }

        window.addEventListener('DOMContentLoaded', async () => {
            app.style.display = 'grid';
            await fetchLoginState();
            mobileInput.focus();
        });

        sendBtn.addEventListener('click', async () => {
            const mobile = mobileInput.value.trim();
            if (!/^[6-9]\d{9}$/.test(mobile)) {
                showToast('Enter a valid 10-digit mobile number', 'error');
                return;
            }

            showSpinner('Sending OTP…');
            setStatus('Sending OTP', 'Step 1 of 2');

            try {
                const res = await fetch('/send-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `mobile=${encodeURIComponent(mobile)}`
                });
                const data = await res.json();
                showToast(data.message || data.error || 'OTP sent', res.ok ? 'info' : 'error');

                if (res.ok) {
                    otpSection.classList.remove('hidden');
                    mobileInput.disabled = true;
                    otpInput.focus();
                    sendBtn.disabled = true;
                    setStatus('OTP sent', 'Step 2 of 2');
                    startResendTimer(60);
                } else {
                    setStatus('Ready', 'Step 1 of 2');
                }
            } catch (e) {
                showToast('Failed to send OTP', 'error');
                setStatus('Ready', 'Step 1 of 2');
            } finally {
                hideSpinner();
            }
        });

        resendBtn.addEventListener('click', () => {
            if (!resendBtn.disabled) {
                sendBtn.click();
            }
        });

        verifyBtn.addEventListener('click', async () => {
            const otp = otpInput.value.trim();
            const mobile = mobileInput.value.trim();

            if (!otp) {
                showToast('Enter OTP', 'error');
                return;
            }

            showSpinner('Verifying OTP…');
            setStatus('Verifying OTP', 'Step 2 of 2');

            try {
                const res = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `mobile=${encodeURIComponent(mobile)}&otp=${encodeURIComponent(otp)}`
                });
                const data = await res.json();
                showToast(data.message || data.error || 'Login response received', res.ok ? 'info' : 'error');

                if (res.ok) {
                    loginUI.classList.add('hidden');
                    postLoginActions.classList.remove('hidden');
                    pageTitle.innerText = 'Login complete';
                    subtitle.innerText = 'Your account is now active on this server.';
                    signedInUser.innerText = data.subscriber_name || 'User';
                    signedInInfo.innerText = `Subscriber ID: ${data.subscriber_id || 'N/A'}`;
                    setStatus('Signed in', 'Session active');
                    resetOtpTimer();
                }
            } catch (e) {
                showToast('Failed to verify OTP', 'error');
                setStatus('OTP verification failed', 'Step 2 of 2');
            } finally {
                hideSpinner();
            }
        });

        otpInput.addEventListener('input', () => {
            const value = otpInput.value.trim();
            if (value.length === 4) {
                verifyBtn.click();
            }
        });

        clearBtn.addEventListener('click', clearForm);

        mobileInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !sendBtn.disabled) {
                sendBtn.click();
            }
        });

        otpInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                verifyBtn.click();
            }
        });

        document.getElementById('logoutBtn').addEventListener('click', async () => {
            showSpinner('Logging out…');
            try {
                const res = await fetch('/logout', { method: 'POST' });
                const data = await res.json();
                showToast(data.message || 'Logged out', res.ok ? 'info' : 'error');
                if (res.ok) {
                    clearForm();
                    await fetchLoginState();
                    setTimeout(() => location.reload(), 700);
                }
            } catch (e) {
                showToast('Logout failed', 'error');
            } finally {
                hideSpinner();
            }
        });
    </script>
</body>
</html>'''


@app.route("/login", methods=['GET', 'POST'])
def login():
    """Login page (GET) or login API (POST)"""
    if request.method == 'GET':
        return LOGIN_HTML, 200, {'Content-Type': 'text/html; charset=utf-8'}
    
    # Handle POST request
    return login_post()


def login_post():
    """Login with mobile number and OTP"""
    global PLATFORM_TOKEN, SUBSCRIBER_ID, SUBSCRIBER_NAME, DEVICE_ID, PROFILE_ID, DEVICE_DETAILS, API_HEADERS
    
    mobile = request.form.get('mobile', '').strip()
    otp = request.form.get('otp', '').strip()
    
    # Validate inputs
    if not mobile or not re.match(r'^[6-9]\d{9}$', mobile):
        return jsonify({"error": "Invalid mobile number"}), 400
    
    if not otp or not re.match(r'^\d{4,6}$', otp):
        return jsonify({"error": "Invalid OTP"}), 400
    
    try:
        # Get/create guest device
        guest_cred = get_or_create_guest_device()
        if not guest_cred:
            return jsonify({"error": "Failed to register device"}), 500
        
        device_id = guest_cred['deviceId']
        anonymous_id = guest_cred['anonymousId']
        
        # Validate OTP
        validate_url = 'https://tb.tapi.videoready.tv/binge-mobile-services/pub/api/v1/user/authentication/validateOTP'
        validate_headers = {
            'accept': 'application/json, text/plain, */*',
            'anonymousid': anonymous_id,
            'content-type': 'application/json',
            'deviceid': device_id,
            'origin': 'https://www.tataplaybinge.com',
            'platform': 'BINGE_ANYWHERE',
            'referer': 'https://www.tataplaybinge.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        }
        
        body = json.dumps({"mobileNumber": mobile, "otp": otp})
        r = http_post(validate_url, data=body, headers=validate_headers, timeout=15)
        
        if not r.ok or r.status_code != 200:
            return jsonify({"error": f"OTP validation failed: {r.status_code}"}), 400
        
        validate_data = r.json()
        if 'data' not in validate_data or 'userAuthenticateToken' not in validate_data['data']:
            return jsonify({"error": "Invalid OTP response"}), 400
        
        user_token = validate_data['data']['userAuthenticateToken']
        device_token = validate_data['data'].get('deviceAuthenticateToken', '')
        
        # Get subscriber details
        sub_url = 'https://tb.tapi.videoready.tv/binge-mobile-services/api/v4/subscriber/details'
        sub_headers = {
            'accept': 'application/json, text/plain, */*',
            'anonymousid': anonymous_id,
            'authorization': f'bearer {user_token}',
            'devicetype': 'WEB',
            'mobilenumber': mobile,
            'origin': 'https://www.tataplaybinge.com',
            'platform': 'BINGE_ANYWHERE',
            'referer': 'https://www.tataplaybinge.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        }
        
        r = http_get(sub_url, headers=sub_headers, timeout=15)
        if not r.ok:
            return jsonify({"error": "Failed to fetch subscriber details"}), 400
        
        sub_data = r.json()
        account_details = sub_data.get('data', {}).get('accountDetails', [{}])[0]
        dth_status = account_details.get('dthStatus', '')
        
        # Prepare login payload based on account type
        login_url = ''
        login_payload = {}
        
        if not dth_status:
            login_url = 'https://tb.tapi.videoready.tv/binge-mobile-services/api/v3/create/new/user'
            login_payload = {
                'dthStatus': 'Non DTH User',
                'subscriberId': mobile,
                'login': 'OTP',
                'mobileNumber': mobile,
                'isPastBingeUser': False,
                'eulaChecked': True,
                'packageId': ''
            }
        elif dth_status == 'DTH Without Binge':
            login_url = 'https://tb.tapi.videoready.tv/binge-mobile-services/api/v3/create/new/user'
            login_payload = {
                'dthStatus': 'DTH Without Binge',
                'subscriberId': account_details.get('subscriberId', ''),
                'login': 'OTP',
                'mobileNumber': mobile,
                'baId': None,
                'isPastBingeUser': False,
                'eulaChecked': True,
                'packageId': '',
                'referenceId': None
            }
        else:
            login_url = 'https://tb.tapi.videoready.tv/binge-mobile-services/api/v3/update/exist/user'
            login_payload = {
                'dthStatus': dth_status,
                'subscriberId': account_details.get('subscriberId', ''),
                'bingeSubscriberId': account_details.get('bingeSubscriberId', ''),
                'baId': account_details.get('baId', ''),
                'login': 'OTP',
                'mobileNumber': mobile,
                'payment_return_url': 'https://www.tataplaybinge.com/subscription-transaction/status',
                'eulaChecked': True,
                'packageId': ''
            }
        
        login_headers = {
            'accept': 'application/json, text/plain, */*',
            'anonymousid': anonymous_id,
            'authorization': f'bearer {user_token}',
            'content-type': 'application/json',
            'device': 'WEB',
            'deviceid': device_id,
            'devicename': 'Web',
            'devicetoken': device_token,
            'origin': 'https://www.tataplaybinge.com',
            'platform': 'WEB',
            'referer': 'https://www.tataplaybinge.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        }
        
        r = http_post(login_url, data=json.dumps(login_payload), headers=login_headers, timeout=15)
        
        if not r.ok:
            return jsonify({"error": f"Login failed: {r.status_code}"}), 400
        
        login_response = r.json()
        login_response['deviceId'] = device_id
        
        # Save login credentials
        login_file = os.path.join(os.path.dirname(__file__), "login.json")
        os.makedirs(os.path.dirname(login_file), exist_ok=True)
        with open(login_file, 'w') as f:
            json.dump(login_response, f, indent=2)
        
        # Update global credentials
        PLATFORM_TOKEN = login_response.get('data', {}).get('userAuthenticateToken', FALLBACK_PLATFORM_TOKEN)
        account = login_response.get('data', {}).get('accountDetails', [{}])[0]
        SUBSCRIBER_ID = account.get('subscriberId', FALLBACK_SUBSCRIBER_ID)
        SUBSCRIBER_NAME = account.get('subscriberName', FALLBACK_SUBSCRIBER_NAME)
        DEVICE_ID = device_id
        PROFILE_ID = account.get('profileId', FALLBACK_PROFILE_ID)
        
        DEVICE_DETAILS['device_id'] = DEVICE_ID
        DEVICE_DETAILS['sname'] = SUBSCRIBER_NAME
        API_HEADERS = get_api_headers()
        
        logger.info(f"✅ Login successful: {SUBSCRIBER_NAME}")
        
        return jsonify({
            "message": "Logged in successfully",
            "subscriber_name": SUBSCRIBER_NAME,
            "subscriber_id": SUBSCRIBER_ID
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({"error": f"Login failed: {str(e)}"}), 500


@app.route("/logout", methods=['POST'])
def logout():
    """Logout and clear stored credentials"""
    global PLATFORM_TOKEN, SUBSCRIBER_ID, SUBSCRIBER_NAME, DEVICE_ID, PROFILE_ID, DEVICE_DETAILS, API_HEADERS
    
    try:
        login_file = os.path.join(os.path.dirname(__file__), "login.json")
        if os.path.exists(login_file):
            os.remove(login_file)
            logger.info("🚪 Logout: login.json removed")
        
        # Reset to fallback credentials
        PLATFORM_TOKEN = FALLBACK_PLATFORM_TOKEN
        SUBSCRIBER_ID = FALLBACK_SUBSCRIBER_ID
        SUBSCRIBER_NAME = FALLBACK_SUBSCRIBER_NAME
        DEVICE_ID = FALLBACK_DEVICE_ID
        PROFILE_ID = FALLBACK_PROFILE_ID
        
        DEVICE_DETAILS['device_id'] = DEVICE_ID
        DEVICE_DETAILS['sname'] = SUBSCRIBER_NAME
        API_HEADERS = get_api_headers()
        
        # Clear caches
        global CHANNEL_CACHE, JWT_CACHE, KEY_CACHE
        CHANNEL_CACHE = None
        JWT_CACHE.clear()
        KEY_CACHE.clear()
        
        return jsonify({"message": "Logged out successfully"}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({"error": f"Logout failed: {str(e)}"}), 500


@app.route("/check-login", methods=['GET'])
def check_login():
    """Check if user is logged in"""
    login_file = os.path.join(os.path.dirname(__file__), "login.json")
    if os.path.exists(login_file):
        try:
            with open(login_file, 'r') as f:
                login_data = json.load(f)
            account = login_data.get('data', {}).get('accountDetails', [{}])[0]
            user_name = account.get('subscriberName', 'User')
            return jsonify({"logged_in": True, "user": user_name}), 200
        except Exception:
            pass
    return jsonify({"logged_in": False}), 200


@app.route("/send-otp", methods=['POST'])
def send_otp():
    """Send OTP to mobile number"""
    mobile = request.form.get('mobile', '').strip()
    
    if not mobile or not re.match(r'^[6-9]\d{9}$', mobile):
        return jsonify({"error": "Invalid mobile number"}), 400
    
    try:
        # Get/create guest device
        guest_cred = get_or_create_guest_device()
        if not guest_cred:
            return jsonify({"error": "Failed to register device"}), 500
        
        device_id = guest_cred['deviceId']
        anonymous_id = guest_cred['anonymousId']
        
        # Send OTP
        url = 'https://tb.tapi.videoready.tv/binge-mobile-services/pub/api/v1/user/authentication/generateOTP'
        headers = {
            'accept': 'application/json, text/plain, */*',
            'anonymousid': anonymous_id,
            'content-length': '0',
            'deviceid': device_id,
            'mobilenumber': mobile,
            'newotpflow': '4DOTP',
            'origin': 'https://www.tataplaybinge.com',
            'platform': 'BINGE_ANYWHERE',
            'referer': 'https://www.tataplaybinge.com/',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        }
        
        r = http_post(url, headers=headers, timeout=15)
        
        if r.ok:
            data = r.json()
            message = data.get('message', 'OTP sent')
            return jsonify({"message": message}), 200
        else:
            return jsonify({"error": f"Failed to send OTP: {r.status_code}"}), 400
            
    except Exception as e:
        logger.error(f"Send OTP error: {e}")
        return jsonify({"error": f"Failed to send OTP: {str(e)}"}), 500


@app.route("/debug/<int:channel_id>")
def debug_channel(channel_id):
    info = {}
    data = {}

    try:
        data = get_player_data(channel_id)
        info["official"] = {}
        for k, v in data.items():
            info["official"][k] = str(v)[:200] if v else "empty"
            if v and isinstance(v, str) and len(v) > 20:
                dec = decrypt_aes_ecb(v)
                if dec:
                    info["official"][f"{k}__DEC"] = dec[:200]
    except Exception as e:
        info["official"] = f"error: {e}"

    # MPD + hdntl test
    mpd_enc = data.get("dashWidewinePlayUrl") or data.get("dashWidevinePlayUrl") or data.get("dashPlayreadyPlayUrl") or ""
    if mpd_enc:
        mpd_url = decrypt_aes_ecb(mpd_enc)
        if mpd_url:
            info["mpd_url"] = mpd_url[:250]
            try:
                r = http_get(mpd_url, headers=CDN_HEADERS, timeout=10)
                info["mpd_status"] = r.status_code
                if r.status_code >= 400:
                    log_upstream_http_failure("Debug MPD fetch failed", mpd_url, r)
                hdntl = extract_hdntl(r)
                info["hdntl"] = hdntl[:80] if hdntl else "not found"
                info["response_cookies"] = dict(r.cookies)
                info["set_cookie_header"] = r.headers.get("Set-Cookie", "none")[:200]
                if r.ok:
                    pssh_list = extract_all_pssh_from_mpd(r.text)
                    info["pssh_count"] = len(pssh_list)
                    info["pssh_samples"] = [p[:60] for p in pssh_list[:3]]
                    kids = extract_all_kids_from_mpd(r.text)
                    info["kids"] = kids
                    info["has_kid"] = len(kids) > 0
            except Exception as e:
                info["mpd_test"] = f"error: {e}"

    # JWT + license test
    ch = find_channel(channel_id)
    if ch:
        epids = get_channel_epids(ch)
        info["epids"] = epids

    jwt = get_jwt_token(channel_id)
    info["jwt"] = (jwt[:50] + "...") if jwt else "FAILED"

    if jwt:
        lic_enc = data.get("dashWidewineLicenseUrl") or ""
        lic_url = decrypt_aes_ecb(lic_enc) if lic_enc else None
        if lic_url:
            lic_with_jwt = append_or_replace_query_params(lic_url, {"ls_session": jwt})
            info["license_url"] = lic_with_jwt[:200]
            try:
                test = http_post(lic_with_jwt, data=b'\x08\x04',
                    headers={"content-type": "application/octet-stream",
                             "origin": "https://watch.tataplay.com",
                             "referer": "https://watch.tataplay.com/",
                             "user-agent": "Mozilla/5.0"}, timeout=10)
                info["license_test"] = f"{test.status_code}: {test.text[:100]}"
            except Exception as e:
                info["license_test"] = f"error: {e}"

    ygx = find_ygx_channel(channel_id)
    info["ygx"] = {"name": ygx.get("name"),
                    "manifest_url": ygx.get("manifest_url", "")[:150],
                    "license_url": ygx.get("license_url", "")[:150]} if ygx else "not found"

    return {"channel_id": channel_id, "data": info}


@app.route("/playlist.mpd")
def playlist():
    ch_id = request.args.get("id")
    begin = request.args.get("begin")
    end = request.args.get("end")

    if not ch_id:
        return "Missing 'id'. Try /channels or /playlist.mpd?id=8", 400

    try:
        stream = get_stream_info(ch_id, begin, end)
        mpd_url = stream["mpd_url"]
        hdntl = stream.get("hdntl")
        source = stream.get("source", "?")

        logger.info(f"📄 [{source}] Fetching MPD...")

        r = http_get(mpd_url, headers=stream.get("manifest_headers", CDN_HEADERS), timeout=15)
        if not r.ok:
            # Fallback for some origins that require `/Manifest` instead of `/manifest`
            if "/manifest" in mpd_url:
                mpd_url_retry = mpd_url.replace("/manifest", "/Manifest")
                logger.info("↩️ MPD retry with /Manifest path")
                r = http_get(mpd_url_retry, headers=stream.get("manifest_headers", CDN_HEADERS), timeout=15)
                if r.ok:
                    mpd_url = mpd_url_retry
            log_upstream_http_failure("Playlist MPD fetch failed", mpd_url, r)
            if not r.ok:
                return f"MPD fetch failed: {r.status_code}", 502
        mpd = r.text

        # Try to extract hdntl from this response too
        if not hdntl:
            hdntl = extract_hdntl(r)

        logger.info(f"✅ MPD fetched ({len(mpd)} bytes), hdntl={'yes' if hdntl else 'no'}")

        # Resolve base URL from MPD
        parsed_mpd = urlparse(mpd_url)
        mpd_dir = f"{parsed_mpd.scheme}://{parsed_mpd.netloc}{parsed_mpd.path.rsplit('/', 1)[0]}/"

        # Get BaseURL from MPD (might be relative like "dash/")
        bm = re.search(r"<BaseURL>(.*?)</BaseURL>", mpd)
        mpd_base_url = bm.group(1) if bm else ""

        # Resolve to absolute URL
        if mpd_base_url and not mpd_base_url.startswith("http"):
            cdn_base = mpd_dir + mpd_base_url
        elif mpd_base_url:
            cdn_base = mpd_base_url
        else:
            cdn_base = mpd_dir

        if not cdn_base.endswith("/"):
            cdn_base += "/"

        # Append hdntl to base URL for segment auth
        if hdntl:
            cdn_base_with_auth = f"{cdn_base}?{hdntl}"
        else:
            # Use hdnea from MPD URL as fallback
            if parsed_mpd.query:
                cdn_base_with_auth = f"{cdn_base}?{parsed_mpd.query}"
            else:
                cdn_base_with_auth = cdn_base

        logger.info(f"🔗 CDN base: {cdn_base_with_auth[:120]}...")

        b64_base = base64.urlsafe_b64encode(cdn_base_with_auth.encode()).decode()

        # Strip global BaseURL from MPD
        mpd = re.sub(r"<BaseURL>.*?</BaseURL>", "", mpd)

        # PSSH extraction - get ALL PSSH values
        pssh_list = extract_all_pssh_from_mpd(mpd)
        logger.info(f"🔐 Found {len(pssh_list)} PSSH(s) in MPD")

        # If no PSSH in MPD, try extracting from init segment
        if not pssh_list:
            logger.info("🔍 No PSSH in MPD, trying init segment...")
            pssh_b64, kid_uuid = fetch_pssh_from_init_segment(mpd, cdn_base, hdntl)
            if pssh_b64:
                pssh_list = [pssh_b64]
                logger.info(f"✅ Got PSSH from init: KID={kid_uuid}")

        # Fetch Widevine keys for ALL PSSH values
        if pssh_list and stream.get("is_drm", True):
            all_keys = fetch_all_widevine_keys(
                pssh_list,
                stream["license_url"],
                stream["license_headers"],
                channel_id=stream.get("channel_id"),
            )
            if all_keys:
                logger.info(f"✅ Got {len(all_keys)} key(s) total")
                for kid, key in all_keys.items():
                    logger.info(f"🔑 KID={kid} KEY={key}")
            else:
                logger.warning("⚠️ No keys obtained")

        # Also extract KIDs from MPD and try to get keys if we don't have them
        mpd_kids = extract_all_kids_from_mpd(mpd)
        missing_kids = [k for k in mpd_kids if not lookup_key(k)]
        if missing_kids:
            logger.warning(f"⚠️ Missing keys for KIDs: {missing_kids}")

        # Rewrite AdaptationSets
        def rewrite(match):
            block = match.group(1)
            km = re.search(r'cenc:default_KID="([0-9a-fA-F-]+)"', block)
            kid_value = km.group(1) if km else "NONE"
            b64_kid = base64.urlsafe_b64encode(kid_value.encode()).decode()
            proxy = f"{request.host_url}segment/{b64_kid}/{b64_base}/"
            ins = block.find(">") + 1
            block = block[:ins] + f"<BaseURL>{proxy}</BaseURL>" + block[ins:]
            block = re.sub(r'<ContentProtection.*?>.*?</ContentProtection>', '', block, flags=re.DOTALL)
            block = re.sub(r'<ContentProtection.*?/>', '', block)
            return block

        mpd = re.sub(r'(<AdaptationSet.*?</AdaptationSet>)', rewrite, mpd, flags=re.DOTALL)
        mpd = mpd.replace('xmlns:cenc="urn:mpeg:cenc:2013"', '')
        mpd = mpd.replace('xmlns:cenc="urn:mpe:cenc:2013"', '')

        resp = Response(mpd, mimetype="application/dash+xml")
        resp.headers["Content-Disposition"] = f"attachment; filename=tp{ch_id}.mpd"
        return resp

    except Exception as e:
        logger.error(f"❌ {e}", exc_info=True)
        return f"Error: {e}", 500


@app.route("/segment/<b64_kid>/<b64_base>/<path:filename>")
def segment_handler(b64_kid, b64_base, filename):
    try:
        remote_base = base64.urlsafe_b64decode(b64_base).decode()
        kid_str = base64.urlsafe_b64decode(b64_kid).decode()
    except Exception:
        return "Bad encoding", 400

    # Build target URL — base already has auth token in query
    if "?" in remote_base:
        bp, q = remote_base.split("?", 1)
        if not bp.endswith("/"):
            bp += "/"
        target = f"{bp}{filename}?{q}"
    else:
        if not remote_base.endswith("/"):
            remote_base += "/"
        target = f"{remote_base}{filename}"

    if request.query_string:
        sep = "&" if "?" in target else "?"
        target += f"{sep}{request.query_string.decode()}"

    try:
        r = http_get(target, headers=CDN_HEADERS, timeout=15)
        if not r.ok:
            logger.warning(f"Segment {r.status_code}: {target[:120]}")
            return f"Segment {r.status_code}", r.status_code
    except Exception as e:
        return f"Net: {e}", 502

    data = r.content

    # Init segments - extract KID if present and try to get key
    if filename.endswith(".dash") or "init" in filename.lower():
        # Try to extract KID from init segment for dynamic key lookup
        pssh_b64, kid_uuid = extract_pssh_from_segment(data)
        if kid_uuid:
            kid_norm = normalize_kid(kid_uuid)
            if kid_norm and not lookup_key(kid_norm):
                logger.info(f"🔍 Init segment has KID {kid_norm} but no key cached")
        return Response(data, content_type="application/octet-stream")

    if kid_str == "NONE":
        return Response(data, content_type="video/mp4")

    key_hex = lookup_key(kid_str)
    if not key_hex:
        logger.warning(f"⚠️ No key for KID: {kid_str}")
        return Response(data, content_type="video/mp4")

    try:
        decrypted = CENCParser(data, key_hex).decrypt()
        return Response(bytes(decrypted), content_type="video/mp4")
    except Exception as e:
        logger.error(f"Decrypt error: {e}")
        return Response(data, content_type="video/mp4")


# ================================================================

if __name__ == "__main__":
    load_credentials()
    get_ygx_channels()
    print("=" * 60)
    print("  Tata Play DRM Proxy")
    print("=" * 60)
    print(f"  CDM:      {'✅' if WV_CDM else '❌'}")
    print(f"  YGX:      {len(YGX_CACHE) if YGX_CACHE else 0} channels")
    print(f"  User:     {SUBSCRIBER_NAME}")
    print("=" * 60)
    print("  Endpoints:")
    print("    /login (POST mobile, otp)")
    print("    /send-otp (POST mobile)")
    print("    /logout (POST)")
    print("    /playlist.mpd?id=<channel_id>")
    print("    /playlist.mpd?id=<channel_id>&begin=<ts>&end=<ts>")
    print("    /channels")
    print("    /keys")
    print("    /debug/<channel_id>")
    print("    /health")
    print("=" * 60)
    print("  Timestamp formats for begin/end:")
    print("    Unix:   1749192000")
    print("    Date:   06/06/2025+10:00:00")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8080, threaded=True)
