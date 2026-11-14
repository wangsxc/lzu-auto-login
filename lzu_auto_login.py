#!/usr/bin/env python3
"""
LZU/iLZU 校园网自动登录脚本（深澜 srun V1.18 协议）
自动检测网络并完成认证。

用法:
    python lzu_auto_login.py              一次检测并登录
    python lzu_auto_login.py --watch      持续监控模式
    python lzu_auto_login.py --test       仅检测网络状态
    python lzu_auto_login.py --logout     注销登录
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
import urllib.parse

# ============================================================
# 配置（凭据来自 config.json，该文件已被 .gitignore 排除）
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.environ.get("LZU_CONFIG") or os.path.join(SCRIPT_DIR, "config.json")


def _load_config():
    if not os.path.exists(CONFIG_FILE):
        raise SystemExit(
            f"缺少配置文件: {CONFIG_FILE}\n"
            "请复制 config.example.json 为 config.json 并填写账号密码。"
        )
    with open(CONFIG_FILE, encoding="utf-8") as f:
        return json.load(f)


_CFG = _load_config()

USERNAME = os.environ.get("LZU_USERNAME") or _CFG["username"]
PASSWORD = os.environ.get("LZU_PASSWORD") or _CFG["password"]
DOMAIN = _CFG.get("domain", "@study")        # @eLearning -> "@study"；@lzu.edu.cn -> ""
PORTAL_HOST = _CFG.get("portal_host", "10.10.0.166")
AC_ID = str(_CFG.get("ac_id", "2"))
TARGET_SSIDS = _CFG.get("target_ssids", [])  # 空列表 = 不限制 SSID
CHECK_INTERVAL = int(_CFG.get("check_interval", 60))
LOGIN_COOLDOWN = int(_CFG.get("login_cooldown", 1800))
ONLINE_PROBE = bool(_CFG.get("online_probe", True))  # False = 跳过外网探活（测试环境）
LOG_FILE = os.path.join(SCRIPT_DIR, _CFG.get("log_file", "lzu_auto_login.log"))

# ============================================================
# 日志（轮转 + 脱敏，避免明文凭据无限落盘）
# ============================================================
from logging.handlers import RotatingFileHandler

logger = logging.getLogger("lzu_login")
logger.setLevel(logging.DEBUG)

fh = RotatingFileHandler(
    LOG_FILE, maxBytes=1024 * 1024, backupCount=3, encoding="utf-8"
)
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
logger.addHandler(ch)


# ============================================================
# 网络工具
# ============================================================
def get_windows_ssid():
    try:
        output = subprocess.check_output(
            ["netsh", "wlan", "show", "interfaces"],
            encoding="utf-8", errors="replace",
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        for line in output.splitlines():
            m = re.search(r"SSID\s*:\s*(.+)", line, re.IGNORECASE)
            if m:
                return m.group(1).strip()
    except Exception as e:
        logger.debug(f"获取 SSID 失败: {e}")
    return None


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        # PORTAL_HOST 可能带端口（测试环境 127.0.0.1:8899），UDP 探测只取主机部分
        s.connect((PORTAL_HOST.split(":", 1)[0], 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"


def can_reach(host, timeout=5):
    try:
        url = f"http://{host}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False


def is_online():
    test_urls = [
        "http://www.baidu.com/",
        "http://captive.apple.com/hotspot-detect.html",
    ]
    for url in test_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            content = resp.read().decode(errors="replace")
            if "captive.apple.com" in url and "Success" in content:
                return True
            if resp.getcode() == 200 and len(content) > 500:
                return True
        except Exception:
            continue
    return False


# ============================================================
# HTTP 工具
# ============================================================
def _http_get(url, timeout=10):
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _http_post(url, data, timeout=10):
    post_data = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=post_data,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _parse_jsonp(text):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError(f"无法解析 JSONP 响应: {text[:200]}")
    return json.loads(match.group())


# ============================================================
# Srun 自定义 Base64（字母表来自 Portal.js）
# ============================================================
SRUN_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_TRANS = str.maketrans(STD_ALPHA, SRUN_ALPHA)
_TRANS_REV = str.maketrans(SRUN_ALPHA, STD_ALPHA)


def _srun_base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode().translate(_TRANS)


def _srun_base64_decode(s: str) -> bytes:
    return base64.b64decode(s.translate(_TRANS_REV))


# ============================================================
# XTEA 编码（来自 Portal.js encode 函数）
# ============================================================
def _s(x: str, length_prefix: bool) -> list:
    """将字符串转为 uint32 小端数组。"""
    v = []
    c = len(x)
    for i in range(0, c, 4):
        chars = x[i : i + 4]
        val = 0
        for j, ch in enumerate(chars):
            val |= ord(ch) << (j * 8)
        v.append(val)
    if length_prefix:
        v.append(c)
    return v


def _l(a: list, length_prefix: bool) -> str:
    """将 uint32 小端数组转回字符串。"""
    result = []
    for val in a:
        result.append(chr(val & 0xFF))
        result.append(chr((val >> 8) & 0xFF))
        result.append(chr((val >> 16) & 0xFF))
        result.append(chr((val >> 24) & 0xFF))
    s = "".join(result)
    if length_prefix:
        d = len(a)
        c = (d - 1) << 2
        m = a[d - 1]
        if m < c - 3 or m > c:
            return ""  # null in JS
        c = m
        return s[:c]
    return s


def _xtea_encode(msg: str, key: str) -> str:
    """XTEA 编码（与 Portal.js encode 完全一致）。"""
    if not msg:
        return ""

    v = _s(msg, True)   # 消息 → uint32，带长度前缀
    k = _s(key, False)  # 密钥 → uint32
    if len(k) < 4:
        k += [0] * (4 - len(k))

    n = len(v) - 1
    z = v[n]
    y = v[0]
    delta = 0x9E3779B9
    q = 6 + 52 // (n + 1)
    d = 0

    while q > 0:
        q -= 1
        d = (d + delta) & 0xFFFFFFFF
        e = (d >> 2) & 3

        for p in range(n):
            y = v[p + 1]
            m = (z >> 5) ^ (y << 2)
            m += (y >> 3) ^ (z << 4) ^ (d ^ y)
            m += k[p & 3 ^ e] ^ z
            z = v[p] = (v[p] + m) & 0xFFFFFFFF

        # After JS for(p=0; p<n; p++), p === n, but in Python p is n-1
        # Use n directly for correct k index
        y = v[0]
        m = (z >> 5) ^ (y << 2)
        m += (y >> 3) ^ (z << 4) ^ (d ^ y)
        m += k[n & 3 ^ e] ^ z
        z = v[n] = (v[n] + m) & 0xFFFFFFFF

    return _l(v, False)


# ============================================================
# Srun 认证协议
# ============================================================
def _get_challenge():
    """获取 challenge token。"""
    username = f"{USERNAME}{DOMAIN}"
    ip = get_local_ip()
    timestamp = int(time.time() * 1000)

    url = (
        f"http://{PORTAL_HOST}/cgi-bin/get_challenge"
        f"?callback=jQuery"
        f"&username={urllib.parse.quote(username)}"
        f"&ip={ip}"
        f"&_={timestamp}"
    )

    logger.debug(f"请求 challenge: {url}")
    resp = _http_get(url)
    data = _parse_jsonp(resp)
    logger.debug(f"Challenge 原始响应: {resp[:300]}")

    if data.get("ecode") != 0:
        raise RuntimeError(
            f"Challenge 失败: {data.get('error', 'unknown')} (ecode={data.get('ecode')})"
        )

    challenge = data["challenge"]
    client_ip = data.get("client_ip", ip)
    logger.info(f"challenge={challenge[:20]}..., client_ip={client_ip}")
    return challenge, client_ip


def srun_login():
    """执行深澜认证登录。"""
    logger.info("===== 开始登录流程 =====")

    challenge, client_ip = _get_challenge()

    username = f"{USERNAME}{DOMAIN}"

    # --- 密码编码: {MD5} + HMAC-MD5(token, raw_password) 的十六进制 ---
    # md5(data, key) = hex(HMAC-MD5(key=key, data=data))
    hmac_hex = hmac.new(
        challenge.encode(), PASSWORD.encode(), hashlib.md5
    ).hexdigest()
    encoded_password = "{MD5}" + hmac_hex

    logger.debug(f"HMAC-MD5(token, raw_password)={hmac_hex}")

    # --- Info 字段: XTEA 编码 + 自定义 base64 ---
    n_val = "200"
    type_val = "1"
    enc_ver = "srun_bx1"

    info_obj = {
        "username": username,
        "password": PASSWORD,  # 原始密码
        "ip": client_ip,
        "acid": AC_ID,
        "enc_ver": enc_ver,
    }
    info_json = json.dumps(info_obj, separators=(",", ":"))
    logger.debug("info_json=<含明文密码，已脱敏，不记录>")

    encoded_info = _xtea_encode(info_json, challenge)
    info_field = "{SRBX1}" + _srun_base64_encode(encoded_info.encode("latin-1"))

    logger.debug(f"info_field={info_field[:80]}...")

    # --- 校验和: SHA1 ---
    chkstr = (
        challenge + username
        + challenge + hmac_hex
        + challenge + AC_ID
        + challenge + client_ip
        + challenge + n_val
        + challenge + type_val
        + challenge + info_field
    )
    chksum = hashlib.sha1(chkstr.encode()).hexdigest()

    logger.debug(f"chkstr (first 200)={chkstr[:200]}")
    logger.debug(f"chksum={chksum}")

    # --- 提交登录 ---
    login_data = {
        "action": "login",
        "username": username,
        "password": encoded_password,
        "ac_id": AC_ID,
        "ip": client_ip,
        "info": info_field,
        "chksum": chksum,
        "n": n_val,
        "type": type_val,
    }

    login_url = f"http://{PORTAL_HOST}/cgi-bin/srun_portal"
    logger.debug(f"POST {login_url}")

    resp = _http_post(login_url, login_data)
    logger.debug(f"登录响应: {resp[:400]}")

    # 登录响应有两种格式:
    #   1. JSONP: jQuery({ecode:0, res:"ok", suc_msg:"..."})
    #   2. CSV:   login_ok,...  或  login_error,...
    if resp.startswith("login_ok"):
        logger.info("登录成功 (login_ok)")
        return True, "登录成功"
    elif resp.startswith("login_error"):
        logger.warning(f"登录失败: {resp}")
        return False, resp
    elif resp.startswith("login_") and "error" in resp:
        # login_error,msg,...
        parts = resp.split(",")
        err = parts[1] if len(parts) > 1 else resp
        logger.warning(f"登录失败: {err}")
        return False, err

    # 尝试 JSONP 解析
    try:
        result = _parse_jsonp(resp)
    except ValueError:
        logger.warning(f"无法识别的登录响应: {resp[:200]}")
        return False, f"无法识别的响应: {resp[:100]}"

    if result.get("ecode") == 0 or result.get("res") == "ok":
        succ_msg = result.get("suc_msg", "登录成功")
        logger.info(f"登录成功: {succ_msg}")
        return True, succ_msg
    else:
        err = result.get("error_msg") or result.get("error") or "未知错误"
        logger.warning(f"登录失败: {err}")
        return False, err


def srun_logout():
    """注销登录。"""
    logger.info("===== 开始注销 =====")
    challenge, client_ip = _get_challenge()
    username = f"{USERNAME}{DOMAIN}"

    logout_data = {
        "action": "logout",
        "username": username,
        "ac_id": AC_ID,
        "ip": client_ip,
    }
    url = f"http://{PORTAL_HOST}/cgi-bin/srun_portal"
    resp = _http_post(url, logout_data)
    logger.info(f"注销响应: {resp[:200]}")
    return True


# ============================================================
# 主逻辑
# ============================================================
def check_and_login():
    """检测网络并在需要时自动登录。"""
    if TARGET_SSIDS:
        ssid = get_windows_ssid()
        logger.info(f"当前 SSID: {ssid}")
        if not ssid:
            return False, "无法获取 SSID（未连接 WiFi？）"
        if ssid not in TARGET_SSIDS:
            return False, f"未连接目标网络（当前: {ssid}），跳过。"
        logger.info(f"已连接目标网络: {ssid}")
    else:
        logger.info("未配置 SSID 白名单，跳过网络名检查")

    if ONLINE_PROBE and is_online():
        logger.info("网络已通，无需登录。")
        return False, "已在线"

    if not can_reach(PORTAL_HOST):
        return False, f"无法连接认证服务器 {PORTAL_HOST}"

    logger.info("检测到 captive portal，开始自动登录...")

    try:
        success, msg = srun_login()
        return success, msg
    except Exception as e:
        logger.error(f"登录异常: {e}", exc_info=True)
        return False, str(e)


def watch_loop():
    """持续监控模式。"""
    logger.info("启动监控模式（Ctrl+C 退出）...")
    print(f"[提示] 正在监控网络，按 Ctrl+C 退出。日志: {LOG_FILE}")

    last_login_time = 0

    while True:
        try:
            if time.time() - last_login_time < LOGIN_COOLDOWN:
                time.sleep(CHECK_INTERVAL)
                continue

            success, msg = check_and_login()
            if success:
                last_login_time = time.time()
                logger.info(f"冷却 {LOGIN_COOLDOWN}s 后恢复检测...")
        except KeyboardInterrupt:
            logger.info("监控模式已退出。")
            break
        except Exception as e:
            logger.error(f"监控异常: {e}")

        time.sleep(CHECK_INTERVAL)


def main():
    if "--test" in sys.argv:
        print(f"SSID:            {get_windows_ssid()}")
        print(f"本机 IP:         {get_local_ip()}")
        print(f"认证服务器可达:   {can_reach(PORTAL_HOST)}")
        print(f"已在线:          {is_online()}")
        return

    if "--watch" in sys.argv:
        watch_loop()
    elif "--logout" in sys.argv:
        srun_logout()
    else:
        success, msg = check_and_login()
        if success:
            print(f"[OK] {msg}")
        else:
            print(f"[跳过] {msg}")
            sys.exit(1)


if __name__ == "__main__":
    main()
