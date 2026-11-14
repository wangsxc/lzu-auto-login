#!/usr/bin/env python3
"""
LZU/iLZU 校园网自动登录脚本（深澜 srun V1.18 协议）
自动检测网络并完成认证。

用法:
    python lzu_auto_login.py              --once：单次检测，跑完即退（默认）
    python lzu_auto_login.py --boot       开机守护：有界短时重试，跑完即退
    python lzu_auto_login.py --test       查看网络与认证状态
    python lzu_auto_login.py --logout     注销登录
    python lzu_auto_login.py --watch      调试用低频循环（生产不用）

设计：不常驻、不做轮询式外网探测。开机由启动项触发 --boot：
      先判断是否在目标网络，立即跑一次；随后 5 分钟每分钟一次，
      再后 30 分钟每 10 分钟一次，共 9 次后进程退出。
      每轮流程：已认证 -> 验联网；未认证 -> 先直接登录；
      仅当登录失败且确认是占用，才调 /cgi-bin/rad_user_dm 解绑并重试；
      服务端返回登录成功不算数，必须本机联网验证通过才算成功。
      解绑前若本机已能联网、冷却未过、或在线设备就是本机，一律拒绝，
      避免"自己把自己占用了又自己解除"的循环。
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
CHECK_INTERVAL = int(_CFG.get("check_interval", 1800))  # 仅 --watch 调试用
TARGET_SSIDS = _CFG.get("target_ssids", [])
SSID_FILTER = bool(_CFG.get("ssid_filter", False))      # 默认不按 SSID 过滤
RETRY_BACKOFF = _CFG.get("retry_backoff", [300, 900, 3600])  # 失败退避（秒）
# 开机后的有界短时守护：0 立即，随后 5 次 ×60s，再 3 次 ×600s，跑完即退出
BOOT_SCHEDULE = _CFG.get("boot_schedule", [0, 60, 60, 60, 60, 60, 600, 600, 600])
AUTO_RELEASE = bool(_CFG.get("auto_release", True))  # 账号被占用时自动解绑
RELEASE_COOLDOWN = int(_CFG.get("release_cooldown", 600))  # 两次解绑最小间隔
INTERNET_PROBE_URLS = _CFG.get("internet_probe_urls", [
    "http://www.baidu.com/",
    "http://captive.apple.com/hotspot-detect.html",
])
LAST_CLIENT_IP = ""  # Portal 侧看到的本机 IP，由 _get_challenge 写入
STATE_FILE = os.path.join(SCRIPT_DIR, _CFG.get("state_file", ".lzu_state.json"))
LOCK_PORT = int(_CFG.get("lock_port", 47621))
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


# 外网探活（baidu / captive.apple.com）已移除：
# 判活统一使用 Portal 自己的 /cgi-bin/rad_user_info，既准确又不访问外网。


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
    global LAST_CLIENT_IP
    LAST_CLIENT_IP = client_ip
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
_LOCK_SOCKET = None


def acquire_lock():
    """绑定本机端口做单实例锁：进程退出自动释放，不留残留锁文件。"""
    global _LOCK_SOCKET
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", LOCK_PORT))
        sock.listen(1)
        _LOCK_SOCKET = sock
        return True
    except OSError:
        sock.close()
        return False


def _read_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


def portal_status():
    """向 Portal 查询权威认证态，返回 (True/False/None, 在线信息)。"""
    url = f"http://{PORTAL_HOST}/cgi-bin/rad_user_info?callback=jsonp"
    try:
        data = _parse_jsonp(_http_get(url, timeout=5))
    except Exception as e:
        logger.debug(f"rad_user_info 查询失败: {e}")
        return None, {}
    online = data.get("error") == "ok" and bool(data.get("online_ip"))
    return online, data


# 账号被别的设备占用时，服务端常见的错误特征
_OCCUPY_HINTS = (
    "authentication success", "auth_info_error", "occupied",
    "already online", "max", "limit", "并发", "设备数",
)


def release_device(ip=""):
    """调用 /cgi-bin/rad_user_dm 解绑（踢下线）指定 IP 的在线设备。

    参数与 Portal.js 的 _logoutDm 一致：
        sign = sha1(time + username + ip + unbind + time), unbind = 1
    """
    username = f"{USERNAME}{DOMAIN}"
    ts = int(time.time())
    unbind = 1
    sign = hashlib.sha1(
        f"{ts}{username}{ip}{unbind}{ts}".encode()
    ).hexdigest()
    params = {
        "callback": "jQuery",
        "ip": ip,
        "username": username,
        "time": str(ts),
        "unbind": str(unbind),
        "sign": sign,
    }
    url = f"http://{PORTAL_HOST}/cgi-bin/rad_user_dm?" + urllib.parse.urlencode(params)
    logger.info(f"请求 DM 解绑下线: ip={ip or '<空>'}")
    resp = _http_get(url, timeout=8)
    logger.debug(f"DM 解绑响应: {resp[:200]}")
    return resp


def verify_internet():
    """单次验证本机是否真的能上网（不是轮询）。

    被 Portal 劫持时明文 HTTP 会 302 到认证主机，据此判定为"未通"。
    只在登录成功后、以及准备解绑前各调用一次。
    """
    portal_ip = PORTAL_HOST.split(":", 1)[0]
    for url in INTERNET_PROBE_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                final = resp.geturl()
                body = resp.read(4096).decode("utf-8", errors="replace")
            # 只有"跳到另一个主机上的 Portal"才算被劫持；
            # 测试环境探测地址本就与 mock Portal 同机，不能误判
            if (portal_ip
                    and urllib.parse.urlparse(final).hostname == portal_ip
                    and urllib.parse.urlparse(url).hostname != portal_ip):
                logger.debug(f"联网探测被劫持到 Portal: {final}")
                continue
            if "hotspot" in url or "__internet" in url:
                if "Success" in body:
                    return True
            elif len(body) > 200:
                return True
        except Exception as e:
            logger.debug(f"联网探测失败 {url}: {e}")
    return False


def _try_release(info, state):
    """仅在登录失败且疑似占用时调用；返回 (是否解绑, 说明)。

    三道保险，防止"自己把自己踢下线"再自己解一遍：
      1. 本机当前能联网        -> 绝不解除
      2. 距上次解绑太近        -> 不重复解除
      3. 在线设备只有本机 IP   -> 绝不解除
    """
    if not AUTO_RELEASE:
        return False, "自动解绑已关闭"
    if verify_internet():
        return False, "本机当前可联网，判定为未占用，拒绝解绑"

    last = float(state.get("last_release") or 0)
    if RELEASE_COOLDOWN > 0 and time.time() - last < RELEASE_COOLDOWN:
        return False, f"距上次解绑不足 {RELEASE_COOLDOWN}s，跳过"

    own = LAST_CLIENT_IP or ""
    candidates = []
    try:
        detail = json.loads(info.get("online_device_detail") or "{}")
        for dev in detail.values():
            ip = dev.get("ip") if isinstance(dev, dict) else ""
            if ip and ip != own:
                candidates.append(ip)
    except Exception:
        pass
    if not candidates:
        ip = info.get("online_ip") or ""
        if not ip or ip == own:
            return False, "在线设备就是本机，拒绝自我解绑"
        candidates = [ip]

    target = candidates[0]
    release_device(target)
    state["last_release"] = time.time()
    return True, f"已解绑占用设备 {target}"


def _looks_occupied(msg):
    text = (msg or "").lower()
    return any(hint in text for hint in _OCCUPY_HINTS)


def once(force=False):
    """单次流程：已认证则验联网；未认证先直接登录，失败且确认占用才解绑，
    重新登录后必须验联网通过才算成功。

    force=True（--boot 内每轮）时忽略失败退避，保证开机后的密集重试不被跳过。
    """
    if SSID_FILTER:
        ssid = get_windows_ssid()
        if ssid not in TARGET_SSIDS:
            return True, f"非目标网络（{ssid}），跳过"

    if not can_reach(PORTAL_HOST):
        return True, f"未接入校园网（{PORTAL_HOST} 不可达），跳过"

    online, info = portal_status()
    if online is None:
        return False, "认证状态查询失败"
    if online:
        if verify_internet():
            logger.info(f"已认证 online_ip={info.get('online_ip')}，本机联网正常，退出。")
            return True, "已在线（联网正常）"
        logger.warning("已认证但本机联网验证失败；不做任何解绑，等下轮重试")
        return False, "已认证但联网异常"

    state = _read_state()
    fails = int(state.get("fail_count", 0))
    if not force and state.get("last_fail") and RETRY_BACKOFF:
        wait = RETRY_BACKOFF[min(max(fails - 1, 0), len(RETRY_BACKOFF) - 1)]
        if wait > 0 and time.time() - float(state["last_fail"]) < wait:
            return True, f"上次失败未满 {wait}s 退避期，跳过"

    # 先直接登录，绝不预先解绑
    logger.info("未认证，先尝试直接登录...")
    try:
        success, msg = srun_login()
    except Exception as e:
        logger.error(f"登录异常: {e}", exc_info=True)
        success, msg = False, str(e)

    # 只有登录失败且响应疑似占用，才尝试解绑并重试一次
    if not success and _looks_occupied(msg) and AUTO_RELEASE:
        logger.warning(f"登录失败且疑似账号被占用: {msg}")
        released, why = _try_release(info, state)
        logger.info(f"占用处理: {why}")
        if released:
            try:
                success, msg = srun_login()
            except Exception as e:
                logger.error(f"解绑后重试登录失败: {e}")
                success, msg = False, str(e)

    # 服务端说成功不算数，必须确认本机真的能联网
    if success:
        if verify_internet():
            logger.info("登录成功且本机联网验证通过")
            # 保留 last_release，避免刚解绑成功又立刻触发下一次解绑
            keep = {}
            if state.get("last_release"):
                keep["last_release"] = state["last_release"]
            _write_state(keep)
            return True, "登录成功（联网验证通过）"
        logger.error("服务端返回登录成功，但本机联网验证失败")
        state.update({"fail_count": fails + 1, "last_fail": time.time()})
        _write_state(state)
        return False, "登录返回成功但本机联网验证失败"

    state.update({"fail_count": fails + 1, "last_fail": time.time()})
    _write_state(state)
    return False, msg


def boot_loop():
    """开机后有界短时守护：按 BOOT_SCHEDULE 跑完即退出，绝不常驻。"""
    delays = list(BOOT_SCHEDULE)
    logger.info(
        f"开机守护启动：共 {len(delays)} 次，约 {sum(delays) / 60:.0f} 分钟后自动退出"
    )
    for i, delay in enumerate(delays, 1):
        if delay > 0:
            time.sleep(delay)
        logger.info(f"--- 开机守护 第 {i}/{len(delays)} 次 ---")
        try:
            ok, msg = once(force=True)
            logger.info(f"第 {i} 次结果: {msg}")
        except Exception as e:
            logger.error(f"第 {i} 次异常: {e}")
    logger.info("开机守护完成，进程退出（不常驻）。")


def watch_loop():
    """调试用低频循环；生产请由启动项 / 任务计划触发 --once。"""
    logger.info(f"调试监控模式，每 {CHECK_INTERVAL}s 一次（Ctrl+C 退出）")
    while True:
        try:
            once()
        except KeyboardInterrupt:
            logger.info("监控模式已退出。")
            break
        except Exception as e:
            logger.error(f"监控异常: {e}")
        time.sleep(CHECK_INTERVAL)


def main():
    if "--test" in sys.argv:
        reachable = can_reach(PORTAL_HOST)
        online, info = portal_status() if reachable else (None, {})
        label = "已认证" if online else "未认证" if online is False else "查询失败"
        print(f"SSID:            {get_windows_ssid()}")
        print(f"本机 IP:         {get_local_ip()}")
        print(f"Portal 可达:     {reachable}")
        print(f"认证状态:        {label}")
        print(f"在线 IP:         {info.get('online_ip', '-')}")
        return

    if "--logout" in sys.argv:
        srun_logout()
        return

    if "--watch" in sys.argv:
        watch_loop()
        return

    if not acquire_lock():
        logger.info("已有实例在运行，本次退出。")
        return

    if "--boot" in sys.argv:
        boot_loop()
        return

    ok, msg = once()
    print(f"[{'OK' if ok else '失败'}] {msg}")
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
