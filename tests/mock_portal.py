#!/usr/bin/env python3
"""
本地 Portal 模拟服务器（测试环境，纯标准库）。

复刻深澜 srun V1.18 的 CGI 接口，让主脚本在完全不接触真实校园网、
不需要下线、不需要第二台设备的情况下跑通完整认证流程，并校验协议字段。

控制接口：
    GET /__state                     查看状态与最近请求
    GET /__control?state=offline     未认证（初始）
    GET /__control?state=online      已认证
    GET /__control?state=occupied    模拟账号被其他设备占用
    GET /__control?state=sign_error  模拟签名失败

用法:
    python tests/mock_portal.py --port 8899
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEST_PASSWORD = "test_password_123"
CLIENT_IP = "10.99.0.7"
SRUN_VER = "SRunCGIAuthIntfSvr V1.18 B20260715"
SRUN_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TRANS_REV = str.maketrans(SRUN_ALPHA, STD_ALPHA)


def _first(query, key, default=""):
    return query.get(key, [default])[0]


class PortalState:
    def __init__(self):
        self.state = "offline"
        self.challenge = ""
        self.challenge_time = 0.0
        self.username = ""
        self.login_count = 0
        self.dm_count = 0
        self.internet_override = None
        self.history = []

    def new_challenge(self):
        self.challenge = hashlib.sha1(
            f"mock-{time.time_ns()}-{os.getpid()}".encode()
        ).hexdigest()
        self.challenge_time = time.time()
        return self.challenge

    def record(self, event, **extra):
        item = {"t": time.strftime("%H:%M:%S"), "event": event}
        item.update(extra)
        self.history.append(item)
        self.history = self.history[-30:]


STATE = PortalState()


def _jsonp(callback, obj):
    cb = callback or "jsonp"
    return f"{cb}({json.dumps(obj, separators=(',', ':'))})"


def _mock_home():
    """模拟自助服务 /home 的在线设备表格（真机格式）。"""
    devices = []
    if STATE.state == "occupied":
        # 手机占用：占用者 IP 与本机不同，应被踢
        devices.append(("9001", "10.99.0.88", "学生办公", "aa:bb:cc:dd:ee:ff"))
    elif STATE.state == "self_occupied":
        # 占用者就是本机：不应被踢（own_ip=CLIENT_IP）
        devices.append(("9002", CLIENT_IP, "学生办公", "00:11:22:33:44:55"))
    elif STATE.state == "online":
        devices.append(("9003", CLIENT_IP, "学生办公", "00:11:22:33:44:55"))

    rows = ""
    for did, ip, product, mac in devices:
        rows += (f'<tr class="w1" data-key="{did}">'
                 f'<td>{STATE.username or "testuser"}</td>'
                 f'<td>{ip}</td>'
                 f'<td>2026-11-19 18:00:00</td>'
                 f'<td>{product}</td>'
                 f'<td><a class="btn btn-danger" href="/home/delete?id={did}&amp;user_mac={mac}" '
                 f'title="下线">下线</a></td></tr>')
    return ('<!doctype html><title>home</title>'
            '<input type="hidden" name="_csrf-8800" value="mock_csrf_token">'
            '<table><tbody>' + rows + '</tbody></table>')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, body, content_type="application/json; charset=utf-8", code=200):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Srun-Server", SRUN_VER)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        if path in ("/", "/index_1.html", "/srun_portal_pc"):
            return self._send(
                "<!doctype html><title>LOCAL MOCK PORTAL</title>"
                "<h1>LOCAL MOCK PORTAL</h1><p>测试环境，不是真实校园网</p>",
                "text/html; charset=utf-8",
            )

        if path == "/__state":
            return self._send(json.dumps({
                "state": STATE.state,
                "authenticated": STATE.state == "online",
                "login_count": STATE.login_count,
                "dm_count": STATE.dm_count,
                "internet_override": STATE.internet_override,
                "username": STATE.username,
                "history": STATE.history[-12:],
            }, ensure_ascii=False, indent=2))

        if path == "/__control":
            new = _first(q, "state", "offline")
            if new not in ("offline", "online", "occupied", "sign_error", "self_occupied"):
                return self._send(json.dumps({"error": "unknown state"}), code=400)
            internet = _first(q, "internet", "")
            if internet in ("0", "1"):
                STATE.internet_override = internet == "1"
            elif internet == "auto":
                STATE.internet_override = None
            STATE.state = new
            if new == "offline":
                STATE.challenge = ""
            STATE.record(f"control -> {new}" + (f" internet={internet}" if internet else ""))
            return self._send(json.dumps({
                "state": new, "internet_override": STATE.internet_override,
            }))

        if path == "/__internet":
            # 模拟联网探测：override 优先，否则按是否已认证决定
            ok = STATE.internet_override
            if ok is None:
                ok = STATE.state in ("online", "self_occupied")
            return self._send(
                "Success" if ok else "<html>portal hijack</html>",
                "text/html; charset=utf-8",
            )

        if path == "/cgi-bin/get_challenge":
            token = STATE.new_challenge()
            STATE.username = _first(q, "username")
            STATE.record("get_challenge")
            return self._send(_jsonp(_first(q, "callback", "jQuery"), {
                "challenge": token,
                "client_ip": CLIENT_IP,
                "ecode": 0, "error": "ok", "error_msg": "",
                "expire": "60", "online_ip": CLIENT_IP,
                "res": "ok", "srun_ver": SRUN_VER,
                "st": int(time.time()),
            }))

        if path == "/cgi-bin/rad_user_info":
            online = STATE.state == "online"
            occupied = STATE.state == "occupied"
            STATE.record("rad_user_info")
            if STATE.state == "self_occupied":
                # 占用设备其实就是本机自己，但本机其实能联网
                return self._send(_jsonp(_first(q, "callback", "jsonp"), {
                    "error": "not_online",
                    "online_ip": CLIENT_IP,
                    "user_name": STATE.username or "testuser",
                    "domain": "study",
                    "products_name": "学生办公",
                    "online_device_total": "1",
                    "online_device_detail": json.dumps({
                        "9002": {"ip": CLIENT_IP, "os_name": "Windows 10", "class_name": "Windows"}
                    }),
                    "add_time": int(time.time()),
                    "ServerFlag": 4294967040,
                }))
            if occupied:
                # 模拟手机占用：本机未认证，但账号下已有别的设备在线
                other_ip = "10.99.0.88"
                return self._send(_jsonp(_first(q, "callback", "jsonp"), {
                    "error": "not_online",
                    "online_ip": other_ip,
                    "user_name": STATE.username or "testuser",
                    "domain": "study",
                    "products_name": "学生办公",
                    "online_device_total": "2",
                    "online_device_detail": json.dumps({
                        "9001": {"ip": other_ip, "os_name": "Android", "class_name": "Phone"}
                    }),
                    "add_time": int(time.time()),
                    "ServerFlag": 4294967040,
                }))
            return self._send(_jsonp(_first(q, "callback", "jsonp"), {
                "error": "ok" if online else "not_online",
                "online_ip": CLIENT_IP if online else "",
                "user_name": STATE.username or "testuser",
                "domain": "study",
                "products_name": "学生办公",
                "online_device_total": "1" if online else "0",
                "online_device_detail": "{}",
                "add_time": int(time.time()),
                "ServerFlag": 4294967040,
            }))

        # ===== 自助服务（账密会话，与来源 IP 无关）=====
        if path == "/site/sso":
            # data = base64("zh-CN:<user>:<md5(pwd)>")
            try:
                raw = base64.b64decode(_first(q, "data")).decode()
                parts = raw.split(":")
                md5_ok = len(parts) >= 3 and parts[2] == hashlib.md5(TEST_PASSWORD.encode()).hexdigest()
            except Exception:
                md5_ok = False
            STATE.record("sso_login", ok=md5_ok)
            if md5_ok:
                # 真机 SSO 成功后 302 到 /home；这里直接返回 home 页内容
                return self._send(_mock_home(), "text/html; charset=utf-8")
            return self._send("<title>login</title>login failed", "text/html; charset=utf-8")

        if path == "/home":
            return self._send(_mock_home(), "text/html; charset=utf-8")

        if path == "/cgi-bin/rad_user_dm":
            # 复刻 Portal.js: sign = sha1(time + username + ip + unbind + time)
            t = _first(q, "time")
            u = _first(q, "username")
            ip = _first(q, "ip")
            unb = _first(q, "unbind")
            sign = _first(q, "sign")
            expect = hashlib.sha1(f"{t}{u}{ip}{unb}{t}".encode()).hexdigest()
            ok = sign == expect and unb == "1"
            STATE.dm_count += 1
            STATE.record("rad_user_dm", sign_ok=ok, ip=ip)
            if ok and STATE.state == "occupied":
                STATE.state = "offline"
                STATE.challenge = ""
                return self._send(_jsonp(_first(q, "callback", "jQuery"), {
                    "ecode": 0, "res": "ok", "error": "ok",
                }))
            return self._send(_jsonp(_first(q, "callback", "jQuery"), {
                "ecode": 1, "res": "error", "error": "unbind_failed",
            }))

        return self._send("not found", "text/plain", 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
        get = lambda k, d="": form.get(k, [d])[0]

        if path == "/home/delete":
            # 自助服务下线：真正把占用设备踢掉
            STATE.dm_count += 1
            # 记录被踢设备的 IP（按 id 反查 mock 设备表，便于测试断言）
            kicked_ip = ""
            if STATE.state == "occupied":
                kicked_ip = "10.99.0.88"
            elif STATE.state == "self_occupied":
                kicked_ip = CLIENT_IP
            STATE.record("home_delete", id=get("id"), mac=get("user_mac"), ip=kicked_ip)
            if STATE.state == "occupied":
                STATE.state = "offline"
                STATE.challenge = ""
            return self._send("/home", "text/html; charset=utf-8")

        if path != "/cgi-bin/srun_portal":
            return self._send("not found", "text/plain", 404)

        if get("action") == "logout":
            # 真机行为：按 ip 参数查会话，与请求来源无关。
            # 不存在的 IP -> login_error#You are not online.
            target = get("ip")
            live_ip = ""
            if STATE.state == "online":
                live_ip = CLIENT_IP
            elif STATE.state == "occupied":
                live_ip = "10.99.0.88"
            elif STATE.state == "self_occupied":
                live_ip = CLIENT_IP
            if target and target == live_ip:
                STATE.state = "offline"
                STATE.challenge = ""
                # 会话被注销后，"强制不通"的模拟也应随之结束（重登后恢复）
                STATE.internet_override = None
                STATE.record("logout", ip=target, ok=True)
                return self._send("logout_ok")
            STATE.record("logout", ip=target, ok=False)
            return self._send("login_error#You are not online.")

        token = STATE.challenge
        hmac_hex = hmac.new(
            token.encode(), TEST_PASSWORD.encode(), hashlib.md5
        ).hexdigest()
        info = get("info")

        checks = {
            "token_fresh": bool(token) and time.time() - STATE.challenge_time < 60,
            "password_hmac": get("password") == "{MD5}" + hmac_hex,
            "info_prefix": info.startswith("{SRBX1}"),
            "chksum": False,
            "info_b64": False,
        }

        chkstr = (
            token + get("username") + token + hmac_hex
            + token + get("ac_id") + token + get("ip")
            + token + get("n") + token + get("type") + token + info
        )
        checks["chksum"] = get("chksum") == hashlib.sha1(chkstr.encode()).hexdigest()

        try:
            raw = base64.b64decode(info[len("{SRBX1}"):].translate(_TRANS_REV))
            checks["info_b64"] = len(raw) > 20
        except Exception:
            pass

        result = "login_ok"
        if not all(checks.values()):
            result = "sign_error"
        elif STATE.state == "occupied":
            result = "occupied -> login_error"
        elif STATE.state == "self_occupied":
            result = "self_occupied -> login_error"
        elif STATE.state == "sign_error":
            result = "forced sign_error"

        STATE.record("login", checks=checks, result=result)

        if result in ("sign_error", "forced sign_error"):
            return self._send("sign_error")
        if result.startswith(("occupied", "self_occupied")):
            return self._send("login_error#Authentication success,Welcome!")

        STATE.state = "online"
        STATE.login_count += 1
        return self._send(
            f"login_ok,{int(time.time())},0,0,0,0.0,0,0,0,0,0,1.01.20260715"
        )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8899)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[mock] http://127.0.0.1:{args.port} 已启动 (Ctrl+C 退出)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
