#!/usr/bin/env python3
"""自助服务模块：用账密 SSO 免登录 8800，列出账号下全部在线设备。

深澜自助服务 https://login.lzu.edu.cn:8800 用独立 PHP 会话（账密认证），
与网络来源 IP 无关，因此即使本机未认证，只要能访问 8800 就能登录并看到
账号下全部在线设备 —— 这正是 rad_user_info 做不到的（后者按来源 IP
判断，未认证时只会返回 not_online_error）。

主程序只用它做一件事：**列出在线设备 IP**，再交给 srun_portal 的
action=logout 按 IP 注销（那个才真的踢得掉）。

注意：本模块的 kick_device()（POST /home/delete）在真机上对 @study 产品
一律返回「下线请求失败」，是服务端业务层拒绝，不是参数问题
（GET 会 405，POST 带 _csrf-8800 也不行）。因此它只是备用路径。

链路：
    1. GET /site/sso?data=base64("zh-CN:<账号>:<md5(密码))")
       -> 免图形验证码、免 RSA，302 到 /home，拿到 PHPSESSID_8800
    2. GET /home -> 解析在线设备表格：
       每行 <tr data-key="<id>">，含 IP、产品名称，
       及 <a href="/home/delete?id=<id>&user_mac=<mac>" data-method="post">
       同时拿到 <input name="_csrf-8800" value="...">
    3. POST /home/delete?id=<id>&user_mac=<mac>（带 _csrf-8800）

本模块不记录密码，不打印响应正文中的敏感内容。
"""

import base64
import hashlib
import http.cookiejar
import re
import ssl
import urllib.parse
import urllib.request

DEFAULT_BASE = "https://login.lzu.edu.cn:8800"
SELF_HOST = "login.lzu.edu.cn"
# 自助服务下线失败时页面上的 flash 提示（Yii2 flash message）
_KICK_FAIL_HINT = "下线请求失败"


class SelfServiceClient:
    def __init__(self, username, password, base=DEFAULT_BASE, timeout=8):
        # 账密必须是纯账号（不带 @study）与明文密码
        self.username = username
        self.password = password
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.ctx = ssl._create_unverified_context()
        self.cjar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.ctx),
            urllib.request.HTTPCookieProcessor(self.cjar),
        )
        self.csrf = None

    def _get(self, path):
        req = urllib.request.Request(
            self.base + path,
            headers={"User-Agent": "Mozilla/5.0 (LZU-AutoAuth)"},
        )
        with self.opener.open(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", "replace"), resp.geturl()

    def _post(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            self.base + path,
            data=body,
            headers={
                "User-Agent": "Mozilla/5.0 (LZU-AutoAuth)",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": self.base + "/home",
            },
        )
        with self.opener.open(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", "replace"), resp.geturl()

    def login(self):
        """SSO 免登录，成功返回 True。

        真机 SSO 会 302 到 /home（final URL 含 /home）；mock 直接返回 home
        内容。两种都算成功：以"拿到了 home 页面"为准，而非仅看跳转 URL。
        """
        payload = f"zh-CN:{self.username}:{hashlib.md5(self.password.encode()).hexdigest()}"
        encoded = base64.b64encode(payload.encode()).decode()
        body, final = self._get("/site/sso?data=" + urllib.parse.quote(encoded))
        redirected_ok = "/home" in final or "/index" in final
        # home 页面标志：在线设备表格（data-key）或用户列，且不是登录页
        home_ok = ("data-key=" in body or "online_device" in body or "学生办公" in body) \
            and "login-form" not in body
        ok = redirected_ok or home_ok
        if ok:
            return True, "SSO 登录成功"
        # 诊断：区分验证码/密码错误/会话问题，不泄露密码
        return False, "SSO 未进入 home（账号或密码可能有误）"

    def _extract_csrf(self, html):
        m = re.search(r'name="_csrf-8800"\s+value="([^"]+)"', html)
        self.csrf = m.group(1) if m else None
        return self.csrf

    def list_devices(self):
        """返回在线设备列表 [{'id','ip','product','user_mac','delete_path'}]。"""
        html, _ = self._get("/home")
        self._extract_csrf(html)
        devices = []
        for m in re.finditer(r'<tr[^>]*data-key="(\d+)"[^>]*>(.*?)</tr>', html, re.S):
            rid, row = m.group(1), m.group(2)
            cells = [re.sub(r"<[^>]+>", "", c).strip()
                     for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
            if len(cells) < 2:
                continue
            dm = re.search(r'href="(/home/delete\?[^"]+)"', row)
            delete_path = urllib.parse.unquote(dm.group(1)) if dm else ""
            umac = re.search(r"user_mac=([^&\"]+)", delete_path)
            devices.append({
                "id": rid,
                "user": cells[0] if cells else "",
                "ip": cells[1] if len(cells) > 1 else "",
                "product": cells[3] if len(cells) > 3 else "",
                "user_mac": umac.group(1) if umac else "",
                "delete_path": delete_path,
            })
        return devices

    def kick_device(self, device):
        """下线指定设备。device 来自 list_devices()。返回 (ok, msg)。

        失败判据必须看响应正文：服务端无论成功失败都会 302/跳回 /home，
        所以判定 URL 会永远"成功"（此前就是这样误报的）。
        自助服务失败时页面带一句 flash：「下线请求失败」。
        """
        if not device or not device.get("delete_path"):
            return False, "设备无下线链接"
        if not self.csrf:
            html, _ = self._get("/home")
            self._extract_csrf(html)
        # 解析 delete_path 的参数（页面里是 &amp; 转义，先还原）
        path = device["delete_path"].replace("&amp;", "&")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)
        params = {"id": qs.get("id", [device.get("id", "")])[0],
                  "user_mac": qs.get("user_mac", [device.get("user_mac", "")])[0]}

        body, _ = self._post("/home/delete", dict(params))
        if _KICK_FAIL_HINT in body:
            return False, "下线请求失败（服务端拒绝，未生效）"

        # 不信响应，回读在线设备列表确认真的消失
        try:
            still = [d for d in self.list_devices() if d.get("id") == str(params["id"])]
        except Exception:
            still = []
        if still:
            return False, "下线后设备仍在线"
        return True, "已下线"


def release_occupant(username, password, own_ip="", log=None, base=DEFAULT_BASE):
    """完整解绑流程：登录自助服务 -> 列出设备 -> 踢掉非本机设备。

    own_ip: 本机在服务端眼中的 IP（用于排除自己，避免自我解绑）。
    base: 自助服务地址（测试时可指向 mock）。
    返回 (是否执行了踢设备, 说明)。
    """
    def _log(msg):
        if log:
            log(msg)

    cli = SelfServiceClient(username, password, base=base)
    ok, msg = cli.login()
    if not ok:
        return False, f"自助服务登录失败: {msg}"
    _log("自助服务 SSO 登录成功")

    devices = cli.list_devices()
    _log(f"在线设备数: {len(devices)}")
    if len(devices) <= 1:
        # 只有一台设备：要么就是本机（没被占用），要么本机不在线
        # 账密视角下若只有一台且就是占用者，也应允许踢 —— 但需确认不是本机
        if devices and own_ip and devices[0]["ip"] == own_ip:
            return False, "在线设备只有本机，拒绝自我解绑"

    target = None
    for d in devices:
        if own_ip and d["ip"] == own_ip:
            continue
        if d.get("delete_path"):
            target = d
            break
    if not target:
        return False, "没有找到可下线的非本机设备"

    _log(f"选择占用设备: ip={target['ip']} id={target['id']}")
    ok, msg = cli.kick_device(target)
    return ok, f"{msg}: ip={target['ip']}"


if __name__ == "__main__":
    import sys
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.json"
    with open(cfg_path, encoding="utf-8") as f:
        cfg = __import__("json").load(f)
    ok, msg = release_occupant(cfg["username"], cfg["password"], log=print)
    print("结果:", ok, msg)
