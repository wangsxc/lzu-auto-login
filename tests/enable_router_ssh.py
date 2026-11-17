#!/usr/bin/env python3
"""用浏览器登录后的 stok 打开 CR8809 的 telnet / SSH。

用法:
    python tests/enable_router_ssh.py <stok>

stok 获取: 浏览器登录 http://192.168.10.1 后台，地址栏
    /cgi-bin/luci/;stok=XXXXXXXX/web/... 中 stok= 后面那串。
"""

import json
import sys
import urllib.parse
import urllib.request

BASE = "http://192.168.10.1"


def api(stok, path, params=None):
    url = f"{BASE}/cgi-bin/luci/;stok={stok}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Referer": BASE + "/cgi-bin/luci/web"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.read().decode("utf-8", "replace")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("用法: python tests/enable_router_ssh.py <stok>")
    stok = sys.argv[1].strip()

    print("1) 打开 telnet ...")
    body = api(stok, "/api/misystem/set_telnet", {"enable": 1})
    print("  ", body[:300])
    try:
        obj = json.loads(body)
        if obj.get("code") not in (0, None):
            print("  警告: 返回非 0，可能需要确认 stok 是否有效")
    except ValueError:
        pass

    print("\n2) 下一步（脚本打印，需你手动或用 SSH 工具执行）:")
    print("   telnet 192.168.10.1  (用户 root，密码为路由器背面管理密码)")
    print("   然后执行:")
    for line in [
        "nvram set ssh_en=1",
        "nvram set telnet_en=1",
        "nvram set uart_en=1",
        "nvram set boot_wait=on",
        "nvram commit",
        "sed -i 's/channel=.*/channel=\"debug\"/g' /etc/init.d/dropbear",
        "/etc/init.d/dropbear restart",
    ]:
        print("   ", line)
    print("\n   完成后 SSH: ssh root@192.168.10.1")


if __name__ == "__main__":
    main()
