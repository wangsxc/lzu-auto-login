#!/usr/bin/env python3
"""
一键回归测试：启动本地 mock Portal，用 config.test.json 跑主脚本。

覆盖：未认证自动登录 / 协议字段校验 / 掉线重连 / 账号占用 / 状态查询。
不接触真实校园网，不需要下线，不需要第二台设备。

用法:
    python tests/run_mock_test.py
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
PORT = 8899
BASE = f"http://127.0.0.1:{PORT}"
CONFIG = ROOT / "config.test.json"


def http_json(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def control(state):
    return http_json("/__control?state=" + state)


def run_client(*args):
    env = dict(os.environ, LZU_CONFIG=str(CONFIG))
    proc = subprocess.run(
        [PY, str(ROOT / "lzu_auto_login.py"), *args],
        env=env, capture_output=True, text=True, timeout=60,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check(label, cond, detail=""):
    print(("  [PASS] " if cond else "  [FAIL] ") + label + (("  " + detail) if detail else ""))
    return bool(cond)


def main():
    server = subprocess.Popen(
        [PY, str(Path(__file__).resolve().parent / "mock_portal.py"), "--port", str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    ok = True
    try:
        for _ in range(40):
            try:
                http_json("/__state")
                break
            except Exception:
                if server.poll() is not None:
                    raise RuntimeError("mock 服务器启动失败: " + (server.stdout.read() or ""))
                time.sleep(0.15)
        else:
            raise RuntimeError("mock 服务器启动超时")

        print("1) 未认证状态 -> 自动登录，并校验协议字段")
        control("offline")
        code, out = run_client()
        st = http_json("/__state")
        ok &= check("客户端退出码 0", code == 0, f"code={code}")
        ok &= check("服务端已切换为已认证", st["authenticated"] is True)
        login_checks = [h["checks"] for h in st["history"] if "checks" in h]
        ok &= check(
            "HMAC 密码 / info 换表 Base64 / SHA1 chksum 全部正确",
            bool(login_checks) and all(all(c.values()) for c in login_checks),
            json.dumps(login_checks, ensure_ascii=False),
        )
        print("     客户端:", out.replace("\n", " | ")[:160])

        print("1b) 已认证时再跑一次 -> 应直接退出，不发起登录")
        code, out = run_client()
        st = http_json("/__state")
        ok &= check("退出码 0（已在线属正常）", code == 0, f"code={code}")
        ok &= check("未重复提交登录", st["login_count"] == 1, f"count={st['login_count']}")
        ok &= check("输出提示已在线", "已在线" in out)

        print("2) 模拟路由器断电、验证态被抹除 -> 应能重新认证")
        control("offline")
        code, out = run_client()
        st = http_json("/__state")
        ok &= check("掉线后重新登录成功", code == 0 and st["authenticated"] is True)
        ok &= check("累计登录 2 次", st["login_count"] == 2, f"count={st['login_count']}")

        print("3) 模拟账号被手机占用 -> 应自动解绑并登录成功")
        control("occupied")
        code, out = run_client()
        st = http_json("/__state")
        dm = [h for h in st["history"] if h["event"] == "rad_user_dm"]
        ok &= check("退出码 0", code == 0, f"code={code}")
        ok &= check("调用了 rad_user_dm 解绑", bool(dm))
        ok &= check("解绑 sign 校验通过", bool(dm) and all(h.get("sign_ok") for h in dm))
        ok &= check("解绑的是占用设备 IP", any(h.get("ip") == "10.99.0.88" for h in dm))
        ok &= check("最终登录成功", st["authenticated"] is True)
        ok &= check("累计登录 3 次", st["login_count"] == 3, f"count={st['login_count']}")

        print("4) rad_user_info 状态查询")
        control("online")
        with urllib.request.urlopen(
            BASE + "/cgi-bin/rad_user_info?callback=jsonp", timeout=5
        ) as resp:
            text = resp.read().decode("utf-8")
        data = json.loads(text[text.index("(") + 1: text.rindex(")")])
        ok &= check("在线态返回 online_ip", bool(data["online_ip"]), data["online_ip"])

        print("5) --boot 有界调度（测试配置 3 次，间隔 0）")
        control("offline")
        code, out = run_client("--boot")
        st = http_json("/__state")
        ok &= check("退出码 0", code == 0, f"code={code}")
        ok &= check("跑完 3 次后自动退出", "开机守护完成" in out)
        ok &= check("最终已认证", st["authenticated"] is True)

        print("\n结果:", "全部通过" if ok else "存在失败项")
        return 0 if ok else 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    main()
