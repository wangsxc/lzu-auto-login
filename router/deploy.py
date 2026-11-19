#!/usr/bin/env python3
"""把路由器版认证脚本部署到 CR8809 的 /overlay/lzu/。

做四件事：
  1. 上传三个 lua（协议层、自助服务、主状态机）
  2. 用本机 config.json 的账密生成路由器 config.json
  3. luac -p 语法检查
  4. 跑协议向量自检 + status

用法：
    python router/deploy.py            # 生产参数
    python router/deploy.py --fast     # 轮询加速（观测用，30s 一档）
    python router/deploy.py --check    # 只检查不上传
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ssh_router as R  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REMOTE = "/overlay/lzu"

FAST_POLL = [30, 30, 30, 60, 120]
PROD_POLL = [60, 120, 300, 600, 900]


def build_config(fast=False):
    local = json.load(open(os.path.join(ROOT, "config.json"), encoding="utf-8"))
    cfg = {
        "username": local["username"],
        "password": local["password"],
        "domain": local.get("domain", "@study"),
        "ac_id": str(local.get("ac_id", "2")),
        "portal_host": local.get("portal_host", "10.10.0.166"),
        "probe_urls": [
            "http://captive.apple.com/hotspot-detect.html",
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://cp.cloudflare.com/generate_204",
        ],
        "probe_expect": ["Success", "Microsoft Connect Test", None],
        "miss_threshold": 2,
        "verify_attempts": 6,
        "verify_interval": 2.5,
        "auto_release": True,
        "release_cooldown": 600,
        "self_service_base": local.get("self_service_base", "https://login.lzu.edu.cn:8800"),
        "poll_intervals": FAST_POLL if fast else PROD_POLL,
        "backoff": [60, 120, 240, 480, 900],
        "http_timeout": 6,
        "log_max_bytes": 262144,
    }
    return cfg


def put_file(t, local, remote, chunk=4096):
    """通过 base64 分块上传（路由器 dropbear 无 sftp 子系统）。"""
    import base64

    data = open(local, "rb").read()
    b64 = base64.b64encode(data).decode("ascii")
    # 每块长度必须是 4 的倍数，才能用 -A 单行独立解码
    R.run(t, f": > {remote}", timeout=20)
    for i in range(0, len(b64), chunk):
        part = b64[i:i + chunk]
        R.run(t, f"printf '%s' '{part}' | openssl base64 -d -A >> {remote}", timeout=30)
    _, out, _ = R.run(t, f"md5sum {remote} | cut -d' ' -f1", timeout=20)
    import hashlib

    local_md5 = hashlib.md5(data).hexdigest()
    if out.strip() != local_md5:
        raise RuntimeError(f"{remote} md5 不一致: 远端={out.strip()} 本地={local_md5}")
    return len(data)


def main():
    fast = "--fast" in sys.argv
    check_only = "--check" in sys.argv

    t = R.connect()
    try:
        if not check_only:
            R.run(t, f"mkdir -p {REMOTE}", timeout=20)
            for name in ("srun_bx1.lua", "self_service.lua", "lzu_auth.lua", "_test_vector.lua"):
                lp = os.path.join(HERE, name)
                if not os.path.exists(lp):
                    print(f"  跳过（本地不存在）: {name}")
                    continue
                n = put_file(t, lp, f"{REMOTE}/{name}")
                print(f"  上传 {name} ({n} 字节，md5 已校验)")
            cfg = build_config(fast)
            data = json.dumps(cfg, ensure_ascii=False, indent=2).encode("utf-8")
            tmp = os.path.join(HERE, ".config.router.tmp.json")
            with open(tmp, "wb") as f:
                f.write(data)
            try:
                put_file(t, tmp, f"{REMOTE}/config.json")
            finally:
                os.remove(tmp)
            R.run(t, f"chmod 600 {REMOTE}/config.json")
            print(f"  写入 config.json（轮询阶梯={cfg['poll_intervals']}）")

        print("\n=== 1. 语法检查 ===")
        code, out, err = R.run(
            t,
            f"cd {REMOTE} && for f in srun_bx1.lua self_service.lua lzu_auth.lua; do "
            f"luac -p $f && echo \"OK  $f\" || echo \"FAIL $f\"; done",
        )
        print(out.strip() or err.strip())

        print("\n=== 2. 协议向量自检 ===")
        code, out, err = R.run(t, f"cd {REMOTE} && lua _test_vector.lua 2>&1 | tail -20")
        print(out.strip())

        print("\n=== 3. 认证状态 ===")
        code, out, err = R.run(t, f"cd {REMOTE} && lua lzu_auth.lua status 2>&1")
        print(out.strip())

        if "--service" in sys.argv:
            print("\n=== 4. 安装开机自启服务 ===")
            put_file(t, os.path.join(HERE, "lzu_auth.init"), "/etc/init.d/lzu_auth")
            code, out, err = R.run(
                t,
                "chmod +x /etc/init.d/lzu_auth && "
                "/etc/init.d/lzu_auth enable && "
                "/etc/init.d/lzu_auth restart; sleep 3; "
                "echo '--- 进程 ---'; ps | grep -v grep | grep lzu_auth; "
                "echo '--- rc.d ---'; ls /etc/rc.d/ | grep -i lzu",
                timeout=60,
            )
            print(out.strip() or err.strip())
    finally:
        t.close()


if __name__ == "__main__":
    main()
