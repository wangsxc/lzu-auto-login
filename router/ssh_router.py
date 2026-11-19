#!/usr/bin/env python3
"""通过 SSH 在路由器上执行命令的助手。

CR8809 跑的是 OpenWrt 18.06（dropbear 2018），只支持 SHA1 类算法，
较新的 paramiko 默认已禁用它们，所以要显式把老算法排到前面。

用法：
    python router/ssh_router.py "命令1; 命令2"
    python router/ssh_router.py -f 本地脚本.sh     # 把脚本内容推过去执行
"""
import io
import json
import os
import socket
import sys

# 路由器 dropbear 2018 只支持 ssh-rsa 主机密钥，paramiko 4/5 已移除该实现，
# 所以项目里隔离安装了一份 3.5.1 到 router/_vendor（不入库）。
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "_vendor"))

import paramiko

HOST = os.environ.get("LZU_ROUTER_HOST", "192.168.10.1")
USER = os.environ.get("LZU_ROUTER_USER", "root")


def _load_auth():
    """从环境变量或 router/.router_auth.json 读路由器密码（该文件不入库）。"""
    pwd = os.environ.get("LZU_ROUTER_PASS")
    if pwd:
        return pwd
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".router_auth.json")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)["password"]


PWD = _load_auth()

LEGACY_KEX = (
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)
LEGACY_KEYS = (
    "rsa-sha2-256",
    "ssh-rsa",
    "rsa-sha2-512",
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
)


def connect(timeout=8):
    sock = socket.create_connection((HOST, 22), timeout=timeout)
    t = paramiko.Transport(sock)
    # 必须在 start_client 之前改偏好，否则不会参与协商
    t._preferred_kex = LEGACY_KEX
    t._preferred_keys = LEGACY_KEYS
    t.start_client(timeout=timeout)
    t.auth_password(USER, PWD)
    if not t.is_authenticated():
        raise RuntimeError("认证失败")
    return t


def run(t, cmd, timeout=90):
    ch = t.open_session(timeout=15)
    ch.exec_command(cmd)
    out, err = io.BytesIO(), io.BytesIO()
    ch.makefile("wb").write(b"")  # noqa: F841 保持接口一致
    import select

    while True:
        got = False
        if ch.recv_ready():
            out.write(ch.recv(65536))
            got = True
        if ch.recv_stderr_ready():
            err.write(ch.recv_stderr(65536))
            got = True
        if ch.exit_status_ready() and not ch.recv_ready() and not ch.recv_stderr_ready():
            break
        if not got:
            select.select([ch], [], [], 0.2)
    return ch.recv_exit_status(), out.getvalue().decode("utf-8", "replace"), err.getvalue().decode("utf-8", "replace")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    if sys.argv[1] == "-f":
        cmd = open(sys.argv[2], "r", encoding="utf-8").read()
    else:
        cmd = sys.argv[1]
    try:
        t = connect()
    except Exception as e:
        print(f"SSH 连接失败: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    try:
        code, out, err = run(t, cmd)
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if err.strip():
            print("--- stderr ---", file=sys.stderr)
            print(err, end="", file=sys.stderr)
        return code
    finally:
        t.close()


if __name__ == "__main__":
    sys.exit(main())
