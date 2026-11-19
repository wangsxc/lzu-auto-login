# 兰州大学校园网自动认证

针对兰州大学校园网（深澜 **srun V1.18** 认证系统）的自动登录工具，两套实现：

| | 电脑端 | 路由器端 |
|---|---|---|
| 语言 | Python 3（纯标准库，零依赖） | Lua 5.1 |
| 触发 | 开机后跑 9 次（约 35 分钟）自动退出 | 常驻轮询，不依赖电脑 |
| 适用 | 想快速上手、不想动路由器 | 家里有 OpenWrt / 小米路由器 |

两套共用同一套协议实现与同一套判活、解绑策略，协议层输出**逐字节一致**。

## 为什么需要它

校园网的认证态绑在**出口 IP** 上，不是绑定在你的设备上。所以：

- 路由器断电、重启、PPPoE 重拨 → 出口 IP 变了 → 认证态失效
- 长时间离线 → 服务端会清掉会话

表现就是：明明昨天还好，今天开机上不了网，必须手动打开认证页面再登一次。这个脚本做的事就是把这个动作自动化。

## 快速开始（电脑端）

```bash
cp config.example.json config.json      # 填入账号密码
python lzu_auto_login.py --once         # 跑一次：已在线直接退出，未在线才登录
python lzu_auto_login.py --boot         # 开机守护：9 次后自动退出
python lzu_auto_login.py --test         # 只打印当前状态，不改动网络
```

Windows 开机自启：注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 加一项，
指向 `lzu_login_watch.vbs`（隐藏窗口启动 `--boot`）。

## 快速开始（路由器端）

适用于已开 SSH 的 OpenWrt 18.06 设备（本项目在小米 CR8809 上验证）。需要 `lua`、`luac`、
`curl`、`openssl`，以及 Lua 的 `socket.http` 与 `cjson`。

```bash
# 1. 配置路由器密码（该文件已被 .gitignore 排除）
echo '{"host":"192.168.10.1","user":"root","password":"你的路由器密码"}' > router/.router_auth.json

# 2. 一键部署：上传 + 生成配置 + 语法检查 + 协议自检 + 装开机自启
python router/deploy.py --service

# 3. 查看
ssh root@192.168.10.1 "tail -f /overlay/lzu/lzu_auth.log"
```

单文件手动部署也行：把 `router/*.lua` 和 `config.json` 放进 `/overlay/lzu/`，
再把 `router/lzu_auth.init` 复制为 `/etc/init.d/lzu_auth` 并 `enable`。

## 工作原理

```
每轮：探测外网（校验响应正文）
  ├─ 通 → 睡眠（间隔 60→120→300→600→900 秒递增）
  └─ 不通 → 连续 2 次才确认掉线 → recover()
                ├─ 服务端说已认证但探测不通 → 注销该会话后重登
                ├─ 查询失败               → 跳过本轮
                ├─ 确认未认证             → 直接登录
                └─ 登录失败且疑似占用      → 注销占用会话后重登
```

几个刻意的设计：

- **不 ping。** 未认证时 ICMP 可能仍通，会误判为已联网。改成 HTTP 请求并校验正文，
  被劫持到认证页就判为不通。
- **`login_ok` 不算成功。** 服务端返回成功但实际不通是常有的事（会话挂在别的 IP 上），
  必须探测确认能上网才算成功。
- **先登录，后解绑。** 绝不预先解绑，避免"自己把自己踢下线再自己解开"的死循环。
- **解绑用 `srun_portal action=logout`。** 该接口按 `ip` 参数查会话，不校验请求来源，
  因此未认证的设备也能注销指定 IP 的会话。代价是需要先通过自助服务（账密 SSO）
  列出账号下有哪些在线设备。

## 配置项

见 `config.example.json`，每一项都有说明。最关键的几个：

| 键 | 作用 |
|---|---|
| `username` / `password` / `domain` | 账号密码与域。`@study` 对应 eLearning（流量不限），空串对应 `@lzu.edu.cn` |
| `target_ssids` / `ssid_filter` | 只在指定 WiFi 下工作，避免在别人家也去连 Portal |
| `auto_release` / `release_cooldown` | 是否自动踢掉占用者，以及两次解绑的最小间隔 |
| `internet_probe_urls` | 联网验证用，被劫持到 Portal 即判未通 |

也可以用环境变量 `LZU_USERNAME` / `LZU_PASSWORD` 覆盖账密，`LZU_CONFIG` 指定别的配置文件。

## 测试

```bash
python tests/run_mock_test.py
```

`tests/mock_portal.py` 是一个本地假 Portal（含 srun 协议、自助服务、在线设备、联网探测），
8 组回归覆盖：已在线、未认证登录、账号被占用、已认证但联网不通、退避与冷却等。
全程离线，不碰真实校园网。

## 安全提醒

- **`config.json` 含明文密码，已被 `.gitignore` 排除。** 不要提交它。
- 路由器部署用的 `router/.router_auth.json` 同理。
- 自动解绑会踢掉同账号下的其他设备（手机、平板）。这是校园网单会话策略的必然结果，
  不想要就设 `auto_release: false`。

## 说明

本项目仅用于自己设备的自动重新认证，不涉及绕过认证、共享账号或任何计费规避。
协议实现来自对公开前端脚本的阅读与抓包分析，仅供学习参考；因使用产生的任何后果自负。

## License

MIT
