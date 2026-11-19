--[[
lzu_auth.lua — 兰大校园网 eLearning 自动认证（路由器常驻版）

部署在 CR8809（OpenWrt 18.06）上，常驻运行。核心目标：
  验证态绑在路由器 WAN IP，断电重拨后 IP 变化导致失效 —— 本脚本在
  路由器本地自检并自动重认证，不依赖电脑是否开机。

设计要点（与电脑版一脉相承）：
  1. 判活：校验正文的 HTTP 探测（不是 ICMP ping —— 未认证时 ping 可能仍通，会误判）
  2. 只有连续 N 轮探测失败才确认掉线，避免抖动误触发
  3. 确认掉线后：先查 rad_user_info 权威状态，已认证但探测失败 = 探测服务问题，不登录
  4. 未认证 → 直接登录；登录失败且疑似占用 → 解绑占用设备 → 重试一次
  5. 登录响应 login_ok 不算数，必须探测通过才算成功（防"自己踢自己"）
  6. 解绑三道保险：本机已联网 / 冷却期内 / 只有本机在线 → 一律拒绝解绑
  7. 轮询间隔与退避都随时间递增（见 CONFIG）

配置从同目录 config.json 读取（不硬编码账密）。
]]

package.path = "/overlay/lzu/?.lua;" .. package.path
local bx1 = require("srun_bx1")
local http = require("socket.http")
local ltn12 = require("ltn12")
local json = require("cjson")

local SCRIPT_DIR = "/overlay/lzu"
local CONFIG_FILE = SCRIPT_DIR .. "/config.json"
local LOG_FILE = SCRIPT_DIR .. "/lzu_auth.log"
local STATE_FILE = SCRIPT_DIR .. "/state.json"

-- ==================== 配置 ====================
local CONFIG = {}
local function load_config()
  local f = assert(io.open(CONFIG_FILE, "r"))
  local s = f:read("*a")
  f:close()
  CONFIG = json.decode(s)
  -- 默认值
  CONFIG.portal_host = CONFIG.portal_host or "10.10.0.166"
  CONFIG.ac_id = tostring(CONFIG.ac_id or "2")
  CONFIG.domain = CONFIG.domain or "@study"
  CONFIG.probe_urls = CONFIG.probe_urls or {
    "http://captive.apple.com/hotspot-detect.html",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://cp.cloudflare.com/generate_204",
  }
  CONFIG.probe_expect = CONFIG.probe_expect or {
    "Success", "Microsoft Connect Test", nil,
  }
  CONFIG.miss_threshold = CONFIG.miss_threshold or 2      -- 连续 N 轮失败才确认掉线
  CONFIG.verify_attempts = CONFIG.verify_attempts or 6    -- 登录后验证次数
  CONFIG.verify_interval = CONFIG.verify_interval or 2.5  -- 验证间隔（秒）
  -- 轮询间隔阶梯（秒）：连续成功越久，间隔越长，逐步拉长到最大值
  CONFIG.poll_intervals = CONFIG.poll_intervals or {60, 120, 300, 600, 900}
  -- 失败退避阶梯（秒）：连续失败越久，退避越长
  CONFIG.backoff = CONFIG.backoff or {60, 120, 240, 480, 900}
  CONFIG.release_cooldown = CONFIG.release_cooldown or 600  -- 两次解绑最小间隔
  CONFIG.http_timeout = CONFIG.http_timeout or 6
end

-- ==================== 日志（简单轮转）====================
local log_fp = nil
local function log(level, msg)
  local line = os.date("%Y-%m-%d %H:%M:%S") .. " [" .. level .. "] " .. msg .. "\n"
  io.write(line)
  io.flush()
  if not log_fp then
    log_fp = io.open(LOG_FILE, "a")
  end
  if log_fp then
    log_fp:write(line)
    log_fp:flush()
    -- 超过 1MB 轮转
    if log_fp:seek("end") > 1048576 then
      log_fp:close()
      os.execute("mv -f " .. LOG_FILE .. " " .. LOG_FILE .. ".1 2>/dev/null")
      log_fp = io.open(LOG_FILE, "a")
    end
  end
end

-- ==================== 状态持久化 ====================
local function load_state()
  local f = io.open(STATE_FILE, "r")
  if not f then return {} end
  local s = f:read("*a")
  f:close()
  local ok, st = pcall(json.decode, s)
  return ok and st or {}
end

local function save_state(st)
  local f = io.open(STATE_FILE, "w")
  if not f then return end
  f:write(json.encode(st))
  f:close()
end

-- ==================== HTTP 工具 ====================
local function url_encode(s)
  if not s then return "" end
  return (s:gsub("([^%w%-_%.~])", function(c)
    return string.format("%%%02X", c:byte())
  end))
end

-- GET 返回 body 或 nil
local function http_get(url, timeout)
  local body = {}
  local ok, code = http.request{
    url = url,
    sink = ltn12.sink.table(body),
    timeout = timeout or CONFIG.http_timeout,
    headers = { ["User-Agent"] = "Mozilla/5.0 (LZU-Router-Auth)", ["Cache-Control"] = "no-cache" },
  }
  if ok and (code == 200 or code == 302) then
    return table.concat(body), code
  end
  return nil, code
end

-- POST 表单返回 body 或 nil
local function http_post(url, fields, timeout)
  local parts = {}
  for k, v in pairs(fields) do
    parts[#parts + 1] = url_encode(k) .. "=" .. url_encode(tostring(v))
  end
  local data = table.concat(parts, "&")
  local body = {}
  local ok, code = http.request{
    url = url,
    method = "POST",
    source = ltn12.source.string(data),
    sink = ltn12.sink.table(body),
    timeout = timeout or CONFIG.http_timeout,
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Content-Length"] = #data,
      ["User-Agent"] = "Mozilla/5.0 (LZU-Router-Auth)",
    },
  }
  if ok then return table.concat(body), code end
  return nil, code
end

-- 从 JSONP 里抠出 JSON 并解码
local function parse_jsonp(text)
  if not text then return nil end
  local s, e = text:find("{", 1, true), text:match(".*()}")
  if not s or not e then return nil end
  local ok, obj = pcall(json.decode, text:sub(s, e))
  return ok and obj or nil
end

-- ==================== 认证状态（权威接口）====================
-- 返回 true/false/nil（nil=查询失败）+ 详情
local function portal_status()
  local url = "http://" .. CONFIG.portal_host .. "/cgi-bin/rad_user_info?callback=jsonp"
  local body = http_get(url)
  local data = parse_jsonp(body)
  if not data then
    log("DEBUG", "rad_user_info 查询失败")
    return nil, nil
  end
  local online = (data.error == "ok" and data.online_ip and data.online_ip ~= "")
  return online, data
end

-- ==================== 联网探测（校验正文，非 ping）====================
-- 任一端点返回预期正文即联网。返回 true/false
local function internet_ok()
  for i, url in ipairs(CONFIG.probe_urls) do
    local body = http_get(url)
    if body then
      local expect = CONFIG.probe_expect[i]
      if expect == nil then
        -- 无正文要求：只要非劫持（正文不含 Portal 特征）即算通
        if not body:find("srun_portal", 1, true) and not body:find("10.10.0.166", 1, true) then
          return true
        end
      elseif body:find(expect, 1, true) then
        return true
      end
    end
  end
  return false
end

-- ==================== 登录 ====================
local function get_challenge()
  local ip = "127.0.0.1"  -- 路由器本地发起，服务端按来源 IP 识别 WAN
  local username = CONFIG.username .. CONFIG.domain
  local ts = tostring(os.time() * 1000)
  local url = "http://" .. CONFIG.portal_host .. "/cgi-bin/get_challenge"
    .. "?callback=jQuery&username=" .. url_encode(username)
    .. "&ip=" .. url_encode(ip) .. "&_=" .. ts
  local body = http_get(url)
  local data = parse_jsonp(body)
  if not data or data.ecode ~= 0 then
    log("WARN", "challenge 失败")
    return nil
  end
  return data.challenge, data.client_ip or ip
end

local OCCUPY_HINTS = {
  "Authentication success", "auth_info_error", "already", "online",
  "existed", "occupied", "user_is_online", " jurisdiction",
}

local function looks_occupied(msg)
  if not msg then return false end
  local low = msg:lower()
  for _, h in ipairs(OCCUPY_HINTS) do
    if low:find(h:lower(), 1, true) then return true end
  end
  return false
end

-- 返回 true/false, 响应文本
local function srun_login()
  local challenge, client_ip = get_challenge()
  if not challenge then return false, "challenge_failed" end

  local username = CONFIG.username .. CONFIG.domain
  local f = bx1.build_login_fields(username, CONFIG.password, "127.0.0.1", CONFIG.ac_id, challenge, client_ip)

  local fields = {
    action = "login", username = username, password = f.encoded_password,
    ac_id = CONFIG.ac_id, ip = client_ip, info = f.info_field,
    chksum = f.chksum, n = f.n, type = f.type,
  }
  local body = http_post("http://" .. CONFIG.portal_host .. "/cgi-bin/srun_portal", fields)

  if not body then return false, "post_failed" end
  if body:match("^login_ok") then return true, "login_ok" end
  local data = parse_jsonp(body)
  if data and (data.ecode == 0 or data.res == "ok") then return true, "ok" end
  -- 提取错误描述
  local err = body:match("^login_error,([^,]*)") or (data and (data.error_msg or data.error)) or body:sub(1, 80)
  return false, err
end

-- ==================== 占用解绑（rad_user_dm）====================
-- sign = sha1(time .. username .. ip .. unbind .. time)，unbind=1
-- 真机实测（2026-11-19）：
--   * username 必须用不带域的纯账号（带 @study 返回 some_parameter_error）
--   * 接口是 JSONP GET（前端 _logoutDm 用 ajax.jsonp），不是 POST
--   * 成功返回 res="ok"；无在线设备返回 res="not_online_error"（也算达成目的）
local function release_device(ip)
  local t = tostring(os.time())
  local username = CONFIG.username  -- 纯账号，不带域
  local sign = bx1.sha1_hex(t .. username .. ip .. "1" .. t)
  local qs = "callback=jQuery&ip=" .. url_encode(ip)
    .. "&username=" .. url_encode(username)
    .. "&time=" .. url_encode(t) .. "&unbind=1&sign=" .. url_encode(sign)
  local url = "http://" .. CONFIG.portal_host .. "/cgi-bin/rad_user_dm?" .. qs
  local body = http_get(url)
  local ok = body and (body:find('"res":"ok"', 1, true) or body:find("res=ok", 1, true))
  local done = ok or (body and body:find("not_online_error", 1, true))
  log("INFO", "DM 解绑 ip=" .. ip .. " 结果=" .. (done and "成功" or "未成功")
    .. " 响应=" .. tostring(body and body:sub(1, 100)))
  return done and true or false
end

-- 从 rad_user_info 详情里挑出"非本机"的占用设备 IP
local function find_occupant_ip(info)
  if not info or not info.online_device_detail then return nil end
  local ok, detail = pcall(json.decode, info.online_device_detail)
  if not ok or type(detail) ~= "table" then return nil end
  -- 本机 WAN IP 不作为占用设备
  local own_ip = info.online_ip or ""
  for _, dev in pairs(detail) do
    if type(dev) == "table" and dev.ip and dev.ip ~= "" and dev.ip ~= own_ip then
      return dev.ip
    end
  end
  return nil
end

-- 解绑三道保险，返回是否允许解绑
local function can_release(info, state)
  if not CONFIG.auto_release then return false end
  -- 保险 1：本机已能联网 —— 没被占用
  if internet_ok() then
    log("INFO", "拒绝解绑：本机已能联网")
    return false
  end
  -- 保险 2：冷却期内
  local last = tonumber(state.last_release) or 0
  if os.time() - last < CONFIG.release_cooldown then
    log("INFO", "拒绝解绑：距上次解绑不足 " .. CONFIG.release_cooldown .. "s")
    return false
  end
  -- 保险 3：在线设备只有本机（无其他占用者）
  local occ = find_occupant_ip(info)
  if not occ then
    log("INFO", "拒绝解绑：在线设备中没有其他占用者")
    return false
  end
  return true, occ
end

-- ==================== 登录 + 联网验证（成功判定）====================
local function login_and_verify()
  local ok, msg = srun_login()
  if not ok then return false, msg end
  -- login_ok 不算数，必须探测通过
  for _ = 1, CONFIG.verify_attempts do
    socket.sleep(CONFIG.verify_interval)
    if internet_ok() then return true, "登录成功且联网验证通过" end
  end
  return false, "登录响应成功但联网未通"
end

-- ==================== 掉线恢复（含占用处理）====================
local function recover()
  local online, info = portal_status()

  -- 情况 A：服务端说已认证，但探测失败 —— 探测服务问题，不登录不解绑
  if online then
    log("INFO", "rad_user_info 显示已认证但外网探测失败，等待下轮（不登录）")
    return false
  end

  -- 情况 B：查询失败 —— 内网可能不通，等下轮
  if online == nil then
    log("WARN", "认证状态查询失败，跳过本轮恢复")
    return false
  end

  -- 情况 C：确认未认证 —— 先直接登录，绝不预先解绑
  log("INFO", "未认证，先尝试直接登录")
  local ok, msg = login_and_verify()
  if ok then return true end

  -- 情况 D：登录失败且疑似占用 —— 才考虑解绑
  if not looks_occupied(msg) then
    log("WARN", "登录失败（非占用）: " .. tostring(msg))
    return false
  end

  -- 重新查一次状态拿最新的在线设备（未认证时首次查询可能看不到占用者，
  -- 登录失败后服务端会话信息可能刷新；路由器视角下这里能看到占用设备）
  local _, fresh_info = portal_status()
  local target_info = fresh_info or info

  local state = load_state()
  local allowed, occ_ip = can_release(target_info, state)
  if not allowed then
    log("WARN", "登录疑似占用，但解绑保险未通过，不自动解绑")
    return false
  end

  log("WARN", "登录失败疑似占用，解绑设备 " .. occ_ip .. " 后重试一次")
  local released = release_device(occ_ip)
  state.last_release = os.time()
  save_state(state)
  if not released then
    log("WARN", "解绑接口未成功，仍尝试重试登录一次")
  end

  ok, msg = login_and_verify()  -- 只重试一次，不循环
  if ok then
    log("INFO", "解绑后重试登录成功")
    return true
  end
  log("WARN", "解绑后重试仍失败: " .. tostring(msg))
  return false
end

-- ==================== 主循环：轮询 + 退避 + 递增间隔 ====================
local function main_loop()
  load_config()
  log("INFO", "=== LZU 路由器认证启动 ===")
  log("INFO", "账号=" .. CONFIG.username .. CONFIG.domain .. " 域=" .. CONFIG.domain
    .. " 轮询阶梯=" .. table.concat(CONFIG.poll_intervals, ",")
    .. " 退避阶梯=" .. table.concat(CONFIG.backoff, ","))

  local consecutive_misses = 0   -- 连续探测失败轮数
  local consecutive_ok = 0       -- 连续成功轮数（决定轮询间隔）
  local consecutive_fail = 0     -- 连续恢复失败次数（决定退避）
  local state = load_state()

  while true do
    if internet_ok() then
      consecutive_misses = 0
      consecutive_ok = consecutive_ok + 1
      consecutive_fail = 0
      -- 轮询间隔随连续成功次数递增：第1次60s，第2次120s……封顶用最后一个值
      local idx = math.min(consecutive_ok, #CONFIG.poll_intervals)
      local interval = CONFIG.poll_intervals[idx]
      log("INFO", "已联网，第 " .. consecutive_ok .. " 次连续正常，下次轮询 " .. interval .. "s")
      socket.sleep(interval)
    else
      consecutive_misses = consecutive_misses + 1
      consecutive_ok = 0
      if consecutive_misses < CONFIG.miss_threshold then
        log("INFO", "探测失败 " .. consecutive_misses .. "/" .. CONFIG.miss_threshold .. "，短等 15s 复核")
        socket.sleep(15)
      else
        log("WARN", "连续 " .. consecutive_misses .. " 轮探测失败，进入恢复流程")
        local ok = recover()
        if ok then
          consecutive_fail = 0
          consecutive_misses = 0
          state.last_fail = nil
          save_state(state)
          log("INFO", "恢复成功，回到轮询模式")
        else
          consecutive_fail = consecutive_fail + 1
          local idx = math.min(consecutive_fail, #CONFIG.backoff)
          local delay = CONFIG.backoff[idx]
          state.last_fail = os.time()
          save_state(state)
          log("WARN", "恢复失败第 " .. consecutive_fail .. " 次，退避 " .. delay .. "s")
          socket.sleep(delay)
        end
      end
    end
  end
end

-- ==================== 命令行入口 ====================
local cmd = arg and arg[1] or "run"
if cmd == "run" then
  main_loop()
elseif cmd == "once" then
  load_config()
  if internet_ok() then
    print("ONLINE")
  else
    print("OFFLINE -> recover: " .. tostring(recover()))
  end
elseif cmd == "status" then
  load_config()
  local online, info = portal_status()
  print("portal_online=" .. tostring(online))
  if info then
    print("online_ip=" .. tostring(info.online_ip))
    print("domain=" .. tostring(info.domain))
    print("device_total=" .. tostring(info.online_device_total))
  end
  print("internet=" .. tostring(internet_ok()))
else
  print("用法: lua lzu_auth.lua [run|once|status]")
end
