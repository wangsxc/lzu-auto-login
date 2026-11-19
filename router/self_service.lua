--[[
self_service.lua — 自助服务账密 SSO 解绑（路由器版，Lua 5.1 + curl）

账密会话（PHPSESSID_8800）与网络来源 IP 无关，能看到并踢掉账号下任意在线设备
—— 这正是 rad_user_dm/rad_user_info 做不到的（它们按来源 IP 判断，未认证时
看不到占用者）。真机验证 2026-11-19。

链路：
  1. curl /site/sso?data=base64("zh-CN:<账号>:<md5(密码)>")  -> 拿 cookie
  2. curl /home  -> 解析在线设备表格（id / IP / user_mac / csrf）
  3. curl -X POST /home/delete?id=&user_mac=  （带 csrf cookie） -> 下线设备

依赖：curl（路由器有）、openssl（算 md5）、Lua string 处理。
无副作用模块，可单独测试。
]]

local M = {}

local function url_encode(s)
  if not s then return "" end
  return (s:gsub("([^%w%-_%.~])", function(c) return string.format("%%%02X", c:byte()) end))
end

-- 调 openssl 算 md5（hex），输入经临时文件避免特殊字符/注入
local function md5_hex(input)
  local tmp = "/tmp/.lzu_md5_" .. tostring(os.time()) .. "_" .. tostring(math.floor(os.clock() * 1e6))
  local f = assert(io.open(tmp, "wb")); f:write(input); f:close()
  local h = io.popen("openssl dgst -md5 -r < " .. tmp .. " 2>/dev/null", "r")
  local out = h:read("*a") or ""; h:close(); os.remove(tmp)
  return (out:gsub("%s+", ""):match("^(%x+)") or "")
end

--[[
用 curl 带 cookie jar 发请求，返回 body。
cookie_jar: 文件路径，跨请求保持 PHPSESSID_8800。
method/data: nil=GET，否则 POST。
]]
local function curl_request(base, path, cookie_jar, method, data)
  -- -L 跟随 SSO 的 302 跳转到 /home（真机 SSO 返回 302）
  local cmd = 'curl -sk -L --max-time 12 -b "' .. cookie_jar .. '" -c "' .. cookie_jar .. '" '
  if method == "POST" then
    cmd = cmd .. "-X POST --data '" .. data .. "' "
  end
  cmd = cmd .. '"' .. base .. path .. '" 2>/dev/null'
  local h = io.popen(cmd, "r")
  local out = h:read("*a") or ""
  h:close()
  return out
end

--[[
自助服务登录。成功返回 cookie_jar 路径，失败返回 nil, 原因。
]]
function M.login(base, username, password)
  local cookie_jar = "/tmp/.lzu_8800_cookie_" .. tostring(os.time())
  local payload = "zh-CN:" .. username .. ":" .. md5_hex(password)
  local mime = require("mime")
  local encoded = mime.b64(payload)
  local path = "/site/sso?data=" .. url_encode(encoded)
  local body = curl_request(base, path, cookie_jar)
  -- home 页面标志：在线设备表格 且 不是登录页
  local home_ok = (body:find("data%-key", 1, false) or body:find("学生办公", 1, true) ~= nil)
    and not body:find("login%-form", 1, false)
  if home_ok then
    return cookie_jar
  end
  os.remove(cookie_jar)
  return nil, "SSO 未进入 home"
end

--[[
解析 /home 页的在线设备。返回列表 + csrf。
每项 {id, ip, product, user_mac, delete_path}
]]
function M.list_devices(base, cookie_jar)
  local body = curl_request(base, "/home", cookie_jar)
  local csrf = body:match('name="_csrf%-8800"%s+value="([^"]+)"')
  local devices = {}
  -- 真机：<tr class="w1" data-key="101601843"> ... <td>user</td><td>ip</td>...<td>product</td> ... href="/home/delete?id=..&amp;user_mac=.."
  -- Lua 5.1 模式不支持可控的非贪婪，用 find 逐行解析
  local pos = 1
  while true do
    local s, e, rid = body:find('<tr[^>]*data%-key="(%d+)"[^>]*>(.-)</tr>', pos)
    if not s then break end
    local row = body:sub(s, e)
    local cells = {}
    for c in row:gmatch('<td[^>]*>(.-)</td>') do
      local txt = c:gsub('<[^>]+>', ''):gsub('^%s+', ''):gsub('%s+$', '')
      cells[#cells + 1] = txt
    end
    local dhref = row:match('href="(/home/delete%?[^"]+)"')
    local umac = dhref and dhref:match('user_mac=([^&"]+)') or ""
    devices[#devices + 1] = {
      id = rid,
      user = cells[1] or "",
      ip = cells[2] or "",
      product = cells[4] or "",
      user_mac = umac,
      delete_path = dhref and dhref:gsub("&amp;", "&") or "",
    }
    pos = e + 1
  end
  return devices, csrf
end

--[[
下线指定设备。device 来自 list_devices。
]]
function M.kick_device(base, cookie_jar, csrf, device)
  if not device or not device.delete_path or device.delete_path == "" then
    return false, "设备无下线链接"
  end
  local q = device.delete_path:match("%?(.*)$") or ""
  local did = q:match("id=(%d+)") or device.id
  local umac = q:match("user_mac=([^&]+)") or device.user_mac
  -- href 里的 mac 已是 URL 编码（a4%3Aa9...），先解码再编码，避免双重编码
  umac = umac:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end)
  local data = "id=" .. url_encode(did) .. "&user_mac=" .. url_encode(umac)
  if csrf and csrf ~= "" then
    data = data .. "&_csrf%-8800=" .. url_encode(csrf)
  end
  curl_request(base, "/home/delete", cookie_jar, "POST", data)
  return true, "已下线 id=" .. did
end

--[[
只列在线设备 IP（账密 SSO）。这是主程序真正需要的唯一能力：
拿到占用者 IP 后交给 srun_portal 的 action=logout 注销。

真机实测：logout 按 ip 参数查会话、不校验来源 IP，任何设备都能踢；
而本模块的 /home/delete 对 @study 产品一律返回「下线请求失败」，
所以 kick_device 只作备用。

返回 ips 表, 或 nil + 原因。
]]
function M.list_ips(base, username, password, logf)
  local log = logf or function() end
  local jar, err = M.login(base, username, password)
  if not jar then return nil, "自助服务登录失败: " .. tostring(err) end
  local devices = M.list_devices(base, jar)
  os.remove(jar)
  local ips = {}
  for _, d in ipairs(devices) do
    if d.ip and d.ip ~= "" then ips[#ips + 1] = d.ip end
  end
  log("在线设备: " .. (#ips > 0 and table.concat(ips, ",") or "无"))
  return ips
end

--[[
完整解绑（旧路径，备用）：登录 -> 列设备 -> 踢掉非本机设备。
own_ip: 本机在服务端眼中的 IP（排除自己）。
返回 ok, 说明。
]]
function M.release_occupant(base, username, password, own_ip, logf)
  local log = logf or function() end
  local jar, err = M.login(base, username, password)
  if not jar then return false, "自助服务登录失败: " .. tostring(err) end
  log("自助服务 SSO 登录成功")

  local devices, csrf = M.list_devices(base, jar)
  log("在线设备数: " .. #devices)
  if #devices == 0 then
    os.remove(jar)
    return false, "没有在线设备"
  end
  if #devices == 1 and own_ip ~= "" and devices[1].ip == own_ip then
    os.remove(jar)
    return false, "在线设备只有本机，拒绝自我解绑"
  end

  local target = nil
  for _, d in ipairs(devices) do
    if not (own_ip ~= "" and d.ip == own_ip) and d.delete_path ~= "" then
      target = d
      break
    end
  end
  if not target then
    os.remove(jar)
    return false, "没有找到可下线的非本机设备"
  end

  log("选择占用设备: ip=" .. target.ip .. " id=" .. target.id)
  local ok, msg = M.kick_device(base, jar, csrf, target)
  os.remove(jar)
  return ok, msg .. " ip=" .. target.ip
end

return M
