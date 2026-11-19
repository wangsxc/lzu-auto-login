--[[
srun_bx1.lua — 深澜 srun V1.18 认证协议（路由器版，纯 Lua 5.1）

从项目 Python 版 lzu_auto_login.py 逐函数移植，算法完全一致：
  - password = {MD5} + hex(HMAC-MD5(key=token, msg=原始密码))
  - info     = {SRBX1} + 换表Base64(XTEA(json, token))
  - chksum   = hex(SHA1(token+username+token+hmac+token+acid+token+ip+token+n+token+type+token+info))

本机实测环境：OpenWrt 18.06 / Lua 5.1.5，有 mime、cjson、socket，无 bit32/bit。
因此 XTEA 的 32 位运算用纯 Lua 算术模拟（16 位半字节异或表 + 取模）。

本模块无副作用、不读配置、不写日志，可单独测试。
]]

local M = {}

local mime = require("mime")

-- srun 自定义 Base64 字母表（与 Python 版 SRUN_ALPHA 一致）
local SRUN_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
local STD_ALPHA  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function make_trans(from, to)
  local t = {}
  for i = 1, #from do
    t[from:byte(i)] = to:byte(i)
  end
  return t
end

local TO_SRUN = make_trans(STD_ALPHA, SRUN_ALPHA)

-- 标准 Base64 -> srun 换表 Base64
function M.b64_srun(raw)
  local std = mime.b64(raw)
  local out = {}
  for i = 1, #std do
    local c = std:byte(i)
    out[i] = TO_SRUN[c] and string.char(TO_SRUN[c]) or string.char(c)  -- '=' 填充原样保留
  end
  return table.concat(out)
end

-- ============ 32 位无符号运算（Lua 5.1 无位运算库）============

local MOD32 = 4294967296  -- 2^32

-- 半字节异或查表（16x16），组合成 8 位再组合成 32 位
local XOR4 = {}
for i = 0, 15 do
  XOR4[i] = {}
  for j = 0, 15 do
    local r = 0
    for k = 0, 3 do
      if math.floor(i / 2^k) % 2 ~= math.floor(j / 2^k) % 2 then
        r = r + 2^k
      end
    end
    XOR4[i][j] = r
  end
end

local function xor8(a, b)
  return XOR4[a % 16][b % 16] + 16 * XOR4[math.floor(a / 16) % 16][math.floor(b / 16) % 16]
end

local function bxor(a, b)
  return xor8(a % 256, b % 256)
       + 256 * xor8(math.floor(a / 256) % 256, math.floor(b / 256) % 256)
       + 65536 * xor8(math.floor(a / 65536) % 256, math.floor(b / 65536) % 256)
       + 16777216 * xor8(math.floor(a / 16777216) % 256, math.floor(b / 16777216) % 256)
end

local function lshift(x, n) return (x * 2^n) % MOD32 end
local function rshift(x, n) return math.floor(x / 2^n) end
local function u32(x) return x % MOD32 end

-- 字符串 -> uint32 小端数组（带长度前缀时末尾追加字节数）
local function str_to_u32(str, with_len)
  local v, n, i = {}, #str, 1
  while i <= n do
    local val = 0
    for j = 0, 3 do
      local c = str:byte(i + j)
      if c then val = val + c * 256^j end
    end
    v[#v + 1] = val
    i = i + 4
  end
  if with_len then v[#v + 1] = n end
  return v
end

-- uint32 小端数组 -> 字符串（每元素固定输出 4 字节）
local function u32_to_str(arr)
  local parts = {}
  for i = 1, #arr do
    local val = arr[i]
    parts[#parts + 1] = string.char(val % 256)
    parts[#parts + 1] = string.char(math.floor(val / 256) % 256)
    parts[#parts + 1] = string.char(math.floor(val / 65536) % 256)
    parts[#parts + 1] = string.char(math.floor(val / 16777216) % 256)
  end
  return table.concat(parts)
end

--[[
XTEA 编码，逐行对应 Python _xtea_encode()。
注意 Python 版的 MX 运算顺序是：
    m  = (z>>5 ^ y<<2)
    m += (y>>3 ^ z<<4 ^ (d ^ y))
    m += k[(p&3)^e] ^ z
即三段【相加】（等价于标准 XTEA 在低 32 位上的结果），这里严格照搬。
]]
function M.xtea_encode(msg, key)
  if msg == "" then return "" end

  local v = str_to_u32(msg, true)
  local k = str_to_u32(key, false)
  while #k < 4 do k[#k + 1] = 0 end

  local n = #v - 1
  local z = v[n + 1]
  local y = v[1]
  local delta = 2654435769  -- 0x9E3779B9
  local q = 6 + math.floor(52 / (n + 1))
  local d = 0

  local function mx(p, e)
    local m = bxor(rshift(z, 5), lshift(y, 2))
    m = u32(m + bxor(bxor(rshift(y, 3), lshift(z, 4)), bxor(d, y)))
    m = u32(m + bxor(k[bxor(p % 4, e) + 1] or 0, z))
    return m
  end

  while q > 0 do
    q = q - 1
    d = u32(d + delta)
    local e = rshift(d, 2) % 4

    for p = 0, n - 1 do
      y = v[p + 2]
      local m = mx(p, e)
      z = u32(v[p + 1] + m)
      v[p + 1] = z
    end

    -- JS 循环结束后 p === n；Lua 这里显式用 n（对应 Python 的注释坑）
    y = v[1]
    local m = mx(n, e)
    z = u32(v[n + 1] + m)
    v[n + 1] = z
  end

  return u32_to_str(v)
end

-- ============ openssl 摘要（SHA1 / HMAC-MD5）============

-- 调 openssl 摘要，stdin 内容来自临时文件（避免特殊字符与命令行注入）
local function digest(cmd, input)
  local tmp = "/tmp/.lzu_digest_" .. tostring(os.time()) .. "_" .. tostring(math.floor(os.clock() * 1000000))
  local f = assert(io.open(tmp, "wb"))
  f:write(input)
  f:close()
  local h = io.popen(cmd .. " < " .. tmp .. " 2>/dev/null", "r")
  local out = h:read("*a") or ""
  h:close()
  os.remove(tmp)
  return (out:gsub("%s+", ""))
end

-- hex(HMAC-MD5(key=token, msg=password))
function M.hmac_md5_hex(key, msg)
  -- key 只允许 [0-9a-f]，来自服务端 challenge，安全
  local out = digest("openssl dgst -md5 -r -hmac '" .. key .. "'", msg)
  return out:match("^(%x+)") or ""
end

-- hex(SHA1(data))
function M.sha1_hex(data)
  local out = digest("openssl dgst -sha1 -r", data)
  return out:match("^(%x+)") or ""
end

-- ============ 组装 info 字段 ============

-- JSON 字符串转义（与 Python json.dumps 对常见字符一致）
local function json_str(s)
  s = s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\n', '\\n'):gsub('\r', '\\r'):gsub('\t', '\\t')
  return '"' .. s .. '"'
end

-- 紧凑 JSON（字段顺序与 Python dict 一致）
local function info_json(username, password, ip, acid, enc_ver)
  return '{"username":' .. json_str(username)
    .. ',"password":' .. json_str(password)
    .. ',"ip":' .. json_str(ip)
    .. ',"acid":' .. json_str(acid)
    .. ',"enc_ver":' .. json_str(enc_ver) .. '}'
end

-- 返回 {encoded_password, info_field, chksum, client_ip}
-- challenge / client_ip 由调用方从 get_challenge 取得后传入
function M.build_login_fields(username, password, ip, acid, challenge, client_ip)
  local n_val, type_val, enc_ver = "200", "1", "srun_bx1"

  local hmac_hex = M.hmac_md5_hex(challenge, password)
  local encoded_password = "{MD5}" .. hmac_hex

  local ijson = info_json(username, password, client_ip, acid, enc_ver)
  local encoded_info = M.xtea_encode(ijson, challenge)
  local info_field = "{SRBX1}" .. M.b64_srun(encoded_info)

  local chkstr = challenge .. username
    .. challenge .. hmac_hex
    .. challenge .. acid
    .. challenge .. client_ip
    .. challenge .. n_val
    .. challenge .. type_val
    .. challenge .. info_field
  local chksum = M.sha1_hex(chkstr)

  return {
    encoded_password = encoded_password,
    info_field = info_field,
    chksum = chksum,
    n = n_val,
    type = type_val,
  }
end

return M
