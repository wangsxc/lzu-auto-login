package.path = "/overlay/lzu/?.lua;" .. package.path
local ss = require("self_service")
local json = require("cjson")
local f = io.open("/overlay/lzu/config.json", "r")
if not f then print("NO_CONFIG"); return end
local cfg = json.decode(f:read("*a")); f:close()
local base = cfg.self_service_base or "https://login.lzu.edu.cn:8800"
local jar, err = ss.login(base, cfg.username, cfg.password)
print("LOGIN=" .. tostring(jar and "OK" or ("FAIL:" .. tostring(err))))
if jar then
  local devs, csrf = ss.list_devices(base, jar)
  print("DEVICE_COUNT=" .. #devs)
  for _, d in ipairs(devs) do
    print("DEV id=" .. d.id .. " ip=" .. d.ip .. " product=" .. d.product .. " mac=" .. d.user_mac)
    print("  delete=" .. d.delete_path)
  end
  print("CSRF=" .. (csrf and csrf:sub(1, 20) .. "..." or "NONE"))
  os.remove(jar)
end
