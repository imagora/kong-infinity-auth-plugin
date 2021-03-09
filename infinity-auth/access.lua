-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local utils = require "kong.plugins.infinity-auth.utils"
local basicauth = require "kong.plugins.infinity-auth.basicauth"
local hmacauth = require "kong.plugins.infinity-auth.hmacauth"
local agoraauth = require "kong.plugins.infinity-auth.agoraauth"


local re_gmatch = ngx.re.gmatch
local auth_method = {
  ["basic"] = function(data, conf)
    if not conf.basicauth.enabled then
      return utils.invalid_type()
    end
    return basicauth.execute(data, conf)
  end,
  ["hmac"] = function(data, conf)
    if not conf.hmacauth.enabled then
      return utils.invalid_type()
    end
    return hmacauth.execute(data, conf)
  end,
  ["agora"] = function(data, conf)
    if not conf.agoraauth.enabled then
      return utils.invalid_type()
    end
    return agoraauth.execute(data, conf)
  end,
}


local _M = {}


local function do_authentication(conf)
  local header_name = "proxy-authorization"
  local authorization = kong.request.get_header(header_name)
  if not authorization then
    header_name = "authorization"
    authorization = kong.request.get_header(header_name)
    if not authorization then
      return false, { status = 401, message = "Unauthorized" }
    end
  end

  local iterator, iter_err = re_gmatch(authorization, "(\\s*[a-zA-Z]+)\\s*(.*)")
  if not iterator then
    kong.log.err(iterator)
    return utils.invalid_authentication()
  end

  local m, err = iterator()
  if err then
    kong.log.err(err)
    return utils.invalid_authentication()
  end

  local auth_info = {}
  if m and #m >= 2 then
    auth_info.type = string.lower(m[1])
    auth_info.data = m[2]
  end

  local method = auth_method[auth_info.type]
  if not method then
    return utils.invalid_type()
  end

  if conf.hide_credentials then
    kong.service.request.clear_header(header_name)
  end

  return method(auth_info.data, conf)
end


function _M.execute(conf)
  if kong.client.get_credential() then
    return
  end

  local ok, err = do_authentication(conf)
  if not ok then
      return kong.response.exit(err.status, { message = err.message }, err.headers)
  end
end


return _M
