-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local utils = require "kong.plugins.infinity-auth.utils"
local access_token = require "kong.plugins.infinity-auth.agora.access_token"


local kong = kong
local time = ngx.time


local _M = {}


function _M.execute(data, conf)
  local channel_name = kong.request.get_header("x-agora-channel-name")
  local uid = kong.request.get_header("x-agora-uid")
  if not channel_name and not uid then
    return utils.invalid_user()
  else
    if channel_name == '' and uid == '' then
      return utils.invalid_user()
    end
  end

  local token = access_token:new(nil, "", "", channel_name, uid)
  local ok = token:from_string(data)
  if not ok then
    return utils.invalid_token()
  end

  local credential = utils.load_credential(kong.db.hmacauth_credentials, 
                                           kong.db.hmacauth_credentials.select_by_username,
                                           token.app_id)
  if not credential then
    kong.log.warn("can not find consumer context. ", "appid : ", token.app_id)
    return utils.invalid_token()
  end

  token.app_cert = credential.secret
  local token_rebuild = token:build()
  if token_rebuild ~= data then
    return utils.invalid_token()
  end

  if token.expire_ts < time() then
    return utils.token_expired()
  end

  local consumer, err = utils.retrieve_consumer(credential.consumer.id)
  if err then
    return error(err)
  end

  utils.set_consumer(consumer, credential)
  return true
end


return _M
