-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local utils = require "kong.plugins.infinity-auth.utils"
local crypto = require "kong.plugins.infinity-auth.crypto"


local decode_base64 = ngx.decode_base64
local re_match = ngx.re.match
local error = error
local kong = kong


local _M = {}


local function retrieve_credentials(auth_data, conf)
  local username, password
  local decoded_basic = decode_base64(auth_data)
  if decoded_basic then
    local basic_parts, err = re_match(decoded_basic, "([^:]+):(.*)", "oj")
    if err then
      kong.log.err(err)
      return
    end

    if not basic_parts then
      kong.log.err("header has unrecognized format")
      return
    end

    username = basic_parts[1]
    password = basic_parts[2]
  end
  return username, password
end


local function validate_credentials(credential, given_password)
  local digest, err = crypto.hash(credential.consumer.id, given_password)
  if err then
    kong.log.err(err)
  end

  return credential.password == digest
end


function _M.execute(data, conf)
  local credential
  local given_username, given_password = retrieve_credentials(data, conf)
  if given_username and given_password then
    credential = utils.load_credential(kong.db.basicauth_credentials, 
                                       kong.db.basicauth_credentials.select_by_username,
                                       given_username)
  end

  if not credential or not validate_credentials(credential, given_password) then
    return utils.invalid_authentication()
  end

  local consumer, err = utils.retrieve_consumer(credential.consumer.id)
  if err then
    return error(err)
  end

  utils.set_consumer(consumer, credential)
  return true
end


return _M
