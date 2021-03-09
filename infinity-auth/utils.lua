-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local constants = require "kong.constants"


local kong = kong


local _M = {}


local function load_credential_into_memory(db, method, user_key)
  local key, err = method(db, user_key)
  if err then
    return nil, err
  end
  return key
end


function _M.load_credential(db, method, user_key)
  local credential, err
  if user_key then
    local credential_cache_key = db:cache_key(user_key)
    credential, err = kong.cache:get(credential_cache_key, nil,
                                     load_credential_into_memory, db,
                                     method, user_key)
  end

  if err then
    return error(err)
  end

  return credential
end


function _M.invalid_authentication()
  return false, { status = 401, message = "Invalid authentication credentials" }
end


function _M.invalid_type()
  return false, { status = 401, message = "Invalid authentication type" }
end


function _M.invalid_signature()
  return false, { status = 401, message = "HMAC signature cannot be verified" }
end


function _M.invalid_date()
  return false, {
    status = 401,
    message = "HMAC signature cannot be verified, a valid date or " ..
              "x-date header is required for HMAC Authentication"
  }
end


function _M.invalid_user()
  return false, { status = 401, message = "Invalid channel-name or uid" }
end


function _M.invalid_token()
  return false, { status = 401, message = "Invalid token" }
end


function _M.mismatch_signature()
  return false, { status = 401, message = "HMAC signature does not match" }
end


function _M.token_expired()
  return false, { status = 401, message = "Token is expired" }
end


function _M.retrieve_consumer(consumer)
  local consumer_cache_key = kong.db.consumers:cache_key(consumer)
  return kong.cache:get(consumer_cache_key, nil, kong.client.load_consumer, consumer)
end


function _M.set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.username then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.username)
    set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
    clear_header(constants.HEADERS.CREDENTIAL_USERNAME)
  end

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end


return _M
