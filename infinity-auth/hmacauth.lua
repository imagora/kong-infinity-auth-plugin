-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local utils = require "kong.plugins.infinity-auth.utils"
local kong_utils = require "kong.tools.utils"
local sha256 = require "resty.sha256"
local openssl_hmac = require "resty.openssl.hmac"


local ngx = ngx
local kong = kong
local error = error
local time = ngx.time
local abs = math.abs
local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64
local parse_time = ngx.parse_http_time
local re_gmatch = ngx.re.gmatch
local hmac_sha1 = ngx.hmac_sha1
local ipairs = ipairs
local fmt = string.format


local hmac = {
  ["hmac-sha256"] = function(secret, data)
    return openssl_hmac.new(secret, "sha256"):final(data)
  end,
  ["hmac-sha384"] = function(secret, data)
    return openssl_hmac.new(secret, "sha384"):final(data)
  end,
  ["hmac-sha512"] = function(secret, data)
    return openssl_hmac.new(secret, "sha512"):final(data)
  end,
}


local _M = {}


local function list_as_set(list)
  local set = kong.table.new(0, #list)
  for _, v in ipairs(list) do
    set[v] = true
  end

  return set
end


local function create_hash(request_uri, hmac_params)
  local signing_string = ""
  local hmac_headers = hmac_params.hmac_headers

  local count = #hmac_headers
  for i = 1, count do
    local header = hmac_headers[i]
    local header_value = kong.request.get_header(header)

    if not header_value then
      if header == "request-line" then
        -- request-line in hmac headers list
        local request_line = fmt("%s %s HTTP/%.01f",
                                 kong.request.get_method(),
                                 request_uri,
                                 assert(kong.request.get_http_version()))
        signing_string = signing_string .. request_line
      else
        signing_string = signing_string .. header .. ":"
      end
    else
      signing_string = signing_string .. header .. ":" .. " " .. header_value
    end

    if i < count then
      signing_string = signing_string .. "\n"
    end
  end

  return hmac[hmac_params.algorithm](hmac_params.secret, signing_string)
end


local function validate_clock_skew(date_header_name, allowed_clock_skew)
  local date = kong.request.get_header(date_header_name)
  if not date then
    return false
  end

  local request_time = parse_time(date)
  if not request_time then
    return false
  end

  local skew = abs(time() - request_time)
  if skew > allowed_clock_skew then
    return false
  end

  return true
end


local function validate_params(params, conf)
  if not params.username or not params.signature then
    return false, "username or signature missing"
  end

  if conf.hmacauth.enforce_headers and #conf.hmacauth.enforce_headers >= 1 then
    local enforced_header_set = list_as_set(conf.hmacauth.enforce_headers)

    if params.hmac_headers then
      for _, header in ipairs(params.hmac_headers) do
        enforced_header_set[header] = nil
      end
    end

    for _, header in ipairs(conf.hmacauth.enforce_headers) do
      if enforced_header_set[header] then
        return false, "enforced header not used for signature creation"
      end
    end
  end

  for _, algo in ipairs(conf.hmacauth.algorithms) do
    if algo == params.algorithm then
      return true
    end
  end

  return false, fmt("algorithm %s not supported", params.algorithm)
end


local function validate_signature(hmac_params)
  local signature_1 = create_hash(kong.request.get_path_with_query(), hmac_params)
  local signature_2 = decode_base64(hmac_params.signature)
  if signature_1 == signature_2 then
    return true
  end

  -- DEPRECATED BY: https://github.com/Kong/kong/pull/3339
  local signature_1_deprecated = create_hash(ngx.var.uri, hmac_params)
  return signature_1_deprecated == signature_2
end


local function validate_body()
  local body, err = kong.request.get_raw_body()
  if err then
    kong.log.debug(err)
    return false
  end

  local digest_received = kong.request.get_header("digest")
  if not digest_received then
    -- if there is no digest and no body, it is ok
    return body == ""
  end

  local digest = sha256:new()
  digest:update(body or '')
  local digest_created = "SHA-256=" .. encode_base64(digest:final())

  return digest_created == digest_received
end


local function retrieve_hmac_fields(authorization_header)
  local hmac_params = {}
  if authorization_header then
    local iterator, iter_err = re_gmatch(authorization_header,
                                         "username=\"(.+)\",\\s*" ..
                                         "algorithm=\"(.+)\",\\s*" ..
                                         "headers=\"(.+)\",\\s*" ..
                                         "signature=\"(.+)\"")
    if not iterator then
      kong.log.err(iter_err)
      return
    end

    local m, err = iterator()
    if err then
      kong.log.err(err)
      return
    end

    if m and #m >= 4 then
      hmac_params.username = m[1]
      hmac_params.algorithm = m[2]
      hmac_params.hmac_headers = kong_utils.split(m[3], " ")
      hmac_params.signature = m[4]
    end
  end

  return hmac_params
end


function _M.execute(data, conf)
  local clock_skew = conf.hmacauth.clock_skew
  if not (validate_clock_skew("x-date", clock_skew) or validate_clock_skew("date", clock_skew)) then
    return utils.invalid_date()
  end

  local hmac_params = retrieve_hmac_fields(data)

  local ok, err = validate_params(hmac_params, conf)
  if not ok then
    kong.log.debug(err)
    return utils.invalid_signature()
  end

  local credential = utils.load_credential(kong.db.hmacauth_credentials, 
                                           kong.db.hmacauth_credentials.select_by_username, 
                                           hmac_params.username)
  if not credential then
    kong.log.debug("failed to retrieve credential for ", hmac_params.username)
    return utils.invalid_signature()
  end
  hmac_params.secret = credential.secret
  if not validate_signature(hmac_params) then
    return utils.mismatch_signature()
  end

  if conf.hmacauth.validate_request_body and not validate_body() then
    kong.log.debug("digest validation failed")
    return utils.mismatch_signature()
  end

  local consumer, err = utils.retrieve_consumer(credential.consumer.id)
  if err then
    return error(err)
  end

  utils.set_consumer(consumer, credential)
  return true
end


return _M
