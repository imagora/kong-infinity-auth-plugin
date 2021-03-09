-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local packer = require "kong.plugins.infinity-auth.agora.packer"
local sha256 = require "resty.sha256"
local openssl_hmac = require "resty.openssl.hmac"


local decode_base64 = ngx.decode_base64
local encode_base64 = ngx.encode_base64

local crc32_short = ngx.crc32_short
local crc32_long = ngx.crc32_long



local _AccessToken = {
  app_id = "",
  app_cert = "",
  channel_name = "",
  uid = "",
  expire_ts = 0,
  salt = 0,
  privileges = {},
}


function _AccessToken:new(o, app_id, app_cert, channel_name, uid)
  o = o or {}
  self.__index = self
  setmetatable(o, self)

  self.app_id = app_id or ""
  self.app_cert = app_cert or ""
  self.channel_name = channel_name or ""

  self.expire_ts = os.time() + 24 * 3600

  math.randomseed(self.expire_ts)
  self.salt = math.random(99999999)

  if not uid or uid == 0 then
    self.uid = ''
  else
    self.uid = tostring(uid)
  end

  self.privileges = {}
  return o
end


function _AccessToken:get_version()
  return "006"
end


function _AccessToken:add_privilege(privilege, expire_ts)
  self.privileges[#self.privileges + 1] = { k = privilege, v = expire_ts }
end


function _AccessToken:build()
  local message = packer.pack_uint32(self.salt) .. packer.pack_uint32(self.expire_ts) .. packer.pack_map_uint32(self.privileges)
  local signing = self.app_id .. self.channel_name .. self.uid .. message
  local digest = openssl_hmac.new(self.app_cert, "sha256"):final(signing)

  local channel_name_crc = crc32_short(self.channel_name)
  local uid_crc = crc32_short(self.uid)

  local content = packer.pack_string(digest) .. packer.pack_uint32(channel_name_crc) .. packer.pack_uint32(uid_crc) .. packer.pack_string(message)
  local token = _AccessToken:get_version() .. self.app_id .. encode_base64(content)
  return token
end


function _AccessToken:from_string(origin_token)
  local pos = 1
  local version_length = 3
  local origin_version = string.sub(origin_token, pos, 3)
  if origin_version ~= self:get_version() then
    return false
  end

  local app_id_length = 32
  if #origin_token < version_length + app_id_length then
    return false
  end

  pos = pos + version_length
  self.app_id = string.sub(origin_token, pos, version_length + app_id_length)

  pos = pos + app_id_length
  local content = decode_base64(string.sub(origin_token, pos))
  if not content then
    return false
  end

  local signature, channel_name_crc, uid_crc, message
  pos, signature = packer.unpack_string(content)
  if not signature then
    return false
  end

  pos, channel_name_crc = packer.unpack_uint32(content, pos)
  if not channel_name_crc then
    return false
  end

  pos, uid_crc = packer.unpack_uint32(content, pos)
  if not uid_crc then
    return false
  end

  pos, message = packer.unpack_string(content, pos)
  if not message then
    return false
  end

  pos, self.salt = packer.unpack_uint32(message)
  if not self.salt then
    return false
  end

  pos, self.expire_ts = packer.unpack_uint32(message, pos)
  if not self.expire_ts then
    return false
  end

  pos, self.privileges = packer.unpack_map_uint32(message, pos)
  if not self.privileges then
    return false
  end

  return true
end


return _AccessToken

