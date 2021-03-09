-- Copyright (c) winking.io
-- winking324@gmail.com
-- use [lua-pack](https://github.com/Kong/lua-pack) to pack/unpack data
-- 


require("lua_pack")


local pack = string.pack
local unpack = string.unpack


local _M = {}


function _M.pack_uint16(x)
  return pack("<S", x)
end


function _M.unpack_uint16(s, p)
  p = p or 1
  if #s < p + 1 then
    return p, nil
  end
  return unpack(s, "<S", p)
end


function _M.pack_uint32(x)
  return pack('<I', x)
end


function _M.unpack_uint32(s, p)
  p = p or 1
  if #s < p + 3 then
    return p, nil
  end
  return unpack(s, "<I", p)
end


function _M.pack_string(x)
  return _M.pack_uint16(#x) .. x
end


function _M.unpack_string(s, p)
  local data_length
  p, data_length = _M.unpack_uint16(s, p)
  if not data_length then
    return p, nil
  end
  if #s < p + data_length - 1 then
    return p - 2, nil
  end
  return p + data_length, string.sub(s, p, p + data_length)
end


function _M.pack_map_uint32(x)
  local ret = _M.pack_uint16(#x)

  table.sort(x, function(l, r) return l.k < r.k end)
  for _, m in ipairs(x) do
    ret = ret .. _M.pack_uint16(m.k) .. _M.pack_uint32(m.v)
  end
  return ret
end


function _M.unpack_map_uint32(s, p)
  local data_length
  p, data_length = _M.unpack_uint16(s, p)
  if not data_length then
    return p, nil
  end

  local start_pos = p - 2
  local data = {}
  for i = 1, data_length do
    local k, v
    p, k = _M.unpack_uint16(s, p)
    p, v = _M.unpack_uint32(s, p)
    if not k or not v then
      return start_pos, nil
    end
    data[#data + 1] = { k = k, v = v }
  end
  return p, data
end


function _M.pack_map_string()
  local ret = _M.pack_uint16(#x)

  table.sort(x, function(l, r) return l.k < r.k end)
  for _, m in ipairs(x) do
    ret = ret .. _M.pack_uint16(m.k) .. _M.pack_string(m.v)
  end
  return ret
end


function _M.unpack_map_string(s, p)
  local data_length
  p, data_length = _M.unpack_uint16(s, p)
  if not data_length then
    return p, nil
  end

  local start_pos = p - 2
  local data = {}
  for i = 1, data_length do
    local k, v
    p, k = _M.unpack_uint16(s, p)
    p, v = _M.unpack_string(s, p)
    if not k or not v then
      return start_pos, nil
    end
    data[#data + 1] = { k = k, v = v }
  end
  return p, data
end


return _M