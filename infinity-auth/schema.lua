-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local typedefs = require "kong.db.schema.typedefs"


local HMAC_ALGORITHMS = {
  "hmac-sha256",
  "hmac-sha384",
  "hmac-sha512",
}


local basicauth_record = {
  type = "record",
  fields = {
    { enabled = { type = "boolean", default = true, }, },
  },
}


local hmacauth_record = {
  type = "record",
  fields = {
    { enabled = { type = "boolean", default = true, }, },
    { clock_skew = { type = "number", default = 300, gt = 0 }, },
    { validate_request_body = { type = "boolean", default = false }, },
    { enforce_headers = {
        type = "array",
        elements = { type = "string" },
        default = {"host", "date", "request-line"},
    }, },
    { algorithms = {
        type = "array",
        elements = { type = "string", one_of = HMAC_ALGORITHMS },
        default = HMAC_ALGORITHMS,
    }, },
  },
}


local agoraauth_record = {
  type = "record",
  fields = {
    { enabled = { type = "boolean", default = true, }, },
  }
}


return {
  name = "infinity-auth",
  fields = {
    { consumer = typedefs.no_consumer },
    -- { run_on = typedefs.run_on_first },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { hide_credentials = { type = "boolean", default = true }, },
          { basicauth = basicauth_record },
          { hmacauth = hmacauth_record },
          { agoraauth = agoraauth_record },
        }
      },
    },
  },
}
