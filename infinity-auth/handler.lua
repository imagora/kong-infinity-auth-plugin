-- Copyright (c) winking.io
-- winking324@gmail.com
-- 


local access = require "kong.plugins.infinity-auth.access"


local InfinityAuthHandler = {}


function InfinityAuthHandler:access(conf)
  access.execute(conf)
end


InfinityAuthHandler.PRIORITY = 1002
InfinityAuthHandler.VERSION = "1.0.0"


return InfinityAuthHandler
