--
-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The ASF licenses this file to You under the Apache License, Version 2.0
-- (the "License"); you may not use this file except in compliance with
-- the License.  You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local hmac         = require("resty.hmac")
local resty_sha256 = require("resty.sha256")
local hex_encode   = require("resty.string").to_hex

local _M           = {}

---@param key string specifies the key to use when calculating the message authentication code (MAC).
---@param msg string
function _M.hmac256(key, msg)
    return hmac:new(key, hmac.ALGOS.SHA256):final(msg)
end

function _M.sha256(msg)
    local hash = resty_sha256:new()
    hash:update(msg)
    local digest = hash:final()
    return hex_encode(digest)
end

function _M.iso8601_to_timestamp(iso8601)
    -- Extract date and time components from the ISO 8601 string
    local year, month, day, hour, min, sec = iso8601:match("(%d%d%d%d)(%d%d)(%d%d)T(%d%d)(%d%d)(%d%d)Z")

    -- Convert the extracted components to numbers
    year = tonumber(year)
    month = tonumber(month)
    day = tonumber(day)
    hour = tonumber(hour)
    min = tonumber(min)
    sec = tonumber(sec)

    -- Create a table compatible with os.time
    local datetime = {
        year = year,
        month = month,
        day = day,
        hour = hour,
        min = min,
        sec = sec
    }

    -- Convert to Unix timestamp
    local timestamp = os.time(datetime)

    return timestamp
end

return _M
