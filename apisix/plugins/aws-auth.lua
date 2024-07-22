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

local ngx                  = ngx
local ngx_time             = ngx.time
local ngx_re               = require("ngx.re")
local abs                  = math.abs
local core                 = require("apisix.core")
local consumer             = require("apisix.consumer")
local pairs                = pairs
local tab_concat           = table.concat
local tab_sort             = table.sort
local str_strip            = require("pl.stringx").strip
local hex_encode           = require("resty.string").to_hex

local ALGORITHM_KEY        = "X-Amz-Algorithm"
local CREDENTIAL_KEY       = "X-Amz-Credential"
local DATE_KEY             = "X-Amz-Date"
local SIGNED_HEADERS_KEY   = "X-Amz-SignedHeaders"
local SIGNATURE_KEY        = "X-Amz-Signature"
local EXPIRES_KEY          = "X-Amz-Expires"
local plugin_name          = "aws-auth"
local DEFAULT_MAX_REQ_BODY = 1024 * 512
local DEFAULT_CLOCK_SKEW   = 60 * 15
local DEFAULT_MAX_EXPIRES  = 60 * 60 * 24 * 7
local ALGO                 = "AWS4-HMAC-SHA256"

local utils                = require("apisix.plugins.aws-auth.utils")

local schema               = {
    type = "object",
    properties = {
        region = {
            type = "string",
            title = "Region to validate. Without validate if not provided.",
            default = nil,
        },
        service = {
            type = "string",
            title = "Service to validate. Without validate if not provided.",
            default = nil,
        },
        clock_skew = {
            type = "integer",
            title = "Clock skew allowed by the signature in seconds. Setting it to 0 will skip checking the date.",
            default = DEFAULT_CLOCK_SKEW
        },
        must_sign_headers = {
            type = "array",
            items = {
                type = "string",
                minLength = 1,
                maxLength = 50,
            },
            title = "The headers must be signed. According to the [AWS v4 signature](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html), at least `host` and `X-Amz-Date` are required.",
            default = { "host", DATE_KEY }
        },
        must_sign_all_headers = {
            type = "boolean",
            title = "All headers must be signed.",
            default = false,
        },
        keep_headers = {
            type = "boolean",
            title = "whether to keep the http request header",
            default = false,
        },
        keep_unsigned_headers = {
            type = "boolean",
            title = "whether to keep the unsigned http request header",
            default = false,
        },
        keep_query_string = {
            type = "boolean",
            default = false,
        },
        max_req_body = {
            type = "integer",
            title = "Max request body size.",
            default = DEFAULT_MAX_REQ_BODY,
        },
        header_auth = {
            type = "boolean",
            default = true,
        },
        query_string_auth = {
            type = "boolean",
            default = false,
        },
        max_expires = {
            type = "integer",
            title = "for query string auth method",
            default = DEFAULT_MAX_EXPIRES,
        }
        --TODO host check
    },
}

local consumer_schema      = {
    type = "object",
    properties = {
        access_key = {
            type = "string",
        },
        secret_key = {
            type = "string",
        },
    },
    encrypt_fields = { "access_key", "secret_key" },
    required = { "access_key", "secret_key" },
}

local _M                   = {
    version = 0.1,
    priority = 50,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema,
}

function _M.check_schema(conf, schema_type)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

-- function _M.init()
--     -- call this function when plugin is loaded
--     local attr = plugin.plugin_attr(plugin_name)
--     if attr then
--         core.log.info(plugin_name, " get plugin attr val: ", attr.val)
--     end
-- end


-- function _M.destroy()
--     -- call this function when plugin is unloaded
-- end


local function create_signature_key(key, datestamp, region, service)
    local kDate = utils.hmac256("AWS4" .. key, datestamp)
    local kRegion = utils.hmac256(kDate, region)
    local kService = utils.hmac256(kRegion, service)
    local kSigning = utils.hmac256(kService, "aws4_request")
    return kSigning
end

local function generate_signature(method, uri, query_string, headers, body, secret_key, time, region, service)
    -- Step 1: Create a canonical request

    -- computing canonical uri
    local canonical_uri = uri
    if canonical_uri == "" then
        canonical_uri = "/"
    end

    -- computing canonical query string
    local canonical_qs_table = {}
    local canonical_qs_i = 0
    for k, v in pairs(query_string) do
        canonical_qs_i = canonical_qs_i + 1
        canonical_qs_table[canonical_qs_i] = ngx.unescape_uri(k) .. "=" .. ngx.unescape_uri(v)
    end

    tab_sort(canonical_qs_table)
    local canonical_qs = tab_concat(canonical_qs_table, "&")

    -- computing canonical and signed headers
    local canonical_headers, signed_headers = {}, {}
    local signed_headers_i = 0
    for k, v in pairs(headers) do
        k = k:lower()
        signed_headers_i = signed_headers_i + 1
        signed_headers[signed_headers_i] = k
        -- strip starting and trailing spaces including strip multiple spaces into single space
        canonical_headers[k] = str_strip(v)
    end
    tab_sort(signed_headers)

    for i = 1, #signed_headers do
        local k = signed_headers[i]
        canonical_headers[i] = k .. ":" .. canonical_headers[k] .. "\n"
    end
    canonical_headers = tab_concat(canonical_headers, nil, 1, #signed_headers)
    signed_headers = tab_concat(signed_headers, ";")


    local canonical_request = method:upper() .. "\n"
        .. canonical_uri .. "\n"
        .. (canonical_qs or "") .. "\n"
        .. canonical_headers .. "\n"
        .. signed_headers .. "\n"
        .. utils.sha256(body or "")

    -- Step 2: Create a hash of the canonical request
    local hashed_canonical_request = utils.sha256(canonical_request)

    -- Step 3: Create a string to sign
    local amzdate = os.date("!%Y%m%dT%H%M%SZ", time) -- ISO 8601 20130524T000000Z
    local datestamp = os.date("!%Y%m%d", time)       -- Date w/o time, used in credential scope

    local credential_scope = datestamp .. "/" .. region .. "/" .. service .. "/aws4_request"
    local string_to_sign = ALGO .. "\n"
        .. amzdate .. "\n"
        .. credential_scope .. "\n"
        .. hashed_canonical_request

    -- Step 4: Calculate the signature
    local signature_key = create_signature_key(secret_key, datestamp, region, service)
    local signature = hex_encode(utils.hmac256(signature_key, string_to_sign))

    return signature
end

local function get_consumer(access_key)
    if not access_key then
        return nil, "missing access key"
    end

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        return nil, "Missing related consumer"
    end

    local consumers = consumer.consumers_kv(plugin_name, consumer_conf, "access_key")
    local consumer = consumers[access_key]
    if not consumer then
        return nil, "Invalid access key"
    end
    core.log.info("consumer: ", core.json.delay_encode(consumer))

    return consumer, nil
end

local function array_to_map(arr)
    local map = core.table.new(0, #arr)
    for _, v in ipairs(arr) do
        map[v] = true
    end

    return map
end

local function validate(conf, params)
    if not params.algorithm then
        return nil, "algorithm missing"
    end

    if params.algorithm ~= ALGO then
        return nil, "algorithm " .. params.algorithm .. " not supported"
    end

    if (not params.credential.access_key) or (not params.signature) then
        return nil, "access key or signature missing"
    end

    if conf.region and #conf.region > 0 then
        if not params.credential.region or params.credential.region ~= conf.region then
            return nil, "Credential should be scoped to a valid Region, not " .. params.credential.region
        end
    end

    if conf.service and #conf.service > 0 then
        if not params.credential.service or params.credential.service ~= conf.service then
            return nil, "Credential should be scoped to correct service: '" .. params.credential.service
        end
    end

    --TODO params.credential.date

    local time_to_validate = utils.iso8601_to_timestamp(params.date)
    core.log.info("clock_skew: ", conf.clock_skew)
    if (conf.clock_skew and conf.clock_skew > 0)
        or (params.query_string_auth) then
        if params.signed_headers[DATE_KEY] then
            return nil, DATE_KEY .. "is not signed"
        end

        core.log.info("params.date: ", params.date, " time_to_validate: ", time_to_validate)

        local now = ngx_time()
        local diff = abs(now - time_to_validate)
        core.log.info("timr diff: ", diff)
        if diff > conf.clock_skew then
            return nil, "Clock skew exceeded"
        end

        if conf.max_expires and conf.max_expires > 0 then
            if diff > conf.max_expires then
                return nil, "Signature expired: " .. params.date .. "is now earlier than " .. now
            end
        end
    end

    -- validate headers
    if conf.must_sign_headers and #conf.must_sign_headers > 0 then
        local headers_map = array_to_map(params.signed_headers)
        for _, must in ipairs(conf.must_sign_headers) do
            if not headers_map[must:lower()] then
                return nil, "header '" .. must .. "' must be signed"
            end
        end
    end

    if conf.must_sign_all_headers then
        local headers_map = array_to_map(params.signed_headers)
        for _, must in ipairs(params.header) do
            if not headers_map[must:lower()] then
                return nil, "header '" .. must .. "' must be signed"
            end
        end
    end

    local consumer, err = get_consumer(params.credential.access_key)
    if err then
        return nil, err
    end

    local headers_to_signature = {}
    for _, header_name in ipairs(params.signed_headers) do
        headers_to_signature[header_name] = params.headers[header_name]
    end

    local qs_to_signature = params.query_string
    if params.query_string_auth then
        qs_to_signature = {}
        for _, qs_name in ipairs(params.query_string) do
            if qs_name ~= ALGORITHM_KEY
                and qs_name ~= CREDENTIAL_KEY
                and qs_name ~= DATE_KEY
                and qs_name ~= EXPIRES_KEY
                and qs_name ~= SIGNED_HEADERS_KEY
                and qs_name ~= SIGNATURE_KEY then
                qs_to_signature[qs_name] = params.headers[qs_name]
            end
        end
    end

    local consumer_auth_conf  = consumer.auth_conf
    local secret_key          = consumer_auth_conf and consumer_auth_conf.secret_key
    local request_signature   = params.signature
    local generated_signature = generate_signature(
        params.method,
        params.uri,
        qs_to_signature,
        headers_to_signature,
        params.body,
        secret_key,
        time_to_validate,
        params.credential.region,
        params.credential.service
    )

    core.log.info("request_signature: ", request_signature,
        " generated_signature: ", generated_signature)

    if request_signature ~= generated_signature then
        return nil, "Invalid signature"
    end

    return consumer
end

local function parse_credential(credential)
    local credential_data = ngx_re.split(credential, "/")
    if #credential_data ~= 5 then
        return nil, "Bad Credential"
    end

    local credential = {
        access_key = credential_data[1],
        date = credential_data[2],
        region = credential_data[3],
        service = credential_data[4],
    }

    local credential_aws4_request = credential_data[4]
    if not credential_aws4_request == "aws4_request" then
        return nil, "Credential should be scoped with a valid terminator: 'aws4_request'"
    end

    return credential
end

local function get_params(ctx, conf)
    local params = {
        host = core.request.get_host(),
        method = core.request.get_method(ctx),
        uri = ctx.var.uri,
        query_string = core.request.get_uri_args(ctx),
        headers = core.request.headers(ctx),
    }

    local err
    if conf.max_req_body and conf.max_req_body > 0 then
        params.body, err = core.request.get_body(conf.max_req_body, ctx)
        if err then
            return nil, "Exceed body limit size"
        end
    end

    if conf.header_auth and params.headers["Authorization"] then
        local auth_string = params.headers["Authorization"]
        local auth_data = ngx.re.match(auth_string,
            [[([\w\-]+) (?:(?:Credential=([\w\-\/]+)|SignedHeaders=([\w;\-]+)|Signature=([\w\d]+))[, ]*)+]])

        if #auth_data ~= 4 then
            return nil, "Bad Authorization Header"
        end

        params.algorithm = auth_data[1]
        params.credential = auth_data[2]
        params.date = params.headers[DATE_KEY]
        params.signed_headers = auth_data[3]
        params.signature = auth_data[4]
    elseif conf.query_string_auth and params.query_string[ALGORITHM_KEY] then
        params.algorithm = params.query_string[ALGORITHM_KEY]
        params.credential = params.query_string[CREDENTIAL_KEY]
        params.date = params.query_string[DATE_KEY]
        params.signed_headers = params.query_string[SIGNED_HEADERS_KEY]
        params.signature = params.query_string[EXPIRES_KEY]
        params.expires = params.query_string[SIGNATURE_KEY]
        params.query_string_auth = true
    end

    params.signed_headers = params.signed_headers and ngx_re.split(params.signed_headers, ";")
    params.credential, err = parse_credential(params.credential)
    if err then
        return nil, err
    end

    return params, nil
end

function _M.rewrite(conf, ctx)
    local params, err = get_params(ctx, conf)
    if err then
        core.log.warn("client request can't be validated: ", err)
        return 401, { message = err }
    end

    local validated_consumer, err = validate(conf, params)
    if not validated_consumer then
        core.log.warn("client request can't be validated: ", err)
        return 401, { message = err }
    end
    core.log.info("validated_consumer: ", core.json.delay_encode(validated_consumer))

    local consumer_conf = consumer.plugin(plugin_name)
    consumer.attach_consumer(ctx, validated_consumer, consumer_conf)
    core.log.info("hit aws-auth rewrite")
end

return _M
