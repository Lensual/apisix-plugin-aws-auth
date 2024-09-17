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

local require              = require
local ngx                  = ngx
local ngx_time             = ngx.time
local ngx_re               = require("ngx.re")
local ngx_re_split         = ngx_re.split
local ngx_re_match         = ngx.re.match
local abs                  = math.abs
local core                 = require("apisix.core")
local consumer             = require("apisix.consumer")
local ipairs               = ipairs

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

--- @class Config
--- @field region string
--- @field service string
--- @field clock_skew integer
--- @field must_sign_headers string[]
--- @field max_req_body integer
--- @field enable_header_method boolean
--- @field enable_query_string_method boolean
--- @field max_expires integer
--- @field keep_unsigned_headers boolean
--- @field keep_unsigned_query_string boolean


local schema = {
    type = "object",
    properties = {
        region                     = {
            type = "string",
            title = "Region to validate. Without validate if not provided.",
            default = nil,
        },
        service                    = {
            type    = "string",
            title   = "Service to validate. Without validate if not provided.",
            default = nil,
        },
        clock_skew                 = {
            type    = "integer",
            title   = "Clock skew allowed by the signature in seconds. "
                .. "The default value is 900 seconds (15 minutes). "
                .. "If `X-Amz-Date` is not in `must_sign_headers` parameter, an error will occur. "
                .. "Setting it to 0 will skip checking the date (UNSAFE).",
            default = DEFAULT_CLOCK_SKEW
        },
        must_sign_headers          = {
            type    = "array",
            items   = {
                type = "string"
            },
            title   = "The headers must be signed. "
                .. "According to the [AWS v4 signature](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html), "
                .. "at least `host` and `X-Amz-Date` are required. "
                .. "Case insensitive.",
            default = { "Host", DATE_KEY }
        },
        max_req_body               = {
            type    = "integer",
            title   = "Max request body size. "
                .. "The default value is 512 KB.",
            default = DEFAULT_MAX_REQ_BODY,
        },
        enable_header_method       = {
            type    = "boolean",
            title   =
                "Enable [HTTP authorization header](https://docs.aws.amazon.com/IAM/latest/UserGuide/aws-signing-authentication-methods.html#aws-signing-authentication-methods-http) method. "
                .. "The default is true.",
            default = true,
        },
        enable_query_string_method = {
            type    = "boolean",
            title   =
                "Enable [Query string parameters](https://docs.aws.amazon.com/IAM/latest/UserGuide/aws-signing-authentication-methods.html#aws-signing-authentication-methods-query) method. "
                .. "The default is true.",
            default = true,
        },
        max_expires                = {
            type    = "integer",
            title   = "Sets the maximum value allowed for the `X-Amz-Expires` parameter. "
                .. "The default value is 604800 seconds (7 days). "
                .. "Setting it to 0 will skip checking exprires limit (UNSAFE).",
            default = DEFAULT_MAX_EXPIRES,
        },
        keep_unsigned_headers      = {
            type    = "boolean",
            title   = "Whether to keep the unsigned request header. "
                .. "The default is false.",
            default = false,
        },
        keep_unsigned_query_string = {
            type    = "boolean",
            title   = "Whether to keep the unsigned request query string. "
                .. "The default is false.",
            default = false,
        },
        -- TODO host check
        -- TODO enable_header_method enable_query_string_method check
        -- TODO clock_skew and must_sign_headers check
        -- TODO clock_skew and max_expires check
    },
}


local consumer_schema = {
    type           = "object",
    properties     = {
        access_key = {
            type = "string",
        },
        secret_key = {
            type = "string",
        },
    },
    encrypt_fields = { "access_key", "secret_key" },
    required       = { "access_key", "secret_key" },
}


local _M = {
    version         = 0.1,
    priority        = 50,
    type            = 'auth',
    name            = plugin_name,
    schema          = schema,
    consumer_schema = consumer_schema,
}


--- check_schema
---
--- @param conf Config
--- @param schema_type unknown
--- @return boolean ok, string err
function _M.check_schema(conf, schema_type)
    core.log.info("input conf: ", core.json.delay_encode(conf))

    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

-- TODO check plugin schema


--- get_consumer
---
--- @param access_key string
--- @return unknown | nil consumer
--- @return string | nil error
local function get_consumer(access_key)
    if not access_key then
        return nil, "missing access key"
    end

    local consumer_conf = consumer.plugin(plugin_name)
    if not consumer_conf then
        return nil, "Missing related consumer"
    end

    local consumers = consumer.consumers_kv(plugin_name, consumer_conf, "access_key")
    if not consumers then
        return nil, "Invalid access key"
    end
    local consumer = consumers[access_key]
    if not consumer then
        return nil, "Invalid access key"
    end

    core.log.info("consumer: ", core.json.delay_encode(consumer))

    return consumer, nil
end


--- validate
---
--- @param conf Config
--- @param params unknown
--- @return unknown | nil consumer
--- @return string | nil error
local function validate(conf, params)
    if params.algorithm ~= ALGO then
        return nil, "algorithm '" .. params.algorithm .. "' is not supported"
    end

    if conf.region and #conf.region > 0 then
        if (not params.credential.region) or params.credential.region ~= conf.region then
            return nil, "Credential should be scoped to a valid Region, not '" .. params.credential.region .. "'"
        end
    end

    if conf.service and #conf.service > 0 then
        if (not params.credential.service) or params.credential.service ~= conf.service then
            return nil, "Credential should be scoped to correct service: '" .. params.credential.service .. "'"
        end
    end

    -- check headers
    local signed_headers_map = utils.array_to_map(params.signed_headers)
    if conf.must_sign_headers and #conf.must_sign_headers > 0 then
        for _, must in ipairs(conf.must_sign_headers) do
            if not signed_headers_map[must:lower()] then
                return nil, "header '" .. must .. "' must be signed"
            end
        end
    end

    -- check clock skew
    local now = ngx_time()
    local time_to_validate = utils.iso8601_to_timestamp(params.date)
    local skew = now - time_to_validate
    core.log.info("conf.clock_skew: ", conf.clock_skew)
    if (conf.clock_skew and conf.clock_skew > 0) then
        if not signed_headers_map[DATE_KEY:lower()] then
            return nil, "'" .. DATE_KEY .. "' is not signed"
        end

        if params.date:sub(1, 8) ~= params.credential.date then
            return nil, "Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP"
        end

        core.log.info("Clock skew: ", skew .. "=" .. now .. "-" .. time_to_validate)
        if skew > conf.clock_skew then
            return nil, "Signature expired: '" .. params.date .. "' is now earlier than '" .. now .. "'"
        elseif skew < 0 then
            return nil, "Signature not yet current: '" .. params.date .. "' is still later than '" .. now .. "'"
        end
    end

    -- check X-Amz-Expires
    if params.is_query_string_method then
        if not params.expires then
            return nil, "TODO 这是必须检查amz_expires的情况"
        end

        if conf.max_expires and conf.max_expires > 0 then
            if params.expires > conf.max_expires then
                return nil, "max_expires limited" --TODO test
            end
        end

        if abs(skew) > params.expires then
            return nil, "Signature expired: '" .. params.date .. "' is now earlier than '" .. now .. "'"
        end
    end


    -- get consumer
    local consumer, err = get_consumer(params.credential.access_key)
    if err or (not consumer) then
        return nil, err
    end

    -- calc signature
    local headers_to_signature = {}
    for _, header_name in ipairs(params.signed_headers) do
        headers_to_signature[header_name] = params.headers[header_name]
    end

    local qs_to_signature = {}
    if params.is_query_string_method then
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
    local generated_signature = utils.generate_signature(
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
        return nil, "The request signature we calculated does not match the signature you provided"
    end

    return consumer
end


local function parse_credential(credential)
    local credential_data = ngx_re_split(credential, "/")
    if (not credential_data) or #credential_data ~= 5 then
        return nil, "Bad Credential"
    end

    local credential = {
        access_key = credential_data[1],
        date       = credential_data[2],
        region     = credential_data[3],
        service    = credential_data[4],
    }

    if (not credential.access_key) or #credential.access_key == 0 then
        return nil, "access key missing"
    end

    if (not credential.date) or #credential.date == 0 then
        return nil, "date missing"
    end

    if (not credential.region) or #credential.region == 0 then
        return nil, "region missing"
    end

    if (not credential.service) or #credential.service == 0 then
        return nil, "service missing"
    end

    local credential_aws4_request = credential_data[5]
    if (not credential_aws4_request) or credential_aws4_request ~= "aws4_request" then
        return nil, "Credential should be scoped with a valid terminator: 'aws4_request'"
    end

    return credential
end


local function get_params(ctx, conf)
    --- @class Parameters
    --- @field host string
    --- @field method string
    --- TODO 补充 判空
    local params = {
        host         = core.request.get_host(),
        method       = core.request.get_method(ctx),
        uri          = ctx.var.uri,
        query_string = core.request.get_uri_args(ctx),
        headers      = core.request.headers(ctx),
    }

    local err
    if conf.max_req_body and conf.max_req_body > 0 then
        params.body, err = core.request.get_body(conf.max_req_body, ctx)
        if err then
            return nil, "Exceed body limit size"
        end
    end

    if conf.enable_header_method and params.headers["Authorization"] then
        -- Using the Authorization Header
        local auth_string = params.headers["Authorization"]
        if #auth_string == 0 then
            return nil, "Authorization header cannot be empty"
        end
        local auth_data = ngx_re_match(auth_string,
            [[([\w\-]+) (?:(?:Credential=([\w\-\/]+)|SignedHeaders=([\w;\-]+)|Signature=([\w\d]+))[, ]*)+]])

        if (not auth_data) or #auth_data ~= 4 then
            return nil, "Bad Authorization Header"
        end

        params.algorithm      = auth_data[1]
        params.credential     = auth_data[2]
        params.date           = params.headers[DATE_KEY]
        params.signed_headers = auth_data[3]
        params.signature      = auth_data[4]
    elseif conf.enable_query_string_method and params.query_string[ALGORITHM_KEY] then
        -- Using Query Parameters
        params.algorithm      = params.query_string[ALGORITHM_KEY]
        params.credential     = params.query_string[CREDENTIAL_KEY]
        params.date           = params.query_string[DATE_KEY]
        params.signed_headers = params.query_string[SIGNED_HEADERS_KEY]
        params.signature      = params.query_string[SIGNATURE_KEY]

        core.log.info("params.expires: ", params.expires)

        params.expires                = tonumber(params.query_string[EXPIRES_KEY]) --TODO test & schema
        params.is_query_string_method = true
    else
        return nil, "Missing Authentication Token"
    end

    params.signed_headers = params.signed_headers and ngx_re_split(params.signed_headers, ";")
    params.credential, err = parse_credential(params.credential)
    if err then
        return nil, err
    end

    if (not params.signature) or #params.signature == 0 then
        return nil, "Authorization header requires 'Signature' parameter"
    end

    return params, nil
end


function _M.rewrite(conf, ctx)
    local params, err = get_params(ctx, conf)
    if err then
        core.log.warn("client request can't be validated: ", err)
        return 403, { message = err }
    end

    local validated_consumer, err = validate(conf, params)
    if not validated_consumer then
        core.log.warn("client request can't be validated: ", err)
        return 403, { message = err }
    end
    core.log.info("validated_consumer: ", core.json.delay_encode(validated_consumer))

    local consumer_conf = consumer.plugin(plugin_name)
    consumer.attach_consumer(ctx, validated_consumer, consumer_conf)
    core.log.info("hit aws-auth rewrite")

    -- TODO keep headers
end

return _M
