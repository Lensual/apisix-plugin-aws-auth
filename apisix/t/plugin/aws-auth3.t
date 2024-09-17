#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

use t::APISIX 'no_plan';

repeat_each(1);
no_long_string();
no_root_location();
no_shuffle();

add_block_preprocessor(sub {
    my ($block) = @_;

    my $user_yaml_config = <<_EOC_;
apisix:
  data_encryption:
    enable_encrypt_fields: false
_EOC_
    $block->set_value("yaml_config", $user_yaml_config);
});

run_tests;

__DATA__

=== TEST 1: Verify by header: add consumer with plugin aws-auth
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/consumers',
                ngx.HTTP_PUT,
                [[{
                    "username": "jack",
                    "plugins": {
                        "aws-auth": {
                            "access_key": "AKIAIOSFODNN7EXAMPLE",
                            "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                        }
                    }
                }]]
                )

            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- request
GET /t
--- response_body
passed



=== TEST 2: Verify by header: add aws auth plugin using admin api
--- config
    location /t {
        content_by_lua_block {
            local t = require("lib.test_admin").test
            local code, body = t('/apisix/admin/routes/1',
                ngx.HTTP_PUT,
                [[{
                    "plugins": {
                        "aws-auth": {
                            "region": "us-east-1",
                            "service": "s3"
                        }
                    },
                    "upstream": {
                        "nodes": {
                            "127.0.0.1:1980": 1
                        },
                        "type": "roundrobin"
                    },
                    "uri": "/hello"
                }]]
                )

            if code >= 300 then
                ngx.status = code
            end
            ngx.say(body)
        }
    }
--- request
GET /t
--- response_body
passed



=== TEST 3: Verify by header: missing header Authentication
--- request
GET /hello
--- error_code: 403
--- response_body
{"message":"Missing Authentication Token"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Missing Authentication Token



=== TEST 4: Verify by header: empty Authentication header
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization:
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"Authorization header cannot be empty"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Authorization header cannot be empty



=== TEST 5: Verify by header: Bad Authorization Header
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: Bearer XXXXXXXXXXXXXXXXXXX
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"Bad Authorization Header"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Bad Authorization Header



=== TEST 6: Verify by header: Credential: algorithm mistake
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: FAKE-ALGO Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"algorithm 'FAKE-ALGO' is not supported"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: algorithm 'FAKE-ALGO' is not supported



=== TEST 7: Verify by header: Credential: access key missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"access key missing"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: access key missing



=== TEST 8: Verify by header: Credential: date missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE//us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"date missing"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: date missing



=== TEST 9: Verify by header: Credential: region missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524//s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"region missing"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: region missing



=== TEST 10: Verify by header: Credential: invalid region
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/fake-region/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"Credential should be scoped to a valid Region, not 'fake-region'"}
--- grep_error_log eval
qr/client request can't be validated: Credential should be scoped to a valid Region, not [^,]+/
--- grep_error_log_out
client request can't be validated: Credential should be scoped to a valid Region, not 'fake-region'



=== TEST 11: Verify by header: Credential: service missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1//aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"service missing"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: service missing



=== TEST 12: Verify by header: Credential: invalid service
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/fake-service/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"Credential should be scoped to correct service: 'fake-service'"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Credential should be scoped to correct service: 'fake-service'



=== TEST 13: Verify by header: Credential: invalid terminator
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/not_aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"Credential should be scoped with a valid terminator: 'aws4_request'"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Credential should be scoped with a valid terminator: 'aws4_request'



=== TEST 14: Verify by header: signed_header: Host missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"header 'Host' must be signed"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: header 'Host' must be signed



=== TEST 15: Verify by header: signed_header: X-Amz-Date missing
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20130524T000000Z
--- error_code: 403
--- response_body
{"message":"header 'X-Amz-Date' must be signed"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: header 'X-Amz-Date' must be signed



=== TEST 17: Verify by header: clock_skew: Date in Credential scope is dismatch X-Amz-Date parameter
--- request
GET /hello
--- more_headers
Host: examplebucket.s3.amazonaws.com
Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41
Range: bytes=0-9
x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
x-amz-date: 20000101T000000Z
--- error_code: 403
--- response_body
{"message":"Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Date in Credential scope does not match YYYYMMDD from ISO-8601 version of date from HTTP



=== TEST 18: Verify by header: clock_skew: Signature expired
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time() - 100000
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"]                 = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"]           = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body                      = nil
        local access_key                = "AKIAIOSFODNN7EXAMPLE"
        local secret_key                = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        local region                    = "us-east-1"
        local service                   = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.say(res_body)
    }
}
--- request
GET /t
--- error_code: 403
--- response_body eval
qr/{"message":"Signature expired: '.+' is now earlier than '.+'"}/
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out eval
qr/Signature expired: '.+' is now earlier than '.+'/



=== TEST 19: Verify by header: clock_skew: Signature in the future
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time() + 10000
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"]                 = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"]           = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body                      = nil
        local access_key                = "AKIAIOSFODNN7EXAMPLE"
        local secret_key                = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        local region                    = "us-east-1"
        local service                   = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.say(res_body)
    }
}
--- request
GET /t
--- error_code: 403
--- response_body eval
qr/{"message":"Signature not yet current: '.+' is still later than '.+'"}/
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out eval
qr/Signature not yet current: '.+' is still later than '.+'/



=== TEST 20: Verify by header: Success
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time()
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"] = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"] = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body = nil
        local access_key =  "AKIAIOSFODNN7EXAMPLE"
        local secret_key =  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        local region = "us-east-1"
        local service = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.say(res_body)
    }
}
--- request
GET /t
--- response_body
passed



=== TEST 21: Verify by header: Consumer not found
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time()
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"] = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"] = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body = nil
        local access_key =  "FAKE_ACCESS_KEY"
        local secret_key =  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        local region = "us-east-1"
        local service = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.print(res_body)
    }
}
--- request
GET /t
--- error_code: 403
--- response_body
{"message":"Invalid access key"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Invalid access key



=== TEST 22: Verify by header: Signature Dismatch
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time()
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"] = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"] = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body = nil
        local access_key =  "AKIAIOSFODNN7EXAMPLE"
        local secret_key =  "FAKE_SECRET_KEY"
        local region = "us-east-1"
        local service = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.print(res_body)
    }
}
--- request
GET /t
--- error_code: 403
--- response_body
{"message":"The request signature we calculated does not match the signature you provided"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: The request signature we calculated does not match the signature you provided



=== TEST 23: Verify by header: Exceed body limit size
--- config
location /t {
    content_by_lua_block {
        local t = require("lib.test_admin")
        local utils = require("apisix.plugins.aws-auth.utils")

        local now       = os.time()
        local amzdate   = os.date("!%Y%m%dT%H%M%SZ", now) -- ISO 8601 20130524T000000Z
        local datestamp = os.date("!%Y%m%d", now)         -- Date w/o time, used in credential scope

        local method = ngx.HTTP_GET
        local path = "/hello"
        local query_string = {}
        local query_string_list = {}
        for k,v in ipairs(query_string) do
            table.insert(query_string_list, k .. "=" .. v)
        end
        local headers = {}
        headers["Host"] = "examplebucket.s3.amazonaws.com"
        headers["x-amz-date"] = amzdate
        headers["x-amz-content-sha256"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        local body = string.rep("A", 1024*1024)
        local access_key =  "AKIAIOSFODNN7EXAMPLE"
        local secret_key =  "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        local region = "us-east-1"
        local service = "s3"

        local signature = utils.generate_signature(
            ngx.req.get_method(method),
            path,
            query_string,
            headers,
            body,
            secret_key,
            now,
            region,
            service
        )

        local _, signed_headers = utils.build_canonical_headers(headers)
        headers["Authorization"] = "AWS4-HMAC-SHA256 "
        .. "Credential="
            .. access_key .. "/"
            .. datestamp .. "/"
            .. region .. "/"
            .. service .. "/"
            .. "aws4_request,"
        .. "SignedHeaders=" .. signed_headers .. ","
        .. "Signature=" .. signature

        local query_string_str = ""
        if #query_string_list > 0 then
            query_string_str = "?" .. table.concat(query_string_list, "&")
        end
        local code, res_body = t.test(path .. query_string_str,
            method,
            body,
            nil,
            headers
        )

        ngx.status = code
        ngx.print(res_body)
    }
}
--- request
GET /t
--- error_code: 403
--- response_body
{"message":"Exceed body limit size"}
--- grep_error_log eval
qr/client request can't be validated: [^,]+/
--- grep_error_log_out
client request can't be validated: Exceed body limit size



