# apisix-plugin-aws-auth

[AWS v4 Signature Authentication](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
) Plugin for [Apache Apisix](https://apisix.apache.org/)

## Attributes

For Consumer:

| Name       | Type   | Requirement | Description                                                                                                                                                                             |
| ---------- | ------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| access_key | string | required    | Unique access_key for a Consumer. This field supports saving the value in Secret Manager using the [APISIX Secret](https://apisix.apache.org/docs/apisix/terminology/secret/) resource. |
| secret_key | string | required    | Unique secret_key for a Consumer. This field supports saving the value in Secret Manager using the [APISIX Secret](https://apisix.apache.org/docs/apisix/terminology/secret/) resource. |

NOTE: `encrypt_fields = {"access_key", "secret_key"}` is also defined in the schema, which means that the field will be stored encrypted in etcd. See [encrypted storage fields](https://apisix.apache.org/docs/apisix/plugin-develop/#encrypted-storage-fields).

For Route:

| Name                       | Type            | Requirement | Default             | Description                                                                                                                                                                                                            |
| -------------------------- | --------------- | ----------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| host                       | string          | optional    |                     | Host to validate. Without validate if not provided.                                                                                                                                                                    |
| region                     | string          | optional    |                     | Region to validate. Without validate if not provided.                                                                                                                                                                  |
| service                    | string          | optional    |                     | Service to validate. Without validate if not provided.                                                                                                                                                                 |
| clock_skew                 | integer         | optional    | 60 \* 15            | Clock skew allowed by the signature in seconds. The default value is 900 seconds (15 minutes). If `X-Amz-Date` is not in request parameter, an error will occur. Setting it to 0 will skip checking the date (UNSAFE). |
| max_req_body               | integer         | optional    | 1024 \* 512         | Max Request Body size. The default value is 512 KiB.                                                                                                                                                                   |
| enable_header_method       | boolean         | optional    | true                | Enable [HTTP authorization header](https://docs.aws.amazon.com/IAM/latest/UserGuide/aws-signing-authentication-methods.html#aws-signing-authentication-methods-http) method. The default is true.                      |
| enable_query_string_method | boolean         | optional    | true                | Enable [Query string parameters](https://docs.aws.amazon.com/IAM/latest/UserGuide/aws-signing-authentication-methods.html#aws-signing-authentication-methods-query) method. The default is true.                       |
| max_expires                | integer         | optional    | 60 \* 60 \* 24 \* 7 | Sets the maximum value allowed for the `X-Amz-Expires` parameter. The default value is 604800 seconds (7 days). Setting it to 0 will skip checking exprires limit (UNSAFE).                                            |
| extra_must_sign_headers    | array of string | optional    |                     | The Request Headers that must be signed. Case insensitive.                                                                                                                                                             |
| keep_unsigned_headers      | boolean         | optional    | false               | Whether to keep the Unsigned Request Header. The default is false.                                                                                                                                                     |

## Install

```sh
git clone https://github.com/Lensual/apisix-plugin-aws-auth
cp apisix-plugin-aws-auth/apisix/plugins/aws-auth.lua /path/to/apisix/plugins
cp -r apisix-plugin-aws-auth/apisix/plugins/aws-auth /path/to/apisix/plugins
```

conf/config.yaml

```yaml
plugins:
  - aws-auth
```

## Install by extra_lua_path

conf/config.yaml

```yaml
plugins:
  - aws-auth
apisix:
  extra_lua_path: '/path/to/apisix-plugin-aws-auth/?.lua'
```

## TODO

- [ ] test query string method
- [ ] PR to apisix
- [ ] documents
- [ ] review log
- [ ] translate documents & comment
- [ ] review test

## License

[Apache 2.0 License](./LICENSE)
