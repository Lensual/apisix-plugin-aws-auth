# apisix-plugin-aws-auth

[AWS v4 Signature Authentication](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
) Plugin for [Apache Apisix](https://apisix.apache.org/)

## Attributes

For Consumer:

| Name | Type | Requirement | Description |
| ---- | ---- | ----------- | ----------- |
|access_key|string|required|Unique access_key for a Consumer. This field supports saving the value in Secret Manager using the [APISIX Secret](https://apisix.apache.org/docs/apisix/terminology/secret/) resource.|
|secret_key|string|required|Unique secret_key for a Consumer. This field supports saving the value in Secret Manager using the [APISIX Secret](https://apisix.apache.org/docs/apisix/terminology/secret/) resource.|

NOTE: `encrypt_fields = {"access_key", "secret_key"}` is also defined in the schema, which means that the field will be stored encrypted in etcd. See [encrypted storage fields](https://apisix.apache.org/docs/apisix/plugin-develop/#encrypted-storage-fields).

For Route:

| Name | Type | Requirement |Default| Description |
| ---- | ---- | ----------- |--| ----------- |
|region|string|optional||Region to validate. Without validate if not provided.|
|service|string|optional||Service to validate. Without validate if not provided.|
|clock_skew|integer|optional|60 \* 60 \* 24 \* 7|Clock skew allowed by the signature in seconds. Setting it to 0 will skip checking the date.|
|must_sign_headers|array of string|optional|["host", "X-Amz-Date"]|The headers must be signed. According to the [AWS v4 signature](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html), at least `host` and `X-Amz-Date` are required.|
|must_sign_all_headers|boolean|optional|false|All headers must be signed.|
|keep_headers|boolean|optional|false||
|keep_unsigned_headers|boolean|optional|false||
|keep_query_string|boolean|optional|false||
|max_req_body|integer|optional|1024 \* 512|Max request body size.|
|header_auth|boolean|optional|true||
|query_string_auth|boolean|optional|false||
|max_expires|integer|optional|60 \* 60 \* 24 \* 7||

## Install

```sh
git clone https://github.com/Lensual/apisix-plugin-aws-auth
cp apisix-plugin-aws-auth/apisix/plugins/aws-auth.lua /path/to/apisix/plugins
cp -r apisix-plugin-aws-auth/apisix/plugins/aws-auth /path/to/apisix/plugins
```

conf/config.yaml

```yaml
plugins:
  - apisix-plugin-aws-auth
```

## Install by extra_lua_path

conf/config.yaml

```yaml
plugins:
  - apisix-plugin-aws-auth
apisix:
  extra_lua_path: '/path/to/apisix-plugin-aws-auth/?.lua'
```

## TODO

- [ ] keep headers & qs
- [ ] review
- [ ] documents
  - [ ] review log
- [ ] translate documents & comment
- [ ] v4a signature ?
- [ ] unit test

## License

[Apache 2.0 License](./LICENSE)
