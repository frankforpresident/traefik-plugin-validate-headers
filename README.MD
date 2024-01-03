# Validate Headers Plugin for Traefik 2

[![Go Report Card](https://goreportcard.com/badge/github.com/frankforpresident/traefik-plugin-validate-headers)](https://goreportcard.com/report/github.com/frankforpresident/traefik-plugin-validate-headers)
[![codecov](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers/branch/master/graph/badge.svg)](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers)
![Release](https://img.shields.io/github/release/frankforpresident/traefik-plugin-validate-headers.svg?style=flat-square)
![Downloads](https://img.shields.io/github/downloads/frankforpresident/traefik-plugin-validate-headers/total.svg?style=flat-square)
![GitHub repo size in bytes](https://img.shields.io/github/repo-size/frankforpresident/traefik-plugin-validate-headers.svg)
![GitHub issues](https://img.shields.io/github/issues/frankforpresident/traefik-plugin-validate-headers.svg)

![Banner](./img/lock.png)

The Validate Headers Plugin for Traefik 2 empowers you to enforce strict header validation policies for incoming HTTP requests. With a versatile set of features, this middleware allows you to control and secure your web applications effectively. Key features include:

### Header Validation :lock:

Ensure compliance with a predefined list of headers and their expected values in incoming requests.

### Flexible Matching :arrows_counterclockwise:

Match headers in various ways, including all headers, any one of the headers, or none of the headers, providing granular control over validation requirements.

### Value Matching :1234:

Specify how header values should be matched – whether all values, any one of the values, or none of the values are expected.

### Regular Expression Support :heavy_exclamation_mark:

Utilize regular expressions to define intricate patterns for matching header values, offering advanced validation capabilities.

### Contains Check :heavy_plus_sign:

Perform header value matching based on whether it contains a specific substring, providing nuanced validation options.

### Optional Headers :grey_question:

Configure the middleware to permit requests with absent headers, allowing for more flexible validation requirements.

### Custom Error Responses :x:

Define custom error responses to be sent when a request fails header validation, offering a tailored experience to clients.

### URL Decoding :link:

Enable URL decoding for header values, accommodating scenarios where values may be URL-encoded.

:mag:
This Validate Headers Plugin is not only a robust solution for standard header validation but also seamlessly integrates with Traefik's PassTLSClientCert middleware, extending its capabilities to scrutinize client certificate information.

:shield:
Enhance the security and compliance of your web applications with the Validate Headers Plugin in Traefik, providing a configurable and adaptable solution for enforcing strict header validation policies.

## Configuration documentation

### Plugin Configuration

| Setting   | Allowed values        | Description                                                                                          |
| :-------- | :-------------------- | :--------------------------------------------------------------------------------------------------- |
| headers   | []header              | A list of headers to validate against.                                                               |
| matchtype | one, all, none        | Match on all headers, one of the headers or none of the headers. The value 'all' is default          |
| error     | {statuscode, message} | A custom error response to return when the request fails to validate against the configured headers. |

## Header Configuration

| Setting   | Allowed values | Description                                                                                                                                                                                                                                                                                      |
| :-------- | :------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| name      | string         | Name of the request header                                                                                                                                                                                                                                                                       |
| matchtype | one, all, none | Match on all values, one of the values specified or none of the values. The value 'all' is only allowed in combination with the 'contains' and 'regex' setting.                                                                                                                                  |
| values    | []string       | A list of allowed values which are matched against the request header value                                                                                                                                                                                                                      |
| contains  | boolean        | If set to true (default false), the request is allowed if the request header value contains the value specified in the configuration                                                                                                                                                             |
| regex     | boolean        | If set to true (default false), the match is done using a regular expression. The value of the request header is matched against the value specified in the configuration. via the [regexp](https://pkg.go.dev/regexp) package                                                                   |
| required  | boolean        | If set to false (default true), the request is allowed if the header is absent or the value is empty                                                                                                                                                                                             |
| urldecode | boolean        | If set to true (default false), the value of the request header will be URL decoded before further processing with the plugin. This is useful when using this plugin with the [PassTLSClientCert](https://doc.traefik.io/traefik/middlewares/passtlsclientcert/) middleware that Traefik offers. |
| debug     | boolean        | If set to true (default false), the request headers, values and validation will be printed to the console                                                                                                                                                                                        |

## Error Configuration

| Setting    | Allowed values | Description                                                                                       |
| :--------- | :------------- | :------------------------------------------------------------------------------------------------ |
| statuscode | integer        | The HTTP status code to return when the request fails to validate against the configured headers. |
| message    | string         | The message to return when the request fails to validate against the configured headers.          |

#

## Basic Example

```yaml
middlewares:
  my-validate-headers:
    plugin:
      validate-headers:
        error: # Optional, default is '403 Forbidden'
          statuscode: 404
          message: "Not Found"
        matchtype: one # Optional, default is 'all'. ('all', 'one', 'none')
        headers:
          - header:
            name: "MATCH_ONE_REQUIRED"
            matchtype: one
            values:
              - "A"
              - "B"
            required: true
          - header:
            name: "MATCH_ONE_OPTIONAL"
            matchtype: none
            values:
              - "C"
              - "D"
            required: false
          - header:
            name: "MATCH_ALL_CONTAINS"
            matchtype: all
            values:
              - "ABC"
              - "123"
            contains: true
            required: true
          - header:
            name: "MATCH_ONE_REGEX"
            matchtype: one
            values:
              - "^XYZ$"
              - "^789$"
            regex: true
            required: true
```

## PassTLSClientCert Example

You can also use this plugin to check on client certificate fields when using mTLS configuration. The [PassTLSClientCert](https://doc.traefik.io/traefik/middlewares/passtlsclientcert/) Traefik middleware adds the client certificate information to the request header `X-Forwarded-Tls-Client-Cert-Info` in a URL encoded format. Using this plugin as second middleware for route, you can verify the client certificate fields.

Example client certificate request header:

```http
X-Forwarded-Tls-Client-Cert-Info: Subject="C=US,ST=Ohio,L=Akron,O=Google,CN=server0.google.com";Issuer="DC=us,DC=google.com,DC=com,CN=GoogleRootCA";NB="1687386830";NA="1750458830";SAN="server0.google.com"
```

You could configure the plugin to check for the `CN` and the `DC` fields:

```yaml
middlewares:
  my-validate-headers:
    plugin:
      validate-headers:
        headers:
          - header:
            name: "X-Forwarded-Tls-Client-Cert-Info"
            matchtype: all
            values:
              - "CN=server0.google.com"
              - "DC=google.com"
            contains: true
            required: true
            urldecode: true
```

## Regex Match Example

This plugin give you also the possibility to validate header via a regular expression. This can be useful when you want to validate a header value against a pattern. For example, you want to validate a JWT token in the `Authorization` header. The JWT token has a specific format and you can validate this with a regular expression.

```yaml
middlewares:
  my-validate-headers:
    plugin:
      validate-headers:
        headers:
          - header:
            name: "Authorization"
            matchtype: one
            values:
              - "^Bearer .*"
            regex: true
```

## Blacklist Example

You can also use this plugin to check if header has a certain value that is not allowed. This way you can allow every value except a the provide ones, acting as blacklist. For example, you want to block requests that have `Content-Language` header that are set to `de-DE` or `de-AT`. You can use 'none' in combination with matchtype 'regex' or 'contains'.

Returning a 404 status code a Not Found error message:

```yaml
middlewares:
  my-validate-headers:
    plugin:
      validate-headers:
        error:
          statuscode: 404
          message: "Not Found"
        headers:
          - header:
            name: "Content-Language"
            matchtype: none
            values:
              - "de-DE"
              - "de-AT"
            required: true
```

## Multiple Headers Example

If you want to match on multiple headers, you can use the `matchtype` setting on top level. This way you can match on all headers, one of the headers or none of the headers. For example, you want to block requests that have `Content-Language` header that are set to `de-DE` or `de-AT` and `Content-Type` header that are set to `application/json` or `application/xml`.

If you use 'all', all headers must match the configuration. If you use 'one', only one header must match the configuration. If you use 'none', none of the headers must match the configuration. By default, the matchtype is set to 'all'.

```yaml
middlewares:
  my-validate-headers:
    plugin:
      validate-headers:
        matchtype: one
        headers:
          - header:
            name: "Content-Language"
            matchtype: none
            values:
              - "de-DE"
              - "de-AT"
            required: true
          - header:
            name: "Content-Type"
            matchtype: one
            values:
              - "application/json"
              - "application/xml"
            required: true
```

## Launch Traefik using dev config (config of plugin can be found in the example folder)

```bash
$ docker run --rm -d -p 4000:80 traefik/whoami
```

## Test using cURL

```bash
curl --location --insecure --request GET "http:/whoami.localhost" \
  --header "MATCH_ONE_REQUIRED: A" \
  --header "MATCH_ONE_OPTIONAL: E" \
  --header "MATCH_ALL_CONTAINS: ABC" \
  --header "MATCH_ALL_CONTAINS: 123" \
  --header "MATCH_ONE_REGEX: XYZ"

```

Should return a 200 showing details about the request.

## Unit Test Coverage

Our Validate Headers Plugin for Traefik boasts a comprehensive suite of unit tests to ensure robustness and reliability. We are proud to share that our codebase achieves 100% unit test coverage.

[![codecov](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers/branch/master/graph/badge.svg)](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers)

This high level of test coverage demonstrates our commitment to delivering a secure and dependable middleware solution. You can explore the detailed coverage reports on Codecov to gain insights into the thorough testing of our Validate Headers Plugin.

Feel free to review our unit test suite and coverage statistics on [Codecov](https://app.codecov.io/gh/frankforpresident/traefik-plugin-validate-headers) to gain confidence in the reliability of our codebase.


Inspired on [checkheadersplugin](https://github.com/dkijkuit/checkheadersplugin)