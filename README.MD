# Validate Headers Plugin for Traefik 2

[![Go Report Card](https://goreportcard.com/badge/github.com/frankforpresident/traefik-plugin-validate-headers)](https://goreportcard.com/report/github.com/frankforpresident/traefik-plugin-validate-headers)
[![codecov](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers/branch/master/graph/badge.svg)](https://codecov.io/gh/frankforpresident/traefik-plugin-validate-headers)

A middleware plugin for Traefik that validates HTTP request headers against configured rules.

## Features

- **Header Validation**: Match against predefined headers and values
- **Flexible Matching**: Support for all, any, or none matching strategies
- **Value Matching**: Match all values, any value, or no values
- **Regular Expressions**: Use regex patterns for advanced validation
- **Contains Check**: Match based on substrings
- **Optional Headers**: Configure whether headers must be present
- **Custom Errors**: Define status codes and messages for failed validation
- **URL Decoding**: Handle URL-encoded header values

Integrates with Traefik's PassTLSClientCert middleware for client certificate validation.

## Installation

### YAML Static Configuration
```yaml
experimental:
  plugins:
    validate-headers:
      moduleName: "github.com/frankforpresident/traefik-plugin-validate-headers"
      version: "v0.0.1"
```

### TOML Static Configuration
```toml
[experimental.plugins.validate-headers]
  moduleName = "github.com/frankforpresident/traefik-plugin-validate-headers"
  version = "v0.0.1"
```

### CLI Configuration
```bash
--experimental.plugins.validate-headers.modulename=github.com/frankforpresident/traefik-plugin-validate-headers
--experimental.plugins.validate-headers.version=v0.0.1
```

## Configuration

**Plugin Settings:**
- `headers`: List of headers to validate
- `matchtype`: Strategy for header matching (`one`, `all`, `none`) - default: `all`
- `error`: Custom response for validation failure (`statuscode`, `message`) - default: `403 Forbidden`

**Header Settings:**
- `name`: Name of the request header
- `matchtype`: Value matching strategy (`one`, `all`, `none`) - required, no default
- `values`: List of values to match
- `contains`: Match substrings (default: `false`)
- `regex`: Use regex patterns (default: `false`)
- `required`: Header must be present (default: `true`)
- `urldecode`: URL decode value (default: `false`)
- `debug`: Print validation details (default: `false`)

## Examples

### Basic Validation
```yaml
middlewares:
  validate-headers:
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

### API Key Validation
```yaml
middlewares:
  validate-api-key:
    plugin:
      validate-headers:
        headers:
          - header:
            name: "X-API-Key"
            matchtype: one
            values:
              - "your-secret-api-key"  # For multiple keys, add them to the values array
            required: true
```

### Using Docker Labels
```yaml
services:
  api:
    image: your-api-image
    labels:
      # Enable the middleware
      - "traefik.enable=true"
      - "traefik.http.routers.api.rule=Host(`api.example.com`)"
      # Define the middleware
      - "traefik.http.middlewares.validate-apikey.plugin.validate-headers.headers[0].header.name=X-API-Key"
      - "traefik.http.middlewares.validate-apikey.plugin.validate-headers.headers[0].matchtype=one"
      - "traefik.http.middlewares.validate-apikey.plugin.validate-headers.headers[0].values[0]=your-secret-api-key"
      - "traefik.http.middlewares.validate-apikey.plugin.validate-headers.headers[0].required=true"
      # Apply the middleware
      - "traefik.http.routers.api.middlewares=validate-apikey@docker"
```

### Client Certificate Validation
```yaml
middlewares:
  validate-cert:
    plugin:
      validate-headers:
        headers:
          - header:
            name: "X-Forwarded-Tls-Client-Cert-Info"
            values:
              - "CN=example.com"
            contains: true
            urldecode: true
```

### Blacklist Headers
```yaml
middlewares:
  block-languages:
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
```

### Testing
```bash
curl -H "X-API-Key: your-secret-api-key" http://api.example.com
```

## Support

- 100% test coverage
- Inspired by [checkheadersplugin](https://github.com/dkijkuit/checkheadersplugin)

