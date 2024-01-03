// Package traefik_plugin_validate_headers provides a header checking plugin for HTTP requests.
package traefik_plugin_validate_headers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// SingleHeader contains a single header key pair.
type SingleHeader struct {
	Name      string   `json:"name,omitempty"`
	Values    []string `json:"values,omitempty"`
	MatchType string   `json:"matchtype"`
	Required  *bool    `json:"required,omitempty"`
	Contains  *bool    `json:"contains,omitempty"`
	URLDecode *bool    `json:"urldecode,omitempty"`
	Debug     *bool    `json:"debug,omitempty"`
	Regex     *bool    `json:"regex,omitempty"`
}

// Config represents the plugin configuration.
type Config struct {
	Headers   []SingleHeader
	MatchType string `json:"matchtype,omitempty"`
	Error     ErrorConfig
}

type ErrorConfig struct {
	StatusCode int    `json:"statuscode,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Validator is the main handler for the Validator plugin.
type Validator struct {
	next    http.Handler
	headers []SingleHeader
	config  *Config
	name    string
}

// MatchType is an enum specifying the match type for the 'contains' config.
type MatchType string

const (
	// MatchAll requires all values to be matched.
	MatchAll MatchType = "all"
	// MatchOne requires only one value to be matched.
	MatchOne MatchType = "one"
	// MatchNone requires none of the values to be matched.
	MatchNone MatchType = "none"
)

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Headers:   []SingleHeader{},
		MatchType: string(MatchAll),
		Error: ErrorConfig{
			StatusCode: http.StatusForbidden, // Default error status code.
			Message:    "Not allowed",        // Default error message.
		},
	}
}

// New creates a new Validator plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("validate-headers: configuration incorrect, missing headers")
	}

	// Set default values for custom error response.
	if config.Error.StatusCode == 0 {
		config.Error.StatusCode = http.StatusForbidden
	}

	if config.Error.Message == "" {
		config.Error.Message = "Not allowed"
	}

	for _, vHeader := range config.Headers {

		if strings.TrimSpace(vHeader.Name) == "" {
			return nil, fmt.Errorf("validate-headers: configuration incorrect, missing header name")
		}

		if vHeader.MatchType == string(MatchAll) && !(vHeader.IsContains() || vHeader.IsRegex()) {
			return nil, fmt.Errorf("validate-headers: configuration incorrect for header %v, %s", vHeader.Name, "match-all can only be used in combination with 'contains' or 'regex'")
		}

		if strings.TrimSpace(vHeader.MatchType) == "" {
			return nil, fmt.Errorf("validate-headers: configuration incorrect, missing match type configuration for header %v", vHeader.Name)
		}

		if len(vHeader.Values) == 0 {
			return nil, fmt.Errorf("validate-headers: configuration incorrect, missing header values")
		}

		for _, value := range vHeader.Values {
			if strings.TrimSpace(value) == "" {
				return nil, fmt.Errorf("validate-headers: configuration incorrect, empty value found")
			}
		}
	}

	return &Validator{
		headers: config.Headers,
		config:  config, // Store the config for later use.
		next:    next,
		name:    name,
	}, nil
}

// ServeHTTP handles the HTTP request and validates headers based on the configured match type.
func (a *Validator) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	headersValid := true

	switch a.config.MatchType {
	case string(MatchNone):
		headersValid = checkNone(a.headers, req)
	case string(MatchAll):
		headersValid = checkAll(a.headers, req)
	case string(MatchOne):
		headersValid = checkOne(a.headers, req)
	default:
		// Unsupported MatchType, treat as MatchAll for backward compatibility.
		headersValid = checkAll(a.headers, req)
	}

	if headersValid {
		a.next.ServeHTTP(rw, req)
	} else {
		http.Error(rw, a.config.Error.Message, a.config.Error.StatusCode)
	}
}

// checkNone checks whether none of the configured headers are present in the request.
func checkNone(headers []SingleHeader, req *http.Request) bool {
	isValid := true

	for _, vHeader := range headers {
		if !isValid {
			return false
		}

		reqHeaderVal := req.Header.Get(vHeader.Name)

		if vHeader.IsURLDecode() {
			reqHeaderVal, _ = url.QueryUnescape(reqHeaderVal)
		}

		if reqHeaderVal != "" {
			if !checkRequired(&reqHeaderVal, &vHeader) {
				isValid = false
			}
		} else {
			if !checkRequired(&reqHeaderVal, &vHeader) {
				isValid = true
			}
		}
	}

	return isValid
}

// checkAll checks whether all of the configured headers match in the request.
func checkAll(headers []SingleHeader, req *http.Request) bool {
	isValid := true

	for _, vHeader := range headers {
		if !isValid {
			return false
		}

		reqHeaderVal := req.Header.Get(vHeader.Name)

		if vHeader.IsURLDecode() {
			reqHeaderVal, _ = url.QueryUnescape(reqHeaderVal)
		}

		if reqHeaderVal != "" {
			if !checkMatches(&reqHeaderVal, &vHeader) {
				isValid = false
			}
		} else {
			if !checkRequired(&reqHeaderVal, &vHeader) {
				isValid = false
			}
		}
	}

	return isValid
}

// checkOne checks whether at least one of the configured headers matches in the request.
func checkOne(headers []SingleHeader, req *http.Request) bool {
	isValid := false

	for _, vHeader := range headers {
		reqHeaderVal := req.Header.Get(vHeader.Name)

		if vHeader.IsURLDecode() {
			reqHeaderVal, _ = url.QueryUnescape(reqHeaderVal)
		}

		if reqHeaderVal != "" {
			if checkMatches(&reqHeaderVal, &vHeader) {
				isValid = true
			}
		} else {
			if !checkRequired(&reqHeaderVal, &vHeader) {
				isValid = false
			}
		}
	}

	return isValid
}

// checkMatches checks whether the header matches the configuration.
func checkMatches(requestValue *string, vHeader *SingleHeader) bool {
	if vHeader.IsContains() {
		return checkContains(requestValue, vHeader)
	}

	if vHeader.IsRegex() {
		return checkRegex(requestValue, vHeader)
	}

	return checkRequired(requestValue, vHeader)
}

// checkContains checks whether a header value contains the configured value.
func checkContains(requestValue *string, vHeader *SingleHeader) bool {
	if vHeader.IsDebug() {
		fmt.Println("validate-headers (debug): Validating contains:", *requestValue, vHeader.Values)
	}

	matchCount := 0
	for _, value := range vHeader.Values {
		if strings.Contains(*requestValue, value) {
			matchCount++
		}
	}

	if vHeader.MatchType == string(MatchNone) {
		return matchCount == 0
	}

	if matchCount == 0 || (vHeader.MatchType == string(MatchAll) && matchCount != len(vHeader.Values)) {
		return false
	}

	return true
}

// checkRegex checks whether a header value matches the configured regex.
func checkRegex(requestValue *string, vHeader *SingleHeader) bool {
	if vHeader.IsDebug() {
		fmt.Println("validate-headers (debug): Validating:", *requestValue, "with regex:", vHeader.Values)
	}

	matchCount := 0
	for _, value := range vHeader.Values {
		match, err := regexp.MatchString(value, *requestValue)

		if err == nil && match {
			matchCount++
		} else if vHeader.IsDebug() && err != nil {
			fmt.Println("validate-headers (debug): ERROR matching regex:", err)
		}
	}

	if vHeader.MatchType == string(MatchNone) {
		return matchCount == 0
	}

	if matchCount == 0 || (vHeader.MatchType == string(MatchAll) && matchCount != len(vHeader.Values)) {
		return false
	}

	return true
}

// checkRequired checks whether a header value is required in the request.
func checkRequired(requestValue *string, vHeader *SingleHeader) bool {
	if vHeader.IsDebug() {
		fmt.Println("validate-headers (debug): Validating required:", *requestValue, vHeader.Values)
	}

	matchCount := 0
	for _, value := range vHeader.Values {
		if *requestValue == value {
			matchCount++
		}

		if !vHeader.IsRequired() && *requestValue == "" {
			matchCount++
		}
	}

	if vHeader.MatchType == string(MatchNone) {
		if *requestValue == "" {
			return !vHeader.IsRequired()
		}

		return matchCount == 0
	}

	return matchCount > 0
}

// IsURLDecode checks whether a header value should be URL decoded before testing it.
func (s *SingleHeader) IsURLDecode() bool {
	return s.URLDecode != nil && *s.URLDecode
}

// IsDebug checks whether a header value should print debug information in the log.
func (s *SingleHeader) IsDebug() bool {
	return s.Debug != nil && *s.Debug
}

// IsContains checks whether a header value should contain the configured value.
func (s *SingleHeader) IsContains() bool {
	return s.Contains != nil && *s.Contains
}

// IsRequired checks whether a header is mandatory in the request; defaults to 'true'.
func (s *SingleHeader) IsRequired() bool {
	return s.Required == nil || *s.Required
}

// IsRegex checks whether a header value should be matched using regular expressions.
func (s *SingleHeader) IsRegex() bool {
	return s.Regex != nil && *s.Regex
}
