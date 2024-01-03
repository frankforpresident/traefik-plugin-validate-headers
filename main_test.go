package traefik_plugin_validate_headers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/yaml.v2"
)

type Test struct {
	name           string
	headers        map[string]string
	expectedStatus int
	expectedError  error
}

type TestConfig struct {
	config *Config
	tests  []Test
}

func TestValidator(t *testing.T) {

	configTestPairs := []TestConfig{
		//MatchNoneConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchNone),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchNone_Success",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchNone_Fail",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchNone_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchNoneOptionalConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchNone),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(false),
						Debug:    Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchNoneOptional_Success",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchNoneOptional_Fail",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchNoneOptional_Success_DifferentHeader",
					headers: map[string]string{
						"Content-Type": "application/json",
					},
					expectedStatus: http.StatusOK,
				},
			},
		},
		//MatchAllContainConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchAll),
						Values: []string{
							"d", "e",
						},
						Required: Bool(true),
						Contains: Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchAllContains_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchAllContains_Fail",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchAll_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchAllRegexConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchAll),
						Values: []string{
							"^de",
							"DE$",
						},
						Required: Bool(true),
						Regex:    Bool(true),
						Debug:    Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchAllRegex_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchAllRegex_Fail",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchAll_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchAllConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchAll),
						Values: []string{
							"d", "e",
						},
						Required: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchAllContains_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect for header Content-Language, match-all can only be used in combination with 'contains' or 'regex'"),
				},
			},
		},
		//matchAllUrlDecodeConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "X-Forwarded-Tls-Client-Cert-Info",
						MatchType: string(MatchAll),
						Values: []string{
							"CN=common-name",
							"SAN=\"somkindofdomain.domain.thing.test\"",
						},
						Required:  Bool(true),
						Debug:     Bool(true),
						Contains:  Bool(true),
						URLDecode: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchAllUrlDecode_Success",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name&SAN=%22somkindofdomain.domain.thing.test%22",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchAllUrlDecode_Success_With_Unknown",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name&SAN=%22somkindofdomain.domain.thing.test%22&UNKNOWN=unknown",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchAllUrlDecode_Fail",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchAllUrlDecode_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchOneUrlDecodeConfig
		{
			config: &Config{
				MatchType: string(MatchOne),
				Headers: []SingleHeader{
					{
						Name:      "X-Forwarded-Tls-Client-Cert-Info",
						MatchType: string(MatchOne),
						Values: []string{
							"CN=common-name",
							"SAN=\"somkindofdomain.domain.thing.test\"",
						},
						Required:  Bool(true),
						Debug:     Bool(true),
						Contains:  Bool(true),
						URLDecode: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchOneUrlDecode_Success",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name&SAN=%22somkindofdomain.domain.thing.test%22",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneUrlDecode_Success_With_Unknown",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name&SAN=%22somkindofdomain.domain.thing.test%22&UNKNOWN=unknown",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneUrlDecode_Fail",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=common-name",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneUrlDecode_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//TopLevelMatchNoneUrlDecodeConfig
		{
			config: &Config{
				MatchType: string(MatchNone),
				Headers: []SingleHeader{
					{
						Name:      "X-Forwarded-Tls-Client-Cert-Info",
						MatchType: string(MatchNone),
						Values: []string{
							"CN=common-name",
							"SAN=\"somkindofdomain.domain.thing.test\"",
						},
						Required:  Bool(true),
						Debug:     Bool(true),
						Contains:  Bool(true),
						URLDecode: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchNoneUrlDecode_Fail_InvalidHeader",
					headers: map[string]string{
						"X-Forwarded-Tls-Client-Cert-Info": "CN=unknown",
					},
					expectedStatus: http.StatusOK,
				},
			},
		},
		//MatchOneConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchOne_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOne_Fail",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchOne_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchOneOptionalConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(false),
						Debug:    Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchOneOptional_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneOptional_Fail",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchOneOptional_Success_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusOK,
				},
			},
		},
		//MatchOneContainsConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"de",
						},
						Required: Bool(true),
						Debug:    Bool(true),
						Contains: Bool(true),
					},
				},
			},
			tests: []Test{

				{
					name: "MatchOneContains_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneContains_Fail",
					headers: map[string]string{
						"Content-Language": "fr-FR",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchOneContains_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchNoneContainsConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchNone),
						Values: []string{
							"de",
						},
						Required: Bool(true),
						Debug:    Bool(true),
						Contains: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchOneContains_Fail",
					headers: map[string]string{
						"Content-Language": "fr-FR",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneContains_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchOneContains_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//MatchOneRegexConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"^de-AT$",
							"^de-DE$",
						},
						Required: Bool(true),
						Debug:    Bool(true),
						Regex:    Bool(true),
					},
				},
				Error: ErrorConfig{
					StatusCode: http.StatusNotFound,
					Message:    "Not Found",
				},
			},
			tests: []Test{

				{
					name: "MatchOneRegex_Success",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneRegex_Fail",
					headers: map[string]string{
						"Content-Language": "fr-FR",
					},
					expectedStatus: http.StatusNotFound,
				},
				{
					name: "MatchOneRegex_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusNotFound,
				},
			},
		},
		//MatchNoneRegexConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchNone),
						Values: []string{
							"^de-AT$",
							"^de-DE$",
						},
						Required: Bool(true),
						Debug:    Bool(true),
						Regex:    Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "MatchOneRegex_Success",
					headers: map[string]string{
						"Content-Language": "fr-FR",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchOneRegex_Fail",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchOneRegex_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//matchTopLevelOneConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
					{
						Name:      "Content-Type",
						MatchType: string(MatchOne),
						Values: []string{
							"application/json",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
				},
				MatchType: string(MatchOne),
			},
			tests: []Test{

				{
					name: "MatchTopLevelOne_Success_All_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/json",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchTopLevelOne_Success_One_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/xml",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "MatchTopLevelOne_Fail",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "MatchTopLevelOne_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//matchTopLevelAllConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
					{
						Name:      "Content-Type",
						MatchType: string(MatchOne),
						Values: []string{
							"application/json",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
				},
				MatchType: string(MatchAll),
			},
			tests: []Test{

				{
					name: "matchTopLevelAll_Success_All_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/json",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "matchTopLevelAll_Fail_One_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/xml",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "matchTopLevelAll_Fail",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "matchTopLevelAll_Fail_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusForbidden,
				},
			},
		},
		//matchTopLevelNoneConfig
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchNone),
						Values: []string{
							"de-DE",
							"de-AT",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
					{
						Name:      "Content-Type",
						MatchType: string(MatchNone),
						Values: []string{
							"application/json",
						},
						Required: Bool(true),
						Debug:    Bool(true),
					},
				},
				MatchType: string(MatchNone),
			},
			tests: []Test{

				{
					name: "matchTopLevelNone_Fail_All_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/json",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "matchTopLevelNone_Fail_One_Present",
					headers: map[string]string{
						"Content-Language": "de-DE",
						"Content-Type":     "application/xml",
					},
					expectedStatus: http.StatusForbidden,
				},
				{
					name: "matchTopLevelNone_Success",
					headers: map[string]string{
						"Content-Language": "nl-NL",
					},
					expectedStatus: http.StatusOK,
				},
				{
					name: "matchTopLevelNone_Success_InvalidHeader",
					headers: map[string]string{
						"InvalidHeader": "invalidValue",
					},
					expectedStatus: http.StatusOK,
				},
			},
		},
		// MissingHeadersConfig
		{
			config: CreateConfig(), //Using CreateConfig() to test the default config
			tests: []Test{
				{
					name: "MissingHeadersConfig",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect, missing headers"),
				},
			},
		},
		// MissingHeaderName
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						MatchType: string(MatchOne),
					},
				},
			},
			tests: []Test{
				{
					name: "MissingHeaderName",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect, missing header name"),
				},
			},
		},
		// MissingHeaderMatchType
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name: "Content-Language",
						Values: []string{
							"de-DE",
							"de-AT",
						},
					},
				},
			},
			tests: []Test{
				{
					name: "MissingHeaderMatchType",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect, missing match type configuration for header Content-Language"),
				},
			},
		},
		// MissingHeaderValues
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
					},
				},
			},
			tests: []Test{
				{
					name: "MissingHeaderValues",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect, missing header values"),
				},
			},
		},
		// EmptyHeaderValues
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						MatchType: string(MatchOne),
						Values: []string{
							"",
						},
					},
				},
			},
			tests: []Test{
				{
					name: "EmptyHeaderValues",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedError: fmt.Errorf("validate-headers: configuration incorrect, empty value found"),
				},
			},
		},
		// InvalidRegex
		{
			config: &Config{
				Headers: []SingleHeader{
					{
						Name:      "Content-Language",
						Regex:     Bool(true),
						MatchType: string(MatchOne),
						Values: []string{
							"[",
						},
						Debug: Bool(true),
					},
				},
			},
			tests: []Test{
				{
					name: "InvalidRegex",
					headers: map[string]string{
						"Content-Language": "de-DE",
					},
					expectedStatus: http.StatusForbidden},
			},
		},
	}

	// Test case execution
	for _, ct := range configTestPairs {
		for _, tt := range ct.tests {
			n := tt.name

			// Uncomment to run a single test
			// if n != "MatchNone_Fail_InvalidHeader" {
			// 	continue
			// }

			t.Run(n, func(t *testing.T) {
				req, err := http.NewRequest("GET", "/", nil)
				if err != nil {
					t.Fatal(err)
				}

				for key, value := range tt.headers {
					req.Header.Add(key, value)
				}

				rr := httptest.NewRecorder()

				h, err := New(nil, http.HandlerFunc(dummyHandler), ct.config, "test")
				if err != nil {
					if err.Error() != tt.expectedError.Error() {
						t.Fatal(err)
					}

					return
				}

				h.ServeHTTP(rr, req)

				if rr.Code != tt.expectedStatus {
					t.Errorf("got %d, want %d", rr.Code, tt.expectedStatus)
				}
			})
		}
	}
}

func dummyHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// Helper function to convert bool to *bool
func Bool(b bool) *bool {
	return &b
}

func TestParseYAML(t *testing.T) {
	yamlData := `
- name: EXAMPLE_HEADER
  matchtype: one
  urldecode: true
  values:
    - "A"
    - "B"
  required: true
`

	var headers []SingleHeader
	err := yaml.Unmarshal([]byte(yamlData), &headers)
	if err != nil {
		t.Fatalf("Error unmarshaling YAML: %v", err)
	}

	if headers[0].Name != "EXAMPLE_HEADER" {
		t.Errorf("Mismatch in header name")
	}

	if headers[0].MatchType != "one" {
		t.Errorf("Mismatch in header matchtype")
	}

	if *headers[0].Required != true {
		t.Errorf("Mismatch in header required")
	}

	if *headers[0].URLDecode != true {
		t.Errorf("Mismatch in header urldecode")
	}

	if headers[0].Values[0] != "A" && headers[0].Values[1] != "B" {
		t.Errorf("Mismatch in header values")
	}
}
