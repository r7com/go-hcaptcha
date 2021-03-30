package hcaptcha

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	httpmock "github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestConfirm(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	tests := []struct {
		score               string
		httpResponseStatus  int
		httpResponseMessage string
		expectedResult      bool
		errorMessage        string
	}{
		{"0.5", 200, `{"success": true, "score": 0.9}`, false, "It must be considered a threat"},
		{"0.5", 200, `{"success": true, "score": 0.2}`, true, "It must be considered a safe request"},
		{"0.5", 200, `{"success": false}`, false, "It must be false when google doesnt return a score"},
		{"0.5", 500, `{"success": false}`, false, "It must be false when google returns an error"},
	}

	for _, test := range tests {
		httpmock.RegisterResponder("POST", hcaptchaServerName,
			httpmock.NewStringResponder(test.httpResponseStatus, test.httpResponseMessage))

		score, _ := strconv.ParseFloat(test.score, 32)
		Init("SOME_KEY", float32(score), 2)
		result, _ := Confirm("test", "1.1.1.1")

		assert.Equal(t, test.expectedResult, result, test.errorMessage)
	}
}

func TestConfirmSlowResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", hcaptchaServerName,
		func(req *http.Request) (*http.Response, error) {
			time.Sleep(90 * time.Second)
			return httpmock.NewJsonResponse(200, map[string]interface{}{
				"success": true,
				"score":   0.9,
			})
		},
	)

	score, _ := strconv.ParseFloat("0.5", 32)
	Init("SOME_KEY", float32(score), 2)
	result, _ := Confirm("test", "1.1.1.1")

	assert.Equal(t, true, result, "Timeout expired!")

	tests := []struct {
		score               string
		httpResponseStatus  int
		httpResponseMessage string
		expectedResult      bool
		errorMessage        string
	}{
		{"0.5", 200, `{"success": true, "score": 0.9}`, false, "It must be considered a threat"},
		{"0.5", 200, `{"success": true, "score": 0.2}`, true, "It must be considered a safe request"},
		{"0.5", 200, `{"success": false}`, false, "It must be false when google doesnt return a score"},
		{"0.5", 500, `{"success": false}`, false, "It must be false when google returns an error"},
	}

	for _, test := range tests {
		httpmock.RegisterResponder("POST", hcaptchaServerName,
			httpmock.NewStringResponder(test.httpResponseStatus, test.httpResponseMessage))

		score, _ := strconv.ParseFloat(test.score, 32)
		Init("SOME_KEY", float32(score), 2)
		result, _ := Confirm("test", "1.1.1.1")

		assert.Equal(t, test.expectedResult, result, test.errorMessage)
	}
}
