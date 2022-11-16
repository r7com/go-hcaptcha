// Package hcaptcha handles hCaptcha (https://hcaptcha.com) form submissions
//
// This package is designed to be called from within an HTTP server or web framework
// which offers hCaptcha form inputs and requires them to be evaluated for correctness
//
// Edit the hcaptchaPrivateKey constant before building and using
package hcaptcha

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.elastic.co/apm/module/apmhttp"
)

// Response holds the response provided by
// google hcaptcha
type Response struct {
	Success    bool     `json:"success"`
	Score      float32  `json:"score"`
	Hostname   string   `json:"hostname"`
	ErrorCodes []string `json:"error-codes"`
}

const hcaptchaServerName = "https://hcaptcha.com/siteverify"

var hcaptchaPrivateKey string
var hcaptchaScore float32
var timeResponse int
var postError bool

func check(ctx context.Context, response string, ip string) (r Response, err error) {
	postError = false

	resp, err := performCaptchaRequest(ctx, response, ip)

	if err != nil {
		log.Printf("Post error: %s\n", err)
		postError = true
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Read error: could not read body: %s", err)
		return
	}

	err = json.Unmarshal(body, &r)
	if err != nil {
		fmt.Printf("Read error: got invalid JSON: %s", err)
		return
	}

	return
}

func performCaptchaRequest(ctx context.Context, response string, ip string) (*http.Response, error) {
	netClient := apmhttp.WrapClient(&http.Client{
		Timeout: time.Duration(timeResponse) * time.Second,
	})

	payload := url.Values{
		"secret":   {hcaptchaPrivateKey},
		"response": {response},
		"remoteip": {ip},
	}

	log.Printf("[%v] Validating captcha challenge result\n", ip)

	request, _ := http.NewRequest("POST", hcaptchaServerName, strings.NewReader(payload.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return netClient.Do(request.WithContext(ctx))
}

// Confirm adds a default context and calls ConfirmWithContext
func Confirm(response, ip string) (result bool, score float32, err error) {
	return ConfirmWithContext(context.Background(), response, ip)
}

// ConfirmWithContext is the public interface function.
// It calls check, which the client ip address, the challenge code from the hCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the hCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func ConfirmWithContext(ctx context.Context, response string, ip string) (result bool, score float32, err error) {
	result = false
	score = 0.0
	resp, err := check(ctx, response, ip)

	log.Printf("[%v] Captcha: User token: %s\n", ip, response)
	if resp.Success {
		score = resp.Score
		if resp.Score < hcaptchaScore {
			result = true
			log.Printf("[%v] Captcha: Valid token with risk score of %f\n", ip, resp.Score)
		} else {
			result = false
			log.Printf("[%v] Captcha: Valid token but refused due high risk score(got: %f, expected: < %f)", ip, resp.Score, hcaptchaScore)
		}
		return
	}

	if postError {
		log.Printf("[%v] Unable to verify captcha due request error", ip)
		result = true
		return
	}

	log.Printf("[%v] Captcha: Invalid token", ip)
	return
}

// Init allows the webserver or code evaluating the hCaptcha form input to set the
// hCaptcha private key (string) value, which will be different for every domain.
func Init(key string, score float32, time int) {
	hcaptchaPrivateKey = key
	hcaptchaScore = score
	timeResponse = time
}
