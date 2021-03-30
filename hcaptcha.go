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
	Success     bool      `json:"success"`
	Score       float32   `json:"score"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

const hcaptchaServerName = "https://hcaptcha.com/siteverify"

var hcaptchaPrivateKey string
var hcaptchaScore float32
var timeResponse int
var postError bool

func check(ctx context.Context, response string) (r Response, err error) {
	postError = false

	resp, err := performRecaptchaRequest(ctx, response)

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

	fmt.Println("Captcha payload", r)

	return
}

func performRecaptchaRequest(ctx context.Context, response string) (*http.Response, error) {
	netClient := apmhttp.WrapClient(&http.Client{
		Timeout: time.Duration(timeResponse) * time.Second,
	})

	payload := url.Values{"secret": {hcaptchaPrivateKey}, "response": {response}}

	request, _ := http.NewRequest("POST", hcaptchaServerName, strings.NewReader(payload.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return netClient.Do(request.WithContext(ctx))
}

// Confirm is the public interface function.
// It calls check, which the client ip address, the challenge code from the hCaptcha form,
// and the client's response input to that challenge to determine whether or not
// the client answered the hCaptcha input question correctly.
// It returns a boolean value indicating whether or not the client answered correctly.
func Confirm(response, ip string) (result bool, err error) {
	return ConfirmWithContext(context.Background(), response, ip)
}

// ConfirmWithContext ...
func ConfirmWithContext(ctx context.Context, response string, ip string) (result bool, err error) {
	result = false
	resp, err := check(ctx, response)

	if resp.Success == true && resp.Score < hcaptchaScore {
		result = true
	}

	if postError == true {
		result = true
	}

	logCaptchaResult(result, resp.Score, ip)

	return
}

// Init allows the webserver or code evaluating the hCaptcha form input to set the
// hCaptcha private key (string) value, which will be different for every domain.
func Init(key string, score float32, time int) {
	hcaptchaPrivateKey = key
	hcaptchaScore = score
	timeResponse = time
}

func logCaptchaResult(success bool, score float32, ip string) {
	if success {
		log.Printf("[%v] Captcha: Valid token with score of %f\n", ip, score)
		return
	}

	// if score > 0 {
	// 	log.Printf("[%v] Captcha: Valid token but refused due high risk score(got: %f, expected: %f)", ip, score, hcaptchaScore)
	// 	return
	// }

	log.Printf("[%v] Captcha: Invalid token", ip)
}
