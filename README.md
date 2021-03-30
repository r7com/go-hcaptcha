go-hcaptcha
============

About
-----

This package handles [hCaptcha](https://www.hcaptcha.com) form submissions in [Go](http://golang.org/).

Usage
-----

Install the package in your environment:

```
go get github.com/r7com/go-hcaptcha
```

To use it within your own code, import <tt>github.com/r7com/go-hcaptcha</tt> and call:

```
hcaptcha.Init(recaptchaPrivateKey, recaptchaScore)
```

once, to set the hCaptcha private key for your domain, then:

```
hcaptcha.Confirm(recaptchaResponse)
```

for each hCaptcha form input you need to check, using the values obtained by reading the form's POST parameters (the <tt>hcaptchaResponse</tt> in the above corresponds to the value of <tt>h-recaptcha-response</tt> sent by the hCaptcha server.)

The hcaptcha.Confirm() function returns **true** if the captcha was completed correctly and the score was equal or above the value passed in hCaptcha.Init() or **false** if the captcha had an invalid token or the score failed, along with any errors (from the HTTP io read or the attempt to unmarshal the JSON reply).
