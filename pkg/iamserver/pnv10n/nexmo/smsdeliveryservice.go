package nexmo

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func (sms *SMSDeliveryService) SendTextMessage(recipient, text string) error {
	sender := sms.config.Number
	if sender == "" {
		sender = "Nexmo"
	}
	endPoint := fmt.Sprintf("%s/%s", apiBaseURL, "json")
	bodyReq := url.Values{}
	bodyReq.Set("to", strings.Trim(recipient, "+"))
	bodyReq.Set("text", text)
	bodyReq.Set("type", "text")
	bodyReq.Set("from", sender)
	payload := strings.NewReader(bodyReq.Encode())

	req, err := http.NewRequest("POST", endPoint, payload)
	if err != nil {
		return errors.New("Unable to build new request > " + err.Error())
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// https://medium.com/@nate510/don-t-use-go-s-default-http-client-4804cb19f779
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)

	if err != nil {
		return errors.New("Unable to send request -> " + err.Error())
	}
	defer resp.Body.Close()

	// resp.StatusCode is between 200 and 300.
	// This is because an HTTP status code with the form 2XX signifies a successful HTTP POST request
	// https://standard.telesign.com/api-reference/apis/sms-api/send-an-sms/reference
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	errBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.New(err.Error())
	}
	return errors.New(string(errBody))
}
