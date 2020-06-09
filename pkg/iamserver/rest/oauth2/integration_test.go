//

//+build integration

package oauth2_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var baseURL = "http://localhost:8080/iam/oauth"

func init() {
	if v := os.Getenv("IAM_TEST_BASE_URL"); v != "" {
		baseURL = v + "/oauth"
	}
}

func TestGetJWKS(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Get(baseURL + "/jwks")
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	//TODO: check body
}

func TestPostTokenEmptyRequest(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/token", "", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestPostTokenEmptyBody(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/token", "application/x-www-form-urlencoded", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	var errData errorResponse
	errDec := json.NewDecoder(resp.Body).Decode(&errData)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Nil(t, errDec)
	assert.Equal(t, "invalid_request", errData.Error)
}

func TestPostTokenInvalidGrantType(t *testing.T) {
	client := &http.Client{}
	data := url.Values{}
	data.Set("grant_type", "invalid")

	resp, err := client.Post(baseURL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()))
	if err == nil {
		defer resp.Body.Close()
	}

	var errData errorResponse
	errDec := json.NewDecoder(resp.Body).Decode(&errData)

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Nil(t, errDec)
	assert.Equal(t, "unsupported_grant_type", errData.Error)
}

type errorResponse struct {
	Error string `json:"error"`
}
