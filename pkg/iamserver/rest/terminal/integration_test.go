//

//+build integration

package terminalservice_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"

	"github.com/kadisoka/iam/pkg/iamtestutils"
)

var baseURL = "http://localhost:8080/iam/terminals"
var testDB *sqlx.DB

func init() {
	if v := os.Getenv("IAM_TEST_BASE_URL"); v != "" {
		baseURL = v + "/terminals"
	}

	dbURL := os.Getenv("IAM_TEST_DB_URL")
	var err error
	testDB, err = sqlx.Connect("postgres", dbURL)
	if err != nil {
		panic(err)
	}
}

func TestGetTerminalsRegisterWrongMethod(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Get(baseURL + "/register")
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestPostTerminalsRegisterEmptyRequest(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/register", "", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestPostTerminalsRegisterWrongContentType(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/register", "application/x-www-form-urlencoded", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode)
}

func TestPostTerminalsRegisterEmptyBody(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/register", "application/json", nil)
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPostTerminalsRegisterEmptyData(t *testing.T) {
	client := &http.Client{}

	resp, err := client.Post(baseURL+"/register", "application/json", strings.NewReader("{}"))
	if err == nil {
		defer resp.Body.Close()
	}

	assert.Nil(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestPostTerminalsRegisterBasic(t *testing.T) {
	client := &http.Client{}

	payload := map[string]interface{}{
		"display_name":               "Integration Test",
		"verification_resource_type": "phone-number",
		"verification_resource_name": "+15550001",
	}
	payloadBytes, _ := json.Marshal(payload)

	resp, err := client.Post(baseURL+"/register", "application/json", bytes.NewReader(payloadBytes))
	if err == nil {
		defer resp.Body.Close()
	}

	var respData map[string]string
	json.NewDecoder(resp.Body).Decode(&respData)

	var code string
	testDB.QueryRow(`SELECT code FROM phone_number_verifications WHERE ` +
		`country_code='1' AND national_number='5550001' AND confirmation_time IS NULL`).
		Scan(&code)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, 6, len(code))
	assert.NotEmpty(t, respData["terminal_id"])
}

func TestPostTerminalsRegisterConfirm(t *testing.T) {
	client := &http.Client{}

	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"display_name":               "Integration Test",
		"verification_resource_type": "phone-number",
		"verification_resource_name": "+15550002",
	})

	regResp, err := client.Post(baseURL+"/register", "application/json", bytes.NewReader(payloadBytes))
	if err == nil {
		defer regResp.Body.Close()
	}

	var regRespData map[string]string
	json.NewDecoder(regResp.Body).Decode(&regRespData)

	var code string
	testDB.QueryRow(`SELECT code FROM phone_number_verifications WHERE ` +
		`country_code='1' AND national_number='5550002' AND confirmation_time IS NULL`).
		Scan(&code)

	payloadBytes, _ = json.Marshal(map[string]interface{}{
		"terminal_id": regRespData["terminal_id"],
		"code":        code,
	})
	secretResp, err := client.Post(baseURL+"/secret", "application/json", bytes.NewReader(payloadBytes))
	if err == nil {
		defer secretResp.Body.Close()
	}
	var secretRespData map[string]string
	json.NewDecoder(secretResp.Body).Decode(&secretRespData)

	assert.Nil(t, err)
	assert.NotNil(t, secretResp)
	assert.Equal(t, http.StatusOK, secretResp.StatusCode)
	assert.NotEmpty(t, secretRespData["secret"])
}

func TestSetUserTerminalFCMRegistrationToken(t *testing.T) {
	userID, terminalID, accessToken := iamtestutils.RegisterAndAuthenticate(t, "+15550101")
	client := &http.Client{}

	token := uuid.New().String() // not a real token; just for testing
	payloadBytes, _ := json.Marshal(map[string]interface{}{
		"token": token,
	})

	tokenPutReq, _ := http.NewRequest("PUT", baseURL+"/fcm_registration_token", bytes.NewReader(payloadBytes))
	tokenPutReq.Header.Set("Content-Type", "application/json")
	tokenPutReq.Header.Set("Authorization", "Bearer "+accessToken)
	tokenPutResp, err := client.Do(tokenPutReq)
	if err == nil {
		defer tokenPutResp.Body.Close()
	}

	var dbToken string
	testDB.QueryRow(`SELECT token FROM user_terminal_fcm_registration_tokens `+
		`WHERE user_id=$1 AND terminal_id=$2 AND deleted_at IS NULL`,
		userID, terminalID).Scan(&dbToken)

	assert.Nil(t, err)
	assert.NotNil(t, tokenPutResp)
	assert.Equal(t, http.StatusNoContent, tokenPutResp.StatusCode)
	assert.Equal(t, token, dbToken)
}
