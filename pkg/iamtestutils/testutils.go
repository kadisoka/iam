//

package iamtestutils

// import (
// 	"bytes"
// 	"encoding/json"
// 	"net/http"
// 	"net/url"
// 	"os"
// 	"strings"
// 	"testing"

// 	"github.com/jmoiron/sqlx"
// 	_ "github.com/lib/pq"
// 	"github.com/nyaruka/phonenumbers"

// 	"github.com/citadelium/iam/pkg/iam"
// )

// func RegisterAndAuthenticate(
// 	t *testing.T, phoneNumber string,
// ) (userID iam.UserID, terminalID iam.TerminalID, accessToken string) {
// 	t.Helper()

// 	parsedPhoneNumber, err := iam.PhoneNumberFromString(phoneNumber, "")
// 	if err != nil {
// 		panic(err)
// 	}
// 	countryCode := parsedPhoneNumber.CountryCode()
// 	nationalNumber := parsedPhoneNumber.NationalNumber()

// 	client := &http.Client{}

// 	payloadBytes, _ := json.Marshal(map[string]interface{}{
// 		"display_name":               "Integration Test",
// 		"verification_resource_type": "phone-number",
// 		"verification_resource_name": phoneNumber,
// 	})

// 	regResp, err := client.Post(TerminalServiceBaseURL+"/register",
// 		"application/json", bytes.NewReader(payloadBytes))
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer regResp.Body.Close()

// 	var regRespData map[string]string
// 	json.NewDecoder(regResp.Body).Decode(&regRespData)

// 	var code string
// 	err = DB.QueryRow(
// 		`SELECT code FROM phone_number_verifications WHERE `+
// 			`country_code=$1 AND national_number=$2 AND confirmation_time IS NULL`,
// 		countryCode, nationalNumber).Scan(&code)
// 	if err != nil {
// 		panic(err)
// 	}

// 	terminalID, err = iam.TerminalIDFromString(regRespData["terminal_id"])
// 	if err != nil {
// 		panic(err)
// 	}

// 	payloadBytes, _ = json.Marshal(map[string]interface{}{
// 		"terminal_id": regRespData["terminal_id"],
// 		"code":        code,
// 	})
// 	secretResp, err := client.Post(TerminalServiceBaseURL+"/secret",
// 		"application/json", bytes.NewReader(payloadBytes))
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer secretResp.Body.Close()

// 	var secretRespData map[string]string
// 	json.NewDecoder(secretResp.Body).Decode(&secretRespData)

// 	authReqData := url.Values{}
// 	authReqData.Set("grant_type", "password")
// 	authReqData.Set("username", "terminal:"+regRespData["terminal_id"])
// 	authReqData.Set("password", secretRespData["secret"])

// 	authResp, err := client.Post(ServerBaseURL+"/token",
// 		"application/x-www-form-urlencoded",
// 		strings.NewReader(authReqData.Encode()))
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer authResp.Body.Close()

// 	var authRespData map[string]string
// 	json.NewDecoder(authResp.Body).Decode(&authRespData)

// 	userID, err = iam.UserIDFromString(authRespData["user_id"])
// 	if err != nil {
// 		panic(err)
// 	}
// 	return userID, terminalID, authRespData["access_token"]
// }

// var ServerBaseURL = "http://localhost:8080/iam/oauth"
// var TerminalServiceBaseURL = "http://localhost:8080/iam/terminals"
// var DB *sqlx.DB

// func init() {
// 	if v := os.Getenv("IAM_TEST_BASE_URL"); v != "" {
// 		ServerBaseURL = v + "/oauth"
// 		TerminalServiceBaseURL = v + "/terminals"
// 	}

// 	dbURL := os.Getenv("IAM_TEST_DB_URL")
// 	var err error
// 	DB, err = sqlx.Connect("postgres", dbURL)
// 	if err != nil {
// 		panic(err)
// 	}
// }
