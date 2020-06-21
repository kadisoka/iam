package user

import (
	"net/http"
	"time"

	"github.com/emicklei/go-restful"
	"github.com/kadisoka/foundation/pkg/api/rest"
	"github.com/kadisoka/foundation/pkg/errors"

	"github.com/kadisoka/iam/pkg/iam"
	"github.com/kadisoka/iam/pkg/iamserver/pnv10n"
)

func (restSrv *Server) putUserPhoneNumber(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		logCtx(reqCtx).Error().Msgf("Request context: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() && !authCtx.IsUserContext() {
		logCtx(reqCtx).Warn().Msgf("Unauthorized: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	var reqEntity UserPhoneNumberPutRequest
	err = req.ReadEntity(&reqEntity)

	phoneNumber, err := iam.PhoneNumberFromString(reqEntity.PhoneNumber)
	if err != nil {
		logCtx(reqCtx).
			Warn().Msgf("Unable to parse %q as phone number: %v",
			reqEntity.PhoneNumber, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}
	if !phoneNumber.IsValid() {
		logCtx(reqCtx).
			Warn().Msgf("Provided phone number %q is invalid", reqEntity.PhoneNumber)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	var verificationMethods []pnv10n.VerificationMethod
	for _, s := range reqEntity.VerificationMethods {
		m := pnv10n.VerificationMethodFromString(s)
		if m != pnv10n.VerificationMethodUnspecified {
			verificationMethods = append(verificationMethods, m)
		}
	}

	verificationID, codeExpiry, err := restSrv.serverCore.
		SetUserPrimaryPhoneNumber(
			reqCtx, authCtx.UserID, phoneNumber, verificationMethods)
	if err != nil {
		if errors.IsCallError(err) {
			logCtx(reqCtx).
				Warn().Msgf("SetUserPrimaryPhoneNumber to %v: %v",
				phoneNumber, err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		logCtx(reqCtx).
			Error().Msgf("SetUserPrimaryPhoneNumber to %v: %v",
			phoneNumber, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	if verificationID == 0 {
		rest.RespondTo(resp).Success(nil)
		return
	}

	rest.RespondTo(resp).SuccessWithHTTPStatusCode(
		&UserPhoneNumberPutResponse{
			VerificationID: verificationID,
			CodeExpiry:     *codeExpiry,
		},
		http.StatusAccepted)
	return
}

//TODO(exa): should we allow confirming without the need to login
func (restSrv *Server) postUserPhoneNumberVerificationConfirmation(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if !reqCtx.IsUserContext() {
		logCtx(reqCtx).
			Warn().Msgf("Unauthorized: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	var reqEntity UserPhoneNumberVerificationConfirmationPostRequest
	err = req.ReadEntity(&reqEntity)
	if err != nil {
		logCtx(reqCtx).
			Warn().Msgf("Unable to load request content: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	updated, err := restSrv.serverCore.
		ConfirmUserPhoneNumberVerification(
			reqCtx, reqEntity.VerificationID, reqEntity.Code)
	if err != nil {
		if errors.IsCallError(err) {
			logCtx(reqCtx).
				Warn().Msgf("ConfirmUserPhoneNumberVerification %v failed: %v",
				reqEntity.VerificationID, err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		logCtx(reqCtx).
			Error().Msgf("ConfirmUserPhoneNumberVerification %v failed: %v",
			reqEntity.VerificationID, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	if !updated {
		rest.RespondTo(resp).EmptyError(
			http.StatusGone)
		return
	}

	rest.RespondTo(resp).Success(nil)
}

type UserPhoneNumberPutRequest struct {
	PhoneNumber         string   `json:"phone_number"`
	VerificationMethods []string `json:"verification_methods"`
}

type UserPhoneNumberPutResponse struct {
	VerificationID int64     `json:"verification_id"`
	CodeExpiry     time.Time `json:"code_expiry"`
}

type UserPhoneNumberVerificationConfirmationPostRequest struct {
	VerificationID int64  `json:"verification_id"`
	Code           string `json:"code"`
}
