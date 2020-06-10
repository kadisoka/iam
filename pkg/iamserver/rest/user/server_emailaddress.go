package user

import (
	"net/http"
	"time"

	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/citadelium/foundation/pkg/errors"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver/eav10n"
)

func (restSrv *Server) putUserEmailAddress(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to load request authorization: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	var reqEntity UserEmailAddressPutRequestJSONV1
	err = req.ReadEntity(&reqEntity)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to read request body: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	emailAddress := reqEntity.EmailAddress
	parsedEmailAddress, err := iam.EmailAddressFromString(emailAddress)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Email address %v, is not valid", emailAddress)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	var verificationMethods []eav10n.VerificationMethod
	for _, s := range reqEntity.VerificationMethods {
		m := eav10n.VerificationMethodFromString(s)
		if m != eav10n.VerificationMethodUnspecified {
			verificationMethods = append(verificationMethods, m)
		}
	}

	restSrv.handleSetEmailAddress(reqCtx, req, resp,
		parsedEmailAddress, verificationMethods)
}

func (restSrv *Server) handleSetEmailAddress(
	reqCtx *iam.RESTRequestContext,
	req *restful.Request,
	resp *restful.Response,
	emailAddress iam.EmailAddress,
	verificationMethods []eav10n.VerificationMethod,
) {
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() && !authCtx.IsUserContext() {
		log.WithContext(reqCtx).Warn().Msgf("Unauthorized")
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	if targetUserIDStr := req.PathParameter("user-id"); targetUserIDStr != "" && targetUserIDStr != "me" {
		targetUserID, err := iam.UserIDFromString(targetUserIDStr)
		if err != nil {
			log.WithContext(reqCtx).Warn().Msgf("Invalid user ID: %v", err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		if targetUserID != authCtx.UserID {
			log.WithContext(reqCtx).Warn().Msgf("Setting other user's email address is not allowed")
			rest.RespondTo(resp).EmptyError(
				http.StatusForbidden)
			return
		}
	}

	verificationID, codeExpiry, err := restSrv.serverCore.
		SetUserPrimaryEmailAddress(
			reqCtx, authCtx.UserID, emailAddress, verificationMethods)
	if err != nil {
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Msgf("SetUserPrimaryEmailAddress to %v: %v",
				emailAddress, err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("SetUserPrimaryEmailAddress to %v: %v",
			emailAddress, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	if verificationID == 0 {
		rest.RespondTo(resp).Success(nil)
		return
	}

	rest.RespondTo(resp).SuccessWithHTTPStatusCode(
		&UserEmailAddressPutResponse{
			VerificationID: verificationID,
			CodeExpiry:     *codeExpiry,
		},
		http.StatusAccepted)
	return
}

//TODO(exa): should we allow confirming without the need to login
func (restSrv *Server) postUserEmailAddressVerificationConfirmation(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if !reqCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Msgf("Unauthorized: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	var reqEntity UserEmailAddressVerificationConfirmationPostRequest
	err = req.ReadEntity(&reqEntity)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to load request content: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	updated, err := restSrv.serverCore.
		ConfirmUserEmailAddressVerification(
			reqCtx, reqEntity.VerificationID, reqEntity.Code)
	if err != nil {
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Msgf("ConfirmUserEmailAddressVerification %v failed: %v",
				reqEntity.VerificationID, err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("ConfirmUserEmailAddressVerification %v failed: %v",
			reqEntity.VerificationID, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	if !updated {
		rest.RespondTo(resp).EmptyError(http.StatusGone)
		return
	}

	rest.RespondTo(resp).Success(nil)
}

type UserEmailAddressPutRequestJSONV1 struct {
	EmailAddress        string   `json:"email_address"`
	VerificationMethods []string `json:"verification_methods"`
}

type UserEmailAddressPutResponse struct {
	VerificationID int64     `json:"verification_id"`
	CodeExpiry     time.Time `json:"code_expiry"`
}

type UserEmailAddressVerificationConfirmationPostRequest struct {
	VerificationID int64  `json:"verification_id"`
	Code           string `json:"code"`
}
