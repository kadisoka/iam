package user

import (
	"net/http"
	"time"

	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/citadelium/foundation/pkg/errors"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver/pnv10n"
)

func (restSrv *Server) putUserPhoneNumber(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).Error().Msgf("Request context: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() && !authCtx.IsUserContext() {
		log.WithContext(reqCtx).Warn().Msgf("Unauthorized: %v", err)
		resp.WriteHeaderAndJson(http.StatusUnauthorized, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	var reqEntity UserPhoneNumberPutRequest
	err = req.ReadEntity(&reqEntity)

	phoneNumber, err := iam.PhoneNumberFromString(reqEntity.PhoneNumber)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to parse %q as phone number: %v",
			reqEntity.PhoneNumber, err)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
	if !phoneNumber.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Provided phone number %q is invalid", reqEntity.PhoneNumber)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
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
			log.WithContext(reqCtx).
				Warn().Msgf("SetUserPrimaryPhoneNumber to %v: %v",
				phoneNumber, err)
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				rest.ErrorResponse{}, restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("SetUserPrimaryPhoneNumber to %v: %v",
			phoneNumber, err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if verificationID == 0 {
		resp.WriteHeader(http.StatusNoContent)
		return
	}

	resp.WriteHeaderAndJson(http.StatusAccepted,
		&UserPhoneNumberPutResponse{
			VerificationID: verificationID,
			CodeExpiry:     *codeExpiry,
		},
		restful.MIME_JSON)
	return
}

//TODO(exa): should we allow confirming without the need to login
func (restSrv *Server) postUserPhoneNumberVerificationConfirmation(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if !reqCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Msgf("Unauthorized: %v", err)
		resp.WriteHeaderAndJson(http.StatusUnauthorized, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	var reqEntity UserPhoneNumberVerificationConfirmationPostRequest
	err = req.ReadEntity(&reqEntity)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to load request content: %v", err)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	updated, err := restSrv.serverCore.
		ConfirmUserPhoneNumberVerification(
			reqCtx, reqEntity.VerificationID, reqEntity.Code)
	if err != nil {
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Msgf("ConfirmUserPhoneNumberVerification %v failed: %v",
				reqEntity.VerificationID, err)
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&rest.ErrorResponse{}, restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("ConfirmUserPhoneNumberVerification %v failed: %v",
			reqEntity.VerificationID, err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	if !updated {
		resp.WriteHeader(http.StatusGone)
		return
	}

	resp.WriteHeader(http.StatusNoContent)
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
