package user

import (
	"net/http"

	oidc "github.com/citadelium/foundation/pkg/api/openid/connect"
	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
)

//TODO: the details would be depends on the type of the client:
// if it's internal, it could get all the details. Otherwise, it will
// be depended on the requested scope and user's privacy settings.
func (restSrv *Server) getUserOpenIDConnectUserInfo(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Request context")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	var requestedUserID iam.UserID
	requestedUserID = authCtx.UserID

	userBaseProfile, err := restSrv.serverCore.
		GetUserBaseProfile(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User base profile fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	userPhoneNumber, err := restSrv.serverCore.
		GetUserPrimaryPhoneNumber(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User phone number fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	var phoneNumberStr string
	var phoneNumberVerified bool
	if userPhoneNumber != nil {
		phoneNumberStr = userPhoneNumber.String()
		phoneNumberVerified = true
	}

	//TODO(exa): should get display email address instead of primary
	// email address for this use case.
	userEmailAddress, err := restSrv.serverCore.
		GetUserPrimaryEmailAddress(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User email address fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	var emailAddressStr string
	var emailAddressVerified bool
	if userEmailAddress != nil {
		emailAddressStr = userEmailAddress.RawInput()
		emailAddressVerified = true
	}

	userInfo := oidc.StandardClaims{
		Sub:                 requestedUserID.String(),
		Name:                userBaseProfile.DisplayName,
		Email:               emailAddressStr,
		EmailVerified:       emailAddressVerified,
		PhoneNumber:         phoneNumberStr,
		PhoneNumberVerified: phoneNumberVerified,
	}

	restSrv.eTagResponder.RespondGetJSON(req, resp, &userInfo)
}
