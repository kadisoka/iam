//

package oauth2

import (
	"net/http"

	"github.com/citadelium/foundation/pkg/api/oauth2"
	"github.com/emicklei/go-restful"
)

func (restSrv *Server) postToken(req *restful.Request, resp *restful.Response) {
	if req.Request.Method != http.MethodPost {
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidRequest)
		return
	}

	// We don't check the authorization here because it is grant-specific

	err := req.Request.ParseForm()
	if err != nil {
		log.WithRequest(req.Request).
			Warn().Msgf("unable to parse form: %v", err)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidRequest)
		return
	}
	grantTypeArgVal := req.Request.FormValue("grant_type")
	if grantTypeArgVal == "" {
		log.WithRequest(req.Request).
			Warn().Msgf("Empty grant_type")
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidRequest)
		return
	}
	grantType := oauth2.GrantTypeFromString(grantTypeArgVal)

	switch grantType {
	case oauth2.GrantTypeAuthorizationCode:
		restSrv.handleTokenRequestByAuthorizationCodeGrant(req, resp)
		return
	case oauth2.GrantTypeClientCredentials:
		restSrv.handleTokenRequestByClientCredentials(req, resp)
		return
	case oauth2.GrantTypePassword:
		// Note: we are currently disabling this grant type until we have
		// implemented rate limiter for handleTokenRequestByPasswordGrant
		log.WithRequest(req.Request).
			Warn().Msgf("Grant type is currently disabled: %v", grantType)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorUnsupportedGrantType)
		return
	case oauth2.GrantTypeRefreshToken:
		//TODO: our refresh tokens are JWT which claims structure can be found
		// in iam.RefreshTokenClaims. It contains terminal ID (and optionally
		// terminal secret). We load it and its related data and then
		// issue another access token if the previous token is about to
		// expire (e.g., < 10 min from expiration), otherwise, we could reuse
		// the previously issued access token (check the authorization ID).
		log.WithRequest(req.Request).
			Warn().Msgf("Unsupported grant_type: %v", grantType)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorUnsupportedGrantType)
		return
	default:
		log.WithRequest(req.Request).
			Warn().Msgf("Unsupported grant_type: %v", grantType)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorUnsupportedGrantType)
		return
	}
}
