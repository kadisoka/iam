//

package oauth2

import (
	"net/http"

	"github.com/citadelium/pkg/api/oauth2"
	"github.com/emicklei/go-restful"
)

func (restSrv *Server) postToken(req *restful.Request, resp *restful.Response) {
	if req.Request.Method != http.MethodPost {
		resp.WriteHeaderAndJson(http.StatusMethodNotAllowed,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidRequest},
			restful.MIME_JSON)
		return
	}

	// We don't check the authorization here because it is grant-specific

	err := req.Request.ParseForm()
	if err != nil {
		log.WithRequest(req.Request).
			Warn().Msgf("unable to parse form: %v", err)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidRequest},
			restful.MIME_JSON)
		return
	}
	grantTypeArgVal := req.Request.FormValue("grant_type")
	if grantTypeArgVal == "" {
		log.WithRequest(req.Request).
			Warn().Msgf("Empty grant_type")
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			oauth2.ErrorResponse{Error: oauth2.ErrorInvalidRequest},
			restful.MIME_JSON)
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
		restSrv.handleTokenRequestByPasswordGrant(req, resp)
		return
	case oauth2.GrantTypeRefreshToken:
		//TODO: our refresh tokens are JWT which claims can be found
		// in iam.RefreshTokenClaims. It contains terminal ID (and optionally
		// terminal secret). We load it and its related data and then
		// issue another access token if the previous token is about to
		// expire (e.g., < 10 min from expiration), otherwise, we could reuse
		// the previously issued access token (check the authorization ID).
		log.WithRequest(req.Request).
			Warn().Msgf("Unsupported grant_type: %v", grantType)
		resp.WriteHeaderAndJson(http.StatusNotImplemented,
			oauth2.ErrorResponse{Error: oauth2.ErrorUnsupportedGrantType},
			restful.MIME_JSON)
		return
	default:
		log.WithRequest(req.Request).
			Warn().Msgf("Unsupported grant_type: %v", grantType)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			oauth2.ErrorResponse{Error: oauth2.ErrorUnsupportedGrantType},
			restful.MIME_JSON)
		return
	}
}
