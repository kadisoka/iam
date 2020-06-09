//

package oauth2

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/citadelium/foundation/pkg/api/oauth2"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
)

//TODO: rate limit
func (restSrv *Server) handleTokenRequestByPasswordGrant(
	req *restful.Request, resp *restful.Response,
) {
	reqClient, err := restSrv.serverCore.
		AuthenticateClientAuthorization(req.Request)
	if err != nil {
		log.WithRequest(req.Request).
			Warn().Err(err).Msg("Client authentication")
		// RFC 6749 § 5.2
		realmName := restSrv.serverCore.RealmName()
		if realmName == "" {
			realmName = "Restricted"
		}
		resp.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realmName))
		resp.WriteHeaderAndJson(http.StatusUnauthorized,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	//TODO: check if the client is allowed to use this grant type

	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil && err != iam.ErrReqFieldAuthorizationTypeUnsupported {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to read authorization: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Authorization context must not be valid")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	username := req.Request.FormValue("username")
	if username == "" {
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
			restful.MIME_JSON)
		return
	}
	password := req.Request.FormValue("password")

	// Username with scheme. The format is '<scheme>:<scheme-specific-identifier>'
	if names := strings.SplitN(username, ":", 2); len(names) == 2 {
		switch names[0] {
		case "terminal":
			restSrv.handleTokenRequestByPasswordGrantWithTerminalCreds(
				reqCtx, resp, reqClient, names[1], password)
			return
		default:
			log.WithRequest(req.Request).
				Warn().Msgf("Unrecognized identifier scheme: %v", names[0])
		}
	}

	log.WithRequest(req.Request).
		Warn().Msgf("Password grant with no scheme.")
	resp.WriteHeaderAndJson(http.StatusBadRequest,
		&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
		restful.MIME_JSON)
}

func (restSrv *Server) handleTokenRequestByPasswordGrantWithTerminalCreds(
	reqCtx *iam.RESTRequestContext,
	resp *restful.Response,
	reqClient *iam.Client,
	terminalIDStr string,
	terminalSecret string,
) {
	terminalID, err := iam.TerminalIDFromString(terminalIDStr)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to parse username %q as TerminalID: %v", terminalIDStr, err)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
			restful.MIME_JSON)
		return
	}

	authOK, userID, err := restSrv.serverCore.
		AuthenticateTerminal(terminalID, terminalSecret)
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("Terminal %v authentication failed: %v", terminalID, err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
	}
	if !authOK {
		log.WithContext(reqCtx).
			Warn().Msgf("Terminal %v authentication failed", terminalID)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
			restful.MIME_JSON)
	}

	if userID.IsValid() {
		userAccountState, err := restSrv.serverCore.
			GetUserAccountState(userID)
		if err != nil {
			log.WithContext(reqCtx).
				Warn().Msgf("Terminal %v user account state: %v", terminalID, err)
			resp.WriteHeaderAndJson(http.StatusInternalServerError,
				&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
				restful.MIME_JSON)
			return
		}
		if userAccountState == nil || !userAccountState.IsAccountActive() {
			var status string
			if userAccountState == nil {
				status = "not exist"
			} else {
				status = "deleted"
			}
			log.WithContext(reqCtx).
				Warn().Msgf("User %v %s", userID, status)
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
				restful.MIME_JSON)
			return
		}
	}

	if reqClient != nil {
		if reqClient.ID != terminalID.ClientID() {
			log.WithContext(reqCtx).
				Error().Msgf("Terminal %v is not associated to client %v", terminalID, reqClient.ID)
			resp.WriteHeaderAndJson(http.StatusInternalServerError,
				&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
				restful.MIME_JSON)
			return
		}
	}

	accessToken, err := restSrv.serverCore.
		GenerateAccessTokenJWT(reqCtx, terminalID, userID)
	if err != nil {
		panic(err)
	}

	refreshToken, err := restSrv.serverCore.
		GenerateRefreshTokenJWT(terminalID, terminalSecret)
	if err != nil {
		panic(err)
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.OAuth2TokenResponse{
			TokenResponse: oauth2.TokenResponse{
				AccessToken:  accessToken,
				TokenType:    oauth2.TokenTypeBearer,
				ExpiresIn:    iam.AccessTokenTTLInSeconds,
				RefreshToken: refreshToken,
			},
			UserID: userID.String(),
		},
		restful.MIME_JSON)
}
