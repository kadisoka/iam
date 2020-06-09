//

package oauth2

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/citadelium/foundation/pkg/api/oauth2"
	"github.com/citadelium/foundation/pkg/errors"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
)

//TODO: rate limit and/or tries limit.
func (restSrv *Server) handleTokenRequestByAuthorizationCodeGrant(
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

	if reqClient == nil {
		log.WithRequest(req.Request).
			Warn().Msg("No authorized client")
		resp.WriteHeaderAndJson(http.StatusUnauthorized,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	authCode := req.Request.FormValue("code")
	if authCode == "" {
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
			restful.MIME_JSON)
		return
	}

	var terminalID iam.TerminalID
	if strings.HasPrefix(authCode, "otp:") {
		// Only for non-confidential user-agents
		if clientID := reqClient.ID; !clientID.IsPublic() && !clientID.IsUserAgent() {
			log.WithRequest(req.Request).
				Warn().Msgf("Client %v is not allowed to use grant type 'authorization_code'", reqClient.ID)
			resp.WriteHeaderAndJson(http.StatusForbidden,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
				restful.MIME_JSON)
			return
		}

		parts := strings.Split(authCode, ":")
		if len(parts) != 3 {
			log.WithRequest(req.Request).
				Warn().Msgf("Authorization code contains invalid number of parts (%v)", len(parts))
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
				restful.MIME_JSON)
			return
		}
		terminalID, err = iam.TerminalIDFromString(parts[1])
		if err != nil || terminalID.IsNotValid() {
			log.WithRequest(req.Request).
				Warn().Err(err).Msg("Auth code malformed")
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
				restful.MIME_JSON)
			return
		}
		authCode = parts[2]
	} else {
		// Only for confidential user-agents
		if clientID := reqClient.ID; !clientID.IsConfidential() && !clientID.IsUserAgent() {
			log.WithRequest(req.Request).
				Warn().Msgf("Client %v is not allowed to use grant type 'authorization_code'", reqClient.ID)
			resp.WriteHeaderAndJson(http.StatusForbidden,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
				restful.MIME_JSON)
			return
		}

		terminalID, err = iam.TerminalIDFromString(authCode)
		if err != nil || terminalID.IsNotValid() {
			log.WithRequest(req.Request).
				Warn().Err(err).Msg("Auth code malformed")
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
				restful.MIME_JSON)
			return
		}
		authCode = ""
	}

	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil && err != iam.ErrReqFieldAuthorizationTypeUnsupported {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Request context")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msg("Authorization context must not be valid")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	redirectURI := req.Request.FormValue("redirect_uri")
	if redirectURI != "" && reqClient.HasOAuth2RedirectURI(redirectURI) {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid redirect_uri: %s (wants %s)", redirectURI, reqClient.OAuth2RedirectURI)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidRequest},
			restful.MIME_JSON)
		return
	}

	clientIDStr := req.Request.FormValue("client_id")
	if clientIDStr != "" && clientIDStr != reqClient.ID.String() {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid client_id: %s (wants %s)", clientIDStr, reqClient.ID)
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	terminalSecret, userID, err := restSrv.serverCore.
		ConfirmTerminalAuthorization(reqCtx, terminalID, authCode)
	if err != nil {
		switch err {
		case iam.ErrTerminalVerificationCodeExpired:
			log.WithContext(reqCtx).
				Warn().Err(err).Msg("ConfirmTerminalAuthorization")
			// Status code 410 (gone) might be more approriate but the standard
			// says that we should use 400 for expired grant.
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{
					Error:            oauth2.ErrorInvalidGrant,
					ErrorDescription: "expired"},
				restful.MIME_JSON)
			return
		case iam.ErrAuthorizationCodeAlreadyClaimed,
			iam.ErrTerminalVerificationCodeMismatch:
			log.WithContext(reqCtx).
				Warn().Err(err).Msg("ConfirmTerminalAuthorization")
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidGrant},
				restful.MIME_JSON)
			return
		}
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Err(err).Msg("ConfirmTerminalAuthorization")
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidRequest},
				restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Err(err).Msgf("ConfirmTerminalAuthorization")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	accessToken, err := restSrv.serverCore.
		GenerateAccessTokenJWT(reqCtx, terminalID, userID)
	if err != nil {
		panic(err)
	}

	refreshToken, err := restSrv.serverCore.
		GenerateRefreshTokenJWT(terminalID, terminalSecret)
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("GenerateRefreshTokenJWT: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.OAuth2TokenResponse{
			TokenResponse: oauth2.TokenResponse{
				AccessToken:  accessToken,
				TokenType:    oauth2.TokenTypeBearer,
				ExpiresIn:    iam.AccessTokenTTLInSeconds,
				RefreshToken: refreshToken,
			},
			UserID:         userID.String(),
			TerminalSecret: terminalSecret,
		},
		restful.MIME_JSON)
}
