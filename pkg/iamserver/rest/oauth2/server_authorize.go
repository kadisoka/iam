//

package oauth2

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/citadelium/foundation/pkg/api/oauth2"
	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/emicklei/go-restful"
	"golang.org/x/text/language"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver"
)

func (restSrv *Server) getAuthorize(req *restful.Request, resp *restful.Response) {
	//TODO: if authorization context is valid, and the application has been
	// previously authorized for the user, simply redirect back.

	r := req.Request
	w := resp

	inQuery := r.URL.Query()
	val, err := oauth2.AuthorizationRequestFromURLValues(inQuery)
	if err != nil {
		log.WithRequest(r).
			Error().Msgf("unable to decode query: %v", err)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found"))
		return
	}

	//TODO:
	// - note that redirect_uri is allowed to be empty
	// - if redirect_uri is not empty, load client data and compare the
	//   redirect_uri. if they are not equal, that's an error
	// - if provided redirect_uri is empty, use client's data
	// - if we have no valid redirect_uri, show error page

	//TODO: support OOB
	if val.RedirectURI != "" && !strings.HasPrefix(val.RedirectURI, "http") {
		log.WithRequest(r).
			Warn().Msgf("redirect_uri invalid")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 Not Found"))
		return
	}

	//TODO: validate inputs
	if val.ClientID == "" {
		if val.RedirectURI == "" {
			log.WithRequest(r).
				Warn().Msgf("client_id invalid and no redirect_uri")
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("404 Not Found"))
			return
		}
		log.WithRequest(r).
			Warn().Msgf("client_id missing")
		cbURL := val.RedirectURI + "?" + oauth2.MustQueryString(oauth2.ErrorResponse{
			Error: oauth2.ErrorInvalidRequest,
			State: val.State,
		})
		http.Redirect(w, r, cbURL, http.StatusFound)
		return
	}

	clientID, err := iam.ClientIDFromString(val.ClientID)
	if err != nil {
		log.WithRequest(r).
			Warn().Msgf("client_id malformed: %v", err)
		cbURL := val.RedirectURI + "?" + oauth2.MustQueryString(oauth2.ErrorResponse{
			Error: oauth2.ErrorInvalidRequest,
			State: val.State,
		})
		http.Redirect(w, r, cbURL, http.StatusFound)
		return
	}
	if clientID.IsNotValid() {
		log.WithRequest(r).
			Warn().Msgf("client_id is invalid: %v", err)
		cbURL := val.RedirectURI + "?" + oauth2.MustQueryString(oauth2.ErrorResponse{
			Error: oauth2.ErrorInvalidRequest,
			State: val.State,
		})
		http.Redirect(w, r, cbURL, http.StatusFound)
		return
	}
	clientData, err := restSrv.serverCore.ClientByID(clientID)
	if err != nil || clientData == nil {
		log.WithRequest(r).
			Warn().Msgf("client_id does not refer a valid client: %v", err)
		cbURL := val.RedirectURI + "?" + oauth2.MustQueryString(oauth2.ErrorResponse{
			Error: oauth2.ErrorInvalidRequest,
			State: val.State,
		})
		http.Redirect(w, r, cbURL, http.StatusFound)
		return
	}
	if val.RedirectURI != "" && !clientData.HasOAuth2RedirectURI(val.RedirectURI) {
		log.WithRequest(r).
			Warn().Msgf("redirect_uri mismatch: %v", err)
		cbURL := val.RedirectURI + "?" + oauth2.MustQueryString(oauth2.ErrorResponse{
			Error: oauth2.ErrorInvalidRequest,
			State: val.State,
		})
		http.Redirect(w, r, cbURL, http.StatusFound)
		return
	}

	//TODO:
	// - check the scopes
	// - ensure that the client is allowed to use this flow

	targetURL := restSrv.loginURL + "?" + inQuery.Encode()
	http.Redirect(w, r, targetURL, http.StatusFound)
	return
}

func (restSrv *Server) postAuthorize(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if !reqCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Msgf("Unauthorized: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	clientIDArgVal, _ := req.BodyParameter("client_id")
	clientID, err := iam.ClientIDFromString(clientIDArgVal)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid field form.client_id %v: %v", clientIDArgVal, err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	responseTypeArgVal, _ := req.BodyParameter("response_type")
	responseType := oauth2.ResponseTypeFromString(responseTypeArgVal)
	if responseType != oauth2.ResponseTypeCode {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid field form.response_type %v: unexpected value", responseType)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	client, err := restSrv.serverCore.ClientByID(clientID)
	if err != nil {
		panic(err)
	}
	if client == nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid client ID: %v", clientID)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}
	if !clientID.IsConfidential() && !clientID.IsUserAgent() {
		log.WithContext(reqCtx).
			Warn().Msgf("Invalid client type for ID %v", clientID)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	redirectURIStr, _ := req.BodyParameter("redirect_uri")
	if redirectURIStr != "" && !client.HasOAuth2RedirectURI(redirectURIStr) {
		log.WithContext(reqCtx).
			Warn().Msgf("Redirect URI mismatch for client %v. Got %v , expecting %v .",
			clientID, redirectURIStr, client.OAuth2RedirectURI)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	if redirectURIStr == "" {
		redirectURIStr = client.OAuth2RedirectURI[0]
	}
	redirectURI, err := url.Parse(redirectURIStr)
	if err != nil {
		panic(err)
	}

	state, _ := req.BodyParameter("state")
	authCtx := reqCtx.Authorization()
	tNow := time.Now().UTC()
	preferredLanguages := restSrv.parseRequestAcceptLanguage(req, reqCtx, "")
	termDisplayName := ""
	var terminalID iam.TerminalID

	switch responseType {
	case oauth2.ResponseTypeCode:
		terminalID, _, err = restSrv.serverCore.
			RegisterTerminal(iamserver.TerminalRegistrationInput{
				ClientID:           clientID,
				UserID:             authCtx.UserID,
				DisplayName:        termDisplayName,
				AcceptLanguage:     strings.Join(preferredLanguages, ","),
				CreationTime:       tNow,
				CreationUserID:     authCtx.UserIDPtr(),
				CreationTerminalID: authCtx.TerminalIDPtr(),
				CreationIPAddress:  reqCtx.RemoteAddress(),
				CreationUserAgent:  strings.TrimSpace(req.Request.UserAgent()),
				VerificationType:   iam.TerminalVerificationResourceTypeOAuthAuthorizationCode,
				VerificationID:     0,
			})
		if err != nil {
			panic(err)
		}

		redirectURI.RawQuery = oauth2.MustQueryString(oauth2.AuthorizationResponse{
			Code:  terminalID.String(),
			State: state,
		})

	case oauth2.ResponseTypeToken:
		terminalID, _, err = restSrv.serverCore.
			RegisterTerminal(iamserver.TerminalRegistrationInput{
				ClientID:           clientID,
				UserID:             authCtx.UserID,
				DisplayName:        termDisplayName,
				AcceptLanguage:     strings.Join(preferredLanguages, ","),
				CreationTime:       tNow,
				CreationUserID:     authCtx.UserIDPtr(),
				CreationTerminalID: authCtx.TerminalIDPtr(),
				CreationIPAddress:  reqCtx.RemoteAddress(),
				CreationUserAgent:  strings.TrimSpace(req.Request.UserAgent()),
				VerificationType:   iam.TerminalVerificationResourceTypeOAuthImplicit,
				VerificationID:     0,
			})
		if err != nil {
			panic(err)
		}

		tokenString, err := restSrv.serverCore.
			GenerateAccessTokenJWT(reqCtx, terminalID, authCtx.UserID)
		if err != nil {
			panic(err)
		}

		redirectURI.Fragment = oauth2.MustQueryString(iam.OAuth2TokenResponse{
			TokenResponse: oauth2.TokenResponse{
				TokenType:   oauth2.TokenTypeBearer,
				AccessToken: tokenString,
				State:       state,
			}})
	}

	rest.RespondTo(resp).Success(
		&iam.OAuth2AuthorizePostResponse{
			RedirectURI: redirectURI.String(),
		})
}

// Parse preferred languages from request
func (restSrv *Server) parseRequestAcceptLanguage(
	req *restful.Request,
	reqCtx *iam.RESTRequestContext,
	defaultPreferredLanguages string,
) (termLangStrings []string) {
	termLangTags, _, err := language.ParseAcceptLanguage(defaultPreferredLanguages)
	if defaultPreferredLanguages != "" && err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to parse preferred languages from body %q: %v", defaultPreferredLanguages, err)
	}
	if len(termLangTags) == 0 || err != nil {
		var headerLangTags []language.Tag
		headerLangTags, _, err = language.ParseAcceptLanguage(req.Request.Header.Get("Accept-Language"))
		if err != nil {
			log.WithContext(reqCtx).
				Warn().Msgf("Unable to parse preferred languages from HTTP header: %v", err)
		} else {
			if len(headerLangTags) > 0 {
				termLangTags = headerLangTags
			}
		}
	}

	for _, langTag := range termLangTags {
		termLangStrings = append(termLangStrings, langTag.String())
	}

	return termLangStrings
}
