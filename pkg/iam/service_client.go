package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"github.com/kadisoka/foundation/pkg/api/oauth2"
	"github.com/kadisoka/foundation/pkg/errors"
	grpcmd "google.golang.org/grpc/metadata"
)

type ServiceClient interface {
	ServiceClientServer

	GRPCServiceClient
	RESTServiceClient

	ServiceClientAuth

	// ServerBaseURL returns the base URL of the IAM server this client
	// will connect to.
	ServerBaseURL() string

	// TerminalID returns the terminal ID of the client instance after
	// successful authentication with IAM server.
	TerminalID() TerminalID
}

type ServiceClientAuth interface {
	// AuthenticateServiceClient authenticates current application as a
	// service which will grant access to S2S API as configured on the
	// IAM service server.
	AuthenticateServiceClient(
		serviceInstanceID string,
	) (terminalID TerminalID, err error)

	// AccessTokenByAuthorizationCodeGrant obtains access token by providing
	// authorization code returned from a 3-legged authorization flow
	// (the authorization code flow).
	AccessTokenByAuthorizationCodeGrant(
		authorizationCode string,
	) (accessToken string, err error)
}

const (
	serverOAuth2JWKSPath  = "/oauth2/jwks"
	serverOAuth2TokenPath = "/oauth2/token"
)

func NewServiceClientSimple(instID string, envPrefix string) (ServiceClient, error) {
	cfg, err := ServiceClientConfigFromEnv(envPrefix, nil)
	if err != nil {
		return nil, errors.Wrap("config loading", err)
	}

	jwksURL := cfg.ServerBaseURL + serverOAuth2JWKSPath
	var jwtKeyChain JWTKeyChain
	_, err = jwtKeyChain.LoadVerifierKeysFromJWKSetByURL(jwksURL)
	if err != nil {
		return nil, errors.Wrap("jwt key set loading", err)
	}

	uaStateServiceClient := &UserAccountStateServiceClientCore{}

	inst, err := NewServiceClient(cfg, &jwtKeyChain, uaStateServiceClient)
	if err != nil {
		return nil, err
	}

	_, err = inst.AuthenticateServiceClient(instID)
	if err != nil {
		return nil, err
	}

	return inst, nil
}

func NewServiceClient(
	serviceClientConfig *ServiceClientConfig,
	jwtKeyChain *JWTKeyChain,
	userAccountStateService UserAccountStateService,
) (ServiceClient, error) {
	if serviceClientConfig != nil {
		cfg := *serviceClientConfig
		serviceClientConfig = &cfg
	}

	serviceClientServer, err := NewServiceClientServer(jwtKeyChain, userAccountStateService)
	if err != nil {
		return nil, err
	}

	return &ServiceClientCore{
		serviceClientConfig: serviceClientConfig,
		ServiceClientServer: serviceClientServer,
	}, nil
}

type ServiceClientCore struct {
	serviceClientConfig *ServiceClientConfig
	terminalID          TerminalID
	clientAccessToken   string
	ServiceClientServer
}

var _ ServiceClient = &ServiceClientCore{}

func (svcClient *ServiceClientCore) ServerBaseURL() string {
	if svcClient.serviceClientConfig != nil {
		return svcClient.serviceClientConfig.ServerBaseURL
	}
	return ""
}

func (svcClient *ServiceClientCore) TerminalID() TerminalID { return svcClient.terminalID }

func (svcClient *ServiceClientCore) AuthenticateServiceClient(
	serviceInstanceID string,
) (terminalID TerminalID, err error) {
	if svcClient.serviceClientConfig == nil {
		return TerminalIDZero, errors.New("oauth client is not configured")
	}
	baseURL := svcClient.ServerBaseURL()
	if !strings.HasPrefix(baseURL, "http") {
		return TerminalIDZero, errors.New("iam server base URL is not configured")
	}

	if serviceInstanceID == "" {
		return TerminalIDZero, errors.ArgMsg("serviceInstanceID", "empty")
	}

	terminalID, accessToken, err := svcClient.
		obtainAccessTokenByClientCredentials(serviceInstanceID)
	if err != nil {
		panic(err)
	}

	svcClient.terminalID = terminalID
	svcClient.clientAccessToken = accessToken

	return svcClient.terminalID, nil
}

func (svcClient *ServiceClientCore) obtainAccessTokenByClientCredentials(
	serviceInstanceID string,
) (terminalID TerminalID, accessToken string, err error) {
	if svcClient.serviceClientConfig == nil || svcClient.serviceClientConfig.Credentials.ClientID == "" {
		return TerminalIDZero, "", errors.New("oauth client is not configured")
	}
	baseURL := svcClient.ServerBaseURL()
	if !strings.HasPrefix(baseURL, "http") {
		return TerminalIDZero, "", errors.New("iam server base URL is not configured")
	}
	tokenEndpointURL := baseURL + serverOAuth2TokenPath

	payloadStr, err := oauth2.QueryString(oauth2.AccessTokenRequest{
		GrantType: oauth2.GrantTypeClientCredentials,
	})
	if err != nil {
		return TerminalIDZero, "", errors.Wrap("outgoing request encoding", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		tokenEndpointURL,
		bytes.NewBuffer([]byte(payloadStr)))
	if err != nil {
		return TerminalIDZero, "", err
	}

	req.SetBasicAuth(
		svcClient.serviceClientConfig.Credentials.ClientID,
		svcClient.serviceClientConfig.Credentials.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	runtimeVersion := runtime.Version()
	runtimeVersion = "go/" + strings.TrimPrefix(runtimeVersion, "go")
	req.Header.Set("User-Agent", "Kadisoka-IAM-Client/1.0 "+runtimeVersion+" ("+serviceInstanceID+")")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return TerminalIDZero, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic("Unexpected response status: " + resp.Status)
	}

	var tokenResp OAuth2TokenResponse
	err = json.NewDecoder(resp.Body).
		Decode(&tokenResp)
	if err != nil {
		return TerminalIDZero, "", err
	}

	terminalID, err = TerminalIDFromString(tokenResp.TerminalID)
	if err != nil {
		return TerminalIDZero, "", errors.Wrap("TerminalIDFromString", err)
	}

	//TODO: to handle expiration, we'll need to store the value of 'ExpiresIn'
	// from the response[1] or 'exp' from the JWT claims[2].
	// [1] https://tools.ietf.org/html/rfc6749#section-4.2.2
	// [2] https://tools.ietf.org/html/rfc7519#section-4.1.4

	return terminalID, tokenResp.AccessToken, nil
}

func (svcClient *ServiceClientCore) getClientAccessToken() string {
	//TOOD:
	// - check the expiration. if the token is about to expire, 1 minute
	//   before expiration which info was obtained in obtainAccessTokenByPasswordWithTerminalCreds,
	//   start a task (goroutine) to obtain a new token
	// - ensure that only one task running at a time (mutex)
	return svcClient.clientAccessToken
}

// AccessTokenByAuthorizationCodeGrant conforms ServiceClientAuth.
func (svcClient *ServiceClientCore) AccessTokenByAuthorizationCodeGrant(
	authorizationCode string,
) (accessToken string, err error) {
	if svcClient.serviceClientConfig == nil {
		return "", errors.New("oauth client is not configured")
	}
	baseURL := svcClient.ServerBaseURL()
	if !strings.HasPrefix(baseURL, "http") {
		return "", errors.New("iam server base URL is not configured")
	}
	tokenEndpointURL := baseURL + serverOAuth2TokenPath

	//TODO: redirect_uri is required
	payloadStr, err := oauth2.QueryString(oauth2.AccessTokenRequest{
		GrantType: oauth2.GrantTypeAuthorizationCode,
		Code:      authorizationCode,
	})
	if err != nil {
		return "", errors.Wrap("outgoing request encoding", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		tokenEndpointURL,
		bytes.NewBuffer([]byte(payloadStr)))
	if err != nil {
		return "", err
	}

	req.SetBasicAuth(
		svcClient.serviceClientConfig.Credentials.ClientID,
		svcClient.serviceClientConfig.Credentials.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		panic("Unexpected response status: " + resp.Status)
	}

	var tokenResp oauth2.TokenResponse
	err = json.NewDecoder(resp.Body).
		Decode(&tokenResp)
	if err != nil {
		return "", err
	}

	//TODO: to handle expiration, we'll need to store the value of 'ExpiresIn'
	// from the response[1] or 'exp' from the JWT claims[2].
	// [1] https://tools.ietf.org/html/rfc6749#section-4.2.2
	// [2] https://tools.ietf.org/html/rfc7519#section-4.1.4

	return tokenResp.AccessToken, nil
}

// AuthorizedOutgoingGRPCContext returns a new instance of Context with
// authorization information set. If baseContext is valid, this method
// will use it as the parent context, otherwise, this method will create
// a Background context.
func (svcClient *ServiceClientCore) AuthorizedOutgoingGRPCContext(
	baseContext context.Context,
) context.Context {
	accessToken := svcClient.getClientAccessToken()
	md := grpcmd.Pairs(AuthorizationMetadataKey, accessToken)
	if baseContext == nil {
		baseContext = context.Background()
	}
	return grpcmd.NewOutgoingContext(baseContext, md)
}

// AuthorizedOutgoingHTTPRequestHeader returns a new instance of http.Header
// with authorization information set. If baseHeader is proivded, this method
// will merge it into the returned value.
func (svcClient *ServiceClientCore) AuthorizedOutgoingHTTPRequestHeader(
	baseHeader http.Header,
) http.Header {
	accessToken := svcClient.getClientAccessToken()
	outHeader := http.Header{}
	if accessToken != "" {
		outHeader.Set("Authorization", "Bearer "+accessToken)
	}
	if len(baseHeader) > 0 {
		for k, v := range baseHeader {
			outHeader[k] = v[:]
		}
	}
	return outHeader
}
