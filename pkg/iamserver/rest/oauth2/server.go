package oauth2

import (
	"net/http"

	"github.com/emicklei/go-restful"
	"github.com/emicklei/go-restful-openapi"
	"github.com/kadisoka/foundation/pkg/api/oauth2"
	apperrs "github.com/kadisoka/foundation/pkg/app/errors"

	"github.com/kadisoka/iam/pkg/iam"
	"github.com/kadisoka/iam/pkg/iam/rest/logging"
	"github.com/kadisoka/iam/pkg/iamserver"
	"github.com/kadisoka/iam/pkg/jose/jwk"
)

var log = logging.NewPkgLogger()

// New instantiates an Server.
func NewServer(
	basePath string,
	iamServerCore *iamserver.Core,
	loginURL string,
) (*Server, error) {
	if !iamServerCore.JWTKeyChain().CanSign() {
		return nil, apperrs.NewConfigurationMsg("JWT key chain is required")
	}
	return &Server{
		iamserver.RESTServiceServerWith(iamServerCore),
		basePath,
		loginURL,
	}, nil
}

// Server is a limited implementation of OAuth 2.0 Authorization Framework standard (RFC 6749)
type Server struct {
	serverCore *iamserver.RESTServiceServerBase
	basePath   string
	loginURL   string
}

func (restSrv *Server) jwtKeyChain() *iam.JWTKeyChain {
	return restSrv.serverCore.JWTKeyChain()
}

func (restSrv *Server) RESTRequestContext(req *http.Request) (*iam.RESTRequestContext, error) {
	return restSrv.serverCore.RESTRequestContext(req)
}

// RestfulWebService is used to obtain restful WebService with all endpoints set up.
func (restSrv *Server) RestfulWebService() *restful.WebService {
	restWS := new(restful.WebService)
	restWS.
		Path(restSrv.basePath).
		Consumes("application/x-www-form-urlencoded").
		Produces(restful.MIME_JSON)

	tags := []string{"iam.v1.oauth"}

	restWS.Route(restWS.
		GET("/authorize").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.getAuthorize).
		Doc("OAuth 2.0 conforming authorization endpoint").
		Param(restWS.QueryParameter("client_id", "The ID of the client which makes the request").
			Required(true)).
		Param(restWS.QueryParameter("response_type", "Value MUST be set to `code`").
			Required(true)).
		Param(restWS.QueryParameter("redirect_uri", "Client's registered redirection URI")).
		Param(restWS.QueryParameter("state", "An opaque value used by the client to "+
			"maintain state between the request and callback.")).
		Returns(http.StatusFound, "Success", nil))

	restWS.Route(restWS.
		POST("/authorize").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.postAuthorize).
		Doc("Authorization endpoint (for use with web front-end)").
		Param(restWS.FormParameter("client_id", "The ID of the client which makes the request").
			Required(true)).
		Param(restWS.FormParameter("response_type", "Value MUST be set to `code`").
			Required(true)).
		Param(restWS.FormParameter("redirect_uri", "Client's registered redirection URI")).
		Param(restWS.FormParameter("state", "An opaque value used by the client to "+
			"maintain state between the request and callback.")).
		Returns(http.StatusOK, "Success", iam.OAuth2AuthorizePostResponse{}))

	restWS.Route(restWS.
		GET("/jwks").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.getJWKS).
		Doc("JSON Web Key Set endpoint").
		Notes("The JSON Web Key Set endpoint provides public keys needed "+
			"to verify JWT (JSON Web Token) tokens issued by this service.").
		Returns(http.StatusOK, "OK", jwk.Set{}))

	restWS.Route(restWS.
		POST("/token").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.postToken).
		Doc("OAuth token endpoint").
		Notes("The token endpoint is used by the client to obtain an "+
			"access token by presenting its authorization grant or "+
			"refresh token. The token endpoint is used with every "+
			"authorization grant except for the implicit grant type "+
			"(since an access token is issued directly). RFC 6749 § 3.2.").
		Param(restWS.
			HeaderParameter(
				"Authorization", "basic-oauth2-client-creds").
			Required(true)).
		Param(restWS.
			FormParameter(
				"grant_type", "Supported grant types: `password`, `authorization_code`, `client_credentials`").
			Required(true)).
		Param(restWS.
			FormParameter(
				"username", "Required for `password` grant type")).
		Param(restWS.
			FormParameter(
				"password", "For use with `password` grant type")).
		Param(restWS.
			FormParameter(
				"code", "Required for `authorization_code` grant type")).
		Returns(http.StatusOK, "Authorization successful", iam.OAuth2TokenResponse{}).
		Returns(http.StatusBadRequest, "Request has missing data or contains invalid data", oauth2.ErrorResponse{}).
		Returns(http.StatusUnauthorized, "Client authorization check failure", oauth2.ErrorResponse{}))

	return restWS
}
