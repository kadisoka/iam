package main

import (
	"net/http"

	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"
	"github.com/kadisoka/foundation/pkg/api/rest"

	"github.com/kadisoka/iam/pkg/iam"
)

func NewRESTService(
	iamClient iam.ServiceClient,
	basePath string,
) *RESTService {
	return &RESTService{
		iamClient: iamClient,
		basePath:  basePath,
	}
}

type RESTService struct {
	iamClient iam.ServiceClient
	basePath  string
}

func (restSvc *RESTService) RestfulWebService() *restful.WebService {
	restWS := new(restful.WebService)
	restWS.Path(restSvc.basePath).
		Produces(restful.MIME_JSON)

	tags := []string{"Microservice"}

	restWS.Route(restWS.
		GET("/auth").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSvc.getAuth).
		Doc("Obtain access token using parameters obtained from a OAuth 2.0 authorization code flow").
		Param(restWS.
			QueryParameter(
				"authorization_code",
				"The authorization code received from the authorization server.").
			Required(true)).
		Param(restWS.
			QueryParameter(
				"state",
				"Will be provided by authorization server if the `state` "+
					"parameter was present in the client authorization request.")).
		Returns(http.StatusOK, "OK", &authGetResponse{}))

	restWS.Route(restWS.
		GET("/hello").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSvc.getHello).
		Doc("Hello").
		Param(restWS.
			HeaderParameter(
				"Authorization",
				"Bearer access_token").
			Required(true)).
		Returns(http.StatusOK, "OK", &helloGetResponse{}))

	return restWS
}

type authGetResponse struct {
	AccessToken string `json:"access_token"`
}

func (restSvc *RESTService) getAuth(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSvc.iamClient.RESTRequestContext(req.Request)
	if err != nil {
		logCtx(reqCtx).Err(err).Msg("Request context")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsUserContext() {
		logCtx(reqCtx).Warn().Msg("Already authorized")
		resp.WriteHeaderAndJson(http.StatusOK,
			&authGetResponse{AccessToken: authCtx.RawToken()},
			restful.MIME_JSON)
		return
	}

	authCode := req.QueryParameter("code")

	accessToken, err := restSvc.iamClient.
		AccessTokenByAuthorizationCodeGrant(authCode)
	if err != nil {
		panic(err)
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&authGetResponse{AccessToken: accessToken},
		restful.MIME_JSON)
}

type helloGetResponse struct {
	Greetings string `json:"greetings"`
}

func (restSvc *RESTService) getHello(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSvc.iamClient.RESTRequestContext(req.Request)
	if err != nil {
		logCtx(reqCtx).Err(err).Msg("Request context")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if !authCtx.IsUserContext() {
		logCtx(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		resp.WriteHeaderAndJson(http.StatusUnauthorized, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&helloGetResponse{Greetings: "Hello, user " + authCtx.UserID.String()},
		restful.MIME_JSON)
}
