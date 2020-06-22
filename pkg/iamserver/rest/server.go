package rest

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"
	"github.com/go-openapi/spec"
	"github.com/kadisoka/foundation/pkg/api/rest"
	"github.com/kadisoka/foundation/pkg/app"
	"github.com/kadisoka/foundation/pkg/errors"

	"github.com/kadisoka/iam/pkg/iam"
	"github.com/kadisoka/iam/pkg/iamserver"
	"github.com/kadisoka/iam/pkg/iamserver/rest/oauth2"
	"github.com/kadisoka/iam/pkg/iamserver/rest/terminal"
	"github.com/kadisoka/iam/pkg/iamserver/rest/user"
)

const ServerLatestVersionString = "v1"

type ServerConfig struct {
	ServePort int    `env:"SERVE_PORT"`
	ServePath string `env:"SERVE_PATH"`

	// SwaggerUIDir provides information where the Swagger UI files are
	// located. If left empty, the server won't serve the Swagger UI.
	SwaggerUIDir string `env:"SWAGGER_UI_DIR"`

	// V1 contains configuration for version 1 of the API service
	V1 *ServerV1Config `env:"V1"`
}

type ServerV1Config struct {
	ServePath string `env:"SERVE_PATH"`
}

type Server struct {
	config       ServerConfig
	httpServer   *http.Server
	serveMux     *http.ServeMux
	shuttingDown bool
}

// ServerName conforms app.ServiceServer interface.
func (srv *Server) ServerName() string { return "IAM REST server" }

// Serve conforms app.ServiceServer interface.
func (srv *Server) Serve() error {
	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", srv.config.ServePort),
		Handler: srv.serveMux}
	srv.httpServer = httpServer
	err := srv.httpServer.ListenAndServe()
	if err == nil {
		if !srv.shuttingDown {
			return errors.Msg("server stopped unexpectedly")
		}
		return nil
	}
	if err == http.ErrServerClosed && srv.shuttingDown {
		return nil
	}
	return err
}

// Shutdown conforms app.ServiceServer interface.
func (srv *Server) Shutdown(ctx context.Context) error {
	//TODO: mutex?
	srv.shuttingDown = true
	return srv.httpServer.Shutdown(ctx)
}

// IsAcceptingClients conforms app.ServiceServer interface.
func (srv *Server) IsAcceptingClients() bool {
	return !srv.shuttingDown && srv.IsHealthy()
}

// IsHealthy conforms app.ServiceServer interface.
func (srv *Server) IsHealthy() bool { return true }

// ServeHTTP conforms Go's HTTP Handler interface.
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	srv.serveMux.ServeHTTP(w, r)
}

func NewServer(
	config ServerConfig,
	appInfo app.Info,
	iamServerCore *iamserver.Core,
	webUIURLs *iam.WebUIURLs, //TODO: add this to server core
) (*Server, error) {
	if webUIURLs == nil || webUIURLs.SignIn == "" {
		return nil, errors.Msg("requires valid web UI config")
	}

	config.ServePath = strings.TrimSuffix(config.ServePath, "/")
	servePath := config.ServePath
	apiDocsPath := servePath + "/apidocs.json"

	serveMux := http.NewServeMux()
	container := restful.NewContainer()
	container.ServeMux = serveMux
	container.EnableContentEncoding(true)
	container.ServiceErrorHandler(
		func(err restful.ServiceError, req *restful.Request, resp *restful.Response) {
			logReq(req.Request).
				Warn().Int("status_code", err.Code).Str("err_msg", err.Message).
				Msg("Routing error")
			resp.WriteErrorString(err.Code, err.Message)
		})
	// We need CORS for our webclients
	rest.SetUpCORSFilterByEnv(container, "CORS_")

	var v1ServePath string
	if config.V1 != nil {
		v1ServePath = config.V1.ServePath
	}
	if v1ServePath == "" {
		v1ServePath = servePath + "/v1"
	}
	initRESTV1Services(v1ServePath, container, iamServerCore, webUIURLs.SignIn)

	secDefs := spec.SecurityDefinitions{
		"basic-oauth2-client-creds": spec.BasicAuth(),
		"bearer-access-token":       spec.APIKeyAuth("Authorization", "header"),
	}
	// Setup API specification handler
	container.Add(restfulspec.NewOpenAPIService(restfulspec.Config{
		WebServices: container.RegisteredWebServices(),
		APIPath:     apiDocsPath,
		PostBuildSwaggerObjectHandler: func(swaggerSpec *spec.Swagger) {
			processSwaggerSpec(swaggerSpec, appInfo, secDefs)
		},
	}))

	if config.SwaggerUIDir != "" {
		serveMux.Handle(servePath+"/apidocs/",
			http.StripPrefix(servePath+"/apidocs/",
				http.FileServer(http.Dir(config.SwaggerUIDir))))
	}

	srv := &Server{
		config:   config,
		serveMux: serveMux,
	}

	// Health check is used by load balancer and/or orchestrator
	serveMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		log.Debug().Msg("TODO: /healthz actual health check e.g., db and other services we depended on")
		if !srv.IsHealthy() {
			log.Error().Msg("Service is not healthy")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte("OK"))
	})

	return srv, nil
}

func initRESTV1Services(
	servePath string,
	container *restful.Container,
	iamServerCore *iamserver.Core,
	signInURL string,
) {
	log.Info().Msg("Initializing terminal service...")
	terminalSrv := terminal.NewServer(servePath+"/terminals", iamServerCore)
	container.Add(terminalSrv.RestfulWebService())

	log.Info().Msg("Initializing user service...")
	userSrv := user.NewServer(servePath+"/users", iamServerCore)
	container.Add(userSrv.RestfulWebService())

	log.Info().Msg("Initializing OAuth 2.0 service...")
	oauth2Srv, err := oauth2.NewServer(servePath+"/oauth2", iamServerCore, signInURL)
	if err != nil {
		log.Fatal().Err(err).Msg("OAuth 2.0 service initialization")
	}
	container.Add(oauth2Srv.RestfulWebService())
}

func processSwaggerSpec(swaggerSpec *spec.Swagger, appInfo app.Info, secDefs spec.SecurityDefinitions) {
	buildInfo := app.GetBuildInfo()
	rev := buildInfo.RevisionID
	if rev != "unknown" && len(rev) > 7 {
		rev = rev[:7]
	}
	swaggerSpec.Info = &spec.Info{
		InfoProps: spec.InfoProps{
			Title:       "IAM",
			Description: "Identity and Access Management service REST API",
			Version:     fmt.Sprintf("0.0.0-%s built at %s", rev, buildInfo.Timestamp),
		},
	}
	for k := range swaggerSpec.Paths.Paths {
		swaggerSpec.Paths.Paths[k] = processOpenAPIPath(swaggerSpec.Paths.Paths[k], secDefs)
	}
	swaggerSpec.SecurityDefinitions = secDefs
}

func processOpenAPIPath(pathItem spec.PathItem, secDefs spec.SecurityDefinitions) spec.PathItem {
	pathItem.Get = processOpenAPIPathOp(pathItem.Get, secDefs)
	pathItem.Put = processOpenAPIPathOp(pathItem.Put, secDefs)
	pathItem.Post = processOpenAPIPathOp(pathItem.Post, secDefs)
	pathItem.Delete = processOpenAPIPathOp(pathItem.Delete, secDefs)
	pathItem.Options = processOpenAPIPathOp(pathItem.Options, secDefs)
	pathItem.Head = processOpenAPIPathOp(pathItem.Head, secDefs)
	pathItem.Patch = processOpenAPIPathOp(pathItem.Patch, secDefs)
	return pathItem
}

func processOpenAPIPathOp(op *spec.Operation, secDefs spec.SecurityDefinitions) *spec.Operation {
	if op == nil {
		return nil
	}

	for _, tag := range op.Tags {
		if tag == "hidden" {
			return nil
		}
	}

	var updatedParams []spec.Parameter
	for _, p := range op.Parameters {
		isSec := false
		if p.Description != "" {
			lowerDesc := strings.ToLower(p.Description)
			for k, secDef := range secDefs {
				if strings.HasPrefix(lowerDesc, k) {
					if secDef.Type == "basic" {
						// Basic authorization is always as 'Authorization' in the header
						if p.Name == "Authorization" && p.In == "header" {
							op.Security = append(op.Security, map[string][]string{k: {}})
							isSec = true
							continue
						}
					}
					if secDef.Type == "apiKey" {
						if p.Name == secDef.Name && p.In == secDef.In {
							op.Security = append(op.Security, map[string][]string{k: {}})
							isSec = true
							continue
						}
					}
				}
			}
		}
		if !isSec {
			updatedParams = append(updatedParams, p)
		}
	}
	op.Parameters = updatedParams
	return op
}
