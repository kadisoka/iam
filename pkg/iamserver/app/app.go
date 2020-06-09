package app

import (
	"net/http"
	"strings"

	"github.com/citadelium/pkg/app"
	"github.com/citadelium/pkg/errors"
	"github.com/citadelium/pkg/webui"
	"github.com/rez-go/stev"

	"github.com/citadelium/iam/pkg/iam/logging"
	"github.com/citadelium/iam/pkg/iamserver"
	"github.com/citadelium/iam/pkg/iamserver/grpc"
	"github.com/citadelium/iam/pkg/iamserver/rest"
	iamwebui "github.com/citadelium/iam/pkg/iamserver/webui"
)

var log = logging.NewPkgLogger()

func NewByEnv(envPrefix string, defaultConfig *Config) (*App, error) {
	cfg := defaultConfig
	if cfg == nil {
		cfg = &Config{}
	}
	err := stev.LoadEnv(envPrefix, cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("App config loading")
	}

	resolveConfig(cfg)

	log.Info().Msg("Initializing server app...")
	srvApp, err := newWithoutServices(*cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("App initialization")
	}

	err = srvApp.initServers(*cfg)
	if err != nil {
		return nil, err
	}

	return srvApp, nil
}

func NewWithCombinedHTTPServers(cfg Config, mux *http.ServeMux) (*App, error) {
	resolveConfig(&cfg)

	srvApp, err := newWithoutServices(cfg)
	if err != nil {
		return nil, errors.Wrap("app initialization", err)
	}

	iamServerCore := srvApp.Core

	if cfg.RESTEnabled {
		log.Info().Msg("Initializing REST server...")
		restServer, err := rest.NewServer(
			*cfg.REST,
			srvApp.AppInfo(),
			iamServerCore,
			&cfg.WebUI.URLs)
		if err != nil {
			return nil, errors.Wrap("REST server initialization", err)
		}

		mux.Handle(cfg.REST.ServePath, restServer)
	}

	if cfg.WebUIEnabled {
		log.Info().Msg("Initializing web UI server...")
		webUIServer, err := setUpWebUIServer(srvApp, cfg)
		if err != nil {
			return nil, errors.Wrap("web UI server initialization", err)
		}

		mux.Handle(cfg.WebUI.Server.ServePath, webUIServer)
	}

	return srvApp, nil
}

func setUpWebUIServer(srvApp *App, cfg Config) (*webui.Server, error) {
	webUICfg := cfg.WebUI.Server

	templateData := map[string]interface{}{
		"AppInfo": srvApp.AppInfo(),
		"AppName": srvApp.AppInfo().Name,
	}
	restAPIURLReplacer := &webui.StringReplacer{
		Old: "http://localhost:11121/rest/v1",
		New: strings.TrimRight(cfg.RESTCanonicalBaseURL, "/"),
	}
	webUIServeURLReplacer := &webui.StringReplacer{
		Old: "/citadel-iam-webui-base-path/",
		New: webUICfg.ServePath,
	}
	defaultURLReplacer := &webui.StringReplacer{
		Old: "http://localhost:3000/",
		New: "/",
	}

	webUICfg.FileProcessors = map[string][]webui.FileProcessor{
		"*.html": {&webui.HTMLRenderer{
			Config: webui.HTMLRendererConfig{
				TemplateDelimBegin: "{:[",
				TemplateDelimEnd:   "]:}",
			},
			TemplateData: templateData,
		}, restAPIURLReplacer, webUIServeURLReplacer, defaultURLReplacer},
		"*.js": {&webui.JSRenderer{
			Config: webui.JSRendererConfig{
				TemplateDelimBegin: "{:[",
				TemplateDelimEnd:   "]:}",
			},
			TemplateData: templateData,
		}, restAPIURLReplacer, webUIServeURLReplacer, defaultURLReplacer},
	}

	webUIServer, err := webui.NewServer(
		webUICfg,
		templateData)
	if err != nil {
		return nil, errors.Wrap("web UI instantiation", err)
	}

	return webUIServer, nil
}

func newWithoutServices(appCfg Config) (*App, error) {
	appCore, err := app.Init(appCfg.AppInfo)
	if err != nil {
		return nil, errors.Wrap("app initialization", err)
	}

	srvCore, err := iamserver.NewCoreByConfig(appCfg.Core, appCore)
	if err != nil {
		return nil, errors.Wrap("core initialization", err)
	}

	return &App{
		App:  appCore,
		Core: srvCore,
	}, nil
}

func resolveConfig(cfg *Config) {
	if cfg.WebUI == nil {
		cfg.WebUI = &iamwebui.ServerConfig{
			Server: webui.ServerConfig{},
		}
	}
	if cfg.WebUI.Server.ServePath == "" {
		cfg.WebUI.Server.ServePath = cfg.HTTPBasePath
	}
	cfg.WebUI.Server.ServePath = strings.TrimRight(cfg.WebUI.Server.ServePath, "/") + "/"
	if cfg.WebUI.Server.FilesDir == "" {
		cfg.WebUI.Server.FilesDir = iamwebui.ResourcesDirDefault
	}
	if cfg.WebUI.URLs.Login == "" {
		cfg.WebUI.URLs.Login = cfg.WebUI.Server.ServePath + "signin"
	}

	if cfg.REST == nil {
		cfg.REST = &rest.ServerConfig{}
	}
	if cfg.REST.ServePath == "" {
		cfg.REST.ServePath = strings.TrimRight(cfg.HTTPBasePath, "/") + "/rest/"
	}
	if cfg.RESTCanonicalBaseURL == "" {
		cfg.RESTCanonicalBaseURL = cfg.REST.ServePath + rest.ServerLatestVersionString + "/"
	}
}

type App struct {
	app.App
	Core *iamserver.Core
}

func (srvApp *App) initServers(cfg Config) error {
	iamServerCore := srvApp.Core

	if cfg.RESTEnabled {
		log.Info().Msg("Initializing REST server...")
		restServer, err := rest.NewServer(
			*cfg.REST,
			srvApp.AppInfo(),
			iamServerCore,
			&cfg.WebUI.URLs)
		if err != nil {
			return errors.Wrap("REST server initialization", err)
		}

		srvApp.AddServer(restServer)
	}

	if cfg.WebUIEnabled {
		log.Info().Msg("Initializing web UI server...")
		webUIServer, err := setUpWebUIServer(srvApp, cfg)
		if err != nil {
			return errors.Wrap("web UI server initialization", err)
		}

		srvApp.AddServer(webUIServer)
	}

	if cfg.GRPCEnabled {
		log.Info().Msg("Initializing gRPC Server...")
		grpcServer, err := grpc.NewServer(
			*cfg.GRPC,
			iamServerCore)
		if err != nil {
			return errors.Wrap("gRPC server initialization", err)
		}

		srvApp.AddServer(grpcServer)
	}

	return nil

}

func ConfigSkeleton() Config {
	return Config{
		Core: iamserver.CoreConfigSkeleton(),
	}
}

func ConfigSkeletonPtr() *Config {
	cfg := ConfigSkeleton()
	return &cfg
}
