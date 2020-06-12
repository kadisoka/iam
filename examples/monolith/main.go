package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/kadisoka/foundation/pkg/app"
	"github.com/kadisoka/foundation/pkg/webui"
	_ "github.com/lib/pq"
	"github.com/rez-go/stev"

	"github.com/citadelium/iam/pkg/iam/logging"
	"github.com/citadelium/iam/pkg/iamserver"
	iamapp "github.com/citadelium/iam/pkg/iamserver/app"
)

var log = logging.NewPkgLogger()

var (
	revisionID     = "unknown"
	buildTimestamp = "unknown"
)

func main() {
	fmt.Fprintf(os.Stderr, "Citadel monolith example server revision %v built at %v\n",
		revisionID, buildTimestamp)
	app.SetBuildInfo(revisionID, buildTimestamp)

	err := initApp()
	if err != nil {
		log.Fatal().Err(err).Msg("Servers initialization")
	}

	http.ListenAndServe(":8080", nil)
}

// Config is the configuration of our app. This config includes config for
// all subsystems in our application.
type Config struct {
	// All of IAM components configurations will be under namespace 'IAM' (i.e., prefixed with 'IAM_')
	IAM   iamapp.Config      `env:"IAM"`
	WebUI webui.ServerConfig `env:"WEBUI"`
}

func initApp() error {
	curDir, err := os.Getwd()
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	appInfo := app.DefaultInfo()
	appInfo.Name = "monolith"

	cfg := Config{
		WebUI: webui.ServerConfig{
			ServePath: "/",
			FilesDir:  filepath.Join(curDir, "resources", "monolith-webui"),
		},
		IAM: iamapp.Config{
			AppInfo: &appInfo,
			Core:    iamserver.CoreConfigSkeleton(),
			// Serve HTTP services under /accounts
			HTTPBasePath: "/accounts",
			// Web UI
			WebUIEnabled: true,
			// REST API
			RESTEnabled: true,
		},
	}

	err = stev.LoadEnv("", &cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Config loading")
	}

	mux := http.DefaultServeMux

	// Init IAM core but don't let it init the services. We'll init
	// the services in our application.
	_, err = iamapp.NewWithCombinedHTTPServers(cfg.IAM, mux)
	if err != nil {
		log.Fatal().Err(err).Msg("IAM initialization")
	}

	webUIServer, err := webui.NewServer(
		cfg.WebUI,
		map[string]interface{}{})
	if err != nil {
		log.Fatal().Err(err).Msg("Web UI initialization")
	}
	mux.Handle("/", webUIServer)

	return nil
}
