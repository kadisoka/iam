package main

import (
	"fmt"
	"os"

	"github.com/citadelium/foundation/pkg/app"
	"github.com/citadelium/foundation/pkg/webui"
	_ "github.com/lib/pq"

	"github.com/citadelium/iam/pkg/iam/logging"
	"github.com/citadelium/iam/pkg/iamserver"
	srvapp "github.com/citadelium/iam/pkg/iamserver/app"
	srvgrpc "github.com/citadelium/iam/pkg/iamserver/grpc"
	srvrest "github.com/citadelium/iam/pkg/iamserver/rest"
	srvwebui "github.com/citadelium/iam/pkg/iamserver/webui"
)

var log = logging.NewPkgLogger()

var (
	revisionID     = "unknown"
	buildTimestamp = "unknown"
)

func main() {
	fmt.Fprintf(os.Stderr, "IAM Server revision %v built at %v\n",
		revisionID, buildTimestamp)
	app.SetBuildInfo(revisionID, buildTimestamp)

	srvApp, err := initApp()
	if err != nil {
		log.Fatal().Err(err).Msg("Servers initialization")
	}

	srvApp.Run()
}

func initApp() (app.App, error) {
	envPrefix := "IAM_"

	cfg := srvapp.Config{
		Core: iamserver.CoreConfigSkeleton(),
		// Web UI
		WebUIEnabled: true,
		WebUI: &srvwebui.ServerConfig{
			Server: webui.ServerConfig{
				ServePort: 8080,
			},
		},
		// REST API
		RESTEnabled: true,
		REST: &srvrest.ServerConfig{
			ServePort:    9080,
			SwaggerUIDir: "resources/swagger-ui",
		},
		// gRPC API
		GRPCEnabled: false,
		GRPC: &srvgrpc.ServerConfig{
			ServePort: 50051,
		},
	}

	srvApp, err := srvapp.NewByEnv(envPrefix, &cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("App initialization")
	}

	return srvApp, nil
}
