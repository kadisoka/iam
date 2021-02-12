package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kadisoka/foundation/pkg/app"
	"github.com/kadisoka/foundation/pkg/webui"
	_ "github.com/lib/pq"

	"github.com/kadisoka/iam/pkg/iam/logging"
	"github.com/kadisoka/iam/pkg/iamserver"
	srvapp "github.com/kadisoka/iam/pkg/iamserver/app"
	srvgrpc "github.com/kadisoka/iam/pkg/iamserver/grpc"
	srvrest "github.com/kadisoka/iam/pkg/iamserver/rest"
	srvwebui "github.com/kadisoka/iam/pkg/iamserver/webui"
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

	// to detect that all services are ready
	go func() {
		for {
			time.Sleep(200 * time.Millisecond)
			if srvApp.IsAllServersAcceptingClients() {
				log.Info().Msg("Services are ready")
				break
			}
		}
	}()

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
			ServePort:          9080,
			SwaggerUIAssetsDir: "resources/swagger-ui",
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
