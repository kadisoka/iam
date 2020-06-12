package app

import (
	"github.com/kadisoka/foundation/pkg/app"

	"github.com/kadisoka/iam/pkg/iamserver"
	"github.com/kadisoka/iam/pkg/iamserver/grpc"
	"github.com/kadisoka/iam/pkg/iamserver/rest"
	"github.com/kadisoka/iam/pkg/iamserver/webui"
)

type Config struct {
	AppInfo *app.Info            `env:"APP"`
	Core    iamserver.CoreConfig `env:",squash"`

	HTTPBasePath         string `env:"HTTP_BASE_PATH"`
	RESTCanonicalBaseURL string `env:"REST_CANONICAL_BASE_URL"`

	WebUIEnabled bool                `env:"WEBUI_ENABLED"`
	WebUI        *webui.ServerConfig `env:"WEBUI"`
	RESTEnabled  bool                `env:"REST_ENABLED"`
	REST         *rest.ServerConfig  `env:"REST"`
	GRPCEnabled  bool                `env:"GRPC_ENABLED"`
	GRPC         *grpc.ServerConfig  `env:"GRPC"`
}
