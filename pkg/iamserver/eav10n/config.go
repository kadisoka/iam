package eav10n

import (
	"path/filepath"
	"reflect"
	"time"

	"github.com/citadelium/foundation/pkg/errors"
	"github.com/rez-go/stev"
)

var ResourcesDirDefault string

func init() {
	type t int
	pkgPath := reflect.TypeOf(t(0)).PkgPath()
	ResourcesDirDefault = filepath.Join(pkgPath, "resources")
}

type Config struct {
	CodeTTLDefault          time.Duration `env:"CODE_TTL_DEFAULT"`
	ConfirmationAttemptsMax int16         `env:"CONFIRMATION_ATTEMPTS_MAX"`
	SenderAddress           string        `env:"SENDER_ADDRESS"`
	ResourcesDir            string        `env:"RESOURCES_DIR"`
	SES                     *SESConfig    `env:"SES"`
}

func ConfigFromEnv(prefix string) (*Config, error) {
	var cfg Config
	err := stev.LoadEnv(prefix, &cfg)
	if err != nil {
		return nil, errors.Wrap("config loading from environment variables", err)
	}
	return &cfg, nil
}

//TODO: make module system like pnv10n
type SESConfig struct {
	Region          string `env:"REGION,required"`
	AccessKeyID     string `env:"ACCESS_KEY_ID"`
	SecretAccessKey string `env:"SECRET_ACCESS_KEY"`
}
