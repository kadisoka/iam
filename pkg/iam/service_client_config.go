package iam

import (
	"github.com/rez-go/stev"
)

type ServiceClientCredentials struct {
	ClientID     string `env:",required"`
	ClientSecret string
}

type ServiceClientConfig struct {
	ServerBaseURL string                   `env:",required"`
	Credentials   ServiceClientCredentials `env:",squash"`
}

func ServiceClientConfigFromEnv(
	prefix string, def *ServiceClientConfig,
) (*ServiceClientConfig, error) {
	if def == nil {
		def = &ServiceClientConfig{}
	}
	err := stev.LoadEnv(prefix, def)
	if err != nil {
		return nil, err
	}
	return def, nil
}
