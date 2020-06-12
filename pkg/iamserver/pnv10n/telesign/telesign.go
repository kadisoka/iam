package telesign

import (
	"errors"

	"github.com/kadisoka/iam/pkg/iamserver/pnv10n"
)

const ServiceName = "telesign"

func init() {
	pnv10n.RegisterModule(
		ServiceName,
		pnv10n.Module{
			ConfigSkeleton:        func() interface{} { cfg := ConfigSkeleton(); return &cfg },
			NewSMSDeliveryService: NewSMSDeliveryService,
		})
}

type SMSDeliveryService struct {
	config *Config
}

var _ pnv10n.SMSDeliveryService = &SMSDeliveryService{}

const apiBaseURL = "https://rest-api.telesign.com/v1"

func NewSMSDeliveryService(config interface{}) pnv10n.SMSDeliveryService {
	if config == nil {
		panic(errors.New("configuration required"))
	}
	conf, ok := config.(*Config)
	if !ok {
		panic(errors.New("configuration of invalid type"))
	}

	if len(conf.APIKey) <= 0 {
		panic("Telesign API Key not provided")
	}
	if len(conf.CustomerID) <= 0 {
		panic("Telesign Customer ID not provided")
	}

	return &SMSDeliveryService{
		config: conf}
}
