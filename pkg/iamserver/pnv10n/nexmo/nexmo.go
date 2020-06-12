package nexmo

import (
	"errors"

	"github.com/kadisoka/iam/pkg/iamserver/pnv10n"
)

const ServiceName = "nexmo"

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

const apiBaseURL = "https://rest.nexmo.com/sms"

func NewSMSDeliveryService(config interface{}) pnv10n.SMSDeliveryService {
	if config == nil {
		panic(errors.New("configuration required"))
	}
	conf, ok := config.(*Config)
	if !ok {
		panic(errors.New("configuration of invalid type"))
	}

	if conf.APIKey == "" {
		panic("NEXMO API Key not provided")
	}
	if conf.APISecret == "" {
		panic("NEXMO API Secret not provided")
	}

	return &SMSDeliveryService{config: conf}
}
