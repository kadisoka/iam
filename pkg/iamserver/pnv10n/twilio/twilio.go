package twilio

import (
	"errors"

	"github.com/citadelium/iam/pkg/iamserver/pnv10n"
)

const ServiceName = "twilio"

func init() {
	pnv10n.RegisterModule(
		ServiceName,
		pnv10n.Module{
			ConfigSkeleton:        func() interface{} { cfg := ConfigSkeleton(); return &cfg },
			NewSMSDeliveryService: NewSMSDeliveryService,
		})
}

type SMSDeliveryService struct {
	config      *Config
	endpointURL string
}

var _ pnv10n.SMSDeliveryService = &SMSDeliveryService{}

const apiBaseURL = "https://api.twilio.com/2010-04-01/Accounts"

func NewSMSDeliveryService(config interface{}) pnv10n.SMSDeliveryService {
	if config == nil {
		panic(errors.New("configuration required"))
	}
	conf, ok := config.(*Config)
	if !ok {
		panic(errors.New("configuration of invalid type"))
	}

	if conf.AccountSID == "" {
		panic("Twilio Account SID not found")
	}
	if conf.AuthToken == "" {
		panic("Unable to find twilio auth token")
	}

	return &SMSDeliveryService{
		config:      conf,
		endpointURL: apiBaseURL + "/%s/Messages.json"}
}
