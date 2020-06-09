package pnv10n

type SMSDeliveryService interface {
	SendTextMessage(recipientPhoneNumber, text string) error
}

type smsDeliveryServiceNULL struct {
}

func (smsDS smsDeliveryServiceNULL) SendTextMessage(recipient, text string) error {
	return nil
}

func init() {
	type smsDeliveryServiceNULLConfig struct{}

	RegisterModule(
		"null",
		Module{
			ConfigSkeleton: func() interface{} {
				return &smsDeliveryServiceNULLConfig{}
			},
			NewSMSDeliveryService: func(config interface{}) SMSDeliveryService {
				return &smsDeliveryServiceNULL{}
			},
		})
}
