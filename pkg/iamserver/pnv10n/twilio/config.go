package twilio

type Config struct {
	AccountSID string `env:"ACCOUNT_SID,required"`
	AuthToken  string `env:"AUTH_TOKEN,required"`
	Sender     string `env:"NUMBER,required"`
}

func ConfigSkeleton() Config { return Config{} }
