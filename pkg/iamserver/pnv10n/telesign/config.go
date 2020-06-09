package telesign

type Config struct {
	CustomerID string `env:"CUSTOMER_ID,required"`
	APIKey     string `env:"API_KEY,required"`
}

func ConfigSkeleton() Config { return Config{} }
