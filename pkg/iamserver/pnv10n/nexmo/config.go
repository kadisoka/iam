package nexmo

type Config struct {
	APIKey    string `env:"API_KEY,required"`
	APISecret string `env:"API_SECRET,required"`
	Number    string `env:"NUMBER,required"`
}

func ConfigSkeleton() Config { return Config{} }
