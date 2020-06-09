package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/citadelium/iam/pkg/iam"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Invalid number of arguments\n")
		os.Exit(-1)
	}
	clientID := iam.GenerateClientID(os.Args[1])
	clientSecret := genSecret(16)
	fmt.Fprintf(os.Stdout, "%s\n%s\n", clientID.String(), clientSecret)
}

func genSecret(len int) string {
	if len == 0 {
		len = 16
	}
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
