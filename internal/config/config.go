package config

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	ServerAddress string
	DbURL         string
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
}

func LoadConfig() (*Config, error) {
	b64PrivateKey := os.Getenv("PRIVATE_KEY")
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(b64PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(decodedPrivateKey) == 0 {
		return nil, errors.New("empty key")
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	if err != nil {
		return nil, err
	}

	b64PublicKey := os.Getenv("PUBLIC_KEY")
	decodedPublicKey, err := base64.StdEncoding.DecodeString(b64PublicKey)
	if err != nil {
		return nil, err
	}
	if len(decodedPublicKey) == 0 {
		return nil, errors.New("empty key")
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, err
	}

	config := &Config{
		ServerAddress: os.Getenv("SERVER_ADDRESS"),
		DbURL:         os.Getenv("DB_URL"),
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
	}

	return config, nil
}
