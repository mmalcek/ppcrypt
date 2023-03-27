package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

// Generate private and public key pair
func GenerateKeyPair(bits int) error {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	if err := PrivateKeyToFile(privkey); err != nil {
		return err
	}
	if err := PublicKeyToBytes(&privkey.PublicKey); err != nil {
		return err
	}
	return nil
}

func PrivateKeyToFile(priv *rsa.PrivateKey) error {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	if err := os.WriteFile("private.pem", privBytes, 0644); err != nil {
		return err
	}
	return nil
}

func PublicKeyToBytes(pub *rsa.PublicKey) error {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})
	if err := os.WriteFile("public.pem", pubBytes, 0644); err != nil {
		return err
	}
	return nil
}
