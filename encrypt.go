package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// Encrypt encrypts a message using a public key
func encryptData(pubKeyFile, inputFile string) (encryptedBytes []byte, err error) {
	var msg []byte
	if inputFile == "" {
		msg, err = readStdin()
		if err != nil {
			return nil, err
		}
	} else {
		msg, err = os.ReadFile(inputFile)
		if err != nil {
			return nil, err
		}
	}
	publicKey, err := bytesToPublicKey(pubKeyFile)
	if err != nil {
		return nil, err
	}
	encryptedBytes, err = encryptWithPublicKey(msg, publicKey)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

func encryptWithPublicKey(msg []byte, pub *rsa.PublicKey) (encryptedBytes []byte, err error) {
	hash := sha512.New()
	encryptedBytes, err = rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}
	return encryptedBytes, nil
}

func bytesToPublicKey(pubKeyFile string) (publicKey *rsa.PublicKey, err error) {
	pubKeyBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pubKeyBytes)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}
	return key, nil
}
