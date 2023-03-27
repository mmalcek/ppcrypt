package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
)

func decryptData(privKeyFile, inputFile string) (decryptedBytes []byte, err error) {
	var msg []byte
	if inputFile == "" {
		if msg, err = readStdin(); err != nil {
			return nil, err
		}
		if msg, err = hex.DecodeString(string(msg)); err != nil {
			return nil, err
		}
	} else {
		msg, err = os.ReadFile(inputFile)
		if err != nil {
			return nil, err
		}
	}
	privateKey, err := BytesToPrivateKey(privKeyFile)
	if err != nil {
		return nil, err
	}
	decryptedBytes, err = decryptWithPrivateKey(msg, privateKey)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func decryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) (decryptedBytes []byte, err error) {
	hash := sha512.New()
	decryptedBytes, err = rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return decryptedBytes, nil
}

func BytesToPrivateKey(privKeyFile string) (privateKey *rsa.PrivateKey, err error) {
	privKeyBytes, err := os.ReadFile(privKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(privKeyBytes)
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	if enc {
		log.Println("is encrypted pem block")
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
