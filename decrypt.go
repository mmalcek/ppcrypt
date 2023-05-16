package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"os"
)

func decryptData(privKeyFile, inputFile, outputFile string) error {
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	header, err := parseHeader(infile)
	if err != nil {
		return err
	}

	privateKey, err := BytesToPrivateKey(privKeyFile)
	if err != nil {
		return err
	}

	decryptedAESKey, err := decryptWithPrivateKey(header.AESKey, privateKey)
	if err != nil {
		return err
	}

	decryptedIV, err := decryptWithPrivateKey(header.IV, privateKey)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(decryptedAESKey)
	if err != nil {
		log.Panic(err)
	}

	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		log.Fatal(err)
	}
	defer outfile.Close()

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, decryptedIV)
	for {
		n, err := infile.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
	return nil
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

func parseHeader(infile *os.File) (header tHeader, err error) {
	marker := make([]byte, 3)
	if _, err := io.ReadFull(infile, marker); err != nil {
		return header, err
	}
	if string(marker) != "mme" {
		return header, errors.New("invalid file format")
	}
	headerBytes := make([]byte, 0)

	for {
		b := make([]byte, 1)
		if _, err := io.ReadFull(infile, b); err != nil {
			return header, err
		}
		if b[0] == 0x00 { // null byte - end of header section
			break
		}
		headerBytes = append(headerBytes, b[0])
	}
	headerBase64, err := base64.StdEncoding.DecodeString(string(headerBytes))
	if err != nil {
		return header, err
	}
	if err := json.Unmarshal(headerBase64, &header); err != nil {
		return header, err
	}
	return header, nil
}
