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
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

type tHeader struct {
	AESKey    []byte `json:"aes_key"`
	IV        []byte `json:"iv"`
	TimeStamp int64  `json:"time_stamp"`
}

// Encrypt encrypts a message using a public key
func encryptData(pubKeyFile, inputFile, outputFile string) error {
	infile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer infile.Close()

	// Random 32 byte key for AES encryption
	AESKey := make([]byte, 32)
	if _, err := rand.Read(AESKey); err != nil {
		return err
	}

	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}

	outfile, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer outfile.Close()

	publicKey, err := bytesToPublicKey(pubKeyFile)
	if err != nil {
		return err
	}
	encryptedAESKey, err := encryptWithPublicKey(AESKey, publicKey)
	if err != nil {
		return err
	}
	encryptedIV, err := encryptWithPublicKey(iv, publicKey)
	if err != nil {
		return err
	}

	header := tHeader{AESKey: encryptedAESKey, IV: encryptedIV, TimeStamp: time.Now().Unix()}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	headerBytes = []byte(base64.StdEncoding.EncodeToString(headerBytes))
	// Write header
	outfile.Write([]byte("mme"))
	outfile.Write(headerBytes)
	outfile.Write([]byte{0})

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
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
