package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	genKeys := flag.Bool("g", false, "Generate RSA keys")
	encrypt := flag.String("e", "", "Public key file name")
	decrypt := flag.String("d", "", "Private key file name")
	input := flag.String("i", "", "Input file name")
	output := flag.String("o", "", "Output file name")

	flag.Parse()

	// generate private and public key pair
	if *genKeys {
		if err := GenerateKeyPair(2048); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	// Encrypt file or stdin
	if *encrypt != "" {
		encryptedBytes, err := encryptData(*encrypt, *input)
		if err != nil {
			log.Fatal(err.Error())
		}
		// write encryptedBytes to output file, or print to stdout as HEX
		if *output != "" {
			if err := os.WriteFile(*output, encryptedBytes, 0644); err != nil {
				log.Fatal(err.Error())
			}
		} else {
			fmt.Printf("%x", encryptedBytes)
		}
		return
	}

	// Decrypt file or stdin
	if *decrypt != "" {
		decryptedBytes, err := decryptData(*decrypt, *input)
		if err != nil {
			log.Fatal(err.Error())
		}
		// write decryptedBytes to output file, or print to stdout
		if *output != "" {
			if err := os.WriteFile(*output, decryptedBytes, 0644); err != nil {
				log.Fatal(err.Error())
			}
		} else {
			fmt.Print(string(decryptedBytes))
		}
		return
	}

	// Print usage
	flag.PrintDefaults()
}
