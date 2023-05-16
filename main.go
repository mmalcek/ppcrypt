package main

import (
	"flag"
	"fmt"
	"log"
)

func main() {
	genKeys := flag.Bool("g", false, "Generate RSA keys")
	encrypt := flag.String("e", "", "Encrypt - Public key file name")
	decrypt := flag.String("d", "", "Decrypt - Private key file name")
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

	if *input == "" || *output == "" {
		fmt.Println("Input and Output file must be specified")
		flag.PrintDefaults()
		return
	}

	// Encrypt file
	if *encrypt != "" {
		if err := encryptData(*encrypt, *input, *output); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	// Decrypt file
	if *decrypt != "" {
		if err := decryptData(*decrypt, *input, *output); err != nil {
			log.Fatal(err.Error())
		}
		return
	}

	// Print usage
	fmt.Println("Action must be specified")
	flag.PrintDefaults()
}
