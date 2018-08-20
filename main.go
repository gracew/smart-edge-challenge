package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gracew/smart-edge-challenge/signature"
)

// Accepts a string input of up to 250 characters and generates a signature using the SHA256 digest of the input. Prints
// the original input, the signature, and a public key that may be used to verify the signature. The function will
// terminate if a string longer than 250 characters is provided.
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Program requires one argument.")
		os.Exit(0)
	}

	input := os.Args[1]
	if len(input) > 250 {
		fmt.Println("Input must be less than 250 characters long.")
		os.Exit(0)
	}

	signed := signature.SignInput(input, signature.GetKey())
	jsonBytes, err := json.Marshal(signed)
	if err != nil {
		log.Fatalf("unable to marshal json represention of SignedIdentifier: %v", err)
	}
	fmt.Println(string(jsonBytes))
}
