package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
)

// A SignedIdentifier contains a message, its signature, and a public key that may be used to verify the signature.
type SignedIdentifier struct {
	// original string provided as user input
	Message string `json:"message"`

	// RFC 4648 compliant Base64 encoded cryptographic signature of the input, calculated using the private key and the
	// SHA256 digest of the input
	Signature string `json:"signature"`

	// Base64 encoded string (PEM format) of the public key generated from the private key used to create the digital
	// signature
	Pubkey string `json:"pubkey"`
}

// SignInput generates a signature using the provided RSA key and the SHA256 digest of the input.
func SignInput(input string, privateKey *rsa.PrivateKey) SignedIdentifier {
	h := crypto.SHA256.New()
	h.Write([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h.Sum(nil))
	if err != nil {
		log.Fatalf("unable to sign message: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	return SignedIdentifier{
		Message:   input,
		Signature: base64.StdEncoding.EncodeToString(sig),
		Pubkey:    string(pemBytes),
	}
}
