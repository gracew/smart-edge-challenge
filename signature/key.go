package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const privateKeyFilename = "private.pem"

// GetKey generates a RSA private key if a previous one cannot be found. Otherwise, returns the previously generated
// key.
func GetKey() *rsa.PrivateKey {
	exe, err := os.Executable()
	if err != nil {
		log.Panicf("could not determine path of executable: %v", err)
	}
	exeDir := filepath.Dir(exe)
	keyFilepath := filepath.Join(exeDir, "var", "data", privateKeyFilename)
	if _, err := os.Stat(keyFilepath); os.IsNotExist(err) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Panicf("could not generate RSA key: %v", err)
		}
		encodeKey(key, keyFilepath)
		return key
	}
	return decodeKey(keyFilepath)
}

// Encodes the specified RSA key in PEM format and writes it to the specified filename. If the file already exists, it
// is overwritten.
func encodeKey(key *rsa.PrivateKey, filename string) {
	err := os.MkdirAll(filepath.Dir(filename), os.ModePerm)
	if err != nil {
		log.Panicf("could not make parent directories for file %s: %v", filename, err)
	}
	pemfile, err := os.Create(filename)
	if err != nil {
		log.Panicf("could not create file %s: %v", filename, err)
	}
	defer pemfile.Close()

	err = pem.Encode(pemfile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		log.Panicf("could not write key to file %s: %v", filename, err)
	}
}

// Decodes an RSA key, expected to be in PEM format, from the specified filename.
func decodeKey(filename string) *rsa.PrivateKey {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Panicf("could not read file %s: %v", filename, err)
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panicf("could not parse key: %v", err)
	}
	return key
}
