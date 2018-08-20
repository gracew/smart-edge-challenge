package signature

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"
)

func TestEncodeAndDecode(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fail()
	}

	file1 := tempFile(t)
	defer file1.Close()
	file2 := tempFile(t)
	defer file2.Close()

	encoding1 := encodeAndReturnBytes(t, key, file1.Name())
	decoded := decodeKey(file1.Name())
	encoding2 := encodeAndReturnBytes(t, decoded, file2.Name())

	if string(encoding1) != string(encoding2) {
		t.Fail()
	}
}

func TestGetKeyIsIdempotent(t *testing.T) {
	key1 := GetKey()
	key2 := GetKey()
	file1 := tempFile(t)
	defer file1.Close()
	file2 := tempFile(t)
	defer file2.Close()

	encoding1 := encodeAndReturnBytes(t, key1, file1.Name())
	encoding2 := encodeAndReturnBytes(t, key2, file2.Name())

	if string(encoding1) != string(encoding2) {
		t.Fail()
	}
}

func tempFile(t *testing.T) *os.File {
	file, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fail()
	}
	return file
}

func encodeAndReturnBytes(t *testing.T, key *rsa.PrivateKey, filename string) []byte {
	encodeKey(key, filename)
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fail()
	}
	return bytes
}
