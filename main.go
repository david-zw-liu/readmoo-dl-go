package main

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

// Licensed Content Protection LicenseDocument
type LicenseDocument struct {
	Id         string `json:"id"`
	Encryption struct {
		ContentKey struct {
			EncryptedValue string `json:"encrypted_value"`
		} `json:"content_key"`
		UserKey struct {
			KeyCheck string `json:"key_check"`
		} `json:"user_key"`
	} `json:"encryption"`
}

func main() {
	privateKeyBytes, _ := os.ReadFile("private.pem")
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	// handle LCPL
	var lcpl LicenseDocument
	lcplJSON, _ := os.ReadFile("lcpl.json")
	json.Unmarshal([]byte(lcplJSON), &lcpl)
	fmt.Println("Test key check", testUserKey(lcpl, privateKey))
	fmt.Println()

	// try handling item/image/p155.jpg
	contentKey := getContentKey(lcpl, privateKey)
	rawFile, _ := os.ReadFile("tmp/item/style/style-reset.css")
	rawFile = decryptContent(contentKey, rawFile)

	r := flate.NewReader(bytes.NewReader(rawFile))
	io.Copy(os.Stdout, r)
	r.Close()
}

func testUserKey(lcpl LicenseDocument, privateKey *rsa.PrivateKey) bool {
	keyCheck := lcpl.Encryption.UserKey.KeyCheck
	keyBytes, _ := base64.StdEncoding.DecodeString(keyCheck)
	plainBytes, _ := rsa.DecryptPKCS1v15(nil, privateKey, keyBytes)
	resultId := base64.URLEncoding.EncodeToString(plainBytes)

	return lcpl.Id == resultId
}

func getContentKey(lcpl LicenseDocument, privateKey *rsa.PrivateKey) []byte {
	encryptedKey := lcpl.Encryption.ContentKey.EncryptedValue
	encryptedKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedKey)
	keyBytes, _ := rsa.DecryptPKCS1v15(nil, privateKey, encryptedKeyBytes)

	return keyBytes
}

func decryptContent(contentKey []byte, rawFile []byte) []byte {
	aesIV, rawFile := rawFile[:16], rawFile[16:]
	aesBlock, _ := aes.NewCipher(contentKey)
	mode := cipher.NewCBCDecrypter(aesBlock, aesIV)
	mode.CryptBlocks(rawFile, rawFile)

	return rawFile
}
