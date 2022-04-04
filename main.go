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
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	utils "github.com/david-liu-950627/readmoo-dl-go/utils"
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
	Links []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	}
}

type Config struct {
	AccessToken   string          `json:"accessToken"`
	UDID          string          `json:"udid"`
	PrivateKeyStr string          `json:"privateKey"`
	PrivateKey    *rsa.PrivateKey `json:"-"`
	PublicKeyStr  string          `json:"publicKey"`
}

type Encryption struct {
	EncryptedData []struct {
		CipherData struct {
			CipherReference struct {
				URI string `xml:"URI,attr"`
			} `xml:"CipherReference"`
		} `xml:"CipherData"`
		EncryptionProperties struct {
			EncryptionProperty struct {
				Compression struct {
					Method string `xml:"Method,attr"`
				} `xml:"Compression"`
			} `xml:"EncryptionProperty"`
		} `xml:"EncryptionProperties"`
	} `xml:"EncryptedData"`
}

func main() {
	// load configurations
	config := loadOrCreateConfig()
	// downloadBook("210102339000101", config)
	storeConfig(config)
}

func storeConfig(config *Config) {
	configJson, err := json.MarshalIndent(config, "", "\t")
	handleError(err)
	os.WriteFile("config.json", configJson, 0644)
}

func downloadBook(bookId string, config *Config) {
	workdir := fmt.Sprintf("tmp/%s/", bookId)
	os.Mkdir(workdir, 0755)

	// Fetch the license doucment of book
	fmt.Print("Fetching the license document... ")
	lcpl := loadLCPL(bookId, config)
	contentKey := getContentKey(lcpl, config.PrivateKey)
	fmt.Println("Done.")

	fmt.Print("Downloading the book epub file... ")
	encryptedEpubPath := workdir + "encrypted.epub"
	epubUrl := getEPUBUrl(lcpl)
	epubFile, err := get(epubUrl, map[string]string{}, config)
	handleError(err)
	os.WriteFile(encryptedEpubPath, epubFile, 0644)
	fmt.Println("Done.")

	fmt.Print("Uncompressing the book epub file... ")
	uncompressedPath := workdir + "uncompressed/"
	utils.UnzipSource(encryptedEpubPath, uncompressedPath)
	fmt.Println("Done.")

	fmt.Print("Decrypting the book epub file... ")
	encryptionXMLPath := workdir + "uncompressed/META-INF/encryption.xml"
	encryption := parseEncryptionXML(encryptionXMLPath)
	decryptFilesInEncryption(encryption, contentKey, uncompressedPath)
	os.Remove(encryptionXMLPath)
	fmt.Println("Done.")

	outputFilePath := fmt.Sprintf("outputs/%s.epub", bookId)
	fmt.Printf("Outputing the book epub file to %s... ", outputFilePath)
	utils.ZipSource(uncompressedPath, outputFilePath)
	fmt.Println("Done.")

	fmt.Print("Clean up tmp files... ")
	os.RemoveAll(workdir)
	fmt.Println("Done.")
}

func getEPUBUrl(lcpl *LicenseDocument) string {
	for _, link := range lcpl.Links {
		if link.Rel == "publication" {
			return link.Href
		}
	}
	return ""
}

func decryptFilesInEncryption(encryption *Encryption, contentKey []byte, workdir string) {
	for _, data := range encryption.EncryptedData {
		filePath := workdir + data.CipherData.CipherReference.URI
		isCompressed := data.EncryptionProperties.EncryptionProperty.Compression.Method != "0"
		undecryptedContent, err := os.ReadFile(filePath)
		handleError(err)
		decrypedFile := decryptContent(undecryptedContent, contentKey)
		if isCompressed {
			buffer := bytes.NewBuffer([]byte{})
			reader := flate.NewReader(bytes.NewReader(decrypedFile))
			_, err = buffer.ReadFrom(reader)
			handleError(err)
			decrypedFile = buffer.Bytes()
		}
		err = os.WriteFile(filePath, decrypedFile, 0644)
		handleError(err)
	}
}

func parseEncryptionXML(xmlPath string) *Encryption {
	_, err := os.Stat(xmlPath)
	handleError(err)

	xmlBytes, err := os.ReadFile(xmlPath)
	handleError(err)

	var encryption Encryption
	xml.Unmarshal(xmlBytes, &encryption)

	return &encryption
}

func keyCheck(lcpl LicenseDocument, privateKey *rsa.PrivateKey) error {
	keyCheck := lcpl.Encryption.UserKey.KeyCheck
	keyBytes, _ := base64.StdEncoding.DecodeString(keyCheck)
	plainBytes, _ := rsa.DecryptPKCS1v15(nil, privateKey, keyBytes)
	resultId := base64.URLEncoding.EncodeToString(plainBytes)

	if len(lcpl.Id) == 0 || len(resultId) == 0 || lcpl.Id != resultId {
		return errors.New("Invalid private key, re-login may solve this.")
	}

	return nil
}

func getContentKey(lcpl *LicenseDocument, privateKey *rsa.PrivateKey) []byte {
	encryptedKey := lcpl.Encryption.ContentKey.EncryptedValue
	encryptedKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedKey)
	keyBytes, _ := rsa.DecryptPKCS1v15(nil, privateKey, encryptedKeyBytes)

	return keyBytes
}

func decryptContent(rawFile, contentKey []byte) []byte {
	aesIV, rawFile := rawFile[:16], rawFile[16:]
	aesBlock, _ := aes.NewCipher(contentKey)
	mode := cipher.NewCBCDecrypter(aesBlock, aesIV)
	mode.CryptBlocks(rawFile, rawFile)

	return rawFile
}

func loadOrCreateConfig() *Config {
	configPath := "config.json"
	var config Config

	if _, err := os.Stat(configPath); err == nil {
		// load json config
		configBytes, err := os.ReadFile(configPath)
		handleError(err)
		err = json.Unmarshal(configBytes, &config)
		handleError(err)

		// parse private key
		block, _ := pem.Decode([]byte(config.PrivateKeyStr))
		if block == nil {
			handleError(errors.New("No private key is found"))
		}
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		handleError(err)
		config.PrivateKey = privateKey

		return &config
	} else if errors.Is(err, os.ErrNotExist) {
		handleError(errors.New("Not implement if config.json is missing"))
	} else {
		handleError(err)
	}

	return nil
}

func loadLCPL(bookId string, config *Config) *LicenseDocument {
	var lcpl LicenseDocument
	url := fmt.Sprintf("https://api.readmoo.com/lcpl/%s", bookId)
	headers := map[string]string{"Content-Type": "application/vnd.api+json"}
	jsonBytes, err := get(url, headers, config)
	handleError(err)

	err = json.Unmarshal(jsonBytes, &lcpl)
	handleError(err)

	err = keyCheck(lcpl, config.PrivateKey)
	handleError(err)

	return &lcpl
}

func get(url string, headers map[string]string, config *Config) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Readmoo/271 CFNetwork/1331.0.7 Darwin/21.4.0")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.AccessToken))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// make a request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if int(resp.StatusCode/100) != 2 {
		return nil, errors.New(fmt.Sprintf("Unexpected response status code: %v", resp.StatusCode))
	}

	// read body into buffer
	buffer := bytes.NewBuffer([]byte{})
	buffer.ReadFrom(resp.Body)

	return buffer.Bytes(), nil
}

func handleError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
