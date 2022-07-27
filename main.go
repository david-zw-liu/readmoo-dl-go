package main

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	"net/url"
	"os"
	"sort"
	"strings"

	utils "github.com/david-liu-950627/readmoo-dl-go/utils"
	"github.com/google/uuid"
	"github.com/manifoldco/promptui"
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
	UserId        string          `json:"userId"`
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

type LoginResp struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            int    `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type MeResp struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

type DeviceReqBody struct {
	Data struct {
		Type       string `json:"type"`
		ID         string `json:"id"`
		Attributes struct {
			Info      string `json:"info"`
			UserAgent string `json:"user_agent"`
			Name      string `json:"name"`
			Key       struct {
				Name      string `json:"name"`
				Value     string `json:"value"`
				Algorithm string `json:"algorithm"`
			} `json:"key"`
			DeviceType string `json:"device_type"`
		} `json:"attributes"`
	} `json:"data"`
}

type LibrayItem struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Attributes struct {
		Title    string `json:"title"`
		Subtitle string `json:"subtitle"`
	}
}

func main() {
	// load configurations
	config := loadOrCreateConfig()
	if config.AccessToken == "" {
		LoginUser(config)
		fetchUserId(config)
		registerDevice(config)
	}

	libraryItem := pickBook(config)
	downloadLibraryItem(libraryItem, config)
	storeConfig(config)
}

func pickBook(config *Config) *LibrayItem {
	apiURL := "https://api.readmoo.com/store/v3/me/library_items?page[count]=500"
	headers := map[string]string{"Content-Type": "application/vnd.api+json"}
	jsonBytes, err := get(apiURL, headers, config)
	handleError(err)

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(jsonBytes, &objmap)
	handleError(err)

	var allLibraryItems []LibrayItem
	err = json.Unmarshal(objmap["included"], &allLibraryItems)
	handleError(err)

	bookOptions := []string{}
	libraryItemsOfBooks := map[string]LibrayItem{}
	for _, libraryItem := range allLibraryItems {
		if libraryItem.Type == "books" {
			bookName := buildBookName(&libraryItem)
			bookOptions = append(bookOptions, bookName)
			libraryItemsOfBooks[bookName] = libraryItem
		}
	}
	sort.Slice(bookOptions, func(i, j int) bool {
		libraryItem1, _ := libraryItemsOfBooks[bookOptions[i]]
		libraryItem2, _ := libraryItemsOfBooks[bookOptions[j]]

		return libraryItem1.Attributes.Title < libraryItem2.Attributes.Title
	})
	_, result, err := (&promptui.Select{
		Label: "Select a book",
		Items: bookOptions,
	}).Run()
	handleError(err)
	selectedBook, _ := libraryItemsOfBooks[result]

	return &selectedBook
}

func fetchUserId(config *Config) {
	apiURL := "https://api.readmoo.com/store/v3/me"
	headers := map[string]string{"Content-Type": "application/vnd.api+json"}
	jsonBytes, err := get(apiURL, headers, config)
	handleError(err)

	var me MeResp
	json.NewDecoder(bytes.NewBuffer(jsonBytes)).Decode(&me)
	config.UserId = me.Data.ID
}

func registerDevice(config *Config) {
	deviceReqBody := &DeviceReqBody{}
	deviceReqBody.Data.Type = "devices"
	deviceReqBody.Data.ID = config.UDID
	deviceReqBody.Data.Attributes.Info = "iPhone 13 Pro"
	deviceReqBody.Data.Attributes.UserAgent =
		fmt.Sprintf("Device UDID=%s; OS=15.4.1; Model=phone; System=iOS; Ver=6.2.1; Build=271", config.UDID)
	deviceReqBody.Data.Attributes.Name = "iPhone 13 Pro"
	deviceReqBody.Data.Attributes.Key.Name = config.UserId
	publicKeyLines := strings.Split(config.PublicKeyStr, "\n")
	publicKeyLines = publicKeyLines[1 : len(publicKeyLines)-1]
	deviceReqBody.Data.Attributes.Key.Value = strings.Join(publicKeyLines, "")
	deviceReqBody.Data.Attributes.Key.Algorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	deviceReqBody.Data.Attributes.DeviceType = "phone"

	json, _ := json.Marshal(deviceReqBody)
	hc := http.Client{}
	apiURL := fmt.Sprintf("https://api.readmoo.com/store/v3/me/devices/%s", config.UDID)
	req, err := http.NewRequest("PATCH", apiURL, bytes.NewBuffer(json))
	req.Header.Set("User-Agent", "Readmoo/271 CFNetwork/1331.0.7 Darwin/21.4.0")
	req.Header.Add("Content-Type", "application/vnd.api+json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", config.AccessToken))
	resp, err := hc.Do(req)
	handleError(err)

	if int(resp.StatusCode/100) != 2 {
		handleError(errors.New(fmt.Sprintf("Unexpected response status code: %v", resp.StatusCode)))
	}
	defer resp.Body.Close()
}

func LoginUser(config *Config) {
	username, _ := (&promptui.Prompt{
		Label: "Username",
	}).Run()
	password, _ := (&promptui.Prompt{
		Label: "Password",
		Mask:  '*',
	}).Run()

	hc := http.Client{}

	// build form
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("udid", config.UDID)
	form.Add("username", username)
	form.Add("password", password)
	form.Add("scope", "reading highlight like comment me library")

	// new request
	api_url := "https://member.readmoo.com/oauth/access_token"
	req, err := http.NewRequest("POST", api_url, strings.NewReader(form.Encode()))
	handleError(err)
	req.Header.Set("User-Agent", "Readmoo/271 CFNetwork/1331.0.7 Darwin/21.4.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic YjgxMDA1NDA3YWM2YWY0MmRmZjY4YzRiNDkyZTA3MWQ6Y2M3MWE4NGU0ZWIwMmU2YjI2MWM0MDAyODYzYTIwZjg=")

	// perform requst
	resp, err := hc.Do(req)
	handleError(err)
	if int(resp.StatusCode/100) != 2 {
		handleError(errors.New(fmt.Sprintf("Unexpected response status code: %v", resp.StatusCode)))
	}
	defer resp.Body.Close()

	var loginResp LoginResp
	json.NewDecoder(resp.Body).Decode(&loginResp)

	config.AccessToken = loginResp.AccessToken
}

func storeConfig(config *Config) {
	configJson, err := json.MarshalIndent(config, "", "\t")
	handleError(err)
	os.WriteFile("config.json", configJson, 0644)
}

func downloadLibraryItem(libraryItem *LibrayItem, config *Config) {
	workdir := fmt.Sprintf("tmp/%s/", libraryItem.ID)
	os.Mkdir(workdir, 0755)

	// Fetch the license doucment of book
	fmt.Print("Fetching the license document... ")
	lcpl := loadLCPL(libraryItem.ID, config)
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

	outputFilePath := fmt.Sprintf("outputs/%s.epub", buildBookName(libraryItem))
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
		reader := rand.Reader
		bitSize := 2048
		privateKey, err := rsa.GenerateKey(reader, bitSize)
		handleError(err)

		privateKeyBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		}
		publicKeyBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
		}

		config.PrivateKey = privateKey
		config.PrivateKeyStr = string(pem.EncodeToMemory(privateKeyBlock))
		config.PublicKeyStr = string(pem.EncodeToMemory(publicKeyBlock))
		config.UDID = strings.ToUpper(uuid.New().String())
		return &config
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

func buildBookName(libraryItem *LibrayItem) string {
	var filenameParts []string
	filenameParts = append(filenameParts, libraryItem.ID)
	filenameParts = append(filenameParts, libraryItem.Attributes.Title)
	if libraryItem.Attributes.Subtitle != "" {
		filenameParts = append(filenameParts, libraryItem.Attributes.Subtitle)
	}

	return strings.Join(filenameParts, "-")
}

func handleError(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
