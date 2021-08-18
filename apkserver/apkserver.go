package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
)

var gSourceFilePath string

type ApkResponse struct {
	Key string
	Id  string
}

func BytesToPublicKey(pubPem []byte) *rsa.PublicKey {
	block, _ := pem.Decode(pubPem)
	if block == nil {
		log.Println("Failed pem Decode")
		return nil
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		log.Println("Failed ParsePKCS1PublicKey: " + err.Error())
		return nil
	}

	return pub
}

func generateUniqueFileName(ext string) string {

	uniq := generateAES256Key()
	sh := sha1.New()
	sh.Write(uniq)
	bs := sh.Sum(nil)
	h := hex.EncodeToString(bs)
	return h + ext
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("method:", r.Method)

	//read
	switch r.Method {
	case "GET":
		fmt.Fprint(w, "use POST for request")
	case "POST":
		//read pub key from header filed

		publicKey, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Fprintf(w, "Failed read body")
			return
		}

		log.Printf("public-key:%s", string(publicKey))

		rsaPublicKey := BytesToPublicKey(publicKey)
		if rsaPublicKey == nil {
			fmt.Fprintf(w, "Failed BytesToPublicKey")
			return
		}

		sourceFilePath := gSourceFilePath

		//Generate aes256 key
		aesKey := generateAES256Key()
		encodedFilePath := generateUniqueFileName("_encoded_" + path.Ext(sourceFilePath))

		ret := encryptFileCBC(sourceFilePath, encodedFilePath, aesKey)
		if ret != true {
			return
		}

		sh := sha1.New()
		aesKeyEncoded, _ := rsa.EncryptOAEP(sh, rand.Reader, rsaPublicKey, aesKey, nil)

		//Encode to base64 encoded string
		apkResponse := &ApkResponse{Key: base64.StdEncoding.EncodeToString(aesKeyEncoded), Id: encodedFilePath}

		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(apkResponse)

	default:
		fmt.Fprintf(w, "Use GET or POST")
	}
}

func generateAES256Key() []byte {
	//32 for aes256
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Println(err)
		return nil
	}
	return key
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func decryptCBC(key []byte, encryptData []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
		return nil
	}

	blockSize := aes.BlockSize

	iv := encryptData[:blockSize]
	encryptData = encryptData[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(encryptData, encryptData)
	encryptData = PKCS7UnPadding(encryptData)

	return encryptData
}

func decryptFileCBC(encodedFile string, decodedFile string, key []byte, iv []byte) {
	data, err := ioutil.ReadFile(encodedFile)
	if err != nil {
		return
	}

	decoded := decryptCBC(key, data)
	if decoded == nil {
		return
	}

	err = ioutil.WriteFile(decodedFile, decoded, 777)
	if err != nil {
		log.Println(err)
		return
	}
}

func encryptCBC(key []byte, rawData []byte) []byte {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	blockSize := aes.BlockSize
	rawData = PKCS7Padding(rawData, blockSize)

	ciphertext := make([]byte, blockSize+len(rawData))
	iv := ciphertext[:blockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}

	mode := cipher.NewCBCEncrypter(b, iv)
	mode.CryptBlocks(ciphertext[blockSize:], rawData)
	return ciphertext
}

func encryptFileCBC(sourceFile string, targetFile string, key []byte) bool {
	//Read data from file
	data, err := ioutil.ReadFile(sourceFile)
	if err != nil {
		log.Println(err)
		return false
	}
	log.Println("[OK] ReadFile")

	enc := encryptCBC(key, data)

	if enc == nil {
		log.Println("[FAILED] encryptCBC")
		return false
	}
	log.Println("[OK] encryptCBC")

	err = ioutil.WriteFile(targetFile, enc, 777)
	if err != nil {
		log.Println(err)
		return false
	}

	log.Println("[OK] WriteFile")

	return true
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("method:", r.Method)
	keys, ok := r.URL.Query()["id"]

	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'id' is missing")
		return
	}
	id := keys[0]

	log.Printf("Request file id:'%s'", id)
	if id != "" {
		http.ServeFile(w, r, id)
	}

	os.Remove(id)
}

func main() {

	sourcePtr := flag.String("source", "", "file path to source file for encryption")
	flag.Parse()
	gSourceFilePath = *sourcePtr

	if gSourceFilePath == "" {
		log.Println("Setup source file. --source=<file_path> ")
		return
	}

	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/download", downloadHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
