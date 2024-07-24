package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/rs/cors"
	"golang.org/x/crypto/pbkdf2"
)

type Payload struct {
	FilePath string `json:"filePath"`
	Password string `json:"password"`
	Action   string `json:"action"`
}

func handleHello(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	var payload Payload

	err := json.NewDecoder(r.Body).Decode(&payload)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	filePath := payload.FilePath
	password := []byte(payload.Password)
	action := payload.Action

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusBadRequest)
		return
	}

	if action == "encrypt" {
		err = encryptFile(filePath, password)
	} else if action == "decrypt" {
		err = decryptFile(filePath, password)
	} else {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Error processing file", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "File processed successfully!")
}

func encryptFile(filepath string, password []byte) error {
	plainText, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	dk := pbkdf2.Key(password, nonce, 4096, 32, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	cipherText := aesgcm.Seal(nil, nonce, plainText, nil)
	cipherText = append(cipherText, nonce...)

	err = ioutil.WriteFile(filepath, cipherText, 0644)
	return err
}

func decryptFile(filepath string, password []byte) error {
	cipherText, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}

	nonce := cipherText[len(cipherText)-12:]
	cipherText = cipherText[:len(cipherText)-12]

	dk := pbkdf2.Key(password, nonce, 4096, 32, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plainText, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filepath, plainText, 0644)
	return err
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/handleFile", handleFile)
	mux.HandleFunc("/hello", handleHello)

	// Allow all origins, methods, and headers for simplicity
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})

	handler := corsHandler.Handler(mux)
	http.ListenAndServe(":8080", handler)
}
