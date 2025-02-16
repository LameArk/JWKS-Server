package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Key struct {
	PublicKey  string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

var (
	keys  = make(map[string]Key)
	mutex sync.Mutex
)

func generateKeyPair() string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v", err)
	}

	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)
	pemPublicKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: publicKeyBytes})
	kid := randomKID()
	expiresAt := time.Now().Add(5 * time.Minute)

	mutex.Lock()
	keys[kid] = Key{PublicKey: string(pemPublicKey), PrivateKey: privateKey, ExpiresAt: expiresAt}
	mutex.Unlock()

	return kid
}

func randomKID() string {
	num, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		log.Fatalf("Failed to generate kid: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(num.Bytes())
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}

	for kid, key := range keys {
		if time.Now().Before(key.ExpiresAt) {
			jwks.Keys = append(jwks.Keys, map[string]string{"kid": kid, "pem": key.PublicKey})
		}
	}

	if len(jwks.Keys) == 0 {
		http.Error(w, "No valid JWKs available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"
	mutex.Lock()
	var chosenKey *Key
	var kid string
	for k, key := range keys {
		if expired || time.Now().Before(key.ExpiresAt) {
			chosenKey = &key
			kid = k
			break
		}
	}
	mutex.Unlock()

	if chosenKey == nil {
		http.Error(w, "No valid keys available", http.StatusInternalServerError)
		return
	}

	expTime := time.Now().Add(5 * time.Minute)
	if expired {
		expTime = time.Now().Add(-5 * time.Minute)
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"exp": expTime.Unix(),
	})
	token.Header["kid"] = kid

	tokenString, err := token.SignedString(chosenKey.PrivateKey)
	if err != nil {
		http.Error(w, "Failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func main() {
	generateKeyPair()
	http.HandleFunc("/jwks", jwksHandler)
	http.HandleFunc("/auth", authHandler)

	log.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
