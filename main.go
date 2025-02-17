package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Key struct
type Key struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	ExpiresAt  time.Time
}

var (
	keys               = make(map[string]Key)
	mutex              sync.RWMutex
	keyRefreshInterval = 10 * time.Second // ONLY FOR TESTING
)

// Key pair generation function
func generateKeyPair() (string, *rsa.PrivateKey, *rsa.PublicKey, time.Time, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, nil, time.Time{}, err
	}
	publicKey := &privateKey.PublicKey
	kid := randomKID()
	expiresAt := time.Now().Add(keyRefreshInterval * 2)

	return kid, privateKey, publicKey, expiresAt, nil
}

// Random KID function
func randomKID() string {
	num, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		log.Println("Failed to generate kid:", err)
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	return base64.RawURLEncoding.EncodeToString(num.Bytes())
}

// JWKS handling function
func jwksHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("JWKS Request START: Keys: %+v\n", keys) // Log at the start

	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	mutex.RLock()
	defer mutex.RUnlock()

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	now := time.Now()

	for kid, key := range keys {
		if now.Before(key.ExpiresAt) {
			jwk := map[string]interface{}{
				"kid": kid,
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}
			jwks.Keys = append(jwks.Keys, jwk)
		}
	}

	if len(jwks.Keys) == 0 {
		http.Error(w, "No valid JWKs available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// Authentication handling function
func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	expired := r.URL.Query().Get("expired") == "true"

	mutex.RLock()
	defer mutex.RUnlock()

	var chosenKey *Key
	var kid string

	for k, key := range keys {
		if expired || time.Now().Before(key.ExpiresAt) {
			chosenKey = &key
			kid = k
			break
		}
	}

	if chosenKey == nil {
		http.Error(w, "No suitable key available", http.StatusNotFound)
		return
	}

	expTime := time.Now().Add(5 * time.Minute)
	if expired {
		expTime = chosenKey.ExpiresAt.Add(-1 * time.Second)
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
	log.Printf("Auth Request (expired=%v): Kid: %s, ExpiresAt: %v\n", expired, kid, chosenKey.ExpiresAt)
}

// Function to refresh keys
func refreshKeys() {
	log.Println("refreshKeys started")
	for {
		time.Sleep(keyRefreshInterval)

		kid, privateKey, publicKey, expiresAt, err := generateKeyPair()
		if err != nil {
			log.Println("Error generating new key pair:", err)
			continue
		}

		mutex.Lock()
		keys[kid] = Key{PrivateKey: privateKey, PublicKey: publicKey, ExpiresAt: expiresAt}
		mutex.Unlock()
		log.Printf("New Key: Kid: %s, ExpiresAt: %v, Keys: %+v\n", kid, expiresAt, keys)
		log.Printf("Keys before removal: %+v\n", keys)

		// Remove expired keys (with a grace period)
		mutex.Lock()
		now := time.Now()
		gracePeriod := keyRefreshInterval
		for k, key := range keys {
			if now.After(key.ExpiresAt.Add(gracePeriod)) {
				delete(keys, k)
				log.Printf("Key %s expired and removed.\n", k)
			}
		}
		mutex.Unlock()
		log.Printf("Keys after removal: %+v\n", keys)
		log.Println("Keys refreshed.")
	}
}

// Function to handle expired keys
func expireKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	kid := r.URL.Query().Get("kid")
	if kid == "" {
		http.Error(w, "kid parameter is required", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	key, ok := keys[kid]
	if !ok {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}

	key.ExpiresAt = time.Now().Add(-1 * time.Second)
	keys[kid] = key

	log.Printf("Key %s expiry set to: %v (Unix: %d)\n", kid, key.ExpiresAt, key.ExpiresAt.Unix())

	// Remove the key immediately
	delete(keys, kid)
	log.Printf("Key %s REMOVED immediately after expiry set. Keys: %+v\n", kid, keys)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Key expiry updated"})
}

func main() {
	keyRefreshInterval = 10 * time.Second // ONLY FOR TESTING

	kid, privateKey, publicKey, expiresAt, err := generateKeyPair()
	if err != nil {
		log.Fatal("Failed to generate initial key pair:", err)
	}
	keys[kid] = Key{PrivateKey: privateKey, PublicKey: publicKey, ExpiresAt: expiresAt}

	go refreshKeys()

	http.HandleFunc("/jwks", jwksHandler)
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/test/expirekey", expireKeyHandler)

	log.Println("Server running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
