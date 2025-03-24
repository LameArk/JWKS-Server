package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/golang-jwt/jwt/v5"
)

const dbPath = "./totally_not_my_privateKeys.db"

//Create / connect to database
func createDatabase() {
        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
                log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        sql := "CREATE TABLE IF NOT EXISTS keys( kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL);"

        _, err = db.Exec(sql)

        if err != nil {
                log.Fatalf("Failed to create table: %v", err)
        }

        fmt.Printf("Database connected to created successfully at %s\n", dbPath)
}

func main() {
        createDatabase()

        db, err := sql.Open("sqlite3", dbPath)
        if err != nil {
                log.Fatalf("Failed to open database: %v", err)
        }
        defer db.Close()

        if err := genKeys(db); err != nil {
                log.Fatalf("Error generating/storing keys: %v", err)
        }
        log.Println("goodPrivKey:", goodPrivKey) //log key value
        log.Println("expiredPrivKey:", expiredPrivKey) //log key value

        http.HandleFunc("/.well-known/jwks.json", JWKSHandler)
        http.HandleFunc("/auth", AuthHandler)
        log.Fatal(http.ListenAndServe(":8080", nil))
}

var (
        goodPrivKey     *rsa.PrivateKey
        expiredPrivKey *rsa.PrivateKey
)

//Generates and stores keys into DB
func genKeys(db *sql.DB) error { 
	var err error
	goodPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
			return fmt.Errorf("error generating good RSA key: %w", err)
	}

	expiredPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
			return fmt.Errorf("error generating expired RSA key: %w", err)
	}

	expGoodKey := time.Now().Add(1 * time.Hour).Unix()
	goodKeyBytes := x509.MarshalPKCS1PrivateKey(goodPrivKey)

	expExpiredKey := time.Now().Add(-1 * time.Hour).Unix()
	expiredKeyBytes := x509.MarshalPKCS1PrivateKey(expiredPrivKey)

	_, err = db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?), (?, ?)",
			goodKeyBytes, expGoodKey,
			expiredKeyBytes, expExpiredKey,
	)

	if err != nil {
			return fmt.Errorf("failed to insert keys: %w", err)
	}

	return nil
}

func storeKeysInDB(db *sql.DB, kid string, privateKey *rsa.PrivateKey, expTime int64) error {
        keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
        keyBase64 := base64.StdEncoding.EncodeToString(keyBytes)

        _, err := db.Exec("INSERT INTO keys(kid, key, exp) VALUES(?, ?, ?)", kid, keyBase64, expTime)
        if err != nil {
                return fmt.Errorf("failed to insert key into database: %w", err)
        }

        return nil
}

const goodKID = "aRandomKeyID"

func AuthHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
        }
        var (
                signingKey *rsa.PrivateKey
                keyID      string
                exp        int64
        )

        signingKey = goodPrivKey
        keyID = goodKID
        exp = time.Now().Add(1 * time.Hour).Unix()

        if expired, _ := strconv.ParseBool(r.URL.Query().Get("expired")); expired {
                signingKey = expiredPrivKey
                keyID = "expiredKeyId"
                exp = time.Now().Add(-1 * time.Hour).Unix()
        }

        if signingKey == nil { //nil check
                http.Error(w, "Signing key is nil", http.StatusInternalServerError)
                return
        }

        token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
                "exp": exp,
        })
        token.Header["kid"] = keyID
        signedToken, err := token.SignedString(signingKey)
        if err != nil {
                http.Error(w, "failed to sign token", http.StatusInternalServerError)
                return
        }

        _, _ = w.Write([]byte(signedToken))
}

type (
        JWKS struct {
                Keys []JWK `json:"keys"`
        }
        JWK struct {
                KID       string `json:"kid"`
                Algorithm string `json:"alg"`
                KeyType   string `json:"kty"`
                Use       string `json:"use"`
                N         string `json:"n"`
                E         string `json:"e"`
        }
)

func JWKSHandler(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
                w.WriteHeader(http.StatusMethodNotAllowed)
                return
        }
        base64URLEncode := func(b *big.Int) string {
                return base64.RawURLEncoding.EncodeToString(b.Bytes())
        }
        publicKey := goodPrivKey.Public().(*rsa.PublicKey)
        resp := JWKS{
                Keys: []JWK{
                        {
                                KID:       goodKID,
                                Algorithm: "RS256",
                                KeyType:   "RSA",
                                Use:       "sig",
                                N:         base64URLEncode(publicKey.N),
                                E:         base64URLEncode(big.NewInt(int64(publicKey.E))),
                        },
                },
        }

        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(resp)
}