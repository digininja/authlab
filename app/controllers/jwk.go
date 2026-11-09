package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// Function signature types matching your helpers in main.go
type RenderFunc func(w http.ResponseWriter, r *http.Request, tmpl string, data map[string]any)
type FlashFunc func(w http.ResponseWriter, category, message string)

var (
	jwkPrivateKey *rsa.PrivateKey
	jwkPublicKey  *rsa.PublicKey

	// Shared helper references
	render   RenderFunc
	setFlash FlashFunc
)

func init() {
	var err error
	jwkPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA keypair for JWK challenge: %v", err))
	}
	jwkPublicKey = &jwkPrivateKey.PublicKey
}

// RegisterJWKRoutes mounts the JWK challenge routes using main's renderer and flash helpers
func RegisterJWKRoutes(r chi.Router, renderFn RenderFunc, flashFn FlashFunc) {
	render = renderFn
	setFlash = flashFn

	r.Get("/JWK_Lab", handleJWKLab)
	r.Post("/JWK_Check", handleJWKCheck)
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func handleJWKLab(w http.ResponseWriter, r *http.Request) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user":  "guest",
		"admin": false,
	})
	token.Header["jwk"] = rsaPublicKeyToJWK(jwkPublicKey)

	sampleToken, err := token.SignedString(jwkPrivateKey)
	if err != nil {
		http.Error(w, "Failed to generate sample token", http.StatusInternalServerError)
		return
	}

	render(w, r, "App/JWK_Lab.html", map[string]any{
		"sampleToken": sampleToken,
	})
}

func handleJWKCheck(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tokenStr := strings.TrimSpace(r.FormValue("jwt"))
	if tokenStr == "" {
		tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		rawJWK, ok := token.Header["jwk"].(map[string]any)
		if !ok {
			return nil, errors.New("missing or invalid 'jwk' object in token header")
		}

		kty, _ := rawJWK["kty"].(string)
		if kty != "RSA" {
			return nil, errors.New("unsupported key type (kty), only RSA is accepted")
		}

		nStr, _ := rawJWK["n"].(string)
		eStr, _ := rawJWK["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, errors.New("missing 'n' or 'e' parameters in jwk")
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, errors.New("invalid base64url encoding for 'n'")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, errors.New("invalid base64url encoding for 'e'")
		}

		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}

		return pubKey, nil
	})

	if err != nil || !token.Valid {
		setFlash(w, "error", fmt.Sprintf("Authentication failed: %v", err))
		http.Redirect(w, r, "/JWK_Lab", http.StatusFound)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		setFlash(w, "error", "Unable to extract claims from token.")
		http.Redirect(w, r, "/JWK_Lab", http.StatusFound)
		return
	}

	user := fmt.Sprintf("%v", claims["user"])
	isAdmin, _ := claims["admin"].(bool)

	if isAdmin || user == "admin" {
		setFlash(w, "success", "Welcome, Administrator!")
	} else {
		setFlash(w, "error", fmt.Sprintf("Logged in as '%s', but administrator privileges are required.", html.EscapeString(user)))
	}

	http.Redirect(w, r, "/JWK_Lab", http.StatusFound)
}
