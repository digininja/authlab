package controllers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html"
	"net/http"
	"strings"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

var (
	algConfOnce      sync.Once
	algConfPublicKey *rsa.PublicKey
	algConfPublicPEM []byte
)

// getAlgConfKeys lazily derives the public key and PKIX PEM bytes from the
// shared RSA keypair initialized in jku.go, avoiding init() ordering issues.
func getAlgConfKeys() (*rsa.PublicKey, []byte) {
	algConfOnce.Do(func() {
		algConfPublicKey = &jkuPrivateKey.PublicKey

		pubASN1, err := x509.MarshalPKIXPublicKey(algConfPublicKey)
		if err != nil {
			panic(fmt.Sprintf("failed to marshal shared public key: %v", err))
		}
		algConfPublicPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubASN1,
		})
	})
	return algConfPublicKey, algConfPublicPEM
}

// RegisterAlgConfusionRoutes mounts the RS256 -> HS256 Algorithm Confusion lab routes.
func RegisterAlgConfusionRoutes(r chi.Router, renderFn RenderFunc, flashFn FlashFunc) {
	r.Get("/Alg_Confusion", func(w http.ResponseWriter, r *http.Request) {
		handleAlgConfusionLab(w, r, renderFn)
	})
	r.Post("/Alg_Confusion_Check", func(w http.ResponseWriter, r *http.Request) {
		handleAlgConfusionCheck(w, r, flashFn)
	})
	r.Get("/Alg_Confusion/public.pem", handleAlgConfusionPublicKey)
}

func handleAlgConfusionPublicKey(w http.ResponseWriter, r *http.Request) {
	_, pubPEM := getAlgConfKeys()
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pubPEM)
}

func handleAlgConfusionLab(w http.ResponseWriter, r *http.Request, render RenderFunc) {
	_, pubPEM := getAlgConfKeys()

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user":  "guest",
		"admin": false,
	})
	token.Header["kid"] = jkuKeyID

	sampleToken, err := token.SignedString(jkuPrivateKey)
	if err != nil {
		http.Error(w, "Failed to generate sample token", http.StatusInternalServerError)
		return
	}

	render(w, r, "App/Alg_Confusion.html", map[string]any{
		"sampleToken": sampleToken,
		"publicPEM":   string(pubPEM),
	})
}

func handleAlgConfusionCheck(w http.ResponseWriter, r *http.Request, setFlash FlashFunc) {
	_ = r.ParseForm()
	tokenStr := strings.TrimSpace(r.FormValue("jwt"))
	if tokenStr == "" {
		tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	pubKey, pubPEM := getAlgConfKeys()

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		// --- VULNERABILITY: Trusts the incoming token's 'alg' header instead of enforcing RS256 ---
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return pubKey, nil
		case *jwt.SigningMethodHMAC:
			// Uses the shared RSA public key (PKIX PEM bytes) as the HMAC secret
			return pubPEM, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil || !token.Valid {
		setFlash(w, "error", fmt.Sprintf("Authentication failed: %v", err))
		http.Redirect(w, r, "/Alg_Confusion", http.StatusFound)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		setFlash(w, "error", "Unable to extract claims from token.")
		http.Redirect(w, r, "/Alg_Confusion", http.StatusFound)
		return
	}

	user := fmt.Sprintf("%v", claims["user"])
	isAdmin, _ := claims["admin"].(bool)

	if isAdmin || user == "admin" {
		setFlash(w, "success", "Welcome, Administrator! FLAG{jwt_rs256_to_hs256_key_confusion}")
	} else {
		setFlash(w, "error", fmt.Sprintf("Logged in as '%s', but administrator privileges are required.", html.EscapeString(user)))
	}

	http.Redirect(w, r, "/Alg_Confusion", http.StatusFound)
}
