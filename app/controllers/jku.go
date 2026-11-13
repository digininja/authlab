package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

const jkuKeyID = "authlab-jku-key-1"

var (
	jkuPrivateKey *rsa.PrivateKey
	jkuPublicKey  *rsa.PublicKey
)

func init() {
	var err error
	jkuPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate RSA keypair for JKU challenge: %v", err))
	}
	jkuPublicKey = &jkuPrivateKey.PublicKey
}

// RegisterJKURoutes mounts the JKU challenge routes and the legitimate JWKS endpoint.
func RegisterJKURoutes(r chi.Router, renderFn RenderFunc, flashFn FlashFunc) {
	r.Get("/JKU_Lab", func(w http.ResponseWriter, r *http.Request) {
		handleJKULab(w, r, renderFn)
	})
	r.Post("/JKU_Check", func(w http.ResponseWriter, r *http.Request) {
		handleJKUCheck(w, r, flashFn)
	})
	// Legitimate JWKS endpoint referenced by the sample token
	r.Get("/.well-known/jwks.json", handleJKUWellKnown)
}

// handleJKUWellKnown serves the server's public key in standard RFC 7517 JWKS format
func handleJKUWellKnown(w http.ResponseWriter, r *http.Request) {
	jwk := rsaPublicKeyToJWK(jkuPublicKey)
	jwk["kid"] = jkuKeyID

	jwks := map[string]any{
		"keys": []map[string]any{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

// handleJKULab generates a sample guest token pointing to the server's own JWKS endpoint
func handleJKULab(w http.ResponseWriter, r *http.Request, render RenderFunc) {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	defaultJKU := fmt.Sprintf("%s://%s/.well-known/jwks.json", scheme, r.Host)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user":  "guest",
		"admin": false,
	})
	token.Header["kid"] = jkuKeyID
	token.Header["jku"] = defaultJKU

	sampleToken, err := token.SignedString(jkuPrivateKey)
	if err != nil {
		http.Error(w, "Failed to generate sample token", http.StatusInternalServerError)
		return
	}

	render(w, r, "App/JKU_Lab.html", map[string]any{
		"sampleToken": sampleToken,
		"jwksURL":     defaultJKU,
	})
}

// handleJKUCheck blindly fetches the JWKS from the URL specified in the token's 'jku' header
func handleJKUCheck(w http.ResponseWriter, r *http.Request, setFlash FlashFunc) {
	_ = r.ParseForm()
	tokenStr := strings.TrimSpace(r.FormValue("jwt"))
	if tokenStr == "" {
		tokenStr = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// --- VULNERABILITY: No domain allowlist check on the 'jku' header ---
		jkuURL, ok := token.Header["jku"].(string)
		if !ok || strings.TrimSpace(jkuURL) == "" {
			return nil, errors.New("missing or invalid 'jku' header")
		}

		// Fetch remote JWKS with a short timeout to prevent hanging workers
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(jkuURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWKS from %s: %v", jkuURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
		if err != nil {
			return nil, fmt.Errorf("failed to read JWKS response: %v", err)
		}

		var jwks struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(body, &jwks); err != nil {
			return nil, fmt.Errorf("invalid JWKS JSON format: %v", err)
		}
		if len(jwks.Keys) == 0 {
			return nil, errors.New("JWKS contains no keys")
		}

		// Match by 'kid' if provided, otherwise fall back to the first RSA key in the set
		targetKid, _ := token.Header["kid"].(string)
		var selectedKey map[string]any

		for _, k := range jwks.Keys {
			if kty, _ := k["kty"].(string); kty != "RSA" {
				continue
			}
			if targetKid != "" {
				if kid, _ := k["kid"].(string); kid == targetKid {
					selectedKey = k
					break
				}
			} else {
				selectedKey = k
				break
			}
		}

		if selectedKey == nil {
			return nil, errors.New("no matching RSA key found in remote JWKS")
		}

		nStr, _ := selectedKey["n"].(string)
		eStr, _ := selectedKey["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, errors.New("missing 'n' or 'e' parameters in JWK")
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, errors.New("invalid base64url encoding for 'n'")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, errors.New("invalid base64url encoding for 'e'")
		}

		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}, nil
	})

	if err != nil || !token.Valid {
		setFlash(w, "error", fmt.Sprintf("Authentication failed: %v", err))
		http.Redirect(w, r, "/JKU_Lab", http.StatusFound)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		setFlash(w, "error", "Unable to extract claims from token.")
		http.Redirect(w, r, "/JKU_Lab", http.StatusFound)
		return
	}

	user := fmt.Sprintf("%v", claims["user"])
	isAdmin, _ := claims["admin"].(bool)

	if isAdmin || user == "admin" {
		setFlash(w, "success", "Welcome, Administrator!")
	} else {
		setFlash(w, "error", fmt.Sprintf("Logged in as '%s', but administrator privileges are required.", html.EscapeString(user)))
	}

	http.Redirect(w, r, "/JKU_Lab", http.StatusFound)
}
