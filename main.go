package main

import (
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var hmacSampleSecret []byte

// --- Flash Message Utilities (Cookie-based, mimicking Revel) ---

func setFlash(w http.ResponseWriter, flashType, message string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "REVEL_FLASH",
		Value:    url.QueryEscape(fmt.Sprintf("%s:%s", flashType, message)),
		Path:     "/",
		HttpOnly: true,
	})
}

func getAndClearFlash(w http.ResponseWriter, r *http.Request) map[string]string {
	flash := make(map[string]string)
	cookie, err := r.Cookie("REVEL_FLASH")
	if err == nil {
		val, _ := url.QueryUnescape(cookie.Value)
		parts := strings.SplitN(val, ":", 2)
		if len(parts) == 2 {
			flash[parts[0]] = parts[1]
		}
		// Clear cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "REVEL_FLASH",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
	return flash
}

// --- View Renderer ---

type ViewRenderer struct {
	viewsDir string
}

func (vr *ViewRenderer) Render(w http.ResponseWriter, r *http.Request, viewPath string, data map[string]any) {
	if data == nil {
		data = make(map[string]any)
	}

	flash := getAndClearFlash(w, r)
	data["flash"] = flash
	if errVal, ok := flash["error"]; ok {
		data["error"] = errVal
	}
	if successVal, ok := flash["success"]; ok {
		data["success"] = successVal
	}

	// Revel template helpers: set, append, raw, field, etc.
	funcMap := template.FuncMap{
		"set": func(renderArgs map[string]any, key string, value any) template.HTML {
			renderArgs[key] = value
			return ""
		},
		"append": func(renderArgs map[string]any, key string, value any) template.HTML {
			if cur, ok := renderArgs[key]; ok {
				if slice, ok := cur.([]any); ok {
					renderArgs[key] = append(slice, value)
					return ""
				}
			}
			renderArgs[key] = []any{value}
			return ""
		},
		"raw": func(s string) template.HTML {
			return template.HTML(s)
		},
		"url": func(path string) string {
			return path
		},
		"eq": func(a, b any) bool {
			return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
		},
	}

	header := filepath.Join(vr.viewsDir, "header.html")
	footer := filepath.Join(vr.viewsDir, "footer.html")
	target := filepath.Join(vr.viewsDir, viewPath)

	tmpl, err := template.New(filepath.Base(viewPath)).Funcs(funcMap).ParseFiles(header, target, footer)
	if err != nil {
		var fallbackErr error
		tmpl, fallbackErr = template.New(filepath.Base(viewPath)).Funcs(funcMap).ParseFiles(target)
		if fallbackErr != nil {
			log.Printf("Template parsing error: %v (fallback: %v)", err, fallbackErr)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// If the template files define a named base template or standard block:
	if err := tmpl.Execute(w, data); err != nil {
		if execErr := tmpl.ExecuteTemplate(w, filepath.Base(target), data); execErr != nil {
			log.Printf("Template execution error: %v", execErr)
		}
	}
}

func renderJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// --- Helper Functions ---

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// --- JWT Challenge 1: Auth0 (CVE-2019-7644) ---

func getToken(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	hmacSampleSecret = []byte("my_secret_key")
	return hmacSampleSecret, nil
}

func ParseJWT(tokenString string) (bool, string) {
	var success bool = false
	var message string = ""

	token, err := jwt.Parse(tokenString, getToken)

	if err == nil {
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			message = fmt.Sprintf("Welcome %s (%s)", claims["user"], claims["level"])
			success = true
		}
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
			newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, token.Claims)
			newTokenString, _ := newToken.SignedString(hmacSampleSecret)

			newParsedToken, _ := jwt.Parse(newTokenString, getToken)

			message = fmt.Sprintf("Invalid signature. Expected %s got %s", newParsedToken.Signature, token.Signature)
		} else if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			message = fmt.Sprintln("That's not even a token")
		} else {
			fmt.Sprintln("Couldn't handle this token:", err)
		}
	} else {
		message = fmt.Sprintf("There was an error parsing the token: %s", err.Error())
	}

	return success, message
}

// --- JWT Challenge 2: None Algorithm ---

func getTokenNone(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	hmacSampleSecret = []byte("No more secrets")
	return hmacSampleSecret, nil
}

type SigningMethodNone struct{}

func (j SigningMethodNone) Verify(signingString, signature string, key interface{}) error {
	return nil
}
func (j SigningMethodNone) Sign(signingString string, key interface{}) (string, error) {
	return "", nil
}
func (j SigningMethodNone) Alg() string {
	return "None"
}

func getSigningMethodNone() jwt.SigningMethod {
	return SigningMethodNone{}
}

func extractClaims(token *jwt.Token) (jwt.MapClaims, bool) {
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, true
	}
	return nil, false
}

type jwtNoneResponse struct {
	Success bool   `json:"Success"`
	User    string `json:"User"`
	Level   string `json:"Level"`
	Message string `json:"Message"`
}

func ParseJWTNone(tokenString string) (bool, jwtNoneResponse) {
	var algorithm string = ""
	var response jwtNoneResponse

	jwt.RegisterSigningMethod("noNe", getSigningMethodNone)
	jwt.RegisterSigningMethod("NoNe", getSigningMethodNone)
	jwt.RegisterSigningMethod("None", getSigningMethodNone)
	jwt.RegisterSigningMethod("NONE", getSigningMethodNone)

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		response.Message = fmt.Sprintf("Error parsing token: %s", err)
		response.Success = false
		return false, response
	}

	if token.Method == nil {
		response.Message = "No hashing method passed"
		response.Success = false
		return false, response
	}

	algorithm = token.Method.Alg()

	if strings.EqualFold(algorithm, "none") {
		if algorithm == "none" {
			response.Message = "'none' signature type is not allowed"
			response.Success = false
			return false, response
		}
	} else if !token.Valid {
		token, err = jwt.Parse(tokenString, getTokenNone)
		if !token.Valid {
			response.Message = "Invalid signature"
			response.Success = false
			return false, response
		}
	}

	claims, success := extractClaims(token)
	if !success {
		response.Message = "Error parsing claims"
		response.Success = false
		return false, response
	}

	var user string
	var level string

	if val, ok := claims["user"]; ok {
		user = val.(string)
	} else {
		response.Message = "User not provided"
		response.Success = false
		return false, response
	}

	if val, ok := claims["level"]; ok {
		level = val.(string)
	} else {
		response.Message = "Level not provided"
		response.Success = false
		return false, response
	}

	response.Message = fmt.Sprintf("Logged in as %s with user level %s", user, level)
	response.User = user
	response.Level = level
	response.Success = true
	return true, response
}

// --- Main Application & Route Setup ---

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	renderer := &ViewRenderer{viewsDir: filepath.Join("app", "views")}
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Map static resources (/public/*filepath -> ./public directory)
	workDir, _ := os.Getwd()
	publicDir := filepath.Join(workDir, "public")
	fs := http.StripPrefix("/public/", http.FileServer(http.Dir(publicDir)))
	r.Get("/public/*", func(w http.ResponseWriter, r *http.Request) {
		fs.ServeHTTP(w, r)
	})

	// Favicon
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	// Index
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		renderer.Render(w, r, "App/Index.html", nil)
	})

	// ClientSide
	r.Get("/ClientSide", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		loggedIn := (hash == "e2b18481be9c7b210e3fa881d7484495")
		renderer.Render(w, r, "App/ClientSide.html", map[string]any{
			"logged_in": loggedIn,
		})
	})

	// Timing
	r.Get("/Timing", func(w http.ResponseWriter, r *http.Request) {
		renderer.Render(w, r, "App/Timing.html", nil)
	})

	r.Post("/Timing_Login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		username := r.FormValue("username")
		users := []string{"zoe", "joe", "alex", "sarah"}

		if contains(users, strings.ToLower(username)) {
			time.Sleep(3000 * time.Millisecond)
		}

		setFlash(w, "error", "Login Failed")
		http.Redirect(w, r, "/Timing", http.StatusFound)
	})

	// Auth1
	r.Get("/Auth1", func(w http.ResponseWriter, r *http.Request) {
		tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZXZlbCI6InVzZXIiLCJ1c2VyIjoic2lkIn0.Hnpn5k6NtrXn8qvOuiSsFjXhAolQGn3TfmGBvA7EGTU"
		renderer.Render(w, r, "App/Auth1.html", map[string]any{
			"tokenString": tokenString,
			"username":    "",
		})
	})

	r.Post("/Auth1_Login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		jwtStr := r.FormValue("jwt")
		success, message := ParseJWT(jwtStr)

		if success {
			setFlash(w, "success", message)
		} else {
			setFlash(w, "error", message)
		}
		http.Redirect(w, r, "/Auth1", http.StatusFound)
	})

	// Bypass
	r.Get("/Bypass", func(w http.ResponseWriter, r *http.Request) {
		forwarded := r.Header.Get("X-Forwarded-For")
		loggedIn := forwarded == "192.168.0.14"
		// loggedIn := strings.Contains(forwarded, "192.168.0.14")
		renderer.Render(w, r, "App/Bypass.html", map[string]any{
			"forwarded": forwarded,
			"logged_in": loggedIn,
		})
	})

	// Expired_JWT
	r.Get("/Expired_JWT", func(w http.ResponseWriter, r *http.Request) {
		tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZXZlbCI6ImFkbWluIiwicGFzc3dvcmQiOiIyYWM5Y2I3ZGMwMmIzYzAwODNlYjcwODk4ZTU0OWI2MyIsInVzZXJuYW1lIjoiam9lIn0.6j3NrK-0C7K8gmaWeB9CCyZuQKfvVEAl4KhitRN2p5k"
		renderer.Render(w, r, "App/Expired_JWT.html", map[string]any{
			"tokenString": tokenString,
			"username":    "",
		})
	})

	r.Post("/Expired_JWT_Login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "joe" && password == "Password1" {
			setFlash(w, "success", "Login Success")
		} else {
			setFlash(w, "error", "Login Failed")
		}
		http.Redirect(w, r, "/Expired_JWT", http.StatusFound)
	})

	// Leaky_JWT
	r.Get("/Leaky_JWT", func(w http.ResponseWriter, r *http.Request) {
		tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsZXZlbCI6ImFkbWluIiwicGFzc3dvcmQiOiIyYWM5Y2I3ZGMwMmIzYzAwODNlYjcwODk4ZTU0OWI2MyIsInVzZXJuYW1lIjoiam9lIn0.6j3NrK-0C7K8gmaWeB9CCyZuQKfvVEAl4KhitRN2p5k"
		renderer.Render(w, r, "App/Leaky_JWT.html", map[string]any{
			"tokenString": tokenString,
			"username":    "",
		})
	})

	r.Post("/Leaky_JWT_Login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "joe" && password == "Password1" {
			setFlash(w, "success", "Login Success")
		} else {
			setFlash(w, "error", "Login Failed")
		}
		http.Redirect(w, r, "/Leaky_JWT", http.StatusFound)
	})

	// UserAgent
	handleUserAgent := func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		app := ""
		comment := fmt.Sprintf("<!-- For debug, the user agent supplied is: %s -->", html.EscapeString(ua))
		if ua == "authlab desktop app" {
			app = "desktop"
		}
		renderer.Render(w, r, "App/UserAgent.html", map[string]any{
			"app":     app,
			"comment": template.HTML(comment),
		})
	}
	r.Get("/UserAgent", handleUserAgent)
	r.Post("/UserAgent", handleUserAgent)

	r.Get("/UserAgentPing", func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		app := ""
		if ua == "authlab desktop app" {
			app = "desktop"
		}
		renderer.Render(w, r, "App/UserAgent_Ping.html", map[string]any{
			"app": app,
		})
	})

	// JWT None
	r.Get("/JWT_None", func(w http.ResponseWriter, r *http.Request) {
		renderer.Render(w, r, "App/JWT_None.html", nil)
	})

	r.Get("/JWT_None_Check", func(w http.ResponseWriter, r *http.Request) {
		data := make(map[string]interface{})
		bearerHeader := r.Header.Get("Authorization")

		re := regexp.MustCompile("(?i)^bearer (.*)$")
		matches := re.FindStringSubmatch(bearerHeader)

		jwtToken := ""
		if len(matches) == 2 {
			jwtToken = matches[1]
		} else {
			data["error"] = true
			data["stuff"] = "No token found"
			renderJSON(w, data)
			return
		}

		_, response := ParseJWTNone(jwtToken)
		renderJSON(w, response)
	})

	fmt.Printf("Authlab running on http://localhost:%s\n", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server exited: %v", err)
	}
}
