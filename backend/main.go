package main

import (
	"crypto/sha256"
	"encoding/base64"

	// "encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"

	// "net/url"
	"strings"
	"time"

	"hunghd/oidc-demo/backend/database"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	validator "github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
	"github.com/microcosm-cc/bluemonday"
)

var validate = validator.New()
var policy = bluemonday.UGCPolicy()

// Client represents an OIDC client
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

// AuthCode represents an authorization code
type AuthCode struct {
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Expiry              time.Time
}

// Token represents an access token
type Token struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int       `json:"expires_in"`
	IDToken     string    `json:"id_token"`
	UserID      string    `json:"user_id"`
	Expiry      time.Time `json:"-"`
}

var (
	clients      = make(map[string]Client)
	authCodes    = make(map[string]AuthCode)
	tokens       = make(map[string]Token)
	resourceData = "This is a secret resource."
	jwtSecret    = []byte(os.Getenv("JWT_SECRET"))
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// A02:2021-Cryptographic Failures
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("JWT_SECRET environment variable not set")
	} else {
		log.Println("loaded secret from environment", os.Getenv("JWT_SECRET"))
	}
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000",
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
	}))

	// A05:2021-Security Misconfiguration
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Frame-Options", "DENY")
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Content-Security-Policy", "default-src 'self'")
		c.Set("X-XSS-Protection", "1; mode=block")
		return c.Next()
	})

	database.InitDB() // Initialize the in-memory database

	// In-memory data setup
	clients["nextjs-client"] = Client{
		ID:           "nextjs-client",
		Secret:       "nextjs-client-secret",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	app.Post("/register", registerUser)
	app.Get("/authorize", authorize)

	// A07:2021-Identification and Authentication Failures
	loginLimiter := limiter.New(limiter.Config{
		Max:        5,
		Expiration: 1 * time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{"error": "Too many requests"})
		},
	})
	app.Post("/login", loginLimiter, login)
	app.Post("/token", token)
	app.Get("/userinfo", userinfo)
	app.Get("/api/resource", protectedResource)
	app.Post("/logout", logout)
	app.Get("/fetch-image", fetchImage)

	log.Fatal(app.ListenTLS(":8080", "cert.pem", "key.pem"))
}

// A10:2021-Server-Side Request Forgery (SSRF)
var allowedDomains = []string{"example.com", "google.com", "live.staticflickr.com"}

func isAllowedURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Allow only http and https schemes
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Disallow empty host
	if u.Host == "" {
		return false
	}

	// Whitelist checking
	for _, d := range allowedDomains {
		if u.Host == d || strings.HasSuffix(u.Host, "."+d) {
			return true
		}
	}

	return false
}

func fetchImage(c *fiber.Ctx) error {
	urlStr := c.Query("url")
	if urlStr == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "URL parameter is missing"})
	}

	if !isAllowedURL(urlStr) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "URL is not allowed"})
	}

	resp, err := http.Get(urlStr)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to fetch image"})
	}
	defer resp.Body.Close()

	c.Set("Content-Type", resp.Header.Get("Content-Type"))
	_, err = io.Copy(c.Response().BodyWriter(), resp.Body)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to stream image"})
	}

	return nil
}

func logout(c *fiber.Ctx) error {
	// In a real application, you would invalidate server-side sessions or tokens here.
	// For this stateless POC, we just acknowledge the logout.
	log.Println("con co be be")
	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Logged out successfully"})
}

func registerUser(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username" validate:"required,alphanum,min=3,max=20"`
		Password string `json:"password" validate:"required,min=8"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Sanitize username
	req.Username = policy.Sanitize(req.Username)

	// Validate request
	if err := validate.Struct(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Check if user already exists
	_, found := database.GetUser(req.Username)
	if found {
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "User already exists"})
	}

	if err := database.AddUser(req.Username, req.Password); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to register user"})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "User registered successfully"})
}

func authorize(c *fiber.Ctx) error {
	// A01:2021-Broken Access Control
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")

	if clientID == "" || redirectURI == "" || codeChallenge == "" || codeChallengeMethod == "" {
		return c.Status(http.StatusBadRequest).SendString("Missing required parameters")
	}

	client, ok := clients[clientID]
	if !ok {
		return c.Status(http.StatusBadRequest).SendString("Invalid client_id")
	}

	validRedirectURI := false
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			validRedirectURI = true
			break
		}
	}
	if !validRedirectURI {
		return c.Status(http.StatusBadRequest).SendString("Invalid redirect_uri")
	}

	tmpl, err := template.ParseFiles("login.html")
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
	}

	authParams := c.Request().URI().QueryString()

	c.Set("Content-Type", "text/html")
	return tmpl.Execute(c.Response().BodyWriter(), map[string]interface{}{
		"AuthParams": string(authParams),
	})
}

func login(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	authParams := c.FormValue("auth_params")

	// Sanitize username
	username = policy.Sanitize(username)

	// Validate username
	if err := validate.Var(username, "required,alphanum,min=3,max=20"); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	user, found := database.GetUser(username)
	if !found || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		tmpl, err := template.ParseFiles("login.html")
		if err != nil {
			return c.Status(http.StatusInternalServerError).SendString("Internal Server Error")
		}
		c.Set("Content-Type", "text/html")
		return tmpl.Execute(c.Response().BodyWriter(), map[string]interface{}{
			"AuthParams": authParams,
			"Error":      "Invalid username or password",
		})
	}

	parsedParams, err := url.ParseQuery(authParams)
	if err != nil {
		return c.Status(http.StatusBadRequest).SendString("Invalid auth params")
	}

	clientID := parsedParams.Get("client_id")
	redirectURI := parsedParams.Get("redirect_uri")
	codeChallenge := parsedParams.Get("code_challenge")
	codeChallengeMethod := parsedParams.Get("code_challenge_method")

	code := uuid.New().String()
	authCodes[code] = AuthCode{
		Code:                code,
		ClientID:            clientID,
		UserID:              user.Username, // Use username as UserID for simplicity
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Expiry:              time.Now().Add(10 * time.Minute),
	}

	return c.Redirect(redirectURI + "?code=" + code)
}

func token(c *fiber.Ctx) error {
	grantType := c.FormValue("grant_type")
	code := c.FormValue("code")
	redirectURI := c.FormValue("redirect_uri")
	clientID := c.FormValue("client_id")
	codeVerifier := c.FormValue("code_verifier")

	if grantType != "authorization_code" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid grant_type"})
	}

	authCode, ok := authCodes[code]
	if !ok || authCode.Expiry.Before(time.Now()) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid or expired code"})
	}

	if authCode.ClientID != clientID {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid client_id"})
	}

	if authCode.RedirectURI != redirectURI {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid redirect_uri"})
	}

	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	if calculatedChallenge != authCode.CodeChallenge {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid code_verifier"})
	}

	delete(authCodes, code)

	accessToken, err := createAccessToken(authCode.UserID, authCode.ClientID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create access token"})
	}
	idToken, err := createIDToken(authCode.UserID, authCode.ClientID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create ID token"})
	}

	return c.JSON(fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func userinfo(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing Authorization header"})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Authorization header"})
	}

	accessToken := parts[1]
	claims, err := validateToken(accessToken)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	userID := claims["sub"].(string)
	user, ok := database.GetUser(userID)
	if !ok {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.JSON(fiber.Map{
		"sub":      user.Username,
		"username": user.Username,
	})
}

func protectedResource(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing Authorization header"})
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid Authorization header"})
	}

	accessToken := parts[1]
	_, err := validateToken(accessToken)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
	}

	return c.JSON(fiber.Map{"data": resourceData})
}

func createAccessToken(username, clientID string) (string, error) {
	exp := time.Now().Add(1 * time.Hour)
	claims := jwt.MapClaims{
		"sub": username,
		"aud": clientID,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func createIDToken(username, clientID string) (string, error) {
	exp := time.Now().Add(1 * time.Hour)
	claims := jwt.MapClaims{
		"iss": "https://localhost:8080",
		"sub": username,
		"aud": clientID,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, fiber.ErrUnauthorized
}
