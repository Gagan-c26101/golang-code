package middleware

import (
	"fib/config"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
)

// var jwtSecret = []byte("asdfasqsdfgsdasdfasdfawqe") // Replace with your actual secret key

// GenerateJWT generates a JWT token for the user
func GenerateJWT(userID uint, name, role, platform string) (string, error) {
	var expDuration time.Duration
	// if strings.ToLower(strings.TrimSpace(platform)) == "mobile" {
	// 	expDuration = 7 * 24 * time.Hour
	// } else {
	// 	expDuration = 24 * time.Hour
	// }

	cleanPlatform := strings.ToLower(strings.TrimSpace(platform))

	if cleanPlatform == "mobile" {
		expDuration = 7 * 24 * time.Hour
		fmt.Printf("JWT generated for MOBILE user_id=%d, expiry=%v", userID, expDuration)
	} else {
		expDuration = 24 * time.Hour
		fmt.Printf("JWT generated for WEB user_id=%d, expiry=%v", userID, expDuration)
	}

	// Set claims
	claims := jwt.MapClaims{
		"userId": userID,                             // User ID
		"name":   name,                               // Name of the user
		"role":   role,                               // User role
		"iat":    time.Now().Unix(),                  // Issued at (current timestamp)
		"exp":    time.Now().Add(expDuration).Unix(), // Expiry based on platform
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := []byte(config.AppConfig.JWTKey)
	// Sign the token with the secret key
	return token.SignedString(jwtSecret)
}

// JWTMiddleware is a middleware to check for valid JWT token in the request
func JWTMiddleware(c *fiber.Ctx) error {
	// Get the token from the Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Missing or invalid Authorization header",
		})
	}

	// The token should be prefixed with "Bearer "
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Invalid Authorization header format",
		})
	}

	// Extract the token part
	tokenString := authHeader[len("Bearer "):]

	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check if the token method is valid
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		jwtSecret := []byte(config.AppConfig.JWTKey)
		return jwtSecret, nil
	})

	// If there's an error parsing the token
	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Invalid or expired token",
		})
	}

	// Extract user ID from the token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["userId"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  false,
			"message": "Invalid token payload",
		})
	}

	// Set the user ID in the request context
	userID := claims["userId"].(float64) // JWT claims are typically stored as `float64`, so cast it
	c.Locals("userId", uint(userID))     // Store userID in context as uint

	// If valid, continue to the next handler
	return c.Next()
}

// GenerateTempToken generates a short-lived JWT
func GenerateTempToken(userID uint, purpose string) (string, error) {
	claims := jwt.MapClaims{
		"userId":  userID,
		"purpose": purpose,                                // dynamic purpose
		"iat":     time.Now().Unix(),                      // issued at
		"exp":     time.Now().Add(5 * time.Minute).Unix(), // hardcoded 5 minutes expiry
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.AppConfig.JWTKey))
}

// TempTokenMiddleware validates a temporary token for a specific purpose
func TempTokenMiddleware(expectedPurpose string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		auth := c.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return JsonResponse(c, fiber.StatusUnauthorized, false, "Missing temporary token", nil)
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
			return []byte(config.AppConfig.JWTKey), nil
		})

		if err != nil || !token.Valid {
			return JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or expired temporary token", nil)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid token claims", nil)
		}
		// fmt.Println("Temp token claims:", claims)

		if claims["purpose"] != expectedPurpose {
			return JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid token purpose", nil)
		}

		userID, ok := claims["userId"].(float64)
		if !ok {
			return JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid user in token", nil)
		}

		c.Locals("userId", uint(userID))
		return c.Next()
	}
}

func JsonResponse(c *fiber.Ctx, statusCode int, status bool, message string, data interface{}) error {
	return c.Status(statusCode).JSON(fiber.Map{
		"status":  status,
		"message": message,
		"data":    data,
	})
}

func ValidationErrorResponse(c *fiber.Ctx, errors map[string]string) error {
	return JsonResponse(c, fiber.StatusUnprocessableEntity, false, "Validation failed!", errors)
}
