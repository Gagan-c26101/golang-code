package authValidator

import (
	"fib/middleware"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
)

func isValidEmail(email string) bool {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func isValidMobile(mobile string) bool {
	re := regexp.MustCompile(`^\+[1-9][0-9]{0,3}[0-9]{7,15}$`)
	return re.MatchString(mobile)
}

func cleanEmail(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "")
}

func cleanMobile(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '(' || r == ')' || r == '.' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
}

func validateSingleCredential(email, mobile, emailKey, mobileKey string, errors map[string]string) {
	if email != "" && mobile != "" {
		errors["credentials"] = "Send OTP either to email OR mobile, not both!"
		return
	} else if email == "" && mobile == "" {
		errors["credentials"] = "Either email or mobile number is required!"
		return
	}
	if email != "" && !isValidEmail(email) {
		errors[emailKey] = "Invalid email!"
	}
	if mobile != "" && !isValidMobile(mobile) {
		errors[mobileKey] = "Invalid mobile number!"
	}
}

func validatePassword(password, key string, errors map[string]string) {
	trimmed := strings.TrimSpace(password)
	if len(trimmed) == 0 {
		errors[key] = "Password is required!"
		return
	}
	if len(trimmed) < 8 || len(trimmed) > 32 {
		errors[key] = "Password must be between 8 and 32 characters long!"
		return
	}

	var hasLower, hasUpper, hasNumber, hasSpecial bool

	for _, ch := range trimmed {
		switch {
		case ch >= 'a' && ch <= 'z':
			hasLower = true
		case ch >= 'A' && ch <= 'Z':
			hasUpper = true
		case ch >= '0' && ch <= '9':
			hasNumber = true
		default:
			hasSpecial = true
		}
	}
	if !hasLower || !hasUpper || !hasNumber || !hasSpecial {
		errors[key] = "Password must contain mix of [A-Z],[a-z],[0-9],special character(eg.@#$%)"
	}
}

// Signup validator middleware
func Signup() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			FirstName   string `json:"firstName"`
			LastName    string `json:"lastName"`
			CountryCode string `json:"countryCode"`
			Mobile      string `json:"mobile"`
			Email       string `json:"email"`
			Password    string `json:"password"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		// Trim fields
		reqData.FirstName = strings.TrimSpace(reqData.FirstName)
		reqData.LastName = strings.TrimSpace(reqData.LastName)
		reqData.Email = cleanEmail(reqData.Email)
		reqData.CountryCode = strings.TrimSpace(reqData.CountryCode)
		cleanNumber := cleanMobile(reqData.Mobile)
		if reqData.CountryCode == "" {
			errors["countryCode"] = "Country code is required!"
		}
		// Ensure country code starts with '+'
		if !strings.HasPrefix(reqData.CountryCode, "+") && reqData.CountryCode != "" {
			reqData.CountryCode = "+" + reqData.CountryCode
		}
		fullMobile := reqData.CountryCode + cleanNumber
		reqData.Mobile = fullMobile
		if reqData.FirstName == "" {
			errors["firstName"] = "First Name is required!"
		}
		if reqData.LastName == "" {
			errors["lastName"] = "Last Name is required!"
		}
		if reqData.Email == "" || !isValidEmail(reqData.Email) {
			errors["email"] = "Invalid email!"
		}
		if reqData.Mobile != "" && !isValidMobile(reqData.Mobile) {
			errors["mobile"] = "Invalid mobile format! Please include country code (e.g., +91 XXXXXXXXXX)."
		}
		validatePassword(reqData.Password, "password", errors)
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		// Pass cleaned and validated data forward
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// Login validator middleware
func Login() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile   string `json:"mobile"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Platform string `json:"platform"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		// Trim and clean
		reqData.Email = cleanEmail(reqData.Email)
		reqData.Mobile = cleanMobile(reqData.Mobile)
		reqData.Password = strings.TrimSpace(reqData.Password)
		if reqData.Email == "" && reqData.Mobile == "" {
			errors["credentials"] = "Either email or mobile number is required!"
		} else {
			if reqData.Email != "" && !isValidEmail(reqData.Email) {
				errors["email"] = "Invalid email!"
			}
			if reqData.Mobile != "" {
				// Validate country code and length
				if !strings.HasPrefix(reqData.Mobile, "+") {
					errors["mobile"] = "Country code is required (e.g., +91XXXXXXXXXX)!"
				} else {
					// Extract numeric part (after country code)
					numberPart := reqData.Mobile
					// remove leading + and country code digits
					for len(numberPart) > 0 && numberPart[0] == '+' {
						numberPart = numberPart[1:]
					}

				}
			}
		}
		validatePassword(reqData.Password, "password", errors)
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// SendOTP validator middleware
func SendOTP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile string `json:"mobile"`
			Email  string `json:"email"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		reqData.Email = cleanEmail(reqData.Email)
		reqData.Mobile = cleanMobile(reqData.Mobile)
		// Validate credentials
		validateSingleCredential(reqData.Email, reqData.Mobile, "email", "mobile", errors)
		// Respond with errors if any exist
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// VerifyOTP validates OTP request data
func VerifyOTP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Mobile string `json:"mobile"`
			Email  string `json:"email"`
			Code   string `json:"code"`
		})
		// Parse the request body into reqData
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		// Initialize a map to collect validation errors
		errors := make(map[string]string)
		reqData.Email = cleanEmail(reqData.Email)
		reqData.Code = strings.TrimSpace(reqData.Code)
		reqData.Mobile = cleanMobile(reqData.Mobile)
		// Validate that either email or mobile is provided
		validateSingleCredential(reqData.Email, reqData.Mobile, "email", "mobile", errors)
		if reqData.Code == "" {
			errors["code"] = "OTP code is required!"
		}
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}

// ResetPassword validator middleware
func ResetPassword() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Password string `json:"password"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		validatePassword(reqData.Password, "password", errors)
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedUser", reqData)
		return c.Next()
	}
}
func Login2FA() fiber.Handler {
	return func(c *fiber.Ctx) error {
		req := new(struct {
			Code string `json:"code"`
		})

		if err := c.BodyParser(req); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		// fmt.Println("RAW BODY:", string(c.Body()))
		// fmt.Println("Parsed UserID:", req.UserID)
		// fmt.Println("Parsed Code:", req.Code)

		errors := make(map[string]string)
		if strings.TrimSpace(req.Code) == "" {
			errors["code"] = "2FA code is required!"
		}

		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}

		c.Locals("validated2FA", req)
		return c.Next()
	}
}

// Change Contact Validation
// Validate New Contact for Sending OTP
func ValidateNewContact() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			NewEmail  string `json:"new_email"`
			NewMobile string `json:"new_mobile"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		reqData.NewEmail = cleanEmail(reqData.NewEmail)
		reqData.NewMobile = cleanMobile(reqData.NewMobile)
		// Validate credentials
		validateSingleCredential(reqData.NewEmail, reqData.NewMobile, "new_email", "new_mobile", errors)
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedNewContact", reqData)
		return c.Next()
	}
}

// Validate OTP for old contact verification
func ValidateNewContactOTP() fiber.Handler {
	return func(c *fiber.Ctx) error {
		reqData := new(struct {
			Code      string `json:"code"`
			NewEmail  string `json:"new_email"`
			NewMobile string `json:"new_mobile"`
		})
		if err := c.BodyParser(reqData); err != nil {
			return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
		}
		errors := make(map[string]string)
		reqData.NewEmail = cleanEmail(reqData.NewEmail)
		reqData.NewMobile = cleanMobile(reqData.NewMobile)
		// Validate that either email or mobile is provided
		validateSingleCredential(reqData.NewEmail, reqData.NewMobile, "new_email", "new_mobile", errors)
		if reqData.Code == "" {
			errors["code"] = "OTP code is required!"
		}
		if len(errors) > 0 {
			return middleware.ValidationErrorResponse(c, errors)
		}
		c.Locals("validatedNewOTP", reqData)
		return c.Next()
	}
}
