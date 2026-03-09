package authController

import (
	"crypto/rand"
	"errors"
	"fib/config"
	"fib/database"
	"fib/middleware"
	"fib/models"
	"fib/utils"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Generates a unique 6-character referral code.
func generateReferralCode() string {
	const charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 6
	checkReferralCodeExists := func(code string) bool {
		var user models.User
		result := database.Database.Db.Where("referral_code = ?", code).First(&user)
		return result.RowsAffected > 0
	}
	for {
		code := make([]byte, length)
		for i := 0; i < length; i++ {
			randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
			if err != nil {
				log.Fatal("Failed to generate random number:", err)
			}
			// Assign the random character to the code slice
			code[i] = charSet[randomIndex.Int64()]
		}
		referralCode := string(code)
		if !checkReferralCodeExists(referralCode) {
			return referralCode // Return the code if it doesn't exist
		}
	}
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), config.AppConfig.SaltRound)
	return string(hashed), err
}

func getUserByEmailOrMobile(email, mobile string, requireVerified bool) (*models.User, error) {
	var user models.User
	query := database.Database.Db.Where("is_deleted = ?", false)
	if email != "" {
		query = query.Where("email = ?", email)
		if requireVerified {
			query = query.Where("is_email_verified = ?", true)
		}
	} else if mobile != "" {
		query = query.Where("mobile = ?", mobile)
		if requireVerified {
			query = query.Where("is_mobile_verified = ?", true)
		}
	} else {
		return nil, fmt.Errorf("email or mobile required")
	}
	if err := query.First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func getOTPDescription(purpose utils.OTPPurpose) string {
	switch purpose {
	case utils.OTPPasswordReset:
		return "password_reset"
	case utils.OTPLogin:
		return "login"
	case utils.OTPVerifyOldContact:
		return "verify_old_contact"
	case utils.OTPVerifyNewContact:
		return "verify_new_contact"
	case utils.OTPContactVerification:
		return "contact_verification"
	default:
		return string(purpose)
	}
}

func hasPendingOTP(userID uint, purpose utils.OTPPurpose) bool {
	description := getOTPDescription(purpose)
	whereClause := "user_id = ? AND is_used = ? AND expires_at > ? AND is_deleted = ?"
	args := []interface{}{userID, false, time.Now(), false}
	if description != "" {
		whereClause += " AND description = ?"
		args = append(args, description)
	}
	var existingOTP models.OTP
	return database.Database.Db.Where(whereClause, args...).First(&existingOTP).Error == nil
}

// sendOTP generates, sends, and saves an OTP .
var ErrOTPCreationFailed = errors.New("otp_creation_failed")

func sendOTP(userID uint, email, mobile string, purpose utils.OTPPurpose) error {
	if email == "" && mobile == "" {
		return errors.New("email or mobile required")
	}
	if email != "" && mobile != "" {
		return fmt.Errorf("only one contact allowed")
	}
	otp := utils.GenerateOTP()
	// expiresAt := time.Now().Add(2 * time.Minute)
	expiresAt := time.Now().Add(time.Duration(config.AppConfig.OTPExpiryMinutes) * time.Minute)
	description := getOTPDescription(purpose)
	otpRecord := models.OTP{
		UserID:      userID,
		Email:       email,
		Mobile:      mobile,
		Code:        otp,
		ExpiresAt:   expiresAt,
		Description: description,
	}
	var user models.User
	if err := database.Database.Db.First(&user, userID).Error; err != nil {
		log.Printf("Failed to fetch user for ID %d: %v", userID, err)
		return errors.New("failed to fetch user")
	}
	username := user.Name
	return database.Database.Db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&otpRecord).Error; err != nil {
			log.Printf("OTP DB create failed: %v", err)
			return ErrOTPCreationFailed
		}

		if email != "" {
			if err := utils.SendOTPEmail(email, username, otp, purpose); err != nil {
			}
		}
		if mobile != "" {
			utils.SendOTPToMobile(mobile, otp, purpose)
		}

		// if mobile != "" {
		// 	if err := utils.SendOTPToMobile(mobile, otp, purpose); err != nil {
		// 		log.Printf("Failed to send OTP Mobile: %v", err)
		// 		return err
		// 	}
		// }
		// if email != "" {
		// 	if err := utils.SendOTPEmail(email, username, otp, purpose); err != nil {
		// 		log.Printf("Failed to send OTP Email: %v", err)
		// 		return err
		// 	}
		// }

		return nil
	})
}

// HELPER FOR verifyOTP verifies an OTP AND, returns OTP and user if valid.
func verifyOTP(code, email, mobile string) (*models.OTP, *models.User, error) {
	if email != "" && mobile != "" {
		return nil, nil, fmt.Errorf("provide either email OR mobile, not both")
	}

	var otpRecord models.OTP

	err := database.Database.Db.Transaction(func(tx *gorm.DB) error {
		query := tx.
			Where("code = ? AND is_used = ? AND is_deleted = ? AND expires_at > ?",
				code, false, false, time.Now()).
			Clauses(clause.Locking{Strength: "UPDATE"})

		if email != "" {
			query = query.Where("email = ?", email)
		} else {
			query = query.Where("mobile = ?", mobile)
		}

		if err := query.First(&otpRecord).Error; err != nil {
			return err
		}

		var user models.User
		if err := tx.First(&user, otpRecord.UserID).Error; err != nil {
			return err
		}

		return tx.Model(&otpRecord).Update("is_used", true).Error
	})

	if err != nil {
		return nil, nil, err
	}

	var user models.User
	if err := database.Database.Db.First(&user, otpRecord.UserID).Error; err != nil {
		return nil, nil, err
	}

	return &otpRecord, &user, nil
}

// HELPER FOR successful login fields and tracks login asynchronously.
func updateLoginSuccess(user *models.User, c *fiber.Ctx) error {
	now := time.Now()
	user.LastLogin = now
	user.FailedLoginAttempts = 0
	// user.IsBlocked = false
	if user.BlockedUntil != nil && user.BlockedUntil.Before(now) {
		user.IsBlocked = false
		user.BlockedUntil = nil
	}
	user.LastFailedLogin = nil
	if err := database.Database.Db.Transaction(func(tx *gorm.DB) error {
		return tx.Save(user).Error
	}); err != nil {
		return err
	}
	// Capture IP and User-Agent
	ip := c.Get("X-Forwarded-For")
	if ip == "" {
		ip = c.IP()
	} else {
		if parts := strings.Split(ip, ","); len(parts) > 0 {
			ip = strings.TrimSpace(parts[0])
		}
	}
	userAgent := c.Get("User-Agent")
	// Asynchronous login tracking
	go func(userID uint, ip, userAgent string, timestamp time.Time) {
		loginTracking := models.LoginTracking{
			UserID:    userID,
			IPAddress: ip,
			Device:    userAgent,
			Timestamp: timestamp,
		}
		if err := database.Database.Db.Create(&loginTracking).Error; err != nil {
			log.Printf("Error saving login tracking: %v", err)
		}
	}(user.ID, ip, userAgent, now)
	return nil
}

// HELPER TO  generates a JWT token for the user.
func generateJWT(user *models.User, platform string) (string, error) {
	return middleware.GenerateJWT(user.ID, user.Name, user.Role, platform)
}

// sanitizeUser removes sensitive fields from user.
func sanitizeUser(user *models.User) {
	user.Password = ""
	// user.ProfileImage = ""
}

// signup handles user registration.
func Signup(c *fiber.Ctx) error {
	reqData := c.Locals("validatedUser").(*struct {
		FirstName   string `json:"firstName"`
		LastName    string `json:"lastName"`
		CountryCode string `json:"countryCode"`
		Mobile      string `json:"mobile"`
		Email       string `json:"email"`
		Password    string `json:"password"`
	})
	// Combine and clean full name
	fullName := strings.TrimSpace(reqData.FirstName + " " + reqData.LastName)
	// Check for existing email or mobile
	var existingUser models.User
	if err := database.Database.Db.
		Where("email = ? OR mobile = ?", reqData.Email, reqData.Mobile).
		First(&existingUser).Error; err == nil {
		if existingUser.Email == reqData.Email {
			return middleware.JsonResponse(c, fiber.StatusConflict, false, "User is already registered!", nil)
		}
		if existingUser.Mobile == reqData.Mobile {
			return middleware.JsonResponse(c, fiber.StatusConflict, false, "User is already registered!", nil)
		}
	}
	// Create user
	user := &models.User{
		Name:         fullName,
		Email:        reqData.Email,
		Mobile:       reqData.Mobile,
		ReferralCode: generateReferralCode(),
	}
	// Hash password
	hashedPassword, err := hashPassword(reqData.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to process your request!", nil)
	}
	user.Password = hashedPassword
	if err := database.Database.Db.Create(user).Error; err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			if strings.Contains(err.Error(), "email") {
				return middleware.JsonResponse(c, fiber.StatusConflict, false, "Email is already registered!", nil)
			}
			if strings.Contains(err.Error(), "mobile") {
				return middleware.JsonResponse(c, fiber.StatusConflict, false, "Mobile number is already registered!", nil)
			}
		}
		log.Printf("Error saving user: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to create user!", nil)
	}
	sanitizeUser(user)
	return middleware.JsonResponse(c, fiber.StatusCreated, true, "User registered successfully.", user)
}

func SignupSendOTP(c *fiber.Ctx) error {
	validated := c.Locals("validatedUser")
	if validated == nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Missing validated user data!", nil)
	}
	reqData := validated.(*struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})
	user, err := getUserByEmailOrMobile(reqData.Email, reqData.Mobile, false)
	if err != nil {
		if reqData.Email != "" {
			return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid email!", nil)
		}
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid mobile!", nil)
	}
	if reqData.Email != "" && user.IsEmailVerified {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Email already verified!", nil)
	}
	if reqData.Mobile != "" && user.IsMobileVerified {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Mobile already verified!", nil)
	}
	// BLOCK sending multiple OTP until previous one expires
	if hasPendingOTP(user.ID, utils.OTPContactVerification) {
		return middleware.JsonResponse(c, fiber.StatusTooManyRequests, false,
			"OTP already sent. Please wait until the previous OTP expires.", nil)
	}
	purpose := utils.OTPContactVerification
	if err := sendOTP(user.ID, reqData.Email, reqData.Mobile, purpose); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent successfully.", nil)
}

func SignupVerifyOTP(c *fiber.Ctx) error {
	validated := c.Locals("validatedUser")
	if validated == nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Missing validated user data!", nil)
	}
	reqData := validated.(*struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})
	otpRecord, user, err := verifyOTP(reqData.Code, reqData.Email, reqData.Mobile)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or mismatched OTP/contact!", nil)
	}
	if otpRecord.Description != getOTPDescription(utils.OTPContactVerification) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP type!", nil)
	}
	// Update user's verification status based on email or mobile
	if reqData.Email != "" {
		user.IsEmailVerified = true
	} else {
		user.IsMobileVerified = true
	}

	if err := database.Database.Db.Transaction(func(tx *gorm.DB) error {
		return tx.Save(user).Error
	}); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update user verification status!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP verified successfully!", nil)
}

// Login handles user login based on platform and OTP AND 2FA.
func Login(c *fiber.Ctx) error {
	reqData := c.Locals("validatedUser").(*struct {
		Mobile   string `json:"mobile"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Platform string `json:"platform"`
	})
	// Validate input
	if reqData.Email == "" && reqData.Mobile == "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Email or mobile is required!", nil)
	}
	if reqData.Email != "" && reqData.Mobile != "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Send OTP to either email OR mobile, not both!", nil)
	}
	user, err := getUserByEmailOrMobile(reqData.Email, reqData.Mobile, true)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or unverified email/mobile!", nil)
	}
	now := time.Now()
	// Reset failed attempts if cooldown passed (moved up before block check)
	if user.LastFailedLogin != nil && time.Since(*user.LastFailedLogin) > 15*time.Minute {
		user.FailedLoginAttempts = 0
		user.LastFailedLogin = nil
	}
	// Check if blocked
	if user.IsBlocked && user.BlockedUntil != nil && user.BlockedUntil.After(now) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Your account is temporarily blocked. Try again later.", nil)
	}
	// Validate password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(reqData.Password)); err != nil {
		user.FailedLoginAttempts++
		user.LastFailedLogin = &now
		if user.FailedLoginAttempts >= 3 {
			user.IsBlocked = true
			unblockTime := now.Add(1 * time.Minute)
			user.BlockedUntil = &unblockTime
		}
		if err := database.Database.Db.Transaction(func(tx *gorm.DB) error {
			return tx.Save(user).Error
		}); err != nil {
			return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Database error!", nil)
		}
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Wrong password!", nil)
	}
	// Check for existing unused login OTP, if none generate and send new one
	if hasPendingOTP(user.ID, utils.OTPLogin) {
		return middleware.JsonResponse(c, fiber.StatusTooManyRequests, false,
			"OTP already sent. Please wait until the previous OTP expires.", nil)
	}
	// No OTP, generate and send new one
	purpose := utils.OTPLogin
	if err := sendOTP(user.ID, reqData.Email, reqData.Mobile, purpose); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP!", nil)
	}
	// Return response indicating OTP sent
	return middleware.JsonResponse(c, 200, true, "Login OTP sent", fiber.Map{
		"otp_sent": true,
		"user_id":  user.ID,
	})
}

func VerifyLoginOTP(c *fiber.Ctx) error {

	reqData := new(struct {
		Mobile   string `json:"mobile"`
		Email    string `json:"email"`
		Code     string `json:"code"`
		Platform string `json:"platform"`
	})
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body!", nil)
	}
	if reqData.Code == "" || (reqData.Email == "" && reqData.Mobile == "") {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid credentials", nil)
	}
	otpRecord, user, err := verifyOTP(reqData.Code, reqData.Email, reqData.Mobile)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP/contact!", nil)
	}
	if otpRecord.Description != getOTPDescription(utils.OTPLogin) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP type!", nil)
	}
	// Now check for 2FA
	if user.IsTwoFAEnabled {
		tempToken, err := middleware.GenerateTempToken(user.ID, "login_2fa")
		if err != nil {
			return middleware.JsonResponse(c, 500, false, "Failed to generate temporary token", nil)
		}

		return middleware.JsonResponse(c, 200, true, "2FA required after OTP", fiber.Map{
			"twofa_required": true,
			"temp_token":     tempToken,
		})
	}

	// No 2FA, proceed to login
	if err := updateLoginSuccess(user, c); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Database error!", nil)
	}
	sanitizeUser(user)
	token, err := generateJWT(user, reqData.Platform)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Error generating JWT token!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Login successful after OTP.", fiber.Map{
		"user":  user,
		"token": token,
	})
}

func LoginVerify2FA(c *fiber.Ctx) error {
	userID := c.Locals("userId").(uint)

	req := c.Locals("validated2FA").(*struct {
		Code     string `json:"code"`
		Platform string `json:"platform"`
	})

	var user models.User
	if err := database.Database.Db.First(&user, userID).Error; err != nil {
		return middleware.JsonResponse(c, 404, false, "User not found", nil)
	}

	secret, err := utils.Decrypt(user.TwoFASecret)
	if err != nil {
		return middleware.JsonResponse(c, 500, false, "Failed to decrypt 2FA secret", nil)
	}

	if !totp.Validate(req.Code, secret) {
		return middleware.JsonResponse(c, 401, false, "Invalid 2FA code", nil)
	}

	// Full login
	if err := updateLoginSuccess(&user, c); err != nil {
		return middleware.JsonResponse(c, 500, false, "Database error", nil)
	}

	sanitizeUser(&user)
	token, err := generateJWT(&user, req.Platform)
	if err != nil {
		return middleware.JsonResponse(c, 500, false, "Token generation failed", nil)
	}

	return middleware.JsonResponse(c, 200, true, "Login successful after 2FA", fiber.Map{
		"user":  user,
		"token": token,
	})
}

// handles a generate , enable and disable of 2FA.
func Generate2FASecret(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)
	var user models.User
	if err := database.Database.Db.First(&user, userId).Error; err != nil {
		return middleware.JsonResponse(c, 400, false, "User not found!", nil)
	}
	if user.IsTwoFAEnabled {
		return middleware.JsonResponse(c, 400, false, "2FA already enabled!", nil)
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      config.AppConfig.AppName,
		AccountName: user.Email,
	})
	if err != nil {
		return middleware.JsonResponse(c, 500, false, "Failed to generate 2FA secret", nil)
	}
	// Store secret temporarily and encrypt the key
	encrypted, err := utils.Encrypt(key.Secret())
	if err != nil {
		log.Printf("2FA encryption failed for user %d: %v", user.ID, err)
		return middleware.JsonResponse(c, 500, false, "Failed to encrypt the 2FA secret", nil)
	}
	user.TwoFASecret = encrypted
	// user.TwoFASecret = key.Secret()

	if err := database.Database.Db.Save(&user).Error; err != nil {
		return middleware.JsonResponse(c, 500, false, "DB Error", nil)
	}
	return middleware.JsonResponse(c, 200, true, "2FA secret generated", fiber.Map{
		"secret": key.Secret(),
		"qr_url": key.URL(),
	})
}

func Enable2FA(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)

	req := new(struct {
		Code string `json:"code"`
	})
	if err := c.BodyParser(req); err != nil {
		return middleware.JsonResponse(c, 400, false, "Invalid request", nil)
	}

	var user models.User
	if err := database.Database.Db.First(&user, userId).Error; err != nil {
		return middleware.JsonResponse(c, 400, false, "User not found", nil)
	}

	if user.TwoFASecret == "" {
		return middleware.JsonResponse(c, 400, false, "2FA not initialized", nil)
	}

	secret, err := utils.Decrypt(user.TwoFASecret)
	if err != nil {
		return middleware.JsonResponse(c, 500, false, "Decrypt 2FA failed", nil)
	}

	if !totp.Validate(req.Code, secret) {
		return middleware.JsonResponse(c, 401, false, "Invalid 2FA code", nil)
	}

	user.IsTwoFAEnabled = true
	if err := database.Database.Db.Save(&user).Error; err != nil {
		return middleware.JsonResponse(c, 500, false, "Error enabling 2FA", nil)
	}

	return middleware.JsonResponse(c, 200, true, "2FA Enabled Successfully", nil)
}

func Disable2FA(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)
	req := new(struct {
		Code string `json:"code"`
	})
	if err := c.BodyParser(req); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Invalid request body", nil)
	}
	var user models.User
	if err := database.Database.Db.First(&user, userId).Error; err != nil {
		return middleware.JsonResponse(c, 400, false, "User not found", nil)
	}
	secret, err := utils.Decrypt(user.TwoFASecret)
	if err != nil {
		log.Printf("Failed to decrypt 2FA secret for user %d: %v", user.ID, err)
		return middleware.JsonResponse(c, 500, false, "Failed to decrypt 2FA secret", nil)
	}
	if !totp.Validate(req.Code, secret) {
		return middleware.JsonResponse(c, 401, false, "Invalid 2FA Code", nil)
	}
	user.IsTwoFAEnabled = false
	user.TwoFASecret = ""
	if err := database.Database.Db.Save(&user).Error; err != nil {
		return middleware.JsonResponse(c, 500, false, "Error disabling 2FA", nil)
	}
	return middleware.JsonResponse(c, 200, true, "2FA Disabled", nil)
}

// handels password change.
func ForgotPasswordSendOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}
	if reqData.Email != "" && reqData.Mobile != "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Send OTP to either email OR mobile, not both!", nil)
	}
	user, err := getUserByEmailOrMobile(reqData.Email, reqData.Mobile, true)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or unverified email/mobile!", nil)
	}
	// BLOCK sending multiple OTP until previous one expires
	if hasPendingOTP(user.ID, "") {
		return middleware.JsonResponse(c, fiber.StatusTooManyRequests, false,
			"OTP already sent. Please wait until the previous OTP expires.", nil)
	}
	purpose := utils.OTPPasswordReset
	if err := sendOTP(user.ID, reqData.Email, reqData.Mobile, purpose); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent successfully.", nil)
}

func ForgotPasswordVerifyOTP(c *fiber.Ctx) error {
	reqData := new(struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}
	otpRecord, user, err := verifyOTP(reqData.Code, reqData.Email, reqData.Mobile)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or mismatched OTP/contact!", nil)
	}
	if otpRecord.Description != getOTPDescription(utils.OTPPasswordReset) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP type!", nil)
	}
	if user == nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
	}
	// Generate temp JWT token
	tempToken, err := middleware.GenerateTempToken(user.ID, "password_reset")
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Error generating JWT token!", nil)
	}
	// Return success response along with the JWT token
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Now You can reset your password.", fiber.Map{
		"temp_token": tempToken,
	})
}

func ResetPassword(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)
	// fmt.Println(userId)
	log.Printf("Reset password requested for user_id=%d", userId)
	reqData := new(struct {
		Password string `json:"password"`
	})
	if err := c.BodyParser(reqData); err != nil {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Failed to parse request body!", nil)
	}
	var user models.User
	result := database.Database.Db.Where("id = ? AND is_deleted = ?", userId, false).First(&user)
	if result.Error != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found or invalid credentials!", nil)
	}
	// Hash the new password
	hashedPassword, err := hashPassword(reqData.Password)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to hash password!", nil)
	}
	// Update the user's password in the database
	user.Password = hashedPassword
	if err := database.Database.Db.Save(&user).Error; err != nil {
		log.Printf("Error updating user password: %v", err)
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update password!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Password reset successfully.", nil)
}

// contact change handels contact from verifying old contact.
func SendOldOTP(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)

	reqData := c.Locals("validatedUser").(*struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
	})
	if reqData.Email != "" && reqData.Mobile != "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Send OTP to either email OR mobile, not both!", nil)
	}
	user, err := getUserByEmailOrMobile(reqData.Email, reqData.Mobile, true)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or unverified email/mobile!", nil)
	}
	if user.ID != userId {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Unauthorized!", nil)
	}
	// Clean up expired or incomplete tracking records
	database.Database.Db.
		Where("user_id = ? AND is_completed = ? AND expires_at <= ?", user.ID, false, time.Now()).
		Delete(&models.ContactChangeTracking{})
	// Check if old contact already verified and session still valid
	var activeTracking models.ContactChangeTracking
	if err := database.Database.Db.
		Where("user_id = ? AND is_old_verified = ? AND is_completed = ? AND expires_at > ?",
			user.ID, true, false, time.Now()).
		First(&activeTracking).Error; err == nil {
		// Old contact already verified but session active
		return middleware.JsonResponse(c, fiber.StatusForbidden, false,
			"Old contact already verified. Active session running — complete new contact verification", nil)
	}
	if hasPendingOTP(user.ID, "") {
		return middleware.JsonResponse(c, fiber.StatusTooManyRequests, false,
			"OTP already sent. Please wait until your previous OTP expires.", nil)
	}
	// Generate OTP
	purpose := utils.OTPVerifyOldContact
	if err := sendOTP(user.ID, reqData.Email, reqData.Mobile, purpose); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP!", nil)
	}
	// Deleteing previous incomplete tracking before creating a new one
	database.Database.Db.
		Where("user_id = ? AND is_completed = ?", user.ID, false).
		Delete(&models.ContactChangeTracking{})
	// create a fresh tracking record so is_old_verified starts false
	tracking := models.ContactChangeTracking{
		UserID:        user.ID,
		OldEmail:      user.Email,
		OldMobile:     user.Mobile,
		IsOldVerified: false,
		IsCompleted:   false,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	database.Database.Db.Create(&tracking)
	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent to old contact", nil)
}

func VerifyOldOTP(c *fiber.Ctx) error {
	userId := c.Locals("userId").(uint)

	reqData := c.Locals("validatedUser").(*struct {
		Mobile string `json:"mobile"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	})
	if reqData.Code == "" || (reqData.Email == "" && reqData.Mobile == "") {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "OTP code and contact (email or mobile) are required!", nil)
	}
	otpRecord, user, err := verifyOTP(reqData.Code, reqData.Email, reqData.Mobile)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or mismatched OTP/contact!", nil)
	}
	if otpRecord.UserID != userId {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP for this user!", nil)
	}
	if otpRecord.Description != getOTPDescription(utils.OTPVerifyOldContact) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP type!", nil)
	}
	if (reqData.Email != "" && reqData.Email != user.Email) ||
		(reqData.Mobile != "" && reqData.Mobile != user.Mobile) {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Provided contact does not match user's registered contact!", nil)
	}

	result := database.Database.Db.Model(&models.ContactChangeTracking{}).
		Where("user_id = ? AND is_completed = ?", otpRecord.UserID, false).
		Order("id DESC").
		Limit(1).
		Updates(map[string]interface{}{
			"is_old_verified": true,
			"expires_at":      time.Now().Add(10 * time.Minute),
		})
	if result.Error != nil {
		log.Printf("Tracking update failed: %v", result.Error)
	} else if result.RowsAffected == 0 {
		log.Printf("No active tracking record found for user %d", otpRecord.UserID)
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "No active session found. Please resend OTP to old contact.", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Old contact verified successfully. You can now verify your new contact within 10 minutes.", nil)
}

func SendNewOTP(c *fiber.Ctx) error {
	userID, ok := c.Locals("userId").(uint)
	if !ok {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized!", nil)
	}
	reqData := c.Locals("validatedNewContact").(*struct {
		NewEmail  string `json:"new_email"`
		NewMobile string `json:"new_mobile"`
	})
	var user models.User
	if err := database.Database.Db.First(&user, userID).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "User not found!", nil)
	}
	if reqData.NewEmail != "" && reqData.NewMobile != "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Send OTP to either email OR mobile, not both!", nil)
	}
	if reqData.NewEmail == "" && reqData.NewMobile == "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "New email or mobile required!", nil)
	}
	// Check for valid old verification session
	var tracking models.ContactChangeTracking
	if err := database.Database.Db.Where("user_id = ? AND is_old_verified = ? AND is_completed = ? AND expires_at > ?", userID, true, false, time.Now()).
		First(&tracking).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusForbidden, false, "Please verify your old contact before sending new OTP or session expired!", nil)
	}
	// Prevent duplicate contacts
	var existingUser models.User
	if reqData.NewEmail != "" && database.Database.Db.Where("email = ?", reqData.NewEmail).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Email already in use!", nil)
	}
	if reqData.NewMobile != "" && database.Database.Db.Where("mobile = ?", reqData.NewMobile).First(&existingUser).Error == nil {
		return middleware.JsonResponse(c, fiber.StatusConflict, false, "Mobile already in use!", nil)
	}
	// Block sending a new OTP if an unused + unexpired OTP exists
	if hasPendingOTP(userID, "") {
		return middleware.JsonResponse(c, fiber.StatusTooManyRequests, false,
			"OTP already sent. Please wait until the previous OTP expires.", nil)
	}
	// Generate OTP
	purpose := utils.OTPVerifyNewContact
	if err := sendOTP(userID, reqData.NewEmail, reqData.NewMobile, purpose); err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to send OTP!", nil)
	}
	return middleware.JsonResponse(c, fiber.StatusOK, true, "OTP sent to new contact.", nil)
}

func VerifyNewOTP(c *fiber.Ctx) error {
	userID, ok := c.Locals("userId").(uint)
	if !ok {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Unauthorized!", nil)
	}
	reqData := c.Locals("validatedNewOTP").(*struct {
		Code      string `json:"code"`
		NewEmail  string `json:"new_email"`
		NewMobile string `json:"new_mobile"`
	})
	if reqData.NewEmail != "" && reqData.NewMobile != "" {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "Send OTP to either email OR mobile, not both!", nil)
	}
	if reqData.Code == "" || (reqData.NewEmail == "" && reqData.NewMobile == "") {
		return middleware.JsonResponse(c, fiber.StatusBadRequest, false, "OTP and new contact required!", nil)
	}
	// Verify OTP using helper
	otpRecord, user, err := verifyOTP(reqData.Code, reqData.NewEmail, reqData.NewMobile)
	if err != nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid or expired OTP!", nil)
	}
	if user == nil {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "User not found!", nil)
	}
	if otpRecord.UserID != userID {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP for this user!", nil)
	}
	if otpRecord.Description != getOTPDescription(utils.OTPVerifyNewContact) {
		return middleware.JsonResponse(c, fiber.StatusUnauthorized, false, "Invalid OTP type!", nil)
	}
	updateFields := map[string]interface{}{}
	if reqData.NewEmail != "" {
		updateFields["email"] = reqData.NewEmail
		updateFields["is_email_verified"] = true
	}
	if reqData.NewMobile != "" {
		updateFields["mobile"] = reqData.NewMobile
		updateFields["is_mobile_verified"] = true
	}
	if err := database.Database.Db.Model(&models.User{}).Where("id = ?", userID).Updates(updateFields).Error; err != nil {
		return middleware.JsonResponse(c, fiber.StatusInternalServerError, false, "Failed to update contact!", nil)
	}
	// Mark tracking as completed
	database.Database.Db.Model(&models.ContactChangeTracking{}).
		Where("user_id = ? AND is_completed = ?", userID, false).
		Updates(map[string]interface{}{
			"is_completed": true,
			"new_email":    reqData.NewEmail,
			"new_mobile":   reqData.NewMobile,
		})
	return middleware.JsonResponse(c, fiber.StatusOK, true, "Contact updated successfully!", nil)
}
