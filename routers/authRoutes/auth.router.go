package authRoutes

import (
	controllers "fib/controllers/auth"
	"fib/middleware"
	validators "fib/validators/auth"

	"github.com/gofiber/fiber/v2"
)

func SetupAuthRoutes(app *fiber.App) {
	authGroup := app.Group("/auth")

	authGroup.Post("/signup", validators.Signup(), controllers.Signup)
	authGroup.Post("/send/otp", validators.SendOTP(), controllers.SignupSendOTP)
	authGroup.Patch("/verify/otp", validators.VerifyOTP(), controllers.SignupVerifyOTP)
	authGroup.Post("/login", validators.Login(), controllers.Login)
	authGroup.Post("/login/VerifyLoginOTP", controllers.VerifyLoginOTP)
	authGroup.Post("/login/login-2fa", middleware.TempTokenMiddleware("login_2fa"), validators.Login2FA(), controllers.LoginVerify2FA)

	authGroup.Post("/forgot/password/send/otp", validators.SendOTP(), controllers.ForgotPasswordSendOTP)
	authGroup.Patch("/forgot/password/verify/otp", validators.VerifyOTP(), controllers.ForgotPasswordVerifyOTP)
	authGroup.Patch("/reset/password", validators.ResetPassword(), middleware.TempTokenMiddleware("password_reset"), controllers.ResetPassword)

	authGroup.Get("generate-2fa", middleware.JWTMiddleware, controllers.Generate2FASecret)
	authGroup.Post("enable-2fa", middleware.JWTMiddleware, controllers.Enable2FA)
	authGroup.Post("disable-2fa", middleware.JWTMiddleware, controllers.Disable2FA)

	authGroup.Post("/change-mobile-email/send-old-otp", middleware.JWTMiddleware, validators.SendOTP(), controllers.SendOldOTP)
	authGroup.Post("/change-mobile-email/verify-old-otp", middleware.JWTMiddleware, validators.VerifyOTP(), controllers.VerifyOldOTP)
	authGroup.Post("/change-mobile-email/send-new-otp", middleware.JWTMiddleware, validators.ValidateNewContact(), controllers.SendNewOTP)
	authGroup.Post("/change-mobile-email/verify-new-otp", middleware.JWTMiddleware, validators.ValidateNewContactOTP(), controllers.VerifyNewOTP)

}
