package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"fib/config"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
)

type OTPPurpose string

const (
	OTPLogin               OTPPurpose = "login"
	OTPContactVerification OTPPurpose = "contact_verification"
	OTPPasswordReset       OTPPurpose = "password_reset"
	OTPVerifyOldContact    OTPPurpose = "verify_old_contact"
	OTPVerifyNewContact    OTPPurpose = "verify_new_contact"
)

func GenerateOTP() string {

	var otp [6]byte

	for i := range otp {

		n, err := rand.Int(rand.Reader, big.NewInt(10))

		if err != nil {

			log.Printf("crypto rand error: %v", err)

			h := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", time.Now().UnixNano(), i)))

			otp[i] = '0' + (h[i] % 10)

		} else {

			otp[i] = byte(n.Int64()) + '0'

		}

	}

	return string(otp[:])

}

func SendOTPToMobile(mobile, otp string, purpose OTPPurpose) error {

	message := buildOTPSMS(purpose, otp)

	params := url.Values{}
	params.Set("apikey", config.AppConfig.AOCSmsApiKey)
	params.Set("type", "TRANS")
	params.Set("text", message)
	params.Set("to", mobile)
	params.Set("sender", config.AppConfig.AOCSmsSender)

	apiURL := fmt.Sprintf("%s?%s", config.AppConfig.AOCSmsApiURL, params.Encode())

	resp, err := http.Get(apiURL)

	if err != nil {

		log.Println("SMS send error:", err)

		return err

	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		log.Println("SMS failed:", resp.StatusCode)

		return fmt.Errorf("failed to send SMS")

	}

	log.Printf("OTP SMS sent to %s (%s)", mobile, purpose)

	return nil

}

func buildOTPSMS(purpose OTPPurpose, otp string) string {

	expiry := config.AppConfig.OTPExpiryMinutes

	switch purpose {

	case OTPPasswordReset:

		return fmt.Sprintf(
			"Use OTP %s to reset your User password. Valid for %d minutes. Do not share.",
			otp, expiry,
		)

	case OTPLogin:

		return fmt.Sprintf(
			"Your User login OTP is %s. Valid for %d minutes. Do not share.",
			otp, expiry,
		)

	case OTPVerifyOldContact:

		return fmt.Sprintf(
			"Verify your old contact with OTP %s for User account update. Valid for %d minutes.",
			otp, expiry,
		)

	case OTPVerifyNewContact:

		return fmt.Sprintf(
			"Verify your new contact with OTP %s for User account update. Valid for %d minutes.",
			otp, expiry,
		)

	case OTPContactVerification:

		return fmt.Sprintf(
			"OTP for User app registration is %s. Do not share it with anyone.",
			otp,
		)

	default:

		return fmt.Sprintf(
			"Your User OTP is %s. Valid for %d minutes.",
			otp, expiry,
		)

	}

}

const EmailTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f4f4;padding:30px 0;font-family:Arial, sans-serif;">
<tr>
<td align="center">

<table width="500" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;padding:30px;">

<tr>
<td align="center">
<h2>{purpose}</h2>
</td>
</tr>

<tr>
<td>

<p>Hello {userid},</p>

<p>Your One Time Password (OTP) is:</p>

<p style="font-size:30px;font-weight:bold;text-align:center;letter-spacing:6px;">
{code}
</p>

<p>This OTP expires in <b>{expiry} minutes</b>.</p>

<p>Please do not share this code with anyone.</p>

<p>If you did not request this, please ignore this email.</p>

<br>

<p>Regards,<br>
<b>User Team</b></p>

</td>
</tr>

<tr>
<td style="text-align:center;font-size:13px;color:#777;padding-top:20px;border-top:1px solid #eee;">

Need help? contact support@user.com

<br><br>

© 2026 User. All rights reserved.

</td>
</tr>

</table>

</td>
</tr>
</table>
`

func SendOTPEmail(email, username, otp string, purpose OTPPurpose) error {

	subject, plain, html := buildOTPEmail(username, purpose, otp)

	from := mail.NewEmail(
		config.AppConfig.SendgridSenderName,
		config.AppConfig.SendgridSenderMail,
	)

	to := mail.NewEmail("", email)

	message := mail.NewSingleEmail(from, subject, to, plain, html)

	client := sendgrid.NewSendClient(config.AppConfig.SendgridApiKey)

	response, err := client.Send(message)

	if err != nil {

		log.Println("Email send error:", err)

		return err

	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {

		log.Println("Email failed:", response.StatusCode, response.Body)

		return fmt.Errorf("failed to send email")

	}

	log.Printf("OTP email sent to %s (%s)", email, purpose)

	return nil

}

func buildOTPEmail(username string, purpose OTPPurpose, otp string) (subject, plain, html string) {

	expiry := config.AppConfig.OTPExpiryMinutes

	expiryStr := fmt.Sprintf("%d", expiry)

	purposeDisplay := ""

	switch purpose {

	case OTPPasswordReset:

		subject = "Reset Your Password"
		purposeDisplay = "Reset Your Password"

	case OTPLogin:

		subject = "User Login Verification"
		purposeDisplay = "User Login Verification"

	case OTPVerifyOldContact:

		subject = "Verify Old Contact"
		purposeDisplay = "Verify Old Contact"

	case OTPVerifyNewContact:

		subject = "Verify New Contact"
		purposeDisplay = "Verify New Contact"

	case OTPContactVerification:

		subject = "Verify Your Email"
		purposeDisplay = "Verify Your Email"

	default:

		subject = "Your OTP Code"
		purposeDisplay = "Your OTP Code"

	}

	plain = fmt.Sprintf(
		"Hello %s,\n\nYour OTP is %s.\nIt expires in %d minutes.\n\nIf you didn't request this please ignore this email.",
		username,
		otp,
		expiry,
	)

	html = strings.ReplaceAll(EmailTemplate, "{purpose}", purposeDisplay)
	html = strings.ReplaceAll(html, "{userid}", username)
	html = strings.ReplaceAll(html, "{expiry}", expiryStr)
	html = strings.ReplaceAll(html, "{code}", otp)

	return

}
