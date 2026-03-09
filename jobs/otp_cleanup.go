package jobs

import (
	"log"
	"time"

	"fib/database"
	"fib/models"

	"github.com/robfig/cron/v3"
)

// StartOTPCleanupJob runs a background cron job to delete expired OTPs.
func StartOTPCleanupJob() {
	c := cron.New()

	_, err := c.AddFunc("@every 10m", func() {
		now := time.Now()

		// Delete OTPs that have expired
		result := database.Database.Db.
			Where("expires_at <= ?", now).
			Delete(&models.OTP{})

		if result.Error != nil {
			log.Printf("[OTP Cleanup] Error: %v", result.Error)
			return
		}

		if result.RowsAffected > 0 {
			log.Printf("[OTP Cleanup] Deleted %d expired OTP(s)", result.RowsAffected)
		}
	})

	if err != nil {
		log.Fatalf("[OTP Cleanup] Failed to schedule job: %v", err)
	}

	c.Start()
	log.Println("[OTP Cleanup] Job started — runs every 10 minutes.")
}
