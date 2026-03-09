package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	ReferralCode        string     `gorm:"unique;not null"` // For referral
	ProfileImage        string     `gorm:"default:''"`
	Name                string     `gorm:"default:''"`
	Email               string     `gorm:"unique;not null"`
	Mobile              string     `gorm:"unique;default:''"`
	Role                string     `gorm:"default:'USER'"` // Default role is USER
	Password            string     `gorm:"not null"`
	BankDetails         uint       `gorm:"foreignKey:BankID"` // Corrected foreign key reference
	UserKYC             uint       `gorm:"foreignKey:KycID"`  // Corrected foreign key reference
	IsMobileVerified    bool       `gorm:"default:false"`
	IsEmailVerified     bool       `gorm:"default:false"`
	LastLogin           time.Time  `gorm:"default:NULL"`
	IsTwoFAEnabled      bool       `json:"is_twofa_enabled" gorm:"default:false"`
	TwoFASecret         string     `json:"-"`
	FailedLoginAttempts int        `gorm:"default:0"`
	LastFailedLogin     *time.Time `json:"last_failed_login"`
	IsBlocked           bool       `gorm:"default:false"`
	BlockedUntil        *time.Time `json:"blocked_until"`
	IsDeleted           bool       `gorm:"default:false"`
}

type ContactChangeTracking struct {
	gorm.Model
	UserID        uint      `gorm:"foreignKey:UserID"`
	OldEmail      string    `gorm:"default:''"`
	NewEmail      string    `gorm:"default:''"`
	OldMobile     string    `gorm:"default:''"`
	NewMobile     string    `gorm:"default:''"`
	IsOldVerified bool      `gorm:"default:false"`
	IsCompleted   bool      `gorm:"default:false"`
	ExpiresAt     time.Time `gorm:"not null" json:"expires_at"`
	ChangedAt     time.Time `gorm:"autoCreateTime"`
	IPAddress     string    `json:"ip_address"`
	Device        string    `json:"device"`
}
