package models

import "time"

type User struct {
	UserID              int       `gorm:"primaryKey;autoIncrement" json:"user_id"`
	Name                string    `gorm:"type:varchar(100);not null" json:"name"`
	Email               string    `gorm:"type:varchar(255);unique;not null" json:"email"`
	PasswordHash        string    `gorm:"type:varchar(255);not null" json:"password_hash"`
	FailedLoginAttempts int       `gorm:"not null;default:0" json:"failed_login_attempts"`
	AccountLocked       bool      `gorm:"type:tinyint(1);not null;default:0" json:"account_locked"`
	AvatarURL           *string   `gorm:"type:varchar(255)" json:"avatar_url,omitempty"`
	RegistrationDate    time.Time `gorm:"type:timestamp;not null;default:current_timestamp()" json:"registration_date"`
}
