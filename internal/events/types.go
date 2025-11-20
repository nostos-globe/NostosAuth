package events

import "time"

type AuthLoginEvent struct {
	UserID    uint      `json:"userId"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"userAgent"`
	At        time.Time `json:"at"`
}
