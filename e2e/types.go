package e2e

import (
	"fmt"
)

func NewInitMsg(admin string, consumerID string, isEnabled bool) string {
	initMsg := fmt.Sprintf(`{"admin":"%s","consumer_id":"%s","is_enabled":%t}`, admin, consumerID, isEnabled)
	return initMsg
}

type Config struct {
	ConsumerID string `json:"consumer_id"`
}
