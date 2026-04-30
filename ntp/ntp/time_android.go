//go:build android

// meta-improve
package ntp

import (
	"os"
	"time"
)

func setSystemTime(nowTime time.Time) error {
	return os.ErrInvalid
}
