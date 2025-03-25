package pkg

import "time"

// GetMidnightTimestamp 计算今天晚上 0 点的时间戳
func GetMidnightTimestamp() time.Time {
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	return midnight
}
