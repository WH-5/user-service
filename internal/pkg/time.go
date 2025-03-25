package pkg

import "time"

// 计算今天晚上 0 点的时间戳
func getMidnightTimestamp() time.Time {
	now := time.Now()
	midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	return midnight
}
