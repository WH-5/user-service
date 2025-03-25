package pkg

import "regexp"

// IsValidPhone 检查字符串是否是有效的手机号（中国大陆）
func IsValidPhone(s string) bool {
	// 手机号正则：以 1 开头，第二位是 3-9，后面 9 位是数字
	regex := `^1[3-9]\d{9}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(s)
}
