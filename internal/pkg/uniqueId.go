// Package pkg uniqueId.go
// Author: 王辉
// Created: 2025-03-25 11:29
// 唯一id只能由字母数字及横线组成

package pkg

import (
	"crypto/rand"
	"math/big"
	"regexp"
)

const (
	charSet              = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	uniqueIdRegex        = "^[a-zA-Z0-9_-]{1,20}$"
	UNIQUE_ID_BIG_LENGTH = 10
)

// CheckUniqueIdIsValid 检查id格式
func CheckUniqueIdIsValid(id string) bool {
	re := regexp.MustCompile(uniqueIdRegex)
	return re.MatchString(id)
}

// GenUniqueId 生成id
func GenUniqueId(n int32) string {
	a := make([]byte, n)
	b := len(charSet)
	for i := range a {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(b)))
		if err != nil {
			panic(err)
		}
		a[i] = charSet[index.Int64()]
	}
	return string(a)
}
