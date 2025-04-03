// Package pkg jwt.go
// Author: 王辉
// Created: 2025-03-27 01:40
// 之前没考虑到时区，先默认+8区，以后做国际化的时候加上
// 要把密钥转换成[]byte类型
package pkg

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

// 定义密钥（用于 HMAC 签名）

// GenJwtToken 生成 JWT
func GenJwtToken(userID uint, duration time.Duration, key string) (string, string, error) {
	secretKey := []byte(key)
	// 创建 payload
	session := uuid.NewString()
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(duration).Unix(), // 过期时间
		"session": session,
		"iat":     time.Now().Unix(), // 签发时间
	}

	// 使用 HS256 生成 Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	//签名
	signedString, err := token.SignedString(secretKey)

	return session, signedString, err
}

// ParseToken 解析 JWT，并检查是否过期，同时返回可读的过期时间
func ParseToken(tokenString, key string) (*jwt.Token, error) {

	secretKey := []byte(key)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 确保算法是 HMAC-SHA256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("无效的签名算法: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, err
	}

	// 获取 Claims（载荷）
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token 无效")
	}

	//loc, _ := time.LoadLocation("Asia/Shanghai")
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		//expTime = expTime.In(loc)

		if time.Now().After(expTime) {
			return nil, fmt.Errorf("token 已过期")
		}
	} else {
		return nil, fmt.Errorf("token 缺少 exp 字段")
	}

	return token, nil
}
