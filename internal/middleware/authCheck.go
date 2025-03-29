// Package middleware authCheck.go
// Author: 王辉
// Created: 2025-03-29 01:36
// 不信任jwt token  需要且只用token进行数据库二次校验 使用接口body里传的身份信息进行操作
package middleware

import (
	"context"
	"fmt"
	"github.com/WH-5/user-service/internal/pkg"
	"github.com/WH-5/user-service/internal/service"
	"github.com/golang-jwt/jwt/v5"
	"log"
	"strings"

	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

// AuthCheckExist 检查token是否可用 可用会在上下文携带token和用户id
func AuthCheckExist(userService *service.UserService) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			log.Println("auth middleware in", req)

			// 从上下文中获取请求头
			if tr, ok := transport.FromServerContext(ctx); ok {
				authHeader := tr.RequestHeader().Get("Authorization")
				if authHeader == "" {
					return nil, fmt.Errorf("missing authorization header")
				}

				// 解析 Bearer Token
				tokenString := strings.TrimPrefix(authHeader, "Bearer ")
				token, err := pkg.ParseToken(tokenString, userService.UC.CF.JWT_SECRET_KEY)
				if err != nil {
					return nil, err
				}
				if err != nil || !token.Valid {

					return nil, fmt.Errorf("token 无效:%v", err)
				}
				claims, ok := token.Claims.(jwt.MapClaims)
				if !ok {
					//fmt.Println(")
					return nil, fmt.Errorf("无法解析 Claims")
				}
				//把用户ID和token放入上下文
				uid := claims["user_id"]
				//有个坑，从claims里读到的int类型，会转变为float64类型
				ctx = context.WithValue(ctx, "user_id", uid)
				ctx = context.WithValue(ctx, "token", token)

			}

			// 调用下一个处理程序
			reply, err = handler(ctx, req)
			//fmt.Println("auth middleware out", reply)
			return reply, err
		}
	}

}
