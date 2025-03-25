// Package data redis.go
// Author: 王辉
// Created: 2025-03-25 22:23
// 给redis客户端加几个方法，方便存取
package data

import (
	"context"
	"errors"
	"github.com/go-redis/redis/v8"
	"time"
)

var ctx = context.Background()

// 设置键值对
func (d *Data) setKey(key string, value string, expiration time.Duration) error {
	rdb := d.RD

	err := rdb.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return err
	}
	return nil
}

// 获取键值
func (d *Data) getValue(key string) (string, error) {
	rdb := d.RD
	val, err := rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	} else if err != nil {
		return "", err
	} else {
		return val, nil
	}
}

// 删除键
func (d *Data) deleteKey(key string) {
	rdb := d.RD
	err := rdb.Del(ctx, key).Err()
	if err != nil {

	}

}
