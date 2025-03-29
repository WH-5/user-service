// Package data pgsql.go
// Author: 王辉
// Created: 2025-03-18 00:55
// 每次启动前都要做一遍自动迁移，会影响启动速度，以后可以做一下优化
// 原定的五个表删减至3个表

package data

import (
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
	"time"
)

// UserAccount 表示用户信息
type UserAccount struct {
	gorm.Model
	Phone          string `gorm:"unique;not null"` // 用户注册手机号，唯一且不能为空
	UniqueID       string `gorm:"unique;not null"` // 用户唯一 ID，唯一且不能为空
	PasswordHash   string `gorm:"not null"`        // 加密后的密码
	FailedAttempts int    `gorm:"default:0"`       // 登录失败次数，默认值 0
}

// UserProfile 表示用户的个人资料
type UserProfile struct {
	gorm.Model
	UserID   uint       `gorm:"not null"`           // 关联用户 ID
	Nickname string     `gorm:"size:100;not null"`  // 用户昵称，不能为空，长度 2-30 个字符
	Bio      string     `gorm:"size:255"`           // 用户简介，长度不超过 200 字符
	Gender   int        `gorm:"default:0"`          // 性别，0：未知，1：男，2：女
	Birthday *time.Time `gorm:"default:2002-07-29"` // 生日，格式为 YYYY-MM-DD
	Location string     `gorm:"size:100"`           // 用户位置，如国家/城市信息
	Other    string     `gorm:"size:255"`           // 个人网站或社交媒体链接
}

//// UserDevice 表示用户的设备信息
//type UserDevice struct {
//	gorm.Model
//	UserID   uint   `gorm:"not null"`          // 关联用户 ID
//	DeviceID string `gorm:"size:255;not null"` // 设备唯一标识符
//}
//发现这个表没啥用，取消了

// UserBehaviorLog 表示用户的行为日志
type UserBehaviorLog struct {
	gorm.Model
	UserID   uint            `gorm:"not null"`          // 关联用户 ID
	Action   string          `gorm:"size:255;not null"` // 用户执行的行为
	Metadata json.RawMessage `gorm:"type:jsonb"`        // 行为的相关数据 0注册、1登录、2其他
}

// MigrateDB 负责数据库迁移
func MigrateDB(db *gorm.DB) error {
	// 执行自动迁移
	err := db.AutoMigrate(&UserAccount{}, &UserProfile{}, &UserBehaviorLog{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	// 添加字段注释
	err = addFieldComments(db)
	if err != nil {
		return fmt.Errorf("failed to add field comments: %w", err)
	}
	return nil
}

// addFieldComments 为每个字段添加注释
func addFieldComments(db *gorm.DB) error {
	queries := []string{
		"COMMENT ON COLUMN user_accounts.phone IS '用户注册手机号，唯一且不能为空'",
		"COMMENT ON COLUMN user_accounts.unique_id IS '用户唯一 ID，唯一且不能为空'",
		"COMMENT ON COLUMN user_accounts.password_hash IS '加密后的密码'",
		"COMMENT ON COLUMN user_accounts.failed_attempts IS '登录失败次数，默认值 0'",
		"COMMENT ON COLUMN user_profiles.user_id IS '关联用户 ID'",
		"COMMENT ON COLUMN user_profiles.nickname IS '用户昵称，不能为空，长度 2-30 个字符'",
		"COMMENT ON COLUMN user_profiles.bio IS '用户简介，长度不超过 200 字符'",
		"COMMENT ON COLUMN user_profiles.gender IS '性别，0：未知，1：男，2：女'",
		"COMMENT ON COLUMN user_profiles.birthday IS '生日，格式为 YYYY-MM-DD'",
		"COMMENT ON COLUMN user_profiles.location IS '用户位置，如国家/城市信息'",
		"COMMENT ON COLUMN user_profiles.other IS '个人网站或社交媒体链接'",
		//"COMMENT ON COLUMN user_devices.user_id IS '关联用户 ID'",
		//"COMMENT ON COLUMN user_devices.device_id IS '设备唯一标识符'",
		"COMMENT ON COLUMN user_behavior_logs.user_id IS '关联用户 ID'",
		"COMMENT ON COLUMN user_behavior_logs.action IS '用户执行的行为 0注册、1登录、2其他'",
		"COMMENT ON COLUMN user_behavior_logs.metadata IS '行为的相关数据'",
	}

	for _, query := range queries {
		result := db.Exec(query)
		if result.Error != nil {

			return result.Error
		}
	}
	return nil
}
