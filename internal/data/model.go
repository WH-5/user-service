// user-service – data/model.go
// Author: 王辉
// Created: 2025-03-18 00:55
// 每次启动前都要做一遍自动迁移，肯定会影响启动速度，以后可以做一下优化

package data

import (
	"fmt"
	"gorm.io/gorm"
	"time"
)

// User 表示用户信息
type User struct {
	gorm.Model
	Phone          string     `gorm:"unique;not null"` // 用户注册手机号，唯一且不能为空
	UniqueID       string     `gorm:"unique;not null"` // 用户唯一 ID，唯一且不能为空
	PasswordHash   string     `gorm:"not null"`        // 加密后的密码
	FailedAttempts int        `gorm:"default:0"`       // 登录失败次数，默认值 0
	LockedUntil    *time.Time `gorm:"default:NULL"`    // 锁定到期时间，仅在账户被锁定时有效
}

// UserProfile 表示用户的个人资料
type UserProfile struct {
	gorm.Model
	UserID   uint       `gorm:";not null"`         // 关联用户 ID，主键
	Nickname string     `gorm:"size:100;not null"` // 用户昵称，不能为空，长度 2-30 个字符
	Bio      string     `gorm:"size:255"`          // 用户简介，长度不超过 200 字符
	Gender   int        `gorm:"default:0"`         // 性别，0：未知，1：男，2：女
	Birthday *time.Time `gorm:"default:NULL"`      // 生日，格式为 YYYY-MM-DD
	Location string     `gorm:"size:100"`          // 用户位置，如国家/城市信息
	Website  string     `gorm:"size:255"`          // 个人网站或社交媒体链接
}

// UserDevice 表示用户的设备信息
type UserDevice struct {
	gorm.Model
	UserID   uint   `gorm:"not null"`          // 关联用户 ID
	DeviceID string `gorm:"size:255;not null"` // 设备唯一标识符
}

// UserBehaviorLog 表示用户的行为日志
type UserBehaviorLog struct {
	gorm.Model
	UserID   uint   `gorm:"not null"`          // 关联用户 ID
	Action   string `gorm:"size:255;not null"` // 用户执行的行为
	Metadata string `gorm:"size:255"`          // 行为的相关数据
}

// MessageLimit 表示用户消息发送的限制
type MessageLimit struct {
	gorm.Model
	UserID       uint      `gorm:"not null"`                  // 关联用户 ID
	DeviceID     string    `gorm:"size:255;not null"`         // 设备唯一标识符
	MessageCount int       `gorm:"default:0"`                 // 当日消息发送数量
	LastReset    time.Time `gorm:"default:CURRENT_TIMESTAMP"` // 上次重置时间
}

// MigrateDB 负责数据库迁移
func MigrateDB(db *gorm.DB) error {

	// 执行自动迁移
	err := db.AutoMigrate(&User{}, &UserProfile{}, &UserDevice{}, &UserBehaviorLog{}, &MessageLimit{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}
	// 添加字段注释
	addFieldComments(db)
	return nil
}

// addFieldComments 为每个字段添加注释
func addFieldComments(db *gorm.DB) {
	db.Exec("COMMENT ON COLUMN users.phone IS '用户注册手机号，唯一且不能为空'")
	db.Exec("COMMENT ON COLUMN users.unique_id IS '用户唯一 ID，唯一且不能为空'")
	db.Exec("COMMENT ON COLUMN users.password_hash IS '存储加密后的密码'")
	db.Exec("COMMENT ON COLUMN users.failed_attempts IS '记录连续失败的登录尝试次数'")
	db.Exec("COMMENT ON COLUMN users.locked_until IS '账户锁定到期时间，仅在被锁定时有效'")
	db.Exec("COMMENT ON COLUMN user_profiles.nickname IS '用户昵称，不能为空，长度 2-30 个字符'")
	db.Exec("COMMENT ON COLUMN user_profiles.bio IS '用户简介，长度不超过 200 字符'")
	db.Exec("COMMENT ON COLUMN user_profiles.gender IS '性别，0：未知，1：男，2：女'")
	db.Exec("COMMENT ON COLUMN user_profiles.birthday IS '生日，格式为 YYYY-MM-DD'")
	db.Exec("COMMENT ON COLUMN user_profiles.location IS '用户位置，如国家/城市信息'")
	db.Exec("COMMENT ON COLUMN user_profiles.website IS '个人网站或社交媒体链接'")
	db.Exec("COMMENT ON COLUMN user_devices.device_id IS '设备唯一标识符'")
	db.Exec("COMMENT ON COLUMN user_behavior_logs.action IS '用户执行的行为'")
	db.Exec("COMMENT ON COLUMN user_behavior_logs.metadata IS '行为的相关数据'")
	db.Exec("COMMENT ON COLUMN message_limits.device_id IS '设备唯一标识符'")
	db.Exec("COMMENT ON COLUMN message_limits.message_count IS '当日消息发送数量'")
}
