package data

import (
	"github.com/WH-5/user-service/internal/conf"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewUserRepo)

// Data .
type Data struct {
	DB *gorm.DB
	RD *redis.Client
	OT Other
}
type Other struct {
	RegisterLimit                     int32
	MaxFailedLoginAttempts            int32
	AccountLockDurationMinutes        int32
	PasswordModifyLockDurationMinutes int32
}

// NewData .
func NewData(c *conf.Data, logger log.Logger) (*Data, func(), error) {
	//time.Sleep(10 * time.Minute)
	// 不做其他数据库的适配了，只做pgsql
	db, err := gorm.Open(postgres.Open(c.Database.Source), &gorm.Config{})
	if err != nil {
		return nil, nil, err
	}
	err = MigrateDB(db)
	if err != nil {
		return nil, nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         c.Redis.Addr,
		Password:     c.Redis.Password,
		DB:           int(c.Redis.Database),
		DialTimeout:  c.Redis.DialTimeout.AsDuration(),
		WriteTimeout: c.Redis.WriteTimeout.AsDuration(),
		ReadTimeout:  c.Redis.ReadTimeout.AsDuration(),
	})
	cleanup := func() {
		logHelper := log.NewHelper(logger)
		logHelper.Info("closing the data resources")

		sqlDB, err := db.DB()
		if err != nil {
			logHelper.Errorf("failed to get SQL DB: %v", err)
			return
		}

		// 关闭数据库连接并检查错误
		if err := sqlDB.Close(); err != nil {
			logHelper.Errorf("failed to close SQL DB: %v", err)
		}
		if err := rdb.Close(); err != nil {
			logHelper.Errorf("failed to close Redis DB: %v", err)
		}
	}

	return &Data{DB: db, RD: rdb,
		OT: Other{RegisterLimit: c.Other.GetRegisterLimitEverydeviceEveryday(),
			MaxFailedLoginAttempts:            c.Other.GetMaxFailedLoginAttempts(),
			AccountLockDurationMinutes:        c.Other.AccountLockDurationMinutes,
			PasswordModifyLockDurationMinutes: c.Other.PasswordModifyLockDurationMinutes,
		}}, cleanup, nil
}
