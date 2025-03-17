package data

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"user-service/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(NewData, NewGreeterRepo, NewUserRepo)

// Data .
type Data struct {
	DB *gorm.DB
}

// NewData .
func NewData(c *conf.Data, logger log.Logger) (*Data, func(), error) {
	// 不做其他数据库的适配了，只做pgsql
	db, err := gorm.Open(postgres.Open(c.Database.Source), &gorm.Config{})
	if err != nil {
		return nil, nil, err
	}
	MigrateDB(db)
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
	}
	return &Data{DB: db}, cleanup, nil
}
