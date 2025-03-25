package data

import (
	"context"
	"github.com/WH-5/user-service/internal/biz"
	"github.com/WH-5/user-service/internal/pkg"
	"github.com/go-kratos/kratos/v2/log"
	"strconv"
)

type userRepo struct {
	data *Data
	log  *log.Helper
}

func (u *userRepo) CheckPhone(ctx context.Context, phone string) (bool, error) {
	//查这个手机号是否注册过，是就返回true
	var count int64
	result := u.data.DB.Model(&UserAccount{}).Where("phone = ?", phone).Count(&count)
	if err := result.Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (u *userRepo) CheckDeviceId(ctx context.Context, deviceId string) (bool, error) {
	//到缓存中查找这个device id，键值对：<deviceId:device id,times> <string,int>
	v, err := u.data.getValue("deviceId:" + deviceId)
	if err != nil {
		return false, err
	}
	if v == "" {
		return true, nil
	}
	intv, err := strconv.Atoi(v)
	if err != nil {
		return false, err
	}
	if int32(intv) >= u.data.OT.RegisterLimit {
		return false, nil
	}
	return true, nil
}

func (u *userRepo) SaveAccount(ctx context.Context, phone, uniqueId, hashPwd, deviceId string) error {
	// 存入数据库，并且在缓存中留下注册记录
	ua := &UserAccount{
		Phone:        phone,
		UniqueID:     uniqueId,
		PasswordHash: hashPwd,
	}
	result := u.data.DB.Create(&ua)
	if err := result.Error; err != nil {
		return err
	}
	DI := "deviceId:" + deviceId
	err := u.data.setKey(DI, "1", 0)
	if err != nil {
		return err
	}
	expiredAt := pkg.GetMidnightTimestamp()
	err = u.data.RD.ExpireAt(ctx, DI, expiredAt).Err()
	return nil
}

func (u *userRepo) WriteLog(ctx context.Context) error {
	//TODO implement me
	panic("implement me")
}

func NewUserRepo(data *Data, logger log.Logger) biz.UserRepo {
	return &userRepo{data: data, log: log.NewHelper(logger)}
}

var _ biz.UserRepo = (*userRepo)(nil)
