// Package data user.go
// Author: 王辉
// Created: 2025-03-30 00:29
// 缓存中键的前缀
// deviceId:限制设备注册次数
// userId:限制连续登录
// uniqueUserId:限制修改uniqueId
package data

import (
	"context"
	"errors"
	"fmt"
	"github.com/WH-5/user-service/internal/biz"
	"github.com/WH-5/user-service/internal/pkg"
	"github.com/go-kratos/kratos/v2/log"
	"gorm.io/gorm"
	"math"
	"strconv"
	"time"
)

type userRepo struct {
	data *Data
	log  *log.Helper
}

func (u *userRepo) RecordModifyUniqueIdOnRedis(ctx context.Context, uid string) error {

	//存到缓存
	k := "uniqueUserId:" + uid
	err := u.data.setKey(k, "", 0)
	if err != nil {
		return err
	}
	expiredAt := pkg.GetMidnightTimestamp()
	err = u.data.RD.ExpireAt(ctx, k, expiredAt).Err()
	if err != nil {
		return err
	}
	return nil
}

// CheckUniqueUpdate true为这个id可以更新
func (u *userRepo) CheckUniqueUpdate(ctx context.Context, uniqueId string) (uint, error) {
	//根据userid检查今天更新情况 没错就是能用

	//获取userid
	userId, err := u.findUserId("unique_id", uniqueId)
	if err != nil {
		return 0, err
	}

	//到缓存里查询
	uid := strconv.FormatUint(uint64(userId), 10)
	have, err := u.data.RD.Exists(ctx, "uniqueUserId:"+uid).Result()
	if err != nil {
		return 0, err
	}
	if have > 0 {
		return 0, errors.New("unique id today has already been modified")
	}
	return userId, nil
}

// CheckUniqueValid true为这个id可以用
func (u *userRepo) CheckUniqueValid(ctx context.Context, uniqueId string) (bool, error) {
	//检查uniqueId格式 (3月30日更新了接口参数校验，基本不用校验了)
	valid := pkg.CheckUniqueIdIsValid(uniqueId)
	if !valid {
		return false, errors.New("invalid uniqueId")
	}
	//检查uniqueId存在情况
	var exist bool
	err := u.data.DB.Model(&UserAccount{}).Where("unique_id=?", uniqueId).Scan(&exist).Error
	if err != nil {
		return false, err
	}
	return !exist, nil
}

func (u *userRepo) UpdateUniqueId(ctx context.Context, uniqueId, newUniqueId string) error {

	//修改数据库的unique ID
	result := u.data.DB.Model(&UserAccount{}).Where("unique_id=?", uniqueId).Update("unique_id", newUniqueId)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("系统不崩遇不到这个错")
	}
	return nil
}

func (u *userRepo) UpdateProfile(ctx context.Context, uniqueId string, profileMap map[string]any) error {

	userId, err := u.findUserId("unique_id", uniqueId)
	if err != nil {
		return err
	}
	result := u.data.DB.Model(&UserProfile{}).Where("user_id = ?", userId).Updates(profileMap)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func (u *userRepo) CheckUser(ctx context.Context, field, account string) (bool, error) {
	uidValue := ctx.Value("user_id")
	uid, ok := uidValue.(float64)
	if !ok {
		return false, errors.New("invalid or missing user_id in context")
	}
	userId, err := u.findUserId(field, account)
	if err != nil {
		return false, err
	}
	if userId == uint(uid) {
		return true, nil
	}
	return false, nil
}

func (u *userRepo) VerifyUserAuth(ctx context.Context, field, account, password string) (bool, uint, error) {
	//验证账号密码是否正确,如果正确，返回用户id
	userId, err := u.findUserId(field, account)
	if err != nil {
		return false, 0, err
	}
	var hpwd string
	result := u.data.DB.Model(&UserAccount{}).Select("password_hash").Where("id=?", userId).Scan(&hpwd)
	if result.Error != nil {
		return false, 0, result.Error
	}
	//验证密码
	isMatch := pkg.CheckPassword(hpwd, password)
	if !isMatch {
		return false, 0, nil
	}
	return true, userId, nil
}

func (u *userRepo) CanLogin(ctx context.Context, field, account string) (bool, int, error) {
	//检查是否允许登录 到缓存里查这个
	userId, err := u.findUserId(field, account)
	if err != nil {
		return false, 0, err
	}
	value, err := u.data.getValue("userId:" + fmt.Sprintf("%d", userId))
	if err != nil {
		// 取报错
		return false, 0, err
	} else if value == "" {
		//缓存里没有这个值
		return true, 0, nil
	}
	va, err := strconv.Atoi(value)
	if err != nil {
		return false, 0, err
	}
	if int32(va) < u.data.OT.MaxFailedLoginAttempts {
		return true, 0, nil
	}
	ttl := u.data.RD.TTL(ctx, "userId:"+fmt.Sprintf("%d", userId)).Val()
	t := int(math.Ceil(ttl.Minutes()))
	return false, t, nil
}
func (u *userRepo) findUserId(field, account string) (uint, error) {
	//如果没找到，直接返回账号不存在
	var userId uint
	q := field + " = ?"
	result := u.data.DB.Model(&UserAccount{}).Select("id").Where(q, account).Scan(&userId)
	if result.Error != nil {
		return 0, result.Error
	}
	if result.RowsAffected == 0 {
		return 0, errors.New(fmt.Sprintf("%s:%s not exist", field, account))
	}
	return userId, nil
}

func (u *userRepo) RecordLoginFailure(ctx context.Context, field, account string) (bool, error) {
	//记录登录失败 存到数据库和缓存 连续失败x次，限制登录x分钟
	userId, err := u.findUserId(field, account)
	if err != nil {
		return false, err
	}
	err = u.data.DB.Model(&UserAccount{}).Where("id = ?", userId).Update("failed_attempts", gorm.Expr("failed_attempts + ?", 1)).Error
	if err != nil {
		return false, err
	}
	UI := fmt.Sprintf("userId:%d", userId)
	value, err := u.data.getValue(UI)
	if err != nil {
		return false, err
	} else if value == "" {
		//缓存中没有当前userId
		duration := time.Duration(u.data.OT.AccountLockDurationMinutes) * time.Minute
		err = u.data.setKey(UI, "1", duration)
		if err != nil {
			return false, err
		}

	} else {
		//缓存中有当前设备码，直接加一
		u.data.RD.Incr(ctx, UI)
	}
	return true, nil
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
	value, err := u.data.getValue(DI)
	if err != nil {
		return err
	} else if value == "" {
		//缓存中没有当前设备码
		err = u.data.setKey(DI, "1", 0)
		if err != nil {
			return err
		}
		expiredAt := pkg.GetMidnightTimestamp()
		err = u.data.RD.ExpireAt(ctx, DI, expiredAt).Err()
	} else {
		//缓存中有当前设备码，直接加一
		u.data.RD.Incr(ctx, DI)
	}
	uid, err := u.findUserId("unique_id", uniqueId)
	if err != nil {
		return err
	}

	up := &UserProfile{
		UserID:   uid,
		Nickname: uniqueId,
		Location: "中国/内蒙古",
	}
	err = u.data.DB.Model(&UserProfile{}).Create(up).Error
	if err != nil {
		return err
	}

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
