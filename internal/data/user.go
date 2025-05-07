// Package data user.go
// Author: 王辉
// Created: 2025-03-30 00:29
// 缓存中键的前缀,由于都有id后缀，全部删除了，只保留用于区分的信息
// D:限制设备注册次数 deviceId
// U:限制连续登录错误 userId
// UNU:限制每天修改唯一标识(uniqueId)-不储存次数 uniqueUserId
// PU:限制段时间多长修改密码-不储存次数 passwordUserId
// PW:因输错次数太多限制修改密码passwordWrongUserId
// S{userID}  s后接userid 值为session
// O{userID}  o后接userid 值的类型为list，内容为因不在线而没有收到的消息 (push服务存入的数据)
package data

import (
	"context"
	"errors"
	"fmt"
	v1 "github.com/WH-5/user-service/api/user/v1"
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

func (u *userRepo) GetUniqueAndPhone(ctx context.Context, field, account string) (string, string, error) {
	// 获取用户ID
	userId, err := u.FindUserId(field, account)
	if err != nil {
		return "", "", err
	}

	// 定义结构体，用来存储查询结果
	type Man struct {
		Phone    string `gorm:"column:phone"`     // 显式指定数据库列名
		UniqueId string `gorm:"column:unique_id"` // 显式指定数据库列名
	}
	man := &Man{}

	// 查询 phone 和 unique_id 字段
	err = u.data.DB.Model(&UserAccount{}).
		Where("id = ?", userId).
		Select("phone", "unique_id").
		Scan(man).Error // 使用 Scan 将查询结果存到结构体指针
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 如果记录没有找到，返回特定的错误
			return "", "", fmt.Errorf("user with ID %d not found", userId)
		}
		// 处理其他类型的错误
		return "", "", err
	}

	// 返回查询到的 uniqueId 和 phone
	return man.UniqueId, man.Phone, nil
}

func (u *userRepo) SetEncrypt(ctx context.Context, userId uint, encrypt *v1.EncryptionInfo) error {

	uce := &UserChatEncryption{
		UserID:              userId,
		KdfSalt:             encrypt.KdfSalt,
		PublicKey:           encrypt.PublicKey,
		EncryptedPrivateKey: encrypt.EncryptedPrivateKey,
	}
	err := u.data.DB.Create(uce).Error
	if err != nil {
		return err
	}
	return nil
}

func (u *userRepo) GetEncrypt(ctx context.Context, userId uint) (*v1.EncryptionInfo, error) {

	uce := &UserChatEncryption{}
	err := u.data.DB.Where("user_id = ?", userId).First(&uce).Error
	if err != nil {
		return nil, err
	}
	return &v1.EncryptionInfo{
		KdfSalt:             uce.KdfSalt,
		PublicKey:           uce.PublicKey,
		EncryptedPrivateKey: uce.EncryptedPrivateKey,
	}, nil
}

func (u *userRepo) GetUniqueByIdMany(ctx context.Context, userId uint64) (biz.UserInfo, error) {
	var unique biz.UserInfo
	err := u.data.DB.Model(&UserAccount{}).Where("id = ?", userId).Select("unique_id", "id").Scan(&unique).Error
	if err != nil {
		return biz.UserInfo{}, err
	}
	return unique, nil
}

// SaveSession 将用户 session 存入缓存
func (u *userRepo) SaveSession(ctx context.Context, userId uint, session string, hour int32) error {
	h := time.Duration(hour) * time.Hour
	err := u.data.setKey(fmt.Sprintf("S%d", userId), session, h)
	if err != nil {
		return err
	}
	return nil
}

// ModifyPassword 修改用户密码并记录限制信息到缓存
func (u *userRepo) ModifyPassword(ctx context.Context, userId uint, newHashPassword string) error {
	//保存密码
	result := u.data.DB.Model(&UserAccount{}).Where("id = ?", userId).Update("password_hash", newHashPassword)
	if result.Error != nil {
		return result.Error
	}
	//记录到缓存
	k := fmt.Sprintf("PU:%d", userId)
	pmldm := int64(u.data.OT.PasswordModifyLockDurationMinutes)
	err := u.data.setKey(k, "", time.Duration(pmldm)*time.Minute)
	if err != nil {
		return err
	}
	return nil
}

// GetProfileByUniqueId 通过唯一 ID 获取用户资料
func (u *userRepo) GetProfileByUniqueId(ctx context.Context, uniqueId string) (*biz.UProfile, error) {
	var userProfile UserProfile
	uid, err := u.FindUserId("unique_id", uniqueId)
	if err != nil {
		return nil, err
	}
	err = u.data.DB.Where("user_id = ?", uid).Find(&userProfile).Error
	if err != nil {
		return nil, err
	}
	return &biz.UProfile{
		Nickname: userProfile.Nickname,
		Bio:      userProfile.Bio,
		Gender:   int32(userProfile.Gender),
		Birthday: userProfile.Birthday.Format("2006-01-02"),
		Location: userProfile.Location,
		Other:    userProfile.Other,
	}, nil
}

// GetPhoneByUniqueId 通过唯一 ID 获取用户手机号
func (u *userRepo) GetPhoneByUniqueId(ctx context.Context, uniqueId string) (string, error) {
	var userAcc UserAccount
	err := u.data.DB.Model(&UserAccount{}).Where("unique_id = ?", uniqueId).First(&userAcc).Error
	if err != nil {
		return "", err
	}
	return userAcc.Phone, nil
}

// RecordModifyUniqueIdOnRedis 记录唯一 ID 修改行为到缓存
func (u *userRepo) RecordModifyUniqueIdOnRedis(ctx context.Context, uid string) error {

	//存到缓存
	k := "UNU:" + uid
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

// CheckUniqueUpdate 检查唯一 ID 当天是否已修改
func (u *userRepo) CheckUniqueUpdate(ctx context.Context, uniqueId string) (uint, error) {
	//根据userid检查今天更新情况 没错就是能用

	//获取userid
	userId, err := u.FindUserId("unique_id", uniqueId)
	if err != nil {
		return 0, err
	}

	//到缓存里查询
	uid := strconv.FormatUint(uint64(userId), 10)
	have, err := u.data.RD.Exists(ctx, "UNU:"+uid).Result()
	if err != nil {
		return 0, err
	}
	if have > 0 {
		return 0, errors.New("unique id today has already been modified")
	}
	return userId, nil
}

// CheckUniqueValid 检查唯一 ID 是否合法且未注册
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

// UpdateUniqueId 更新用户的唯一 ID
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

// UpdateProfile 根据唯一 ID 更新用户资料
func (u *userRepo) UpdateProfile(ctx context.Context, uniqueId string, profileMap map[string]any) error {

	userId, err := u.FindUserId("unique_id", uniqueId)
	if err != nil {
		return err
	}
	result := u.data.DB.Model(&UserProfile{}).Where("user_id = ?", userId).Updates(profileMap)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// CheckUser 校验当前用户是否是账号所有者
func (u *userRepo) CheckUser(ctx context.Context, field, account string) (bool, error) {
	uidValue := ctx.Value("user_id")
	uid, ok := uidValue.(float64)
	if !ok {
		return false, errors.New("invalid or missing user_id in context")
	}
	userId, err := u.FindUserId(field, account)
	if err != nil {
		return false, err
	}

	sv, err := u.data.getValue(fmt.Sprintf("S%d", uint(uid)))
	if err != nil {
		return false, err
	}
	if sv == "" {
		return false, errors.New("not logged in")
	}
	sessionValue := ctx.Value("session")
	session, ok := sessionValue.(string)
	if !ok {
		return false, errors.New("invalid or missing session in context")
	}
	if session != sv {
		//在其他地方登录了
		return false, errors.New("logged in another")
	}
	if userId == uint(uid) {
		return true, nil
	}
	return false, nil
}

// VerifyUserAuth 校验账号和密码是否正确
func (u *userRepo) VerifyUserAuth(ctx context.Context, field, account, password string) (bool, uint, error) {
	//验证账号密码是否正确,如果正确，返回用户id
	//false:没匹配上
	userId, err := u.FindUserId(field, account)
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

// CanLogin 判断用户是否可以登录
func (u *userRepo) CanLogin(ctx context.Context, field, account string) (bool, int, error) {
	//检查是否允许登录 到缓存里查这个
	userId, err := u.FindUserId(field, account)
	if err != nil {
		return false, 0, err
	}
	value, err := u.data.getValue("U:" + fmt.Sprintf("%d", userId))
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
	ttl := u.data.RD.TTL(ctx, "U:"+fmt.Sprintf("%d", userId)).Val()
	t := int(math.Ceil(ttl.Minutes()))
	return false, t, nil
}

// FindUserId 通过字段和值查找用户 ID
func (u *userRepo) FindUserId(field, account string) (uint, error) {
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

// RecordLoginFailure 记录用户登录失败次数
func (u *userRepo) RecordLoginFailure(ctx context.Context, field, account string) (bool, error) {
	//记录登录失败 存到数据库和缓存 连续失败x次，限制登录x分钟
	userId, err := u.FindUserId(field, account)
	if err != nil {
		return false, err
	}
	err = u.data.DB.Model(&UserAccount{}).Where("id = ?", userId).Update("failed_attempts", gorm.Expr("failed_attempts + ?", 1)).Error
	if err != nil {
		return false, err
	}
	UI := fmt.Sprintf("U:%d", userId)
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

// RecordPasswordFailure 记录用户密码修改失败次数
func (u *userRepo) RecordPasswordFailure(ctx context.Context, uniqueId string) error {
	//记录改密码输入失败 存到缓存 连续失败x次，限制登录x分钟
	userId, err := u.FindUserId("unique_id", uniqueId)
	if err != nil {
		return err
	}
	PW := fmt.Sprintf("PW:%d", userId)
	value, err := u.data.getValue(PW)
	if err != nil {
		return err
	} else if value == "" {
		//缓存中没有当前PW
		duration := time.Duration(u.data.OT.AccountLockDurationMinutes) * time.Minute
		err = u.data.setKey(PW, "1", duration)
		if err != nil {
			return err
		}

	} else {
		//缓存中有当前PW，直接加一
		u.data.RD.Incr(ctx, PW)
	}
	return nil
}

// CheckPhone 检查手机号是否已注册
func (u *userRepo) CheckPhone(ctx context.Context, phone string) (bool, error) {
	//查这个手机号是否注册过，是就返回true
	var count int64
	result := u.data.DB.Model(&UserAccount{}).Where("phone = ?", phone).Count(&count)
	if err := result.Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// CheckDeviceId 检查设备注册次数是否超限
func (u *userRepo) CheckDeviceId(ctx context.Context, deviceId string) (bool, error) {
	//到缓存中查找这个device id，键值对：<D:device id,times> <string,int>
	v, err := u.data.getValue("D:" + deviceId)
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

// CheckPasswordByUserId 检查用户是否允许修改密码
func (u *userRepo) CheckPasswordByUserId(ctx context.Context, uniqueId string) error {
	//获取userId
	userId, err := u.FindUserId("unique_id", uniqueId)
	if err != nil {
		return err
	}

	//需要检查PW和PU
	suid := fmt.Sprintf("%d", userId)
	have, err := u.data.RD.Exists(ctx, "PU:"+suid).Result()
	if err != nil {
		return err
	}
	if have > 0 {
		return errors.New(fmt.Sprintf("change password later"))
	}
	pw, err := u.data.getValue("PW:" + suid)
	if err != nil {
		return err
	}
	if pw == "" {
		//没有
		return nil
	}
	pwv, err := strconv.Atoi(pw)
	if err != nil {
		return err
	}
	if int32(pwv) >= u.data.OT.MaxFailedLoginAttempts {
		//大于最大次数
		return errors.New(fmt.Sprintf("yoo many incorrect password attempts"))
	}
	return nil
}

// SaveAccount 保存新用户账号信息并初始化缓存及用户资料
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
	DI := "D:" + deviceId
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
	uid, err := u.FindUserId("unique_id", uniqueId)
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

// WriteLog 写入用户行为日志
func (u *userRepo) WriteLog(ctx context.Context, userId uint, action string, meta []byte) {
	userBehavior := &UserBehaviorLog{
		UserID:   userId,
		Action:   action,
		Metadata: meta,
	}
	err := u.data.DB.Create(userBehavior).Error
	if err != nil {
		u.log.WithContext(ctx).Infof("Write log in db error: %v", err)
	}
}

// NewUserRepo 创建一个新的 UserRepo 实例
func NewUserRepo(data *Data, logger log.Logger) biz.UserRepo {
	return &userRepo{data: data, log: log.NewHelper(logger)}
}

var _ biz.UserRepo = (*userRepo)(nil)
