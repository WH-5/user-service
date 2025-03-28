package biz

import (
	"context"
	"errors"
	"fmt"
	"github.com/WH-5/user-service/internal/conf"
	"github.com/WH-5/user-service/internal/pkg"
	"github.com/go-kratos/kratos/v2/log"
	"reflect"
	"strconv"
	"time"
)

type RegisterReq struct {
	Phone    string
	Password string
	DeviceId string
}
type LoginReq struct {
	Phone    string
	Unique   string
	Password string
}
type ProfileReq struct {
	UniqueId string
	Profile  *UProfile
}
type UProfile struct {
	Nickname string // 用户昵称
	Bio      string // 用户简介
	Gender   int32  // 性别，0：未知，1：男，2：女
	Birthday string // 生日，格式 YYYY-MM-DD
	Location string // 位置（国家/城市）
	Other    string //网站
}

type UniqueIdReq struct {
	UniqueId    string
	NewUniqueId string
}
type RegisterReply struct {
	Msg      string
	UniqueId string
}
type LoginReply struct {
	Token string
	Msg   string
	Field string
	Value string
}
type ProfileReply struct {
	UniqueId string
	Msg      string
}
type UniqueIdReply struct {
	NewUniqueId string
	Msg         string
}
type GetProfileReq struct {
	UniqueId string
}
type GetProfileReply struct {
	UProfile *UProfile
	Phone    string
}
type PasswordReq struct{}
type PasswordReply struct{}

type UserRepo interface {
	CheckPhone(ctx context.Context, phone string) (bool, error)
	CheckDeviceId(ctx context.Context, deviceId string) (bool, error)
	SaveAccount(ctx context.Context, phone, uniqueId, hashPwd, deviceId string) error
	WriteLog(ctx context.Context) error
	VerifyUserAuth(ctx context.Context, field, account, password string) (bool, uint, error)
	CanLogin(ctx context.Context, field, account string) (bool, int, error)
	RecordLoginFailure(ctx context.Context, field, account string) (bool, error)
	CheckUser(ctx context.Context, field, account string) (bool, error)
	UpdateProfile(ctx context.Context, uniqueId string, profileMap map[string]any) error
	CheckUniqueUpdate(ctx context.Context, uniqueId string) (uint, error)
	CheckUniqueValid(ctx context.Context, uniqueId string) (bool, error)
	UpdateUniqueId(ctx context.Context, uniqueId, newUniqueId string) error
	RecordModifyUniqueIdOnRedis(ctx context.Context, uid string) error
}
type UserUsecase struct {
	repo UserRepo
	log  *log.Helper
	CF   *conf.Bizfig
}

func NewUserUsecase(c *conf.Bizfig, repo UserRepo, logger log.Logger) *UserUsecase {
	return &UserUsecase{repo: repo, log: log.NewHelper(logger), CF: c}
}
func (uc *UserUsecase) Register(ctx context.Context, req *RegisterReq) (*RegisterReply, error) {
	//1. 设备注册限制 每天每设备注册x个  repo到缓存中查询设备今天是否可以注册了
	can, err := uc.repo.CheckDeviceId(ctx, req.DeviceId)
	if err != nil {
		return nil, err
	} else if !can {
		return nil, errors.New("registration limit reached today")
	}
	//2. 手机号校验：未注册   repo到数据库里查询是否有这个手机号
	have, err := uc.repo.CheckPhone(ctx, req.Phone)
	if err != nil {
		return nil, err
	} else if have {
		return nil, errors.New("phone already used")
	}
	//密码校验
	pwdCan := pkg.PasswordIsValid(req.Password)
	if !pwdCan {
		return nil, errors.New("password is invalid")
	}
	//3. 唯一id生成 调用生成函数
	uniqueId := pkg.GenUniqueId(uc.CF.DefaultUniqueLength)
	//4. 加密密码，并储存 调用加密函数
	hashPwd := pkg.HashPassword(req.Password)
	//5. 存储账号信息repo,还要在缓存里加入这个设备今天注册过一次,新增profile
	err = uc.repo.SaveAccount(ctx, req.Phone, uniqueId, hashPwd, req.DeviceId)
	if err != nil {
		fmt.Println("Error during registration:", err)
		return nil, err
	}
	//6. 记录注册日志 repo到数据库记录
	//TODO 记录到数据库
	uc.log.WithContext(ctx).Infof("Register: %v", req.Phone)
	return &RegisterReply{
		UniqueId: uniqueId,
		Msg:      "register successfully",
	}, nil
}
func (uc *UserUsecase) Login(ctx context.Context, req *LoginReq) (*LoginReply, error) {
	var field, value string

	if req.Phone != "" {
		field = "phone"
		value = req.Phone
	} else if req.Unique != "" {
		field = "unique_id"
		value = req.Unique
	}
	//检查是否允许登录
	can, t, err := uc.repo.CanLogin(ctx, field, value)
	//t是数据层返回的限制登录时间
	if err != nil {
		return nil, err
	}
	if !can {
		return nil, errors.New(fmt.Sprintf("login again after %d minutes", t))
	}
	//验证账号密码是否正确,如果正确，返回用户id
	isAuth, userId, err := uc.repo.VerifyUserAuth(ctx, field, value, req.Password)
	if err != nil {
		return nil, err
	}
	if !isAuth {
		//记录登录失败 存到数据库和缓存 连续失败x次，限制登录x分钟
		state, err := uc.repo.RecordLoginFailure(ctx, field, value)
		if err != nil || !state {
			//输出到日志
			uc.log.WithContext(ctx).Errorf("login failed record failed, state: %v, err: %v", state, err)
		}
		uc.log.WithContext(ctx).Errorf("login failed : %v[%v]", field, value)
		return nil, errors.New("login failed")
	}

	duration := time.Duration(uc.CF.JWT_EXPIRED_HOUR) * time.Hour
	//生成jwt token
	token, err := pkg.GenJwtToken(userId, duration, uc.CF.JWT_SECRET_KEY)
	if err != nil {
		return nil, err
	}
	//记录登录日志
	uc.log.WithContext(ctx).Infof("Login: %v[%v]", field, value)

	return &LoginReply{Token: token, Msg: "Login successfully", Field: field, Value: value}, nil
}
func (uc *UserUsecase) Profile(ctx context.Context, req *ProfileReq) (*ProfileReply, error) {
	var msg string
	//1. 输入唯一id
	uniqueId := req.UniqueId
	//2. 传入要修改的字段
	profileMap := make(map[string]interface{})

	val := reflect.ValueOf(req.Profile)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()
	n := typ.NumField()
	for i := 0; i < n; i++ {
		value := val.Field(i)
		if value.IsZero() {
			continue
		}
		field := typ.Field(i)
		profileMap[field.Name] = value.Interface()
		var valueStr string
		if value.Kind() == reflect.String {
			valueStr = value.String()
		} else {
			valueStr = fmt.Sprintf("%v", value.Interface())
		}

		msg += fmt.Sprintf(field.Name) + " set " + valueStr + ","
	}

	err := uc.repo.UpdateProfile(ctx, uniqueId, profileMap)
	if err != nil {
		return nil, err
	}
	//3. 返回修改了的字段
	//就是msg，最后返回
	//4. 记录日志
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)

	//msg[:len(msg)-1]去除最后一个逗号
	return &ProfileReply{UniqueId: req.UniqueId, Msg: msg[:len(msg)-1]}, nil
}
func (uc *UserUsecase) UpdateUniqueId(ctx context.Context, req *UniqueIdReq) (*UniqueIdReply, error) {
	//判断今天修改过没有
	uid, err := uc.repo.CheckUniqueUpdate(ctx, req.UniqueId)
	if err != nil {
		return nil, err
	}

	//验证合法 及无重复
	valid, err := uc.repo.CheckUniqueValid(ctx, req.NewUniqueId)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, errors.New("unique has already been used")
	}
	//修改 记录今天修改过
	err = uc.repo.UpdateUniqueId(ctx, req.UniqueId, req.NewUniqueId)
	if err != nil {
		return nil, err
	}
	m := "modification successful"
	id := strconv.FormatUint(uint64(uid), 10)
	err = uc.repo.RecordModifyUniqueIdOnRedis(ctx, id)
	if err != nil {
		m += " but save failed"
	}
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)
	return &UniqueIdReply{NewUniqueId: req.NewUniqueId, Msg: m}, nil
}
func (uc *UserUsecase) GetProfile(ctx context.Context, req *GetProfileReq) (*GetProfileReply, error) {

	return &GetProfileReply{}, nil
}
func (uc *UserUsecase) Password(ctx context.Context, req *PasswordReq) (*PasswordReply, error) {
	return &PasswordReply{}, nil
}

// AuthCheckUser 验证token是否具有操作请求的账号的权限
func (uc *UserUsecase) AuthCheckUser(ctx context.Context, field, account string) (bool, error) {
	if field == "" || account == "" {
		return false, errors.New("field or account is empty")
	}
	have, err := uc.repo.CheckUser(ctx, field, account)
	if err != nil {
		return false, err
	}
	return have, nil
}
