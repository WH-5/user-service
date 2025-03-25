package biz

import (
	"context"
	"errors"
	"fmt"
	"github.com/WH-5/user-service/internal/conf"
	"github.com/WH-5/user-service/internal/pkg"
	"github.com/go-kratos/kratos/v2/log"
)

type RegisterReq struct {
	Phone    string
	Password string
	DeviceId string
}
type LoginReq struct {
}
type ProfileReq struct {
}
type UniqueIdReq struct {
}
type RegisterReply struct {
	Msg      string
	UniqueId string
}
type LoginReply struct {
}
type ProfileReply struct {
}
type UniqueIdReply struct {
}
type UserRepo interface {
	CheckPhone(ctx context.Context, phone string) (bool, error)
	CheckDeviceId(ctx context.Context, deviceId string) (bool, error)
	SaveAccount(ctx context.Context, phone, uniqueId, hashPwd, deviceId string) error
	WriteLog(ctx context.Context) error
}
type UserUsecase struct {
	repo UserRepo
	log  *log.Helper
	cf   *conf.Bizfig
}

func NewUserUsecase(c *conf.Bizfig, repo UserRepo, logger log.Logger) *UserUsecase {
	return &UserUsecase{repo: repo, log: log.NewHelper(logger), cf: c}
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
	uniqueId := pkg.GenUniqueId(uc.cf.DefaultUniqueLength)
	//4. 加密密码，并储存 调用加密函数
	hashPwd := pkg.HashPassword(req.Password)
	//5. 存储账号信息repo,还要在缓存里加入这个设备今天注册过一次
	err = uc.repo.SaveAccount(ctx, req.Phone, uniqueId, hashPwd, "")
	if err != nil {
		fmt.Println("Error during registration:", err)
		return nil, err
	}
	//6. 记录注册日志 repo到数据库记录
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)
	return &RegisterReply{
		UniqueId: uniqueId,
		Msg:      "register successfully",
	}, nil
}
func (uc *UserUsecase) Login(ctx context.Context, req *LoginReq) (*LoginReply, error) {
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)

	return &LoginReply{}, nil
}
func (uc *UserUsecase) Profile(ctx context.Context, req *ProfileReq) (*ProfileReply, error) {
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)
	return &ProfileReply{}, nil
}
func (uc *UserUsecase) UpdateUniqueId(ctx context.Context, req *UniqueIdReq) (*UniqueIdReply, error) {
	//uc.log.WithContext(ctx).Infof("Create: %v", user.Name)
	return &UniqueIdReply{}, nil
}
