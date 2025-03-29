package service

import (
	"context"
	"fmt"
	pb "github.com/WH-5/user-service/api/user/v1"
	"github.com/WH-5/user-service/internal/biz"
	"github.com/WH-5/user-service/internal/pkg"
)

type UserService struct {
	pb.UnimplementedUserServer
	UC *biz.UserUsecase
}

func NewUserService(uc *biz.UserUsecase) *UserService {
	return &UserService{UC: uc}
}

// Register 注册

func (s *UserService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterReply, error) {
	//必须要传入设备号
	if req.DeviceId == "" {
		return nil, UserDeviceIdEmptyError
	} else if req.Phone == "" || !pkg.IsValidPhone(req.Phone) {
		//非法
		return nil, UserPhoneInvalidError
	}
	//1. 手机号校验：格式（app和服务端双校验）、未注册
	//格式在api层校验，是否注册在biz层校验
	//2. 唯一id生成
	//3. 加密密码，并储存
	//4. 设备注册限制 每天每设备注册x个
	//5. 记录注册日志
	//这些都放在业务逻辑层
	registerReply, err := s.UC.Register(ctx, &biz.RegisterReq{Phone: req.Phone, Password: req.Password, DeviceId: req.DeviceId})
	//意外退出的错误处理，逻辑判断的错误放在msg里了
	if err != nil {
		return nil, RegisterError(err)
	}

	return &pb.RegisterReply{Msg: registerReply.Msg, UniqueId: registerReply.UniqueId}, nil
}
func (s *UserService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginReply, error) {
	//1. 输入唯一id或手机号 客户端选择输入的类型 二选一
	ui := req.GetUniqueId()
	p := req.GetPhone()
	//这两个字段最多一个有值
	if ui == "" && p == "" {
		//都没有就是传错了
		return nil, UserPhoneORUniqueError
	}

	login, err := s.UC.Login(ctx, &biz.LoginReq{Phone: p, Unique: ui, Password: req.GetPassword()})
	if err != nil {
		//自定的错误处理方式
		return nil, LoginError(err)
	}
	//2. 验证账号密码
	//3. 生成jwt token
	//4. 连续失败x次，限制登录x分钟
	//5. 记录登录日志
	return &pb.LoginReply{Token: login.Token, Msg: login.Msg, Field: login.Field, Value: login.Value}, nil
}
func (s *UserService) Profile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileReply, error) {
	//检查权限
	field := "unique_id"
	account := req.GetUniqueId()
	have, err := s.UC.AuthCheckUser(ctx, field, account)
	if err != nil {
		return nil, ProfileError(err)
	}
	if !have {
		return nil, UserNotAccountPermissionError
	}
	p := &biz.UProfile{
		Nickname: req.UserProfile.GetNickname(),
		Bio:      req.UserProfile.GetBio(),
		Gender:   req.UserProfile.GetGender(),
		Birthday: req.UserProfile.GetBirthday(),
		Location: req.UserProfile.GetLocation(),
		Other:    req.UserProfile.GetOther(),
	}
	fmt.Printf("%+v\n", p)
	fmt.Printf("%+v\n", req.UserProfile.GetNickname())
	////如果p获取的值全为零值
	//if pkg.IsZeroValue(*p) {
	//	return nil, UserProfileEmptyError
	//}
	if (*p == biz.UProfile{}) {
		//不带括号过不了编译
		return nil, UserProfileEmptyError
	}
	//if reflect.DeepEqual(*p, reflect.Zero(reflect.TypeOf(*p)).Interface()) {
	//}
	// if判断p全部为零值的s三种写法。各测试1000000*100次
	//== 操作平均耗时: 5.040436ms
	//reflect.DeepEqual 操作平均耗时: 74.898268ms
	//pkg.IsZeroValue 操作平均耗时: 29.06546ms
	profileRep, err := s.UC.Profile(ctx, &biz.ProfileReq{
		UniqueId: req.GetUniqueId(),
		Profile:  p,
	})
	if err != nil {
		return nil, err
	}
	//1. 输入唯一id
	//2. 传入要修改的字段
	//3. 返回修改了的字段
	//4. 记录日志
	return &pb.ProfileReply{UniqueId: profileRep.UniqueId, Msg: ""}, nil
}
func (s *UserService) UpdateUniqueId(ctx context.Context, req *pb.UniqueIdRequest) (*pb.UniqueIdReply, error) {
	return &pb.UniqueIdReply{}, nil
}
