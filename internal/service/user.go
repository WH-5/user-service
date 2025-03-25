package service

import (
	"context"
	pb "github.com/WH-5/user-service/api/user/v1"
	"github.com/WH-5/user-service/internal/biz"
	"github.com/WH-5/user-service/internal/pkg"
)

type UserService struct {
	pb.UnimplementedUserServer
	uc *biz.UserUsecase
}

func NewUserService(uc *biz.UserUsecase) *UserService {
	return &UserService{uc: uc}
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
	//格式在api层校验，是否注册在biz层
	//2. 唯一id生成
	//3. 加密密码，并储存
	//4. 设备注册限制 每天每设备注册x个
	//5. 记录注册日志
	//这些都放在业务逻辑层
	registerReply, err := s.uc.Register(ctx, &biz.RegisterReq{Phone: req.Phone, Password: req.Password, DeviceId: req.DeviceId})
	//意外退出的错误处理，逻辑判断的错误放在msg里了
	if err != nil {
		return nil, RegisterError(err)
	}

	return &pb.RegisterReply{Msg: registerReply.Msg, UniqueId: registerReply.UniqueId}, nil
}
func (s *UserService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginReply, error) {
	return &pb.LoginReply{}, nil
}
func (s *UserService) Profile(ctx context.Context, req *pb.ProfileRequest) (*pb.ProfileReply, error) {
	return &pb.ProfileReply{}, nil
}
func (s *UserService) UpdateUniqueId(ctx context.Context, req *pb.UniqueIdRequest) (*pb.UniqueIdReply, error) {
	return &pb.UniqueIdReply{}, nil
}
