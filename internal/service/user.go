package service

import (
	"context"
	"github.com/WH-5/user-service/internal/biz"

	pb "github.com/WH-5/user-service/api/user/v1"
)

type UserService struct {
	pb.UnimplementedUserServer
	uc *biz.UserUsecase
}

func NewUserService(uc *biz.UserUsecase) *UserService {
	return &UserService{
		uc: uc,
	}
}

func (s *UserService) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserReply, error) {
	create, err := s.uc.Create(ctx, &biz.User{Name: req.Name})
	if err != nil {
		return nil, err
	}

	return &pb.CreateUserReply{
		Msg: create.Name,
	}, nil
}
