package biz

import (
	"context"
	"github.com/go-kratos/kratos/v2/log"
)

type User struct {
	Name string
}
type UserRepo interface {
	CreateData(ctx context.Context, u *User) (*User, error)
}
type UserUsecase struct {
	repo UserRepo
	log  *log.Helper
}

func NewUserUsecase(repo UserRepo, logger log.Logger) *UserUsecase {
	return &UserUsecase{repo: repo, log: log.NewHelper(logger)}
}
func (uc *UserUsecase) Create(ctx context.Context, user *User) (*User, error) {
	uc.log.WithContext(ctx).Infof("Create: %v", user.Name)
	return user, nil
}
