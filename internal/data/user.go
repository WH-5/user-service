package data

import (
	"context"
	"github.com/WH-5/user-service/internal/biz"
	"github.com/go-kratos/kratos/v2/log"
)

type userRepo struct {
	data *Data
	log  *log.Helper
}

func NewUserRepo(data *Data, logger log.Logger) biz.UserRepo {
	return &userRepo{data: data, log: log.NewHelper(logger)}
}
func (r *userRepo) CreateData(ctx context.Context, u *biz.User) (*biz.User, error) {
	return nil, nil
}

var _ biz.UserRepo = (*userRepo)(nil)
