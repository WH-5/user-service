package server

import (
	"context"
	v1 "github.com/WH-5/user-service/api/helloworld/v1"
	v2 "github.com/WH-5/user-service/api/user/v1"
	"github.com/WH-5/user-service/internal/conf"
	"github.com/WH-5/user-service/internal/middleware"
	"github.com/WH-5/user-service/internal/service"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/middleware/selector"
	"github.com/go-kratos/kratos/v2/transport/http"
	"strings"
)

// NewHTTPServer new an HTTP server.
func NewHTTPServer(c *conf.Server, greeter *service.GreeterService, userService *service.UserService, logger log.Logger) *http.Server {
	opts := []http.ServerOption{
		http.Middleware(
			selector.Server(
				middleware.AuthCheckExist(userService),
			).Match(func(ctx context.Context, operation string) bool {

				if strings.HasSuffix(operation, "User/Login") || strings.HasSuffix(operation, "User/Register") {
					return false
				}
				return true
			}).Build(),
			recovery.Recovery(),
			logging.Server(logger),
		),
	}
	if c.Http.Network != "" {
		opts = append(opts, http.Network(c.Http.Network))
	}
	if c.Http.Addr != "" {
		opts = append(opts, http.Address(c.Http.Addr))
	}
	if c.Http.Timeout != nil {
		opts = append(opts, http.Timeout(c.Http.Timeout.AsDuration()))
	}
	srv := http.NewServer(opts...)
	v1.RegisterGreeterHTTPServer(srv, greeter)
	v2.RegisterUserHTTPServer(srv, userService)
	return srv
}
