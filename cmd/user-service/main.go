package main

import (
	"flag"
	"fmt"
	"github.com/go-kratos/kratos/contrib/registry/consul/v2"
	"os"
	"time"

	"github.com/WH-5/user-service/internal/conf"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"github.com/go-kratos/kratos/v2/transport/http"

	//consul "github.com/go-kratos/kratos/contrib/registrar/consul/v2"
	"github.com/hashicorp/consul/api"

	_ "go.uber.org/automaxprocs"
)

// go build -ldflags "-X main.Version=x.y.z"
var (
	// Name is the name of the compiled software.
	Name string
	// Version is the version of the compiled software.
	Version string
	// flagconf is the config flag.
	flagconf string

	id, _ = os.Hostname()
)

func getConfigPath() string {
	//if _, err := os.Stat("/app/configs"); err == nil {
	//	return "/app/configs" // 适用于 Docker 容器
	//}
	if _, err := os.Stat("../../configs"); err == nil {
		return "../../configs" // 适用于 kratos run
	}
	return "configs" // 适用于 go run main.go
}
func init() {
	flag.StringVar(&flagconf, "conf", getConfigPath(), "config path, eg: -conf config.yaml")
	// 设置全局时区为 UTC+8
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		fmt.Println("Error loading location:", err)
		return
	}
	// 设置全局时区
	time.Local = loc
}

func newApp(logger log.Logger, gs *grpc.Server, hs *http.Server, server *conf.Server) *kratos.App {
	Name = server.Name
	Version = server.Version
	cg := api.DefaultConfig()
	cg.Address = server.Registry.GetConsul()
	// new consul client
	client, err := api.NewClient(cg)
	if err != nil {
		panic(err)
	}
	// new reg with consul client
	reg := consul.New(client)

	return kratos.New(
		kratos.ID(id+"-"+server.GetName()),
		kratos.Name(Name),
		kratos.Version(Version),
		kratos.Metadata(map[string]string{}),
		kratos.Logger(logger),
		kratos.Server(
			gs,
			hs,
		),
		kratos.Registrar(reg),
	)
}

func main() {
	flag.Parse()
	logger := log.With(log.NewStdLogger(os.Stdout),
		"ts", log.DefaultTimestamp,
		"caller", log.DefaultCaller,
		"service.id", id,
		"service.name", Name,
		"service.version", Version,
		"trace.id", tracing.TraceID(),
		"span.id", tracing.SpanID(),
	)
	c := config.New(
		config.WithSource(
			file.NewSource(flagconf),
		),
	)
	defer c.Close()

	if err := c.Load(); err != nil {
		panic(err)
	}

	var bc conf.Bootstrap
	if err := c.Scan(&bc); err != nil {
		panic(err)
	}

	app, cleanup, err := wireApp(bc.Server, bc.Data, bc.Bizfig, logger)
	if err != nil {
		panic(err)
	}
	defer cleanup()

	// start and wait for stop signal
	if err := app.Run(); err != nil {
		panic(err)
	}
}
