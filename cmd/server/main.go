package main

import (
	pb "authService/gen/auth"
	"authService/internal/config"
	"authService/internal/service"
	"authService/internal/storage"
	"authService/internal/storage/postgres"
	"authService/internal/transport"
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("something wrong with config")
		return
	}

	dbConnPool, err := postgres.InitDb()
	if err != nil {
		fmt.Println("something wrong with database")
		return
	}
	defer dbConnPool.Close()

	repos := storage.NewAuthRepo(dbConnPool)
	services := service.NewAuthService(repos, cfg)
	handler := transport.NewAuthServerHandler(services)

	err = services.AddFirstUser(context.Background())
	if err != nil {
		fmt.Println("Main file internal error: ", err.Error())
		return
	}

	lis, err := net.Listen("tcp", cfg.ServerAddress)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, handler)

	fmt.Println("gRPC server started")
	if err := grpcServer.Serve(lis); err != nil {
		fmt.Println(err.Error())
		return
	}
}
