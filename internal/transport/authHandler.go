package transport

import (
	"authService/gen/auth"
	pb "authService/gen/auth"
	"authService/internal/models"
	"authService/internal/service"
	"authService/internal/serviceErrors"
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type AuthServer struct {
	auth.UnimplementedAuthServiceServer
	service service.Auth
}

func NewAuthServerHandler(service service.Auth) *AuthServer {
	return &AuthServer{service: service}
}

func GetAccessTokenFromMD(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", serviceErrors.MissingMetadata
	}

	accessTokens := md.Get("authorization")
	if len(accessTokens) == 0 {
		return "", status.Error(codes.InvalidArgument, serviceErrors.AccessTokenNotFound.Error())
	}

	accessToken := strings.TrimPrefix(accessTokens[0], "Bearer ")

	return accessToken, nil
}

func GetRefreshTokenFromMD(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", serviceErrors.MissingMetadata
	}

	refreshToken := md.Get("refresh-token")
	if len(refreshToken) == 0 {
		return "", status.Error(codes.InvalidArgument, serviceErrors.RefreshTokenNotFound.Error())
	}
	return refreshToken[0], nil
}

func (a *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.Tokens, error) {
	user := &models.User{
		Login:    req.Login,
		Password: &req.Password,
		Email:    req.Email,
	}
	tokens, err := a.service.Register(ctx, user)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	respTokens := &pb.Tokens{
		RefreshToken: tokens.RefreshToken,
		AccessToken:  tokens.AccessToken,
	}
	return respTokens, nil
}

func (a *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.Tokens, error) {
	user := &models.User{
		Login:    req.Login,
		Password: &req.Password,
	}

	tokens, err := a.service.Login(ctx, user)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}
	respTokens := &pb.Tokens{
		RefreshToken: tokens.RefreshToken,
		AccessToken:  tokens.AccessToken,
	}
	return respTokens, nil
}

func (a *AuthServer) Logout(ctx context.Context, _ *emptypb.Empty) (*emptypb.Empty, error) {
	token, err := GetRefreshTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	err = a.service.Logout(ctx, token)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	return &emptypb.Empty{}, nil
}

func (a *AuthServer) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*emptypb.Empty, error) {
	accessToken, err := GetAccessTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	err = a.service.ChangePassword(ctx, accessToken, req.OldPassword, req.NewPassword)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}
	return &emptypb.Empty{}, nil
}

func (a *AuthServer) ChangeEmail(ctx context.Context, req *pb.ChangeEmailRequest) (*emptypb.Empty, error) {
	accessToken, err := GetAccessTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	err = a.service.ChangeEmail(ctx, accessToken, req.Password, req.NewEmail)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}
	return &emptypb.Empty{}, nil
}

func (a *AuthServer) UserDeleteAccount(ctx context.Context, req *pb.UserDeleteAccRequest) (*emptypb.Empty, error) {
	accessToken, err := GetAccessTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	err = a.service.UserDeleteAcc(ctx, accessToken, req.Password)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}
	return &emptypb.Empty{}, nil
}

func (a *AuthServer) UserLogoutAllSessions(ctx context.Context, _ *emptypb.Empty) (*pb.LogoutSessionResponse, error) {
	accessToken, err := GetAccessTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	numberOfDeletedSessions, err := a.service.DeleteAllUserSessions(ctx, accessToken)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}
	resp := &pb.LogoutSessionResponse{
		NumberOfDeleteSessions: int32(numberOfDeletedSessions),
	}
	return resp, nil
}

func (a *AuthServer) NewRole(ctx context.Context, req *pb.NewRoleRequest) (*emptypb.Empty, error) {
	req.RoleName = strings.ToLower(req.RoleName)
	err := a.service.AddNewRole(ctx, req.RoleName)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	return &emptypb.Empty{}, nil
}

func (a *AuthServer) ChangeUserRole(ctx context.Context, req *pb.ChangeRoleRequest) (*emptypb.Empty, error) {
	reqUser := &models.User{
		Login: req.Login,
		Role:  strings.ToLower(req.RoleName),
	}

	err := a.service.ChangeUserRole(ctx, reqUser)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	return &emptypb.Empty{}, nil
}

func (a *AuthServer) GetUserData(ctx context.Context, req *pb.AdminTargetUserRequest) (*pb.GetUserResponse, error) {
	reqUser := &models.User{Login: req.Login}
	user, err := a.service.GetUserInfo(ctx, reqUser)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	respUser := &pb.GetUserResponse{
		Uid:   user.Uid.String(),
		Login: user.Login,
		Email: user.Email,
		Role:  user.Role,
	}

	return respUser, nil
}

func (a *AuthServer) AdminDeleteAccount(ctx context.Context, req *pb.AdminTargetUserRequest) (*emptypb.Empty, error) {
	reqUser := &models.User{Login: req.Login}
	err := a.service.AdminDeleteUserAcc(ctx, reqUser)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return &emptypb.Empty{}, respErr
	}

	return &emptypb.Empty{}, nil
}

func (a *AuthServer) AdminLogoutUserSessions(ctx context.Context, req *pb.AdminTargetUserRequest) (*pb.LogoutSessionResponse, error) {
	numberOfDeletedSessions, err := a.service.AdminDeleteAllUserSessions(ctx, req.Login)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}
	resp := &pb.LogoutSessionResponse{
		NumberOfDeleteSessions: int32(numberOfDeletedSessions),
	}
	return resp, nil
}

func (a *AuthServer) UpdateTokens(ctx context.Context, _ *emptypb.Empty) (*pb.Tokens, error) {
	token, err := GetRefreshTokenFromMD(ctx)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	newTokens, err := a.service.UpdateAccessToken(ctx, token)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	respTokens := &pb.Tokens{
		AccessToken:  newTokens.AccessToken,
		RefreshToken: newTokens.RefreshToken,
	}

	return respTokens, nil
}

func (a *AuthServer) GetPublicRSAKey(ctx context.Context, _ *emptypb.Empty) (*pb.PublicKeyResponse, error) {
	publicKey := a.service.GetPublicKey(ctx)
	resp := &pb.PublicKeyResponse{
		PublicKey: publicKey,
	}
	return resp, nil
}

func (a *AuthServer) GetUsersList(req *pb.GetUsersRequest, stream pb.AuthService_GetUsersListServer) error {
	if req.PageLimit > 100 || req.PageLimit < 1 {
		return serviceErrors.BadGetUsersListRequest
	}

	users, err := a.service.GetUsersList(stream.Context(), int(req.PageLimit), int(req.PageNumber))
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return respErr
	}

	for _, user := range users {
		outUser := &pb.GetUserResponse{
			Uid:   user.Uid.String(),
			Login: user.Login,
			Email: user.Email,
			Role:  user.Role,
		}

		if err := stream.Send(outUser); err != nil {
			return serviceErrors.CantSendUserFromUsersList
		}
	}

	return nil

}
