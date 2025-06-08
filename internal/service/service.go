package service

import (
	"authService/internal/config"
	"authService/internal/models"
	"authService/internal/service/authServ"
	"authService/internal/storage"
	"context"
)

type Auth interface {
	Register(ctx context.Context, user *models.User) (*models.AuthTokens, error) // return access and refresh tokens for user
	Login(ctx context.Context, user *models.User) (*models.AuthTokens, error)    // return access and refresh tokens for user
	Logout(ctx context.Context, refreshToken string) error
	ChangePassword(ctx context.Context, accessToken string, password string, newPassword string) error
	ChangeEmail(ctx context.Context, accessToken string, password string, newEmail string) error

	DeleteAllUserSessions(ctx context.Context, accessToken string) (int64, error)
	AdminDeleteAllUserSessions(ctx context.Context, login string) (int64, error)

	AddNewRole(ctx context.Context, roleName string) error
	ChangeUserRole(ctx context.Context, user *models.User) error

	GetUserInfo(ctx context.Context, user *models.User) (*models.User, error)
	AdminDeleteUserAcc(ctx context.Context, user *models.User) error
	UserDeleteAcc(ctx context.Context, refreshToken string, password string) error

	UpdateAccessToken(ctx context.Context, refreshToken string) (*models.AuthTokens, error)
	GetPublicKey(ctx context.Context) string
}

type Deps struct {
	Repos *storage.Repositories
	Cfg   *config.Config
}

type Services struct {
	Auth Auth
}

func NewService(deps *Deps) *Services {
	return &Services{
		Auth: authServ.NewAuthService(deps.Repos.Auth, deps.Cfg),
	}
}
