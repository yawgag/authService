// storage layer
// auth app interface in communication with db

package storage

import (
	"authService/internal/models"
	"authService/internal/storage/postgres"
	"authService/internal/storage/postgres/authRepo"
	"context"

	"github.com/google/uuid"
)

type AuthInter interface {
	AddNewUser(ctx context.Context, user *models.User) (*models.User, error) // add new user in database
	GetUser(ctx context.Context, user *models.User) (*models.User, error)    // return all user info, if user doesn't exist, throw error. Require UID or login in "user" struct arguments
	ChangePassword(ctx context.Context, user *models.User) error             // require UID and new password in "user" struct arguments
	ChangeEmail(ctx context.Context, user *models.User) error                // require UID and new email in "user" struct arguments
	DeleteUser(ctx context.Context, user *models.User) error                 // return serviceErrors.UserDoesntExist if wrong uid. Require UID in "user" struct arguments

	GetRoleIdByName(ctx context.Context, role string) (int, error)
	AddNewRole(ctx context.Context, roleName string) (*models.Role, error)
	UpdateUserRole(ctx context.Context, user *models.User) error // update user role. Require UID and new user role in "user" struct argument

	CreateSession(ctx context.Context, user *models.User) (*models.Session, error) // create new session in database
	GetSession(ctx context.Context, sessionId uuid.UUID) (*models.Session, error)  // for updating access token. After this methos should call GetUserRole
	DeleteSession(ctx context.Context, sessiondId uuid.UUID) error                 // used for logout
	DeleteAllUserSessions(ctx context.Context, uid uuid.UUID) (int64, error)       // logout from all devices. Return number of deleted sessions and error

	UpdateSessionExpireTime(ctx context.Context, sessionId uuid.UUID) (int64, error)
}

type Repositories struct {
	Auth AuthInter
}

func NewRepositories(db postgres.DBPool) *Repositories {
	return &Repositories{
		Auth: authRepo.NewAuthRepo(db),
	}
}
