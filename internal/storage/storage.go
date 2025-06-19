// storage layer
// auth app interface in communication with db

package storage

import (
	"authService/internal/models"
	"authService/internal/serviceErrors"
	"authService/internal/storage/postgres"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v5"
)

type AuthInter interface {
	AddNewUser(ctx context.Context, user *models.User) (*models.User, error) // add new user in database
	GetUser(ctx context.Context, user *models.User) (*models.User, error)    // return all user info, if user doesn't exist, throw error. Require Uid or login in "user" struct arguments
	ChangePassword(ctx context.Context, user *models.User) error             // require Uid and new password in "user" struct arguments
	ChangeEmail(ctx context.Context, user *models.User) error                // require Uid and new email in "user" struct arguments
	DeleteUser(ctx context.Context, user *models.User) error                 // return serviceErrors.UserDoesntExist if wrong uid. Require Uid in "user" struct arguments
	GetUsersList(ctx context.Context, pageLimit int, pageNumber int) ([]models.User, error)

	GetRoleIdByName(ctx context.Context, role string) (uuid.UUID, error)
	AddNewRole(ctx context.Context, roleName string) (*models.Role, error)
	UpdateUserRole(ctx context.Context, user *models.User) error // update user role. Require Uid and new user role in "user" struct argument

	CreateSession(ctx context.Context, user *models.User) (*models.Session, error) // create new session in database
	GetSession(ctx context.Context, sessionId uuid.UUID) (*models.Session, error)  // for updating access token. After this methos should call GetUserRole
	DeleteSession(ctx context.Context, sessiondId uuid.UUID) error                 // used for logout
	DeleteAllUserSessions(ctx context.Context, uid uuid.UUID) (int64, error)       // logout from all devices. Return number of deleted sessions and error

	UpdateSessionExpireTime(ctx context.Context, sessionId uuid.UUID) (int64, error)
}

type authRepo struct {
	pool postgres.DBPool
}

func NewAuthRepo(pool postgres.DBPool) *authRepo {
	return &authRepo{
		pool: pool,
	}
}

func (r *authRepo) GetRoleIdByName(ctx context.Context, role string) (uuid.UUID, error) {
	query := `select id 
				from role
				where name = $1`

	var id uuid.UUID
	err := r.pool.QueryRow(ctx, query, role).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, serviceErrors.RoleDoesntExist
		}
		return uuid.Nil, fmt.Errorf("GetRoleIdByName internal error: %w", err)
	}
	return id, nil
}

func (r *authRepo) AddNewUser(ctx context.Context, user *models.User) (*models.User, error) {
	query := `insert into users(login, email, password, roleId)
						values ($1, $2, $3, $4)
						returning uid`

	roleId, err := r.GetRoleIdByName(ctx, user.Role)
	if err != nil {
		return nil, err
	}

	respUser := *user

	err = r.pool.QueryRow(ctx, query, user.Login, user.Email, user.PasswordHash, roleId).Scan(&respUser.Uid)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			switch pgErr.ConstraintName {
			case "unique_login":
				return nil, serviceErrors.LoginAlreadyUsed
			case "unique_email":
				return nil, serviceErrors.EmailAlreadyUsed
			}
		}
		return nil, fmt.Errorf("AddNewUser internal error: %w", err)
	}

	return &respUser, nil
}

func (r *authRepo) CreateSession(ctx context.Context, user *models.User) (*models.Session, error) {
	query := `insert into sessions(uid, exp)
				values(
					$1, $2
				)
				returning sessionId`
	exp := time.Now().Add(time.Hour * 24 * 30).Unix()
	var sessionId uuid.UUID

	err := r.pool.QueryRow(ctx, query, user.Uid, exp).Scan(&sessionId)
	if err != nil {
		return nil, fmt.Errorf("CreateSession internal error: %w", err)
	}

	session := &models.Session{
		SessionId: sessionId,
		Uid:       user.Uid,
		Exp:       exp,
	}

	return session, nil
}

func (r *authRepo) GetSession(ctx context.Context, sessionId uuid.UUID) (*models.Session, error) {
	query := `select uid, exp
				from sessions
				where sessionId = $1`

	session := &models.Session{}

	err := r.pool.QueryRow(ctx, query, sessionId).Scan(&session.Uid, &session.Exp)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, serviceErrors.SessionDoesntExist
		}
		return nil, fmt.Errorf("GetSession internal error: %w", err)
	}

	return session, nil
}

func (r *authRepo) GetUser(ctx context.Context, user *models.User) (*models.User, error) {
	query := `select u.uid, u.login, u.email, u.password, r.name
				from users as u
				join role as r on u.roleId = r.id
				where uid = $1 or login = $2`

	respUser := &models.User{}

	err := r.pool.QueryRow(ctx, query, user.Uid, user.Login).Scan(&respUser.Uid, &respUser.Login, &respUser.Email, &respUser.PasswordHash, &respUser.Role)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, serviceErrors.UserDoesntExist
		}
		return nil, fmt.Errorf("GetUser internal error: %w", err)
	}

	return respUser, nil
}

func (r *authRepo) AddNewRole(ctx context.Context, roleName string) (*models.Role, error) {
	query := `insert into role(name)
				values ($1)
				returning id`

	respRole := &models.Role{
		Name: roleName,
	}

	err := r.pool.QueryRow(ctx, query, roleName).Scan(&respRole.Id)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "unique_name" {
				return nil, serviceErrors.RoleAlreadyExist
			}
		}
		return nil, fmt.Errorf("AddNewRole internal error: %w", err)
	}

	return respRole, nil
}

func (r *authRepo) UpdateUserRole(ctx context.Context, user *models.User) error {
	query := `update users
				set roleId = $1
				where login = $2`

	roleId, err := r.GetRoleIdByName(ctx, user.Role)
	if err != nil {
		return err
	}

	res, err := r.pool.Exec(ctx, query, roleId, user.Login)
	if err != nil {
		return fmt.Errorf("UpdateUserRole internal error: %w", err)
	}
	if res.RowsAffected() == 0 {
		return serviceErrors.UserDoesntExist
	}

	return nil
}

func (r *authRepo) DeleteSession(ctx context.Context, sessiondId uuid.UUID) error {
	query := `delete from sessions
				where sessionId = $1`

	res, err := r.pool.Exec(ctx, query, sessiondId)
	if err != nil {
		return fmt.Errorf("DeleteSession internal error: %w", err)
	}

	if res.RowsAffected() == 0 {
		return serviceErrors.SessionDoesntExist
	}

	return nil
}

func (r *authRepo) DeleteAllUserSessions(ctx context.Context, uid uuid.UUID) (int64, error) {
	query := `delete from sessions
				where uid = $1`

	res, err := r.pool.Exec(ctx, query, uid)

	if err != nil {
		return -1, fmt.Errorf("DeleteAllUserSessions internal error: %w", err)
	}

	return res.RowsAffected(), nil
}

func (r *authRepo) ChangePassword(ctx context.Context, user *models.User) error {
	query := `update users
				set password = $1
				where uid = $2`

	res, err := r.pool.Exec(ctx, query, user.PasswordHash, user.Uid)
	if err != nil {
		return err
	}

	if res.RowsAffected() == 0 {
		return serviceErrors.UserDoesntExist
	}

	return nil
}

func (r *authRepo) ChangeEmail(ctx context.Context, user *models.User) error {
	query := `update users
				set email = $1
				where uid = $2`

	res, err := r.pool.Exec(ctx, query, user.Email, user.Uid)
	if err != nil {
		return err
	}

	if res.RowsAffected() == 0 {
		return serviceErrors.UserDoesntExist
	}

	return nil
}

func (r *authRepo) DeleteUser(ctx context.Context, user *models.User) error {
	queryDeleteAcc := `delete from users
				where uid = $1 or login = $2`

	resA, err := r.pool.Exec(ctx, queryDeleteAcc, user.Uid, user.Login)
	if err != nil {
		return fmt.Errorf("DeleteUser internal error: %w", err)
	}
	if resA.RowsAffected() == 0 {
		return serviceErrors.UserDoesntExist
	}

	return nil
}

func (r *authRepo) UpdateSessionExpireTime(ctx context.Context, sessionId uuid.UUID) (int64, error) {
	query := `update sessions
				set exp = $1
				where sessionId = $2`

	exp := time.Now().Add(time.Hour * 24 * 30).Unix()
	err := r.pool.QueryRow(ctx, query, sessionId).Scan(&exp)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return -1, serviceErrors.SessionDoesntExist
		}
		return -1, fmt.Errorf("UpdateSessionExpireTime internal error: %w", err)
	}

	return exp, nil
}

func (r *authRepo) GetUsersList(ctx context.Context, pageLimit int, pageNumber int) ([]models.User, error) {
	query := `select u.uid, u.login, u.email, r.name
				from users as u
				join role as r on u.roleId = r.id
				limit $1 offset $2;`

	offset := pageLimit * (pageNumber - 1)

	rows, err := r.pool.Query(ctx, query, pageLimit, offset)
	if err != nil {
		return nil, fmt.Errorf("GetUsersList internal error: %w", err)
	}

	defer rows.Close()

	var out []models.User

	for rows.Next() {
		var row models.User
		err := rows.Scan(
			&row.Uid,
			&row.Login,
			&row.Email,
			&row.Role,
		)
		if err != nil {
			continue
		}
		out = append(out, row)
	}

	return out, nil
}
