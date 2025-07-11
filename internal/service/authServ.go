package service

import (
	"authService/internal/config"
	"authService/internal/models"
	"authService/internal/serviceErrors"
	"authService/internal/storage"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthServ struct {
	authRepo      storage.AuthInter
	cfg           *config.Config
	tokensHandler AuthTokenHandler
}

type AuthTokenHandler interface {
	CreateAccessToken(ctx context.Context, user *models.User) (string, error)
	CreateRefreshToken(ctx context.Context, session *models.Session) (string, error)

	ParseAccessToken(token string) (*models.AccessToken, error)
	ParseRefreshToken(token string) (*models.Session, error)

	ParseJwt(token string) (*jwt.MapClaims, error)
}
type TokenHandlerImpl struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	authRepo   storage.AuthInter
}

type Auth interface {
	Register(ctx context.Context, user *models.User) (*models.AuthTokens, error) // return access and refresh tokens for user
	Login(ctx context.Context, user *models.User) (*models.AuthTokens, error)    // return access and refresh tokens for user
	Logout(ctx context.Context, refreshToken string) error
	ChangePassword(ctx context.Context, accessToken string, password string, newPassword string) error
	ChangeEmail(ctx context.Context, accessToken string, password string, newEmail string) error
	GetUsersList(ctx context.Context, pageLimit, pageNumber int) ([]models.User, error)

	DeleteAllUserSessions(ctx context.Context, accessToken string) (int64, error)
	AdminDeleteAllUserSessions(ctx context.Context, login string) (int64, error)

	AddNewRole(ctx context.Context, roleName string) error
	ChangeUserRole(ctx context.Context, user *models.User) error

	GetUserInfo(ctx context.Context, user *models.User) (*models.User, error)
	AdminDeleteUserAcc(ctx context.Context, user *models.User) error
	UserDeleteAcc(ctx context.Context, refreshToken string, password string) error

	GetUserFromRefreshToken(ctx context.Context, token string) (*models.User, error)
	UpdateAccessToken(ctx context.Context, refreshToken string) (*models.AuthTokens, error)
	GetPublicKey(ctx context.Context) string
}

func NewAuthService(authRepo storage.AuthInter, cfg *config.Config) *AuthServ {
	handler := &TokenHandlerImpl{publicKey: cfg.PublicKey, privateKey: cfg.PrivateKey, authRepo: authRepo}
	return &AuthServ{
		authRepo:      authRepo,
		cfg:           cfg,
		tokensHandler: handler,
	}
}

func (s *TokenHandlerImpl) CreateRefreshToken(ctx context.Context, session *models.Session) (string, error) {
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sessionId": session.SessionId,
		"exp":       session.Exp,
	}).SignedString(s.privateKey)

	if err != nil {
		return "", fmt.Errorf("CreateRefreshToken internal error: %w", err)
	}

	return refreshToken, nil
}

func (s *TokenHandlerImpl) CreateAccessToken(ctx context.Context, user *models.User) (string, error) {
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"uid":      user.Uid,
		"userRole": user.Role,
		"exp":      time.Now().Add(15 * time.Minute).Unix(),
	}).SignedString(s.privateKey)

	if err != nil {
		return "", fmt.Errorf("CreateAccessToken internal error: %w", err)
	}

	return "Bearer " + accessToken, nil
}

func (s *TokenHandlerImpl) ParseAccessToken(token string) (*models.AccessToken, error) {
	tokenClaims, err := s.ParseJwt(token)
	if err != nil {
		fmt.Println()
		return nil, err
	}

	uidStr, ok := (*tokenClaims)["uid"].(string)
	if !ok {
		return nil, serviceErrors.BadAccessToken
	}
	uid, err := uuid.Parse(uidStr)
	if err != nil {
		return nil, serviceErrors.BadAccessToken
	}

	userRole, ok := (*tokenClaims)["userRole"].(string)
	if !ok {
		return nil, serviceErrors.BadAccessToken
	}

	expFloat, ok := (*tokenClaims)["exp"].(float64)
	if !ok {
		return nil, serviceErrors.BadAccessToken
	}
	exp := int64(expFloat)

	if exp < time.Now().Unix() {
		return nil, serviceErrors.AccessTokenExpired
	}

	outToken := &models.AccessToken{
		Uid:      uid,
		UserRole: userRole,
		Exp:      exp,
	}

	return outToken, nil
}

func (s *TokenHandlerImpl) ParseRefreshToken(token string) (*models.Session, error) {
	tokenClaims, err := s.ParseJwt(token)
	if err != nil {
		return nil, err
	}
	sessionIdStr, ok := (*tokenClaims)["sessionId"].(string)
	if !ok {
		return nil, serviceErrors.BadRefreshToken
	}
	sessiondId, err := uuid.Parse(sessionIdStr)
	if err != nil {
		return nil, serviceErrors.BadRefreshToken
	}

	exp, ok := (*tokenClaims)["exp"].(float64)
	if !ok {
		return nil, serviceErrors.BadRefreshToken
	}

	sessionResp := &models.Session{
		SessionId: sessiondId,
		Exp:       int64(exp),
	}

	return sessionResp, nil
}

func (p *TokenHandlerImpl) ParseJwt(tokenString string) (*jwt.MapClaims, error) {
	jwtToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodRSA)
		if !ok {
			return nil, errors.New("wrong token format")
		}
		return p.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if ok && jwtToken.Valid {
		return &claims, nil
	}

	return nil, errors.New("wrong token")
}

func (s *AuthServ) Register(ctx context.Context, user *models.User) (*models.AuthTokens, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	hashStr := string(passwordHash)
	user.PasswordHash = &hashStr
	user.Role = "user"
	newUser, err := s.authRepo.AddNewUser(ctx, user)
	if err != nil {
		return nil, err
	}

	session, err := s.authRepo.CreateSession(ctx, newUser)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokensHandler.CreateRefreshToken(ctx, session)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.tokensHandler.CreateAccessToken(ctx, newUser)
	if err != nil {
		return nil, err
	}

	outTokens := &models.AuthTokens{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
	return outTokens, nil
}

func (s *AuthServ) Login(ctx context.Context, user *models.User) (*models.AuthTokens, error) {
	userFromDb, err := s.authRepo.GetUser(ctx, user)
	if err != nil {
		return nil, err
	}

	validPassword := bcrypt.CompareHashAndPassword([]byte(*userFromDb.PasswordHash), []byte(*user.Password))
	if validPassword != nil {
		return nil, serviceErrors.PasswordDoesntMatch
	}

	fmt.Println("user: ", user)
	fmt.Println("user from db: ", userFromDb)
	session, err := s.authRepo.CreateSession(ctx, userFromDb)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.tokensHandler.CreateRefreshToken(ctx, session)
	if err != nil {
		return nil, err
	}

	accessToken, err := s.tokensHandler.CreateAccessToken(ctx, userFromDb)
	if err != nil {
		return nil, err
	}

	outTokens := &models.AuthTokens{
		RefreshToken: refreshToken,
		AccessToken:  accessToken,
	}
	return outTokens, nil
}

func (s *AuthServ) Logout(ctx context.Context, refreshToken string) error {
	token, err := s.tokensHandler.ParseRefreshToken(refreshToken)
	if err != nil {
		return err
	}

	err = s.authRepo.DeleteSession(ctx, token.SessionId)
	return err
}

func (s *AuthServ) ChangePassword(ctx context.Context, accessToken string, password string, newPassword string) error {
	token, err := s.tokensHandler.ParseAccessToken(accessToken)
	if err != nil {
		return err
	}

	userFromDb, err := s.authRepo.GetUser(ctx, &models.User{Uid: token.Uid})
	if err != nil {
		return err
	}

	vaidPassword := bcrypt.CompareHashAndPassword([]byte(*userFromDb.PasswordHash), []byte(password))
	if vaidPassword != nil {
		return serviceErrors.PasswordDoesntMatch
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("ChangePassword internal error: %w", err)
	}

	*userFromDb.PasswordHash = string(newPasswordHash)
	err = s.authRepo.ChangePassword(ctx, userFromDb)
	return err
}

func (s *AuthServ) ChangeEmail(ctx context.Context, accessToken string, password string, newEmail string) error {
	token, err := s.tokensHandler.ParseAccessToken(accessToken)
	if err != nil {
		return err
	}

	userFromDb, err := s.authRepo.GetUser(ctx, &models.User{Uid: token.Uid})
	if err != nil {
		return err
	}

	validPassword := bcrypt.CompareHashAndPassword([]byte(*userFromDb.PasswordHash), []byte(password))
	if validPassword != nil {
		return serviceErrors.PasswordDoesntMatch
	}

	userFromDb.Email = string(newEmail)
	err = s.authRepo.ChangeEmail(ctx, userFromDb)
	return err
}

func (s *AuthServ) DeleteAllUserSessions(ctx context.Context, accessToken string) (int64, error) {
	token, err := s.tokensHandler.ParseAccessToken(accessToken)
	if err != nil {
		return -1, err
	}

	numberOfDeletedSessions, err := s.authRepo.DeleteAllUserSessions(ctx, token.Uid)
	if err != nil {
		return -1, err
	}

	return numberOfDeletedSessions, nil
}

func (s *AuthServ) AdminDeleteAllUserSessions(ctx context.Context, login string) (int64, error) {
	user, err := s.authRepo.GetUser(ctx, &models.User{Login: login})
	if err != nil {
		return -1, err
	}

	numberOfDeletedSessions, err := s.authRepo.DeleteAllUserSessions(ctx, user.Uid)
	if err != nil {
		return -1, err
	}

	return numberOfDeletedSessions, nil
}

func (s *AuthServ) AddNewRole(ctx context.Context, roleName string) error {
	_, err := s.authRepo.AddNewRole(ctx, roleName)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthServ) ChangeUserRole(ctx context.Context, user *models.User) error {
	err := s.authRepo.UpdateUserRole(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthServ) GetUserInfo(ctx context.Context, user *models.User) (*models.User, error) {
	respUser, err := s.authRepo.GetUser(ctx, user)
	if err != nil {
		return nil, err
	}
	return respUser, err
}

func (s *AuthServ) AdminDeleteUserAcc(ctx context.Context, user *models.User) error {
	err := s.authRepo.DeleteUser(ctx, user)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthServ) UserDeleteAcc(ctx context.Context, accessToken string, password string) error {
	token, err := s.tokensHandler.ParseAccessToken(accessToken)
	if err != nil {
		return err
	}

	userFromDb, err := s.authRepo.GetUser(ctx, &models.User{Uid: token.Uid})
	if err != nil {
		return err
	}

	validPassword := bcrypt.CompareHashAndPassword([]byte(*userFromDb.PasswordHash), []byte(password))
	if validPassword != nil {
		return serviceErrors.PasswordDoesntMatch
	}

	err = s.authRepo.DeleteUser(ctx, userFromDb)
	if err != nil {
		return err
	}

	return nil
}

func (s *AuthServ) UpdateAccessToken(ctx context.Context, refreshToken string) (*models.AuthTokens, error) {

	reqSession, err := s.tokensHandler.ParseRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	session, err := s.authRepo.GetSession(ctx, reqSession.SessionId)
	if err != nil {
		return nil, err
	}

	if session.Exp < time.Now().Unix() {
		session.Exp, err = s.authRepo.UpdateSessionExpireTime(ctx, session.SessionId)
		if err != nil {
			return nil, err
		}
	}

	user, err := s.authRepo.GetUser(ctx, &models.User{Uid: session.Uid})
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := s.tokensHandler.CreateRefreshToken(ctx, session)
	if err != nil {
		return nil, err
	}
	newAccessToken, err := s.tokensHandler.CreateAccessToken(ctx, user)

	tokenResp := &models.AuthTokens{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}

	return tokenResp, nil
}

func (s *AuthServ) GetPublicKey(ctx context.Context) string {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(s.cfg.PublicKey),
	})

	return string(pemBytes)
}

func (s *AuthServ) GetUserByRefreshToken(ctx context.Context, refreshToken string) (*models.User, error) {
	token, err := s.tokensHandler.ParseRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	session, err := s.authRepo.GetSession(ctx, token.SessionId)
	if err != nil {
		return nil, err
	}

	user, err := s.authRepo.GetUser(ctx, &models.User{Uid: session.Uid})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *AuthServ) AddFirstUser(ctx context.Context) error {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return serviceErrors.CantInitFirstUser
	}
	hashStr := string(passwordHash)

	users, err := s.GetUsersList(ctx, 1, 1)
	if err != nil {
		return fmt.Errorf("AddFirstUser internal error: %w", err)
	}
	if len(users) != 0 {
		return nil
	}

	firstUser := &models.User{
		Login:        "admin",
		PasswordHash: &hashStr,
		Email:        "admin",
		Role:         "admin",
	}

	_, err = s.authRepo.AddNewUser(ctx, firstUser)
	if err != nil {
		return err
	}

	return nil

}

func (s *AuthServ) GetUsersList(ctx context.Context, pageLimit, pageNumber int) ([]models.User, error) {
	out, err := s.authRepo.GetUsersList(ctx, pageLimit, pageNumber)
	if err != nil {
		return nil, fmt.Errorf("GetUsersList internal error: %w", err)
	}
	return out, nil
}

func (s *AuthServ) GetUserFromRefreshToken(ctx context.Context, token string) (*models.User, error) {
	tokenInfo, err := s.tokensHandler.ParseRefreshToken(token)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	session, err := s.authRepo.GetSession(ctx, tokenInfo.SessionId)
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}

	user, err := s.authRepo.GetUser(ctx, &models.User{Uid: session.Uid})
	if err != nil {
		respErr := serviceErrors.GRPCError(err)
		return nil, respErr
	}
	return user, nil
}
