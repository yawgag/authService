package serviceErrors

import (
	"errors"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	UserAlreadyExist = errors.New("User already exist")
	UserDoesntExist  = errors.New("User does not exit")
	RoleAlreadyExist = errors.New("Role already exist")
	RoleDoesntExist  = errors.New("Role does not exist")

	LoginAlreadyUsed = errors.New("Login already used")
	EmailAlreadyUsed = errors.New("Email already used")

	SessionDoesntExist = errors.New("Session does not exist")

	PasswordDoesntMatch = errors.New("The password does not match")

	MissingMetadata = errors.New("Missing metadata")

	AccessTokenNotFound  = errors.New("Access token not found")
	RefreshTokenNotFound = errors.New("Refresh token not found")

	BadAccessToken  = errors.New("Invalid access token")
	BadRefreshTOken = errors.New("Invalid refresh token")

	AccessTokenExpired  = errors.New("Access token has expired")
	RefreshTokenExpired = errors.New("Refresh token has expired")
)

func GRPCError(err error) error {
	switch {
	case errors.Is(err, UserAlreadyExist):
		return status.Error(codes.AlreadyExists, UserAlreadyExist.Error())
	case errors.Is(err, RoleAlreadyExist):
		return status.Error(codes.AlreadyExists, RoleAlreadyExist.Error())
	case errors.Is(err, UserDoesntExist):
		return status.Error(codes.NotFound, UserDoesntExist.Error())
	case errors.Is(err, RoleDoesntExist):
		return status.Error(codes.NotFound, RoleDoesntExist.Error())
	case errors.Is(err, LoginAlreadyUsed):
		return status.Error(codes.InvalidArgument, LoginAlreadyUsed.Error())
	case errors.Is(err, EmailAlreadyUsed):
		return status.Error(codes.InvalidArgument, EmailAlreadyUsed.Error())
	case errors.Is(err, SessionDoesntExist):
		return status.Error(codes.NotFound, SessionDoesntExist.Error())
	case errors.Is(err, PasswordDoesntMatch):
		return status.Error(codes.InvalidArgument, PasswordDoesntMatch.Error())
	case errors.Is(err, BadAccessToken):
		return status.Error(codes.InvalidArgument, BadAccessToken.Error())
	case errors.Is(err, BadRefreshTOken):
		return status.Error(codes.InvalidArgument, BadRefreshTOken.Error())
	case errors.Is(err, AccessTokenExpired):
		return status.Error(codes.PermissionDenied, AccessTokenExpired.Error())
	case errors.Is(err, RefreshTokenExpired):
		return status.Error(codes.PermissionDenied, RefreshTokenExpired.Error())

	default:
		log.Printf("[GRPCError] Unmapped error: %v", err)
		return status.Error(codes.Internal, err.Error())
	}
}
