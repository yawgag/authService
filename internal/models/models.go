package models

import (
	"github.com/google/uuid"
)

type Role struct {
	Id   uuid.UUID
	Name string
}

type User struct {
	Uid          uuid.UUID `json:"uid"`
	Login        string    `json:"login"`
	Email        string    `json:"email"`
	Password     *string   `json:"password"`
	PasswordHash *string   `json:"passwordHash,omitempty"`
	Role         string    `json:"role"`
}

type Session struct {
	SessionId uuid.UUID `json:"sessionId"`
	Uid       uuid.UUID `json:"uid"`
	Exp       int64     `json:"exp"`
}

type AuthTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type AccessToken struct {
	Uid      uuid.UUID
	UserRole string
	Exp      int64
}
