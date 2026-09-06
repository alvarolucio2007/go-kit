package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/alvarolucio2007/go-kit/token"
	"github.com/golang-jwt/jwt/v5"
)

const minSecretKeySize = 32

type JWTMaker struct {
	secretKey string
}

func NewJWTMaker(secretKey string) (*JWTMaker, error) {
	if len(secretKey) < minSecretKeySize {
		return nil, fmt.Errorf("invalid key size: must at least be %d characters", minSecretKeySize)
	}
	return &JWTMaker{secretKey}, nil
}

func (maker *JWTMaker) CreateToken(username string, duration time.Duration) (string, error) {
	payload, err := token.NewPayload(username, duration)
	if err != nil {
		return "", err
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return jwtToken.SignedString([]byte(maker.secretKey))
}

func (maker *JWTMaker) VerifyToken(tkn string) (*token.Payload, error) {
	keyFunc := func(tkn *jwt.Token) (interface{}, error) {
		_, ok := tkn.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, token.ErrInvalidToken
		}
		return []byte(maker.secretKey), nil
	}
	jwtToken, err := jwt.ParseWithClaims(tkn, &token.Payload{}, keyFunc)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, token.ErrExpiredToken
		}
		return nil, token.ErrInvalidToken
	}
	payload, ok := jwtToken.Claims.(*token.Payload)
	if !ok {
		return nil, token.ErrInvalidToken
	}
	return payload, nil
}
