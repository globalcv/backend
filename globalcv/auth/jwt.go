package auth

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

func ParseJWTCookie(r *http.Request, cookieName string) (*jwt.Token, error) {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil, err
	}
	token, err := jwt.Parse(cookie.Value,
		func(*jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("jwt_secret")), nil
		})
	if err != nil {
		return nil, fmt.Errorf("error parsing jwt: %v", err)
	}
	if token == nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return token, nil
}
