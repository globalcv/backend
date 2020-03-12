package oauth

import (
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/gitlab"
)

var glOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/gitlab/callback",
	ClientID:     os.Getenv("gl_id"),
	ClientSecret: os.Getenv("gl_secret"),
	Scopes:       []string{"user"},
	Endpoint:     gitlab.Endpoint,
}
