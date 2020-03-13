package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/gitlab"
)

var glOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/gitlab/callback",
	ClientID:     os.Getenv("gl_id"),
	ClientSecret: os.Getenv("gl_secret"),
	Scopes:       []string{"read_user"},
	Endpoint:     gitlab.Endpoint,
}

func GitlabLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateGlOAuthState(w)
	u := glOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateGlOAuthState(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("error generating random bytes")
		return ""
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "gitlab_oauth", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
