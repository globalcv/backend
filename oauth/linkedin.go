package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/linkedin"
)

var liOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/linkedin/callback",
	ClientID:     os.Getenv("li_id"),
	ClientSecret: os.Getenv("li_secret"),
	Scopes:       []string{"user"},
	Endpoint:     linkedin.Endpoint,
}

func LinkedInLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateLiOAuthState(w)
	u := ghOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateLiOAuthState(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("error generating random bytes")
		return ""
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "linkedin_oauth", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}
