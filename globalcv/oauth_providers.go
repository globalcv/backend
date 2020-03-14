package globalcv

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/linkedin"
)

var ghOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/github/callback",
	ClientID:     os.Getenv("gh_id"),
	ClientSecret: os.Getenv("gh_secret"),
	Scopes:       []string{"user"},
	Endpoint:     github.Endpoint,
}

var glOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/gitlab/callback",
	ClientID:     os.Getenv("gl_id"),
	ClientSecret: os.Getenv("gl_secret"),
	Scopes:       []string{"read_user"},
	Endpoint:     gitlab.Endpoint,
}

var liOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/linkedin/callback",
	ClientID:     os.Getenv("li_id"),
	ClientSecret: os.Getenv("li_secret"),
	Scopes:       []string{"user"},
	Endpoint:     linkedin.Endpoint,
}

func GitHubLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateOAuthState(w, GithubCookie)
	u := ghOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func GitLabLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateOAuthState(w, GitLabCookie)
	u := glOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func LinkedInLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateOAuthState(w, LinkedInCookie)
	u := liOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateOAuthState(w http.ResponseWriter, cookieName string) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("error generating random bytes")
		return ""
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: cookieName, Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func getUserDataFromGitHub(code string) ([]byte, error) {
	// Use code to get token and get user info from Google.
	token, err := ghOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("code exchange wrong: %v", err)
	}

	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Authorization: token", token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %v", err)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	if err := resp.Body.Close(); err != nil {
		return nil, err
	}

	return b, nil
}
