package oauth

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
)

var ghOAuthConfig = &oauth2.Config{
	RedirectURL:  "https://globalcv.io/oauth/github/callback",
	ClientID:     os.Getenv("gb_id"),
	ClientSecret: os.Getenv("gb_secret"),
	Scopes:       []string{"user"},
	Endpoint:     github.Endpoint,
}

func GitHubLogin(w http.ResponseWriter, r *http.Request) {
	oauthState := generateOAuthState(w)
	u := ghOAuthConfig.AuthCodeURL(oauthState)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
}

func generateOAuthState(w http.ResponseWriter) string {
	var expiration = time.Now().Add(365 * 24 * time.Hour)

	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		log.Println("error generating random bytes")
		return ""
	}

	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "github_oauth", Value: state, Expires: expiration}
	http.SetCookie(w, &cookie)

	return state
}

func GitHubCallback(w http.ResponseWriter, r *http.Request) {
	// Read oauthState from Cookie
	oauthState, err := r.Cookie("github_oauth")
	if err != nil {
		http.Error(w, "cookie not found", http.StatusUnauthorized)
		return
	}

	if r.FormValue("state") != oauthState.Value {
		log.Println("invalid oauth github state")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	data, err := getUserDataFromGitHub(r.FormValue("code"))
	if err != nil {
		log.Println(err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// GetOrCreate User in your db.

	// Redirect or response with a token.

	fmt.Fprintf(w, "UserInfo: %s\n", data)
}

//"login": "octocat",
//"id": 1,
//"node_id": "MDQ6VXNlcjE=",
//"avatar_url": "https://github.com/images/error/octocat_happy.gif",
//"gravatar_id": "",
//"url": "https://api.github.com/users/octocat",
//"html_url": "https://github.com/octocat",
//"followers_url": "https://api.github.com/users/octocat/followers",
//"following_url": "https://api.github.com/users/octocat/following{/other_user}",
//"gists_url": "https://api.github.com/users/octocat/gists{/gist_id}",
//"starred_url": "https://api.github.com/users/octocat/starred{/owner}{/repo}",
//"subscriptions_url": "https://api.github.com/users/octocat/subscriptions",
//"organizations_url": "https://api.github.com/users/octocat/orgs",
//"repos_url": "https://api.github.com/users/octocat/repos",
//"events_url": "https://api.github.com/users/octocat/events{/privacy}",
//"received_events_url": "https://api.github.com/users/octocat/received_events",
//"type": "User",
//"site_admin": false,
//"name": "monalisa octocat",
//"company": "GitHub",
//"blog": "https://github.com/blog",
//"location": "San Francisco",
//"email": "octocat@github.com",
//"hireable": false,
//"bio": "There once was...",
//"public_repos": 2,
//"public_gists": 1,
//"followers": 20,
//"following": 0,
//"created_at": "2008-01-14T04:33:35Z",
//"updated_at": "2008-01-14T04:33:35Z",
//"plan": {
//"name": "pro",
//"space": 976562499,
//"collaborators": 0,
//"private_repos": 9999

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
